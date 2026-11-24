#!/usr/bin/env python3
# Generates test/captures/steam_ihs_discovery_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Steam In-Home Streaming discovery coverage captures: mksteam-ihs-discovery.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
from c17lib import Cap, udp

SIG = struct.pack('>Q', 0xFFFFFFFF214C5FA0)

def varint(v):
    out = b''
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])

def V(field, value):      # varint field
    return varint(field << 3 | 0) + varint(value)

def L(field, data):       # length-delimited field
    if isinstance(data, str):
        data = data.encode()
    return varint(field << 3 | 2) + varint(len(data)) + data

def F64(field, value):    # fixed64 field
    return varint(field << 3 | 1) + struct.pack('<Q', value)

def F32(field, value):    # fixed32 field
    return varint(field << 3 | 5) + struct.pack('<I', value)

def pkt(msgtype, body=b'', client=0x1122334455667788, instance=0x99aabbccdd, header_extra=b'', hdr=None):
    if hdr is None:
        hdr = V(1, client) + (V(2, msgtype) if msgtype is not None else b'') + V(3, instance) + header_extra
    return SIG + struct.pack('<I', len(hdr)) + hdr + struct.pack('<I', len(body)) + body

def main(out, verbose):
    c = Cap(1)
    def add(p, sport=27036, dport=27036, dst='255.255.255.255', src='192.0.2.5'):
        c.add(udp(sport, dport, p, src, dst))
    c.mark('Client Discovery with a sequence number and several client IDs')
    add(pkt(0, V(1, 4660) + V(2, 1) + V(2, 0xfedcba9876543210) + V(2, 3)))
    add(pkt(0, V(1, 0)))
    c.mark('Client Status with every field: services, users, addresses, versions, device type')
    status = (V(1, 5) + V(2, 3) + V(3, 27036) + L(4, 'synthetic-host') + V(6, 0x3f) + V(7, 20) + V(8, 1)
              + L(9, F64(1, 76561197960287930) + V(2, 7)) + L(9, F64(1, 76561197960265729))
              + L(9, V(2, 99))
              + V(11, 1) + V(12, 1700000000) + V(13, 0) + V(14, 1) + L(15, '02:00:00:00:00:01') + L(15, '02:00:00:00:00:02')
              + L(20, '192.0.2.5') + L(20, '2001:db8::5') + L(21, '198.51.100.7') + V(23, 0x15) + V(25, 1698000000)
              + V(26, 1) + F64(27, 0x1122334455667788) + V(29, 1) + V(30, 0) + V(31, 2))
    add(pkt(1, status), dst='192.0.2.255')
    add(pkt(1, L(4, 'only a host name')))
    add(pkt(1, L(4, '') + V(6, 0) + V(23, 0x3f) + V(26, 3)))
    c.mark('Client Status with fields that are not known (reproducer of the log spam fix): varint, fixed64, length-delimited and fixed32 fields')
    add(pkt(1, V(1, 5) + V(100, 0) * 100))
    add(pkt(1, V(40, 1) + F64(41, 2) + L(42, b'unknown bytes') + F32(43, 3) + V(1, 6)))
    c.mark('Fields that are not known in the other message bodies (discovery, authorization, streaming request, response and cancel, proofs) and in a status user')
    unk = V(50, 1) + L(51, b'u')
    for t, b in ((0, V(1, 1)), (3, L(1, b't')), (4, V(1, 0)), (5, V(1, 1)), (6, V(1, 1) + V(2, 0)), (7, L(1, b'c')), (8, L(1, b'r')), (10, V(1, 1))):
        add(pkt(t, b + unk))
    add(pkt(1, L(9, F64(1, 5) + V(2, 6) + V(50, 1))))
    add(pkt(12, unk))
    c.mark('Client Offline and Device Authorization Cancel Request (no body)')
    add(pkt(2)); add(pkt(9))
    c.mark('Device Authorization Request, then responses with every result (0-8) and an unknown result')
    add(pkt(3, L(1, bytes(range(16))) + L(2, 'Synthetic Phone') + L(3, b'\xde\xad\xbe\xef' * 8)), src='192.0.2.9', dst='192.0.2.5')
    add(pkt(3, L(1, b'tok') + L(2, '') + L(3, b'enc')), src='192.0.2.9', dst='192.0.2.5')
    for r in list(range(9)) + [99]:
        add(pkt(4, V(1, r)), src='192.0.2.5', dst='192.0.2.9')
    c.mark('Device Streaming Request with every field, one with only the request ID, and cancel requests')
    add(pkt(5, V(1, 0x01020304) + V(2, 1920) + V(3, 1080) + V(4, 6) + L(5, '1.2.3') + V(6, 1) + L(7, b'devtoken') + L(8, b'1234')
            + V(9, 1) + V(10, 0) + V(11, 1)), src='192.0.2.9', dst='192.0.2.5')
    add(pkt(5, V(1, 7)), src='192.0.2.9', dst='192.0.2.5')
    add(pkt(10, V(1, 0x01020304)), src='192.0.2.9', dst='192.0.2.5')
    c.mark('Device Streaming Response with results 0-11 and an unknown result, port, session key and licensed device count')
    for r in list(range(12)) + [40]:
        add(pkt(6, V(1, 0x01020304) + V(2, r) + (V(3, 27031) + L(4, b'\x55' * 32) + V(5, 2) if r == 0 else b'')), src='192.0.2.5', dst='192.0.2.9')
    c.mark('Device Proof Request and Response')
    add(pkt(7, L(1, b'\x01' * 32)), src='192.0.2.5', dst='192.0.2.9')
    add(pkt(8, L(1, b'\x02' * 32)), src='192.0.2.9', dst='192.0.2.5')
    c.mark('Message types that are not known (11, a missing type) and header fields that are not known')
    add(pkt(11, V(1, 5) + L(2, b'text') + F64(3, 9) + F32(4, 8)))
    add(pkt(None, V(1, 5)))
    add(pkt(0, V(1, 5), header_extra=V(9, 5) + L(10, b'x') + F64(11, 1) + F32(12, 1)))
    c.mark('Packets that are not Steam discovery (wrong signature, too short, wrong body length) are left to UDP')
    add(b'\0' * 12 + b'abc')
    add(SIG[:8] + b'\0\0')
    p = bytearray(pkt(0, V(1, 3))); p[-3] = 9
    add(bytes(p))
    add(pkt(0, V(1, 3)) + b'\0')

    m = Cap(1)
    def madd(p):
        m.add(udp(27036, 27036, p, '192.0.2.5', '255.255.255.255'))
    m.mark('Wire types that do not match the field (status, discovery, request, response fields)')
    madd(pkt(1, L(1, b'x') + V(4, 3) + L(6, b'y') + L(8, b'z') + V(15, 1) + V(9, 1) + F64(2, 1)))
    madd(pkt(0, L(1, b'x') + L(2, b'y')))
    madd(pkt(5, L(1, b'x') + V(7, 1) + V(5, 2)))
    madd(pkt(6, L(2, b'x') + F64(1, 1)))
    madd(pkt(10, F32(1, 1)))
    madd(pkt(1, L(9, F32(1, 5) + L(2, b'x') + V(1, 5))))
    m.mark('Length prefixes past the buffer or negative, in known and unknown fields; a field that ends in the middle of a varint')
    madd(pkt(1, varint(4 << 3 | 2) + varint(500) + b'abc'))
    madd(pkt(1, varint(4 << 3 | 2) + b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01'))
    madd(pkt(1, varint(60 << 3 | 2) + varint(500) + b'abc'))
    madd(pkt(1, varint(60 << 3 | 3) + b'abc'))
    madd(pkt(1, b'\x80\x80'))
    madd(pkt(1, V(1, 5) + b'\xa0'))
    madd(pkt(0, V(1, 5), hdr=b'\x80'))
    madd(pkt(0, V(1, 5), hdr=varint(1 << 3 | 2) + varint(100) + b'abc'))
    madd(pkt(0, V(1, 5), hdr=V(1, 5) + V(2, 1) + varint(3 << 3 | 2) + b'\xff\xff\xff\xff\x0f'))
    madd(pkt(3, L(1, b'tok') + varint(2 << 3 | 2) + varint(100)))
    madd(pkt(1, L(9, varint(2 << 3 | 2) + varint(200) + b'abc')))
    m.mark('Wire types 6 and 7 (not defined) on known fields and on unknown fields')
    madd(pkt(0, varint(1 << 3 | 6) + b'\x01' + varint(2 << 3 | 7)))
    madd(pkt(0, varint(60 << 3 | 6) + b'\x01'))
    m.mark('Captures cut short by the snap length (the reported length is the full packet)')
    full = pkt(1, L(4, 'a host name that is cut') + V(3, 27036))
    fr = udp(27036, 27036, full, '192.0.2.5', '255.255.255.255')
    m.add((fr[:42 + 11], len(fr)))
    m.add((fr[:42 + 40], len(fr)))
    m.mark('A header length that points outside the packet, and a zero length header')
    madd(SIG + struct.pack('<I', 0xffffff00) + b'abcdefgh')
    madd(SIG + struct.pack('<I', 0) + struct.pack('<I', 0))
    madd(SIG + struct.pack('<I', 0x7fffffff) + b'abcdefgh')
    c.write(os.path.join(out, 'steam-ihs-discovery-coverage.pcap'))
    m.write(os.path.join(out, 'steam-ihs-discovery-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
