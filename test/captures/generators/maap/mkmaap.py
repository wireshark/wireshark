#!/usr/bin/env python3
# Generates test/captures/maap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the MAAP (IEEE 1722 MAAP Protocol) coverage captures.
# Usage: mkmaap.py <outdir>
import struct
import sys
import os

def pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', i, 0, len(fr), len(fr)))
            f.write(fr)

DST = bytes.fromhex('91e0f000ff00')          # MAAP multicast address
SRC = bytes.fromhex('020000000001')

def maap_pdu(mtype, ver=1, dlen=16, stream=0x0000000000000000, req=bytes.fromhex('91e0f0000000'),
             rcount=0, conf=bytes.fromhex('000000000000'), ccount=0, subtype=0xfe, sv=0):
    return struct.pack('>BBHQ', subtype, (sv << 7) | mtype, (ver << 11) | dlen, stream) + req + \
        struct.pack('>H', rcount) + conf + struct.pack('>H', ccount)

def eth(pdu):
    fr = DST + SRC + struct.pack('>H', 0x22f0) + pdu
    return fr + b'\0' * max(0, 60 - len(fr))

def csum(b):
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def udp(pdu, seq):
    # IEEE 1722 UDP encapsulation (Annex J): 4 octet sequence number first
    payload = struct.pack('>I', seq) + pdu
    u = struct.pack('>HHHH', 40000, 17220, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), seq, 0, 1, 17, 0,
                     bytes([192, 168, 1, 1]), bytes([224, 0, 0, 1]))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return bytes.fromhex('01005e000001') + SRC + struct.pack('>H', 0x0800) + ip + u

main = [
    eth(maap_pdu(1, stream=0x1122334455667788, req=bytes.fromhex('91e0f0001000'), rcount=8)),     # probe
    eth(maap_pdu(2, stream=0x1122334455667788, req=bytes.fromhex('91e0f0001000'), rcount=8,
                 conf=bytes.fromhex('91e0f0001004'), ccount=2)),                                    # defend
    eth(maap_pdu(3, stream=0x1122334455667788, req=bytes.fromhex('91e0f0001000'), rcount=8)),      # announce
    eth(maap_pdu(0)),                      # reserved 0
    eth(maap_pdu(4)),                      # reserved 4
    eth(maap_pdu(5)),                      # reserved 5
    eth(maap_pdu(0xf, stream=0xffffffffffffffff, req=b'\xff' * 6, rcount=0xffff,
                 conf=b'\xff' * 6, ccount=0xffff, ver=0x1f, dlen=0x7ff)),                           # unknown type, all ones
    eth(maap_pdu(1, ver=0, dlen=0)),       # version and data length zero
    eth(maap_pdu(1, sv=1, rcount=0xfd00)), # sv bit set
    udp(maap_pdu(1, stream=1, rcount=4), 1),   # IEEE 1722 over UDP
    udp(maap_pdu(2, stream=1, rcount=4, conf=bytes.fromhex('91e0f0002000'), ccount=1), 2),
    udp(maap_pdu(3, stream=1, rcount=4), 3),
]
mal = [
    eth(maap_pdu(1))[:14 + 2],             # truncated, message type only
    eth(maap_pdu(1))[:14 + 20],            # truncated in the request count (probe)
    eth(maap_pdu(2))[:14 + 24],            # truncated in the conflict address (defend)
    eth(maap_pdu(3))[:14 + 27],            # truncated in the conflict count
    eth(maap_pdu(0))[:14 + 24],            # reserved type, truncated in the tree only
    eth(maap_pdu(0))[:14 + 10],            # reserved type, truncated in the stream ID
]
out = sys.argv[1]
pcap(os.path.join(out, 'maap-coverage.pcap'), main)
pcap(os.path.join(out, 'maap-coverage-malformed.pcap'), mal)
