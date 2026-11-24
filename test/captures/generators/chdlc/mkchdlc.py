#!/usr/bin/env python3
# Generates test/captures/chdlc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco HDLC and SLARP
dissectors (packet-chdlc.c).

A Cisco HDLC frame is an address octet (0x0f unicast, 0x8f multicast), a
control octet and a 16 bit protocol type, optionally followed at the end
by a 16 or 32 bit FCS (preference chdlc.fcs_type). OSI (0xfefe) frames
may carry a padding octet before the NLPID. SLARP (0x8035) is Cisco's
address resolution and keepalive protocol. Every packet is built from
scratch with struct; no captured traffic is used.

The captures are pcapng with link type 104 (Cisco HDLC); the enhanced
packet block flags give the direction (inbound, outbound or none), which
the dissector shows as DCE/DTE.

Usage: mkchdlc.py <output directory>

Writes:
  chdlc-coverage.pcapng            IPv4, IPv6, CDP, SLARP (every type),
                                   OSI with and without the padding octet
                                   (ES-IS, CLNP, IS-IS), unknown protocols,
                                   frames with a 16 and a 32 bit FCS, and
                                   the reproducer of the fix on the branch
  chdlc-coverage-malformed.pcapng  frames cut short and a SLARP keepalive
                                   with a bad reliability
"""

import os
import struct
import sys
import zlib

SRC = (192, 0, 2, 1)
DST = (198, 51, 100, 2)
INBOUND, OUTBOUND = 1, 2


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def ipv4(proto, payload, src=SRC, dst=DST, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp4(sport, dport, data, src=SRC, dst=DST):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


SRC6 = bytes.fromhex('20010db8000000000000000000000001')
DST6 = bytes.fromhex('20010db8000000000000000000000002')


def ipv6_udp(sport, dport, data):
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    pseudo = SRC6 + DST6 + struct.pack('>I3xB', len(u), 17)
    c = csum(pseudo + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    return struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + SRC6 + DST6 + u


def chdlc(proto, payload=b'', addr=0x0f):
    return struct.pack('>BBH', addr, 0, proto) + payload


def crc16_x25(data):
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xffff


def with_fcs16(f):
    return f + struct.pack('<H', crc16_x25(f))


def with_fcs32(f):
    return f + struct.pack('<I', zlib.crc32(f) & 0xffffffff)


# CDP (PID 0x2000 on Cisco HDLC), with a valid CDP checksum
def cdp_pdu():
    body = struct.pack('>HH', 1, 4 + 8) + b'router-1'
    pdu = struct.pack('>BBH', 2, 180, 0) + body
    return pdu[:2] + struct.pack('>H', csum(pdu)) + pdu[4:]


def slarp(code, a, b, rel=None):
    p = struct.pack('>I', code) + a + b
    if rel is not None:
        p += struct.pack('>H', rel)
    return p


NSAP_ES = bytes.fromhex('490001020000000000aa00')
NSAP_DST = bytes.fromhex('490001020000000000bb00')


def esis_esh():
    # number of source addresses, then length and NSAP of each
    sa = struct.pack('>BB', 1, len(NSAP_ES)) + NSAP_ES
    li = 9 + len(sa)
    return struct.pack('>BBBBBHH', 0x82, li, 1, 0, 0x02, 30, 0) + sa


def clnp_dt():
    addrs = (struct.pack('>B', len(NSAP_DST)) + NSAP_DST
             + struct.pack('>B', len(NSAP_ES)) + NSAP_ES)
    li = 9 + len(addrs)
    return struct.pack('>BBBBBHH', 0x81, li, 1, 32, 0x1c, li, 0) + addrs


def isis_psnp():
    # Level 1 PSNP, no TLVs: common header (8 octets), PDU length, source ID
    return (struct.pack('>BBBBBBBB', 0x83, 17, 1, 0, 26, 1, 0, 0)
            + struct.pack('>H', 17) + bytes.fromhex('02000000000100'))


def main_frames():
    M = []  # (frame, direction or None)
    # 1: IPv4 UDP, inbound (DCE -> DTE)
    M.append((chdlc(0x0800, ipv4(17, udp4(40000, 9, b'chdlc-ipv4'))), INBOUND))
    # 2: IPv6 UDP, outbound (DTE -> DCE)
    M.append((chdlc(0x86dd, ipv6_udp(40001, 9, b'chdlc-ipv6')), OUTBOUND))
    # 3: IPv4 to a multicast address, multicast HDLC address
    M.append((chdlc(0x0800, ipv4(17, udp4(40002, 9, b'mcast'), dst=(239, 1, 1, 9)),
                    addr=0x8f), None))
    # 4-7: SLARP request, reply, line keepalive and an unknown type
    M.append((chdlc(0x8035, slarp(0, bytes([0, 0, 0, 0]), bytes([0, 0, 0, 0]), 0xffff)), OUTBOUND))
    M.append((chdlc(0x8035, slarp(1, bytes([10, 1, 1, 1]), bytes([255, 255, 255, 252]), 0xffff)), INBOUND))
    M.append((chdlc(0x8035, slarp(2, struct.pack('>I', 17), struct.pack('>I', 16), 0xffff)), OUTBOUND))
    M.append((chdlc(0x8035, slarp(7, b'\x01\x02\x03\x04', b'\x05\x06\x07\x08', 0xffff)), None))
    # 8: CDP over Cisco HDLC
    M.append((chdlc(0x2000, cdp_pdu()), None))
    # 9: OSI with a padding octet before ES-IS
    M.append((chdlc(0xfefe, b'\x00' + esis_esh()), None))
    # 10-12: OSI without a padding octet: ES-IS, CLNP, IS-IS
    M.append((chdlc(0xfefe, esis_esh()), None))
    M.append((chdlc(0xfefe, clnp_dt()), None))
    M.append((chdlc(0xfefe, isis_psnp()), None))
    # 13: a protocol with no dissector (data, protocol column 0x1234)
    M.append((chdlc(0x1234, b'\xde\xad\xbe\xef'), None))
    # 14: reproducer of the fix on the branch (chdlc_no_payload): a frame
    #     with only the four octet header; the CLNS padding octet used to be
    #     read for every protocol, which threw an exception. A protocol
    #     with no dissector shows an empty frame; the original reproducer
    #     (IPv4 with no payload) is in the malformed capture, as IPv4
    #     itself rejects an empty packet.
    M.append((chdlc(0x1234), None))
    # 15-16: frames ending with a valid 16 bit and a valid 32 bit FCS
    #        (shown with chdlc.fcs_type 16-bit or 32-bit); the payload is
    #        data, so the FCS is part of it at the default preferences
    M.append((with_fcs16(chdlc(0x1234, b'\x01\x02\x03\x04')), INBOUND))
    M.append((with_fcs32(chdlc(0x1234, b'\x05\x06\x07\x08')), OUTBOUND))
    return M


def malformed_frames():
    B = []
    # 1: the original reproducer frame 1: IPv4 with no payload
    B.append((chdlc(0x0800), None))
    # 2: OSI with no octet after the header (padding octet read)
    B.append((chdlc(0xfefe), None))
    # 3: OSI with only the padding octet (no NLPID after it)
    B.append((chdlc(0xfefe, b'\x00'), None))
    # 4: shorter than the header
    B.append((b'\x0f\x00', None))
    # 5: SLARP keepalive with a reliability other than 0xffff
    B.append((chdlc(0x8035, slarp(2, struct.pack('>I', 3), struct.pack('>I', 2), 0x0000)), INBOUND))
    # 6: SLARP request and keepalive cut short
    B.append((chdlc(0x8035, slarp(0, b'\x0a\x00', b'')), None))
    B.append((chdlc(0x8035, slarp(2, b'\x00\x00\x00\x01', b'')), None))
    # 8: the original reproducer frame 2: unknown protocol with a 16 bit
    #    FCS (bad at default preferences only in the sense that it is data)
    B.append((chdlc(0x1234, b'\xde\xad\xbe\xef\x55\x66'), None))
    # 9: one octet only, with a 32 bit FCS preference this is shorter than
    #    the FCS
    B.append((chdlc(0x1234, b'\x01'), None))
    return B


def pad4(b):
    return b + b'\0' * (-len(b) % 4)


def write_pcapng(path, frames, linktype=104):
    out = bytearray()
    shb_body = struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)
    out += struct.pack('<II', 0x0a0d0d0a, 12 + len(shb_body)) + shb_body + struct.pack('<I', 12 + len(shb_body))
    idb_body = struct.pack('<HHI', linktype, 0, 65535)
    out += struct.pack('<II', 1, 12 + len(idb_body)) + idb_body + struct.pack('<I', 12 + len(idb_body))
    for i, (p, direction) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        body = struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(p), len(p)) + pad4(p)
        if direction is not None:
            body += struct.pack('<HHI', 2, 4, direction) + struct.pack('<HH', 0, 0)
        out += struct.pack('<II', 6, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))
    with open(path, 'wb') as f:
        f.write(out)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'chdlc-coverage.pcapng'), main_frames())
    write_pcapng(os.path.join(out, 'chdlc-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
