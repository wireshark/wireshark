#!/usr/bin/env python3
# Generates test/captures/optommp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OptoMMP coverage captures: mkoptommp.py <outdir>.
OptoMMP is registered only for Decode As (tcp.port / udp.port), so the
capture has Exported PDU frames naming "optommp.udp" and "optommp.tcp"
(no Decode As needed), plus a UDP flow and a TCP stream on port 2001 that
need  -d udp.port==2001,optommp -d tcp.port==2001,optommp."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from wslib import pcapng, exported_pdu, udp, TCP, gz

def hdr(dest, tl, tcode):
    return struct.pack('!HBB', dest, tl << 2, tcode << 4)

def wq(dest, tl, src, off, data=0x11223344):
    return hdr(dest, tl, 0) + struct.pack('!HHII', src, 0xffff, off, data)

def wb(dest, tl, src, off, data, ext=0):
    return hdr(dest, tl, 1) + struct.pack('!HHIHH', src, 0xffff, off, len(data), ext) + data

def wr(dest, tl, src, rcode):
    return hdr(dest, tl, 2) + struct.pack('!HB', src, rcode << 4) + bytes(5)

def rq(dest, tl, src, off):
    return hdr(dest, tl, 4) + struct.pack('!HHI', src, 0xffff, off)

def rb(dest, tl, src, off, n):
    return hdr(dest, tl, 5) + struct.pack('!HHIHH', src, 0xffff, off, n, 0)

def rqr(dest, tl, src, rcode, data=0xdeadbeef):
    return hdr(dest, tl, 6) + struct.pack('!HB', src, rcode << 4) + bytes(5) + struct.pack('!I', data)

def rbr(dest, tl, src, rcode, data):
    return hdr(dest, tl, 7) + struct.pack('!HB', src, rcode << 4) + bytes(5) + struct.pack('!HH', len(data), 0) + data

OFFS = [0xf0100000, 0xf01c0010, 0xf01d4000, 0xf01e0100, 0xf0220000, 0xf0260004, 0xf02a0008, 0xf02e0000,
        0xf02f8000, 0xf0300000, 0xf0380000, 0xf0310400, 0xf0329000, 0xf0350000, 0xf0390000, 0xf03a0004,
        0xf03a1000, 0xf03a7f00, 0xf03a8000, 0xf03a8500, 0xf03a9000, 0xf03c0000, 0xf03d0000, 0xf03e0000,
        0xf03eb800, 0xf03fffc0, 0xf0400000, 0xf0500000, 0xf0600000, 0xf0700000, 0xf0800000, 0x00001000]

def pdus():
    p = []
    for i, o in enumerate(OFFS):
        p.append(rq(0x0001, i, 0x0002, o))
        p.append(rqr(0x0002, i, 0x0001, i % 16, 0x3f800000 + i))
    p.append(wq(0x8003, 1, 0x0002, 0xf0390000))                    # boot ID present
    p.append(wq(0x0003, 2, 0x0002, 0xf0500004, 0xcafef00d))
    p.append(wb(0x0003, 3, 0x0002, 0xf0100000, bytes(range(16))))
    p.append(wb(0x8003, 4, 0x0002, 0xf0100040, bytes(range(7))))   # not a multiple of 4
    p.append(wb(0x0003, 5, 0x0002, 0xf0100040, b''))               # empty block
    p.append(rb(0x0003, 6, 0x0002, 0xf0400000, 32))
    p.append(rbr(0x0002, 6, 0x0003, 0, bytes(range(32))))
    p.append(rbr(0x0002, 7, 0x0003, 8, bytes(range(3))))
    p.append(wr(0x0002, 8, 0x0003, 0))
    p.extend(wr(0x0002, 9, 0x0003, rc) for rc in (5, 6, 15))
    p.append(hdr(0x0001, 10, 3) + bytes(4))                        # unknown tcode 3, header only
    p.append(hdr(0x0001, 11, 9) + bytes(4))                        # unknown tcode 9, header only
    return p

def main(out):
    P = pdus()
    frames = []
    for i, d in enumerate(P):
        frames.append(exported_pdu('optommp.udp' if i % 2 == 0 else 'optommp.tcp', d))
    # UDP flow on port 2001
    for i, d in enumerate(P[:20]):
        frames.append(udp(d, '192.0.2.1', 40200, '192.0.2.2', 2001) if i % 2 == 0 else
                      udp(d, '192.0.2.2', 2001, '192.0.2.1', 40200))
    # TCP stream on port 2001: PDUs in single segments, split and coalesced
    c = TCP('192.0.2.1', 40201, '192.0.2.2', 2001)
    frames += c.handshake()
    frames.append(c.c2s(rq(1, 1, 2, 0xf0300000)))
    frames.append(c.s2c(rqr(2, 1, 1, 0)))
    big = wb(0x0003, 3, 0x0002, 0xf0100000, bytes(range(64)))
    frames.append(c.c2s(big[:6]))
    frames.append(c.c2s(big[6:30]))
    frames.append(c.c2s(big[30:]))
    frames.append(c.s2c(wr(2, 3, 1, 0) + rbr(2, 4, 1, 0, bytes(range(20))) + rqr(2, 5, 1, 0)))
    frames.append(c.c2s(hdr(1, 6, 3) + bytes(4)))                   # unknown tcode, 8 octets
    pcapng(os.path.join(out, 'optommp-coverage.pcapng'), frames)
    gz(os.path.join(out, 'optommp-coverage.pcapng'))
    # malformed: too short for the header fields
    bad = []
    for n in range(1, 12):
        bad.append(exported_pdu('optommp.udp', wq(0x8001, 1, 2, 0xf0100000)[:n]))
    for t in (1, 4, 5, 6, 7):
        bad.append(exported_pdu('optommp.udp', (hdr(1, 1, t) + bytes(12))[:12]))
        bad.append(exported_pdu('optommp.udp', (hdr(1, 1, t) + bytes(12))[:14]))
    bad.append(exported_pdu('optommp.udp', wb(1, 1, 2, 0xf0100000, bytes(8))[:20]))
    bad.append(exported_pdu('optommp.udp', wb(1, 1, 2, 0xf0100000, bytes(8))[:13] ))
    bad.append(exported_pdu('optommp.udp', rbr(1, 1, 2, 0, bytes(64))[:30]))
    bad.append(exported_pdu('optommp.udp', rbr(1, 1, 2, 0, bytes(6))[:17]))
    bad.append(exported_pdu('optommp.tcp', hdr(1, 1, 1)))              # PDU needing more data than present
    pcapng(os.path.join(out, 'optommp-coverage-malformed.pcapng'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
