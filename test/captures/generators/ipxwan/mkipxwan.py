#!/usr/bin/env python3
# Generates test/captures/ipxwan_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-ipxwan.c (IPX WAN, RFC 1362 and
the NLSP specification, carried in IPX socket 0x9004).

Usage: mkipxwan.py <outdir> [-v]

Writes ipxwan-coverage.pcap (clean) and ipxwan-coverage-malformed.pcap.
Everything is made up.
"""
import struct
import sys
import os

VERBOSE = '-v' in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith('-')]
OUT = args[0] if args else '.'

class Cap:
    def __init__(self):
        self.recs = []; self.ts = 1700000000; self.marks = []
    def mark(self, t):
        self.marks.append((len(self.recs) + 1, t))
    def pkt(self, p, caplen=None):
        self.ts += 1
        cl = len(p) if caplen is None else caplen
        self.recs.append(struct.pack('<IIII', self.ts, 0, cl, len(p)) + p[:cl])
    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            f.write(b''.join(self.recs))
        if VERBOSE:
            print(name, len(self.recs), 'frames')
            for i, (n, t) in enumerate(self.marks):
                end = self.marks[i + 1][0] - 1 if i + 1 < len(self.marks) else len(self.recs)
                print('  %d-%d  %s' % (n, end, t))

NA = b'\x02\x00\x00\x00\x00\x0a'
NB = b'\x02\x00\x00\x00\x00\x0b'

def ipx(payload, ptype=4, sock=0x9004):
    n = 30 + len(payload)
    h = struct.pack('!HHBB', 0xffff, n, 0, ptype) + struct.pack('!I', 0xb002) + NB + struct.pack('!H', sock)
    h += struct.pack('!I', 0xa001) + NA + struct.pack('!H', sock)
    p = h + payload
    return NB + NA + b'\x81\x37' + p + b'\0' * max(0, 46 - len(p))

def opt(num, accept, data, dlen=None):
    return struct.pack('!BBH', num, accept, len(data) if dlen is None else dlen) + data

def wan(ptype, nodeid, seq, opts, nopts=None, ident=b'WASM'):
    return ident + struct.pack('!BIBB', ptype, nodeid, seq, len(opts) if nopts is None else nopts) + b''.join(opts)

NAME = b'ROUTER-A'.ljust(48, b'\0')

def build():
    c = Cap()
    c.mark('Packet types: Timer Request/Response, Information Request/Response, Throughput Request/Response, Delay Request/Response, NAK, unknown type; no options')
    for t in (0, 1, 2, 3, 4, 5, 6, 7, 0xff, 9):
        c.pkt(ipx(wan(t, 0x01020304, t, [])))
    c.mark('Routing Type option for every value (RIP, NLSP, unnumbered RIP, on-demand, client-router, unknown) and accept values 0, 1, 3 and 2')
    for i, (rt, acc) in enumerate([(0, 1), (1, 1), (2, 0), (3, 3), (4, 1), (9, 2)]):
        c.pkt(ipx(wan(0, 0x0a0b0c0d, i, [opt(0, acc, bytes([rt]))])))
    c.mark('Timer request/response with RIP/SAP information exchange, NLSP information, raw throughput data, extended node ID, node number')
    c.pkt(ipx(wan(0, 0x11111111, 1, [opt(0, 1, b'\x00'), opt(1, 1, struct.pack('!HI', 0x0102, 0xa001) + NAME),
                                     opt(4, 1, b'\xde\xad\xbe\xef'), opt(5, 1, NA)])))
    c.pkt(ipx(wan(1, 0x22222222, 1, [opt(0, 1, b'\x00'), opt(1, 1, struct.pack('!HI', 0x0050, 0xb002) + b'ROUTER-B'.ljust(48, b'\0')),
                                     opt(4, 3, b'\x00\x00\x00\x00'), opt(5, 0, NB)])))
    c.mark('Reproducer of "IPXWAN: Fix the offsets of the NLSP throughput fields" (delay 0x11111111, throughput 0x22222222, request size 0x33333333, delta time 0x44444444), then the same options in other packets')
    c.pkt(ipx(wan(2, 0x01020304, 0, [opt(2, 1, struct.pack('!II', 0x11111111, 0x22222222)),
                                     opt(3, 1, struct.pack('!II', 0x33333333, 0x44444444))])))
    c.pkt(ipx(wan(3, 0x01020304, 1, [opt(2, 1, struct.pack('!II', 1500, 64000))])))
    c.pkt(ipx(wan(4, 0x01020304, 2, [opt(3, 1, struct.pack('!II', 2048, 17))])))
    c.pkt(ipx(wan(5, 0x01020304, 3, [opt(3, 1, struct.pack('!II', 2048, 1700)), opt(2, 1, struct.pack('!II', 18, 19))])))
    c.mark('Compression option: Telebit with options and slots, an unknown type with parameters, Pad, an unknown option, several options in one packet')
    c.pkt(ipx(wan(0, 5, 0, [opt(0x80, 1, b'\x00\x01\x10')])))
    c.pkt(ipx(wan(0, 5, 1, [opt(0x80, 1, b'\x00\x01\x10\xaa\xbb')])))
    c.pkt(ipx(wan(0, 5, 2, [opt(0x80, 1, b'\x07\x01\x02\x03\x04\x05')])))
    c.pkt(ipx(wan(0, 5, 3, [opt(0x80, 1, b'\x07')])))
    c.pkt(ipx(wan(0, 5, 4, [opt(0xff, 0, b'\x00' * 6)])))
    c.pkt(ipx(wan(0, 5, 5, [opt(0xff, 0, b'')])))
    c.pkt(ipx(wan(0, 5, 6, [opt(0x42, 1, b'unknown option data')])))
    c.pkt(ipx(wan(0, 5, 7, [opt(0, 1, b'\x01'), opt(0x80, 1, b'\x00\x00\x08'), opt(0x42, 1, b'zz'), opt(0xff, 0, b'\0\0')])))
    c.mark('Identifier other than WASM, sequence 255, node ID 0 and 0xffffffff, in a PEP and in an unknown packet type')
    c.pkt(ipx(wan(0, 0, 255, [], ident=b'ABCD')))
    c.pkt(ipx(wan(1, 0xffffffff, 0, [opt(0, 1, b'\x01')]), ptype=0))
    c.pkt(ipx(wan(1, 0xffffffff, 0, [opt(0, 1, b'\x01')]), ptype=17))
    c.write('ipxwan-coverage.pcap')

    m = Cap()
    m.mark('Wrong option lengths (Routing Type, RIP/SAP, NLSP info, raw throughput, extended node ID, node number, Compression 0 and Telebit < 3)')
    for num, ln in [(0, 2), (0, 0), (1, 10), (2, 4), (3, 12), (4, 2), (5, 4), (0x80, 0), (0x80, 0xf000)]:
        m.pkt(ipx(wan(0, 7, 0, [opt(num, 1, b'\x00' * min(ln, 64), dlen=ln)]) + b'\x00' * 0))
    m.pkt(ipx(wan(0, 7, 0, [opt(0x80, 1, b'\x00\x01')])))        # Telebit with 2 octets: expert, no options
    m.mark('Option count larger than the options present, option running past the end, header cut short, snaplen cut-offs')
    m.pkt(ipx(wan(0, 7, 0, [opt(0, 1, b'\x00')], nopts=3)))
    m.pkt(ipx(wan(0, 7, 0, [opt(0x42, 1, b'\x00' * 8, dlen=100)])))
    m.pkt(ipx(wan(0, 7, 0, [])[:8]))
    m.pkt(ipx(wan(0, 7, 0, [])[:3]))
    m.pkt(ipx(wan(0, 7, 0, [opt(1, 1, struct.pack('!HI', 1, 2) + NAME)])), caplen=14 + 30 + 11 + 4 + 20)
    m.pkt(ipx(wan(0, 7, 0, [opt(2, 1, struct.pack('!II', 1, 2))])), caplen=14 + 30 + 11 + 4 + 5)
    m.write('ipxwan-coverage-malformed.pcap')

build()
