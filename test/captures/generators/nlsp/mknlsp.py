#!/usr/bin/env python3
# Generates test/captures/nlsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-nlsp.c (NetWare Link Services
Protocol, carried in IPX socket 0x9001).

Usage: mknlsp.py <outdir> [-v]

Writes nlsp-coverage.pcap (clean) and nlsp-coverage-malformed.pcap.
Everything is made up (system IDs and network numbers are placeholders).
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
NC = b'\x02\x00\x00\x00\x00\x0c'


def ipx(payload, sock=0x9001, dsock=None):
    n = 30 + len(payload)
    dsock = sock if dsock is None else dsock
    h = struct.pack('!HHBB', 0xffff, n, 0, 0) + struct.pack('!I', 0xb002) + NB + struct.pack('!H', dsock)
    h += struct.pack('!I', 0xa001) + NA + struct.pack('!H', sock)
    p = h + payload
    return NB + NA + b'\x81\x37' + p + b'\0' * max(0, 46 - len(p))


def clv(code, data, dlen=None):
    return struct.pack('!BB', code, len(data) if dlen is None else dlen) + data


def common(hlen, ptype, major=1, minor=1, irpd=0x83):
    return struct.pack('!BBBBBBH', irpd, hlen, minor, 0, ptype, major, 0)


def pad_len(hdr, body, plen=None):
    """packet length field = header + CLV area"""
    return len(hdr) + len(body) if plen is None else plen


def hello(clvs=b'', flags=0x11, sysid=NA, hold=30, prio=44, dr=NB + b'\x01',
          plen=None, hlen=27, major=1, ptype=15):
    # fixed part after the common header: flags, system ID, holding timer,
    # packet length, priority, designated router (system ID + pseudonode)
    total = 8 + 1 + 6 + 2 + 2 + 1 + 7 + len(clvs)
    b = struct.pack('!B', flags) + sysid + struct.pack('!HHB', hold, total if plen is None else plen, prio) + dr
    return common(hlen, ptype, major) + b + clvs


def wan_hello(clvs=b'', state=0, ctype=1, sysid=NA, hold=60, prio=1, circuit=3, plen=None):
    total = 8 + 1 + 6 + 2 + 2 + 1 + 1 + len(clvs)
    b = struct.pack('!B', (state << 6) | ctype) + sysid + struct.pack('!HHBB', hold, total if plen is None else plen, prio, circuit)
    return common(21, 17) + b + clvs


def lsp(clvs=b'', life=1200, lspid=NA + b'\x00\x00', seq=0x10, cksum=0xbeef, flags=0x03,
        plen=None, hlen=27, ptype=18, major=1):
    total = 8 + 2 + 2 + 8 + 4 + 2 + 1 + len(clvs)
    b = struct.pack('!HH', total if plen is None else plen, life) + lspid + struct.pack('!IHB', seq, cksum, flags)
    return common(hlen, ptype, major) + b + clvs


def entry(life, sysid, pseudo, num, seq, ck):
    return struct.pack('!H', life) + sysid + struct.pack('!BBIH', pseudo, num, seq, ck)


def csnp(clvs=b'', src=NA + b'\x00', start=b'\0' * 8, end=b'\xff' * 8, plen=None, hlen=33):
    total = 8 + 2 + 7 + 8 + 8 + len(clvs)
    return common(hlen, 24) + struct.pack('!H', total if plen is None else plen) + src + start + end + clvs


def psnp(clvs=b'', src=NA + b'\x00', plen=None, hlen=17):
    total = 8 + 2 + 7 + len(clvs)
    return common(hlen, 26) + struct.pack('!H', total if plen is None else plen) + src + clvs


AREA = clv(0xC0, struct.pack('!II', 0x0000a001, 0xffffff00))
AREA2 = clv(0xC0, struct.pack('!IIII', 0x0000a001, 0xffffff00, 0x0000b002, 0xffff0000))
NEIGH = clv(6, NB + NC)
MTU = clv(0xC5, struct.pack('!I', 1500))
MGT = clv(0xC1, struct.pack('!I', 0xa001) + NA + b'\x01' + b'\x08' + b'ROUTER-A')
MGT0 = clv(0xC1, struct.pack('!I', 0xa001) + NA + b'\x01\x00')
def link(flags=0x00, router=NB + b'\x02', mtu=1500, delay=2000, thr=10000000, media=2):
    return clv(0xC2, struct.pack('!B', flags) + b'\0\0\0' + router + struct.pack('!IIIH', mtu, delay, thr, media))
SVC = clv(0xC3, struct.pack('!B', 2) + struct.pack('!I', 0xa001) + NA + struct.pack('!HH', 0x0451, 0x0004) + b'FILESERVER\0')
SVC0 = clv(0xC3, struct.pack('!B', 1) + struct.pack('!I', 0xa001) + NA + struct.pack('!HH', 0x0452, 0x0007))
EXT = clv(0xC4, struct.pack('!BIH', 3, 0xc001, 5) + struct.pack('!BIH', 1, 0xc002, 0xffff))
UNK = clv(0x55, b'unknown clv')


def build():
    c = Cap()
    c.mark('L1 Hello (LAN): no CLVs; multicast flag set and clear; circuit types reserved, level 1, level 2, level 1+2; designated router; CLVs area addresses (one, two), neighbors (one, two), local MTU, an unknown CLV, all CLVs together')
    c.pkt(ipx(hello()))
    c.pkt(ipx(hello(flags=0x01)))
    for ct in (0, 2, 3):
        c.pkt(ipx(hello(flags=0x10 | ct)))
    c.pkt(ipx(hello(AREA, hold=0xffff, prio=0x7f)))
    c.pkt(ipx(hello(AREA2)))
    c.pkt(ipx(hello(NEIGH)))
    c.pkt(ipx(hello(NEIGH + clv(6, NA + NB))))
    c.pkt(ipx(hello(MTU)))
    c.pkt(ipx(hello(UNK)))
    c.pkt(ipx(hello(AREA + NEIGH + MTU + UNK)))
    c.pkt(ipx(hello(clv(0xC0, b'') + clv(6, b'') + MTU)))
    c.mark('WAN Hello: state up, initializing, down, an invalid state; circuit types; local WAN circuit ID; with CLVs')
    for st in (0, 1, 2, 3):
        c.pkt(ipx(wan_hello(state=st)))
    c.pkt(ipx(wan_hello(AREA + MTU, state=0, ctype=3, circuit=255)))
    c.pkt(ipx(wan_hello(NEIGH + UNK, state=1, ctype=2)))
    c.mark('L1 LSP: flags (partition repair, attached, database overloaded, router type 1 and 3), no CLVs, NR flag in the type byte, sequence number and lifetime values, pseudonode and LSP number')
    c.pkt(ipx(lsp()))
    c.pkt(ipx(lsp(flags=0x80 | 0x78 | 0x04 | 0x01, seq=0xffffffff, life=0)))
    c.pkt(ipx(lsp(flags=0x08 | 0x03, lspid=NB + b'\x05\x07')))
    c.pkt(ipx(lsp(ptype=18 | 0x80)))
    c.mark('LSP CLVs: area addresses, management information (with and without a name), link information (cost present with the cost, cost not present, several media types), services information (with and without a name), external routes (one, two entries), unknown CLV, everything in one packet')
    c.pkt(ipx(lsp(AREA2)))
    c.pkt(ipx(lsp(MGT)))
    c.pkt(ipx(lsp(MGT0)))
    c.pkt(ipx(lsp(link(0x00))))
    c.pkt(ipx(lsp(link(0x05, media=0x8000))))
    c.pkt(ipx(lsp(link(0x80, media=0x000a))))
    c.pkt(ipx(lsp(link(0x83, media=0x801f, router=NC + b'\x00'))))
    c.pkt(ipx(lsp(link(0x7f, media=0x0099))))
    c.pkt(ipx(lsp(SVC)))
    c.pkt(ipx(lsp(SVC0)))
    c.pkt(ipx(lsp(EXT)))
    c.pkt(ipx(lsp(clv(0xC4, struct.pack('!BIH', 1, 0xc001, 5)))))
    c.pkt(ipx(lsp(UNK)))
    c.pkt(ipx(lsp(AREA + MGT + link() + link(0x81) + SVC + SVC0 + EXT + UNK, seq=0x1234)))
    c.mark('CLV edge cases: zero length CLVs in the middle and at the end (the last one is silently dropped), a lone code octet at the end')
    c.pkt(ipx(lsp(clv(0xC0, b'') + clv(0xC4, b'') + AREA)))
    c.pkt(ipx(lsp(AREA + clv(0xC0, b''))))
    c.pkt(ipx(lsp(AREA + b'\xc0')))
    c.mark('L1 CSNP: no entries, one, three entries; other source, start and end IDs')
    c.pkt(ipx(csnp()))
    e1 = entry(1100, NA, 0, 0, 0x11, 0x1111)
    e2 = entry(900, NB, 1, 2, 0x22222222, 0x2222)
    e3 = entry(0xffff, NC, 0xff, 0xff, 0xffffffff, 0xffff)
    c.pkt(ipx(csnp(clv(9, e1))))
    c.pkt(ipx(csnp(clv(9, e1 + e2 + e3), src=NB + b'\x03', start=NA + b'\x00\x00', end=NC + b'\xff\xff')))
    c.pkt(ipx(csnp(clv(9, e1) + UNK)))
    c.mark('L1 PSNP: no entries, one, three entries, an unknown CLV')
    c.pkt(ipx(psnp()))
    c.pkt(ipx(psnp(clv(9, e2))))
    c.pkt(ipx(psnp(clv(9, e1 + e2 + e3), src=NC + b'\x02')))
    c.pkt(ipx(psnp(UNK + clv(9, e3))))
    c.mark('Header fields: unknown major version (warning), unknown minor version and IRPD, header length field other than the real one, unknown packet types (warning)')
    c.pkt(ipx(hello(major=2)))
    c.pkt(ipx(lsp(major=0)))
    c.pkt(ipx(common(27, 15, minor=9, irpd=0x00) + hello()[8:]))
    for t in (0, 1, 16, 19, 25, 27, 31):
        c.pkt(ipx(common(8, t) + b'\0' * 12))
    c.mark('Source or destination socket 0x9001 only (the other socket unknown or lower)')
    c.pkt(ipx(hello(), sock=0x9001, dsock=0x1234))
    c.pkt(ipx(hello(), sock=0x1234, dsock=0x9001))
    c.write('nlsp-coverage.pcap')

    m = Cap()
    m.mark('Packet length smaller than the header length (hello, WAN hello, LSP, CSNP, PSNP); the CSNP and PSNP just stop')
    m.pkt(ipx(hello(AREA, plen=10)))
    m.pkt(ipx(wan_hello(AREA, plen=5)))
    m.pkt(ipx(lsp(AREA, plen=3)))
    m.pkt(ipx(csnp(clv(9, e1), plen=3)))
    m.pkt(ipx(psnp(clv(9, e1), plen=0)))
    m.mark('Short CLV: length beyond the packet')
    m.pkt(ipx(hello(clv(0xC0, b'\0' * 8, dlen=40))))
    m.pkt(ipx(lsp(clv(0xC3, b'\0' * 4, dlen=200))))
    m.mark('Short entries in every CLV type')
    m.pkt(ipx(hello(clv(0xC0, struct.pack('!I', 1)))))                 # area address: network only
    m.pkt(ipx(hello(clv(0xC0, struct.pack('!II', 1, 2) + b'\0\0\0\0\0\0'))))  # second entry short
    m.pkt(ipx(hello(clv(0xC0, b'\0\0'))))
    m.pkt(ipx(hello(clv(6, NB + b'\0\0'))))
    m.pkt(ipx(hello(clv(0xC5, b'\0\0'))))
    m.pkt(ipx(lsp(clv(0xC1, b'\0\0'))))                               # mgt: < 4
    m.pkt(ipx(lsp(clv(0xC1, b'\0\0\0\1' + b'\0\0\0'))))               # < 6
    m.pkt(ipx(lsp(clv(0xC1, b'\0\0\0\1' + NA))))                      # no IPX version
    m.pkt(ipx(lsp(clv(0xC1, b'\0\0\0\1' + NA + b'\1'))))              # no name length
    m.pkt(ipx(lsp(clv(0xC1, b'\0\0\0\1' + NA + b'\1\x09ab'))))        # name too long
    for n in (0, 1, 2, 4, 8, 11, 15, 19, 23, 24):                      # link info cut at every field
        data = struct.pack('!B', 0) + b'\0\0\0' + NB + b'\x02' + struct.pack('!IIIH', 1, 2, 3, 4)
        m.pkt(ipx(lsp(clv(0xC2, data[:n]))))
    for n in (0, 1, 3, 5, 11, 13, 15, 17):                             # services info
        data = struct.pack('!B', 2) + struct.pack('!I', 1) + NA + struct.pack('!HH', 3, 4)
        m.pkt(ipx(lsp(clv(0xC3, data[:n]))))
    m.pkt(ipx(lsp(clv(0xC2, b'') + clv(0xC3, b'') + AREA)))          # empty link and services CLVs
    for data in (struct.pack('!B', 1), struct.pack('!BI', 1, 2), struct.pack('!BIHB', 1, 2, 3, 9)):
        m.pkt(ipx(lsp(clv(0xC4, data))))
    m.pkt(ipx(csnp(clv(9, e1[:10]))))
    m.pkt(ipx(psnp(clv(9, e1 + e2[:15]))))
    m.mark('Packets cut inside the header, and a packet length larger than the data (truncated frames)')
    for n in (1, 2, 5, 8, 12, 20, 26):
        m.pkt(ipx(hello(AREA)), caplen=14 + 30 + n)
    for n in (10, 20, 30, 33):
        m.pkt(ipx(lsp(AREA)), caplen=14 + 30 + n)
    m.pkt(ipx(csnp(clv(9, e1))), caplen=14 + 30 + 20)
    m.pkt(ipx(psnp(clv(9, e1))), caplen=14 + 30 + 12)
    m.pkt(ipx(hello(AREA, plen=2000)))
    m.pkt(ipx(lsp(AREA, plen=2000)))
    m.pkt(ipx(csnp(clv(9, e1), plen=2000)))
    m.pkt(ipx(psnp(clv(9, e1), plen=2000)))
    m.write('nlsp-coverage-malformed.pcap')


build()
