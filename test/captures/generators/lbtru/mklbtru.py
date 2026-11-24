#!/usr/bin/env python3
# Generates test/captures/lbtru_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the LBT-RU (Ultra Messaging reliable unicast over UDP) coverage captures.
# Usage: mklbtru.py <outdir> [-v]
# Source ports 14380-14389 and receiver ports 14360-14379 are what the
# default heuristic looks for; every packet is built with struct and uses
# addresses from 192.0.2.0/24.
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def udp_frame(payload, src, dst, sport, dport):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, ip4(dst)[3]]) + bytes([2, 0, 0, 0, 0, ip4(src)[3]]) + b'\x08\x00'
    return eth + ip + udp


class Cap:
    def __init__(self):
        self.pk = []
        self.notes = []

    def add(self, d):
        self.pk.append(d)
        return len(self.pk)

    def mark(self, label):
        self.notes.append((len(self.pk) + 1, label))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, d in enumerate(self.pk):
                f.write(struct.pack('<IIII', 1700000000 + i // 1000, (i % 1000) * 1000, len(d), len(d)))
                f.write(d)


def lbmc(data=b'payload', tidx=1, sqn=1):
    return struct.pack('!BBHII', 0x00, 0, 12 + len(data), tidx, sqn) + data


# ---- LBT-RU packets ----------------------------------------------------------
DATA, SM, NAK, NCF, ACK, CREQ, RST = 0, 2, 3, 4, 5, 6, 7
NH_DATA, NH_SID, NH_CID = 0, 1, 2
SID = 0x11223344


def sid_opt(sid=SID, nxt=NH_DATA, flags=0, hlen=8):
    return struct.pack('!BBHI', nxt, hlen, flags, sid)


def cid_opt(cid=0x55667788, nxt=NH_DATA, flags=0, hlen=8):
    return struct.pack('!BBHI', nxt, hlen, flags, cid)


def head(ptype, nxt, fr, ver=0):
    return struct.pack('!BBH', (ver << 4) | ptype, nxt, fr)


def data(sqn, trail=0, rx=False, opts=None, nxt=NH_SID, payload=None, fr=0):
    if opts is None:
        opts = sid_opt()
    if payload is None:
        payload = lbmc(b'msg%d' % sqn, 1, sqn)
    return head(DATA, nxt, (0x4000 if rx else 0) | fr) + struct.pack('!II', sqn, trail) + opts + payload


def sm(sm_sqn, lead, trail, syn=False, opts=None, nxt=NH_SID):
    if opts is None:
        opts = sid_opt()
    return head(SM, nxt, 0x8000 if syn else 0) + struct.pack('!III', sm_sqn, lead, trail) + opts


def nak(sqns, fmt=0, num=None, opts=None, nxt=NH_SID, res=0):
    if opts is None:
        opts = sid_opt()
    return (head(NAK, nxt, res) + struct.pack('!HH', len(sqns) if num is None else num, fmt) +
            b''.join(struct.pack('!I', s) for s in sqns) + opts)


def ncf(sqns, reason=0, fmt=0, trail=0, num=None, opts=None, nxt=NH_SID, res=0):
    if opts is None:
        opts = sid_opt()
    return (head(NCF, nxt, res) + struct.pack('!IHBB', trail, len(sqns) if num is None else num, 0, (reason << 4) | fmt) +
            b''.join(struct.pack('!I', s) for s in sqns) + opts)


def ack(sqn, opts=None, nxt=NH_SID, res=0):
    if opts is None:
        opts = sid_opt()
    return head(ACK, nxt, res) + struct.pack('!I', sqn) + opts


def creq(req=0, opts=None, nxt=NH_SID):
    if opts is None:
        opts = sid_opt()
    return head(CREQ, nxt, req) + opts


def rst(reason=0, opts=None, nxt=NH_SID):
    if opts is None:
        opts = sid_opt()
    return head(RST, nxt, reason) + opts


SRC = '192.0.2.1'
R1 = '192.0.2.50'
R2 = '192.0.2.51'


def build_main(c):
    S = lambda p, rcv=R1, rport=14360, sport=14380: c.add(udp_frame(p, SRC, rcv, sport, rport))
    Rx = lambda p, rcv=R1, rport=14360, sport=14380: c.add(udp_frame(p, rcv, SRC, rport, sport))
    c.mark('connection setup: CREQ (SYN) with SID, SM with SYN, ACK; data with SID and CID option chain')
    Rx(creq(0))
    S(sm(0, 0, 0, syn=True))
    Rx(ack(0))
    S(data(0))
    S(data(1, trail=0, opts=sid_opt(nxt=NH_CID) + cid_opt(), nxt=NH_SID))
    S(data(2, trail=1, opts=sid_opt(flags=0x8000, nxt=NH_CID) + cid_opt(flags=0x8000), nxt=NH_SID))
    S(data(3, trail=1, opts=cid_opt(nxt=NH_SID) + sid_opt(), nxt=NH_CID))
    Rx(ack(1))
    Rx(ack(3))
    c.mark('SM, gap in DATA (sqn 5), NAK (selective, several), NCF with every reason, retransmission')
    S(sm(1, 3, 1))
    S(data(5, trail=1))
    S(data(6, trail=1))
    Rx(nak([4]))
    Rx(nak([4, 7, 8], fmt=0))
    Rx(nak([], fmt=1, res=0x0102))
    for r in (0, 1, 2, 3, 9):
        S(ncf([4] * (1 + r % 2), reason=r, trail=1))
    S(ncf([], reason=0, fmt=0, res=0x0304))
    S(data(4, trail=1, rx=True))
    S(data(7, trail=1))
    S(data(7, trail=1))                 # duplicate
    S(data(6, trail=1))                 # out of order
    S(data(8, trail=1, rx=True))
    S(data(10, trail=1))                # gap
    S(data(9, trail=1))                 # out of order
    S(sm(2, 10, 1))
    S(sm(5, 10, 1))                     # SM gap
    S(sm(3, 10, 1))                     # SM out of order
    S(sm(3, 10, 1))                     # SM duplicate
    S(sm(6, 10, 1, syn=True))
    Rx(ack(10))
    Rx(ack(10))
    Rx(creq(0))
    Rx(creq(1))                         # unknown request value
    c.mark('RST with default reason and with an unknown reason (reproducer of the RST option offset)')
    S(rst(0))
    S(rst(5))
    c.mark('options: DATA without any option (session 0), SM/NAK/ACK/CREQ/RST without option')
    S(data(40, opts=b'', nxt=NH_DATA), R1, 14361)
    S(sm(9, 9, 9, opts=b'', nxt=NH_DATA), R1, 14361)
    S(nak([1], opts=b'', nxt=NH_DATA), R1, 14361)
    S(ack(7, opts=b'', nxt=NH_DATA), R1, 14361)
    S(creq(0, opts=b'', nxt=NH_DATA), R1, 14361)
    S(rst(0, opts=b'', nxt=NH_DATA), R1, 14361)
    c.mark('second receiver of the same source and session (client 2), third source port')
    S(data(0), R2, 14362)
    S(data(1), R2, 14362)
    S(sm(0, 1, 0), R2, 14362)
    Rx(nak([1]), R2, 14362)
    Rx(ack(1), R2, 14362)
    S(data(0), R2, 14362, 14381)
    S(data(1, opts=sid_opt(sid=0x99887766)), R2, 14362, 14381)
    c.mark('DATA without payload and with an LBMC header only')
    S(data(60, payload=b''))
    S(data(61, payload=lbmc(b'')))
    c.mark('110 DATA packets with sequence number 50 (reproducer of the sequence list; needs sequence analysis)')
    for i in range(110):
        S(data(50, trail=50, rx=(i == 2), payload=lbmc(b'x', 1, 50)), R2, 14363)
    c.mark('end of main capture')


def build_malformed(c):
    S = lambda p, rcv=R1, rport=14360, sport=14380: c.add(udp_frame(p, SRC, rcv, sport, rport))
    Rx = lambda p, rcv=R1, rport=14360, sport=14380: c.add(udp_frame(p, rcv, SRC, rport, sport))
    c.mark('valid packets so that the transport exists')
    Rx(creq(0)); S(sm(0, 0, 0, syn=True)); S(data(0))
    c.mark('truncated: every packet type cut after the common header and inside every part')
    d = data(1)
    for cut in (1, 2, 3, 4, 7, 11, 12, 13, 16, 17, 19):
        S(d[:cut])
    s = sm(1, 1, 1)
    for cut in (4, 8, 12, 15, 16, 19):
        S(s[:cut])
    n = nak([1, 2, 3])
    for cut in (4, 6, 7, 8, 11, 15, 19):
        Rx(n[:cut])
    f = ncf([1, 2, 3], reason=2)
    for cut in (4, 8, 10, 11, 12, 15, 19):
        S(f[:cut])
    a = ack(5)
    for cut in (4, 6, 7, 8, 11, 15):
        Rx(a[:cut])
    for cut in (3, 4, 5, 8):
        Rx(creq(0)[:cut])
        S(rst(0)[:cut])
    c.mark('NAK/NCF with a count larger than the data')
    Rx(nak([1], num=3))
    Rx(nak([1], num=0xffff))
    S(ncf([1], num=3))
    S(ncf([1], num=0xffff))
    c.mark('zero length option headers (SID, CID, unknown) and option headers cut short')
    S(data(2, opts=sid_opt(hlen=0)))
    S(data(3, opts=cid_opt(hlen=0), nxt=NH_CID))
    S(data(4, opts=struct.pack('!BBH', 0, 0, 0) + b'\0' * 4, nxt=9))
    S(data(5, opts=b'', nxt=NH_SID))
    S(data(6, opts=b'\x00', nxt=NH_SID))
    S(data(7, opts=b'\x00\x08\x00\x00\x11', nxt=NH_SID))
    S(data(8, opts=b'\x00\x08\x00\x00\x11', nxt=NH_CID))
    S(data(9, opts=b'\x00\x20\x00\x00', nxt=9))
    S(sm(2, 2, 2, opts=b'', nxt=NH_SID))
    Rx(creq(0, opts=b'', nxt=NH_CID))
    Rx(rst(0, opts=b'\x00', nxt=NH_SID))
    c.mark('unknown option headers (error expert info): long and chained to SID')
    S(data(41, opts=struct.pack('!BBH', NH_DATA, 12, 0) + b'\xaa' * 8, nxt=9), R1, 14361)
    S(data(42, opts=struct.pack('!BBH', NH_SID, 8, 0) + b'\xbb' * 4 + sid_opt(), nxt=9), R1, 14361)
    c.mark('DATA without payload / LBMC cut short, unknown packet types, different versions')
    S(data(10, payload=b'\x00\x00'))
    S(data(11, payload=lbmc(b'abcdef')[:10]))
    for t in (1, 8, 9, 15):
        S(head(t, 0, 0) + b'\0' * 12)
    S(head(DATA, NH_SID, 0, ver=1) + struct.pack('!II', 1, 1) + sid_opt() + lbmc())
    c.mark('heuristic rejects: ports outside the ranges, both ports in the same range, short packets')
    c.add(udp_frame(data(1), SRC, R1, 14390, 14360))
    c.add(udp_frame(data(1), SRC, R1, 14380, 14380))
    c.add(udp_frame(data(1), SRC, R1, 14360, 14361))
    c.add(udp_frame(data(1), SRC, R1, 14380, 14400))
    c.add(udp_frame(data(1), SRC, R1, 14370, 14390))
    c.add(udp_frame(b'\0', SRC, R1, 14380, 14360))
    c.mark('end of malformed capture')


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    m = Cap(); build_main(m); m.write(os.path.join(OUT, 'lbtru-coverage.pcap'))
    x = Cap(); build_malformed(x); x.write(os.path.join(OUT, 'lbtru-coverage-malformed.pcap'))
    if VERBOSE:
        for name, cc in (('lbtru-coverage.pcap', m), ('lbtru-coverage-malformed.pcap', x)):
            print(name, len(cc.pk), 'frames')
            for n, l in cc.notes:
                print('  %4d  %s' % (n, l))
