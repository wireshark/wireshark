#!/usr/bin/env python3
# Generates test/captures/ipsec_tcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-ipsec-tcp.c (TCP Encapsulation of
IPsec Packets, the Cisco VPN 3000 "TCPENCAP" trailer).

Usage: mkipsec-tcp.py <outdir> [-v]

Writes ipsec-tcp-coverage.pcap (clean) and ipsec-tcp-coverage-malformed.pcap.
All data is made up: ESP payloads are constant placeholder bytes, the
trailer "magic" fields are constant placeholders.
"""
import struct
import sys
import os

VERBOSE = '-v' in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith('-')]
OUT = args[0] if args else '.'

class Cap:
    def __init__(self):
        self.recs = []
        self.ts = 1700000000
        self.marks = []
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

M1 = b'\x02\x00\x00\x00\x00\x01'
M2 = b'\x02\x00\x00\x00\x00\x02'
A1 = b'\xc0\x00\x02\x01'
A2 = b'\xc0\x00\x02\x02'

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(proto, payload, src, dst):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

class Conn:
    """One TCP connection client (A1) -> server (A2)."""
    def __init__(self, cport, sport):
        self.c = (A1, A2, cport, sport)
        self.cseq = 1000
        self.sseq = 5000
    def seg(self, from_client, flags, data=b''):
        if from_client:
            s, d, sp, dp = self.c[0], self.c[1], self.c[2], self.c[3]
            seq, ack = self.cseq, self.sseq
            ms, md = M1, M2
        else:
            s, d, sp, dp = self.c[1], self.c[0], self.c[3], self.c[2]
            seq, ack = self.sseq, self.cseq
            ms, md = M2, M1
        t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0, 0x50, flags, 8192, 0, 0) + data
        if from_client:
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            self.sseq += len(data) + (1 if flags & 3 else 0)
        return md + ms + b'\x08\x00' + ip4(6, t, s, d)
    def open(self, cap):
        cap.pkt(self.seg(True, 0x02))
        cap.pkt(self.seg(False, 0x12))
        cap.pkt(self.seg(True, 0x10))
    def close(self, cap):
        cap.pkt(self.seg(True, 0x11))
        cap.pkt(self.seg(False, 0x11))
        cap.pkt(self.seg(True, 0x10))

MAGIC = b'\xc1\x5c\x00\x01\x02'    # placeholder, 5 octets
MAGIC2 = b'\x00\x01'

def trailer(proto, seq, direction=0, zero=b'\0\0\0\0', magic=MAGIC, magic2=MAGIC2):
    # 4 zero octets, 16 bit sequence, 16 bit direction/zero, 5 octets magic,
    # protocol (0x11 ISAKMP, 0x32 ESP), 2 octets
    return zero + struct.pack('!HH', seq, direction) + magic + bytes([proto]) + magic2

def esp(spi, seq, body):
    return struct.pack('!II', spi, seq) + body

def udp500(data, sport=500, dport=500):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0x1234) + data

def ike_hdr(init=b'\x11' * 8, resp=b'\0' * 8, exch=34, flags=0x08, mid=0, ln=28):
    return init + resp + struct.pack('!BBBBII', 0, 0x20, exch, flags, mid, ln)

P_ESP = 0x32
P_UDP = 0x11

def build():
    c = Cap()
    k = Conn(40001, 62001)
    c.mark('TCP handshake, ESP in TCPENCAP (server port 62001, found by the heuristic)')
    k.open(c)
    for i in range(3):
        c.pkt(k.seg(True, 0x18, esp(0xd0007000, i + 1, b'\x11\x22\x33\x44' * 4) + trailer(P_ESP, i)))
    c.pkt(k.seg(False, 0x18, esp(0xd0007001, 1, b'\x55' * 24) + trailer(P_ESP, 0)))
    c.mark('ISAKMP in TCPENCAP (UDP 500 to 500), both directions, and the ISAKMP direction values')
    c.pkt(k.seg(True, 0x18, udp500(ike_hdr()) + trailer(P_UDP, 1, 0x4000)))
    c.pkt(k.seg(False, 0x18, udp500(ike_hdr(resp=b'\x22' * 8, flags=0x28)) + trailer(P_UDP, 1, 0x0000)))
    c.mark('Other TCPENCAP variants: ESP with a nonzero "ESP zero" field (high bits only), a payload of exactly 9 octets before the trailer, sequence numbers 0 and 0xffff')
    c.pkt(k.seg(True, 0x18, esp(0xd0007000, 4, b'\x00' * 8) + trailer(P_ESP, 4, 0x1000)))
    c.pkt(k.seg(True, 0x18, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00' + trailer(P_ESP, 5)))
    c.pkt(k.seg(True, 0x18, esp(0xd0007000, 5, b'\x33' * 8) + trailer(P_ESP, 0)))
    c.pkt(k.seg(True, 0x18, esp(0xd0007000, 6, b'\x33' * 8) + trailer(P_ESP, 0xffff)))
    k.close(c)
    # Port 10000 is NDMP: a payload that is a valid NDMP header makes packet_is_tcpencap() give up
    # (check_if_ndmp), although the trailer is valid.  The "ESP header" below is a made-up NDMP record marker,
    # a sequence number that is a plausible timestamp and so on.
    kn = Conn(40030, 10000)
    c.mark('Connection on TCP port 10000 (NDMP): a valid-looking NDMP header in front of a valid TCPENCAP trailer is left to NDMP')
    kn.open(c)
    ndmp = struct.pack('!IIIIII', 0x80000030, 1, 0x60000000, 1, 0x00000101, 0) + b'\x00' * 4
    c.pkt(kn.seg(True, 0x18, ndmp + trailer(P_ESP, 1)))
    kn.close(c)
    # Once a TCP payload is not recognised, the rest of that connection is not tried again,
    # so each negative case has a connection of its own
    for n, (what, data) in enumerate([
            ('trailer protocol is neither UDP nor ESP', esp(0xd0007002, 1, b'\x00' * 16) + trailer(0x06, 1)),
            ('first trailer word is not zero', esp(0xd0007002, 2, b'\x00' * 16) + trailer(P_ESP, 2, zero=b'\0\0\0\1')),
            ('low 12 bits of the direction field are not zero', esp(0xd0007002, 3, b'\x00' * 16) + trailer(P_ESP, 3, direction=0x0001)),
            ('payload of 24 octets: not longer than the trailer plus 8', b'\x00' * 8 + trailer(P_ESP, 4))]):
        kn = Conn(40002 + n, 62002 + n)
        c.mark('Connection %d: not TCPENCAP (%s), no dissector, so TCP shows it as data' % (n + 2, what))
        kn.open(c)
        c.pkt(kn.seg(True, 0x18, data))
        kn.close(c)
    c.write('ipsec-tcp-coverage.pcap')

    m = Cap()
    k = Conn(40010, 62003)
    m.mark('TCPENCAP payloads whose UDP/ISAKMP part is bad: 0x01f401f4 followed by garbage (UDP length), an ISAKMP header cut short')
    kg = Conn(40012, 62005)
    kg.open(m)
    m.pkt(kg.seg(True, 0x18, b'\x01\xf4\x01\xf4' + b'\xee' * 16 + trailer(P_UDP, 6, 0x4000)))
    m.pkt(kg.seg(True, 0x18, udp500(b'\x11\x22\x33') + trailer(P_UDP, 7, 0x4000)))
    m.mark('Payloads of 20 and 22 octets: ESP header cut short inside TCPENCAP (needs Decode As, the heuristic wants more than 24 octets)')
    ks = Conn(40013, 62006)
    ks.open(m)
    m.pkt(ks.seg(True, 0x18, b'\xd0\x00\x71\x00' + trailer(P_ESP, 1)))
    m.pkt(ks.seg(True, 0x18, b'\xd0\x00\x71\x00\x00\x00' + trailer(P_ESP, 2)))
    m.mark('A connection learned as TCPENCAP by the heuristic, then packets that are too short for the trailer')
    k.open(m)
    m.pkt(k.seg(True, 0x18, esp(0xd0007100, 1, b'\x11' * 16) + trailer(P_ESP, 0)))
    m.pkt(k.seg(True, 0x18, b'\x00' * 10))
    m.pkt(k.seg(True, 0x18, b'\x01'))
    m.mark('Truncated trailer (1 and 2 octets missing from the capture, 3 and 4 missing: the heuristic gives up)')
    full = k.seg(True, 0x18, esp(0xd0007100, 2, b'\x11' * 16) + trailer(P_ESP, 1))
    k2 = Conn(40011, 62004)
    k2.open(m)
    f2 = k2.seg(True, 0x18, esp(0xd0007101, 1, b'\x11' * 16) + trailer(P_ESP, 0))
    m.pkt(f2, caplen=len(f2) - 1)
    f3 = k2.seg(True, 0x18, esp(0xd0007101, 2, b'\x11' * 16) + trailer(P_ESP, 1))
    m.pkt(f3, caplen=len(f3) - 2)
    f4 = k2.seg(True, 0x18, esp(0xd0007101, 3, b'\x11' * 16) + trailer(P_ESP, 2))
    m.pkt(f4, caplen=len(f4) - 3)
    f5 = k2.seg(True, 0x18, udp500(ike_hdr()) + trailer(P_UDP, 3, 0x4000))
    m.pkt(f5, caplen=len(f5) - 10)
    m.write('ipsec-tcp-coverage-malformed.pcap')

build()
