#!/usr/bin/env python3
# Generates test/captures/nasdaq_itch_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic Nasdaq TotalView-ITCH coverage captures.

Usage: mknasdaq-itch.py <outdir>

ITCH has no port of its own: it is reached through Nasdaq-SoupTCP (sequenced
and unsequenced data packets) or MoldUDP64.  Both need Decode As:
    -d tcp.port==6000,nasdaq_soup           (the SoupTCP stream)
    -d udp.port==6002,moldudp64 -d moldudp64.payload,nasdaq_itch  (not used here)
nasdaq-itch-coverage.pcap: a SoupTCP stream on TCP 6000 whose sequenced data
packets carry every ITCH 3.0 message type, the ITCH 2.0 forms (8 digit
millisecond prefix, Chi-X big messages) and unknown types.
nasdaq-itch-coverage-malformed.pcap: truncated messages (not added to the tree).
"""
import struct
import sys
import os


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Pcap:
    def __init__(self):
        self.pkts = []
        self.ipid = 1

    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)


class Flow:
    def __init__(self, pcap, cport, sport=6000, cip='192.0.2.1', sip='192.0.2.2'):
        self.pcap = pcap
        self.c = (bytes(map(int, cip.split('.'))), cport, b'\x02\x00\x00\x00\x00\x01')
        self.s = (bytes(map(int, sip.split('.'))), sport, b'\x02\x00\x00\x00\x00\x02')
        self.seq = {True: 1000, False: 5000}

    def seg(self, from_client, payload):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        pseudo = src[0] + dst[0] + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.pcap.ipid, 0, 64, 6, 0, src[0], dst[0])
        self.pcap.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pcap.pkts.append(dst[2] + src[2] + b'\x08\x00' + ip + tcp + payload)
        self.seq[from_client] = (seq + len(payload)) & 0xffffffff

    def s2c(self, *b):
        self.seg(False, b''.join(b))

    def c2s(self, *b):
        self.seg(True, b''.join(b))


def line(kind, body=b''):
    return kind + body + b'\n'


def seq(itch):          # a sequenced data packet
    return line(b'S', itch)


def num(n, w):
    return b'%0*d' % (w, n)


def stock(s):
    return s.encode().ljust(6)


def ref(n):
    return num(n, 9)


def price(p, big=False):
    return num(p, 19 if big else 10)


def shares(n, big=False):
    return num(n, 10 if big else 6)


MATCH = b'000000123'


def itch3():
    m = []
    m.append(b'T' + num(37800, 5))
    m.append(b'M' + num(123, 3))
    for ev in b'OSQMEC':
        m.append(b'S' + bytes([ev]))
    m.append(b'S' + b'Z')                                                      # unknown event code
    for cat in b'TQGS ':
        m.append(b'R' + stock('ABCD') + bytes([cat]) + b'D' + num(100, 6) + b'Y')
    for fin in b'DEQSGHJK ':
        m.append(b'R' + stock('EFGH') + b'Q' + bytes([fin]) + num(100, 6) + b'N')
    m.append(b'H' + stock('ABCD') + b'T' + b' ' + b'    ')
    m.append(b'H' + stock('ABCD') + b'H' + b' ' + b'IPO1')
    m.append(b'A' + ref(1) + b'B' + shares(500) + stock('ABCD') + price(1234500))
    m.append(b'A' + ref(2) + b'S' + shares(100) + stock('ABCD') + price(1234600))
    m.append(b'F' + ref(3) + b'B' + shares(300) + stock('ABCD') + price(1000000) + b'NSDQ')
    m.append(b'E' + ref(1) + shares(200) + MATCH)
    m.append(b'C' + ref(2) + shares(50) + MATCH + b'Y' + price(1234650))
    m.append(b'C' + ref(2) + shares(50) + MATCH + b'N' + price(99))
    m.append(b'X' + ref(3) + shares(100))
    m.append(b'D' + ref(3))
    m.append(b'P' + ref(0) + b'B' + shares(75) + stock('ABCD') + price(1234550) + MATCH)
    m.append(b'Q' + shares(10000) + stock('ABCD') + price(1234500) + MATCH + b'O')
    m.append(b'Q' + shares(10000) + stock('ABCD') + price(1234500) + MATCH + b'C')
    m.append(b'B' + MATCH)
    m.append(b'I' + stock('ABCD') + b'O')
    # Chi-X message types are only valid in ITCH 2.0: unknown here
    m.append(b'a' + ref(5) + b'B' + shares(1, True) + stock('ABCD') + price(5, True))
    m.append(b'Y' + b'unknown message with some text')
    return m


def itch2():
    ts = b'12345678'
    m = []
    m.append(ts + b'A' + ref(11) + b'B' + shares(500) + stock('WXYZ') + price(1234500) + b'Y')
    m.append(ts + b'F' + ref(12) + b'S' + shares(500) + stock('WXYZ') + price(1234500) + b'MPID')
    m.append(ts + b'E' + ref(11) + shares(100) + MATCH)
    m.append(ts + b'C' + ref(12) + shares(100) + MATCH + b'Y' + price(1234500))
    m.append(ts + b'X' + ref(12) + shares(10))
    m.append(ts + b'D' + ref(12))
    m.append(ts + b'P' + ref(0) + b'S' + shares(7) + stock('WXYZ') + price(1) + MATCH)
    m.append(ts + b'S' + b'O')
    m.append(ts + b'T' + b'x')                       # seconds are not a version 2 message
    # Chi-X big messages
    m.append(ts + b'a' + ref(21) + b'B' + shares(123456, True) + stock('CHIX') + price(123456789, True) + b'Y')
    m.append(ts + b'p' + ref(0) + b'S' + shares(77, True) + stock('CHIX') + price(5000000, True) + MATCH)
    m.append(ts + b'e' + ref(21) + shares(1000, True) + MATCH)
    m.append(ts + b'x' + ref(21) + shares(20, True))
    return m


def build_main(pc):
    f = Flow(pc, 50001)
    f.c2s(line(b'L', b'user01' + b'secret    ' + b'SESSION001' + b'0000000001'))
    f.s2c(line(b'A', b'SESSION001' + b'0000000001'))
    msgs = itch3()
    # one ITCH message per sequenced data packet, four per TCP segment
    for i in range(0, len(msgs), 4):
        f.s2c(*[seq(x) for x in msgs[i:i + 4]])
    for x in itch2():
        f.s2c(seq(x))
    # the same messages as unsequenced data from the client
    f.c2s(line(b'U', msgs[2]))
    f.c2s(line(b'U', msgs[12]))
    f.s2c(line(b'H'))
    f.c2s(line(b'O'))


def build_malformed(pc):
    f = Flow(pc, 50101)
    f.s2c(seq(b'A' + ref(1) + b'B' + shares(5)))                      # truncated add order
    f.s2c(seq(b'R' + stock('AB')))
    f.s2c(seq(b'12345678'))                                           # version 2 without a message type
    f.s2c(seq(b'T123'))
    f.s2c(seq(b'S'))
    f.s2c(line(b'S'))                                                 # SOUP data packet without a message
    f.s2c(seq(b'A' + ref(1) + b'B' + b'abcdef' + stock('ABCD') + b'notanumber'))   # non numeric fields
    f.s2c(seq(b'a' + ref(1) + b'B' + shares(5, True) + stock('ABCD') + price(5)))  # big message with a short price


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    pc = Pcap()
    build_main(pc)
    pc.write(os.path.join(out, 'nasdaq-itch-coverage.pcap'))
    n = len(pc.pkts)
    pc = Pcap()
    build_malformed(pc)
    pc.write(os.path.join(out, 'nasdaq-itch-coverage-malformed.pcap'))
    print('main frames:', n, 'malformed frames:', len(pc.pkts))


if __name__ == '__main__':
    main()
