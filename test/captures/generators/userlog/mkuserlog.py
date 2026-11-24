#!/usr/bin/env python3
# Generates test/captures/userlog_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the H3C UserLog coverage captures (packet-userlog.c).

usage: mkuserlog.py <outdir> [-v]
Writes userlog-coverage.pcap and userlog-coverage-malformed.pcap (Ethernet,
IPv4 and UDP; the dissector has no port of its own, the tests use
-d udp.port==6000,userlog).
"""
import os
import socket
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []
PORT = 6000

NAT, BAS, FLOW = 1, 2, 4
TCP, UDP, ICMP = 6, 17, 1


class Pcap:
    def __init__(self, lt=1):
        self.b = bytearray(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, lt))
        self.n = 0
        self.t = 1700000000

    def pkt(self, data):
        self.t += 1
        self.b += struct.pack('<IIII', self.t, 0, len(data), len(data)) + data
        self.n += 1

    def write(self, fn):
        open(fn, 'wb').write(self.b)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp4(payload, sport=40000, dport=PORT, src='192.0.2.10', dst='192.0.2.20'):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp


def mark(p, name, start):
    RANGES.append((name, start + 1, p.n))


def ip(a):
    return socket.inet_aton(a)


def entry(proto=TCP, op=1, ipver=4, tos=0, sip='10.0.0.1', snat='198.51.100.1', dip='203.0.113.9', dnat='203.0.113.9',
          sport=1025, snatport=40001, dport=80, dnatport=80, start=1700000000, end=1700000060,
          inp=10, inb=1500, outp=12, outb=14000, r1=0, r2=0, r3=0):
    return (struct.pack('!BBBB', proto, op, ipver, tos) + ip(sip) + ip(snat) + ip(dip) + ip(dnat) +
            struct.pack('!HHHH', sport, snatport, dport, dnatport) +
            struct.pack('!IIIIIIIII', start, end, inp, inb, outp, outb, r1, r2, r3))


def header(version, logtype, count, ts=1700000000, reserved=bytes(8)):
    return struct.pack('!BBHI', version, logtype, count, ts) + reserved


assert len(entry()) == 64


def main_capture():
    p = Pcap()
    s0 = p.n
    p.pkt(udp4(header(1, NAT, 1) + entry()))                                          # NAT, V1
    p.pkt(udp4(header(3, BAS, 3) + entry(TCP, 1) + entry(UDP, 2, sport=5060, dport=5060) + entry(ICMP, 3)))   # BAS, V3
    p.pkt(udp4(header(3, FLOW, 8) + b''.join(entry(TCP, op, sport=2000 + op) for op in range(1, 9))))        # Flow, every operator
    p.pkt(udp4(header(1, NAT, 0)))                                                   # no log entries
    mark(p, 'versions, log types, operators', s0)
    s0 = p.n
    p.pkt(udp4(header(2, 9, 2, reserved=bytes(range(8))) + entry(253, 0) + entry(TCP, 9, ipver=6, tos=0xb8)))   # unknown version, type, operator and protocol
    p.pkt(udp4(header(3, FLOW, 1) + entry(r1=1, r2=2, r3=3) + b'trailing bytes'))     # data after the last entry
    p.pkt(udp4(header(3, FLOW, 22) + b''.join(entry(TCP, 1 + i % 8, sport=3000 + i) for i in range(22))))   # 22 entries: 1424 octets of UDP payload
    p.pkt(udp4(header(1, NAT, 1) + entry(sip='0.0.0.0', snat='255.255.255.255', sport=0, snatport=65535, inp=0xffffffff, inb=0xffffffff, start=0, end=0xffffffff)))  # extreme values
    mark(p, 'unknown values, trailing data, 22 entries, extreme values', s0)
    s0 = p.n
    p.pkt(udp4(b'\x01\x04\x00\x01abc'))                                                # 7 octets: shorter than the minimum, left to data
    p.pkt(udp4(b'', dport=PORT))                                                      # empty datagram
    mark(p, 'datagrams below the minimum length', s0)
    return p


def malformed_capture():
    p = Pcap()
    p.pkt(udp4(header(1, NAT, 1)[:8]))                                                # only the 8 octet minimum
    p.pkt(udp4(header(1, NAT, 1)[:12]))                                               # header cut inside
    p.pkt(udp4(header(1, NAT, 3) + entry() + entry()[:30]))                           # count 3, one and a half entries
    p.pkt(udp4(header(3, FLOW, 65535) + entry()))                                      # count far larger than the data
    p.pkt(udp4(header(1, NAT, 1) + entry()[:63]))                                      # entry cut by one octet
    p.pkt(udp4(header(1, BAS, 1)))                                                    # count 1, no entry at all
    return p


if __name__ == '__main__':
    p = main_capture()
    p.write(os.path.join(OUT, 'userlog-coverage.pcap'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'userlog-coverage-malformed.pcap'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-60s frames %d-%d' % (n, a, b))
        print('main', p.n, 'malformed', m.n)
