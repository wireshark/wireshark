#!/usr/bin/env python3
# Generates test/captures/paltalk_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the Paltalk coverage captures. Usage: mkpaltalk.py <outdir> [-v]
# Paltalk is a TCP heuristic dissector (enabled by default): it claims a TCP
# stream when the source or the destination is in 199.106.0.0/15 (IPv4).
import os
import struct
import sys
from pcaplib import eth, ipv4, write_pcap

class Stream:
    def __init__(self, client, server, cport, sport):
        self.c, self.s, self.cp, self.sp = client, server, cport, sport
        self.cseq, self.sseq = 1000, 5000
    def _seg(self, src, dst, sp, dp, seq, ack, data):
        t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, 0x18, 65535, 0, 0) + data
        return eth(ipv4(6, t, src=src, dst=dst))
    def c2s(self, d):
        f = self._seg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, d); self.cseq += len(d); return f
    def s2c(self, d):
        f = self._seg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, d); self.sseq += len(d); return f

def ip6_tcp(sport, dport, data):
    src = bytes([0x20, 1, 0x0d, 0xb8] + [0] * 11 + [1]); dst = bytes([0x20, 1, 0x0d, 0xb8] + [0] * 11 + [2])
    t = struct.pack('!HHIIBBHHH', sport, dport, 1, 1, 0x50, 0x18, 65535, 0, 0) + data
    ip = struct.pack('!IHBB', 0x60000000, len(t), 6, 64) + src + dst
    return eth(ip + t, 0x86dd)

def pt(ptype, content, version=0x8a, length=None):
    return struct.pack('>HhH', ptype, version, len(content) if length is None else length) + content

def main_frames():
    F, marks = [], []
    def mark(n): marks.append((n, len(F) + 1))
    mark('client 192.0.2.10 to the Paltalk network 199.106.4.20: PDUs of several types, an empty PDU, two PDUs in one segment, a PDU split in two segments, server replies')
    t = Stream('192.0.2.10', '199.106.4.20', 49300, 5001)
    F.append(t.c2s(pt(0x0001, b'login payload')))
    F.append(t.s2c(pt(0x0002, b'welcome')))
    F.append(t.c2s(pt(0x0003, b'')))
    F.append(t.c2s(pt(0x0004, b'one') + pt(0x0005, b'two')))
    big = pt(0x0006, bytes(range(200)))
    F.append(t.c2s(big[:50])); F.append(t.c2s(big[50:]))
    F.append(t.s2c(pt(0x0007, b'x' * 300) + pt(0x0008, b'y')))
    mark('the Paltalk network is the source only, and the upper half of the /15 (199.107.0.0)')
    t2 = Stream('199.107.255.1', '192.0.2.11', 5002, 49301)
    F.append(t2.c2s(pt(0x1001, b'from the server side')))
    F.append(t2.s2c(pt(0x1002, b'ack')))
    mark('traffic that is not Paltalk: neither address in the network (199.108.0.1, 199.105.255.254), IPv6')
    t3 = Stream('192.0.2.12', '199.108.0.1', 49302, 5003)
    F.append(t3.c2s(pt(0x0001, b'not paltalk')))
    t4 = Stream('192.0.2.13', '199.105.255.254', 49303, 5004)
    F.append(t4.c2s(pt(0x0001, b'not paltalk either')))
    F.append(ip6_tcp(49304, 5005, pt(0x0001, b'ipv6')))
    return F, marks

def malformed_frames():
    F = []
    t = Stream('192.0.2.10', '199.106.4.21', 49310, 5001)
    F.append(t.c2s(struct.pack('>HhH', 1, 0x8a, 0xffff) + b'short'))     # length past the data (waits for more segments)
    t = Stream('192.0.2.10', '199.106.4.22', 49311, 5001)
    F.append(t.c2s(b'\x00\x01\x00'))                                      # header cut short
    t = Stream('192.0.2.10', '199.106.4.23', 49312, 5001)
    F.append(t.c2s(pt(1, b'abcd', length=20)))                            # length past the segment
    F.append(t.c2s(b'more'))
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'paltalk-coverage.pcap'), F)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'paltalk-coverage-malformed.pcap'), M)
    if '-v' in sys.argv:
        for n, s in marks: print(s, n)
        print(len(F), 'frames', len(M), 'malformed frames')
