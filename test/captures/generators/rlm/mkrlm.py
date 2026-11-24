#!/usr/bin/env python3
# Generates test/captures/rlm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- helpers (struct only) ----
import struct
import sys

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(s): return bytes(map(int, s.split('.')))

class Cap:
    def __init__(self, linktype=1):
        self.frames = []; self.linktype = linktype
        self.seq = {}; self.ipid = 1; self.ts = 1700000000.0
    def raw(self, data, caplen=None):
        self.frames.append((self.ts, bytes(data), caplen)); self.ts += 0.01
        return len(self.frames)
    def ip(self, src, dst, proto, payload, ttl=64, frag=0):
        self.ipid += 1
        h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), self.ipid, frag, ttl, proto, 0, ip4(src), ip4(dst))
        h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
        return h + payload
    def eth(self, pkt, et=0x0800, s=b'\x02\0\0\0\0\x01', d=b'\x02\0\0\0\0\x02'):
        return d + s + struct.pack('!H', et) + pkt
    def ip6(self, src, dst, nh, payload, hop=64):
        return struct.pack('!IHBB', 0x60000000, len(payload), nh, hop) + src + dst + payload
    def udp(self, src, dst, sp, dp, payload):
        u = struct.pack('!HHHH', sp, dp, 8+len(payload), 0) + payload
        return self.raw(self.eth(self.ip(src, dst, 17, u, ttl=1 if dst.startswith('224.') else 64)))
    def udp6(self, src, dst, sp, dp, payload):
        u = struct.pack('!HHHH', sp, dp, 8+len(payload), 0)
        ph = src + dst + struct.pack('!IBBBB', 8+len(payload), 0, 0, 0, 17)
        c = csum(ph + u + payload) or 0xffff
        u = u[:6] + struct.pack('!H', c) + payload
        return self.raw(self.eth(self.ip6(src, dst, 17, u), et=0x86dd,
                                 d=b'\x33\x33\0\0\0\x09'))
    def tcp(self, src, dst, sp, dp, payload, flags=0x18, seq=None, urp=0):
        k = (src, dst, sp, dp)
        if seq is None: seq = self.seq.get(k, 1000 + (sp * 7919 + dp) % 100000)
        self.seq[k] = seq + len(payload) + (1 if flags & 3 else 0)
        ack = self.seq.get((dst, src, dp, sp), 0)
        t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, urp) + payload
        return self.raw(self.eth(self.ip(src, dst, 6, t)))
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for ts, d, cl in self.frames:
                c = d if cl is None else d[:cl]
                f.write(struct.pack('<IIII', int(ts), int((ts % 1)*1e6), len(c), len(d)) + c)

def expdu(name, payload):
    n = name.encode(); pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload
# ---- end helpers ----
out = sys.argv[1] if len(sys.argv) > 1 else '.'
def rlm(typ, unk=0, tid=0, unk2=0, ver=2): return struct.pack('!BBHHH', ver, typ, unk, tid, unk2)
A, B = '192.0.2.10', '192.0.2.20'
c = Cap()
c.udp(A, B, 3001, 3001, rlm(1, tid=1))                       # 1 start request
c.udp(B, A, 3001, 3001, rlm(2, tid=1, unk2=0x0001))          # 2 start acknowledgement
c.udp(A, B, 3001, 3001, rlm(5, unk=0x0203, tid=2))           # 3 echo request
c.udp(B, A, 3001, 3001, rlm(6, unk=0x0203, tid=2, unk2=0xbeef))   # 4 echo reply
c.udp(A, B, 3015, 3015, rlm(9, tid=65535))                   # 5 unknown type 9, highest port
c.udp(A, B, 3002, 3002, rlm(3, tid=3))                       # 6 type 3 (not named), port 3002
c.udp(B, A, 3002, 3002, rlm(4, tid=3))                       # 7 type 4 (not named)
# not RLM: each fails one of the heuristic tests (Data over UDP)
c.udp(A, B, 3001, 3002, rlm(1))                              # 8 different ports
c.udp(A, B, 2999, 2999, rlm(1))                              # 9 port below 3000
c.udp(A, B, 3016, 3016, rlm(1))                              # 10 port above 3015
c.udp(A, B, 3001, 3001, rlm(1, ver=1))                       # 11 version 1
c.udp(A, B, 3001, 3001, rlm(1) + b'\0')                      # 12 nine octets
c.udp(A, B, 3001, 3001, b'\x02')                             # 13 one octet
c.write(out + '/rlm-coverage.pcap')
