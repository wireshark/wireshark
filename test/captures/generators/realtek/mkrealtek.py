#!/usr/bin/env python3
# Generates test/captures/realtek_coverage.pcap.gz
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
BC = b'\xff' * 6
M1 = b'\x02\0\0\0\0\x01'; M2 = b'\x02\0\0\0\0\x02'; M3 = b'\x00\xe0\x4c\x12\x34\x56'
c = Cap()
def f(payload, d=BC, s=M1, pad=True):
    if pad: payload = payload.ljust(46, b'\0')
    c.raw(d + s + b'\x88\x99' + payload)
f(struct.pack('!BBH', 1, 0x00, 0xffff))                                                         # 1 RRCP Hello request
f(struct.pack('!BBHBB6sHI', 1, 0x80, 0xffff, 3, 25, M3, 0x8308, 0x00000000) , d=M2, s=M3)      # 2 RRCP Hello reply: ports, uplink MAC, chip, vendor id
f(struct.pack('!BBHHH', 1, 0x01, 0x1234, 0x0300, 0x0000), d=M2)                                # 3 RRCP Get request
f(struct.pack('!BBHHH', 1, 0x81, 0x1234, 0x0300, 0xbeef), d=M1, s=M2)                          # 4 RRCP Get reply
f(struct.pack('!BBHHH', 1, 0x02, 0x1234, 0x0301, 0x0001), d=M2)                                # 5 RRCP Set request
f(struct.pack('!BBH', 1, 0x05, 0x0000), d=M2)                                                  # 6 RRCP with an unknown opcode (5)
f(struct.pack('!BBH', 1, 0x82, 0x0000), d=M2)                                                  # 7 RRCP Set reply
f(b'\x02', d=BC)                                                                                # 8 REP, broadcast: echo request
f(b'\x02', d=M2, s=M3)                                                                          # 9 REP, unicast: echo reply
f(b'\x03' + b'\x00' * 10, d=bytes.fromhex('0180c2000001'))                                      # 10 RLDP (0x03)
f(b'\x23' + M3 + M1 + b'\x0d' + b'\0' * 20, d=bytes.fromhex('0180c2000001'))                   # 11 RLDP (0x23)
f(b'\x04\x01\x02\x03\x04')                                                                      # 12 unknown protocol 0x04 (DSA): no sub-dissector
f(b'\x99' + bytes(range(1, 20)))                                                                # 13 unknown protocol byte 0x99
f(b'\x00' + b'\x11' * 10, d=M2)                                                                 # 14 protocol 0
f(struct.pack('!BBHHH', 1, 0x01, 0x4321, 0x0000, 0x0000), pad=False, d=M2)                      # 15 RRCP Get request without padding
c.write(out + '/realtek-coverage.pcap')
m = Cap()
def g(payload, d=BC, s=M1):
    m.raw(d + s + b'\x88\x99' + payload)
g(b'\x01')                                                                                      # 1: RRCP with only the protocol octet (opcode missing)
g(struct.pack('!BBH', 1, 0x01, 0x1234))                                                         # 2: Get request without register fields
g(struct.pack('!BBHBB', 1, 0x80, 0xffff, 3, 25), d=M2)                                          # 3: Hello reply cut after the ports
g(b'')                                                                                          # 4: Realtek with no payload
m.write(out + '/realtek-coverage-malformed.pcap')
