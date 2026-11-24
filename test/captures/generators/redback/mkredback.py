#!/usr/bin/env python3
# Generates test/captures/redback_coverage.pcap.gz
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
def ipv4(src='10.0.0.1', dst='10.0.0.2', payload=struct.pack('!HHHH', 5000, 5001, 8, 0)):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 7, 0, 64, 17, 0, ip4(src), ip4(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload
def ipv6():
    return struct.pack('!IHBB', 0x60000000, 8, 59, 64) + bytes(15) + b'\x01' + bytes(15) + b'\x02' + bytes(8)
def ethf(et, payload, d=b'\xff' * 6):
    return d + b'\x02\0\0\0\0\x01' + struct.pack('!H', et) + payload
ARP = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, b'\x02\0\0\0\0\x01', ip4('10.0.0.1'), bytes(6), ip4('10.0.0.2'))
PADI = struct.pack('!BBHH', 0x11, 0x09, 0, 0)
LCP = b'\xc0\x21' + bytes([1, 7, 0, 10, 5, 6, 0x12, 0x34, 0x56, 0x78])           # LCP Configure-Request with a magic number
def rb(proto, dataoff, l3off, payload, flags=0, ctx=0x10, circ=0x0102030405060708, pad=None, length=None):
    if pad is None: pad = b'\0' * max(0, dataoff - 24)
    body = pad + payload
    h = struct.pack('!IIQHHHH', ctx, flags, circ, len(payload) if length is None else length, proto, dataoff, l3off)
    return h + body
ISIS = bytes([0x83, 20, 1, 0, 17, 1, 0, 3, 1]) + b'\x02\0\0\0\0\x01' + struct.pack('!HHB', 30, 20 + 6, 1) + bytes([1, 4, 3, 0x49, 0, 1])
c = Cap(linktype=32)
r = c.raw
r(rb(1, 24, 24, ipv4()))                                          # 1 IPv4 (data offset == layer 3 offset)
r(rb(1, 24, 26, b'\x00\x21' + ipv4()))                            # 2 PPP (l3 offset = data offset + 2)
r(rb(1, 24, 28, b'\xff\x03\x00\x21' + ipv4()))                    # 3 PPP in HDLC framing (l3 offset = data offset + 4)
r(rb(1, 24, 38, ethf(0x0800, ipv4())))                           # 4 IPv4 on Ethernet (otherwise: eth without FCS)
r(rb(2, 24, 24, ISIS))                                            # 5 IS-IS (NLPID 0x83 in the osinl.incl table), outgoing
r(rb(2, 24, 24, b'\xcc' + ipv4()))                                # 6 NLPID 0xcc (IPv4 in the osinl.excl table, NLPID skipped)
r(rb(2, 24, 24, b'\xfe' + b'\x01\x02\x03\x04'))                   # 7 unknown NLPID: Data
r(rb(2, 24, 38, ethf(0x0800, ipv4(), d=b'\x01\x80\xc2\0\0\x14')))  # 8 incoming IS-IS: Ethernet (l3 offset > data offset)
r(rb(6, 24, 24, LCP, flags=0x04000000))                           # 9 PPP message, flag 0x04000000 set: data starts at the data offset, PPP
r(rb(6, 24, 24, b'\x00\x01\x02\x03' + LCP))                       # 10 PPP message without the flag: 4 unknown octets, then PPP
r(rb(6, 24, 38, b'\x00\x01\x02\x03' + ethf(0x8863, PADI)))        # 11 PPP message on Ethernet (l3 offset != data offset): eth, PPPoE
r(rb(3, 24, 38, ethf(0x8863, struct.pack('!BBHH', 0x11, 0x07, 0, 0))))   # 12 unicast Ethernet tx (PPPoE PADO)
r(rb(4, 24, 38, ethf(0x0806, ARP)))                               # 13 unicast Ethernet rx (ARP)
r(rb(8, 24, 38, ethf(0x8863, PADI)))                              # 14 broadcast Ethernet rx (PPPoE PADI)
r(rb(9, 24, 24, ipv6()))                                          # 15 IPv6 native (data offset == l3 offset)
r(rb(9, 24, 38, ethf(0x86dd, ipv6())))                            # 16 IPv6 on Ethernet
r(rb(1, 32, 32, ipv4(), pad=bytes(range(8))))                      # 17 data offset 32: eight octets of padding
r(rb(1, 24, 24, ipv4(), ctx=0xdeadbeef, flags=0x80000001, circ=0xffffffffffffffff))   # 18 other context, flags, circuit values
r(rb(0x55, 24, 24, b'\x01\x02\x03\x04'))                      # 19 unknown protocol 0x55 (warning)
c.write(out + '/redback-coverage.pcap')
m = Cap(linktype=32)
m.raw(rb(1, 24, 24, ipv4())[:20])                                 # 2: header cut before the data offset
m.raw(rb(2, 24, 24, b'')) # 3: ISIS, no payload at the data offset
m.raw(rb(6, 24, 24, b'\x00\x01'))                                 # 4: PPP message with only 2 octets (4 unknown expected)
m.raw(rb(1, 200, 200, b'\x45\0'))                                 # 5: data offset beyond the packet (padding exception)
m.write(out + '/redback-coverage-malformed.pcap')
