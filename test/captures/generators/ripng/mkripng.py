#!/usr/bin/env python3
# Generates test/captures/ripng_coverage.pcap.gz
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
        return self.raw(self.eth(self.ip(src, dst, 17, u)))
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
def a6(s):
    import socket
    return socket.inet_pton(socket.AF_INET6, s)
def rte(prefix, tag, plen, metric):
    return a6(prefix) + struct.pack('!HBB', tag, plen, metric)
def msg(cmd, ver, rtes=(), res=0):
    return struct.pack('!BBH', cmd, ver, res) + b''.join(rtes)
SRC = a6('fe80::1'); DST = a6('ff02::9')
c = Cap()
c.udp6(SRC, DST, 521, 521, msg(1, 1, [rte('::', 0, 0, 16)]))                       # 1 request for the whole table
c.udp6(SRC, DST, 521, 521, msg(2, 1, [rte('2001:db8::', 0, 32, 1),
        rte('2001:db8:1::', 0x00ff, 48, 2), rte('2001:db8:2:3::', 0xffff, 64, 15),
        rte('2001:db8:4::5', 7, 128, 16)]))                                         # 2 response, four RTEs
c.udp6(SRC, DST, 521, 521, msg(2, 1))                                              # 3 response without RTEs
c.udp6(SRC, DST, 521, 521, msg(3, 2, [rte('fe80::', 0, 10, 1)], res=0x1234))       # 4 unknown command 3, version 2, reserved set
c.udp6(SRC, DST, 521, 521, msg(2, 1, [rte('2001:db8:%x::' % i, i, 48, 1 + i % 16) for i in range(25)]))  # 5 25 RTEs (maximum per RFC 2080 MTU 512)
c.udp(  '192.0.2.1', '192.0.2.2', 521, 521, msg(1, 1, [rte('2001:db8:9::', 0, 48, 3)]))  # 6 over IPv4
c.write(out + '/ripng-coverage.pcap')
m = Cap()
m.udp6(SRC, DST, 521, 521, b'\x02')                                                # 1: one octet
m.udp6(SRC, DST, 521, 521, msg(2, 1)[:3])                                          # 2: header cut in the reserved field
m.udp6(SRC, DST, 521, 521, msg(2, 1, [rte('2001:db8::', 0, 32, 1)])[:4 + 10])      # 3: RTE cut short
m.write(out + '/ripng-coverage-malformed.pcap')
