#!/usr/bin/env python3
# Generates test/captures/rgmp_coverage.pcap.gz
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
def igmp(typ, grp, bad=False, resp=0):
    h = struct.pack('!BBH4s', typ, resp, 0, ip4(grp))
    c = csum(h)
    if bad: c ^= 0x1234
    return h[:2] + struct.pack('!H', c) + h[4:]
RG = '224.0.0.25'
c = Cap()
def send(pl, dst=RG, src='192.0.2.1', frag=0, caplen=None):
    c.raw(c.eth(c.ip(src, dst, 2, pl, ttl=1, frag=frag), d=b'\x01\0\x5e\0\0\x19' if dst == RG else b'\x01\0\x5e\0\0\x01'), caplen)
send(igmp(0xFF, '0.0.0.0'))                       # 1 hello
send(igmp(0xFD, '224.1.1.1'), src='192.0.2.2')    # 2 join
send(igmp(0xFC, '224.1.1.1'), src='192.0.2.2')    # 3 leave
send(igmp(0xFE, '0.0.0.0'), src='192.0.2.1')      # 4 bye
send(igmp(0xFD, '239.9.9.9', resp=0x5a))          # 5 join, nonzero reserved
send(igmp(0xFF, '0.0.0.0'), frag=0x2000)          # 6 first IP fragment (MF): shown as data unless IP reassembly is off
send(igmp(0xFF, '0.0.0.0'), dst='224.0.0.1')      # 7 RGMP type to another group: declined, left to IGMP
c.write(out + '/rgmp-coverage.pcap')
m = Cap()
m.raw(m.eth(m.ip('192.0.2.1', RG, 2, igmp(0xFD, '224.1.1.1')[:3], ttl=1)))   # 1: 3 octets (reserved, checksum cut)
m.raw(m.eth(m.ip('192.0.2.1', RG, 2, igmp(0xFD, '224.1.1.1')[:6], ttl=1)))   # 2: group address cut
m.raw(m.eth(m.ip('192.0.2.1', RG, 2, igmp(0xFD, '224.3.3.3'), ttl=1)), 14+20+6)   # 3: truncated capture: checksum unverified
m.raw(m.eth(m.ip('192.0.2.1', RG, 2, igmp(0xFD, '224.2.2.2', bad=True), ttl=1)))   # 4: bad checksum
m.write(out + '/rgmp-coverage-malformed.pcap')
