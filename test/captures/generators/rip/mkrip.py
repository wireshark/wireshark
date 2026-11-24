#!/usr/bin/env python3
# Generates test/captures/rip_coverage.pcap.gz
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
def ent(fam, tag, ip, mask, nh, metric):
    return struct.pack('!HH4s4s4sI', fam, tag, ip4(ip), ip4(mask), ip4(nh), metric)
def hdr(cmd, ver, dom=0): return struct.pack('!BBH', cmd, ver, dom)
def auth(atype, body16): return struct.pack('!HH', 0xffff, atype) + body16
A, B = '192.0.2.1', '224.0.0.9'
c = Cap()
def r(pl, src=A, dst=B, dp=520, sp=520): c.udp(src, dst, sp, dp, pl)
r(hdr(1, 1) + ent(0, 0, '0.0.0.0', '0.0.0.0', '0.0.0.0', 16))                       # 1 v1 request, whole table (unspecified family)
r(hdr(2, 1) + ent(2, 0, '10.1.0.0', '0.0.0.0', '0.0.0.0', 1) + ent(2, 0, '10.2.0.0', '0.0.0.0', '0.0.0.0', 3))  # 2 v1 response
r(hdr(2, 2) + ent(2, 7, '10.3.0.0', '255.255.0.0', '192.0.2.254', 2) + ent(0, 9, '0.0.0.0', '255.0.0.0', '192.0.2.253', 16))  # 3 v2 response: IP entry, unspecified entry with tag, mask, next hop
r(hdr(1, 2, 0x0102) + ent(0, 0, '0.0.0.0', '0.0.0.0', '0.0.0.0', 16), dst='192.0.2.2')  # 4 v2 request with a routing domain value in the header (shown with the preference)
r(hdr(3, 1))                                                                         # 5 traceon, no entries
r(hdr(4, 1))                                                                         # 6 traceoff
r(hdr(5, 1) + b'\x00' * 20)                                                          # 7 vendor specific (Sun), one entry (family 0)
r(hdr(9, 3) + ent(2, 0, '10.4.0.0', '255.255.255.0', '0.0.0.0', 5))                  # 8 unknown command 9, unknown version 3 (Info "RIP")
r(hdr(2, 2) + auth(2, b'secret'.ljust(16, b'\0')) + ent(2, 0, '10.5.0.0', '255.255.0.0', '0.0.0.0', 1))  # 9 v2 with simple password
body = struct.pack('!HBBI8s', 4 + 20 + 20, 1, 16, 0x1000, b'\0' * 8)                 # digest offset, key id, auth data len, seq, zero padding
r(hdr(2, 2) + auth(3, body) + ent(2, 0, '10.6.0.0', '255.255.0.0', '0.0.0.0', 1)
  + struct.pack('!HH', 0xffff, 1) + bytes(range(16)))                                # 10 v2 with keyed MD5 authentication and trailer
body = struct.pack('!HBBI8s', 4 + 20, 2, 16, 0x1001, b'\0' * 8)
r(hdr(2, 2) + auth(3, body) + struct.pack('!HH', 0xffff, 1) + bytes(range(16, 32)))  # 11 MD5 authentication, no routes
r(hdr(2, 2) + auth(1, b'\x11' * 16) + ent(2, 0, '10.7.0.0', '255.255.0.0', '0.0.0.0', 1))  # 12 authentication of type 1 (IP route, not decoded)
r(hdr(2, 2) + auth(4, b'\x22' * 16))                                                  # 13 unknown authentication type
r(hdr(2, 2) + ent(2, 0, '10.8.0.0', '255.255.0.0', '0.0.0.0', 1) + auth(2, b'late'.ljust(16, b'\0')))  # 14 0xFFFF entry that is not first: unknown address family (warning)
r(hdr(2, 1) + ent(99, 0, '10.9.0.0', '0.0.0.0', '0.0.0.0', 1))                        # 15 unknown address family 99 (warning)
r(hdr(2, 2) + ent(2, 0, '10.10.0.0', '255.255.0.0', '0.0.0.0', 1), sp=1234, dp=520)   # 16 response from a non-RIP source port
r(hdr(2, 1) + b''.join(ent(2, 0, '10.%d.0.0' % (20 + i), '0.0.0.0', '0.0.0.0', 1 + i % 15) for i in range(25)))  # 17 25 entries (maximum)
body = struct.pack('!HBBI8s', 4 + 20, 3, 16, 0x1002, b'\0' * 8)
r(hdr(2, 2) + auth(3, body) + struct.pack('!HH', 0xffff, 1) + bytes(16) + ent(2, 0, '10.11.0.0', '255.255.0.0', '0.0.0.0', 1))  # 18 MD5 authentication, then a 0xFFFF entry that is not the trailer (more than 20 octets left): unknown address family (warning)
c.write(out + '/rip-coverage.pcap')
m = Cap()
m.udp(A, B, 520, 520, b'\x02\x02\x00')                                               # 1: header cut
m.udp(A, B, 520, 520, hdr(2, 2) + ent(2, 0, '10.1.0.0', '255.255.0.0', '0.0.0.0', 1)[:12])  # 2: entry cut short
m.udp(A, B, 520, 520, hdr(2, 2) + auth(2, b'short'))                                 # 3: password cut short
body = struct.pack('!HBBI8s', 500, 1, 16, 1, b'\0' * 8)
m.udp(A, B, 520, 520, hdr(2, 2) + auth(3, body))                                     # 4: digest offset beyond the packet
m.udp(A, B, 520, 520, hdr(2, 2) + auth(3, struct.pack('!HBB', 24, 1, 16)))           # 5: MD5 authentication cut short
m.udp(A, B, 520, 520, hdr(2, 2) + ent(2, 0, '10.1.0.0', '255.255.0.0', '0.0.0.0', 0x00010005))   # 6: metric above 65535 (the field is 16 bit, the value is read as 32 bit)
m.write(out + '/rip-coverage-malformed.pcap')
