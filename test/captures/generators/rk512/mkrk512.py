#!/usr/bin/env python3
# Generates test/captures/rk512_coverage.pcap.gz
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
        if flags & 2:   # SYN: MSS option
            t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x70, flags, 65535, 0, urp) + b'\x02\x04\x05\xb4\x04\x02\x01\x01' + payload
        else:
            t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, urp) + payload
        return self.raw(self.eth(self.ip(src, dst, 6, t)))
    def hs(self, src, dst, sp, dp):
        # three-way handshake: SYN, SYN/ACK, ACK
        self.tcp(src, dst, sp, dp, b'', flags=0x02, seq=1000 + (sp * 7919 + dp) % 100000 - 1)
        self.tcp(dst, src, dp, sp, b'', flags=0x12, seq=5000)
        self.tcp(src, dst, sp, dp, b'', flags=0x10)
    def fin(self, src, dst, sp, dp):
        self.tcp(src, dst, sp, dp, b'', flags=0x11)
        self.tcp(dst, src, dp, sp, b'', flags=0x11)
        self.tcp(src, dst, sp, dp, b'', flags=0x10)
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
def crc(data):                      # CRC-CCITT, seed 0xffff, MSB first, no final xor
    r = 0xffff
    for b in data:
        r ^= b << 8
        for _ in range(8):
            r = ((r << 1) ^ 0x1021) & 0xffff if r & 0x8000 else (r << 1) & 0xffff
    return r
def pdu(btype, body, hdr=0, size=None, badcrc=False, withcrc=True):
    # body: the octets after the size field up to the CRC
    if size is None: size = (len(body) + 2) // 2
    sz = struct.pack('!H', size)
    data = sz + body
    c = crc(b'\0\0' + data[:size * 2] if len(data) >= size * 2 else b'\0\0' + data)
    if badcrc: c ^= 0x5555
    return struct.pack('!IH', hdr, btype) + data + struct.pack('<H', c)
def meas(npts, seed=0, flagsel=0):
    return b''.join(struct.pack('!H', ((((i + flagsel) % 8) << 13) | ((seed + i * 3) % 8000))) for i in range(npts))
def cont(scan, tel, dtype=0xBBBB, npts=541, dev=7, status=0, coord=0, ver=0x0102, size=None, flagsel=0, **kw):
    b = struct.pack('!BBHH', coord, dev, ver, status) + struct.pack('<IHH', scan, tel, dtype)
    if dtype == 0xBBBB:
        b += struct.pack('<H', 0x0001) + meas(npts, scan, flagsel)
    return pdu(0, b, size=size, **kw)
def other(btype, extra=b'\0\0', **kw): return pdu(btype, extra, **kw)
c = Cap()
def S(sp, data, dp=40001, **kw): return c.tcp('192.0.2.1', '192.0.2.2', sp, dp, data, **kw)
a = 40000
c.hs('192.0.2.1', '192.0.2.2', a, 40001)
# connection 1: every segment is recognised by the TCP heuristic (zero header, known block type and data type)
S(a, b'\x01\x02\x03' + cont(1, 1))                           # 1 three octets of garbage, then measurement data (541 points), good CRC
S(a, cont(2, 2, dev=8, status=1, coord=1, ver=0x0203, flagsel=3))   # 2 device Guest, status Lockout, other version
S(a, cont(3, 3, dtype=0xCCCC))                                # 3 reflector data
S(a, pdu(0, struct.pack('!BBHH', 0, 7, 0x0102, 0) + struct.pack('<IHH', 4, 4, 0xCCCC) + b'\xaa' * 8))   # 4 reflector data with extra octets
S(a, other(0x0017, b'\x01\x02'))                              # 5 SCID block
S(a, other(0x0019, b'\x03\x04'))                              # 6 Token block
S(a, other(0x0067, b'\x05\x06'))                              # 7 Data Mode block
p = cont(7, 7)
S(a, p[:600]); S(a, p[600:])                                  # 8-9 one PDU in two segments (reassembly)
S(a, other(0x0017, b'\x0a\x0b') + other(0x0019, b'\x0c\x0d')) # 10 two PDUs in one segment
S(a, cont(8, 8, badcrc=True))                                 # 11 wrong checksum (warning)
# connection 2: garbage of five octets before the PDU
c.hs('192.0.2.1', '192.0.2.2', 40100, 40001)
S(40100, b'\x11\x22\x33\x44\x55' + other(0x0017, b'\x01\x02'))   # 12
S(40100, other(0x0019, b'\x03\x04'))                          # 13
# connection 3 (TCP port 40002): needs Decode As, the heuristic does not accept these PDUs
c.hs('192.0.2.1', '192.0.2.2', 40200, 40002)
S(40200, other(0x1234, b'\x07\x08'), dp=40002)                # 14 unknown block type
S(40200, cont(5, 5, dtype=0xDDDD), dp=40002)                  # 15 continuous data with an unknown data type (warning)
S(40200, cont(6, 6, hdr=0x01020304), dp=40002)                # 16 non-zero reply header (warning)
S(40200, cont(9, 9), dp=40002)                                # 17 plain measurement data
c.write(out + '/rk512-coverage.pcap')
m = Cap()
def M(sp, data, **kw): return m.tcp('192.0.2.1', '192.0.2.2', sp, 40001, data, **kw)
bad = pdu(0, struct.pack('!BBHH', 0, 7, 0x0102, 0) + struct.pack('<IHH', 9, 9, 0xBBBB) + b'\0' * 8, size=2)   # size 2 words but 16 more octets
m.hs('192.0.2.1', '192.0.2.2', 40200, 40001)
M(40200, b'\x01' + bad)                                                 # 1: the size field is smaller than the data: exceptions
m.hs('192.0.2.1', '192.0.2.2', 40210, 40001)
M(40210, cont(10, 10, npts=100))                              # 2: 100 measurement points but 541 expected: exceptions
m.hs('192.0.2.1', '192.0.2.2', 40220, 40001)
M(40220, other(0x0017, b'')[:11])                             # 3: truncated PDU at the end of the stream
# 381 point PDUs (decoded without exceptions only with -o rk512.num_measurement_pts:381)
m.hs('192.0.2.1', '192.0.2.2', 40300, 40001)
M(40300, b'\x01' + cont(11, 11, npts=381, size=392))                    # 4: size field 392 (hack for the 381 point sensor)
M(40300, other(0x0017, b'\x01\x02'))                          # 5
m.hs('192.0.2.1', '192.0.2.2', 40400, 40001)
M(40400, b'\x01\x00\x00\x00\x00\x00')                         # 6: signature followed by one octet only (heuristic needs two)
m.hs('192.0.2.1', '192.0.2.2', 40410, 40001)
M(40410, b'\x01\x00\x00\x00\x00\x00\x00' + b'\x02' * 5)       # 7: continuous data block with fewer than 18 octets after the block type (heuristic declines)
m.write(out + '/rk512-coverage-malformed.pcap')
