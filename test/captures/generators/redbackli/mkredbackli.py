#!/usr/bin/env python3
# Generates test/captures/redbackli_coverage.pcapng.gz
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


class CapNG(Cap):
    """pcapng with one interface per link type: raw(data, lt=1)"""
    def __init__(self, linktypes=(1, 252)):
        Cap.__init__(self, 1); self.lts = list(linktypes)
    def raw(self, data, caplen=None, lt=1):
        self.frames.append((self.ts, bytes(data), caplen, self.lts.index(lt))); self.ts += 0.01
        return len(self.frames)
    def write(self, path):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.lts:
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
        for ts, d, cl, ifx in self.frames:
            c = d if cl is None else d[:cl]
            t = int(ts * 1e6)
            out += blk(6, struct.pack('<IIIII', ifx, t >> 32, t & 0xffffffff, len(c), len(d)) + c)
        open(path, 'wb').write(out)

def expdu(name, payload):
    n = name.encode(); pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload
# ---- end helpers ----
out = sys.argv[1] if len(sys.argv) > 1 else '.'
def avp(t, v): return struct.pack('!BB', t, len(v)) + v
def icmp_ip():
    pl = struct.pack('!HHHH', 5000, 5001, 8 + 7, 0) + b'redback'
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(pl), 9, 0, 64, 17, 0, ip4('10.1.1.1'), ip4('10.2.2.2'))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + pl
SEQ = lambda n=1: avp(1, struct.pack('!I', n))
LIID = lambda n=0x1001: avp(2, struct.pack('!I', n))
SESS = lambda n=0x2002: avp(3, struct.pack('!I', n))
EOH1 = avp(0, b'\0'); EOH0 = avp(0, b'')
IP = icmp_ip()
c = CapNG()
CL, SV = '192.0.2.30', '192.0.2.40'
# UDP: found by the heuristic (sequence number, session id and LI id AVPs present, only known AVP types)
c.udp(CL, SV, 49000, 49001, SEQ(1) + LIID() + SESS() + avp(20, b'tap-one') + avp(4, b'\x01') + avp(40, b'\xa0\xa1\xa2\xa3') + EOH1 + IP)   # 1 every AVP type
c.udp(CL, SV, 49000, 49001, SEQ(2) + LIID() + SESS() + EOH0 + IP)                                    # 2 end-of-header AVP of length 0
c.udp(CL, SV, 49000, 49001, SESS(0x2003) + SEQ(3) + LIID(0x1002) + avp(20, b'') + avp(4, b'\x02') + EOH1 + IP)   # 3 other order, zero-length label
# Exported PDU naming the dissector: bypasses the heuristic
c.raw(expdu('redbackli', SEQ(4) + LIID() + SESS() + avp(40, b'\x01\x02') + EOH1 + IP), lt=252)              # 4 plain
# the reproducer of the fix: integer AVPs whose length is not 4 are shown as raw bytes (reproducer of the fixed bug)
c.raw(expdu('redbackli', avp(1, b'\x00\x05') + avp(2, b'\x00\x00\x00\x00\x00\x06') + avp(3, b'\x07') + avp(77, b'\x01\x02\x03')
            + avp(1, b'\0' * 8) + EOH1 + IP), lt=252)                                                    # 5 SEQNO of 2 octets, LIID of 6, SESSID of 1, SEQNO of 8, unknown AVP type 77
c.raw(expdu('redbackli', avp(2, b'') + avp(3, b'') + avp(1, b'') + EOH1 + IP), lt=252)                   # 6 integer AVPs of length 0 (shown as header only)
c.write(out + '/redbackli-coverage.pcapng')
m = CapNG()
m.raw(expdu('redbackli', SEQ(5) + LIID() + SESS() + avp(20, b'x' * 40)), lt=252)                         # 1: no end-of-header, nothing for IP
m.raw(expdu('redbackli', SEQ(6) + LIID() + SESS() + struct.pack('!BB', 20, 200) + b'short'), lt=252)     # 2: AVP longer than the data left: stops, IP gets the rest
m.raw(expdu('redbackli', SEQ(7) + LIID() + SESS() + EOH1 + b'\x45\x00'), lt=252)                         # 3: IP header cut
m.udp(CL, SV, 49000, 49001, avp(1, b'\0\0') + LIID() + SESS() + EOH1 + IP)                                    # 4: heuristic: wrong SEQNO length (declined, Data)
m.udp(CL, SV, 49000, 49001, SEQ(9) + LIID() + avp(20, b'abc') + EOH1 + IP)                               # 5: heuristic: session id missing (declined)
m.udp(CL, SV, 49000, 49001, SEQ(9) + LIID() + SESS() + avp(99, b'zz') + EOH1 + IP)                       # 6: heuristic: unknown AVP type (declined)
m.udp(CL, SV, 49000, 49001, avp(0, b'') + SEQ(9) + LIID() + SESS() + IP)                                 # 7: heuristic: end-of-header first (declined)
m.udp(CL, SV, 49000, 49001, SEQ(9) + LIID() + SESS() + avp(0, b'\0\0\0') + IP)                          # 8: heuristic: end-of-header longer than 1 (declined)
m.udp(CL, SV, 49000, 49001, SEQ(1) + LIID())                                                              # 9: heuristic: shorter than the minimum size
m.udp(CL, SV, 49000, 49001, LIID() + SESS() + avp(20, b'abc') + EOH1 + IP)                                 # 10: heuristic: sequence number missing (declined)
m.udp(CL, SV, 49000, 49001, SEQ(9) + SESS() + avp(20, b'abc') + EOH1 + IP)                               # 11: heuristic: LI id missing (declined)
m.write(out + '/redbackli-coverage-malformed.pcapng')
