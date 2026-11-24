#!/usr/bin/env python3
# Generates test/captures/rlogin_coverage.pcap.gz
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
CL, SV = '192.0.2.1', '192.0.2.2'
URG = 0x20
c = Cap()
def cs(sp, data, **kw): return c.tcp(CL, SV, sp, 513, data, **kw)
def sc(sp, data, **kw): return c.tcp(SV, CL, 513, sp, data, **kw)
WIN = lambda r, co, x, y: b'\xff\xffss' + struct.pack('!HHHH', r, co, x, y)
# connection 1: the usual sequence
cs(1023, b'\0')                                             # 1 client startup flag (waiting for the user info)
sc(1023, b'\0')                                             # 2 server: startup info received
cs(1023, b'root\0root\0xterm/38400\0')                      # 3 user info: client and server name, terminal type, speed
sc(1023, b'login: ')                                        # 4 data from the server (Info shows the user name)
cs(1023, b'ls\r')                                           # 5 data from the client
sc(1023, b'abc\x10', flags=0x18 | URG, urp=4)               # 6 urgent: data before, control byte 0x10 (raw mode)
sc(1023, b'\x80', flags=0x18 | URG, urp=1)                  # 7 window size request
sc(1023, b'\x02', flags=0x18 | URG, urp=1)                  # 8 clear buffer
sc(1023, b'\x20', flags=0x18 | URG, urp=1)                  # 9 cooked mode
sc(1023, b'\x99', flags=0x18 | URG, urp=1)                  # 10 unknown control byte
sc(1023, b'hello', flags=0x18 | URG, urp=100)               # 11 urgent pointer beyond this segment: plain data
cs(1023, WIN(24, 80, 640, 480))                             # 12 window change
cs(1023, b'xy' + WIN(50, 132, 0, 0) + b'tail')              # 13 data, window change, data
sc(1023, b'\0abc')                                          # 14 from the server: starts with a NUL, then data
cs(1023, b'\0')                                             # 15 client: a NUL after the handshake (state done)
# connection 2: terminal type without speed
cs(1022, b'\0')                                             # 16
cs(1022, b'bob\0bob\0vt100\0')                              # 17 user info without a slash
cs(1022, b'x' * 150)                                        # 18 long data (Info shows 128 characters)
# connection 3: user info followed by the window information
cs(1021, b'\0')                                             # 19
cs(1021, b'carol\0carol\0xterm/9600\0' + WIN(25, 80, 0, 0)) # 20 user info and window info in one segment
# connection 4: no leading NUL: no user info expected
cs(1020, b'hello world')                                    # 21
cs(1020, b'second')                                         # 22
# connection 5: user name of 40 characters (longer than the 32 octets kept)
cs(1019, b'\0')                                             # 23
cs(1019, b'u' * 40 + b'\0' + b'u' * 40 + b'\0vt220/19200\0')   # 24
# connection 6: one segment with the NUL, the user info and no more
cs(1018, b'\0dave\0dave\0ansi/1200\0')                      # 25 handshake and user info in one segment (state done at once)
sc(1018, b'\0')                                             # 26
# the reproducers of the bugs fixed on the branch (connection 7)
cs(1017, b'hello', flags=0x18 | URG, urp=0)                 # 27 URG with urgent pointer 0
cs(1017, b'ab\xff\xffss\x00\x18\x00\x50\x00\x00\x00\x00')   # 28 data before the window information: rows 24, cols 80
c.write(out + '/rlogin-coverage.pcap')
m = Cap()
def mc(sp, data, **kw): return m.tcp(CL, SV, sp, 513, data, **kw)
mc(1023, b'\0')                                             # 1
mc(1023, b'eve\0eve\0xterm/fast\0')                         # 2: invalid terminal speed (error expert info)
mc(1022, b'\0')                                             # 3
mc(1022, b'frank\0frank')                                   # 4: user info without the terminators (string size exception)
mc(1021, b'\xff\xffss\x00\x18')                             # 5: window information cut short
m.write(out + '/rlogin-coverage-malformed.pcap')
