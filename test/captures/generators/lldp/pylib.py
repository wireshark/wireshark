# Helper module for the lldp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import gzip
import socket

def ip4(s): return socket.inet_aton(s)
def mac(s): return bytes.fromhex(s.replace(':', ''))

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack('>H', etype) + payload

def ipv4(src, dst, proto, payload, ident=1, ttl=64, tos=0, flags=0):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, tos, 20 + len(payload), ident, flags, ttl, proto, 0, ip4(src), ip4(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sport, dport, payload):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload

def tcp(sport, dport, seq, ack, flags, payload=b'', win=65535):
    opts = b''
    if flags & 2:
        opts = struct.pack('>BBH', 2, 4, 1460) + b'\x01\x03\x03\x07' + b'\x04\x02\x01\x01'
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0) + opts + payload

H, S = '02:00:00:00:00:01', '02:00:00:00:00:02'
A, B = '192.0.2.1', '192.0.2.2'

def eth_udp(sport, dport, payload, src=A, dst=B, rev=False):
    s, d = (S, H) if rev else (H, S)
    return eth(d, s, 0x0800, ipv4(src, dst, 17, udp(sport, dport, payload)))

class Pcap:
    def __init__(self, linktype=1):
        self.lt = linktype; self.frames = []; self.t = 0; self.origs = {}
    def add(self, data, orig=None):
        """orig: original length when the frame is truncated (snap length)"""
        self.frames.append(data); self.origs[len(self.frames) - 1] = orig; return len(self.frames)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.lt))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), self.origs.get(i) or len(d)) + d)

class Pcapng:
    """Minimal pcapng writer; add_if(linktype) returns the interface id."""
    def __init__(self):
        self.ifs = []; self.pkts = []
    def add_if(self, linktype, snaplen=65535):
        self.ifs.append((linktype, snaplen)); return len(self.ifs) - 1
    def add(self, ifid, data):
        self.pkts.append((ifid, data)); return len(self.pkts)
    @staticmethod
    def blk(t, body):
        body += bytes((-len(body)) % 4)
        n = 12 + len(body)
        return struct.pack('<II', t, n) + body + struct.pack('<I', n)
    def write(self, path):
        out = self.blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
        for lt, sn in self.ifs:
            out += self.blk(1, struct.pack('<HHI', lt, 0, sn))
        for i, (ifid, d) in enumerate(self.pkts):
            ts = 1700000000 * 1000000 + i * 1000
            out += self.blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
        open(path, 'wb').write(out)

class Tcp:
    def __init__(self, p, sport=50000, dport=6801, rev=False):
        self.p = p; self.sport = sport; self.dport = dport
        self.seq = {True: 1000, False: 5000}
    def seg(self, data, fwd=True, flags=0x18):
        s, d = (self.sport, self.dport) if fwd else (self.dport, self.sport)
        src, dst = (A, B) if fwd else (B, A)
        e1, e2 = (H, S) if fwd else (S, H)
        t = tcp(s, d, self.seq[fwd], 0 if flags == 2 else self.seq[not fwd], flags, data)
        self.seq[fwd] += len(data) + (1 if flags & 3 else 0)
        return self.p.add(eth(e2, e1, 0x0800, ipv4(src, dst, 6, t)))
    def hs(self):
        self.seg(b'', True, 0x02); self.seg(b'', False, 0x12); self.seg(b'', True, 0x10)


def udp6(src, dst, sport, dport, payload):
    """UDP over IPv6 with the pseudo header checksum"""
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ps = socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + struct.pack('>IBBBB', len(u), 0, 0, 0, 17)
    c = csum(ps + u) or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]

def ipv6(src, dst, nh, payload, hlim=64):
    return struct.pack('>IHBB16s16s', 0x60000000, len(payload), nh, hlim,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + payload
