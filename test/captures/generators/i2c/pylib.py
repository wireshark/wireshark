# Helper module for the i2c capture generator
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
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload

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
