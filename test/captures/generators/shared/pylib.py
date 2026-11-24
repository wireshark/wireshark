# Shared helper module for the capture generators in test/captures/generators
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
        self.lt = linktype; self.frames = []; self.t = 0
    def add(self, data):
        self.frames.append(data); return len(self.frames)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.lt))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)) + d)
