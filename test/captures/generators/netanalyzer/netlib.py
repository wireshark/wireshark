# Helper module for the netanalyzer capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Small helpers: Ethernet/IPv4/TCP/UDP frames and classic pcap writing.
import struct

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(s):
    return bytes(int(x) for x in s.split('.'))

def eth_ip(src, dst, proto, l4, ident=1):
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, ip4(src), ip4(dst))
    iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + iph + l4

def tcp_seg(src, dst, sport, dport, seq, ack, payload=b'', flags=0x18):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, flags, 65535, 0, 0)
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    c = csum(ph + tcp + payload)
    tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
    return eth_ip(src, dst, 6, tcp + payload)

def udp_dgram(src, dst, sport, dport, payload):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    return eth_ip(src, dst, 17, udp + payload)

class Conn:
    """A TCP connection that appends frames to a shared list."""
    def __init__(self, frames, c, s, cport, sport, isn_c=1000, isn_s=5000, syn=True):
        self.f = frames
        self.c, self.s, self.cp, self.sp = c, s, cport, sport
        self.sc, self.ss = isn_c, isn_s
        if syn:
            self.f.append(tcp_seg(c, s, cport, sport, self.sc, 0, b'', 0x02))
            self.sc += 1
            self.f.append(tcp_seg(s, c, sport, cport, self.ss, self.sc, b'', 0x12))
            self.ss += 1
            self.f.append(tcp_seg(c, s, cport, sport, self.sc, self.ss, b'', 0x10))

    def c2s(self, data):
        self.f.append(tcp_seg(self.c, self.s, self.cp, self.sp, self.sc, self.ss, data))
        self.sc += len(data)

    def s2c(self, data):
        self.f.append(tcp_seg(self.s, self.c, self.sp, self.cp, self.ss, self.sc, data))
        self.ss += len(data)

    def fin(self):
        self.f.append(tcp_seg(self.c, self.s, self.cp, self.sp, self.sc, self.ss, b'', 0x11))
        self.sc += 1
        self.f.append(tcp_seg(self.s, self.c, self.sp, self.cp, self.ss, self.sc, b'', 0x11))
        self.ss += 1

def write_pcap(name, frames, linktype=1, t0=1700000000):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', t0 + i // 4, (i % 4) * 100000 + 1000, len(p), len(p)))
            f.write(p)

def write_pcapng(name, frames, linktypes=(1, 252), t0=1700000000):
    """frames: list of (interface index, bytes); interface i has link type linktypes[i]."""
    def blk(btype, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, p) in enumerate(frames):
        ts = (t0 + i // 4) * 1000000 + (i % 4) * 100000 + 1000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    open(name, 'wb').write(out)
