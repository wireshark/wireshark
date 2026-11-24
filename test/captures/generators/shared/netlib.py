# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small helpers shared by the generators: pcap writer, IPv4/IPv6/TCP/UDP builders."""
import struct
import socket

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def ip6(src, dst, nh, payload):
    return struct.pack('>IHBB16s16s', 0x60000000, len(payload), nh, 64,
                       socket.inet_pton(socket.AF_INET6, src),
                       socket.inet_pton(socket.AF_INET6, dst)) + payload

def pseudo(src, dst, proto, length):
    if ':' in src:
        return (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
                + struct.pack('>IBBBB', length, 0, 0, 0, proto))
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, proto, length)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, opts=b''):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                    (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    c = csum(pseudo(src, dst, 6, len(t) + len(payload)) + t + payload)
    return t[:16] + struct.pack('>H', c) + t[18:] + payload

def udp(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    c = csum(pseudo(src, dst, 17, len(u) + len(payload)) + u + payload) or 0xffff
    return u[:6] + struct.pack('>H', c) + payload

def ip_any(src, dst, proto, payload):
    return ip6(src, dst, proto, payload) if ':' in src else ip4(src, dst, proto, payload)

def eth(src_mac, dst_mac, etype, payload):
    return dst_mac + src_mac + struct.pack('>H', etype) + payload

def write_pcap(path, frames, linktype=1):
    """frames: list of bytes or (bytes, ts_seconds_float)"""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        t = 1700000000.0
        for fr in frames:
            cap = None
            if isinstance(fr, tuple):
                if len(fr) == 3:
                    fr, _, cap = fr
                    t += 0.01
                else:
                    fr, t = fr
            else:
                t += 0.01
            cap = len(fr) if cap is None else min(cap, len(fr))
            f.write(struct.pack('<IIII', int(t), int((t % 1) * 1e6), cap, len(fr)))
            f.write(fr[:cap])

class TcpStream:
    """One TCP connection; send() returns Ethernet frames."""
    def __init__(self, a, ap, b, bp, mac_a=b'\x02\0\0\0\0\x01', mac_b=b'\x02\0\0\0\0\x02', isn_a=1000, isn_b=5000):
        self.a, self.ap, self.b, self.bp = a, ap, b, bp
        self.ma, self.mb = mac_a, mac_b
        self.seq = {'a': isn_a, 'b': isn_b}
    def _frame(self, frm, data, flags=0x18, opts=b''):
        to = 'b' if frm == 'a' else 'a'
        if frm == 'a':
            s, d, sp, dp, ms, md = self.a, self.b, self.ap, self.bp, self.ma, self.mb
        else:
            s, d, sp, dp, ms, md = self.b, self.a, self.bp, self.ap, self.mb, self.ma
        ack = self.seq[to] if flags & 0x10 else 0
        seg = tcp(s, d, sp, dp, self.seq[frm], ack, data, flags, opts)
        self.seq[frm] += len(data) + (1 if flags & 3 else 0)
        et = 0x86dd if ':' in s else 0x0800
        return eth(ms, md, et, ip_any(s, d, 6, seg))
    def syn(self):
        mss = b'\x02\x04\x05\xb4\x04\x02\x01\x01'
        return [self._frame('a', b'', 0x02, mss), self._frame('b', b'', 0x12, mss), self._frame('a', b'', 0x10)]
    def send(self, frm, data, cuts=()):
        """Send data as one segment, or cut at the given offsets."""
        out = []
        prev = 0
        for c in list(cuts) + [len(data)]:
            out.append(self._frame(frm, data[prev:c]))
            prev = c
        return out
