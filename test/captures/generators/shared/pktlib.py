# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small packet building helpers (pcap writer, Ethernet, IPv4/IPv6,
UDP, TCP with per-direction sequence numbers). Everything is built with
struct; no captured traffic is used."""

import struct


def pcap(path, frames, linktype=1):
    """frames: list of bytes, or (bytes, linktype-ignored) tuples."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def mac(n):
    return bytes([0x02, 0, 0, 0, 0, n])


def eth(dst, src, etype, payload):
    return dst + src + struct.pack('!H', etype) + payload


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(src, dst, proto, payload, ident=1, ttl=64):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000,
                      ttl, proto, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return hdr + payload


def ip6(src, dst, nh, payload, hlim=64):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nh, hlim,
                       bytes(src), bytes(dst)) + payload


def l4sum4(src, dst, proto, seg):
    ph = struct.pack('!4s4sBBH', bytes(src), bytes(dst), 0, proto, len(seg))
    return csum(ph + seg)


def udp(src, dst, sport, dport, payload):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = l4sum4(src, dst, 17, seg) or 0xffff
    return seg[:6] + struct.pack('!H', c) + seg[8:]


def tcp_seg(src, dst, sport, dport, seq, ack, flags, payload, win=65535):
    seg = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload
    c = l4sum4(src, dst, 6, seg)
    return seg[:16] + struct.pack('!H', c) + seg[18:]


IP_A = (10, 0, 0, 1)
IP_B = (10, 0, 0, 2)


def udp_frame(sport, dport, payload, a=IP_A, b=IP_B, rev=False, ident=1):
    s, d = (b, a) if rev else (a, b)
    ms, md = (mac(2), mac(1)) if rev else (mac(1), mac(2))
    return eth(md, ms, 0x0800, ip4(s, d, 17, udp(s, d, sport, dport, payload), ident))


class TcpConn:
    """A TCP connection between a client and a server. send(data,
    from_server) returns one Ethernet frame (PSH|ACK) and advances the
    sequence numbers. handshake() returns SYN, SYN/ACK, ACK."""

    def __init__(self, cport, sport, a=IP_A, b=IP_B, cseq=1000, sseq=5000):
        self.cport, self.sport, self.a, self.b = cport, sport, a, b
        self.seq = [cseq, sseq]

    def _frame(self, frm, flags, payload):
        if frm == 0:
            s, d, sp, dp, ms, md = self.a, self.b, self.cport, self.sport, mac(1), mac(2)
        else:
            s, d, sp, dp, ms, md = self.b, self.a, self.sport, self.cport, mac(2), mac(1)
        seg = tcp_seg(s, d, sp, dp, self.seq[frm], self.seq[1 - frm], flags, payload)
        return eth(md, ms, 0x0800, ip4(s, d, 6, seg))

    def handshake(self):
        f = []
        f.append(self._frame(0, 0x02, b''))
        self.seq[0] += 1
        f.append(self._frame(1, 0x12, b''))
        self.seq[1] += 1
        f.append(self._frame(0, 0x10, b''))
        return f

    def send(self, data, from_server=False):
        frm = 1 if from_server else 0
        fr = self._frame(frm, 0x18, data)
        self.seq[frm] += len(data)
        return fr

    def ack(self, from_server=False):
        return self._frame(1 if from_server else 0, 0x10, b'')
