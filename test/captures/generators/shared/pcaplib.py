# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small capture-building helpers (struct only). Copied into each coverage
directory."""
import struct

LT_ETH, LT_SLL, LT_EXPORTED_PDU, LT_RAW = 1, 113, 252, 101
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def pcap(path, frames, linktype=LT_ETH):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)


def pcapng(path, frames, linktypes=(LT_ETH,)):
    """frames: list of bytes (interface 0) or (interface, bytes)."""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, fr in enumerate(frames):
        if isinstance(fr, tuple):
            ifc, data = fr[0], fr[1]
            orig = fr[2] if len(fr) > 2 else len(data)
        else:
            ifc, data, orig = 0, fr, len(fr)
        ts = 1700000000 * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                   len(data), orig) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(payload, proto, src='192.0.2.1', dst='192.0.2.2', ident=1, flags_frag=0, ttl=64):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, flags_frag,
                    ttl, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def eth(payload, etype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('!H', etype) + payload


def udp(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2', ident=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ip4(u, 17, src, dst, ident))


def tcp(payload, sport, dport, seq, ack=0, flags=0x18, src='192.0.2.1',
        dst='192.0.2.2', ident=1, win=65535):
    opts = b''
    if flags & 0x02:                      # SYN: MSS and window scale options
        opts = struct.pack('!BBHBBBBBBBB', 2, 4, 1460, 4, 2, 1, 3, 3, 7, 1, 1)
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0) + opts + payload
    return eth(ip4(t, 6, src, dst, ident))


def exported_pdu(name, payload):
    n = name.encode()
    n += b'\0' * ((-len(n)) % 4)
    tags = struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0)
    return tags + payload


def sll(payload, ptype=0, hatype=1, addr=b'\x02\0\0\0\0\x01', proto=0x0800):
    return struct.pack('!HHH', ptype, hatype, len(addr)) + addr.ljust(8, b'\0') + \
        struct.pack('!H', proto) + payload


class TcpConn:
    """One TCP connection with sequence number bookkeeping; the client is
    192.0.2.1 (sport), the server 192.0.2.2 (dport)."""

    def __init__(self, sport, dport, c='192.0.2.1', s='192.0.2.2', isn_c=1000, isn_s=5000):
        self.sport, self.dport, self.c, self.s = sport, dport, c, s
        self.seq_c, self.seq_s = isn_c, isn_s
        self.ident = 1
        self.frames = []

    def _add(self, fr):
        self.frames.append(fr)
        self.ident += 1

    def handshake(self):
        self._add(tcp(b'', self.sport, self.dport, self.seq_c, 0, 0x02, self.c, self.s, self.ident))
        self.seq_c += 1
        self._add(tcp(b'', self.dport, self.sport, self.seq_s, self.seq_c, 0x12, self.s, self.c, self.ident))
        self.seq_s += 1
        self._add(tcp(b'', self.sport, self.dport, self.seq_c, self.seq_s, 0x10, self.c, self.s, self.ident))

    def send(self, data, client=True, flags=0x18):
        if client:
            self._add(tcp(data, self.sport, self.dport, self.seq_c, self.seq_s, flags, self.c, self.s, self.ident))
            self.seq_c += len(data)
        else:
            self._add(tcp(data, self.dport, self.sport, self.seq_s, self.seq_c, flags, self.s, self.c, self.ident))
            self.seq_s += len(data)


def tcp6(payload, sport, dport, seq, ack=0, flags=0x18,
         src=bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [1]),
         dst=bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [2]), win=65535):
    opts = b''
    if flags & 0x02:
        opts = struct.pack('!BBHBBBBBBBB', 2, 4, 1440, 4, 2, 1, 3, 3, 7, 1, 1)
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0) + opts + payload
    ck = csum(src + dst + struct.pack('!II', len(t), 6) + t)
    t = t[:16] + struct.pack('!H', ck) + t[18:]
    return eth(struct.pack('!IHBB', 0x60000000, len(t), 6, 64) + src + dst + t, 0x86dd)
