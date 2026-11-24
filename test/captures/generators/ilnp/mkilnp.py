#!/usr/bin/env python3
# Generates test/captures/ilnp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the ILNP dissector (packet-ilnp.c).

Usage: mkilnp.py <outdir>

ILNP is reached only through the IPv6 destination options ILNP Nonce
option (type 0x8b), so every frame is an Ethernet/IPv6 packet with that
option.  Writes ilnp-coverage.pcapng (clean) and
ilnp-coverage-malformed.pcapng.
"""
import socket
import struct
import sys

# ---------------------------------------------------------------- helpers


def a6(s):
    return socket.inet_pton(socket.AF_INET6, s)


def a4(s):
    return socket.inet_aton(s)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def blk(btype, body):
    pad = (-len(body)) % 4
    tot = 12 + len(body) + pad
    return struct.pack('<II', btype, tot) + body + b'\0' * pad + struct.pack('<I', tot)


class Cap:
    """pcapng writer with several interfaces; frames = (ifidx, data, orig)."""

    def __init__(self, linktypes):
        self.linktypes = linktypes
        self.frames = []
        self.notes = []

    def add(self, note, data, iface=0, orig=None):
        self.frames.append((iface, data, orig if orig else len(data)))
        self.notes.append(note)
        return len(self.frames)

    def write(self, path):
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.linktypes:
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
        for i, (ifidx, data, orig) in enumerate(self.frames):
            ts = (1700000000 + i) * 1000000
            out += blk(6, struct.pack('<IIIII', ifidx, ts >> 32, ts & 0xffffffff,
                                      len(data), orig) + data)
        with open(path, 'wb') as f:
            f.write(out)


ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01'
SRC = a6('2001:db8::1')
DST = a6('2001:db8::2')

NXT_HBH, NXT_TCP, NXT_UDP, NXT_V6, NXT_RT, NXT_FRAG, NXT_AH = 0, 6, 17, 41, 43, 44, 51
NXT_ICMP6, NXT_NONE, NXT_DST, NXT_V4 = 58, 59, 60, 4


def ip6(payload, nxt, src=SRC, dst=DST, tc=0, flow=0, hlim=64, plen=None):
    if plen is None:
        plen = len(payload)
    return struct.pack('>IHBB', (6 << 28) | (tc << 20) | flow, plen, nxt, hlim) \
        + src + dst + payload


def eth6(payload, nxt, **kw):
    return ETH + b'\x86\xdd' + ip6(payload, nxt, **kw)


def eth4(payload, proto, ttl=64):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, ttl, proto, 0,
                      a4('192.0.2.1'), a4('192.0.2.2'))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return ETH + b'\x08\x00' + hdr + payload


def l4csum(src, dst, nxt, seg, off):
    pseudo = src + dst + struct.pack('>IBBBB', len(seg), 0, 0, 0, nxt)
    c = csum(pseudo + seg)
    if c == 0:
        c = 0xffff
    return seg[:off] + struct.pack('>H', c) + seg[off + 2:]


def udp(data=b'ipv6-coverage', src=SRC, dst=DST, sport=40000, dport=40001):
    seg = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    return l4csum(src, dst, NXT_UDP, seg, 6)


def icmp6(typ, code, body, src=SRC, dst=DST):
    seg = struct.pack('>BBHI', typ, code, 0, 0) + body
    return l4csum(src, dst, NXT_ICMP6, seg, 2)


def pad_opts(opts, extra=2):
    """Pad an options area to a multiple of 8 (with the 2 header octets)."""
    n = (-(len(opts) + extra)) % 8
    if n == 1:
        opts += b'\x00'
    elif n:
        opts += bytes([1, n - 2]) + bytes(n - 2)
    return opts


def exthdr(nxt, opts):
    opts = pad_opts(opts)
    return struct.pack('>BB', nxt, (len(opts) + 2) // 8 - 1) + opts


def opt(t, data=b''):
    return bytes([t, len(data)]) + data


def hbh(nxt, opts):
    return exthdr(nxt, opts)


def dst_opts(nxt, opts):
    return exthdr(nxt, opts)


def rt(nxt, rtype, segleft, body):
    """Routing header; body is the type specific data after the 4 octets."""
    body += bytes((-len(body) - 4) % 8)
    return struct.pack('>BBBB', nxt, (len(body) + 4) // 8 - 1, rtype, segleft) + body


def frag(nxt, off, more, ident, data):
    return struct.pack('>BBHI', nxt, 0, (off & 0xfff8) | (1 if more else 0), ident) + data



U = udp()


def nonce_pkt(nonce, src, dst, nxt=NXT_UDP, tail=U, extra=b''):
    return eth6(dst_opts(nxt, opt(0x8b, nonce) + extra) + tail, NXT_DST,
                src=a6(src), dst=a6(dst))


def build_main():
    c = Cap([1])
    add = c.add
    A, B = '2001:db8:1:1:1111:2222:3333:4444', '2001:db8:2:2:aaaa:bbbb:cccc:dddd'
    add('nonce (4 octets) from A to B, new stream 0', nonce_pkt(b'\x11\x22\x33\x44', A, B))
    add('nonce from B to A, same conversation', nonce_pkt(b'\x55\x66\x77\x88', B, A))
    add('A to B again, different locators (same NIDs, other conversation)',
        nonce_pkt(b'\x11\x22\x33\x44', '2001:db8:9:9:1111:2222:3333:4444', '2001:db8:8:8:aaaa:bbbb:cccc:dddd'))
    add('another pair, new stream, 8 octet nonce',
        nonce_pkt(bytes(range(8)), 'fd00::1:0:0:1', 'fd00::2:0:0:2'))
    add('nonce with zero length', nonce_pkt(b'', A, B))
    add('two nonce options in one header', nonce_pkt(b'\x01\x02\x03\x04', A, B, extra=opt(0x8b, b'\x09\x08')))
    add('nonce followed by a fragment header and UDP',
        nonce_pkt(b'\xaa\xbb\xcc\xdd', A, B, nxt=NXT_FRAG, tail=frag(NXT_UDP, 0, False, 0x1234, U)))
    add('nonce of 16 octets, no next header after the options',
        nonce_pkt(bytes(range(16)), B, A, nxt=NXT_NONE, tail=b'\x01\x02\x03\x04'))
    add('nonce of 250 octets (largest that fits a 255 octet header)', nonce_pkt(bytes(range(250)), 'fe80::1:2:3:4', 'fe80::5:6:7:8'))
    add('same pair, again (conversation reuse)', nonce_pkt(b'\x00\x00\x00\x01', 'fe80::1:2:3:4', 'fe80::5:6:7:8'))
    add('IPv6 without an ILNP nonce (not decoded as ILNP)', eth6(U, NXT_UDP))
    # reproducer shape from the review: nonce in IPv4 and after a fragment header
    add('nonce in a destination options header carried in IPv4: ILNP returns without dissecting',
        eth4(dst_opts(NXT_UDP, opt(0x8b, b'\x11\x22\x33\x44')) + U, 60))
    return c


def build_malformed():
    c = Cap([1])
    add = c.add
    A, B = '2001:db8:1::1', '2001:db8:2::2'
    add('nonce length beyond the option header (option cut)',
        eth6(bytes([NXT_UDP, 0, 0x8b, 20, 1, 2, 3, 4]) + U, NXT_DST, src=a6(A), dst=a6(B)))
    add('nonce option in a hop-by-hop header (header mismatch)',
        eth6(bytes([NXT_UDP, 0]) + opt(0x8b, b'\x01\x02\x03\x04') + bytes(2) + U, NXT_HBH, src=a6(A), dst=a6(B)))
    add('nonce followed by truncated payload', nonce_pkt(b'\x01\x02\x03\x04', A, B)[:14 + 40 + 10])
    return c


if __name__ == '__main__':
    out = sys.argv[1]
    m = build_main()
    m.write(out + '/ilnp-coverage.pcapng')
    b = build_malformed()
    b.write(out + '/ilnp-coverage-malformed.pcapng')
    with open(out + '/ilnp-frames.txt', 'w') as f:
        for i, n in enumerate(m.notes, 1):
            f.write('%d: %s\n' % (i, n))
        f.write('--- malformed\n')
        for i, n in enumerate(b.notes, 1):
            f.write('%d: %s\n' % (i, n))
    print(len(m.frames), len(b.frames))
