#!/usr/bin/env python3
# Generates test/captures/lisp_data_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the LISP data plane
dissector (packet-lisp-data.c).

LISP data packets are UDP port 4341, which is registered, so no Decode As
is needed. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mklisp_data.py <output directory>

Writes:
  lisp-data-coverage.pcap            every combination of the N, L, E, V
                                     and I flags around inner IPv4 and IPv6
                                     packets, an inner packet that is
                                     neither, and a LISP control packet sent
                                     from the data port to the control port
  lisp-data-coverage-malformed.pcap  headers shorter than 8 bytes, inner
                                     packets cut short
"""

import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4_pkt(proto, l4, src='10.1.0.1', dst='10.2.0.1'):
    sa = bytes(map(int, src.split('.')))
    da = bytes(map(int, dst.split('.')))
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, sa, da)
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + l4


V6A = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])
V6B = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [2])


def ipv6_pkt(proto, l4):
    return struct.pack('!IHBB16s16s', 0x60000000, len(l4), proto, 64, V6A, V6B) + l4


def udp4(payload, sport, dport, src, dst):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return u


def udp6(payload, sport, dport, src, dst):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ck = csum(src + dst + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u) or 0xffff
    return u[:6] + struct.pack('!H', ck) + u[8:]


def outer4(payload, sport=4341, dport=4341):
    ip = ipv4_pkt(17, udp4(payload, sport, dport, None, None), '192.0.2.1', '192.0.2.2')
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip


def outer6(payload, sport=4341, dport=4341):
    ip = ipv6_pkt(17, udp6(payload, sport, dport, V6A, V6B))
    return bytes.fromhex('020000000002020000000001') + b'\x86\xdd' + ip


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def inner4(n=0):
    return ipv4_pkt(17, struct.pack('!HHHH', 41000 + n, 41001, 8 + 4, 0) + b'data', '10.1.0.1', '10.2.0.1')


def inner6(n=0):
    return ipv6_pkt(17, udp6(b'data', 41000 + n, 41001, V6A, V6B))


N, L, E, V, I = 0x80, 0x40, 0x20, 0x10, 0x08


def hdr(flags, w1=0, w2=0, w3=0, nonce=0, mapver=0, iid=0, lsb=0, lsb8=0):
    """Flags octet followed by the 3 octet nonce / map-version word and the
    instance-ID / locator-status-bits word."""
    h = bytes([flags])
    h += struct.pack('!I', (nonce if flags & N else mapver))[1:]
    if flags & I:
        h += struct.pack('!I', (iid << 8) | lsb8)
    else:
        h += struct.pack('!I', lsb)
    return h


def build_main():
    F = []
    # N: nonce present; with L: LSBs; with E: echo-nonce request
    F.append(outer4(hdr(N, nonce=0x123456, lsb=0) + inner4(0)))
    F.append(outer4(hdr(N | L, nonce=0xabcdef, lsb=0x00000003) + inner4(1)))
    F.append(outer4(hdr(N | E, nonce=0x0a0b0c) + inner4(2)))
    F.append(outer6(hdr(N | L | E, nonce=0x010203, lsb=0xffffffff) + inner6(3)))
    # V: map-version present
    F.append(outer4(hdr(V, mapver=0x123abc) + inner6(4)))
    F.append(outer4(hdr(V | L, mapver=0xfff001, lsb=0x80000001) + inner4(5)))
    # instance ID, with and without locator status bits
    F.append(outer4(hdr(I, iid=0x00abcd, lsb8=0) + inner4(6)))
    F.append(outer4(hdr(N | I, nonce=0x112233, iid=0x00ffff, lsb8=0x55) + inner4(7)))
    F.append(outer4(hdr(N | I | L, nonce=0x112233, iid=0x010203, lsb8=0xa5) + inner4(8)))
    F.append(outer6(hdr(V | I | L, mapver=0x001002, iid=0x000001, lsb8=0x0f) + inner6(9)))
    # no flags, reserved bits
    F.append(outer4(hdr(0) + inner4(10)))
    F.append(outer4(hdr(0x07) + inner4(11)))
    F.append(outer6(hdr(L, lsb=0x1) + inner6(12)))
    # invalid combinations: E without N, N with V
    F.append(outer4(hdr(E) + inner4(13)))
    F.append(outer4(hdr(N | V, nonce=0x000001) + inner4(14)))
    # inner packet that is neither IPv4 nor IPv6
    F.append(outer4(hdr(N, nonce=7) + b'\x00\x01\x02\x03'))
    # data header over IPv6 transport carrying IPv4
    F.append(outer6(hdr(N, nonce=0x777777) + inner4(15)))
    # A LISP control packet from the data port to the control port
    req = struct.pack('!I', 1 << 20)[1:] + bytes([1]) + bytes(range(8)) + struct.pack('!H', 1) + bytes([10, 1, 0, 1]) \
        + struct.pack('!H', 1) + bytes([192, 0, 2, 9]) + bytes([0, 32]) + struct.pack('!H', 1) + bytes([10, 2, 0, 1])
    F.append(outer4(req, sport=4341, dport=4342))
    return F


def build_malformed():
    F = []
    # header shorter than 8 bytes: the dissector declines
    F.append(outer4(b'\x80\x00\x00'))
    F.append(outer4(b''))
    F.append(outer4(b'\x80\x00\x00\x01\x00\x00\x00'))
    # nothing after the 8 octet header: the inner packet type is read
    # past the end (exception)
    F.append(outer4(hdr(N, nonce=7)))
    # inner IPv4 header cut short
    F.append(outer4(hdr(N, nonce=1) + b'\x45\x00\x00'))
    # inner IPv6 header cut short
    F.append(outer4(hdr(N, nonce=1) + b'\x60\x00\x00\x00\x00'))
    # a control packet cut short
    F.append(outer4(b'\x10\x00\x00', sport=4341, dport=4342))
    return F


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'lisp-data-coverage.pcap'), build_main())
    pcap(os.path.join(out, 'lisp-data-coverage-malformed.pcap'), build_malformed())


if __name__ == '__main__':
    main()
