#!/usr/bin/env python3
# Generates test/captures/clip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Classical IP over ATM
dissector (packet-clip.c).

Linux ATM Classical IP frames (pcap link type 106) have no link layer
header: the frame is an IP packet. The CLIP dissector adds an empty
protocol item with a note that there is no link information and hands
the frame to the IP dissector. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkclip.py <output directory>

Writes:
  clip-coverage.pcap            IPv4 UDP, ICMP echo request and reply and
                                an IPv6 UDP packet
  clip-coverage-malformed.pcap  an empty frame and an IPv4 header cut short
"""

import os
import struct
import sys

SRC = (192, 0, 2, 1)
DST = (198, 51, 100, 2)
SRC6 = bytes.fromhex('20010db8000000000000000000000001')
DST6 = bytes.fromhex('20010db8000000000000000000000002')


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def ipv4(proto, payload, src=SRC, dst=DST, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def l4sum(proto, seg, src=SRC, dst=DST):
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, proto, len(seg))
    return csum(pseudo + seg)


def udp4(sport, dport, data, src=SRC, dst=DST):
    seg = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    c = l4sum(17, seg, src, dst) or 0xffff
    return seg[:6] + struct.pack('>H', c) + seg[8:]


def icmp_echo(t, ident, seq, data):
    m = struct.pack('>BBHHH', t, 0, 0, ident, seq) + data
    return m[:2] + struct.pack('>H', csum(m)) + m[4:]


def ipv6_udp(sport, dport, data):
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    pseudo = SRC6 + DST6 + struct.pack('>I3xB', len(u), 17)
    c = csum(pseudo + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    return struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + SRC6 + DST6 + u


def main_frames():
    return [
        # 1: IPv4 UDP to the discard port
        ipv4(17, udp4(40000, 9, b'classical-ip'), ident=1),
        # 2-3: ICMP echo request and reply
        ipv4(1, icmp_echo(8, 0x1234, 1, b'abcdefgh'), ident=2),
        ipv4(1, icmp_echo(0, 0x1234, 1, b'abcdefgh'), DST, SRC, ident=3),
        # 4: IPv6 UDP (the IP dissector hands version 6 to IPv6)
        ipv6_udp(40002, 9, b'classical-ipv6'),
    ]


def malformed_frames():
    return [
        # 1: an empty frame
        b'',
        # 2: an IPv4 header cut short
        ipv4(17, udp4(40000, 9, b'x'))[:12],
    ]


def write_pcap(path, frames, linktype=106):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'clip-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'clip-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
