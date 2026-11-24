#!/usr/bin/env python3
# Generates test/captures/cisco_ttag_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco ttag dissector
(packet-cisco-ttag.c, filter name "ttag").

Cisco ttag (ethertype 0x8905) carries a 48 bit timestamp in nanoseconds
followed by the ethertype of the payload. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkcisco-ttag.py <output directory>
Writes:
  cisco-ttag-coverage.pcap            several timestamps and payloads,
                                      nesting, a trailer and the nesting
                                      limit
  cisco-ttag-coverage-malformed.pcap  truncated headers and payloads
"""
import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
ETH_TTAG = 0x8905


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def eth(etype, payload, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def ip_udp(data, ident=1, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    hdr = struct.pack('>HHHH', 40000 + ident, 9, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return ipv4(17, hdr[:6] + struct.pack('>H', c) + data, src, dst, ident)


def ipv6_udp(data):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    hdr = struct.pack('>HHHH', 40001, 9, 8 + len(data), 0)
    pseudo = src + dst + struct.pack('>II', 8 + len(data), 17)
    c = csum(pseudo + hdr + data) or 0xffff
    u = hdr[:6] + struct.pack('>H', c) + data
    return struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + src + dst + u


def arp():
    return struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC_A,
                       bytes((192, 0, 2, 1)), b'\0' * 6, bytes((192, 0, 2, 2)))


def ttag(ns, etype, payload=b''):
    """48 bit timestamp in nanoseconds, payload ethertype."""
    return struct.pack('>Q', ns)[2:] + struct.pack('>H', etype) + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


# Each nesting level adds two layers (ttag, ethertype); the default
# gui.max_tree_depth is 500 and the dissector stops when the layer count
# + 16 reaches it. 260 levels are enough and keep the frame small (2 KB).
NEST = 260


def main_frames():
    F = []
    # 1: timestamp 0, IPv4 UDP payload
    F.append(eth(ETH_TTAG, ttag(0, 0x0800, ip_udp(b'ttag-ipv4', 1))))
    # 2: 1.5 s, IPv6 UDP payload
    F.append(eth(ETH_TTAG, ttag(1500000000, 0x86dd, ipv6_udp(b'ttag-ipv6'))))
    # 3: 1 ns, ARP payload
    F.append(eth(ETH_TTAG, ttag(1, 0x0806, arp())))
    # 4: the largest timestamp (2^48 - 1 ns, 281474.976710655 s), IPv4
    # followed by 6 octets of trailer
    F.append(eth(ETH_TTAG, ttag(2 ** 48 - 1, 0x0800,
                                ip_udp(b'trailer', 4) + b'\xde\xad\xbe\xef\x00\x01')))
    # 5: ttag in ttag, IPv4 payload
    F.append(eth(ETH_TTAG, ttag(123456789, ETH_TTAG, ttag(987654321, 0x0800,
                                                          ip_udp(b'nested', 5)))))
    # 6: 802.1Q VLAN 42 then IPv4
    F.append(eth(ETH_TTAG, ttag(1000000000, 0x8100,
                                struct.pack('>HH', 42, 0x0800) + ip_udp(b'vlan', 6))))
    # 7: an ethertype with no dissector (local experimental 0x88b5): data
    F.append(eth(ETH_TTAG, ttag(60000000000, 0x88b5, b'experimental')))
    # 8: ttag nested NEST times (the ttag_recursion reproducer, shortened):
    # stops with ttag.too_deep before the layer limit
    payload = b''.join(ttag(i, ETH_TTAG) for i in range(NEST))
    F.append(eth(ETH_TTAG, payload + ttag(NEST, 0x88b5, b'\0' * 8)))
    return F


def malformed_frames():
    F = []
    # 1: only the timestamp, no payload ethertype
    F.append(eth(ETH_TTAG, struct.pack('>Q', 5)[2:]))
    # 2: three octets
    F.append(eth(ETH_TTAG, b'\x00\x00\x01'))
    # 3: IPv4 payload cut short
    F.append(eth(ETH_TTAG, ttag(7, 0x0800, ip_udp(b'cut', 3)[:12])))
    # 4: a nested ttag cut short
    F.append(eth(ETH_TTAG, ttag(8, ETH_TTAG, b'\x00\x00')))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cisco-ttag-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cisco-ttag-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
