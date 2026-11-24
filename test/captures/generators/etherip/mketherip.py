#!/usr/bin/env python3
# Generates test/captures/etherip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the EtherIP dissector (packet-etherip.c).

EtherIP (RFC 3378) is IP protocol 97: a 16 bit header (4 bit version,
12 reserved bits) followed by an Ethernet frame without FCS. Every packet
is built from scratch with struct.

Usage: mketherip.py <output directory>

Writes:
  etherip-coverage.pcap            version 3 / reserved 0 over IPv4 and IPv6
                                   carrying ARP, IPv4/UDP, IPv6, 802.1Q;
                                   version != 3, reserved != 0, both
  etherip-coverage-malformed.pcap  EtherIP with 1 octet, inner Ethernet cut
"""
import os
import struct
import sys

M1 = bytes.fromhex('020000000001'); M2 = bytes.fromhex('020000000002')

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def eth(dst, src, typ, payload):
    return dst + src + struct.pack('!H', typ) + payload

def ip4(src, dst, proto, payload):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def udp6(src, dst, sp, dp, data):
    u = udp(sp, dp, data)
    c = csum(src + dst + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def ip6(src, dst, nh, payload):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nh, 64, src, dst) + payload

def udp(sp, dp, data):
    return struct.pack('!HHHH', sp, dp, 8 + len(data), 0) + data

A4 = bytes([10, 0, 0, 1]); B4 = bytes([10, 0, 0, 2])
A6 = bytes.fromhex('fd000000000000000000000000000001')
B6 = bytes.fromhex('fd000000000000000000000000000002')
IA = bytes([192, 168, 1, 1]); IB = bytes([192, 168, 1, 2])

arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, M1, IA, b'\0' * 6, IB)
inner_udp = eth(M2, M1, 0x0800, ip4(IA, IB, 17, udp(1234, 5678, b'hello etherip')))
inner_ip6 = eth(M2, M1, 0x86dd, ip6(A6, B6, 17, udp6(A6, B6, 6001, 6002, b'v6 inside')))
inner_arp = eth(b'\xff' * 6, M1, 0x0806, arp)
inner_vlan = eth(M2, M1, 0x8100, struct.pack('!HH', 5, 0x0800) + ip4(IA, IB, 17, udp(3333, 4444, b'vlan')))

def eip(ver, res=0): return struct.pack('!H', (ver << 12) | res)

def outer4(payload): return eth(M2, M1, 0x0800, ip4(A4, B4, 97, payload))
def outer6(payload): return eth(M2, M1, 0x86dd, ip6(A6, B6, 97, payload))

main = [
    outer4(eip(3) + inner_udp),
    outer4(eip(3) + inner_arp),
    outer4(eip(3) + inner_ip6),
    outer4(eip(3) + inner_vlan),
    outer6(eip(3) + inner_udp),
    outer6(eip(3) + inner_arp),
    outer4(eip(2) + inner_udp),
    outer4(eip(0xf) + inner_arp),
    outer4(eip(3, 0x001) + inner_udp),
    outer4(eip(3, 0xfff) + inner_arp),
    outer4(eip(1, 0x800) + inner_udp),
]
mal = [
    outer4(b'\x30'),                       # EtherIP header cut to 1 octet
    outer4(eip(3)),                        # no inner Ethernet at all
    outer4(eip(3) + inner_udp[:9]),        # inner Ethernet cut short
    outer4(eip(3) + inner_udp[:30]),       # inner IPv4 cut short
    outer6(eip(3) + inner_ip6[:20]),
]
out = sys.argv[1]; os.makedirs(out, exist_ok=True)
pcap(os.path.join(out, 'etherip-coverage.pcap'), main)
pcap(os.path.join(out, 'etherip-coverage-malformed.pcap'), mal)
