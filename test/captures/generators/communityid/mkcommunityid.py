#!/usr/bin/env python3
# Generates test/captures/communityid_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Community ID
post-dissector (packet-communityid.c).

Community ID hashes the flow tuple (seed, addresses, IP protocol, ports)
with SHA-1 and shows it as "1:<base64>" or "1:<hex>". The post-dissector
is disabled by default (enable it with --enable-protocol communityid or
the enabled_protos file in cfg/). It handles TCP, UDP and SCTP over IPv4
and IPv6, ICMP and ICMPv6 (type and code as ports, with request/reply
pairs mapped to one flow) and other IP protocols without ports. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkcommunityid.py <output directory>

Writes:
  communityid-coverage.pcap            TCP/UDP/SCTP flows in both
                                       directions over IPv4 and IPv6,
                                       every ICMP and ICMPv6 type with a
                                       reply mapping, one-way ICMP,
                                       IP-only flows, tunnels, non-IP
  communityid-coverage-malformed.pcap  truncated TCP and ICMP headers
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')

V4_A = '192.0.2.1'
V4_B = '192.0.2.2'
V6_A = '2001:db8::1'
V6_B = '2001:db8::2'


def a4(s):
    return bytes(map(int, s.split('.')))


def a6(s):
    head, _, tail = s.partition('::')
    h = [int(x, 16) for x in head.split(':') if x]
    t = [int(x, 16) for x in tail.split(':') if x]
    return struct.pack('>8H', *(h + [0] * (8 - len(h) - len(t)) + t))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def eth(payload, etype, rev=False):
    src, dst = (MAC_B, MAC_A) if rev else (MAC_A, MAC_B)
    return dst + src + struct.pack('>H', etype) + payload


def ip4hdr(proto, payload, src, dst):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64,
                    proto, 0, a4(src), a4(dst))
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def ip6hdr(nh, payload, src, dst, hlim=64):
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, hlim) + \
        a6(src) + a6(dst) + payload


def ipv4(proto, payload, src=V4_A, dst=V4_B):
    return eth(ip4hdr(proto, payload, src, dst), 0x0800, src > dst)


def ipv6(nh, payload, src=V6_A, dst=V6_B, hlim=64):
    return eth(ip6hdr(nh, payload, src, dst, hlim), 0x86dd, src > dst)


def pseudo6(src, dst, nh, length):
    return a6(src) + a6(dst) + struct.pack('>IxxxB', length, nh)


def pseudo4(src, dst, proto, length):
    return a4(src) + a4(dst) + struct.pack('>xBH', proto, length)


def tcphdr(sport, dport, seq, flags, pseudo, data=b''):
    h = struct.pack('>HHIIBBHHH', sport, dport, seq, 0 if flags == 0x02 else 1,
                    0x50, flags, 65535, 0, 0) + data
    c = csum(pseudo(len(h)) + h)
    return h[:16] + struct.pack('>H', c) + h[18:]


def tcp4(sport, dport, seq=1000, flags=0x02, src=V4_A, dst=V4_B, data=b''):
    return ipv4(6, tcphdr(sport, dport, seq, flags,
                          lambda n: pseudo4(src, dst, 6, n), data), src, dst)


def tcp6(sport, dport, seq=1000, flags=0x02, src=V6_A, dst=V6_B, data=b''):
    return ipv6(6, tcphdr(sport, dport, seq, flags,
                          lambda n: pseudo6(src, dst, 6, n), data), src, dst)


def udphdr(sport, dport, data, pseudo):
    h = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    c = csum(pseudo(len(h)) + h) or 0xffff
    return h[:6] + struct.pack('>H', c) + h[8:]


def udp4(sport, dport, data=b'abcd', src=V4_A, dst=V4_B):
    return ipv4(17, udphdr(sport, dport, data,
                           lambda n: pseudo4(src, dst, 17, n)), src, dst)


def udp6(sport, dport, data=b'abcd', src=V6_A, dst=V6_B):
    return ipv6(17, udphdr(sport, dport, data,
                           lambda n: pseudo6(src, dst, 17, n)), src, dst)


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def sctphdr(sport, dport):
    # One INIT chunk
    init = struct.pack('>BBHIIHHI', 1, 0, 20, 0x11223344, 65535, 1, 1, 1)
    h = struct.pack('>HHII', sport, dport, 0, 0) + init
    c = crc32c(h)
    return h[:8] + struct.pack('<I', c) + h[12:]


def sctp4(sport, dport, src=V4_A, dst=V4_B):
    return ipv4(132, sctphdr(sport, dport), src, dst)


def sctp6(sport, dport, src=V6_A, dst=V6_B):
    return ipv6(132, sctphdr(sport, dport), src, dst)


def icmp4(typ, code, body, src=V4_A, dst=V4_B):
    h = struct.pack('>BBH', typ, code, 0) + body
    h = h[:2] + struct.pack('>H', csum(h)) + h[4:]
    return ipv4(1, h, src, dst)


def icmp6(typ, code, body, src=V6_A, dst=V6_B, hlim=64):
    h = struct.pack('>BBH', typ, code, 0) + body
    c = csum(pseudo6(src, dst, 58, len(h)) + h)
    h = h[:2] + struct.pack('>H', c) + h[4:]
    return ipv6(58, h, src, dst, hlim)


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def main_frames():
    F = []
    # 1-4: TCP over IPv4, both directions, then the reverse ordering of
    #      addresses (lower address as destination)
    F.append(tcp4(40000, 80))
    F.append(tcp4(80, 40000, 5000, 0x12, V4_B, V4_A))
    F.append(tcp4(40001, 443, 2000, 0x02, '198.51.100.9', '198.51.100.3'))
    F.append(tcp4(443, 40001, 7000, 0x12, '198.51.100.3', '198.51.100.9'))
    # 5-6: TCP between ports of the same address (address compare equal):
    #      lower port first and higher port first
    F.append(tcp4(1000, 2000, 1, 0x02, '127.0.0.1', '127.0.0.1'))
    F.append(tcp4(2000, 1000, 9, 0x12, '127.0.0.1', '127.0.0.1'))
    # 7-8: UDP over IPv4 both directions
    F.append(udp4(40005, 33333))
    F.append(udp4(33333, 40005, b'wxyz', V4_B, V4_A))
    # 9-10: SCTP over IPv4 both directions
    F.append(sctp4(7000, 7001))
    F.append(sctp4(7001, 7000, V4_B, V4_A))
    # 11-12: TCP over IPv6 both directions
    F.append(tcp6(40002, 22))
    F.append(tcp6(22, 40002, 3000, 0x12, V6_B, V6_A))
    # 13-14: UDP over IPv6 both directions
    F.append(udp6(40003, 33334))
    F.append(udp6(33334, 40003, b'wxyz', V6_B, V6_A))
    # 15-16: SCTP over IPv6 both directions
    F.append(sctp6(7002, 7003))
    F.append(sctp6(7003, 7002, V6_B, V6_A))
    # 17-26: ICMP request/reply pairs: echo, timestamp, information,
    #        router solicitation/advertisement, address mask
    F.append(icmp4(8, 0, struct.pack('>HH', 1, 1) + b'ping'))
    F.append(icmp4(0, 0, struct.pack('>HH', 1, 1) + b'ping', V4_B, V4_A))
    F.append(icmp4(13, 0, struct.pack('>HHIII', 2, 1, 1000, 0, 0)))
    F.append(icmp4(14, 0, struct.pack('>HHIII', 2, 1, 1000, 1001, 1002), V4_B, V4_A))
    F.append(icmp4(15, 0, struct.pack('>HH', 3, 1)))
    F.append(icmp4(16, 0, struct.pack('>HH', 3, 1), V4_B, V4_A))
    F.append(icmp4(10, 0, b'\0' * 4, V4_A, '224.0.0.2'))
    F.append(icmp4(9, 0, struct.pack('>BBH', 1, 2, 1800) + a4(V4_B) + struct.pack('>I', 0),
                   V4_B, '224.0.0.1'))
    F.append(icmp4(17, 0, struct.pack('>HHI', 4, 1, 0)))
    F.append(icmp4(18, 0, struct.pack('>HH', 4, 1) + a4('255.255.255.0'), V4_B, V4_A))
    # 27-28: one-way ICMP: destination unreachable (port unreachable)
    #        quoting the UDP packet of frame 7, and time exceeded
    quoted = ip4hdr(17, struct.pack('>HHHH', 40005, 33333, 12, 0) + b'abcd', V4_A, V4_B)
    F.append(icmp4(3, 3, b'\0' * 4 + quoted, V4_B, V4_A))
    F.append(icmp4(11, 0, b'\0' * 4 + quoted, '198.51.100.254', V4_A))
    # 29-40: ICMPv6 request/reply pairs: echo, MLD query/report, router
    #        solicitation/advertisement, neighbor solicitation and
    #        advertisement, node information query/reply (WRU), home
    #        agent address discovery request/reply
    F.append(icmp6(128, 0, struct.pack('>HH', 1, 1) + b'ping'))
    F.append(icmp6(129, 0, struct.pack('>HH', 1, 1) + b'ping', V6_B, V6_A))
    F.append(icmp6(130, 0, struct.pack('>HH', 1000, 0) + a6('::') +
                   struct.pack('>BBH', 2, 125, 0), 'fe80::1', 'ff02::1', 1))
    F.append(icmp6(131, 0, struct.pack('>HH', 0, 0) + a6('ff02::1:3'),
                   'fe80::2', 'ff02::1:3', 1))
    F.append(icmp6(133, 0, b'\0' * 4, 'fe80::2', 'ff02::2', 255))
    F.append(icmp6(134, 0, struct.pack('>BBHII', 64, 0, 1800, 0, 0),
                   'fe80::1', 'ff02::1', 255))
    F.append(icmp6(135, 0, b'\0' * 4 + a6(V6_B), V6_A, 'ff02::1:ff00:2', 255))
    F.append(icmp6(136, 0, struct.pack('>I', 0x60000000) + a6(V6_B), V6_B, V6_A, 255))
    F.append(icmp6(139, 0, struct.pack('>HH', 2, 0) + b'\x01\x02\x03\x04\x05\x06\x07\x08' + a6(V6_B)))
    F.append(icmp6(140, 0, struct.pack('>HH', 2, 0) + b'\x01\x02\x03\x04\x05\x06\x07\x08' +
                   struct.pack('>I', 0) + b'\x04host\x00\x00\x00', V6_B, V6_A))
    F.append(icmp6(144, 0, struct.pack('>HH', 7, 0), V6_A, '2001:db8::fdff:ffff:ffff:fffe'))
    F.append(icmp6(145, 0, struct.pack('>HH', 7, 0) + a6('2001:db8::10'), '2001:db8::10', V6_A))
    # 41-42: one-way ICMPv6: destination unreachable quoting the UDP
    #        packet of frame 13, packet too big
    quoted6 = ip6hdr(17, udphdr(40003, 33334, b'abcd',
                                lambda n: pseudo6(V6_A, V6_B, 17, n)), V6_A, V6_B)
    F.append(icmp6(1, 4, b'\0' * 4 + quoted6, V6_B, V6_A))
    F.append(icmp6(2, 0, struct.pack('>I', 1280) + quoted6, '2001:db8::fe', V6_A))
    # 43-44: IP-only flows without ports over IPv4: protocol 99 in both
    #        directions
    F.append(ipv4(99, b'\0' * 8))
    F.append(ipv4(99, b'\0' * 8, V4_B, V4_A))
    # 45: ARP: not IP, no Community ID
    F.append(eth(struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + MAC_A + a4(V4_A) +
                 b'\0' * 6 + a4(V4_B), 0x0806))
    # 46: TCP inside IPv4-in-IPv4: hashed on the inner flow
    F.append(ipv4(4, ip4hdr(6, tcphdr(40004, 25, 1, 0x02,
                                      lambda n: pseudo4('198.51.100.1', '198.51.100.2', 6, n)),
                            '198.51.100.1', '198.51.100.2'),
                  '203.0.113.1', '203.0.113.2'))
    # 47-48: reproducer communityid_ipv6_ip_only: IPv4 protocol 99, then
    #        IPv6 next header 99 (gets no Community ID, see README)
    F.append(ipv4(99, b'\0' * 8))
    F.append(ipv6(99, b'\0' * 8))
    # 49-50: reproducer communityid_tunnel_proto: IPv4 protocol 4
    #        carrying IPv4 protocol 99, then the bare inner packet (they
    #        hash differently, see README)
    inner = ip4hdr(99, b'\0' * 8, '198.51.100.1', '198.51.100.2')
    F.append(ipv4(4, inner, V4_A, V4_B))
    F.append(ipv4(99, b'\0' * 8, '198.51.100.1', '198.51.100.2'))
    return F


def malformed_frames():
    F = []
    # 1: IPv4 protocol 6 with a 4 octet TCP header: the TCP dissector
    #    throws before the ports are known, so it is hashed as IP-only
    F.append(ipv4(6, struct.pack('>HH', 40000, 80)))
    # 2: ICMP with only 2 octets: no ICMP info is stored, IP-only
    F.append(ipv4(1, b'\x08\x00'))
    # 3: ICMPv6 with only 2 octets
    F.append(ipv6(58, b'\x80\x00'))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'communityid-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'communityid-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
