#!/usr/bin/env python3
# Generates test/captures/stats_tree_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for the stats_tree plugin (plugins/epan/stats_tree,
pinfo_stats_tree.c): the -z ip_hosts,tree / ip_srcdst,tree / ptype,tree /
dests,tree / ip_ttl,tree, the ipv6_* versions and plen,tree.

Usage: mkstats_tree.py <outdir> [-v]
Writes stats_tree-coverage.pcap (and stats_tree-coverage-malformed.pcap).
Built with struct only; addresses are from the documentation ranges.
"""
import struct
import sys
import os


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def eth(payload, et=0x0800, src=1, dst=2):
    return bytes([2, 0, 0, 0, 0, dst, 2, 0, 0, 0, 0, src]) + struct.pack('!H', et) + payload


def ip4(src, dst, proto, payload, ttl=64, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0, src, dst)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def ip6(src, dst, nxt, payload, hop=64):
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), nxt, hop, src, dst) + payload


def udp(sport, dport, payload, pseudo=None):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    if pseudo:
        ck = csum(pseudo + struct.pack('!IxxxB', len(u), 17) + u) or 0xffff
        u = u[:6] + struct.pack('!H', ck) + u[8:]
    return u


def tcp(sport, dport, flags, payload, seq=1, ack=0):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload


def A4(n):
    return bytes([192, 0, 2, n])


def B4(n):
    return bytes([198, 51, 100, n])


def A6(n):
    return bytes.fromhex('20010db8000000000000000000000000')[:15] + bytes([n])


def B6(n):
    return bytes.fromhex('20010db8000100000000000000000000')[:15] + bytes([n])


SCTP_HB = b'\x0b\xb8\x0b\xb8' + b'\0' * 8 + b'\x04\x00\x00\x0c' + b'\x00\x01\x00\x08\0\0\0\0'


def icmp(typ, code, rest, data):
    m = struct.pack('!BBH', typ, code, 0) + rest + data
    return m[:2] + struct.pack('!H', csum(m)) + m[4:]


def icmp6(src, dst, typ, code, rest, data):
    m = struct.pack('!BBH', typ, code, 0) + rest + data
    ck = csum(src + dst + struct.pack('!IxxxB', len(m), 58) + m)
    return m[:2] + struct.pack('!H', ck) + m[4:]


def build():
    f = []
    notes = []

    def note(txt):
        notes.append((len(f) + 1, txt))

    note('IPv4 TCP: three clients, three servers, ports 80/443/22/25/8080, several TTLs, SYN, SYN/ACK and data')
    ttls = [64, 128, 255, 1, 63, 32]
    n = 0
    for ci in (10, 11, 12):
        for si, port in ((20, 80), (21, 443), (22, 22), (23, 25), (24, 8080)):
            ttl = ttls[n % len(ttls)]
            n += 1
            sp = 40000 + n
            f.append(eth(ip4(A4(ci), B4(si), 6, tcp(sp, port, 2, b''), ttl)))
            f.append(eth(ip4(B4(si), A4(ci), 6, tcp(port, sp, 0x12, b'', ack=2), 56), src=2, dst=1))
            f.append(eth(ip4(A4(ci), B4(si), 6, tcp(sp, port, 0x18, b'x' * (n * 7), 2, 1), ttl)))
    note('IPv4 UDP: DNS, NTP, a high port, from several clients (destination ports 53/123/5353/50000)')
    for i, (port, ttl) in enumerate([(53, 64), (123, 64), (5353, 255), (50000, 30), (53, 64), (53, 128)]):
        f.append(eth(ip4(A4(10 + i % 3), B4(30 + i % 2), 17, udp(41000 + i, port, b'\0' * (16 + 60 * i)), ttl)))
    note('IPv4 ICMP echo and ICMP destination unreachable with an inner IPv4+UDP header (two IP layers per frame)')
    f.append(eth(ip4(A4(10), B4(20), 1, icmp(8, 0, b'\0\1\0\1', b'ping' * 4), 64)))
    f.append(eth(ip4(B4(20), A4(10), 1, icmp(0, 0, b'\0\1\0\1', b'ping' * 4), 57), src=2, dst=1))
    inner = ip4(A4(10), B4(20), 17, udp(40000, 33434, b'\0' * 8), 1)
    f.append(eth(ip4(B4(1), A4(10), 1, icmp(3, 3, b'\0' * 4, inner), 250)))
    inner = ip4(A4(11), B4(21), 6, tcp(40001, 80, 2, b''), 1)[:28]
    f.append(eth(ip4(B4(2), A4(11), 1, icmp(11, 0, b'\0' * 4, inner), 249)))
    note('IPv4 other protocols: SCTP (132), DCCP (33), GRE (47), an unknown protocol (253); a frame with a fragment')
    f.append(eth(ip4(A4(10), B4(20), 132, SCTP_HB)))
    dccp = b'\x00\x50\x00\x50\x04\x00\x00\x00' + b'\0' * 8
    ck = csum(A4(10) + B4(20) + struct.pack('!BBH', 0, 33, len(dccp)) + dccp)
    dccp = dccp[:6] + struct.pack('!H', ck) + dccp[8:]
    f.append(eth(ip4(A4(10), B4(20), 33, dccp)))
    f.append(eth(ip4(A4(10), B4(20), 47, b'\x00\x00\x88\xb5' + b'\0' * 4)))
    f.append(eth(ip4(A4(10), B4(20), 253, b'\xaa' * 16)))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + 16, 77, 0x2000, 64, 17, 0, A4(10), B4(20))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    f.append(eth(h + b'\x11' * 16))
    note('IPv6 TCP: hosts 20010db8::10-12 to ::20-24, hop limits, ports 80/443/22/25/8080')
    n = 0
    for ci in (0x10, 0x11, 0x12):
        for si, port in ((0x20, 80), (0x21, 443), (0x22, 22), (0x23, 25), (0x24, 8080)):
            hop = ttls[n % len(ttls)]
            n += 1
            sp = 42000 + n
            f.append(eth(ip6(A6(ci), B6(si), 6, tcp(sp, port, 2, b''), hop), 0x86dd))
            f.append(eth(ip6(B6(si), A6(ci), 6, tcp(port, sp, 0x12, b'', ack=2), 57), 0x86dd, src=2, dst=1))
            f.append(eth(ip6(A6(ci), B6(si), 6, tcp(sp, port, 0x18, b'y' * (n * 9), 2, 1), hop), 0x86dd))
    note('IPv6 UDP: DNS, NTP, mDNS, a high port')
    for i, (port, hop) in enumerate([(53, 64), (123, 64), (5353, 255), (50000, 30), (53, 64), (53, 128)]):
        s, d = A6(0x10 + i % 3), B6(0x30 + i % 2)
        f.append(eth(ip6(s, d, 17, udp(43000 + i, port, b'\0' * (16 + 55 * i), s + d), hop), 0x86dd))
    note('ICMPv6 echo, ICMPv6 destination unreachable carrying an inner IPv6+UDP packet, ICMPv6 time exceeded')
    s, d = A6(0x10), B6(0x20)
    f.append(eth(ip6(s, d, 58, icmp6(s, d, 128, 0, b'\0\1\0\1', b'ping' * 4)), 0x86dd))
    inner = ip6(s, d, 17, udp(40000, 33434, b'\0' * 8, s + d), 1)
    r = B6(0x01)
    f.append(eth(ip6(r, s, 58, icmp6(r, s, 1, 4, b'\0' * 4, inner), 250), 0x86dd))
    f.append(eth(ip6(r, s, 58, icmp6(r, s, 3, 0, b'\0' * 4, inner), 249), 0x86dd))
    note('IPv6 other: SCTP, an unknown next header (253), a hop-by-hop options header before UDP')
    f.append(eth(ip6(s, d, 132, SCTP_HB), 0x86dd))
    f.append(eth(ip6(s, d, 253, b'\xaa' * 16), 0x86dd))
    hbh = bytes([17, 0, 1, 4, 0, 0, 0, 0])
    f.append(eth(ip6(s, d, 0, hbh + udp(40000, 53, b'\0' * 12, s + d), 12), 0x86dd))
    note('Frames of every packet-length range (frame length 18 to 6000): non-IP frames (ethertype 0x88b5), short and long IPv4 UDP')
    for size in (18, 19, 20, 38, 39, 40, 41, 78, 79, 80, 100, 158, 159, 160, 300, 319, 320, 500, 638, 639, 640,
                 1000, 1278, 1279, 1280, 1500, 2559, 2560, 4000, 5119, 5120, 5121, 6000):
        if size < 60:
            f.append(eth(b'\0' * (size - 14), 0x88b5))
        else:
            pl = size - 14 - 20 - 8
            f.append(eth(ip4(A4(13), B4(25), 17, udp(40100, 40101, b'\0' * pl), 61)))
    return f, notes


def write_pcap(fn, frames):
    with open(fn, 'wb') as fp:
        fp.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            fp.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def build_malformed():
    f = []
    # truncated IPv4/IPv6 headers and an IP header whose protocol field says
    # TCP with no TCP header, plus an ICMP with a truncated inner header
    f.append(eth(ip4(A4(10), B4(20), 6, b'')))
    f.append(eth(ip4(A4(10), B4(20), 17, b'\0\1')))
    f.append(eth(ip4(A4(10), B4(20), 1, b'\x03\x01\0\0\0\0\0\0\x45\0')))
    f.append(eth(ip6(A6(10), B6(20), 6, b''), 0x86dd))
    f.append(eth(ip6(A6(10), B6(20), 58, b'\x01\x04\0\0\0\0\0\0\x60\0'), 0x86dd))
    f.append(eth(ip4(A4(10), B4(20), 17, b'\0' * 8)[:25]))
    return f


if __name__ == '__main__':
    out = sys.argv[1]
    frames, notes = build()
    write_pcap(os.path.join(out, 'stats_tree-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'stats_tree-coverage-malformed.pcap'), build_malformed())
    if '-v' in sys.argv:
        print(len(frames), 'frames')
        for i, (first, txt) in enumerate(notes):
            last = notes[i + 1][0] - 1 if i + 1 < len(notes) else len(frames)
            print('%d-%d: %s' % (first, last, txt))
