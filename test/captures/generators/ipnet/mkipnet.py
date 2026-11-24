#!/usr/bin/env python3
# Generates test/captures/ipnet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the Solaris IPNET dissector (packet-ipnet.c).

Usage: mkipnet.py <outdir>

IPNET is the pcap link type DLT_IPNET (226).  Writes ipnet-coverage.pcap
(clean) and ipnet-coverage-malformed.pcap.  Documentation addresses only.
"""
import socket
import struct
import sys

DLT_IPNET = 226
AF_INET, AF_INET6 = 2, 26


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(payload, proto=17):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2'))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload


def udp6(data=b'ipnet-coverage'):
    seg = struct.pack('!HHHH', 40000, 40001, 8 + len(data), 0) + data
    src = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
    dst = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
    c = csum(src + dst + struct.pack('!IBBBB', len(seg), 0, 0, 0, 17) + seg) or 0xffff
    return seg[:6] + struct.pack('!H', c) + seg[8:]


def ip6(payload, nxt=17):
    return struct.pack('!IHBB', 6 << 28, len(payload), nxt, 64) \
        + socket.inet_pton(socket.AF_INET6, '2001:db8::1') \
        + socket.inet_pton(socket.AF_INET6, '2001:db8::2') + payload


def udp(data=b'ipnet-coverage'):
    return struct.pack('!HHHH', 40000, 40001, 8 + len(data), 0) + data


def hdr(pktlen, family=AF_INET, htype=0, version=1, ifindex=2, grif=3, zsrc=0, zdst=0):
    return struct.pack('!BBHIIIII', version, family, htype, pktlen, ifindex, grif, zsrc, zdst)


def rec(payload_with_hdr, orig=None):
    return (payload_with_hdr, orig or len(payload_with_hdr))


def write(path, recs):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, DLT_IPNET))
        for i, (d, orig) in enumerate(recs):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), orig))
            f.write(d)


def main_recs():
    notes, recs = [], []

    def add(note, d, orig=None):
        notes.append(note)
        recs.append(rec(d, orig))
    p4, p6 = ip4(udp()), ip6(udp6())
    add('IPv4 UDP, inbound hook, interface 2, group interface 3', hdr(len(p4)) + p4)
    add('IPv6 UDP, outbound hook', hdr(len(p6), AF_INET6, 1) + p6)
    add('IPv4: local hook with source and destination zone IDs',
        hdr(len(p4), AF_INET, 2, ifindex=7, grif=9, zsrc=5, zdst=6) + p4)
    hb = bytes([17, 0, 1, 4, 0, 0, 0, 0])   # hop-by-hop with PadN
    p = ip6(hb + udp6(), 0)
    add('IPv6 with a hop-by-hop header', hdr(len(p), AF_INET6, 0) + p)
    add('unknown address family 99: the payload is left undissected', hdr(len(p4), 99) + p4)
    add('header version 2, hook type 7 (unnamed)', hdr(len(p4), AF_INET, htype=7, version=2) + p4)
    add('IPv4 with the maximum interface index and zone IDs',
        hdr(len(p4), AF_INET, 1, ifindex=0xffffffff, grif=0xffffffff, zsrc=0xffffffff, zdst=0xffffffff) + p4)
    # reproducers of "IPNET: Start the payload after the fixed header"
    add('REPRODUCER pktlen 0 (payload offset used to wrap)', hdr(0) + p4)
    add('REPRODUCER pktlen 20, shorter than the payload (IP used to start mid-packet)', hdr(20) + p4)
    big = ip4(udp(b'\0' * 1472))
    add('REPRODUCER snap-length truncated frame: pktlen larger than the captured data',
        (hdr(len(big)) + big)[:24 + 40], 24 + len(big))
    add('IPv6 frame truncated by the snap length', (hdr(len(p6), AF_INET6) + p6)[:24 + 44], 24 + len(p6))
    add('pktlen larger than the frame (IPv4)', hdr(5000) + p4)
    return notes, recs


def malformed_recs():
    notes, recs = [], []

    def add(note, d, orig=None):
        notes.append(note)
        recs.append(rec(d, orig))
    p4 = ip4(udp())
    add('header only (no payload): IP gets an empty tvb', hdr(0))
    add('header cut after 23 octets', hdr(len(p4))[:23])
    add('2 octets only', b'\x01\x02')
    add('IPv6 family with an IPv4 payload', hdr(len(p4), AF_INET6) + p4)
    add('IPv4 family with an IPv6 payload', hdr(40 + 22, AF_INET) + ip6(udp()))
    return notes, recs


if __name__ == '__main__':
    out = sys.argv[1]
    n, r = main_recs()
    write(out + '/ipnet-coverage.pcap', r)
    mn, mr = malformed_recs()
    write(out + '/ipnet-coverage-malformed.pcap', mr)
    with open(out + '/ipnet-frames.txt', 'w') as f:
        for i, t in enumerate(n, 1):
            f.write('%d: %s\n' % (i, t))
        f.write('--- malformed\n')
        for i, t in enumerate(mn, 1):
            f.write('%d: %s\n' % (i, t))
    print(len(r), len(mr))
