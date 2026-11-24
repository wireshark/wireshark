#!/usr/bin/env python3
# Generates test/captures/null_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Null/Loopback coverage capture (packet-null.c).

Usage: mknull.py <output directory> [-v]   (-v prints the frame ranges)

Writes null-coverage.pcapng (main capture; interface 0 is DLT_NULL,
interface 1 DLT_LOOP) and null-coverage-malformed.pcapng. Everything is
built with struct; addresses are from 192.0.2.0/24 and 2001:db8::/32.

The header of a DLT_NULL frame is the address family in the byte order
of the capturing host (little endian for tshark on x86, which is what
the capture assumes), so the same family appears in several forms: the
host order, big endian (BSD capture on a big endian host), the IRIX
snoop forms (2 byte family and 2 zero bytes, in both orders), the Linux
"cooked" form (2 zero bytes and an Ethernet type) and PPP in HDLC
framing (ff 03).
"""
import os
import struct
import sys

LT_NULL, LT_LOOP = 0, 108


def pcapng(path, frames):
    """frames: list of (interface, bytes). Interface 0 is DLT_NULL, 1 DLT_LOOP."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', LT_NULL, 0, 262144))
    out += block(1, struct.pack('<HHI', LT_LOOP, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp4(sport=40000, dport=40001, data=b'null'):
    u = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + u


def udp6(sport=40000, dport=40001, data=b'null'):
    u = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    c = csum(src + dst + struct.pack('!II', len(u), 17) + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return struct.pack('!IHBB', 0x60000000, len(u), 17, 64) + src + dst + u


def ipx():
    hdr = struct.pack('!HHBB', 0xffff, 30 + 4, 0, 4)
    hdr += struct.pack('!I', 1) + bytes(6) + struct.pack('!H', 0x4000)
    hdr += struct.pack('!I', 2) + b'\x02\0\0\0\0\x01' + struct.pack('!H', 0x4001)
    return hdr + b'ipx!'


def ddp():
    # long DDP header: hop count/length, checksum, dst net, src net, dst
    # node, src node, dst socket, src socket, type
    return struct.pack('!HHHHBBBBB', 13 + 4, 0, 1, 2, 3, 4, 5, 6, 99) + b'ddp!'


def arp():
    return struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + b'\x02\0\0\0\0\x01' + bytes([192, 0, 2, 1]) \
        + bytes(6) + bytes([192, 0, 2, 2])


def ppp_lcp():
    # LCP Echo-Request: code 9, id 1, length 8, magic number
    return struct.pack('!BBHI', 9, 1, 8, 0x01020304)


def le(af):
    return struct.pack('<I', af)


def be(af):
    return struct.pack('>I', af)


def main_frames(verbose=False):
    F = []
    marks = []

    def mark(name):
        marks.append((len(F) + 1, name))
    mark('DLT_NULL: IPv4 in every header form')
    F.append((0, le(2) + udp4()))                     # host order
    F.append((0, be(2) + udp4()))                     # big endian (byte swapped)
    F.append((0, bytes([0, 2, 0, 0]) + udp4()))       # IRIX snoop, 2 byte family (read little endian: 0x200)
    F.append((0, bytes([0, 0, 2, 0]) + udp4()))       # IRIX snoop, family in the upper 16 bits
    mark('DLT_NULL: IPv6 (BSD, FreeBSD, Darwin values)')
    F.append((0, le(24) + udp6()))
    F.append((0, le(28) + udp6()))
    F.append((0, le(30) + udp6()))
    F.append((0, be(28) + udp6()))
    mark('DLT_NULL: Linux style, Ethernet type behind two zero bytes')
    F.append((0, bytes([0, 0, 0x08, 0x00]) + udp4()))
    F.append((0, bytes([0, 0, 0x86, 0xdd]) + udp6()))
    F.append((0, bytes([0, 0, 0x08, 0x06]) + arp()))
    F.append((0, bytes([0, 0, 0x99, 0x99]) + b'unknown ethertype'))
    mark('DLT_NULL: other families (OSI, AppleTalk, IPX, unknown, none)')
    F.append((0, le(7) + b'\x99' + b'osi-unknown-nlpid'))
    F.append((0, le(16) + ddp()))
    F.append((0, le(23) + ipx()))
    F.append((0, le(99) + b'unknown family'))
    F.append((0, le(0) + b'family zero'))
    F.append((0, le(1500) + b'family 1500 (not an Ethernet type)'))
    F.append((0, le(1501) + b'\x00\x01'))                  # smallest "Ethernet type"
    mark('DLT_NULL: PPP in HDLC framing')
    F.append((0, bytes([0xff, 0x03, 0x00, 0x21]) + udp4()))
    F.append((0, bytes([0xff, 0x03, 0xc0, 0x21]) + ppp_lcp()))
    mark('DLT_LOOP: always big endian')
    F.append((1, be(2) + udp4()))
    F.append((1, be(24) + udp6()))
    F.append((1, be(23) + ipx()))
    F.append((1, be(77) + b'unknown loop family'))
    F.append((1, be(0x0800) + udp4()))           # a "family" above 1500 is shown as such, no ethertype lookup
    mark('DLT_NULL: byte swapped value above 0xffff (the type is truncated to 16 bits)')
    F.append((0, bytes([0x78, 0x56, 0x34, 0x12]) + b'swapped above 16 bits'))
    mark('End')
    if verbose:
        for (n, name), nxt in zip(marks, marks[1:]):
            print('%d-%d: %s' % (n, nxt[0] - 1, name))
        print('total', len(F))
    return F


def malformed_frames():
    F = []
    F.append((0, b''))                       # empty
    F.append((0, b'\x02'))                   # one octet
    F.append((0, b'\x02\x00\x00'))           # three octets (family cut)
    F.append((0, bytes([0xff, 0x03])))       # PPP header only
    F.append((0, bytes([0xff])))             # one octet starting a PPP header
    F.append((0, le(2)))                     # IPv4 family without a packet
    F.append((0, le(2) + udp4()[:10]))       # IPv4 header cut
    F.append((0, le(24) + udp6()[:20]))      # IPv6 header cut
    F.append((0, bytes([0, 0, 0x08, 0x00])))             # Ethernet type IPv4, no packet
    F.append((0, bytes([0, 0, 0x08, 0x06]) + arp()[:5]))  # ARP cut
    F.append((0, le(23) + ipx()[:10]))       # IPX cut
    F.append((0, le(16) + ddp()[:6]))        # DDP cut
    F.append((1, b'\x00\x00\x00'))           # DLT_LOOP three octets
    F.append((1, be(2)))                     # DLT_LOOP IPv4 without a packet
    F.append((1, be(24) + udp6()[:12]))
    F.append((0, bytes([0xff, 0x03, 0x00, 0x21])))       # PPP IP without a packet
    return F


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != '-v' else '.'
    pcapng(os.path.join(out, 'null-coverage.pcapng'), main_frames('-v' in sys.argv))
    pcapng(os.path.join(out, 'null-coverage-malformed.pcapng'), malformed_frames())
