#!/usr/bin/env python3
# Generates test/captures/ipoib_coverage.pcap.gz, ipoib_coverage.snoop.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the IP over InfiniBand dissector (packet-ipoib.c).

Usage: mkipoib.py <outdir>

Writes ipoib-coverage.pcap (DLT_IP_OVER_IB_PCAP, 242), ipoib-coverage.snoop
(snoop file, InfiniBand network type, no GRH pseudo header) and
ipoib-coverage-malformed.pcap.  Documentation addresses and GIDs only.
"""
import socket
import struct
import sys

DLT_IPOIB = 242
SNOOP_IB = 26


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def gid(s):
    return socket.inet_pton(socket.AF_INET6, s)


def udp(data=b'ipoib-coverage'):
    return struct.pack('!HHHH', 40000, 40001, 8 + len(data), 0) + data


def ip4(payload, proto=17, dst='192.0.2.2'):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    socket.inet_aton('192.0.2.1'), socket.inet_aton(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload


def ip6(payload, nxt=17):
    seg = payload
    src, dst = gid('2001:db8::1'), gid('2001:db8::2')
    if nxt == 17:
        seg = payload[:6] + struct.pack('!H', csum(src + dst + struct.pack('!IBBBB', len(payload), 0, 0, 0, 17) + payload) or 0xffff) + payload[8:]
    return struct.pack('!IHBB', 6 << 28, len(seg), nxt, 64) + src + dst + seg


def icmp_echo():
    m = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'abcd'
    return m[:2] + struct.pack('!H', csum(m)) + m[4:]


def arp(op, sqpn=0x80001a, tqpn=0):
    sha = struct.pack('!BBBB', 0x80, 0, 0, 0x1a) + bytes(range(1, 17))
    tha = bytes(20) if op in (1, 3) else struct.pack('!I', 0x80002b) + bytes(range(21, 37))
    return struct.pack('!HHBBH', 0x20, 0x0800, 20, 4, op) + sha + socket.inet_aton('192.0.2.1') \
        + tha + socket.inet_aton('192.0.2.2')


def dest_hdr(qpn=0x000102, dgid='fe80::2:c903:1:2'):
    """40 octet pseudo header without a GRH: first 2 octets zero, then the
    destination address (reserved octet, QPN, GID) at offset 20."""
    return bytes(20) + bytes([0]) + struct.pack('!I', qpn)[1:] + gid(dgid)


def grh(tclass=0x12, flow=0x3456, sqpn=0x000a0b, sgid='fe80::1:c903:1:1', dgid='fe80::2:c903:1:2'):
    """40 octet pseudo header with a GRH: version/traffic class/flow label,
    a reserved octet, the 24 bit source QPN at offset 5, source GID at 8,
    destination GID at 24."""
    w0 = (6 << 28) | (tclass << 20) | flow
    return struct.pack('!I', w0) + b'\x00' + struct.pack('!I', sqpn)[1:] + gid(sgid) + gid(dgid)


def ib(typ, payload, reserved=0):
    return struct.pack('!HH', typ, reserved) + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, DLT_IPOIB))
        for i, (d, orig) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), orig))
            f.write(d)


def write_snoop(path, frames):
    with open(path, 'wb') as f:
        f.write(b'snoop\0\0\0' + struct.pack('>II', 2, SNOOP_IB))
        for i, d in enumerate(frames):
            pad = (-len(d)) % 4
            f.write(struct.pack('>IIIIII', len(d), len(d), 24 + len(d) + pad, 0, 1700000000 + i, 0))
            f.write(d + bytes(pad))


class Frames:
    def __init__(self):
        self.frames, self.notes = [], []

    def add(self, note, d, orig=None):
        self.notes.append(note)
        self.frames.append((d, orig or len(d)))


def main_frames():
    c = Frames()
    add = c.add
    p4, p6 = ip4(udp()), ip6(udp())
    add('IPv4 UDP, destination address pseudo header (no GRH)', dest_hdr() + ib(0x0800, p4))
    add('IPv4 UDP, GRH: traffic class 0x12, flow label 0x3456, source QPN',
        grh() + ib(0x0800, p4))
    add('IPv6 UDP, GRH', grh(tclass=0xff, flow=0xfffff, sqpn=0xffffff) + ib(0x86dd, p6))
    add('ARP request, destination address pseudo header', dest_hdr() + ib(0x0806, arp(1)))
    add('ARP reply, GRH', grh() + ib(0x0806, arp(2)))
    add('Reverse ARP (0x8035), GRH', grh() + ib(0x8035, arp(3)))
    add('unknown type 0x1234 with reserved field set: payload not dissected',
        dest_hdr() + ib(0x1234, b'\xde\xad\xbe\xef', reserved=0xbeef))
    add('IPv4 multicast with a multicast destination GID',
        grh(dgid='ff12:401b:ffff::1') + ib(0x0800, ip4(udp(), dst='239.1.2.3')))
    add('IPv4 ICMP echo request', dest_hdr(qpn=0xffffff) + ib(0x0800, ip4(icmp_echo(), proto=1)))
    return c


def malformed_frames():
    c = Frames()
    add = c.add
    p4 = ip4(udp())
    add('only 39 octets (pseudo header cut)', dest_hdr()[:39])
    add('pseudo header only (no IPoIB header)', dest_hdr())
    add('IPoIB header cut after the type', dest_hdr() + b'\x08\x00')
    add('IPoIB header only, type IPv4 (IP gets an empty tvb)', dest_hdr() + ib(0x0800, b''))
    add('IPv4 type with an IPv6 payload', grh() + ib(0x0800, ip6(udp())))
    add('IPv6 type with an IPv4 payload', grh() + ib(0x86dd, p4))
    add('ARP type with a truncated ARP', dest_hdr() + ib(0x0806, arp(1)[:10]))
    return c


if __name__ == '__main__':
    out = sys.argv[1]
    m = main_frames()
    write_pcap(out + '/ipoib-coverage.pcap', m.frames)
    # snoop: the same payloads without the 40 octet pseudo header
    snoop = [d[40:] for d, _ in m.frames[:3]] + [m.frames[3][0][40:], m.frames[6][0][40:]]
    write_snoop(out + '/ipoib-coverage.snoop', snoop)
    b = malformed_frames()
    write_pcap(out + '/ipoib-coverage-malformed.pcap', b.frames)
    with open(out + '/ipoib-frames.txt', 'w') as f:
        for i, t in enumerate(m.notes, 1):
            f.write('%d: %s\n' % (i, t))
        f.write('--- snoop: frames 1, 2, 3, 4 and 7 of the pcap without the pseudo header\n')
        f.write('--- malformed\n')
        for i, t in enumerate(b.notes, 1):
            f.write('%d: %s\n' % (i, t))
    print(len(m.frames), len(snoop), len(b.frames))
