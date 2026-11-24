#!/usr/bin/env python3
# Generates test/captures/ipos_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the IPOS dissector (packet-ipos.c).

Usage: mkipos.py <outdir>

IPOS rides on Linux cooked captures (DLT_LINUX_SLL, 113) with the IPOS
protocol numbers 0x30-0x35 and hands the rest to the REDBACK dissector.
Writes ipos-coverage.pcap and ipos-coverage-malformed.pcap.
"""
import socket
import struct
import sys


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp(data=b'ipos-coverage'):
    return struct.pack('!HHHH', 40000, 40001, 8 + len(data), 0) + data


def ip4(payload, proto=17):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2'))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload


def sll(proto, pkttype=0):
    return struct.pack('!HHH8sH', pkttype, 1, 6, b'\x02\x00\x00\x00\x00\x01\x00\x00', proto)


def ipos(protocol, priority, ppe, slot):
    return struct.pack('!BBH', (protocol << 4) | priority, ppe, slot)


def rbn(rproto, payload, dataoff=24, l3off=24, context=0x01020304, flags=0, circuit=0x1122334455667788,
        padding=b''):
    h = struct.pack('!IIQHHHH', context, flags, circuit, len(payload) + dataoff, rproto, dataoff, l3off)
    return h + padding + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113))
        for i, (d, orig) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), orig))
            f.write(d)


class Frames:
    def __init__(self):
        self.frames, self.notes = [], []

    def add(self, note, d, orig=None):
        self.notes.append(note)
        self.frames.append((d, orig or len(d)))


def main_frames():
    c = Frames()
    add = c.add
    p4 = ip4(udp())
    names = {0x30: 'NETIPC', 0x31: 'RBN', 0x32: 'NETLINK', 0x33: 'XCRP', 0x34: 'ISIS', 0x35: 'PAKIO'}
    for n, (lt, nm) in enumerate(names.items()):
        add('SLL protocol 0x%x (%s), IPOS protocol %d, priority %d, PPE %d, slot %d, REDBACK IPv4'
            % (lt, nm, n % 5, n, (4, 6, 10, 4, 6, 10)[n], n + 1),
            sll(lt) + ipos(n % 5, n, (4, 6, 10, 4, 6, 10)[n], n + 1) + rbn(1, p4))
    add('IPOS protocol 5 (unnamed) and PPE 7 (unnamed), priority 15, slot 65535',
        sll(0x31) + ipos(5, 15, 7, 0xffff) + rbn(1, p4))
    add('packet sent by us (SLL packet type 4), unknown REDBACK protocol 0x77',
        sll(0x30, pkttype=4) + ipos(2, 0, 4, 1) + rbn(0x77, b'\x01\x02\x03\x04'))
    add('REDBACK with padding between header and data (data offset 32)',
        sll(0x31) + ipos(1, 3, 6, 2) + rbn(1, p4, dataoff=32, l3off=32, padding=bytes(8)))
    add('IPOS header followed by nothing', sll(0x35) + ipos(4, 1, 10, 3) + bytes(24))
    return c


def malformed_frames():
    c = Frames()
    add = c.add
    p4 = ip4(udp())
    add('SLL header only', sll(0x30))
    add('IPOS header cut after 3 octets', sll(0x30) + b'\x10\x04\x00')
    add('IPOS header only (REDBACK gets an empty tvb)', sll(0x31) + ipos(1, 0, 4, 1))
    add('REDBACK header cut', sll(0x31) + ipos(1, 0, 4, 1) + rbn(1, p4)[:15])
    add('REDBACK data offset beyond the frame', sll(0x31) + ipos(1, 0, 4, 1) + rbn(1, p4, dataoff=400, l3off=400))
    return c


if __name__ == '__main__':
    out = sys.argv[1]
    m = main_frames()
    write_pcap(out + '/ipos-coverage.pcap', m.frames)
    b = malformed_frames()
    write_pcap(out + '/ipos-coverage-malformed.pcap', b.frames)
    with open(out + '/ipos-frames.txt', 'w') as f:
        for i, t in enumerate(m.notes, 1):
            f.write('%d: %s\n' % (i, t))
        f.write('--- malformed\n')
        for i, t in enumerate(b.notes, 1):
            f.write('%d: %s\n' % (i, t))
    print(len(m.frames), len(b.frames))
