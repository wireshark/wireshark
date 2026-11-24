#!/usr/bin/env python3
# Generates test/captures/ipvs_syncd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ipvs-syncd.c (IPVS connection
synchronisation, UDP 8848).  Usage: mkipvs-syncd.py <outdir> [-v]
Writes ipvs-syncd-coverage.pcap (main) and
ipvs-syncd-coverage-malformed.pcap."""
import struct
import sys
import os

ETH = bytes.fromhex('01005e000012' '020000000001') + b'\x08\x00'
GRP = bytes([224, 0, 0, 18])
SRC = bytes([192, 0, 2, 1])


def cksum(b):
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def frame(payload, sport=8848, dport=8848, dst=GRP, eth=ETH):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0xc0, 20 + len(udp), 1, 0, 255, 17,
                    0, SRC, dst)
    h = h[:10] + struct.pack('!H', cksum(h)) + h[12:]
    return eth + h + udp


# version 0 -------------------------------------------------------------
def conn_v0(proto=6, cport=1111, vport=80, dport=8080, flags=0, state=0,
            caddr=(192, 0, 2, 10), vaddr=(198, 51, 100, 1),
            daddr=(10, 0, 0, 1), seq=True):
    b = struct.pack('!BBHHH', 0, proto, cport, vport, dport)
    b += bytes(caddr) + bytes(vaddr) + bytes(daddr)
    b += struct.pack('!HH', flags, state)
    if flags & 0x0600:      # IP_VS_CONN_F_SEQ_MASK: full connection info
        b += struct.pack('!6I', 0x1000, 0x20, 0x30, 0x2000, 0x40, 0x50)
    return b


def v0(conns, syncid=3, cnt=None, size=None):
    body = b''.join(conns)
    if cnt is None:
        cnt = len(conns)
    if size is None:
        size = 4 + len(body)
    return struct.pack('!BBH', cnt, syncid, size) + body


# version 1 -------------------------------------------------------------
def conn_v1(type_=0, proto=6, ver=0, opts=b'', flags=0x40, state=4,
            cport=2222, vport=443, dport=8443, fwmark=0, timeout=300,
            caddr=None, vaddr=None, daddr=None, size=None):
    if type_ == 0:
        a = (bytes([192, 0, 2, 20]) if caddr is None else caddr) + \
            (bytes([198, 51, 100, 2]) if vaddr is None else vaddr) + \
            (bytes([10, 0, 0, 2]) if daddr is None else daddr)
    else:
        a = (bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\x01' if caddr is None else caddr) + \
            (bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\x02' if vaddr is None else vaddr) + \
            (bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\x03' if daddr is None else daddr)
    fixed = 24 + len(a)
    if size is None:
        size = fixed + len(opts)
    b = struct.pack('!BBH', type_, proto, (ver << 13) | (size & 0x1fff))
    b += struct.pack('!IHHHHII', flags, state, cport, vport, dport, fwmark,
                     timeout)
    return b + a + opts


def v1(conns, syncid=4, version=1, cnt=None, size=None):
    body = b''.join(conns)
    if cnt is None:
        cnt = len(conns)
    if size is None:
        size = 8 + len(body)
    return struct.pack('!BBHBBH', 0, syncid, size, cnt, version, 0) + body


class Cap:
    def __init__(self):
        self.frames = []
        self.marks = []

    def add(self, d):
        self.frames.append(d)

    def mark(self, name):
        self.marks.append((len(self.frames) + 1, name))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
                f.write(d)


def main_cap():
    c = Cap()
    c.mark('v0')
    c.add(frame(v0([conn_v0()])))
    c.add(frame(v0([conn_v0(proto=17, flags=0x0003 | 0x0040, state=0),
                    conn_v0(flags=0x0080, state=8),
                    conn_v0(flags=0x0100, state=4)])))
    for fl in (0x0001, 0x0002, 0x0003, 0x0800, 0x0200, 0x0400, 0x0600, 0x0fc3):
        c.add(frame(v0([conn_v0(flags=fl)], syncid=fl & 0xff)))
    c.add(frame(v0([conn_v0(proto=1), conn_v0(proto=0x2f)] * 2)))
    c.mark('v1')
    c.add(frame(v1([conn_v1()])))
    c.add(frame(v1([conn_v1(type_=2, proto=17)])))
    c.add(frame(v1([conn_v1(type_=0), conn_v1(type_=2), conn_v1(type_=0, ver=1)])))
    c.add(frame(v1([conn_v1(fwmark=0x10, timeout=0xffffffff, state=0, flags=0)])))
    c.add(frame(v1([conn_v1(proto=1)])))
    c.add(frame(v1([conn_v1(type_=1)])))                  # any other type: IPv6 layout
    c.add(frame(v1([])))
    c.mark('v1_options')
    # the reproducer of "IPVS-SYNCD: Use the v1 connection size to
    # advance": options after the fixed part of a connection
    c.add(frame(v1([conn_v1(caddr=bytes([192, 0, 2, 10]), opts=b'\x01\x18' + bytes(22)),
                    conn_v1(caddr=bytes([192, 0, 2, 11]))])))
    c.add(frame(v1([conn_v1(type_=2, opts=b'\x02\x04abcd'),
                    conn_v1(type_=0, opts=bytes(1)),
                    conn_v1(type_=0)])))
    c.add(frame(v1([conn_v1(opts=bytes(8)), conn_v1(opts=bytes(4), type_=2)])))
    c.mark('version_field')
    c.add(frame(v1([conn_v1()], version=0)))              # version 0 in a v1 header: v0 layout
    c.add(frame(v1([conn_v0()], version=0)))
    c.add(frame(v1([conn_v1()], version=2)))
    return c


def malformed_cap():
    c = Cap()
    c.add(frame(b''))
    c.add(frame(v0([])))                                  # count 0: v1 header missing
    c.add(frame(b'\x01'))
    c.add(frame(b'\x01\x02\x00'))
    c.add(frame(v0([conn_v0()], cnt=2)))                  # fewer connections than counted
    c.add(frame(v0([conn_v0()], cnt=255)))
    c.add(frame(v0([conn_v0()])[:20]))
    c.add(frame(v0([conn_v0(flags=0x0600)])[:30]))
    c.add(frame(v0([conn_v0(flags=0x0600)])[:-1]))
    c.add(frame(v1([conn_v1()], cnt=3)))
    c.add(frame(v1([conn_v1()])[:12]))
    c.add(frame(v1([conn_v1()])[:30]))
    c.add(frame(v1([conn_v1(type_=2)])[:50]))
    c.add(frame(v1([conn_v1(opts=bytes(20))], cnt=1)[:-10]))
    c.add(frame(v1([conn_v1(), conn_v1()], cnt=2)[:-5]))
    # size smaller than the fixed part or with the version bits only: no extra data
    c.add(frame(v1([conn_v1(size=0)])))
    c.add(frame(v1([conn_v1(size=10)])))
    c.add(frame(v1([conn_v1(size=0x1fff)])))              # size past the end of the frame
    c.add(frame(v1([conn_v1(size=60), conn_v1()])))
    return c


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_cap()
    m.write(os.path.join(out, 'ipvs-syncd-coverage.pcap'))
    x = malformed_cap()
    x.write(os.path.join(out, 'ipvs-syncd-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, nm in m.marks:
            print(n, nm)
        print('main frames', len(m.frames), 'malformed', len(x.frames))


main()
