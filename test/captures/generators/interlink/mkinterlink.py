#!/usr/bin/env python3
# Generates test/captures/interlink_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-interlink.c (Interlink over UDP,
heuristic "ILNK" magic).  Usage: mkinterlink.py <outdir> [-v]
Writes interlink-coverage.pcap (main) and interlink-coverage-malformed.pcap."""
import struct
import sys
import os

ETH = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'


def cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def frame(payload, sport=40000, dport=40001):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                    bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    h = h[:10] + struct.pack('!H', cksum(h)) + h[12:]
    return ETH + h + udp


def il(cmd=1, seq=0, flags=0, btype=1, bver=1, data=b'', ver=1, magic=b'ILNK', blen=None):
    """Interlink header (magic, version, command, sequence, flags; little
    endian) and a block header (type, version, length) before the data."""
    if blen is None:
        blen = len(data)
    return (magic + struct.pack('<HHHH', ver, cmd, seq, flags) +
            struct.pack('<BBH', btype, bver, blen) + data)


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
    c.mark('commands')
    c.add(frame(il(cmd=1, seq=1, data=b'hello interlink')))
    c.add(frame(il(cmd=2, seq=1)))                                  # Ack, no data
    c.add(frame(il(cmd=3, seq=2, data=b'\0')))                      # unknown command
    c.add(frame(il(cmd=0, seq=0xffff, data=b'x' * 200)))
    c.mark('flags')
    for fl in (0, 1, 2, 3, 0x8000, 0xfffc):
        c.add(frame(il(flags=fl, seq=10 + fl & 0xff, data=b'flags')))
    c.mark('block_types')
    for t, v in ((0, 0), (1, 1), (2, 1), (0x10, 3), (0xff, 0xff), (7, 0)):
        c.add(frame(il(btype=t, bver=v, data=b'type %d' % t)))
    c.mark('versions')
    c.add(frame(il(ver=0, data=b'v0')))
    c.add(frame(il(ver=2, data=b'v2')))
    c.add(frame(il(ver=0xffff, data=b'vffff')))
    c.mark('ports')
    c.add(frame(il(data=b'port 1'), sport=1, dport=2))
    c.add(frame(il(data=b'port 2'), sport=65000, dport=7000))
    c.add(frame(il(data=b'port 3'), sport=5000, dport=5001))
    c.mark('block_length')
    c.add(frame(il(data=b'abc', blen=100)))                          # block length past the data
    c.add(frame(il(data=b'abc', blen=0)))
    c.add(frame(il(data=b'', blen=0xffff)))
    c.mark('not_interlink')
    c.add(frame(b'ILN'))                                             # 3 octets: no heuristic decision
    c.add(frame(b'ILNX' + bytes(20)))
    c.add(frame(b'ilnk' + bytes(20)))
    c.add(frame(b'LINK' + bytes(20)))
    return c


def malformed_cap():
    c = Cap()
    c.add(frame(b'ILNK'))                                            # magic only
    c.add(frame(b'ILNK\x01\x00'))
    c.add(frame(b'ILNK\x01\x00\x01\x00\x01\x00\x00\x00'))            # no block header
    c.add(frame(b'ILNK\x01\x00\x01\x00\x01\x00\x00\x00\x01\x01'))    # block header cut
    c.add(frame(il()[:11]))
    c.add(frame(il()[:15]))
    c.add(frame(b'ILNK' + b'\0' * 8))
    return c


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_cap()
    m.write(os.path.join(out, 'interlink-coverage.pcap'))
    x = malformed_cap()
    x.write(os.path.join(out, 'interlink-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, nm in m.marks:
            print(n, nm)
        print('main frames', len(m.frames), 'malformed', len(x.frames))


main()
