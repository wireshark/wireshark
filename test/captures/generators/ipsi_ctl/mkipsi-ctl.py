#!/usr/bin/env python3
# Generates test/captures/ipsi_ctl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ipsi-ctl.c (IPSI control, TCP 5010).
Usage: mkipsi-ctl.py <outdir> [-v]
Writes ipsi-ctl-coverage.pcap (main) and ipsi-ctl-coverage-malformed.pcap."""
import struct
import sys
import os

ETH = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'
MAGIC = 0x0300


def cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self):
        self.frames = []
        self.marks = []
        self.seq = {}
        self.ipid = 1

    def mark(self, name):
        self.marks.append((len(self.frames) + 1, name))

    def tcp(self, payload, sport=40000, dport=5010, flags=0x18, src=(192, 0, 2, 1),
            dst=(192, 0, 2, 2)):
        key = (sport, dport)
        seq = self.seq.get(key, 1000)
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, flags, 65535, 0, 0) + payload
        self.seq[key] = seq + len(payload) + (1 if flags & 3 else 0)
        h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t), self.ipid, 0, 64, 6, 0,
                        bytes(src), bytes(dst))
        self.ipid += 1
        h = h[:10] + struct.pack('!H', cksum(h)) + h[12:]
        self.frames.append(ETH + h + t)

    def raw(self, d):
        self.frames.append(d)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
                f.write(d)


def pdu(type_, seq, field1, data=b'', length=None, magic=MAGIC):
    """length counts everything after the length field: type, sequence,
    field1 and data."""
    if length is None:
        length = 6 + len(data)
    return struct.pack('!HHHHH', magic, length, type_, seq, field1) + data


def main_cap():
    c = Cap()
    c.mark('init')
    c.tcp(b'', flags=0x02)
    c.tcp(b'\x00\x01initialize')                         # no magic: Initialization
    c.mark('pdus')
    c.tcp(pdu(0x0001, 0x0001, 0x0000))                  # header only
    c.tcp(pdu(0x0001, 0x0002, 0x0004, b'\xaa\xbb\xcc\xdd'))
    c.tcp(pdu(0x0010, 0x0003, 0x1234, b'payload!'), sport=5010, dport=40000,
          src=(192, 0, 2, 2), dst=(192, 0, 2, 1))
    c.tcp(pdu(0x0002, 0x0004, 0x0000, b'\x01'))
    c.mark('multi')
    c.tcp(pdu(0x0001, 0x0010, 0) + pdu(0x0002, 0x0011, 1, b'ab'))          # two PDUs
    c.tcp(pdu(0x0001, 0x0020, 0) + pdu(0x0002, 0x0021, 1, b'ab') +
          pdu(0x0003, 0x0022, 2, b'abcd'))                                   # three
    c.tcp(pdu(0x0001, 0x0030, 0, b'x' * 1000))                              # long
    c.mark('short')
    # the header is cut by the end of the segment: length claims more
    c.tcp(pdu(0x0001, 0x0041, 0, b'', length=6) + b'\x03\x00\x00\x06\x00\x01')   # second PDU: no seq
    c.tcp(pdu(0x0001, 0x0042, 0)[:9])                    # cut inside the sequence word
    c.tcp(pdu(0x0001, 0x0043, 0)[:7])                    # cut inside the type word
    c.tcp(pdu(0x0001, 0x0044, 0)[:5])                    # cut inside the length
    c.tcp(pdu(0x0001, 0x0045, 0, b'tail') + b'\x03\x00\x00\x08')    # trailing partial header
    c.tcp(pdu(0x0001, 0x0046, 0, b'tail') + b'\x03\x00\x00\x08\x00\x01\x00')
    c.mark('lengths')
    c.tcp(pdu(0x0001, 0x0050, 0, length=6))
    c.tcp(pdu(0x0001, 0x0051, 0, b'data', length=7))     # length shorter than the data
    c.tcp(pdu(0x0001, 0x0052, 0, b'data', length=10))
    c.tcp(pdu(0x0001, 0x0053, 0, b'dat', length=9) + pdu(0x0001, 0x0054, 0, b'x', length=7))
    c.mark('pdu_lengths_below_6')
    # reproducer of "IPSI-CTL: Reject PDU lengths below 6": a PDU length
    # of 0 made the data length negative.  This frame (and the next, with a
    # valid PDU after the bad one) decodes with an error expert info and
    # without an exception
    c.tcp(pdu(1, 2, 3, b'\xaa\xbb', length=0) + pdu(1, 3, 3, b'\xaa\xbb', length=8))
    c.tcp(pdu(1, 5, 0, b'', length=5))
    return c


def malformed_cap():
    c = Cap()
    c.tcp(b'\x03')                                       # one octet: magic cut short
    c.tcp(pdu(0x0001, 0x0040, 0, b'ab', length=40))   # length claims more than the segment
    c.tcp(b'')
    c.tcp(pdu(1, 1, 1, b'ab', length=0))
    c.tcp(pdu(1, 1, 1, b'ab', length=5))
    c.tcp(pdu(1, 1, 1, b'ab', length=1))
    c.tcp(pdu(1, 1, 1, b'ab', length=2) + pdu(1, 2, 2, b'cd', length=8))
    c.tcp(pdu(1, 1, 1, b'ab', length=8) + pdu(1, 2, 2, b'cd', length=3))
    c.tcp(pdu(1, 1, 1, b'ab', length=0xffff))
    c.tcp(pdu(1, 1, 1, b'ab', length=6) + pdu(1, 2, 2, b'cd', length=0xfff0))
    c.tcp(b'\x03\x00\x00\x00\x00\x00\x00')
    c.tcp(b'\x03\x00\x00\x06\x00')
    c.tcp(b'\x03\x00')
    return c


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_cap()
    m.write(os.path.join(out, 'ipsi-ctl-coverage.pcap'))
    x = malformed_cap()
    x.write(os.path.join(out, 'ipsi-ctl-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, nm in m.marks:
            print(n, nm)
        print('main frames', len(m.frames), 'malformed', len(x.frames))


main()
