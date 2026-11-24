#!/usr/bin/env python3
# Generates test/captures/sercosiii_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for the SERCOS III dissector.

Usage: mksercosiii.py <outdir>

Writes sercosiii-coverage.pcap (clean) and sercosiii-coverage-malformed.pcap.
Every packet is built with struct; nothing comes from a real network.
"""
import struct
import sys
import os
import zlib

ETH = bytes([0xff] * 6) + bytes([0x02, 0, 0, 0, 0, 0x01]) + b'\x88\xcd'


def hdr(chan_s, at, telno, phase, tail=b''):
    b0 = (0x80 if chan_s else 0) | (0x40 if at else 0) | telno
    h = bytes([b0, phase])
    return h + struct.pack('<I', zlib.crc32(h + tail) & 0xFFFFFFFF)


def mdt_cp0(version):
    return struct.pack('<I', version) + bytes(36)


def mdt_cp12(seed):
    """128 service channels (6 bytes) and 128 device controls (4 bytes, 2 used)."""
    svc = b''
    for i in range(128):
        dbe = (i + seed) % 8
        ctrl = (dbe << 3) | ((i % 2) << 2) | (((i >> 1) % 2) << 1) | ((i >> 2) % 2) | ((i % 3) << 6) | (((i + seed) % 2) << 15)
        info = struct.pack('<I', 0x00010000 | ((i * 37 + seed) & 0xFFFF) | (0x8000 if i % 5 == 0 else 0))
        svc += struct.pack('<H', ctrl) + info
    dev = b''
    for i in range(128):
        dev += struct.pack('<HH', ((i % 4) << 12) | ((i % 2) << 14) | ((i % 3 == 0) << 15) | i, 0)
    return svc + dev


def at_cp0(ndev):
    out = struct.pack('<H', ndev + 1)
    for i in range(1, 512):
        out += struct.pack('<H', (0x8000 | i) if i % 7 == 0 else (i if i <= ndev else 0xFFFF))
    return out


def at_cp12(seed):
    svc = b''
    for i in range(128):
        stat = ((i + seed) % 2) | (((i >> 1) % 2) << 1) | (((i >> 2) % 2) << 2) | (((i >> 3) % 2) << 3) | ((i % 4) << 8)
        svc += struct.pack('<H', stat | (0x8000 if i % 2 else 0)) + struct.pack('<I', 0x00020000 | (i + seed))
    dev = b''
    for i in range(128):
        dev += struct.pack('<HH', (i * 331 + seed) & 0xFFFF, 0)
    return svc + dev


def hp(addr, ctl):
    return struct.pack('<HH', addr, ctl) + bytes([1, 2, 3, 4])


def frame(chan_s, at, telno, phase, payload):
    return ETH + hdr(chan_s, at, telno, phase, payload) + payload


def pcap(fname, frames):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def clean():
    F = []
    # CP0: MDT0 with different communication version words (every bit), P and S channel
    F.append(frame(0, 0, 0, 0, mdt_cp0(0x00000000)))
    F.append(frame(1, 0, 0, 0, mdt_cp0(0x00700301 | 0x0000FF00)))
    F.append(frame(0, 0, 0, 0, mdt_cp0(0x00210100)))
    F.append(frame(1, 0, 0, 0, mdt_cp0(0x00130001)))
    # CP0: AT0 with recognised devices; telegram number 1
    F.append(frame(0, 1, 0, 0, at_cp0(0)))
    F.append(frame(1, 1, 0, 0, at_cp0(24)))
    F.append(frame(0, 1, 1, 0, at_cp0(511)))
    # CP1 / CP2: four MDTs and four ATs, P and S channel
    for t in range(4):
        F.append(frame(t % 2, 0, t, 1 + (t % 2), mdt_cp12(t)))
    for t in range(4):
        F.append(frame((t + 1) % 2, 1, t, 2 - (t % 2), at_cp12(t)))
    # a telegram number above 3 (reserved but accepted)
    F.append(frame(0, 0, 9, 1, mdt_cp12(9)))
    F.append(frame(0, 1, 15, 2, at_cp12(15)))
    # CP3 / CP4: hot plug field in MDT0 and AT0 only
    F.append(frame(0, 0, 0, 3, hp(0x0001, 0x0000) + bytes(60)))
    F.append(frame(1, 0, 0, 4, hp(0x01FF, 0x0003) + bytes(100)))
    F.append(frame(0, 0, 1, 3, bytes(60)))
    F.append(frame(1, 0, 2, 4, bytes(46)))
    F.append(frame(0, 1, 0, 3, hp(0x0002, 0x0080) + bytes(60)))
    F.append(frame(1, 1, 0, 4, hp(0x0003, 0x0001) + bytes(100)))
    F.append(frame(0, 1, 3, 3, bytes(60)))
    F.append(frame(1, 1, 1, 4, bytes(46)))
    return F


def malformed():
    F = []
    # communication phase unknown (5, 7) and phase switching (bit 7): warning "CP is unknown"
    F.append(frame(0, 0, 0, 5, bytes(40)))
    F.append(frame(0, 1, 0, 7, bytes(40)))
    F.append(frame(0, 0, 0, 0x83, bytes(40)))
    F.append(frame(1, 1, 0, 0x81, bytes(40)))
    F.append(frame(0, 0, 0, 0x80, bytes(40)))
    F.append(frame(0, 1, 2, 0x8F, bytes(40)))
    # truncated telegrams: header only, CP0 short, CP1/2 short (exceptions)
    F.append(ETH + b'\x00')
    F.append(ETH + b'\x00\x00\x00\x00')
    F.append(ETH + hdr(0, 0, 0, 0) + bytes(10))
    F.append(ETH + hdr(0, 0, 0, 1) + bytes(100))
    F.append(ETH + hdr(0, 0, 0, 2) + bytes(800))
    F.append(ETH + hdr(0, 0, 0, 3) + bytes(3))
    F.append(ETH + hdr(0, 1, 0, 0) + bytes(30))
    F.append(ETH + hdr(0, 1, 0, 1) + bytes(900))
    F.append(ETH + hdr(1, 1, 0, 2) + bytes(1000))
    F.append(ETH + hdr(0, 1, 0, 4) + bytes(5))
    F.append(ETH + hdr(0, 0, 1, 0) + bytes(39))
    F.append(ETH + hdr(0, 1, 1, 0) + bytes(1000))
    return F


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'sercosiii-coverage.pcap'), clean())
    pcap(os.path.join(out, 'sercosiii-coverage-malformed.pcap'), malformed())
