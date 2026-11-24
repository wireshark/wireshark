#!/usr/bin/env python3
# Generates test/captures/vlp16_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Velodyne VLP-16 captures for packet-vlp16.c.

Usage: mkvlp16.py <outdir> [-v]
The two dissectors (VLP-16 Data, VLP-16 Position) are registered only for
Decode As on UDP, so they are used with
  -d udp.port==2368,vlp16_data -d udp.port==8308,vlp16_position
The ports are the ones the sensor uses by default.
Writes vlp16-coverage.pcapng (main capture: no malformed packets or error
expert infos) and vlp16-coverage-malformed.pcapng (a position packet with
non-zero "zero data", truncated packets). Addresses are from 192.0.2.0/24.
"""
import os
import struct
import sys

from pcaplib import eth, ipv4, udp, write_pcapng

DATA_PORT = 2368
POS_PORT = 8308


def data_packet(f1=0x37, f2=0x22, gps=1000000, seed=0, rot0=0):
    out = b''
    for i in range(12):
        out += struct.pack('<HH', 0xEEFF, (rot0 + i * 20) % 36000)
        for j in range(32):
            out += struct.pack('<HB', (i * 100 + j * 7 + seed) & 0xffff, (i + j + seed) & 0xff)
    out += struct.pack('<I', gps) + bytes([f1, f2])
    assert len(out) == 1206
    return out


def v12(v):
    return v & 0xfff


def position_packet(vals, gps=123456789, sentence=b'$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A',
                    zero=b'\0' * 14):
    out = zero
    for g, t, ax, ay in vals:
        out += struct.pack('<HHHH', v12(g), v12(t), v12(ax), v12(ay))
    out += bytes(160)
    out += struct.pack('<I', gps) + bytes(4)
    out += sentence[:72].ljust(72, b'\0')
    out += bytes(234)
    assert len(out) == 512, len(out)
    return out


def frame(payload, port, n=0):
    return eth(2, 1, 0x0800, ipv4(17, udp(40000 + n, port, payload), 1, 2, n + 1))


def build_main():
    fr, marks = [], []

    def mark(label):
        marks.append((len(fr) + 1, label))

    def add(d, i=0):
        fr.append((i, d))

    mark('Data packets: every strongest/last/dual return and factory byte, GPS timestamps')
    for n, (f1, f2) in enumerate(((0x37, 0x22), (0x38, 0x22), (0x39, 0x22), (0x37, 0x21), (0x38, 0x21), (0x39, 0x21),
                                  (0x00, 0x00), (0xff, 0xff))):
        add(frame(data_packet(f1, f2, gps=n * 1000000 + 1, seed=n, rot0=n * 4000), DATA_PORT, n))
    add(frame(data_packet(gps=0xffffffff, rot0=35980), DATA_PORT, 9))
    mark('Position packets: gyro, temperature and acceleration as 12 bit two\'s complement values')
    pv = [
        [(0, 0, 0, 0), (1, 1, 1, 1), (0x7ff, 0x7ff, 0x7ff, 0x7ff)],              # zero, small, the largest positive
        [(0x800, 0x800, 0x800, 0x800), (0xfff, 0xfff, 0xfff, 0xfff), (0x801, 0x400, 0xc00, 0x555)],   # negative values
        [(100, 200, 300, 400), (0xf9c, 0xe70, 0xed4, 0xe70), (0x123, 0x456, 0x789, 0xabc)],
    ]
    for n, v in enumerate(pv):
        add(frame(position_packet(v, gps=n * 500000), POS_PORT, 20 + n))
    add(frame(position_packet(pv[0], sentence=b''), POS_PORT, 24))
    add(frame(position_packet(pv[1], sentence=b'$GPRMC,' + b'x' * 80), POS_PORT, 25))
    return fr, marks


def build_malformed():
    fr, marks = [], []

    def mark(label):
        marks.append((len(fr) + 1, label))

    def add(d, i=0):
        fr.append((i, d))

    mark('Position packet whose "zero data" is not zero (error expert info)')
    add(frame(position_packet([(0, 0, 0, 0)] * 3, zero=b'\0' * 13 + b'\x01'), POS_PORT, 30))
    add(frame(position_packet([(0, 0, 0, 0)] * 3, zero=b'\xff' * 14), POS_PORT, 31))
    mark('Truncated data and position packets')
    add(frame(data_packet()[:1200], DATA_PORT, 32))
    add(frame(data_packet()[:100], DATA_PORT, 33))
    add(frame(position_packet([(0, 0, 0, 0)] * 3)[:300], POS_PORT, 34))
    add(frame(position_packet([(0, 0, 0, 0)] * 3)[:10], POS_PORT, 35))
    return fr, marks


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    for name, fn in (('vlp16-coverage', build_main), ('vlp16-coverage-malformed', build_malformed)):
        fr, marks = fn()
        write_pcapng(os.path.join(out, name + '.pcapng'), [1], fr)
        print('%s.pcapng: %d frames' % (name, len(fr)))
        if verbose:
            ends = [m[0] for m in marks[1:]] + [len(fr) + 1]
            for (s, label), e in zip(marks, ends):
                print('  %d-%d %s' % (s, e - 1, label))


if __name__ == '__main__':
    main()
