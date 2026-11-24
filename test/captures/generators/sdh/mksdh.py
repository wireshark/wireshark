#!/usr/bin/env python3
# Generates test/captures/sdh_coverage.erf.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SDH coverage captures: mksdh.py <outdir> [-v].  All data is synthetic.

SDH is reached through the ERF reader: a record of type 24 (RAW_LINK) holds
one SDH/SONET frame (2430 octets for OC-3 and a multiple of it for the
faster rates).  The data rate is a preference (default OC-3) or, with the
preference set to "Guess", it comes from a raw link extension header or from
the frame length."""
import os
import struct
import sys

COLUMNS = 270
EH_RAWLINK = 5
EH_CLASS = 1

class Erf:
    def __init__(self):
        self.recs = []
        self.marks = []
        self.ts = 1700000000 << 32
    def mark(self, text):
        self.marks.append((len(self.recs) + 1, text))
    def rec(self, data, ehdrs=(), rtype=24, flags=0x04, wlen=None):
        self.ts += 1 << 30
        eh = b''
        for k, h in enumerate(ehdrs):
            eh += struct.pack('>Q', h | (1 << 63 if k < len(ehdrs) - 1 else 0))
        t = rtype | (0x80 if ehdrs else 0)
        body = eh + data
        hdr = struct.pack('<Q', self.ts) + struct.pack('>BBHHH', t, flags, 16 + len(body), 0, len(data) if wlen is None else wlen)
        self.recs.append(hdr + body)
    def write(self, path):
        with open(path, 'wb') as f:
            for r in self.recs:
                f.write(r)

def ehdr(t, value):
    return (t << 56) | (value & ((1 << 56) - 1))

def frame(level=1, au=522, s1=0, m1=7, j1=0x5a, ndf=0x6, fill=0, hdrsz=None):
    """An STM-N frame with distinct values in the section overhead bytes."""
    n = hdrsz if hdrsz is not None else 2430 * level
    f = bytearray([fill]) * n if fill else bytearray(n)
    def put(col, row, b):
        o = col * level + row * level * COLUMNS
        if o < n:
            f[o:o + len(b)] = b
    put(0, 0, b'\xf6' * (3 * level))
    put(3, 0, b'\x28' * (3 * level))
    put(6, 0, b'\x01')
    put(0, 1, b'\xb1'); put(3, 1, b'\xe1'); put(6, 1, b'\xf1')
    put(0, 2, b'\xd1'); put(3, 2, b'\xd2'); put(6, 2, b'\xd3')
    h1 = (ndf << 4) | (3 << 2) | ((au >> 8) & 3)
    put(0, 3, bytes([h1])); put(3, 3, bytes([au & 0xff]))
    put(0, 4, b'\xb2' * (3 * level)); put(3, 4, b'\xc1'); put(6, 4, b'\xc2')
    for i, (c, r) in enumerate([(0, 5), (3, 5), (6, 5), (0, 6), (3, 6), (6, 6), (0, 7), (3, 7), (6, 7)]):
        put(c, r, bytes([0xd4 + i]))
    put(0, 8, bytes([s1]))
    o = 3 * level + 2 + 8 * level * COLUMNS
    if o < n:
        f[o] = m1
    put(6, 8, b'\xe2')
    ao = (((9 + 3 * COLUMNS) + au * 3 + 9 * (au // 87)) * level) % (COLUMNS * 9 * level)
    if ao < n:
        f[ao] = j1
    return bytes(f)

def main(out, verbose=False):
    e = Erf()
    e.mark('OC-3 frames (2430 octets), default data rate: typical AU pointer 522, S1 sync status values, AU pointers below and above 87 (the SOH row offset) and the largest valid and out of range pointers')
    e.rec(frame(1, 522, 0, 7, 0x5a))
    for i, au in enumerate((0, 1, 86, 87, 88, 174, 261, 609, 782, 783, 1022)):
        e.rec(frame(1, au, i, i, 0x40 + i))
    for s1 in (2, 4, 8, 11, 15):
        e.rec(frame(1, 522, s1, 0, 0x70 + s1))
    e.mark('Frame lengths of the faster rates and raw link extension headers with the rates 1, 2 and 3 (read with the data rate preference "Guess"; the default OC-3 is used otherwise)')
    e.rec(frame(1, 522, 1, 1, 0x61), [ehdr(EH_RAWLINK, (1 << 8) | 1)])
    e.rec(frame(4, 522, 2, 2, 0x62), [ehdr(EH_RAWLINK, (2 << 8) | 1)])
    e.rec(frame(16, 600, 3, 3, 0x63), [ehdr(EH_RAWLINK, (3 << 8) | 1)])
    e.mark('Raw link extension header after another extension header, rate 0 and 7 (fall back to the frame length)')
    e.rec(frame(4, 90, 4, 4, 0x64), [ehdr(EH_CLASS, 0x01), ehdr(EH_RAWLINK, (7 << 16) | (0 << 8) | 2)])
    e.rec(frame(8, 100, 5, 5, 0x65), [ehdr(EH_RAWLINK, (7 << 8) | 2)])
    e.mark('Frame lengths without extension header: OC-12, OC-24, OC-48, and an odd length')
    e.rec(frame(4, 200, 6, 6, 0x66))
    e.rec(frame(8, 300, 7, 7, 0x67))
    e.rec(frame(16, 400, 8, 8, 0x68))
    e.rec(frame(1, 522, 9, 9, 0x69, hdrsz=3000))
    main_n = len(e.recs)

    m = Erf()
    m.mark('Frames too short for the selected data rate (exceptions)')
    m.rec(frame(1, 522, hdrsz=2430)[:2000])
    m.rec(frame(1, 522)[:900])
    m.rec(frame(1, 522)[:10])
    m.rec(frame(4, 522)[:5000])
    m.rec(b'')
    m.rec(frame(1, 522) + b'', wlen=5000)
    e.write(os.path.join(out, 'sdh-coverage.erf'))
    m.write(os.path.join(out, 'sdh-coverage-malformed.erf'))
    if verbose:
        for n, tx in e.marks:
            print(n, tx)
        print(main_n, 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
