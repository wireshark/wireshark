#!/usr/bin/env python3
# Generates test/captures/radiotap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the radiotap coverage captures (synthetic).  Usage: mkradiotap.py <outdir>

radiotap-coverage.pcap            main capture, DLT 127 (IEEE802_11_RADIOTAP)
radiotap-coverage-malformed.pcap  malformed headers (not added to the tree)
radiotap-coverage-bit14.pcap      the "bit 14 is FCS" preference variant
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import random
from rtlib import ack, add_fcs, ALIGN_SIZE, beacon, build, nulldata, rts, simple, write_pcap, zlib

out = sys.argv[1] if len(sys.argv) > 1 else '.'
rng = random.Random(0x802a)


def rb(n, bias=0.3):
    """random bytes, biased to 0x00 / 0xff so that 'known' bits and zero values occur"""
    r = bytearray()
    for _ in range(n):
        x = rng.random()
        r.append(0 if x < bias / 2 else 0xff if x < bias else rng.randrange(256))
    return bytes(r)


def under(kind=None):
    k = kind if kind is not None else rng.choice(['null', 'qos', 'ack', 'rts', 'beacon', 'null'])
    s = rng.randrange(4096)
    return {'null': lambda: nulldata(s), 'qos': lambda: nulldata(s, qos=True),
            'ack': ack, 'rts': rts, 'beacon': lambda: beacon(b'rt', s, s)}[k]()


def frame(rt):
    """append an 802.11 frame; honour the FCS flag if the flags field says so"""
    return rt


frames = []
main = []
marks = {}
seq = [0]


def add(rt, kind=None, fcs=False, lst=None):
    body = under(kind)
    if fcs:
        body = add_fcs(body)
    (main if lst is None else lst).append(rt + body)


marks['A'] = len(main) + 1
# ---------------------------------------------------------------- A. single fields
def sf(idx, data, **kw):
    add(simple([(idx, data)]), **kw)

sf(0, struct.pack('<Q', 0x0123456789abcdef))
for fl in (0x00, 0x01, 0x02, 0x04, 0x08, 0x20, 0x80, 0xff & ~0x10 & ~0x40):
    sf(1, bytes([fl]))
sf(1, bytes([0x10]), fcs=True)
sf(1, bytes([0x50]), fcs=True)
for r in (2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108, 0, 0x80, 0x80 + 7, 0x80 + 76, 0xff):
    sf(2, bytes([r]))
for fr, fl in ((2412, 0x00a0), (2437, 0x0480), (5180, 0x0140), (5805, 0x0140), (2484, 0x00b0),
               (5200, 0x0140 | 0x2000), (57240, 0x0100), (6000, 0x0100), (0, 0), (902, 0x0010 | 0x0100),
               (2412, 0x0200), (2412, 0x0100 | 0x0400), (2412, 0x0100 | 0x0800), (5180, 0x0140 | 0x0040),
               (5180, 0x0140 | 0x0200), (5180, 0x0140 | 0x0010), (2412, 0x0020 | 0x2000 | 0x4000),
               (2412, 0x0020 | 0x0100 | 0x0800), (2412, 0x0020 | 0x0400), (2412, 0x0020 | 0x0400 | 0x0800),
               (5180, 0x0140 | 0x0100), (2412, 0x00c0 | 0x0100), (5180, 0x0140 | 0x0080 | 0x0100), (1, 0), (4000, 0),
               (5955, 0x0100), (7115, 0x0100), (2417, 0x0020), (45000, 0x0100), (58320, 0x0100), (60480, 0x0100),
               (5170, 0x0140), (4920, 0x0140), (5035, 0x0140), (3700, 0x0140), (5925, 0x0140), (2407, 0x0020),
               (2512, 0x0020), (2477, 0x0020), (5000, 0x0140), (2411, 0x0020), (2472, 0x0020)):
    sf(3, struct.pack('<HH', fr, fl))
sf(4, bytes([3, 9]))
for v in (-90, -20, 0, 127, -128):
    sf(5, struct.pack('<b', v)); sf(6, struct.pack('<b', v))
sf(7, struct.pack('<H', 66))
sf(8, struct.pack('<H', 3)); sf(9, struct.pack('<H', 3))
sf(10, struct.pack('<b', 17)); sf(11, bytes([2])); sf(12, bytes([30])); sf(13, bytes([12]))
for v in (0, 1, 2, 4, 0x8000, 0xffff, 8):
    sf(14, struct.pack('<H', v))
for v in (0, 1, 2, 4, 8, 0x10, 0x20, 0x3f, 0xffff):
    sf(15, struct.pack('<H', v))
sf(16, bytes([3])); sf(17, bytes([7]))
for xf, fr, ch in ((0x0040 | 0x0080, 2412, 1), (0x0100 | 0x0200, 5180, 36), (0x0140 | 0x0010, 5200, 40),
                   (0x0140 | 0x20000 | 0, 5180, 36), (0x0140 | 0x40000, 5180, 36), (0x0140 | 0x10000, 5180, 36),
                   (0x0020 | 0x0200 | 0x20000, 2412, 1), (0x0100, 57240, 2), (0x0080 | 0x0400, 2412, 1),
                   (0x0140 | 0x0800 | 0x1000, 5180, 36), (0x0140 | 0x2000, 5180, 36), (0x0140 | 0x4000, 5180, 36),
                   (0x0040 | 0x0010 | 0x0100, 0, 0), (0x0020 | 0x0040 | 0x0200, 2412, 1), (0x0020, 2412, 1),
                   (0x0010, 2412, 1), (0x0100 | 0x0040 | 0x0020 | 0x0001, 2412, 1), (0x0200 | 0x0040, 5180, 36),
                   (0x0100 | 0x0010 | 0x0020, 2412, 1)):
    sf(18, struct.pack('<IHBB', xf, fr, ch, 17))

for fl in (0x0880, 0x0080, 0x00a0, 0x0040 | 0x0080, 0x0400 | 0x0080, 0x00d0, 0x2150, 0x2140, 0x0150, 0x0140, 0x0090):
    sf(3, struct.pack('<HH', 2412, fl))
    sf(18, struct.pack('<IHBB', fl, 2412, 1, 0))
    sf(18, struct.pack('<IHBB', fl | 0x10000, 5180, 36, 0))
    sf(18, struct.pack('<IHBB', fl | 0x20000, 5180, 36, 0))
# MCS: every combination of known bits, bandwidth, GI, many indexes
for known in (0x00, 0x7f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x03, 0x07, 0x47, 0x7e):
    for flags in (0x00, 0x01, 0x02, 0x03, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x7f, 0xff, 0x23):
        sf(19, bytes([known, flags, rng.choice([0, 1, 7, 8, 15, 23, 31, 32, 33, 76, 77, 100, 255])]))
for m in range(0, 78):
    sf(19, bytes([0x07, m % 4 & 0x01 | (m // 4 % 2) << 2 | (m % 3 == 0) << 1, m]))
# the FCS and datapad flag with an MCS (11n short GI from the flags field)
add(simple([(1, bytes([0x80])), (19, bytes([0x00, 0, 0]))]))
add(simple([(1, bytes([0x80])), (19, bytes([0x03, 0, 5]))]))
add(simple([(1, bytes([0x00])), (19, bytes([0x03, 0, 5]))]))
add(simple([(1, bytes([0x80])), (19, bytes([0x04, 0, 5]))]))
add(simple([(1, bytes([0x00])), (19, bytes([0x04, 0, 5]))]))
add(simple([(1, bytes([0x80])), (19, bytes([0x00, 0, 5]))]))
add(simple([(1, bytes([0x00])), (3, struct.pack('<HH', 5180, 0x140)), (19, bytes([0x00, 0, 5]))]))

# A-MPDU status
for fl in (0, 1, 2, 4, 8, 0x10, 0x20, 0x3f, 0xffff, 0x0a, 0x24):
    sf(20, struct.pack('<IHBB', rng.randrange(1 << 32), fl, 0x5a, 0x00))

# VHT
for known in (0, 0xffff, 0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400):
    for fl in (0, 0xff, 0x01, 0x04, 0x08, 0x10, 0x20):
        for bw in (0, 1, 4, 11, 12, 20):
            users = bytes([rng.choice([0x11, 0x92, 0x93, 0x00, 0x24, 0xa1, 0x09, 0x1f, 0xf2, 0x72]) for _ in range(4)])
            if rng.random() < 0.3:
                users = bytes([0x00] * 4)
            sf(21, struct.pack('<HBB', known, fl, bw) + users + bytes([rng.randrange(8), rng.randrange(64)]) + struct.pack('<H', rng.randrange(512)))
for mcs in range(12):
    for nss in (1, 2, 3, 4, 5, 8, 9):
        for bw in (0, 1, 4, 11):
            sf(21, struct.pack('<HBB', 0x017f if mcs % 2 else 0x00ff | 0x0100, 0x04 * (mcs % 2) | 0x04, bw) +
               bytes([(mcs << 4) | nss, 0, 0, 0]) + bytes([0, 0]) + b'\0\0')

# timestamp
for unit_pos, flags in ((0x08, 0x00), (0x10, 0x01), (0x00, 0x02), (0x01, 0x03), (0x12, 0x03), (0x03, 0x02), (0x0f, 0x01)):
    sf(22, struct.pack('<QHBB', rng.randrange(1 << 60), 0x0042, unit_pos, flags))
# HE, HE-MU, 0-length PSDU, L-SIG
for _ in range(80):
    sf(23, rb(12))
for fmt in range(4):
    for d2 in (0, 0xffff):
        for d5 in (0, 0xffff, 0x1234, 0x0007, 0x0f00):
            sf(23, struct.pack('<HHHHHH', fmt | 0x7ffc if d2 else 0, d2, rng.choice([0xffff, 0x0000, 0x7fff]), rng.randrange(65536), d5, rng.randrange(65536)))
for _ in range(40):
    sf(24, rb(12))
for ft in range(0, 12):
    None
# HE-MU with RU channel
for fl1 in (0x0000, 0xffff, 0x0eff, 0x1000, 0x4000, 0x8000, 0x0100, 0x0200, 0x0400, 0x0800, 0x2000):
    for fl2 in (0x0000, 0xffff, 0x0007, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x00ff, 0x0300):
        sf(24, struct.pack('<HH', fl1, fl2) + bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]))
for t in range(0, 255, 17):
    sf(26, bytes([t]))
sf(26, bytes([0xff])); sf(26, bytes([0x00])); sf(26, bytes([0x01])); sf(26, bytes([0x02]))
for rl in range(0, 0x20):
    sf(27, struct.pack('<HH', rng.choice([0x0003, 0x0001, 0x0002, 0x0000, 0x0007]), (rl << 4) | rng.randrange(16)))
sf(27, struct.pack('<HH', 0x0003, 0xfff0)); sf(27, struct.pack('<HH', 0x0003, 0x0000)); sf(27, struct.pack('<HH', 0x0007, 0x0050))

marks['B'] = len(main) + 1
# -------------------------------------------------------------- B. random combos
FIELDS = sorted(i for i in ALIGN_SIZE)
for n in range(330):
    k = rng.choice([2, 3, 4, 6, 8, 12])
    idxs = sorted(rng.sample([i for i in FIELDS if i not in (18, 4)] + [18, 4] if rng.random() < 0.5 else
                             [i for i in FIELDS if i not in (18,)], k))
    fl = []
    fcs = False
    for i in idxs:
        sz = ALIGN_SIZE[i][1]
        d = rb(sz)
        if i == 1:
            d = bytes([d[0] & ~0x40 if rng.random() < 0.7 else d[0]])
            fcs = bool(d[0] & 0x10)
        if i == 14:
            d = bytes([d[0], d[1] & 0x7f])
        if i == 3 and rng.random() < 0.7:
            d = struct.pack('<HH', rng.choice([2412, 2437, 5180, 5745, 6055, 58320, 5920, 2484, 2467]), rng.randrange(0x4000))
        if i == 2 and rng.random() < 0.7:
            d = bytes([rng.choice([2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108])])
        fl.append((i, d))
    # bits 14 and 15 sit right of the xchannel override size: keep xchannel last-ish handled by builder
    add(simple(fl), fcs=fcs)

marks['C'] = len(main) + 1
# ----------------------------------------------------------- C. multiple words, namespaces
add(build([('rt', [(5, b'\xc0')]), ('rt', [(5, b'\xc1'), (11, b'\x02')])]))
add(build([('rt', [(1, b'\x00'), (5, b'\xc0')]), ('rt', [(0, struct.pack('<Q', 5)), (5, b'\xc1')]), ('rt', [(11, b'\x01')])]))
# vendor namespace, unknown vendor (shown as bytes)
add(build([('rt', [(5, b'\xc0')]), ('ven', bytes.fromhex('0050f2'), 1, 0x00000001, b'\x01\x02\x03\x04'),
           ('rt', [(11, b'\x01')])]))
add(build([('rt', [(5, b'\xc0')]), ('ven', bytes.fromhex('001018'), 7, 0x00000003, b'\x01\x02\x03\x04\x05\x06\x07\x08'),
           ('ven', bytes.fromhex('00904c'), 0, 0x00000001, b''), ('rt', [(5, b'\xc3')])]))
add(build([('rt', [(11, b'\x01')]), ('ven', bytes.fromhex('00e04c'), 0, 0x00000001, b'abcd'), ('rt', [(5, b'\xc3')])]))
add(build([('rt', [(1, b'\x00')]), ('ven', bytes.fromhex('aabbcc'), 9, 0x80000001, b'')]))
# unknown radiotap-namespace bit beyond the table (iterator stops, no error)
w = None

marks['D'] = len(main) + 1
# ------------------------------------------------------------------------- D. TLVs
def tlv(*items, **kw):
    return simple([], tlv=list(items), **kw)

add(tlv((0, struct.pack('<Q', 7)), (1, b'\x00'), (3, struct.pack('<HH', 5180, 0x0140)), (5, b'\xc5')))
add(tlv((2, b'\x0c'), (11, b'\x01'), (14, b'\x04\x00'), (19, bytes([7, 1, 3])), (20, struct.pack('<IHBB', 5, 3, 0, 0))))
add(tlv((23, rb(12)), (24, rb(12))))
add(tlv((23, rb(12)), (24, rb(12)), (26, b'\x01'), (27, struct.pack('<HH', 3, 0x0150))))
add(tlv((21, rb(12)), (22, rb(12)), (18, struct.pack('<IHBB', 0x140, 5180, 36, 0))))
add(tlv((26, b'\x00')))
add(tlv((26, b'\x01')))
add(tlv((26, b'\x04')))
add(tlv((26, b'\xff')))
add(tlv((27, struct.pack('<HH', 3, 0x0150))))
add(tlv((27, struct.pack('<HH', 0, 0x0150))))
for _ in range(10):
    add(tlv((32, rb(6, 0.5))))
# U-SIG with every field known.  A mask with unknown bits makes the dissector
# overwrite entries of the static usig_eht_mu_ppdu_headers/usig_eht_tb_ppdu_headers
# arrays for good (see README, "Bugs"); those frames are in the malformed capture.
def usig_frames(lst, masks, n_random):
    for ul_dl in (0, 1):
        for tc in range(4):
            for ppdu in range(4):
                for mask in masks:
                    common = rng.randrange(1 << 32) | 0x00000f7f
                    common = (common & ~0x4) | (ul_dl << 2)
                    val = struct.unpack('<I', bytes([(tc << 6) | rng.randrange(64), rng.randrange(256), rng.randrange(256), rng.randrange(256)]))[0]
                    lst.append(tlv_(33, struct.pack('<III', common, val, mask)))
    for _ in range(n_random):
        lst.append(tlv_(33, struct.pack('<III', rng.randrange(1 << 32), rng.randrange(1 << 32), rng.choice(masks))))

def tlv_(t, d):
    return tlv((t, d))

usigs = []
usig_frames(usigs, (0xffffffff,), 40)
for u in usigs:
    add(u)
usig_unknown = []
usig_frames(usig_unknown, (0, 0x0f0f0f0f, 0xf0f0f0f0, 0x55555555, 0xaaaaaaaa, 0x00ffff00), 120)
for users in (0, 1, 2, 4):
    for _ in range(5):
        add(tlv((34, rb(40, 0.5) + b''.join(rb(4) for _ in range(users)))))
for k in range(5):
    add(tlv((34, struct.pack('<I', 0xffffffff) + b'\xff' * 36 + b''.join(rb(4) for _ in range(k)))))
    add(tlv((34, struct.pack('<I', 0) + b'\0' * 36)))
for _ in range(60):
    add(tlv((34, rb(40, 0.45) + rb(4) + rb(4))))
add(tlv((34, rb(40)), (33, rb(8) + b'\xff\xff\xff\xff'), (32, rb(6))))
add(tlv((28, b'\x00\x00\x00\x00')))   # TLV type 28 is padding
# last TLV whose padding is cut off by the header length, and a second present word outside the radiotap namespace table
add((lambda b: struct.pack('<BBHI', 0, 0, len(b) - 3, 1 << 28) + b[8:-3])(tlv((5, b'\xc0'))) + under('null'))
add(struct.pack('<BBHII', 0, 0, 12, 1 << 31, 1) + under('null'))
# unknown TLV types, vendor TLVs
add(tlv((99, b'\x01\x02\x03\x04\x05')))
add(tlv((0x1234, b'')))
add(tlv((30, bytes.fromhex('0050f2') + b'\x01' + struct.pack('<HH', 3, 4) + b'\xaa\xbb\xcc\xdd')))
add(tlv((30, bytes.fromhex('0050f2') + b'\x01' + struct.pack('<HH', 3, 0))))
add(tlv((30, bytes.fromhex('001018') + b'\x07' + struct.pack('<HH', 3, 12) + bytes(range(12))), (5, b'\xc1')))
add(tlv((5, b'\xc1'), (31, b'\x00\x00\x00\x00')))   # unknown (extension) type in TLV
# TLV after normal fields in the first word and mixed namespaces
add(build([('rt', [(1, b'\x00'), (5, b'\xc0')])], tlv=[(5, b'\xc2'), (11, b'\x01')]))
add(build([('rt', [(3, struct.pack('<HH', 2412, 0x80))]), ('rt', [(5, b'\xc0')])], tlv=[(5, b'\xc2')]))

marks['E'] = len(main) + 1
# ----------------------------------------------- E. frames with FCS / datapad / flags
for fl in (0x10, 0x50, 0x30):
    add(simple([(1, bytes([fl])), (2, b'\x0c'), (3, struct.pack('<HH', 2437, 0x00a0))]), fcs=True)
for fl in (0x20, 0x20 | 0x10):
    add(simple([(1, bytes([fl])), (2, b'\x0c')]), kind='qos', fcs=bool(fl & 0x10))
# data rate and channel with the different PHYs, for the PHY guessing code
for fr, cf in ((2412, 0x0080), (2412, 0x0480), (2412, 0x0020), (2412, 0x00a0), (5180, 0x0140), (5180, 0x0100), (2412, 0x0000)):
    for r in (2, 4, 11, 22, 66, 12, 24, 108, 0):
        add(simple([(1, b'\x02'), (2, bytes([r])), (3, struct.pack('<HH', fr, cf))]))
        add(simple([(1, b'\x00'), (2, bytes([r])), (3, struct.pack('<HH', fr, cf))]))
add(simple([(2, b'\x0c')]))
add(simple([(2, b'\x04'), (5, b'\xb0')]))
add(simple([(2, b'\x16'), (3, struct.pack('<HH', 0, 0x00a0))]))
add(simple([(3, struct.pack('<HH', 2412, 0x0480)), (2, b'\x04')]))
add(simple([(3, struct.pack('<HH', 5180, 0x0140)), (1, b'\x00'), (2, b'\x0c'), (19, bytes([0x07, 0x04, 3]))]))
add(simple([(3, struct.pack('<HH', 57240, 0x0100)), (19, bytes([0x07, 0x00, 3]))]))
add(simple([(3, struct.pack('<HH', 57240, 0x0100)), (19, bytes([0x00, 0x00, 0]))]))
add(simple([(3, struct.pack('<HH', 5180, 0x0140)), (21, bytes([0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))]))
add(simple([(3, struct.pack('<HH', 5180, 0x0140)), (21, bytes([0x00, 0, 0, 0, 0x11, 0, 0, 0, 0, 0, 0, 0]))]))

if len(main) == 0:
    raise SystemExit('empty')

# ------------------------------------------------------------------ malformed
bad = []
v = under('null')
bad.append(struct.pack('<BBHIII', 0, 0, 22, (1 << 31) | (1 << 30), (1 << 31) | 1, 1) + bytes.fromhex('0050f2') + b'\x01' + struct.pack('<H', 0) + v)  # data bit with no namespace
bad.append(struct.pack('<BBHI', 0, 0, 4, 0) + v)                       # length < 8
bad.append(struct.pack('<BBHI', 1, 0, 8, 0) + v)                       # version 1 -> iterator init fails
bad.append(struct.pack('<BBHI', 0, 0, 12, 1 << 31) + b'\0' * 4 + v)    # ext, ok? present word 2 missing bits
bad.append(struct.pack('<BBHII', 0, 0, 8, 1 << 31, 1 << 31) + v)       # ext chain past the end
bad.append(struct.pack('<BBHII', 0, 0, 12, 1 << 31, (1 << 31) | (1 << 28)) + b'\0' * 4 + v)   # ext + TLV + ext
bad.append(struct.pack('<BBHI', 0, 0, 16, 1 << 28) + struct.pack('<HH', 5, 40) + v)   # TLV extends past header
bad.append(struct.pack('<BBHI', 0, 0, 10, 1 << 28) + struct.pack('<H', 5) + v)         # TLV header does not fit
bad.append(struct.pack('<BBHI', 0, 0, 8, 1 << 5) + v)                  # field past header (dbm signal)
bad.append(struct.pack('<BBHI', 0, 0, 12, (1 << 3)) + b'\0' * 4 + v)   # channel past header after padding
bad.append(struct.pack('<BBHI', 0, 0, 100, 1) + b'\0' * 8 + v)         # length larger than the frame
bad.append(struct.pack('<BBHI', 0, 0, 16, 1 << 29 | 1 << 30) + struct.pack('<HHI', 0, 0, 0) + v)  # radiotap + vendor both
bad.append(struct.pack('<BBHII', 0, 0, 12, (1 << 31) | (1 << 29) | (1 << 30), 1) + b'\0' * 4 + v)
bad.append(struct.pack('<BBHII', 0, 0, 18, (1 << 31) | (1 << 30), 1) + bytes.fromhex('0050f2') + b'\x01' + struct.pack('<H', 40) + v)  # vendor skip past end
bad.append(struct.pack('<BBHII', 0, 0, 16, (1 << 31) | (1 << 30), 0x80000001 & ~(1 << 31)) + bytes.fromhex('0050f2') + b'\x01' + struct.pack('<H', 0) + v)
bad.append(tlv((30, bytes.fromhex('0050f2') + b'\x01')) + v)      # reproducer: vendor TLV with datalen 4 (< 8)
bad.append(tlv((30, bytes.fromhex('0050f2') + b'\x01\x00\x00')) + v)   # datalen 6 (< 8)
bad.append(tlv((30, b'')) + v)
bad.append(struct.pack('<BBHI', 0, 0, 16, (1 << 30)) + struct.pack('<BBBBH', 0, 0x50, 0xf2, 1, 0) + v)  # vendor namespace
bad.append(struct.pack('<BBHI', 0, 0, 12, (1 << 30)) + struct.pack('<HH', 0, 0) + v)     # vendor ns too short (needs 6)
bad.append(struct.pack('<BBHII', 0, 0, 16, (1 << 31) | (1 << 30), 0) + struct.pack('<BBBBH', 0, 0x50, 0xf2, 1, 0) + b'\0\0' + v)
# fields truncated by the end of the captured frame (the radiotap length is larger than the capture)
for ln in (9, 12, 20, 30):
    t = simple([(0, bytes(8)), (3, bytes(4)), (19, bytes(3)), (21, bytes(12)), (22, bytes(12))])
    bad.append(t[:ln])
t = tlv((34, rb(40)))
bad.append(t[:20]); bad.append(t[:30])
t = tlv((33, rb(12)))
bad.append(t[:14])
bad.append(tlv((34, rb(40) + b''.join(rb(4) for _ in range(5)))))
# EHT with a user info that is cut off
bad.append(tlv((34, rb(40) + b'\1\2')) + b'')
# interior TLV length wrong: TLV datalen odd
bad.append(tlv((5, b'\xc0'), (5, b'\xc1', ), (99, b'\x01\x02\x03')) + v)
bad.append(simple([(1, b'\x10')]) + v[:3])   # FCS flag, frame shorter than FCS
bad.append(simple([(1, b'\x10')]))             # radiotap only
bad.append(simple([(0, bytes(8))])[:6])
bad.append(simple([(0, bytes(8))])[:4])

bad.extend(u + under('null') for u in usig_unknown)

# bit 14 variant
b14 = []
None
for good in (True, False):
    for kind in ('null', 'qos', 'ack'):
        body = under(kind)
        fcsv = zlib.crc32(body) & 0xffffffff if good else 0xdeadbeef
        # field 14 is 4 bytes, align 4 with the preference
        hdr = bytearray(struct.pack('<BBHI', 0, 0, 12, 1 << 14))
        hdr += struct.pack('<I', fcsv)
        b14.append(bytes(hdr) + body)
        hdr2 = bytearray(struct.pack('<BBHI', 0, 0, 13, (1 << 14) | (1 << 5)))
        hdr2 += struct.pack('<I', fcsv) + b'\xc0'
        b14.append(bytes(hdr2) + body)
None
b14.append(struct.pack('<BBHI', 0, 0, 12, 1 << 14) + struct.pack('<I', 1) + under('null')[:6])     # too short to verify
b14.append(struct.pack('<BBHI', 0, 0, 12, (1 << 14) | 0) + struct.pack('<I', 1))                   # nothing after
b14.append(add_fcs(under('null')) and struct.pack('<BBHII', 0, 0, 13, (1 << 14) | (1 << 1), 0)[:8] + b'')

# three U-SIG frames (UL/DL 0, PPDU type 0 = EHT MU): everything known, nothing known, everything known
# again.  The third frame is shown with the "not known" items of the second.
st = [tlv((33, struct.pack('<III', 0x00000f7b, 0x00000000, m))) + under('null') for m in (0xffffffff, 0, 0xffffffff)]
os.makedirs(out, exist_ok=True)
write_pcap(os.path.join(out, 'radiotap-usig-static-state.pcap'), 127, st)
write_pcap(os.path.join(out, 'radiotap-coverage.pcap'), 127, main)
write_pcap(os.path.join(out, 'radiotap-coverage-malformed.pcap'), 127, bad)
write_pcap(os.path.join(out, 'radiotap-coverage-bit14.pcap'), 127, b14)
print(len(main), len(bad), len(b14), marks)
