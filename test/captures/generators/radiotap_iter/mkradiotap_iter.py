#!/usr/bin/env python3
# Generates test/captures/radiotap_iter_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the radiotap iterator coverage captures (synthetic).
Usage: mkradiotap_iter.py <outdir>

radiotap-iter-coverage.pcap            main capture, DLT 127, no malformed frames
radiotap-iter-coverage-malformed.pcap  headers the iterator rejects (not added to the tree)

The iterator (packet-ieee80211-radiotap-iter.c) walks the present-flag words
and the field data of the radiotap header; the frames here exercise every
way it can move: alignment padding, extended present words, namespace
switches (radiotap, vendor), vendor skip lengths, TLVs and the overrides.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import random
from rtlib import ALIGN_SIZE, build, nulldata, simple, write_pcap

out = sys.argv[1] if len(sys.argv) > 1 else '.'
rng = random.Random(0x1ec7)
main, bad = [], []
marks = {}
v = nulldata


def add(rt, lst=None, fcs=False):
    f = nulldata(rng.randrange(4096))
    (main if lst is None else lst).append(rt + f)


# every fixed-size field alone and all of them together (alignment padding)
for idx in sorted(ALIGN_SIZE):
    if idx == 18:
        continue
    add(simple([(idx, bytes([0x11 * (idx % 15 + 1)]) * ALIGN_SIZE[idx][1])]))
add(simple([(i, bytes([i]) * ALIGN_SIZE[i][1]) for i in sorted(ALIGN_SIZE) if i not in (18, 23, 24)]))
# one byte field first, so that each aligned field needs padding
for idx in (0, 3, 4, 7, 14, 19, 20, 21, 22, 27):
    add(simple([(1, b'\x00'), (idx, bytes([0x22]) * ALIGN_SIZE[idx][1])]))
    add(simple([(2, b'\x04'), (11, b'\x01'), (idx, bytes([0x22]) * ALIGN_SIZE[idx][1])]))
# xchannel override (4 byte aligned, 8 bytes)
add(simple([(1, b'\x00'), (18, struct.pack('<IHBB', 0x140, 5180, 36, 0))]))
add(simple([(18, struct.pack('<IHBB', 0x80, 2412, 1, 0)), (19, bytes([7, 0, 1]))]))

marks['ext'] = len(main) + 1
# extended present words, radiotap namespace repeated, fields in each
add(build([('rt', [(5, b'\xc0')]), ('rt', [(5, b'\xc1')])]))
add(build([('rt', [(1, b'\x00'), (5, b'\xc0')]), ('rt', [(0, struct.pack('<Q', 5)), (5, b'\xc1')]), ('rt', [(11, b'\x01')])]))
add(build([('rt', [(i, bytes([i]) * ALIGN_SIZE[i][1])]) for i in (1, 2, 5, 11, 12, 13, 16, 17)]))
add(build([('rt', []), ('rt', [(5, b'\xc0')])]))
marks['enoent'] = len(main) + 1
# extended word without the radiotap-namespace bit: bits >= 32 are unknown,
# the iterator stops without an error
add(struct.pack('<BBHII', 0, 0, 12, 1 << 31, 1) + nulldata())
add(struct.pack('<BBHIII', 0, 0, 17, (1 << 31) | (1 << 5), (1 << 31) | 1, 0) + b'\xc0' + nulldata())
add(struct.pack('<BBHIII', 0, 0, 17, (1 << 31) | (1 << 5), (1 << 31) | 0x7fffffff & ~(1 << 29) & ~(1 << 30), 0) + b'\xc0' + nulldata())

marks['vendor'] = len(main) + 1
# vendor namespaces (unknown to the iterator: shown as raw bytes)
vend = lambda oui, sub, bits, data: ('ven', bytes.fromhex(oui), sub, bits, data)
add(build([('rt', [(5, b'\xc0')]), vend('0050f2', 1, 1, b'\1\2\3\4'), ('rt', [(11, b'\x01')])]))
add(build([('rt', [(5, b'\xc0')]), vend('001018', 7, 3, bytes(range(8))), vend('00904c', 0, 1, b''), ('rt', [(5, b'\xc3')])]))
add(build([('rt', [(11, b'\x01')]), vend('00e04c', 0, 1, b'abcd'), ('rt', [(5, b'\xc3'), (12, b'\x05')])]))
add(build([('rt', [(1, b'\x00')]), vend('aabbcc', 9, 0x80000001 & 0x7fffffff, b'')]))
add(build([('rt', [(1, b'\x00')]), vend('aabbcc', 9, 0, b'xy')]))             # vendor word without bits
add(build([('rt', [(0, struct.pack('<Q', 1))]), vend('112233', 2, 0x7, bytes(30)), ('rt', [(14, b'\x04\x00'), (15, b'\x01\x00')])]))
add(build([('rt', [(5, b'\xc0')]), vend('0050f2', 1, 1, b''), vend('0050f2', 2, 1, b'\5'), vend('0050f2', 3, 1, b'\6\7')]))

marks['tlv'] = len(main) + 1
# TLVs: fixed fields as TLVs, padding to 4, unknown types, vendor TLV
def tlv(*items, **kw):
    return simple([], tlv=list(items), **kw)

add(tlv((0, struct.pack('<Q', 7)), (1, b'\x00'), (3, struct.pack('<HH', 5180, 0x0140)), (5, b'\xc5')))
add(tlv((5, b'\xc5')))
add(tlv((5, b'\xc5'), (11, b'\x01'), (12, b'\x02'), (13, b'\x03')))
add(tlv((99, b'\x01\x02\x03\x04\x05'), (5, b'\xc1')))
add(tlv((0x1234, b'')))
add(tlv((28, b'\0\0\0\0')))
add(tlv((30, bytes.fromhex('0050f2') + b'\x01' + struct.pack('<HH', 3, 4) + b'\xaa\xbb\xcc\xdd')))
add(tlv((30, bytes.fromhex('0050f2') + b'\x01' + struct.pack('<HH', 3, 0))))
add(tlv((30, bytes.fromhex('001018') + b'\x07' + struct.pack('<HH', 3, 12) + bytes(range(12))), (5, b'\xc1')))
add(tlv((5, b'\xc1'), (31, b'\x00\x00\x00\x00')))
add(build([('rt', [(1, b'\x00'), (5, b'\xc0')])], tlv=[(5, b'\xc2'), (11, b'\x01')]))
add(build([('rt', [(3, struct.pack('<HH', 2412, 0x80))]), ('rt', [(5, b'\xc0')])], tlv=[(5, b'\xc2')]))
# the last TLV's padding is not part of the header length
add((lambda b: struct.pack('<BBHI', 0, 0, len(b) - 3, 1 << 28) + b[8:-3])(tlv((5, b'\xc0'))))
add((lambda b: struct.pack('<BBHI', 0, 0, len(b) - 2, 1 << 28) + b[8:-2])(tlv((99, b'\xc0\xc1'))))
for n in range(1, 9):
    add(tlv((99, bytes(range(n))), (5, b'\xc0'), (99, bytes(range(n)))))

# ---------------------------------------------------------------- malformed
bad.append(struct.pack('<BBHI', 0, 0, 4, 0) + nulldata())                       # length < 8
bad.append(struct.pack('<BBHI', 1, 0, 8, 0) + nulldata())                       # version 1
bad.append(struct.pack('<BBHII', 0, 0, 12, 1 << 31, 1 << 31) + nulldata())      # extension chain runs off the header
bad.append(struct.pack('<BBHI', 0, 0, 8, 1 << 31) + nulldata())                 # extension, no word
bad.append(struct.pack('<BBHIII', 0, 0, 20, 1 << 31, 1 << 31, (1 << 31) | (1 << 28)) + b'\0' * 4 + nulldata())   # TLV and ext bits in one word
bad.append(struct.pack('<BBHI', 0, 0, 8, 1 << 5) + nulldata())                  # field past the header
bad.append(struct.pack('<BBHI', 0, 0, 12, 1 << 3) + b'\0' * 4 + nulldata())     # channel after padding past the header
bad.append(struct.pack('<BBHI', 0, 0, 12, 1 << 0) + b'\0' * 4 + nulldata())     # TSFT does not fit
bad.append(struct.pack('<BBHI', 0, 0, 100, 1) + b'\0' * 8 + nulldata())         # length > frame
bad.append(struct.pack('<BBHI', 0, 0, 16, 1 << 29 | 1 << 30) + struct.pack('<HHI', 0, 0, 0) + nulldata())   # both namespace bits
bad.append(struct.pack('<BBHII', 0, 0, 12, (1 << 31) | (1 << 29) | (1 << 30), 1) + b'\0' * 4 + nulldata())
bad.append(struct.pack('<BBHII', 0, 0, 18, (1 << 31) | (1 << 30), 1) + bytes.fromhex('0050f2') + b'\x01' + struct.pack('<H', 40) + nulldata())  # vendor skip past the end
bad.append(struct.pack('<BBHI', 0, 0, 10, 1 << 30) + bytes.fromhex('0050f2') + b'\x01' + nulldata())   # vendor header does not fit
bad.append(struct.pack('<BBHIII', 0, 0, 22, (1 << 31) | (1 << 30), (1 << 31) | 1, 1) + bytes.fromhex('0050f2') + b'\x01' + struct.pack('<H', 0) + nulldata())  # data bit, no namespace
bad.append(struct.pack('<BBHI', 0, 0, 16, 1 << 28) + struct.pack('<HH', 5, 40) + nulldata())   # TLV past the header
bad.append(struct.pack('<BBHI', 0, 0, 10, 1 << 28) + struct.pack('<H', 5) + nulldata())         # TLV header does not fit
bad.append(tlv((30, bytes.fromhex('0050f2') + b'\x01')) + nulldata())   # vendor TLV, datalen 4 (< 8)
bad.append(tlv((30, b'')) + nulldata())
bad.append(struct.pack('<BBHI', 0, 0, 14, 1 << 28) + struct.pack('<HH', 5, 4) + b'\0' * 4 + nulldata())   # last TLV does not fit
t = simple([(0, bytes(8)), (3, bytes(4)), (19, bytes(3))])
for ln in (9, 12, 20):
    bad.append(t[:ln])

os.makedirs(out, exist_ok=True)
write_pcap(os.path.join(out, 'radiotap-iter-coverage.pcap'), 127, main)
write_pcap(os.path.join(out, 'radiotap-iter-coverage-malformed.pcap'), 127, bad)
print(len(main), len(bad), marks)
