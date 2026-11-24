#!/usr/bin/env python3
# Generates test/captures/fpp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Frame Preemption Protocol (FPP, IEEE 802.3br mPackets) captures.

Usage: mkfpp.py <outdir>
Writes fpp-coverage.pcapng and fpp-coverage-malformed.pcapng.

Link type 274 (LINKTYPE_ETHERNET_MPACKET).  The pcapng files have two
interfaces and per-packet direction flags: the reassembly state is kept per
interface and direction, so two fragmented frames are interleaved.
The CRCs are plain CRC-32 (zlib); a fragment's CRC is seeded with the CRC
of the previous fragment and the CRC of a not last fragment is inverted in
the upper 16 bits (mCRC).
"""
import struct
import sys
import os
import zlib

out = sys.argv[1] if len(sys.argv) > 1 else '.'
LINKTYPE = 274

def pad4(b):
    return b + b'\0' * (-len(b) % 4)

def block(btype, body):
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)

def opt(code, val):
    return struct.pack('<HH', code, len(val)) + pad4(val)

def write_pcapng(path, frames, nifaces=2):
    """frames: (interface, direction 0/1/2, bytes)"""
    with open(path, 'wb') as f:
        f.write(block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        for _ in range(nifaces):
            f.write(block(1, struct.pack('<HHI', LINKTYPE, 0, 65535)))
        for i, (ifc, d, p) in enumerate(frames):
            ts = 1700000000 * 1000000 + i * 1000
            body = struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(p), len(p))
            body += pad4(p)
            if d:
                body += opt(2, struct.pack('<I', d)) + struct.pack('<HH', 0, 0)
            f.write(block(6, body))

def le(v):
    return struct.pack('<I', v & 0xffffffff)

def eth(payload_len=46, seed=0, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01', et=0x88b5):
    return dst + src + struct.pack('>H', et) + bytes((seed + 3 * i + 1) & 0xff for i in range(payload_len))

PRE = b'\x55' * 7
S = {0: 0xe6, 1: 0x4c, 2: 0x7f, 3: 0xb3}        # SMD-S0..3 (also the fragment counts #0..#3)
C = {0: 0x61, 1: 0x52, 2: 0x9e, 3: 0x2a}        # SMD-C0..3

def express(fr, bad=False, pre=PRE):
    crc = zlib.crc32(fr)
    return pre + b'\xd5' + fr + le(crc ^ (1 if bad else 0))

def whole(fr, s=0, pre=PRE):
    """non-fragmented preemptable frame: CRC"""
    return pre + bytes([S[s]]) + fr + le(zlib.crc32(fr))

def fragments(fr, cuts, s=0, pre_init=PRE, pre_cont=b'\x55' * 6, counts=None, bad_last=False,
              bad_mid=None):
    """split fr at the offsets in cuts; returns the list of mPackets:
    SMD-S (mCRC), SMD-C #0.. (mCRC) and a last SMD-C with the CRC"""
    parts = []
    last = 0
    for c in cuts + [len(fr)]:
        parts.append(fr[last:c])
        last = c
    pkts = []
    crc = 0
    for i, part in enumerate(parts):
        crc = zlib.crc32(part, crc)
        final = i == len(parts) - 1
        if i == 0:
            pkts.append(pre_init + bytes([S[s]]) + part + le(crc ^ 0x0000ffff))
        else:
            cnt = (i - 1) % 4 if counts is None else counts[i - 1]
            smd = bytes([C[s], S[cnt]])
            if final:
                v = crc ^ (1 if bad_last else 0)
            else:
                v = crc ^ 0x0000ffff
                if bad_mid == i:
                    v ^= 2
            pkts.append(pre_cont + smd + part + le(v))
    return pkts

main, mal = [], []
IN, OUT = 1, 2

# 1-2 express frames: good CRC, and a bad CRC (shown as an error? no: the
# frame is then shown but not dissected further) goes to the malformed file
main.append((0, 0, express(eth(60, 1))))
main.append((0, IN, express(eth(100, 2), pre=b'\x50' + b'\x55' * 7)))
# 3-6 non-fragmented frames with every SMD-S, then alignment prefix, a
# shortened and a lengthened preamble
for s in range(4):
    main.append((0, OUT, whole(eth(50 + s, 10 + s), s)))
main.append((0, OUT, whole(eth(70, 20), 0, pre=b'\x50' + b'\x55' * 6)))
main.append((0, OUT, whole(eth(70, 21), 1, pre=b'\x55' * 3)))
main.append((0, OUT, whole(eth(70, 22), 2, pre=b'\x55' * 11)))
# SMD-V (verify) and SMD-R (respond) mPackets: no payload, CRC 0
main.append((0, 0, PRE + b'\x07' + le(0x0000ffff)))
main.append((0, 0, PRE + b'\x19' + le(0x0000ffff)))
# a fragmented frame with two fragments (SMD-S0, last SMD-C0 #0)
fr = eth(120, 30)
for p in fragments(fr, [50], 0):
    main.append((0, IN, p))
# a frame in three fragments with SMD-S1/C1 on the other interface
fr = eth(200, 40)
for p in fragments(fr, [40, 110], 1):
    main.append((1, IN, p))
# five fragments (all four fragment counts), alignment prefix on the first
fr = eth(300, 50)
ps = fragments(fr, [60, 100, 160, 220], 2, pre_init=b'\x50' + b'\x55' * 7)
for p in ps:
    main.append((0, OUT, p))
# two frames interleaved on the same interface in both directions
fa, fb = eth(150, 60), eth(160, 70, et=0x88b6)
pa = fragments(fa, [50, 100], 3)
pb = fragments(fb, [70], 0)
order = [(0, pa[0], IN), (0, pb[0], OUT), (0, pa[1], IN), (0, pb[1], OUT), (0, pa[2], IN)]
for ifc, p, d in order:
    main.append((ifc, d, p))
# a frame whose first part starts a new fragmentation while the previous
# one is unfinished (drops the old fragments), then it is completed
fa, fb = eth(100, 80), eth(100, 90)
pa = fragments(fa, [30, 60], 0)
pb = fragments(fb, [40], 1)
main.append((1, OUT, pa[0]))
main.append((1, OUT, pa[1]))
for p in pb:
    main.append((1, OUT, p))
# the reproducer of the address offset fix: an initial fragment behind the
# 0x50 alignment octet and a 7 octet preamble, and without it, so the
# addresses are not at the fixed offsets 8 and 14 of the mPacket
fr = eth(64, 0)
for pre in (b'\x50' + b'\x55' * 7, b'\x55' * 7):
    for p in fragments(fr, [40], 0, pre_init=pre):
        main.append((0, 0, p))
# an express frame with a shortened preamble
main.append((0, 0, express(eth(60, 98), pre=b'\x55' * 5)))
# a continuation fragment after a complete frame: no fragmentation is in
# progress, but its mCRC (seed 0) is valid, so it is taken for a continuation
orph = eth(40, 97)
main.append((0, OUT, whole(eth(60, 96), 0)))
main.append((0, OUT, b'\x55' * 6 + bytes([C[0], S[0]]) + orph + le(zlib.crc32(orph) ^ 0x0000ffff)))
# the same frames again as plain frames after the fragmented ones
main.append((0, 0, whole(eth(60, 99), 0)))

# ---- malformed (checksum errors, orphans, invalid sequences)
mal.append((0, 0, express(eth(60, 1), bad=True)))
mal.append((0, 0, PRE + b'\x07' + le(0x12345678)))
mal.append((0, 0, PRE + b'\x19' + le(0x12345678)))
# non-fragmented frame with a bad CRC: "possibly first fragment"
mal.append((0, 0, PRE + bytes([S[0]]) + eth(60, 5) + le(0xdeadbeef)))
# continuation with no start, then a last one
mal.append((0, 0, b'\x55' * 6 + bytes([C[0], S[0]]) + eth(40, 3) + le(0x11111111)))
mal.append((0, 0, b'\x55' * 6 + bytes([C[0], S[0]]) + eth(40, 3) + le(zlib.crc32(eth(40, 3)))))
# start, then a continuation with a wrong count, then a bad continuation
fr = eth(160, 4)
ps = fragments(fr, [40, 80, 120], 0, counts=[2, 1, 0])
for p in ps:
    mal.append((1, 0, p))
# start, then a bad mCRC mid fragment, then the last one
ps = fragments(fr, [40, 80], 1, bad_mid=1)
for p in ps:
    mal.append((1, IN, p))
# last fragment with a bad CRC
ps = fragments(fr, [40], 2, bad_last=True)
for p in ps:
    mal.append((1, OUT, p))
# a start fragment whose frame is shorter than an Ethernet header (< 12
# octets, the fix: addresses are only taken if present)
tiny = b'\x01\x02\x03'
for p in fragments(tiny + b'\x04\x05', [3], 0):
    mal.append((0, IN, p))
mal.append((0, 0, PRE + bytes([S[0]]) + tiny + le(zlib.crc32(tiny) ^ 0x0000ffff)))
# frames shorter than the preamble plus CRC
mal.append((0, 0, PRE + b'\xe6'))
mal.append((0, 0, PRE[:3]))
mal.append((0, 0, b'\x55\x55\x55\x55\x55\x55\x55\x55'))
mal.append((0, 0, b'\x50'))
mal.append((0, 0, b'\xe6'))
# no preamble at all: the SMD is the first octet, so the previous octet
# that the code reads for continuation tests does not exist
mal.append((0, 0, whole(eth(70, 22), 3, pre=b'')))
mal.append((0, 0, whole(eth(70, 22), 0, pre=b'')))
# unknown SMD, and continuation with an unknown fragment count
mal.append((0, 0, PRE + b'\x42' + eth(50, 7) + le(zlib.crc32(eth(50, 7)))))
mal.append((0, 0, b'\x55' * 6 + b'\x61\x42' + eth(50, 7) + le(0)))

write_pcapng(os.path.join(out, 'fpp-coverage.pcapng'), main)
write_pcapng(os.path.join(out, 'fpp-coverage-malformed.pcapng'), mal)
# a classic pcap file: no interface id in the records
def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE))
        for i, (ifc, d, p) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)
legacy = [(0, 0, p) for p in fragments(eth(120, 30), [50], 0)] + [(0, 0, express(eth(60, 1)))]
write_pcap(os.path.join(out, 'fpp-coverage-legacy.pcap'), legacy)
print(len(main), len(mal))
