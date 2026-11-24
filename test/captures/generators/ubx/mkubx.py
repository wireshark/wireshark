#!/usr/bin/env python3
# Generates test/captures/ubx_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the UBX coverage captures: mkubx.py <outdir>

ubx-coverage.pcap            valid traffic, every message the dissector knows
ubx-coverage-malformed.pcap  bad checksums, truncated and inconsistent frames
All frames are Exported PDU (link type 252) naming the "ubx" dissector.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct

from ubxlib import (  # noqa
    exp_pdu, gal_page, gal_sfrbx, gps_sfrbx, gps_words, outdir, sfrbx, ubx_frame, write_pcap,
)

rnd = random.Random(3737)


def rb(n):
    return bytes(rnd.getrandbits(8) for _ in range(n))


def patch(buf, off, fmt, *vals):
    struct.pack_into(fmt, buf, off, *vals)


def msg(cid, payload, **kw):
    return exp_pdu('ubx', ubx_frame(cid, payload, **kw))


frames = []


def add(cid, payload, **kw):
    frames.append(msg(cid, payload, **kw))


# ---- ACK-ACK / ACK-NAK (acknowledged message named by class and id) ----
for cid in (0x063E, 0x0613, 0x0A04, 0x0F0F):
    add(0x0501, struct.pack('>H', cid))
    add(0x0500, struct.pack('>H', cid))

# ---- CFG-GNSS: one block for each GNSS id (and an unknown one) ----
for nblk, gids in ((7, range(7)), (8, range(8)), (0, ()), (1, (6,))):
    p = bytearray(struct.pack('<BBBB', 0, 32, 28, nblk))
    for g in gids:
        p += struct.pack('<BBBBI', g, rnd.randrange(0, 20), rnd.randrange(0, 20), 0,
                         0x01000000 | rnd.getrandbits(16) << 1 | (g & 1))
    add(0x063E, bytes(p))

# ---- CFG-SBAS ----
for i in range(4):
    p = bytearray(rb(8))
    if i == 0:
        p[:] = bytes([0x01, 0x07, 3, 0x00, 0x00, 0x00, 0x00, 0x00])
    if i == 1:
        p[:] = bytes([0xff, 0xff, 3, 0xff, 0xff, 0xff, 0xff, 0xff])
    add(0x0616, bytes(p))

# ---- MON-RF with 0, 1, 2 and 4 blocks ----
for nb in (0, 1, 2, 4):
    p = bytearray(struct.pack('<BBH', 0, nb, 0))
    for b in range(nb):
        blk = bytearray(rb(24))
        blk[0] = b
        p += blk
    add(0x0A38, bytes(p))

# ---- NAV-DOP, EOE, ODO, POSECEF ----
for i in range(3):
    add(0x0104, struct.pack('<IHHHHHHH', 345000 + i * 1000, 99 + i, 150, 80, 120, 110, 95, 70))
    add(0x0161, struct.pack('<I', 345000 + i * 1000))
    add(0x0109, rb(20))
    add(0x0101, struct.pack('<Iiiii', 345000 + i * 1000, -2745000000 // 1000 * i + 4000000,
                             -4300000 + i, 3850000, 500 + i))

# ---- NAV-PVT, positive and negative angles ----
for i in range(6):
    p = bytearray(rb(92))
    patch(p, 0, '<I', 345000 + i * 1000)
    patch(p, 4, '<HBBBBB', 2026, 11, 12, 5, 7, 9 + i)
    patch(p, 20, '<BBBB', 3, 0x01 | (i & 1) << 5, 0x20, 12 + i)
    patch(p, 24, '<ii', (-1 if i & 1 else 1) * rnd.randrange(0, 1800000000),
          (-1 if i & 2 else 1) * rnd.randrange(0, 900000000))
    patch(p, 64, '<i', (-1 if i & 1 else 1) * rnd.randrange(0, 36000000))
    patch(p, 84, '<h', (-1 if i & 4 else 1) * rnd.randrange(0, 3000))
    add(0x0107, bytes(p))

# ---- NAV-RELPOSNED: positive and negative high precision parts ----
for i in range(4):
    p = bytearray(rb(64))
    p[0] = 1
    for off in (32, 33, 34, 35):
        p[off] = rnd.getrandbits(7) | (0x80 if i & 1 else 0)
    patch(p, 8, '<iiii', *[(-1 if i & 2 else 1) * rnd.randrange(0, 100000) for _ in range(4)])
    add(0x013C, bytes(p))

# ---- NAV-SAT with 0..many satellites, SBAS, TIMEGPS, TIMEUTC, VELECEF ----
for n in (0, 1, 5, 24, 40):
    p = bytearray(struct.pack('<IBBH', 345000, 1, n, 0))
    for s in range(n):
        p += struct.pack('<BBBbhhI', s % 8, 1 + s, 20 + s, (s * 7) % 90 - 10,
                         (s * 37) % 360, (s * 11) % 200 - 100,
                         0x0008 * (s & 1) | 0x1 | (s & 7) << 4)
    add(0x0135, bytes(p))
for n in (0, 1, 3, 9):
    p = bytearray(struct.pack('<IBBBBBBH', 345000, 122, 1, 0x0f, 3, 0, 0, 0)[:12])
    patch(p, 8, '<B', n)
    for s in range(n):
        p += struct.pack('<BBBBBBhHh', 120 + s, 1, 0, 0, 1, 0, 100 * s, 0, -50 * s)
    add(0x0132, bytes(p))
for ftow in (123456, -5, 0, -999999):
    add(0x0120, struct.pack('<IiHbBI', 346000 if ftow != -5 else 346000, ftow, 2400, 18, 0x07, 25))
add(0x0120, struct.pack('<IiHbBI', 345000, 5, 2400, 18, 0x07, 25))
for i in range(3):
    p = bytearray(rb(20))
    p[19] = 0
    add(0x0121, bytes(p))
for i in range(3):
    add(0x0111, rb(20))

# ---- RXM-MEASX ----
for n in (0, 1, 6, 12):
    p = bytearray(rb(44 + 24 * n))
    p[0] = 1
    p[34] = n
    for s in range(n):
        p[44 + 24 * s] = s % 7
    add(0x0214, bytes(p))

# ---- RXM-RAWX (sane doubles/floats) ----
for n in (0, 1, 8, 20):
    p = bytearray(16 + 32 * n)
    patch(p, 0, '<dHbBBBH', 345678.123, 2400, 18, n, 0x03, 1, 0)
    for s in range(n):
        o = 16 + 32 * s
        patch(p, o, '<ddf', 22000000.5 + s * 1.25, -123456.75 * (1 if s & 1 else -1), -1234.5 + 100 * s)
        patch(p, o + 20, '<BBBBHBBBBBB', s % 7, 1 + s, s & 3, 8 + s % 7, 1000 * s, 30 + s,
              s & 15, (s * 3) & 15, (s * 5) & 15, 0x0f if s & 1 else s & 15, 0)
    add(0x0215, bytes(p))

# ---- RXM-SFRBX: every GNSS ID and both message versions ----
# GPS and Galileo carry valid navigation data (their own dissectors), the
# other constellations (SBAS has its own dissector) fall back to data
for gnss, nw in ((3, 10), (4, 3), (5, 10), (6, 4), (7, 2)):
    for ver in (1, 2):
        add(0x0213, sfrbx(gnss, 1 + gnss, rb(nw * 4), version=ver, sigid=gnss, freqid=3, chn=2))
for ver in (1, 2):
    frames.append(msg(0x0213, gps_sfrbx(gps_words(rnd, 1 + ver % 2, tow=500 + ver), 7 + ver, version=ver)))
    frames.append(msg(0x0213, gal_sfrbx(gal_page(rnd, inav_type=1 + ver), 9 + ver, version=ver)))
# an unknown message version: no version specific fields
frames.append(msg(0x0213, sfrbx(7, 9, rb(8), version=3)))

# ---- classes and ids with no dissector of their own ----
for cid in (0x0A04, 0x0101 + 0x0600, 0x0B01, 0x0602, 0xFFFF, 0x0000):
    add(cid, rb(8))
add(0x0A04, b'')

# a frame with trailing octets after the checksum
frames.append(msg(0x0161, struct.pack('<I', 1)) + b'\x00\x00\x00')

# ---- malformed ----
mal = []
mal.append(msg(0x0213, sfrbx(0, 7, b'', version=2)))
mal.append(msg(0x0213, sfrbx(0, 7, rb(20), version=2)))
for cid, ln in ((0x0501, 2), (0x063E, 4), (0x0616, 8), (0x0A38, 4), (0x0104, 18),
                (0x0161, 4), (0x0109, 20), (0x0101, 20), (0x0107, 92), (0x013C, 64),
                (0x0135, 8), (0x0132, 12), (0x0120, 16), (0x0121, 20), (0x0111, 20),
                (0x0214, 44), (0x0215, 16), (0x0213, 8)):
    # checksummed message whose payload is one octet short of the structure
    mal.append(msg(cid, rb(ln - 1) if ln > 1 else b''))
# counts larger than the data
p = bytearray(rb(8)); p[3] = 5
mal.append(msg(0x063E, bytes(p)))
p = bytearray(rb(4)); p[1] = 3
mal.append(msg(0x0A38, bytes(p)))
p = bytearray(rb(8)); p[5] = 4
mal.append(msg(0x0135, bytes(p)))
p = bytearray(rb(12)); p[8] = 4
mal.append(msg(0x0132, bytes(p)))
p = bytearray(rb(44)); p[34] = 3
mal.append(msg(0x0214, bytes(p)))
p = bytearray(rb(16)); p[11] = 2
mal.append(msg(0x0215, bytes(p)))
p = bytearray(rb(8)); p[4] = 9
mal.append(msg(0x0213, bytes(p) + rb(4)))
# bad checksum (warning), length field larger than the frame, short frames
mal.append(msg(0x0161, struct.pack('<I', 7), bad_chk=True))
mal.append(msg(0x0501, struct.pack('>H', 0x0613), bad_chk=True))
mal.append(msg(0x0161, struct.pack('<I', 7), length=40))
mal.append(exp_pdu('ubx', b'\xb5\x62\x01\x61'))
mal.append(exp_pdu('ubx', b'\xb5'))
mal.append(exp_pdu('ubx', b''))

out = sys.argv[1] if len(sys.argv) > 1 else outdir()
write_pcap(os.path.join(out, 'ubx-coverage.pcap'), frames)
write_pcap(os.path.join(out, 'ubx-coverage-malformed.pcap'), mal)
print(len(frames), len(mal))
