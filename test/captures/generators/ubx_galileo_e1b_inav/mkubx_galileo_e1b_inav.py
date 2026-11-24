#!/usr/bin/env python3
# Generates test/captures/ubx_galileo_e1b_inav_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Galileo E1-B I/NAV coverage captures:
mkubx_galileo_e1b_inav.py <outdir>

ubx_galileo_e1b_inav-coverage.pcap           valid traffic
ubx_galileo_e1b_inav-coverage-malformed.pcap OSNMA DSMs that run out of the data
Frames are Exported PDU (link type 252). UBX-RXM-SFRBX frames name the
"ubx" dissector (which hands the SVID to the Galileo dissector); a few
frames name "ubx_gal_inav" directly, without an SVID.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random

from ubxlib import exp_pdu, gal_page, gal_sfrbx, outdir, setf, sfrbx, ubx_frame, write_pcap  # noqa

rnd = random.Random(4242)
NAME = 'ubx_galileo_e1b_inav'


def sfr(page, svid, version=2):
    return exp_pdu('ubx', ubx_frame(0x0213, gal_sfrbx(page, svid, version=version)))


def direct(page):
    return exp_pdu('ubx_gal_inav', page)


# word types used for the 14 frames that follow a type 2 word in a sub-frame
TYPES = [2, 4, 5, 6, 7, 8, 9, 10, 0, 1, 3, 4, 5, 6, 7]


def subframe(svid, hk, version=2, count=15):
    """count frames of one OSNMA sub-frame; hk are the 15 HKROOT octets."""
    out = []
    for k in range(count):
        out.append(sfr(gal_page(rnd, inav_type=TYPES[k], hkroot=hk[k],
                                mack=0x10000 + 7 * k + 1, zero=True), svid, version))
    return out


def hk_msg(dsm_id, blk_id, blk, b0=0x92):
    assert len(blk) == 13
    return bytes([b0, (dsm_id << 4) | blk_id]) + bytes(blk)


def rb(n):
    return bytes(rnd.getrandbits(8) | 1 for _ in range(n))


def kroot_dsm(nb_dk, ks, hf=0, mf=0, ts=9, pkid=1):
    nblk = nb_dk + 6
    total = bytearray(rb(nblk * 13))
    total[0] = (nb_dk << 4) | pkid
    total[1] = (1 << 6) | (hf << 2) | mf
    total[2] = (ks << 4) | ts
    total[3] = 0x21
    return total


def pkr_dsm(nb_dp, mid, npkt, npkid=2):
    nblk = nb_dp + 6
    total = bytearray(rb(nblk * 13))
    total[0] = (nb_dp << 4) | mid
    total[129] = (npkt << 4) | npkid
    return total


def blocks(total):
    return [bytes(total[i:i + 13]) for i in range(0, len(total), 13)]


def send_block(svid, dsm_id, blk_id, blk, **kw):
    return subframe(svid, hk_msg(dsm_id, blk_id, blk), **kw)


def build():
    frames = []
    # ---- word sweep: every word type with random data, no OSNMA/SAR state ----
    for t in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 17, 20, 63):
        for i in range(3):
            frames.append(sfr(gal_page(rnd, inav_type=t), 30 + i))
    for t in (0, 1, 3, 4, 6):
        for i in range(8):
            frames.append(sfr(gal_page(rnd, inav_type=t), 33))
    # word 3 with every SISA range (the index is the last octet of the word)
    for sisa in (10, 55, 80, 110, 130, 255):
        pg = bytearray(gal_page(rnd, inav_type=3))
        setf(pg, 16, 8, 0x3fffc00000000000, (0x3a << 8) | sisa)
        frames.append(sfr(bytes(pg), 34))
    # ---- alert pages and mixed pages ----
    frames.append(sfr(gal_page(rnd, even_alert=True, odd_alert=True), 31))
    frames.append(sfr(gal_page(rnd, even_alert=False, odd_alert=True), 31))
    frames.append(sfr(gal_page(rnd, even_alert=True, odd_alert=False,
                               sar_start=1, sar_data=0x12345), 31))
    # ---- named handle directly: no SVID, so no OSNMA / SAR state ----
    for t in (0, 2, 4, 6):
        frames.append(direct(gal_page(rnd, inav_type=t, hkroot=0x55, mack=0x1234567,
                                      sar_start=1, sar_data=0x777)))
    frames.append(direct(gal_page(rnd, even_alert=True, odd_alert=True)))

    # ---- SAR RLM re-assembly ----
    # Short-RLM for SVID 20: start bit, then three parts; the 4th part
    # completes it. A second Short-RLM with a new start bit follows.
    for rlm in (0x1234567, 0xabcdef0):
        frames.append(sfr(gal_page(rnd, inav_type=1, sar_start=1, sar_long=0, sar_data=0x12345 + (rlm & 0xf)), 20))
        for k in range(3):
            frames.append(sfr(gal_page(rnd, inav_type=1, sar_start=0, sar_long=0,
                                       sar_data=(rlm >> (4 * k)) & 0xfffff), 20))
    # a part with no start bit and no conversation yet
    frames.append(sfr(gal_page(rnd, inav_type=1, sar_start=0, sar_long=0, sar_data=0x11111), 22))
    # Long-RLM for SVID 21: start bit and seven more parts, then a restart
    for rep in range(2):
        frames.append(sfr(gal_page(rnd, inav_type=1, sar_start=1, sar_long=1, sar_data=0x2000 + rep), 21))
        for k in range(7):
            frames.append(sfr(gal_page(rnd, inav_type=1, sar_start=0, sar_long=1, sar_data=0x3000 + k), 21))
    # a part (not the start) of the other kind after a complete Long-RLM
    frames.append(sfr(gal_page(rnd, inav_type=1, sar_start=0, sar_long=0, sar_data=0x4444), 21))
    # an incomplete Long-RLM followed by a Short-RLM part
    frames.append(sfr(gal_page(rnd, inav_type=1, sar_start=1, sar_long=1, sar_data=0x5000), 23))
    frames.append(sfr(gal_page(rnd, inav_type=1, sar_start=0, sar_long=0, sar_data=0x5001), 23))
    frames.append(sfr(gal_page(rnd, inav_type=1, sar_start=0, sar_long=1, sar_data=0x5002), 23))
    # reproducer of "GNSS: Fix Galileo I/NAV SAR RLM reassembly read ...":
    # four Short-RLM parts, then a part with the Long-RLM flag. Without the
    # fix the display loop read sar_rlm_parts[4..7] of a 4 entry array.
    frames.append(sfr(gal_page(rnd, inav_type=0, sar_start=1, sar_long=0, sar_data=0x12345, zero=True), 5))
    for k in range(2):
        frames.append(sfr(gal_page(rnd, inav_type=0, sar_start=0, sar_long=0, sar_data=0x12345, zero=True), 5))
    frames.append(sfr(gal_page(rnd, inav_type=0, sar_start=0, sar_long=0, sar_data=0x12345, zero=True), 5))
    frames.append(sfr(gal_page(rnd, inav_type=0, sar_start=0, sar_long=1, sar_data=0x12345, zero=True), 5))

    # ---- OSNMA HKROOT / MACK re-assembly ----
    # parts without a conversation (word type is not 2): ignored
    frames.append(sfr(gal_page(rnd, inav_type=4, hkroot=0x12, mack=0x34567, zero=True), 12))
    # a frame with empty HKROOT and MACK is skipped even for type 2
    frames.append(sfr(gal_page(rnd, inav_type=2, hkroot=0, mack=0, zero=True), 12))
    # an interrupted sub-frame (5 parts) followed by a complete one
    frames += subframe(13, hk_msg(0, 0, rb(13)), count=5)
    frames += subframe(13, hk_msg(0, 0, rb(13)))
    # a sub-frame carried in version 1 messages
    frames += subframe(14, hk_msg(0, 1, rb(13)), version=1)

    # DSM-KROOT, DSM ID 1: 9 blocks (NB_DK 3), key size 128 bits (KS 4)
    svid = 11
    k = kroot_dsm(3, 4, hf=0, mf=1)
    for i, b in enumerate(blocks(k)):
        frames += send_block(svid, 1, i, b)
    # the same DSM again with other key sizes and hash/MAC functions: the
    # blocks 1.. are kept and block 0 is replaced. KS 9 is reserved.
    for ks, hf, mf in ((0, 2, 0), (5, 1, 2), (8, 3, 1), (9, 0, 0)):
        k2 = bytearray(k)
        k2[0] = (3 << 4) | 1
        k2[1] = (1 << 6) | (hf << 2) | mf
        k2[2] = (ks << 4) | 9
        frames += send_block(svid, 1, 0, bytes(k2[0:13]))
    # NB_DK that does not match the blocks received: not displayed
    k2 = bytearray(k)
    k2[0] = (5 << 4) | 1
    frames += send_block(svid, 1, 0, bytes(k2[0:13]))
    # DSM ID 2: block 3 arrives first, then a block 0 whose NB_DK is 0
    frames += send_block(svid, 2, 3, rb(13))
    frames += send_block(svid, 2, 0, bytes(13))

    # DSM-PKR, DSM ID 12: 13 blocks (NB_DP 7), message ID 0, NPKT 1 (ECDSA P-256)
    p = pkr_dsm(7, 0, 1)
    for i, b in enumerate(blocks(p)):
        frames += send_block(svid, 12, i, b)
    # message IDs 1..15 (block 0 replaced)
    for mid in range(1, 16):
        p2 = bytearray(p)
        p2[0] = (7 << 4) | mid
        frames += send_block(svid, 12, 0, bytes(p2[0:13]))
    # NPKT 3 (OSNMA alert message), 0 and 2 (reserved: no key): block 9 replaced
    for npkt in (3, 0, 2):
        p2 = bytearray(p)
        p2[129] = (npkt << 4) | 5
        frames += send_block(svid, 12, 9, bytes(p2[117:130]))
    # grow the DSM to 16 blocks (NB_DP 10): NPKT 1 with a longer padding
    # and NPKT 4 (ECDSA P-521); blocks 13..15 are new
    p10 = bytearray(rb(16 * 13))
    for i in range(13, 16):
        frames += send_block(svid, 12, i, bytes(p10[13 * i:13 * i + 13]))
    for mid, npkt in ((3, 1), (4, 4), (5, 3)):
        p10[0] = (10 << 4) | mid
        p10[129] = (npkt << 4) | 7
        frames += send_block(svid, 12, 0, bytes(p10[0:13]))
        frames += send_block(svid, 12, 9, bytes(p10[117:130]))

    # ---- malformed: DSMs whose fields do not fit the data received ----
    mal = []
    # DSM-PKR with 13 blocks and NPKT 4: the padding length underflows
    p = pkr_dsm(7, 2, 4)
    for i, b in enumerate(blocks(p)):
        mal += send_block(40, 13, i, b)
    # DSM-KROOT with 7 blocks (NB_DK 1) and KS 4: the padding length underflows
    k = kroot_dsm(1, 4)
    for i, b in enumerate(blocks(k)):
        mal += send_block(40, 3, i, b)
    # pages too short for the structure (UBX messages and the direct handle)
    mal.append(sfr(gal_page(rnd, inav_type=1)[:20], 41))
    mal.append(exp_pdu('ubx', ubx_frame(0x0213, sfrbx(2, 41, rnd.randbytes(16)))))
    mal.append(direct(gal_page(rnd, inav_type=1)[:24]))
    mal.append(direct(b''))
    # a word type 1 page whose length is cut after the odd page header
    mal.append(direct(gal_page(rnd, inav_type=1)[:17]))
    return frames, mal


frames, mal = build()
out = sys.argv[1] if len(sys.argv) > 1 else outdir()
write_pcap(os.path.join(out, NAME + '-coverage.pcap'), frames)
write_pcap(os.path.join(out, NAME + '-coverage-malformed.pcap'), mal)
print(len(frames), len(mal))
