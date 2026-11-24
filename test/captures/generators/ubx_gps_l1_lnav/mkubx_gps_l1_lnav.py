#!/usr/bin/env python3
# Generates test/captures/ubx_gps_l1_lnav_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the GPS L1 LNAV coverage captures: mkubx_gps_l1_lnav.py <outdir>

ubx_gps_l1_lnav-coverage.pcap           valid subframes (and two with a warning)
ubx_gps_l1_lnav-coverage-malformed.pcap warnings (preamble, TOW count) and short subframes
Frames are Exported PDU (link type 252): UBX-RXM-SFRBX frames name the
"ubx" dissector, a few name "ubx_gps_l1" directly.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct

from ubxlib import exp_pdu, gps_sfrbx, gps_words, outdir, ubx_frame, write_pcap  # noqa

rnd = random.Random(5151)
NAME = 'ubx_gps_l1_lnav'


def sfr(words, svid, version=2):
    return exp_pdu('ubx', ubx_frame(0x0213, gps_sfrbx(words, svid, version=version)))


def direct(words):
    return exp_pdu('ubx_gps_l1', words)


def build():
    frames = []
    tow = 1000
    # subframes 1 and 2 of several satellites, alternating, both message
    # versions; random 30 bit words so that signed values of both signs occur
    for i in range(40):
        for sf in (1, 2):
            tow += 1
            frames.append(sfr(gps_words(rnd, sf, tow=tow, alert=i & 1, spoof=(i >> 1) & 1,
                                        integrity=(i >> 2) & 1), 1 + i % 32, version=1 + i % 2))
    # TOW count at its limit (100799 is the last valid count) and at 0
    for t in (0, 100799):
        for sf in (1, 2):
            frames.append(sfr(gps_words(rnd, sf, tow=t), 3))
    # an invalid TLM preamble and a TOW count past 100799: warnings only
    frames.append(sfr(gps_words(rnd, 1, tow=4000, preamble=0x00), 5))
    frames.append(sfr(gps_words(rnd, 2, tow=100800), 5))
    # subframes 3, 4 and 5 and the unused subframe ids: no dissector
    for sf in (0, 3, 4, 5, 6, 7):
        frames.append(sfr(gps_words(rnd, sf, tow=2000 + sf), 4))
    # named handle without an SVID
    for sf in (1, 2, 3):
        frames.append(direct(gps_words(rnd, sf, tow=3000 + sf)))
    # all-zero and all-one data words (zero and the most negative values)
    for sf in (1, 2):
        for fill in (0, 0x3fffffff):
            w = [fill] * 10
            w[0] = (0x8b << 22) | (fill & 0x3fffff)
            w[1] = (500 << 13) | (sf << 8) | (fill & 0xff)
            frames.append(sfr(b''.join(struct.pack('<I', x & 0x3fffffff) for x in w), 9))

    mal = []
    # invalid TLM preamble and TOW counts past 100799 (warnings, still decoded)
    for sf in (1, 2):
        mal.append(sfr(gps_words(rnd, sf, tow=4000, preamble=0x00), 5))
        mal.append(sfr(gps_words(rnd, sf, tow=100800), 5))
        mal.append(sfr(gps_words(rnd, sf, tow=131071, preamble=0xff), 5))
    # subframes too short for their words (throw, with a tree)
    for sf in (1, 2):
        w = gps_words(rnd, sf, tow=5000)
        mal.append(sfr(w[:24], 6))
        mal.append(sfr(w[:12], 6))
        mal.append(direct(w[:36]))
        mal.append(direct(w[:8]))
    mal.append(direct(b''))
    mal.append(exp_pdu('ubx_gps_l1', gps_words(rnd, 2)[:4]))
    return frames, mal


frames, mal = build()
out = sys.argv[1] if len(sys.argv) > 1 else outdir()
write_pcap(os.path.join(out, NAME + '-coverage.pcap'), frames)
write_pcap(os.path.join(out, NAME + '-coverage-malformed.pcap'), mal)
print(len(frames), len(mal))
