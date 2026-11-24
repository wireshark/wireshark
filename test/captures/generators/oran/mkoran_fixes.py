#!/usr/bin/env python3
# Generates test/captures/oran_coverage.pcap.gz, oran_fixes_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Supplementary O-RAN FH CUS capture for the fixes of the section state
change: oran-fixes-coverage.pcap.  Uses the helpers of mkoran.py (same
directory).  Everything is synthetic.  Usage: mkoran_fixes.py <outdir>"""
import os
import sys
from mkoran import (  # noqa
    BFP, Bits, Cap, csec, DL, exts, MOD_SREM, se11_weights, ST1, ST5, ST6, st6_sec, st_hdr, uprb,
    usec,
)


def fixes_capture():
    c = Cap()
    # 1: ST1 with reMask 0x5a5 (leaves the value on the stack of the old code)
    c.cplane(0x2001, DL, ST1, st_hdr(ST1) + csec(ST1, sid=1, start=0, num=1, remask=0x5a5, beam=3),
             frame=1)
    se5 = Bits().u(0xfff, 12).u(0, 1).u(0x0800, 15).u(0, 20)
    # 2: SE 5 in an ST1 section with reMask: the checks run and are clean
    c.cplane(0x2001, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=2, start=0, num=1, remask=0xfff, beam=4, ext_bytes=exts((5, se5))),
             frame=1, slot=2)
    # 4-5: SE 27, the beamIds are in the extension tree; numElements 0 means 256
    se27_256 = Bits().u(0, 2).u(0, 6).u(0, 8)
    for i in range(256):
        se27_256.u(0, 1).u(1000 + i, 15)
    se27_3 = Bits().u(0, 2).u(0, 6).u(3, 8)
    for i in range(3):
        se27_3.u(0, 1).u(2000 + i, 15)
    se27_t1 = Bits().u(1, 2).u(0, 6).u(1, 8).u(0, 1).u(3000, 15)
    c.cplane(0x2002, DL, ST5, st_hdr(ST5) +
             csec(ST5, sid=3, start=0, num=1, ueid=5, ext_bytes=exts((27, se27_256))), frame=2)
    c.cplane(0x2002, DL, ST5, st_hdr(ST5) +
             csec(ST5, sid=4, start=0, num=1, ueid=5, ext_bytes=exts((27, se27_3))) +
             csec(ST5, sid=5, start=1, num=1, ueid=6, ext_bytes=exts((27, se27_t1))),
             nsec=2, frame=2, slot=1)
    # 6-8: a section with SE 11 bundle beams (per-PRB beamIds), redefined by a plain
    # section with the same sectionId, and a U-plane frame using the redefinition
    c.cplane(0x2003, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=7, start=0, num=4, beam=9, ext_bytes=exts(se11_weights(2, [(0, 130, False), (1, 131, False)], 9, BFP))),
             frame=3)
    c.cplane(0x2003, DL, ST1, st_hdr(ST1) + csec(ST1, sid=7, start=0, num=4, beam=11),
             frame=3, slot=1)
    c.uplane(0x2003, DL, [usec(7, 0, 4, [uprb(BFP, 9, seed=p) for p in range(4)], hdr=(9, BFP))],
             frame=3, slot=1)
    # 9-11: memory amplification reproducers, a few frames: 255 sections with
    # distinct sectionIds in each of two flows, and U-plane frames with 255 minimal sections
    for flow in (0x2010, 0x2011):
        c.cplane(flow, DL, ST1, st_hdr(ST1) +
                 b''.join(csec(ST1, sid=s, start=0, num=1, numsym=14, beam=1) for s in range(255)),
                 nsec=255, frame=4)
    for k in range(2):
        c.uplane(0x2011, DL, [usec(s, 0, 1, [], hdr=(1, MOD_SREM), masks=(0, 0)) for s in range(255)],
                 frame=4)
    return c


def malformed_capture():
    c = Cap()
    # SE 5 in an ST6 section (not allowed there: warning).  ST6 has no section
    # reMask, so the SE 5 reMask checks must not read an uninitialised value.
    c.cplane(0x2001, DL, ST1, st_hdr(ST1) + csec(ST1, sid=1, start=0, num=1, remask=0x5a5, beam=3),
             frame=1)
    se5 = Bits().u(0xfff, 12).u(0, 1).u(0x0800, 15).u(0, 20)
    c.cplane(0x2001, DL, ST6, st_hdr(ST6, ci=(2, BFP, 0), num_ues=1) +
             st6_sec(1001, 0, 1, 2, BFP, 0, ext_list=((5, se5),)), nsec=1, frame=1, slot=1)
    # SE 5 in an ST1 section with reMask 0x0f0: the first set has REs outside the
    # section reMask, the second repeats REs of the first
    b = Bits()
    for m, csf, off in ((0xff0, 1, 0x0c00), (0x0f0, 0, 0x1200)):
        b.u(m, 12).u(csf, 1).u(off, 15)
    c.cplane(0x2001, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=3, start=0, num=1, remask=0x0f0, beam=3, ext_bytes=exts((5, b.align(), 3))),
             frame=1, slot=2)
    return c


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    fixes_capture().write(os.path.join(out, 'oran-fixes-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'oran-fixes-malformed.pcap'))
