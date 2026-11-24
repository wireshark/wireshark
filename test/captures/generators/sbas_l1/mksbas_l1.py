#!/usr/bin/env python3
# Generates test/captures/sbas_l1_coverage.ems.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SBAS L1 coverage captures: mksbas_l1.py <outdir> [-v].  All data is synthetic.

SBAS L1 navigation messages (ICAO Annex 10) are reached through the EMS file
format (EGNOS Message Server text files, read by wiretap/ems.c, dissected by
packet-egnos-ems.c, which hands the decoded octets to the "ems.svc_flag" table:
"L1" goes to SBAS L1).  Every message is built bit by bit with a valid
preamble and CRC-24Q; the data bits are pseudo random (fixed seed) except for the
fields that select a branch (IGP band, block, velocity code)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
from emslib import l1, l1_line, put, rnd_bits, write_lines

T = (24, 3, 15, 12, 0)

def main(out, verbose=False):
    rng = random.Random(1327)
    lines = []
    marks = []
    sec = [0]
    def add(mt, data=None, preamble=0x53, badcrc=False, prn=123, mt_col=None, mark=None):
        if mark:
            marks.append((len(lines) + 1, mark))
        if data is None:
            data = rnd_bits(rng, 212)
        lines.append(l1_line(prn, T + (sec[0] % 60,), mt if mt_col is None else mt_col, l1(mt, data, preamble, badcrc)))
        sec[0] += 1
    pre = (0x53, 0x9a, 0xc6)
    # every message type 0-63 with random data; the preamble cycles through the three values
    for mt in range(64):
        add(mt, preamble=pre[mt % 3], prn=120 + mt % 39,
            mark='All 64 message types with pseudo random data (MT 0 is flagged "Do Not Use"); the dissected types are 0-7, 9, 10, 12, 17, 18, 24-28 and 63' if mt == 0 else None)
    # MT 18: every IGP band ID 0-10 (and the reserved 11-15)
    for band in range(16):
        d = rnd_bits(rng, 212)
        d = put(d, 0, format(band + 1 if band < 10 else 5, '04b'))
        d = put(d, 4, format(band, '04b'))
        add(18, d, mark='MT 18 with every IGP band ID 0-15 (the dissector shows the IGP masks of bands 0-10)' if band == 0 else None)
    # MT 24 and 25: velocity code 0 and 1 in each half message
    for v in (0, 1):
        d = rnd_bits(rng, 212)
        d = put(d, 106, str(v))
        add(24, d, mark='MT 24 and 25 with velocity code 0 and 1 (first and second half message of MT 25)' if v == 0 else None)
    for v1 in (0, 1):
        for v2 in (0, 1):
            d = rnd_bits(rng, 212)
            d = put(d, 0, str(v1))
            d = put(d, 106, str(v2))
            add(25, d)
    # MT 26: IGP band ID and block ID in and out of range
    for band, block in ((0, 0), (3, 7), (10, 13), (11, 5), (15, 14), (5, 15), (12, 15)):
        d = rnd_bits(rng, 212)
        d = put(d, 0, format(band, '04b'))
        d = put(d, 4, format(block, '04b'))
        add(26, d, mark='MT 26 with IGP band and block IDs in and out of range (Invalid IGP Band/Block Identifier warnings)' if (band, block) == (0, 0) else None)
    # MT 17: three PRNs with chosen numbers
    for _ in range(3):
        add(17, mark='MT 17, MT 1, MT 2-5, MT 6, MT 7, MT 9, MT 10, MT 12, MT 27, MT 28 and MT 63 with all-ones, all-zero and alternating data' if _ == 0 else None)
    for mt in (1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 17, 18, 24, 25, 26, 27, 28, 63):
        for fill in ('0', '1', '10'):
            d = (fill * 212)[:212]
            if mt == 18:
                d = put(d, 4, '0000')
            add(mt, d, prn=130)
    # single digit and two digit MT columns are both used above
    main_n = len(lines)

    mal = []
    t2 = (24, 3, 15, 13, 0)
    for i, (mt, kw) in enumerate(((1, dict(preamble=0x00)), (2, dict(badcrc=True)), (63, dict(preamble=0xff, badcrc=True)))):
        mal.append(l1_line(123, t2 + (i,), mt, l1(mt, rnd_bits(rng, 212), **kw)))
    mal.append(l1_line(123, t2 + (3,), 18, l1(18, put(rnd_bits(rng, 212), 4, '1111'))))
    write_lines(os.path.join(out, 'sbas_l1-coverage.ems'), lines)
    write_lines(os.path.join(out, 'sbas_l1-coverage-malformed.ems'), mal)
    if verbose:
        for n, tx in marks:
            print(n, tx)
        print(main_n, 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
