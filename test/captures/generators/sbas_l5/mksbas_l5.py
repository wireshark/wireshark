#!/usr/bin/env python3
# Generates test/captures/sbas_l5_coverage.ems.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SBAS L5 coverage captures: mksbas_l5.py <outdir> [-v].  All data is synthetic.

SBAS L5 navigation messages are reached through the EMS file format (EGNOS
Message Server text files, read by wiretap/ems.c, dissected by
packet-egnos-ems.c, which hands the decoded octets to the "ems.svc_flag" table:
"L5" goes to SBAS L5).  Every message is built bit by bit with a valid
preamble and CRC-24Q; the data bits are pseudo random (fixed seed)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
from emslib import l5, l5_line, rnd_bits, write_lines

T = (24, 3, 15, 12, 0)

def main(out, verbose=False):
    rng = random.Random(1328)
    lines = []
    marks = []
    n = [0]
    def add(mt, data=None, preamble=0x5, badcrc=False, prn=123, mark=None, flag='L5', nbits=250):
        if mark:
            marks.append((len(lines) + 1, mark))
        if data is None:
            data = rnd_bits(rng, 216)
        lines.append(l5_line(prn, T + (n[0] % 60,), 100000 * (n[0] % 10), flag, nbits, mt, l5(mt, data, preamble, badcrc)))
        n[0] += 1
    pre = (0x5, 0xc, 0x6, 0x9, 0x3, 0xa)
    for mt in range(64):
        add(mt, preamble=pre[mt % 6], prn=120 + mt % 39,
            mark='All 64 message types with pseudo random data and the six preamble values (MT 0 is flagged "Do Not Use"); MT 0, 31 and 63 have a dissector, the others are shown as data' if mt == 0 else None)
    for mt in (0, 31, 63):
        for fill in ('0', '1', '10', '01'):
            add(mt, (fill * 216)[:216], preamble=0x5,
                mark='MT 0, 31 and 63 with all-zero, all-ones and alternating data' if (mt, fill) == (0, '0') else None)
    for prn in (120, 138, 158):
        add(31, prn=prn, mark='MT 31 for several PRNs' if prn == 120 else None)
    main_n = len(lines)

    mal = []
    t2 = (24, 3, 15, 13, 0)
    mal.append(l5_line(123, t2 + (0,), 0, 'L5', 250, 31, l5(31, rnd_bits(rng, 216), preamble=0x0)))
    mal.append(l5_line(123, t2 + (1,), 0, 'L5', 250, 63, l5(63, rnd_bits(rng, 216), badcrc=True)))
    mal.append(l5_line(123, t2 + (2,), 0, 'L5', 250, 0, l5(0, rnd_bits(rng, 216), preamble=0xf, badcrc=True)))
    mal.append(l5_line(123, t2 + (3,), 0, 'L5', 64, 31, '00' * 8))
    write_lines(os.path.join(out, 'sbas_l5-coverage.ems'), lines)
    write_lines(os.path.join(out, 'sbas_l5-coverage-malformed.ems'), mal)
    if verbose:
        for k, tx in marks:
            print(k, tx)
        print(main_n, 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
