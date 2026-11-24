#!/usr/bin/env python3
# Helper module for the unistim capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Reduce clean.txt (search.py) to the table mkunistim.py uses:
for every (address, command) up to 5 lengths spread over the clean ones,
with the variants that are clean for them.  Usage: select.py clean.txt > unistim_table.txt"""
import sys
from collections import defaultdict
cl = defaultdict(lambda: defaultdict(list))
for l in open(sys.argv[1]):
    a, c, L, v, p = map(int, l.split())
    cl[(a, c)][L].append((v, p))
for (a, c), d in sorted(cl.items()):
    ls = sorted(d)
    if len(ls) <= 5:
        pick = ls
    else:
        pick = sorted({ls[round(i * (len(ls) - 1) / 4)] for i in range(5)})
    for L in pick:
        vs = sorted(d[L])
        # up to 4 variants; the 4 modes of body() are v % 4
        seen, out = set(), []
        for v, p in vs:
            if v % 4 not in seen:
                seen.add(v % 4)
                out.append((v, p))
        for v, p in out:
            print(a, c, L, v, p)
