#!/usr/bin/env python3
# Helper module for the ansi_map capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Random ANSI-MAP parameter sets (synthetic) for each opcode, invoke and result.
Usage: ansi_map_fuzz_gen.py <out.pcap> <seed>"""
import sys
import random
import os
import importlib.util
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("g", os.path.join(here, "ansi_map_gen.py"))
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
out, seed = sys.argv[1], int(sys.argv[2])
r = random.Random(seed)
frames = []
tid = 0
for rnd in range(4):
    for op in range(1, 113):
        for _ in range(3):
            params = b''
            for _ in range(r.randint(1, 12)):
                t = r.randint(0, 400)
                ln = r.choice([0, 1, 2, 3, 4, 5, 8, 16, r.randint(0, 40)])
                params += g.tlv(g.CTX, 0, t, bytes(r.randrange(256) for _ in range(ln)))
            tid += 1
            t4 = tid.to_bytes(4, 'big')
            frames.append(g.exp_pdu(g.package(2, t4, [g.invoke(1, op, params)])))
            frames.append(g.exp_pdu(g.package(4, t4, [g.return_result(1, params)])))
g.write_pcap(out, frames)
