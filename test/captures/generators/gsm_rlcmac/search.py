#!/usr/bin/env python3
# Helper module for the gsm_rlcmac capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Random search over RLC/MAC candidates for decoded target fields.
usage: search.py kind mt_list nseeds length out.json   (run on the VM)"""
import json
import os
import subprocess
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
import csn1gen as g
T = os.environ.get('TSHARK', 'tshark')
TARGETS = sys.argv[6].split(',') if len(sys.argv) > 6 else [
    'gsm_rlcmac.cell_parameter', 'gsm_rlcmac.dl.lu_modeonlycellselectionparamswithfreqdiff',
    'gsm_rlcmac.dl.ps_handoverto_utran_payload_rrc_container',
    'gsm_rlcmac.dl.packet_compact_neighbour_cell_param_freq_diff']
kind = sys.argv[1]
mts = [int(x) for x in sys.argv[2].split(',')]
nseeds = int(sys.argv[3]); length = int(sys.argv[4]); out = sys.argv[5]
cands = []
for mt in mts:
    for seed in range(nseeds):
        for p in (0.2, 0.35, 0.5, 0.65):
            cands.append((kind, mt, seed, p, length))
frames = [g.rand_frame(*c) for c in cands]
pc = os.path.join(HERE, 'search.pcapng')
g.write_pcapng(pc, frames)
cmd = [T, '-r', pc, '-Tfields', '-eframe.number', '-e_ws.malformed', '-e_ws.expert.message'] + \
      ['-e' + t for t in TARGETS]
env = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE, 'cfg'))
res = subprocess.run(cmd, capture_output=True, text=True, env=env, errors='replace').stdout
hits = {t: [] for t in TARGETS}
for line in res.splitlines():
    p = line.split('\t')
    n = int(p[0]) - 1
    clean = not p[1] and not p[2]
    for i, t in enumerate(TARGETS):
        if len(p) > 3 + i and p[3 + i]:
            hits[t].append((cands[n], clean))
json.dump(hits, open(out, 'w'))
for t in TARGETS:
    print(t, len(hits[t]), [h for h in hits[t] if h[1]][:3])
