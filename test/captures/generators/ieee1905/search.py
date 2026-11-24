#!/usr/bin/env python3
# Helper module for the ieee1905 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
HERE = os.path.dirname(os.path.abspath(__file__))
# Search tool (run on the VM): for each TLV type try random bodies at every
# declared length, keep frames that dissect cleanly (TLV + EOM, no
# malformed, no expert), then greedily pick a small set covering most
# distinct fields/values. Writes selected.json {type: [hexbody,...]}.
import struct
import random
import subprocess
import json
import sys
import collections
TSHARK = os.environ.get('TSHARK', 'tshark')
random.seed(int(sys.argv[2]) if len(sys.argv) > 2 else 1905)
TYPES = [int(x) for x in sys.argv[1].split(',')] if len(sys.argv) > 1 and sys.argv[1] != 'all' else None
ALL = [1,2,3,4,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30] + list(range(128,208)) + [209,210,211,212,213,214,215,216,217,218,219,220,221,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237]
if TYPES is None: TYPES = ALL
eth = bytes.fromhex('0180c2000013' '020000000001') + struct.pack('>H', 0x893a)
def pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)
def rbody(n, mode):
    if mode == 0:
        pool = [0, 1, 2, 3]
    elif mode == 1:
        pool = [0, 1, 2, 0xff, 0x80, 0x40, 5, 6]
    else:
        pool = None
    return bytes((random.choice(pool) if pool and random.random() < 0.85 else random.getrandbits(8)) for _ in range(n))
frames = []; meta = []
for t in TYPES:
    for k in range(60):
        n = 300 if k < 12 else 70
        body = rbody(n, k % 3)
        for L in range(1, n + 1):
            frames.append(eth + bytes([0, 0, 0, 0, 0, 1, 0, 0x80]) + bytes([t]) + struct.pack('>H', L) + body[:L] + b'\x00\x00\x00')
            meta.append((t, body[:L]))
tmp = os.environ.get('TMPD', os.path.join(HERE))
pc = os.path.join(tmp, 'ieee1905_search_%d.pcap' % os.getpid())
pcap(pc, frames)
print('frames', len(frames), file=sys.stderr)
p = subprocess.Popen([TSHARK, '-r', pc, '-Y', '!_ws.malformed && !_ws.expert && count(ieee1905.tlv_type)==2', '-T', 'ek'],
    stdout=subprocess.PIPE, env=dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE)), text=True)
cands = collections.defaultdict(list)
def flat(d, pre=''):
    for k, v in d.items():
        if isinstance(v, dict): yield from flat(v, pre + k + '.')
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, dict): yield from flat(x, pre + k + '.')
                else: yield (k, str(x))
        else: yield (k, str(v))
for line in p.stdout:
    if not line.startswith('{"timestamp"'): continue
    d = json.loads(line)
    lay = d['layers']
    fn = int(lay['frame']['frame_frame_number'])
    t, body = meta[fn - 1]
    ie = lay.get('ieee1905')
    if not ie: continue
    items = list(flat(ie))
    tt = [v for k, v in items if k == 'ieee1905_ieee1905_tlv_type']
    if not tt or int(tt[0], 0) != t: continue
    cands[t].append((body, items))
p.wait()
os.unlink(pc)
sel = {}
for t, lst in cands.items():
    # value cardinality per key
    vals = collections.defaultdict(set)
    for b, items in lst:
        for k, v in items: vals[k].add(v)
    def sig(items):
        s = set()
        for k, v in items:
            if k.endswith('tlv_type') or k.endswith('tlv_length') or 'tlv_length_' in k: continue
            s.add(k)
            if len(vals[k]) <= 12: s.add((k, v))
        return s
    sigs = [sig(items) for b, items in lst]
    covered = set(); chosen = []
    # prefer shorter bodies on ties
    order = sorted(range(len(lst)), key=lambda i: len(lst[i][0]))
    while True:
        best = None; bg = 0
        for i in order:
            g = len(sigs[i] - covered)
            if g > bg: best, bg = i, g
        if best is None: break
        covered |= sigs[best]; chosen.append(lst[best][0].hex())
    sel[t] = chosen
    print(t, len(lst), len(chosen), len(covered), file=sys.stderr)
json.dump({str(k): v for k, v in sel.items()}, open(sys.argv[3] if len(sys.argv) > 3 else 'selected.json', 'w'))
