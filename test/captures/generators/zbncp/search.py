#!/usr/bin/env python3
# Helper module for the zbncp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
HERE = os.path.dirname(os.path.abspath(__file__))
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
# Helper (not a deliverable): finds, per (call id, packet type), body bytes
# that decode cleanly (no malformed, no expert info, no leftover Data) and
# produce the most tree lines.  Candidates are random bodies of small bytes.
import random
import subprocess
import sys
import re
import json
from zbnlib import frame, IND, LINKTYPE_ZBOSS_NCP, REQ, RSP, write_pcap
H = os.path.join(SRCDIR, 'epan/dissectors/packet-zbncp.h')
ids = []
for l in open(H):
    m = re.match(r'#define ZBNCP_CMD_(\w+)\s+(0x[0-9a-fA-F]+)', l)
    if m:
        ids.append((m.group(1), int(m.group(2), 16)))
seed = int(sys.argv[1]); per = int(sys.argv[2]); out = sys.argv[3]
rnd = random.Random(seed)
cands = []
for name, cid in ids:
    for pt in (REQ, RSP, IND):
        for k in range(per):
            n = rnd.randint(0, 100) if rnd.random() < 0.7 else rnd.choice([0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 16, 18, 20, 24, 28, 32, 40, 48, 64])
            alpha = rnd.choice([[0], [0, 1], [0, 1, 2], [1, 2, 3], [0, 1, 2, 3, 4, 5], list(range(16)), list(range(48)), list(range(256))])
            if len(alpha) == 256 and rnd.random() < 0.7:
                alpha = [0, 1, 2]
            body = bytes(rnd.choice(alpha) for _ in range(n))
            cands.append((name, cid, pt, body))
pc = out + '.pcap'
write_pcap(pc, LINKTYPE_ZBOSS_NCP, [frame(pt, cid, b, tsn=1, cat=0, status=0) for _, cid, pt, b in cands])
env = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE))
p = subprocess.Popen([os.environ.get('TSHARK', 'tshark'), '-r', pc, '-V'], stdout=subprocess.PIPE, text=True, env=env)
chosen = {}
covered = {}
cur = None; labels = set(); bad = False
def flush():
    global cur
    if cur is None: return
    name, cid, pt, body = cands[cur]
    if not bad:
        key = (cid, pt)
        cov = covered.setdefault(key, set())
        if labels - cov:
            cov |= labels
            chosen.setdefault(key, []).append((body.hex(), name))
for l in p.stdout:
    if l.startswith('Frame '):
        flush()
        cur = int(l.split(':')[0].split()[1]) - 1; labels = set(); bad = False
        continue
    if l.startswith('0000') or not l.strip():
        continue
    if 'Malformed' in l or 'Expert Info' in l or l.lstrip().startswith('Data ('):
        bad = True
    if 'ZBNCP' in l: continue
    t = l.strip()
    if t.startswith(('Frame', 'Encapsulation', 'Arrival', 'UTC', 'Epoch', '[Time', 'Capture', '[Frame', '[Protocols', 'Character', 'Packet length', 'CRC', 'Signature', 'Packet flags', 'TSN', 'Version')) or t[:1] in '.0123456789':
        continue
    labels.add(t.split(':')[0])
flush()
res = {'%d,%d' % k: v for k, v in chosen.items()}
json.dump(res, open(out + '.json', 'w'))
print(len(cands), 'candidates', len(chosen), 'combos with frames,', sum(len(v) for v in chosen.values()), 'bodies')
