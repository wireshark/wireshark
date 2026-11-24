#!/usr/bin/env python3
# Helper module for the umts_fp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Pick seeds for the FP-over-UDP flows: builds cand.pcapng with every flow generator
x many seeds (one UDP flow each), dissects it and writes seeds.json with, per
flow, the first seeds whose whole flow decodes without a malformed packet or an
error expert info and whose frames are all FP/MAC/RLC/RRC.  Run on the VM."""
import os
HERE = os.path.dirname(os.path.abspath(__file__))
import sys
import json
import subprocess
from fplib import eth_udp, struct
import flows

TSHARK = os.environ.get('TSHARK', 'tshark')
here = os.path.dirname(os.path.abspath(__file__))
N = int(sys.argv[1]) if len(sys.argv) > 1 else 40
only = sys.argv[2].split(',') if len(sys.argv) > 2 else list(flows.FLOWS)
recs, owner = [], []
n = 0
for name in only:
    for seed in range(N):
        n += 1
        ip = lambda k: '10.%d.%d.%d' % (n >> 8, 1 + (n & 127), k)
        for payload, rev in flows.FLOWS[name](seed):
            if rev:
                fr = eth_udp(ip(2), ip(1), 40000, 40000 + n, payload)
            else:
                fr = eth_udp(ip(1), ip(2), 40000 + n, 40000, payload)
            recs.append((1, fr))
            owner.append((name, seed))
# write as a pcapng with the Ethernet IDB (second interface index 1)
def block(btype, body):
    body += b'\0' * (-len(body) % 4)
    k = 12 + len(body)
    return struct.pack('<II', btype, k) + body + struct.pack('<I', k)
f = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)) + block(1, struct.pack('<HHI', 1, 0, 262144))
for i, (_, d) in enumerate(recs):
    f += block(6, struct.pack('<IIIII', 0, 0, i, len(d), len(d)) + d)
open(os.path.join(here, 'cand.pcapng'), 'wb').write(f)
env = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(here, 'cfg'))
def run(extra):
    return subprocess.run(['timeout', '-s', 'KILL', '600', TSHARK, '-r', os.path.join(here, 'cand.pcapng'), '--enable-heuristic', 'fp_udp'] + extra +
                    ['-T', 'fields', '-e', 'frame.number', '-e', '_ws.col.protocol', '-e', '_ws.malformed', '-e', '_ws.expert.severity',
                     '-e', '_ws.col.info'],
                   capture_output=True, text=True, env=env).stdout.splitlines()
p1, p2 = run([]), run(['-2'])
res = {}
for l1, l2 in zip(p1, p2):
    p = l1.split('\t')
    fn = int(p[0]); name, seed = owner[fn - 1]
    q = l2.split('\t')
    bad = bool(p[2]) or any(int(x, 0) >= 0x00800000 for x in p[3].split(',') if x)
    bad2 = bool(q[2]) or any(int(x, 0) >= 0x00800000 for x in q[3].split(',') if x)
    fpok = p[1].split(',')[0] != 'UDP' and p[1] != 'UDP'
    st = res.setdefault((name, seed), [True, True, [], True])
    st[0] &= not bad
    if name not in flows.ONEPASS:
        st[0] &= (not bad2) and (l1 == l2)
        if len(st[2]) == 0:
            st[3] = fpok            # the first datagram must be framed by itself
    st[1] = fpok
    st[2].append(p[1] + ' ' + p[4][:50])
seeds = {}
for (name, seed), (ok, fpok, info, first) in sorted(res.items()):
    if ok and fpok and first:
        seeds.setdefault(name, []).append(seed)
sf = os.path.join(here, 'seeds.json')
old = json.load(open(sf)) if os.path.exists(sf) else {}
for k in only:
    old[k] = seeds.get(k, [])
json.dump(old, open(sf, 'w'))
for name in only:
    print(name, seeds.get(name, [])[:12], 'of', N)
if '-v' in sys.argv:
    for k, v in res.items():
        print(k, v)
