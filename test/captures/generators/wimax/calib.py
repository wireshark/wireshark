#!/usr/bin/env python3
# Helper module for the wimax capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""TLV calibration (run on the VM): for a management message find which
(TLV path, length) combinations the dissector accepts without malformed /
warn / error and which fields they produce.
usage: calib.py <tshark> <msgtype> <prefixhex> <outjson> [maxdepth] [subtypemax]"""
import os
import sys
import json
import subprocess
import tempfile
from wxlib import eth, gmh, m2m_tlvs, mgmt, MS, T_PDU, tlv, write_pcap

TSHARK, MSG, PREFIX, OUT = sys.argv[1], int(sys.argv[2]), bytes.fromhex(sys.argv[3]), sys.argv[4]
MAXD = int(sys.argv[5]) if len(sys.argv) > 5 else 3
SUBMAX = int(sys.argv[6]) if len(sys.argv) > 6 else 90
HERE = os.path.dirname(os.path.abspath(__file__))
LENS = [1, 2, 3, 4, 5, 6, 8, 12, 16]


def PAT(n, k=0):
    return bytes((((i + 1) * 0x11 + k) & 0xff) or 1 for i in range(n))


def run(payloads):
    frames = [eth(MS, m2m_tlvs([tlv(T_PDU, gmh(1, mgmt(MSG, p)))])) for p in payloads]
    d = tempfile.mkdtemp(dir=os.path.join(HERE))
    f = d + '/c.pcap'
    write_pcap(f, frames)
    env = dict(os.environ, WIRESHARK_CONFIG_DIR=HERE + '/cfg')
    r = subprocess.run(['timeout', '-s', 'KILL', '900', TSHARK, '-r', f, '-T', 'json'],
                       capture_output=True, env=env)
    os.system('rm -rf ' + d)
    pk = json.loads(r.stdout or b'[]')
    res = []
    for p in pk:
        keys = set(); bad = [False]
        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k.startswith('_ws.malformed'):
                        bad[0] = True
                    if k == '_ws.expert.severity':
                        vs = v if isinstance(v, list) else [v]
                        if any(x in ('error', 'warn') for x in vs):
                            bad[0] = True
                    if k.startswith('wmx.') and ' ' not in k:
                        keys.add(k)
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(p['_source']['layers'])
        res.append((bad[0], keys))
    return res


def wrap(path, inner):
    for t in reversed(path):
        inner = tlv(t, inner)
    return inner


out = {}      # path-as-string -> list of [len, hex of full tlv chain, newkeys]
queue = [()]
while queue:
    path = queue.pop(0)
    depth = len(path)
    types = range(0, 256) if depth == 0 else range(0, SUBMAX)
    cands = [(None, None, wrap(path, tlv(254, b'\x01')))]
    for t in types:
        for n in LENS:
            cands.append((t, n, wrap(path, tlv(t, PAT(n, t)))))
    res = run([PREFIX + c[2] for c in cands])
    base = res[0][1]
    solved = {}
    for (t, n, raw), (bad, keys) in zip(cands[1:], res[1:]):
        new = keys - base
        if not bad:
            if new:
                out.setdefault('/'.join(map(str, path + (t,))), []).append([n, (PREFIX + raw).hex(), sorted(new)])
            solved.setdefault(t, True)
        else:
            solved.setdefault(t, False)
            if solved[t] is not True:
                pass
    for t in types:
        if depth + 1 < MAXD and any((not b) and (k - base) for (tt, nn, rr), (b, k) in zip(cands[1:], res[1:]) if tt == t):
            queue.append(path + (t,))
json.dump(out, open(OUT, 'w'))
print(len(out), 'paths with clean decodes')
