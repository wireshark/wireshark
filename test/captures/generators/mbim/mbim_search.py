#!/usr/bin/env python3
# Helper module for the mbim capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Search information buffers for MBIM (service UUID, CID, message kind):
for each combination generate random structured candidates (little endian
words: small counts and enums, offsets into a data area, sizes), dissect
them all with tshark and keep, per combination, the candidate that decodes
without malformed packets or error/warning expert infos and has the most
tree lines. Writes mbim_chosen.json (hex strings).

Usage: mbim_search.py <workdir> <tshark> <rounds> <candidates per round> [<tag> [tshark options]]
(tag and options: search with preferences, e.g. ex4 -o mbim.extended_version:4.0;
the result is mbim_chosen_<tag>.json)
It runs tshark (TSHARK)."""
import sys
import os
import json
import struct
import random
import subprocess
import re
from mbimlib import CIDS, command, command_done, indicate, pcap, service_uuids

work, tshark, rounds, K = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
tag = sys.argv[5] if len(sys.argv) > 5 else ''
opts = sys.argv[6:]
chosen_fn = os.path.join(work, 'mbim_chosen%s.json' % ('_' + tag if tag else ''))
rnd = random.Random(28)
env = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(work, 'cfg'))
os.makedirs(os.path.join(work, 'cfg'), exist_ok=True)
uuids = service_uuids()
KINDS = ['query', 'set', 'done_q', 'done_s', 'ind']

def data_area(n):
    r = rnd.random()
    if r < 0.5:      # UTF-16LE text
        s = ''.join(rnd.choice('0123456789abcdefABCDEF+.:') for _ in range(n // 2))
        return s.encode('utf-16-le')
    if r < 0.75:     # small numbers
        return b''.join(struct.pack('<I', rnd.randrange(0, 6)) for _ in range(n // 4 + 1))[:n]
    return bytes(rnd.getrandbits(8) for _ in range(n))

def zero_based():
    n = rnd.choice([4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 128, 160, 192, 256, 320, 384, 512])
    b = bytearray(n)
    for _ in range(rnd.choice([0, 0, 1, 1, 2, 3, 5])):
        p = rnd.randrange(0, n // 4) * 4
        b[p:p + 4] = struct.pack('<I', rnd.choice([1, 1, 2, 3, 4, 0x10, n // 2, n - 8 if n > 8 else 0]))
    if rnd.random() < 0.3 and n >= 16:
        # an element: offset/size pair pointing at a short string
        p = rnd.randrange(0, n // 8) * 8
        off = rnd.randrange(n // 2 // 4, n // 4) * 4
        b[p:p + 8] = struct.pack('<II', off, min(8, n - off))
        for i in range(off, min(n, off + 8)):
            b[i] = 0x31 if i % 2 == 0 else 0
    return bytes(b)

def candidate():
    if rnd.random() < 0.5:
        return zero_based()
    W = rnd.choice([1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24, 32])
    D = rnd.choice([0, 16, 32, 64, 128, 256])
    total = W * 4 + D
    words = []
    for i in range(W):
        r = rnd.random()
        if r < 0.35:
            words.append(rnd.choice([0, 1, 1, 1, 2, 2, 3, 4]))
        elif r < 0.65 and D:
            words.append(W * 4 + 4 * rnd.randrange(0, D // 4))
        elif r < 0.9:
            words.append(rnd.choice([2, 4, 6, 8, 10, 12, 16, 20, 32, 4, 4]))
        else:
            words.append(rnd.choice([0xffffffff, 0x100, 5, 6, 7, 8, 9, 10]))
    # pair up offsets with plausible sizes: make some words (offset, size) pairs
    buf = b''.join(struct.pack('<I', w) for w in words) + data_area(D)
    if rnd.random() < 0.15:
        buf = buf[:rnd.randrange(0, len(buf) + 1)]
    return buf

def frames_for(kind, ui, cid, buf, tid):
    u = uuids[ui]
    if kind == 'query':
        return [command(tid, u, cid, 0, buf)]
    if kind == 'set':
        return [command(tid, u, cid, 1, buf)]
    if kind == 'done_q':
        return [command(tid, u, cid, 0, b''), command_done(tid, u, cid, buf)]
    if kind == 'done_s':
        return [command(tid, u, cid, 1, b''), command_done(tid, u, cid, buf)]
    return [indicate(tid, u, cid, buf)]

def run(cands):
    """cands: list of (ui, cid, kind, buf). Returns list of (clean, lines) per candidate."""
    pk, idx = [], []
    for n, (ui, cid, kind, buf) in enumerate(cands):
        fr = frames_for(kind, ui, cid, buf, n + 1)
        pk += fr
        idx.append(len(pk))          # 1-based frame number of the last frame of this candidate
    fn = os.path.join(work, 'search.pcap')
    pcap(fn, pk)
    res = {}
    out = subprocess.run([tshark, *opts, '-r', fn, '-T', 'fields', '-e', 'frame.number', '-e', '_ws.malformed',
                          '-e', '_ws.expert.severity'], env=env, capture_output=True, text=True, timeout=1500).stdout
    bad = set()
    for l in out.splitlines():
        p = l.split('\t')
        if len(p) > 1 and (p[1] or (len(p) > 2 and p[2])):
            bad.add(int(p[0]))
    lines = {}
    proc = subprocess.run([tshark, *opts, '-r', fn, '-V', '-Y', '!_ws.malformed && !_ws.expert'], env=env,
                          capture_output=True, text=True, timeout=3000)
    cur = None
    for l in proc.stdout.splitlines():
        m = re.match(r'^Frame (\d+):', l)
        if m:
            cur = int(m.group(1)); lines[cur] = 0
        elif cur is not None:
            lines[cur] += 1
    return [((last not in bad), lines.get(last, 0)) for last in idx]

# stage 0: which (uuid, cid) are known
probe = [(ui, cid, 'query', b'') for ui in range(len(uuids)) for cid in CIDS]
pk = [frames_for('query', ui, cid, b'', n + 1)[0] for n, (ui, cid, _, _) in enumerate(probe)]
fn0 = os.path.join(work, 'probe.pcap'); pcap(fn0, pk)
out = subprocess.run([tshark, *opts, '-r', fn0, '-V'], env=env, capture_output=True, text=True, timeout=1500).stdout
known, cur = set(), None
for l in out.splitlines():
    m = re.match(r'^Frame (\d+):', l)
    if m:
        cur = int(m.group(1)) - 1
    elif cur is not None and re.match(r'\s+CID: ', l) and 'Unknown' not in l:
        known.add(probe[cur][:2])
print(len(known), 'known (uuid, cid) pairs', flush=True)

best = {}   # (ui, cid, kind) -> (score, buf)
try:
    best = {tuple(json.loads(k)): (v[0], bytes.fromhex(v[1])) for k, v in json.load(open(chosen_fn)).items()}
except Exception:
    pass
for rd in range(rounds):
    cands = []
    for (ui, cid) in sorted(known):
        for kind in KINDS:
            cands.append((ui, cid, kind, b''))
            for _ in range(K):
                if rd > 0 and (ui, cid, kind) in best and rnd.random() < 0.5:
                    b = bytearray(best[(ui, cid, kind)][1])
                    for _ in range(rnd.randrange(1, 4)):
                        if len(b) >= 4:
                            p = rnd.randrange(0, len(b) // 4) * 4
                            b[p:p + 4] = struct.pack('<I', rnd.choice([0, 1, 2, 3, 4, 8, 16, 32, len(b), rnd.getrandbits(8)]))
                    cands.append((ui, cid, kind, bytes(b)))
                else:
                    cands.append((ui, cid, kind, candidate()))
    print('round', rd, len(cands), 'candidates', flush=True)
    res = run(cands)
    for (ui, cid, kind, buf), (ok, nl) in zip(cands, res):
        if ok and nl > best.get((ui, cid, kind), (-1, b''))[0]:
            best[(ui, cid, kind)] = (nl, buf)
    json.dump({json.dumps(list(k)): [v[0], v[1].hex()] for k, v in best.items()},
              open(chosen_fn, 'w'))
    print('chosen', len(best), 'total lines', sum(v[0] for v in best.values()), flush=True)
