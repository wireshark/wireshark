#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Pick RDM messages (greedily, by new decoded field names) from a pool of random candidates.
Run on the VM: selectrdm.py <tshark> <workdir> <seed> > rdm_selected.txt
Output lines: manf cc rt pid pdhex  (decimal manf/cc/rt/pid).
The candidates are Art-Net ArtRdm packets; a candidate that is malformed or has an
expert info of warning or higher is only used in the second round (warnings) or never (errors)."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import random
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from rdmlib import artrdm, eth_udp, rdm_msg, write_pcap

TSHARK, WORK, SEED = sys.argv[1], sys.argv[2], int(sys.argv[3])
SRC = os.path.join(SRCDIR, 'epan/dissectors', '')
pids = sorted(set(int(x, 16) for x in re.findall(r'#define RDM_PARAM_ID_\w+\s+0x([0-9A-Fa-f]+)', open(SRC + 'packet-rdm.c').read())))
etc = sorted(set(int(x, 16) for x in re.findall(r'#define ETC_PARAM_ID_\w+\s+0x([0-9A-Fa-f]+)', open(SRC + 'packet-rdm-etc.c').read())))
rnd = random.Random(SEED)
LENS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 18, 19, 20, 21, 22, 24, 25, 28, 32, 33, 34, 40, 44, 48, 64, 100, 128, 200, 231]

WORDS = [b'Lamp', b'Dimmer 1', b'ETC', b'Label', b'x']

def content(n):
    k = rnd.random()
    if k < 0.1:
        return bytes(rnd.randrange(256) for _ in range(n))
    if k < 0.35:
        w = rnd.choice(WORDS)
        return (w * (n // len(w) + 1))[:n]
    if k < 0.75:
        return bytes(rnd.randrange(4) for _ in range(n))
    return bytes(rnd.choice([0, 1, 2, 0x7f, 0x80, 0xff]) for _ in range(n))

cands = []
for manf, pl in ((0x0001, pids + [0x8000 + i for i in (0, 1, 2, 0x100)]), (0x6574, etc)):
    for pid in pl:
        for cc in (0x10, 0x11, 0x20, 0x21, 0x30, 0x31):
            if cc in (0x10, 0x11) and pid not in (1, 2, 3):
                continue
            rts = [0, 1, 2, 3, 4] if cc & 1 else [0]
            for n in LENS:
                for _ in range(4):
                    cands.append((manf, cc, rnd.choice(rts), pid, content(n)))
rnd.shuffle(cands)

def features(cs):
    """run tshark on candidates; return list of (names, bad, warn)"""
    path = os.path.join(WORK, 'pool.pcap')
    write_pcap(path, [eth_udp(artrdm(rdm_msg((c[0], 1), (c[0], 2), i, c[2], c[1], c[3], c[4]))) for i, c in enumerate(cs)])
    p = subprocess.Popen([TSHARK, '-r', path, '-T', 'pdml'], stdout=subprocess.PIPE)
    out = []
    for ev, el in ET.iterparse(p.stdout, events=('end',)):
        if el.tag != 'packet':
            continue
        names = set(); bad = False; warn = False
        for f in el.iter('field'):
            n = f.get('name', '')
            if n.startswith('rdm'):
                names.add(n)
                sn = f.get('showname', '')
                mm = re.match(r'[^:]*: (.*) \(0x[0-9a-f]+\)$', sn)
                if mm and not re.match(r'^[0-9.,-]+$', mm.group(1)) and len(mm.group(1)) < 40:
                    names.add(n + '=' + mm.group(1))
            elif n == '_ws.malformed':
                bad = True
            elif n == '_ws.expert':
                sev = [x.get('show') for x in f.iter('field') if x.get('name') == '_ws.expert.severity']
                if sev and sev[0] in ('Error', '8388608', '0x00800000'):
                    bad = True
                else:
                    warn = True
        out.append((names, bad, warn))
        el.clear()
    p.wait()
    return out

import pickle
import heapq
PK = os.path.join(WORK, 'feats%d.pkl' % SEED)
if os.path.exists(PK):
    cands, feats = pickle.load(open(PK, 'rb'))
else:
    feats = []
    CH = 6000
    for i in range(0, len(cands), CH):
        feats.extend(features(cands[i:i + CH]))
    pickle.dump((cands, feats), open(PK, 'wb'))
full = []
for c, (names, bad, warn) in zip(cands, feats):
    if os.environ.get('NOLABEL'):
        names = set(x for x in names if '=' not in x)
    names = names | set('%s|%d|%d' % (x, c[3], c[1]) for x in names if '=' not in x) | set('%s|%d' % (x, c[2]) for x in names if x == 'rdm.response_type')
    full.append((names, bad, warn))
seen = set(); chosen = []
for rnd_no in (0, 1):
    # lazy greedy: always the candidate that adds the most new features
    heap = [(-len(n), i) for i, (n, bad, warn) in enumerate(full)
            if not bad and ((warn) == (rnd_no == 1))]
    heapq.heapify(heap)
    while heap:
        negs, i = heapq.heappop(heap)
        gain = len(full[i][0] - seen)
        if gain == 0:
            continue
        if heap and gain < -heap[0][0]:
            heapq.heappush(heap, (-gain, i))
            continue
        seen |= full[i][0]; chosen.append(cands[i])
for c in chosen:
    print(c[0], c[1], c[2], c[3], c[4].hex() or '-')
sys.stderr.write('candidates %d chosen %d features %d\n' % (len(cands), len(chosen), len(seen)))
