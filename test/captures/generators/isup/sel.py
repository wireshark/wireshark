#!/usr/bin/env python3
# Helper module for the isup capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Greedy selection of candidate frames: pick, per parameter type, the clean
# candidates that add new (field, value) pairs.  Usage: sel.py <json> <meta> <out.json>
import sys
import json
import re
class P(list): pass
data = json.load(open(sys.argv[1]), object_pairs_hook=P)
meta = json.load(open(sys.argv[2]))
CAP = int(sys.argv[4]) if len(sys.argv) > 4 else 14
small = re.compile(r'^(0x)?[0-9a-fA-F]{1,2}$|^[A-Za-z][A-Za-z ,\-/()]{0,40}$')
SKIP = {'isup.cic','isup.message_type','isup.parameter_type','isup.parameter_length','isup.parameter_value','isup.optional_parameter_part_pointer'}
def walk(o, pairs, st):
    if isinstance(o, P):
        for k, v in o:
            if k.startswith('Parameter: (t='):
                pairs.add(('P', re.sub(r'l=\d+', 'l=', k)[:60]))
            if k.startswith('_ws.malformed'):
                st['bad'] = True
            if k == '_ws.expert':
                for e in (v if isinstance(v, list) and not isinstance(v, P) else [v]):
                    if isinstance(e, P):
                        e = dict(e)
                        sev = e.get('_ws.expert.severity')
                        if sev in ('8388608', '0x00800000'):
                            st['bad'] = True
                        st.setdefault('exp', set()).add(e.get('_ws.expert.message', ''))
            if isinstance(v, list):
                walk(v, pairs, st)
            elif isinstance(v, str) and k not in SKIP and (k.startswith('isup.') or k.startswith('bicc.') or k.startswith('nsap') or k.startswith('sdp') or k.startswith('q931') or k.startswith('e164') or k.startswith('e212') or k.startswith('gsm') or k.startswith('bat')):
                pairs.add((k, v if small.match(v) else ''))
    elif isinstance(o, list):
        for v in o:
            walk(v, pairs, st)
frames = []
for fr in data:
    pairs = set(); st = {}
    walk(dict(dict(fr)['_source'])['layers'], pairs, st)
    frames.append((pairs, st))
bytype = {}
for i, (t, b) in enumerate(meta):
    bytype.setdefault(t, []).append(i)
chosen = []
report = {}
for t, idxs in bytype.items():
    seen = set()
    good = [i for i in idxs if not frames[i][1].get('bad')]
    report[t] = (len(good), len(idxs))
    n = 0
    while good and n < CAP:
        best = max(good, key=lambda i: len(frames[i][0] - seen))
        gain = frames[best][0] - seen
        if not gain:
            break
        seen |= frames[best][0]
        chosen.append(best); n += 1
        good.remove(best)
json.dump({'chosen': chosen, 'report': report}, open(sys.argv[3], 'w'))
print(len(chosen), 'chosen')
for t in sorted(report):
    print(t, report[t], end='; ')
