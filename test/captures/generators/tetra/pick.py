#!/usr/bin/env python3
# Helper module for the tetra capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Choose the frames of the main capture from the candidates.
Usage: pick.py <tshark> <workdir>   (run on the VM)
Prints SELECTED and REJECTED lists for mktetra.py."""
import os
import re
import subprocess
import sys
here = os.path.dirname(os.path.abspath(__file__))
import mktetra
T, W = sys.argv[1], sys.argv[2]
env = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(here, 'cfg'))
enum = re.compile(r': [A-Za-z].*\(\d+\)$')
seen = set()
sel, rej = [], []
for first in range(0, mktetra.NCAND, mktetra.CHUNK):
    subprocess.check_call([sys.executable, os.path.join(here, 'mktetra.py'), W,
                           '--candidates', str(first)])
    p = subprocess.run(['timeout', '-s', 'KILL', '900', T, '-r', W + '/candidates.pcap', '-V'],
                       capture_output=True, text=True, env=env, errors='replace')
    frames = re.split(r'^Frame (\d+):', p.stdout, flags=re.M)
    for j in range(1, len(frames), 2):
        n = int(frames[j]) - 1 + first
        body = frames[j + 1]
        bad = ('Malformed' in body or '[Expert Info (Error' in body or
               'Dissector bug' in body or '[Expert Info (Warning' in body)
        if bad:
            rej.append(n)
            continue
        keys = set()
        for line in body.splitlines():
            l = line.strip()
            if ':' not in l:
                continue
            keys.add(l.split(':')[0])
            if enum.search(l):
                keys.add(l)
        if keys - seen:
            seen |= keys
            sel.append(n)
print('# candidates', mktetra.NCAND, 'selected', len(sel),
      'bad', len(rej), 'keys', len(seen), file=sys.stderr)
print('SELECTED =', sel)
print('REJECTED =', rej[:60])
