#!/usr/bin/env python3
# Helper module for the unistim capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Find, for every command of every manager, the (length, variant) pairs
whose single message decodes cleanly (no error expert info, exactly one
message in the packet).  Usage: search.py <tmpdir> <tshark> <maxlen> <nvar>
Writes <tmpdir>/clean.txt: addr cmd length variant (one per line)."""
import os
import subprocess
import sys
from unistimlib import commands, frame, MANAGERS, message, payload, write_pcap

tmp, tshark, maxlen, nvar = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
cmds = commands()
envg = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.dirname(os.path.abspath(__file__)) + '/cfg')
# Requesting every UNISTIM field makes tshark build real tree items (with
# only a few fields the others are faked and length errors do not show).
allf = [l.split('\t')[2] for l in subprocess.run([tshark, '-G', 'fields'], capture_output=True, text=True, env=envg).stdout.split('\n')
        if l.startswith('F\t') and l.split('\t')[2].startswith('unistim.')]
FARGS = []
for f in allf:
    FARGS += ['-e', f]
AI = allf.index('unistim.add')
cand = []
for fn, addrs in MANAGERS.items():
    for a in addrs[:1] if len(addrs) > 1 else addrs:
        for c in sorted(set(cmds[fn]) | {0x70, 0x7e}):
            for L in range(0, maxlen + 1):
                for v in range(nvar):
                    cand.append((addrs[0], c, L, v))
frames = [frame(payload([message(*k)]), 5000, 5001) for k in cand]
write_pcap(os.path.join(tmp, 'cand.pcap'), frames)
env = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.dirname(os.path.abspath(__file__)) + '/cfg')
out = subprocess.run(['timeout', '-s', 'KILL', '900', tshark, '-d', 'udp.port==5000,unistim', '-r', os.path.join(tmp, 'cand.pcap'),
                      '-T', 'fields', '-e', '_ws.expert.message', '-e', '_ws.malformed'] + FARGS,
                     capture_output=True, text=True, env=env).stdout.split('\n')
clean = []
for k, line in zip(cand, out):
    f = line.split('\t')
    adds = f[2 + AI].split(',') if len(f) > 2 + AI and f[2 + AI] else []
    if len(adds) == 1 and not f[0] and not f[1]:
        clean.append(k)
# Can the message be followed by another one?  (Some commands read to the
# end of the packet.)
STD = bytes([0x1a, 4, 0x01, 0x00])
write_pcap(os.path.join(tmp, 'pack.pcap'), [frame(payload([message(*k), STD]), 5000, 5001) for k in clean])
out = subprocess.run(['timeout', '-s', 'KILL', '900', tshark, '-d', 'udp.port==5000,unistim', '-r', os.path.join(tmp, 'pack.pcap'),
                      '-T', 'fields', '-e', '_ws.expert.message', '-e', '_ws.malformed'] + FARGS,
                     capture_output=True, text=True, env=env).stdout.split('\n')
with open(os.path.join(tmp, 'clean.txt'), 'w') as fh:
    for k, line in zip(clean, out):
        f = line.split('\t')
        ok = len(f) > 2 + AI and len(f[2 + AI].split(',')) == 2 and not f[0] and not f[1]
        fh.write('%d %d %d %d %d\n' % (k + (1 if ok else 0,)))
print(len(cand), 'candidates', len(clean), 'clean')
