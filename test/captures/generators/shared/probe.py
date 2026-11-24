# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Find payloads for the hand-off octet strings that dissect cleanly.
usage: probe.py <name> <rounds> <variants> : updates pool_<name>.json"""
import os
HERE = os.path.dirname(os.path.abspath(__file__))
import sys
import random
import json
import subprocess
import asngen
import capio
name = sys.argv[1]; rounds = int(sys.argv[2]); K = int(sys.argv[3])
ONLY = sys.argv[4].split(',') if len(sys.argv) > 4 else None
cfg = __import__('cfg_' + name)
s = asngen.Spec(name, cfg.PREFIX)
D = os.path.join(HERE, '%s-coverage') % name
pool = {}
try:
    pool = {k: [cfg.dec(x) for x in v] for k, v in json.load(open(D + 'pool_%s.json' % name)).items()}
except Exception:
    pass
stats = {}
SCEN = getattr(cfg, 'SCENARIOS', [None])
CAP = 12
for rnd in range(rounds):
  for scen in SCEN:
    frames = []
    pre = []
    sport = 40000 + rnd
    if scen:
        def gf(rng):
            return cfg.make_gen(s, rng)
        pre = cfg.prelude(s, scen, gf)
    for pname, imsg, sout, uout, code, crit in s.procs:
        for kind, msg in ((0, imsg), (1, sout), (2, uout)):
            if not msg or (os.environ.get('MSGS') and msg not in os.environ['MSGS'].split(',')):
                continue
            for v in range(K):
                rng = random.Random('probe/%s/%s/%d/%d' % (scen, msg, rnd, v))
                g = cfg.make_gen(s, rng, list_max=1)
                g.mode = 'probe'; g.used = []; g.ambig = False; g.scen = scen; g.pool = pool
                if ONLY:
                    g.only = ONLY[v % len(ONLY)]
                try:
                    body = g.gen_encode(msg)
                except Exception as e:
                    continue
                if g.ambig or len(g.used) != 1 or (ONLY and g.used[0][0] != g.only):
                    continue
                if code == 17 and scen and msg.startswith('XnSetup'):
                    continue      # would change the node types
                frames.append((g.used[0], capio.pdu(kind, code, crit, body)))
    A, B = '192.0.2.1', '192.0.2.2'
    pk = []
    tsn = 1
    for rev, kind, code, crit, body in pre:
        pk.append(capio.eth(capio.ipv4(capio.sctp_packet([capio.data_chunk(capio.pdu(kind, code, crit, body), tsn, cfg.PPID)], sport, cfg.PORT, 0x1234), *( (B, A) if rev else (A, B)))))
        tsn += 1
    for i, (u, p) in enumerate(frames):
        pk.append(capio.eth(capio.ipv4(capio.sctp_packet([capio.data_chunk(p, tsn + i, cfg.PPID)], sport, cfg.PORT, 0x1234), A, B)))
    fn = D + 'probe.pcap'
    capio.write_pcap(fn, pk)
    env = dict(os.environ, WIRESHARK_CONFIG_DIR=D + 'cfg')
    out = subprocess.run(['timeout', '-s', 'KILL', '300', os.environ.get('TSHARK', 'tshark'), '-r', fn, '-T', 'fields', '-e', 'frame.number', '-e', '_ws.malformed', '-e', '_ws.expert.severity'], capture_output=True, text=True, env=env).stdout
    bad = set()
    for l in out.splitlines():
        f = l.split('\t')
        if len(f) > 1 and (f[1] or '8388608' in l or '6291456' in l or '4194304' in l):
            bad.add(int(f[0]))
    for i, (u, p) in enumerate(frames):
        key, val = u
        if scen:
            key = key + '@' + scen
        st = stats.setdefault(key, [0, 0])
        if (i + 1 + len(pre)) in bad:
            st[1] += 1
        else:
            st[0] += 1
            if len(pool.setdefault(key, [])) < CAP and val not in pool[key]:
                pool[key].append(val)
    print('round', rnd, scen, 'frames', len(frames), 'bad', len(bad), file=sys.stderr, flush=True)
for k in sorted(stats):
    print('%-60s good %3d bad %3d pool %d' % (k, stats[k][0], stats[k][1], len(pool.get(k, []))))
json.dump({k: [cfg.enc(x) for x in v] for k, v in pool.items()}, open(D + 'pool_%s.json' % name, 'w'), indent=0)
