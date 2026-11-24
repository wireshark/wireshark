#!/usr/bin/env python3
# Generates test/captures/rua_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the RUA coverage captures: python3 mkrua.py <outdir>

Needs asn1tools (ASN1TOOLS_PATH, ./pylib or the shared pylib of the batch) and
the Wireshark tree (WS_TREE) for the ASN.1 files.  Random values of every RUA
procedure are made with the generator of asnlib.py; the RANAP-Message IE
carries a random RANAP PDU from the RANAP ASN.1 (every procedure).  tshark
(TSHARK) is run over them and the frames that decode without a malformed packet
or error expert info go to the main capture, the others to the malformed
capture."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import random
import re
import subprocess

import asnlib
from capio import Cap, Sctp

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
HERE = os.path.dirname(os.path.abspath(__file__))
TSHARK = os.environ.get('TSHARK', os.environ.get('TSHARK', 'tshark'))
NVAR = int(os.environ.get('NVAR', '40'))
PPID = 19
PORT = 29169
RANAP = []


def digits(r, n):
    return [r.randint(0, 9) for _ in range(n)]


def h_plmn(g, t, depth):
    d = digits(g.r, 6)
    mnc3 = d[5] if g.r.random() < 0.5 else 0xf
    return bytes([d[1] << 4 | d[0], mnc3 << 4 | d[2], d[4] << 4 | d[3]])


def h_ranap(g, t, depth):
    return g.r.choice(RANAP)


def bad_frames(path, *opts):
    r = subprocess.run([TSHARK, '-r', path, *opts, '-Y', '_ws.malformed || _ws.expert.severity >= 0x00800000',
                        '-T', 'fields', '-e', 'frame.number'], capture_output=True, text=True,
                       env=dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE, 'cfg')))
    bad = set(int(x) for x in r.stdout.split())
    bad |= set(int(x) for x in re.findall(r'Dissector bug, protocol \w+, in packet (\d+)', r.stderr))
    return bad


def ranap_pdus(g, procs):
    """Small RANAP PDUs of every procedure whose RUA DirectTransfer frame decodes without error."""
    cod, sets, rprocs = asnlib.compile_spec('ranap', 'per')
    rg = asnlib.Gen(cod, random.Random(77), sets, rprocs, {'PLMNidentity': h_plmn, 'pLMNidentity': h_plmn})
    cand = []
    for p in rprocs:
        for which in ('init', 'succ', 'unsucc', 'outcome'):
            if not p[which]:
                continue
            for k in range(4):
                rg.popt = [0.0, 0.3, 0.7, 1.0][k]
                try:
                    cand.append(bytes(rg.pdu(p, which)))
                except RecursionError:
                    pass
    cand = [d for d in cand if len(d) < 400]
    dt = [p for p in procs if p['init'] == 'DirectTransfer'][0]
    c = Cap()
    sc = Sctp(50000, PORT)
    g.popt = 0.0
    for d in cand:
        RANAP[:] = [d]
        c.eth(sc.data(bytes(g.pdu(dt, 'init')), ppid=PPID))
    c.write(os.path.join(OUT, 'cand0.pcapng'))
    bad = bad_frames(os.path.join(OUT, 'cand0.pcapng'))
    os.remove(os.path.join(OUT, 'cand0.pcapng'))
    return [d for i, d in enumerate(cand, 1) if i not in bad]


def main():
    os.makedirs(OUT, exist_ok=True)
    cod, sets, procs = asnlib.compile_spec('rua', 'per')
    g = asnlib.Gen(cod, random.Random(20261111), sets, procs, {'RANAP-Message': h_ranap})
    good = ranap_pdus(g, procs)
    print(len(good), 'RANAP PDUs usable')
    RANAP[:] = good
    cand = []
    for p in procs:
        for which in ('init', 'succ', 'unsucc'):
            if not p[which]:
                continue
            for k in range(NVAR):
                g.popt = [0.0, 0.3, 0.6, 0.9, 1.0, 0.5][k % 6]
                try:
                    cand.append((p[which], bytes(g.pdu(p, which))))
                except RecursionError:
                    pass
    # the IntraDomainNasNodeSelector of Connect has many nested alternatives: more Connect PDUs with every optional IE
    conn = [p for p in procs if p['init'] == 'Connect'][0]
    for k in range(70):
        g.popt = 1.0
        cand.append(('Connect', bytes(g.pdu(conn, 'init'))))
    # RUA has only initiating messages; the PDU CHOICE still has the outcome alternatives, which reach the
    # (empty) outcome dissector tables
    for code in (1, 2, 3, 4, 5, 6):
        for alt in ('successfulOutcome', 'unsuccessfulOutcome'):
            for crit in ('reject', 'ignore'):
                cand.append(('outcome', bytes(g.c.types['PDU'].encode((alt, {'procedureCode': code, 'criticality': crit,
                                                                              'value': b'\x00\x01'})))))
    c = Cap()
    sc = Sctp(40000, PORT)
    for i, d in enumerate(cand):
        c.eth(sc.data(d[1], up=(i % 2 == 0), ppid=PPID))
    c.write(os.path.join(OUT, 'cand.pcapng'))
    bad = bad_frames(os.path.join(OUT, 'cand.pcapng'))
    os.remove(os.path.join(OUT, 'cand.pcapng'))
    clean = [x for i, x in enumerate(cand, 1) if i not in bad]
    badl = [x for i, x in enumerate(cand, 1) if i in bad]
    print(len(cand), 'candidates', len(bad), 'bad')
    main_c, mal = Cap(), Cap()
    layout = []
    sc = Sctp(40000, PORT)
    for i, (_, d) in enumerate(clean):
        main_c.eth(sc.data(d, up=(i % 2 == 0), ppid=PPID))
    layout.append(('SCTP PPI 19', len(main_c.fr)))
    n0 = len(main_c.fr)
    sc = Sctp(40001, PORT)       # SCTP port 29169, PPID 0
    for i, (_, d) in enumerate(clean[::5]):
        main_c.eth(sc.data(d, up=(i % 2 == 0), ppid=0))
    layout.append(('SCTP port 29169', len(main_c.fr) - n0))
    main_c.write(os.path.join(OUT, 'rua-coverage.pcapng'))
    sc = Sctp(40000, PORT)
    for i, (_, d) in enumerate(badl):
        mal.eth(sc.data(d, up=(i % 2 == 0), ppid=PPID))
    for i, (_, d) in enumerate(clean[::7]):
        cut = max(2, (len(d) * (1 + i % 7)) // 8)
        mal.eth(sc.data(d[:cut], up=True, ppid=PPID))
    mal.write(os.path.join(OUT, 'rua-coverage-malformed.pcapng'))
    print(' / '.join('%s: %d' % x for x in layout))


main()
