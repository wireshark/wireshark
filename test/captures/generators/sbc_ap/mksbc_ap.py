#!/usr/bin/env python3
# Generates test/captures/sbc_ap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the SBc-AP coverage captures: python3 mksbc_ap.py <outdir>

Needs asn1tools (ASN1TOOLS_PATH, ./pylib or the shared pylib of the batch) and
the Wireshark tree (WS_TREE) for the ASN.1 files.  Random values of every
SBc-AP procedure are made with the generator of asnlib.py; tshark (TSHARK) is
run over them and the frames that decode without a malformed packet or error
expert info go to the main capture, the others to the malformed capture.  The
warning messages use every data coding scheme and page counts up to 16."""
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
NVAR = int(os.environ.get('NVAR', '10'))
PPID = 24
PORT = 29168
DCS = [0x00, 0x01, 0x10, 0x11, 0x48, 0x44, 0x40, 0x60, 0xf0, 0xf4, 0x20, 0x70]


def digits(r, n):
    return [r.randint(0, 9) for _ in range(n)]


def h_plmn(g, t, depth):
    d = digits(g.r, 6)
    mnc3 = d[5] if g.r.random() < 0.5 else 0xf
    return bytes([d[1] << 4 | d[0], mnc3 << 4 | d[2], d[4] << 4 | d[3]])


def h_dcs(g, t, depth):
    g.dcs = g.force_dcs if g.force_dcs is not None else g.r.choice(DCS)
    return (bytes([g.dcs]), 8)


def h_wmc(g, t, depth):
    if g.wmc_len is not None:
        return bytes([2]) + g.rbytes(82) + bytes([g.wmc_len]) + g.rbytes(83) + bytes([g.wmc_len])
    n = g.r.choice([1, 2, 3, 15, 15, 16, 5])
    out = bytes([n])
    for i in range(min(n, 15)):
        ln = [82, 40, 20, 2, 0, 80][i % 6]
        if g.dcs in (0x48, 0x11):
            ln &= ~1
        out += g.rbytes(82) + bytes([ln])
    return out


HOOKS = {'PLMNidentity': h_plmn, 'pLMNidentity': h_plmn, 'Data-Coding-Scheme': h_dcs,
         'Warning-Message-Content': h_wmc}


def bad_frames(path, *opts):
    r = subprocess.run([TSHARK, '-r', path, *opts, '-Y', '_ws.malformed || _ws.expert.severity >= 0x00800000',
                        '-T', 'fields', '-e', 'frame.number'], capture_output=True, text=True,
                       env=dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE, 'cfg')))
    bad = set(int(x) for x in r.stdout.split())
    bad |= set(int(x) for x in re.findall(r'Dissector bug, protocol \w+, in packet (\d+)', r.stderr))
    return bad


def main():
    os.makedirs(OUT, exist_ok=True)
    cod, sets, procs = asnlib.compile_spec('sbc-ap', 'per')
    g = asnlib.Gen(cod, random.Random(20261111), sets, procs, HOOKS)
    g.force_dcs = None
    g.dcs = 0
    g.wmc_len = None
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
    wr = [p for p in procs if p['init'] == 'Write-Replace-Warning-Request'][0]
    for dcs in DCS:
        for k in range(3):
            g.force_dcs = dcs
            g.popt = 1.0 if k else 0.5
            cand.append(('Write-Replace-Warning-Request', bytes(g.pdu(wr, 'init'))))
    g.force_dcs = None
    # the PDU CHOICE has outcome alternatives for procedures that have none: they reach the empty dissector tables
    for p in procs:
        for alt, which in (('successfulOutcome', 'succ'), ('unsuccessfulOutcome', 'unsucc')):
            if not p[which]:
                cand.append(('outcome', bytes(g.c.types['PDU'].encode((alt, {'procedureCode': p['code'], 'criticality': 'ignore',
                                                                              'value': b'\x00\x01'})))))
    # page length octets above 82 (dissect_s1ap_warningMessageContents does not clamp them): malformed capture only
    long_pages = []
    g.wmc_len = 255
    for dcs in (0x00, 0x48):
        g.force_dcs = dcs
        g.popt = 1.0
        long_pages.append(bytes(g.pdu(wr, 'init')))
    g.wmc_len = None
    g.force_dcs = None
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
    layout.append(('SCTP PPI 24', len(main_c.fr)))
    n0 = len(main_c.fr)
    sc = Sctp(40001, PORT)       # the SCTP port 29168 (PPID 0)
    for i, (_, d) in enumerate(clean[::7]):
        main_c.eth(sc.data(d, up=(i % 2 == 0), ppid=0))
    layout.append(('SCTP port 29168', len(main_c.fr) - n0))
    main_c.write(os.path.join(OUT, 'sbc-ap-coverage.pcapng'))
    sc = Sctp(40000, PORT)
    for i, (_, d) in enumerate(badl):
        mal.eth(sc.data(d, up=(i % 2 == 0), ppid=PPID))
    for d in long_pages:
        mal.eth(sc.data(d, up=True, ppid=PPID))
    for i, (_, d) in enumerate(clean[::11]):
        cut = max(2, (len(d) * (1 + i % 7)) // 8)
        mal.eth(sc.data(d[:cut], up=True, ppid=PPID))
    mal.write(os.path.join(OUT, 'sbc-ap-coverage-malformed.pcapng'))
    print(' / '.join('%s: %d' % x for x in layout))


main()
