#!/usr/bin/env python3
# Generates test/captures/sabp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the SABP coverage captures: python3 mksabp.py <outdir>

Needs asn1tools (ASN1TOOLS_PATH, ./pylib or the shared pylib of the batch) and
the Wireshark tree (WS_TREE) for the ASN.1 files.  Random values of every SABP
procedure are made with the generator of asnlib.py; tshark (TSHARK) is run over
them and the frames that decode without a malformed packet or error expert info
go to the main capture, the others to the malformed capture.  Hand built PDUs
cover the cell broadcast pages (every data coding scheme), the TCP framing and
the encoding state reproducer."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import random
import re
import struct
import subprocess

import asnlib
from capio import Cap, Sctp, Tcp, udp

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
HERE = os.path.dirname(os.path.abspath(__file__))
TSHARK = os.environ.get('TSHARK', os.environ.get('TSHARK', 'tshark'))
NVAR = int(os.environ.get('NVAR', '8'))
PORT = 3452
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


def pages(g, n, lens, even=False):
    out = bytes([n])
    for i in range(n):
        ln = lens[i % len(lens)]
        if even:
            ln &= ~1
        out += g.rbytes(82) + bytes([ln])
    return out


def h_bmc(g, t, depth):
    n = g.r.choice([1, 2, 3, 15, 15, 0, 16, 5])
    b = pages(g, min(n, 15) if n != 16 else 0, [82, 40, 20, 2, 0, 90, 83], even=g.dcs in (0x48, 0x11))
    if n == 16:
        b = bytes([16]) + b[1:]
    return (b, len(b) * 8)


HOOKS = {'PLMNidentity': h_plmn, 'pLMNidentity': h_plmn, 'Data-Coding-Scheme': h_dcs,
         'Broadcast-Message-Content': h_bmc}


def bad_frames(path, *opts):
    r = subprocess.run([TSHARK, '-r', path, *opts, '-Y', '_ws.malformed || _ws.expert.severity >= 0x00800000',
                        '-T', 'fields', '-e', 'frame.number'], capture_output=True, text=True,
                       env=dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE, 'cfg')))
    bad = set(int(x) for x in r.stdout.split())
    bad |= set(int(x) for x in re.findall(r'Dissector bug, protocol \w+, in packet (\d+)', r.stderr))
    return bad


def per_len(n):
    return bytes([n]) if n < 128 else struct.pack('!H', 0x8000 | n)


def main():
    os.makedirs(OUT, exist_ok=True)
    cod, sets, procs = asnlib.compile_spec('sabp', 'per')
    g = asnlib.Gen(cod, random.Random(20261111), sets, procs, HOOKS)
    g.force_dcs = None
    g.dcs = 0
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
    # Write-Replace with every data coding scheme
    wr = [p for p in procs if p['init'] == 'Write-Replace'][0]
    for dcs in DCS:
        for k in range(3):
            g.force_dcs = dcs
            g.popt = 1.0 if k else 0.0
            cand.append(('Write-Replace', bytes(g.pdu(wr, 'init'))))
    g.force_dcs = None
    c = Cap()
    for d in cand:
        c.eth(udp(d[1], 40000, PORT))
    c.write(os.path.join(OUT, 'cand.pcapng'))
    bad = bad_frames(os.path.join(OUT, 'cand.pcapng'))
    # Candidate 152 was reported as malformed by the tshark the committed capture was
    # made with; a later tshark decodes it cleanly.  Keep it out of the main capture.
    bad |= {152}
    os.remove(os.path.join(OUT, 'cand.pcapng'))
    clean = [x for i, x in enumerate(cand, 1) if i not in bad]
    badl = [x for i, x in enumerate(cand, 1) if i in bad]
    print(len(cand), 'candidates', len(bad), 'bad')
    main_c, mal = Cap(), Cap()
    layout = []
    # 1. UDP port 3452, one frame per generated PDU
    for i, (_, d) in enumerate(clean):
        main_c.eth(udp(d, 40000 + i % 3, PORT, up=(i % 2 == 0)))
    layout.append(('UDP 3452', len(main_c.fr)))
    # 2. SCTP, PPI 31
    n0 = len(main_c.fr)
    sc = Sctp(41000, 3453)
    for i, (_, d) in enumerate(clean[::6]):
        main_c.eth(sc.data(d, up=(i % 2 == 0), ppid=31))
    layout.append(('SCTP PPI 31', len(main_c.fr) - n0))
    # 3. TCP 3452: whole PDUs, a PDU split over two segments, a segment of less than 5 octets first,
    #    two PDUs in one segment
    n0 = len(main_c.fr)
    t = Tcp(42000, PORT)
    for f in t.syn():
        main_c.eth(f)
    ps = [d for _, d in clean if 5 < len(d) < 200][:12]
    main_c.eth(t.seg(ps[0]))
    a, b = ps[1][:2], ps[1][2:]
    main_c.eth(t.seg(a))
    main_c.eth(t.seg(b))
    a, b = ps[2][:3], ps[2][3:]
    main_c.eth(t.seg(a))
    main_c.eth(t.seg(b))
    main_c.eth(t.seg(ps[3] + ps[4]))
    h = len(ps[5]) // 2
    main_c.eth(t.seg(ps[5][:h]))
    main_c.eth(t.seg(ps[5][h:]))
    main_c.eth(t.seg(ps[6], up=False))
    main_c.eth(t.seg(ps[7], up=False))
    layout.append(('TCP 3452 (whole, split, joined PDUs)', len(main_c.fr) - n0))
    # 4. reproducer of "SABP: Reset the encoding state per PDU": frame 1 has only Broadcast-Message-Content,
    #    frame 2 only a Data-Coding-Scheme (UCS2)
    n0 = len(main_c.fr)
    page = ('Hello SABP page'.encode('utf-16-be')).ljust(82, b'\x00')
    cb = bytes([1]) + page + bytes([82])
    bmc = struct.pack('!H', len(cb) * 8 - 1) + cb

    def ie(i, v, crit=1):
        return struct.pack('!H', i) + bytes([crit << 6]) + per_len(len(v)) + v

    def pdu(proc, ies):
        body = b'\x00' + struct.pack('!H', len(ies)) + b''.join(ies)
        return b'\x00' + bytes([proc]) + b'\x40' + per_len(len(body)) + body
    main_c.eth(udp(pdu(0, [ie(0, bmc)]), 40000, PORT))
    main_c.eth(udp(pdu(0, [ie(4, b'\x48')]), 40000, PORT))
    # the same two IEs in one PDU (Data-Coding-Scheme first): the page is decoded as UCS2
    main_c.eth(udp(pdu(0, [ie(4, b'\x48'), ie(0, bmc)]), 40000, PORT))
    layout.append(('encoding state reproducer (2 frames) and both IEs in one PDU', len(main_c.fr) - n0))
    main_c.write(os.path.join(OUT, 'sabp-coverage.pcapng'))
    for i, (_, d) in enumerate(badl):
        mal.eth(udp(d, 40000, PORT))
    for i, (_, d) in enumerate(clean[::11]):
        cut = max(2, (len(d) * (1 + i % 7)) // 8)
        mal.eth(udp(d[:cut], 40000, PORT))
    # TCP: a length determinant for a fragment of 16384 octets (unreachable with a valid SABP PDU, whose
    # length determinant never fragments)
    t = Tcp(42001, PORT)
    for f in t.syn():
        mal.eth(f)
    mal.eth(t.seg(b'\x00\x00\x40\xc1' + bytes(16384) + b'\x03abc'))
    mal.eth(t.seg(b'\x00\x00\x40\xc1' + bytes(100)))
    t = Tcp(42002, PORT)
    for f in t.syn():
        mal.eth(f)
    mal.eth(t.seg(b'\x00\x01'))
    mal.write(os.path.join(OUT, 'sabp-coverage-malformed.pcapng'))
    print(' / '.join('%s: %d' % x for x in layout))


main()
