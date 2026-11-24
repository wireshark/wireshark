#!/usr/bin/env python3
# Generates test/captures/h501_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.501 coverage captures.  Usage: mkh501.py <outdir> <workdir> [-v]

Run it on a machine with the Wireshark source tree (the .asn files of
H.501, H.225 and H.235 are parsed with the parser of
tools/dissector_generators/asn2wrs.py; <workdir> receives parsetab.py).
The aligned PER encodings come from asnper.py (a small PER encoder and
random value generator driven by that syntax tree).  Everything is built
with Python struct; nothing comes from a real network.

H.501 runs in TPKT over UDP or TCP port 2099 (both registered).
H.235 tokens and signatures are never generated (optional security
fields are skipped), so no key handling is exercised.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import random
import asnper
from _lib import Pcap

FILES = ['h501/H501-MESSAGES.asn', 'h225/H323-MESSAGES.asn', 'h235/H235-SECURITY-MESSAGES.asn']
SKIP = {'integrityCheckValue', 'tokens', 'cryptoTokens', 'cryptoToken', 'clearToken', 'nonStandardData'} - {'nonStandardData'}
SKIP |= {'tokens', 'cryptoTokens', 'integrityCheckValue'}

A, B = '192.0.2.50', '192.0.2.60'

def tpkt(d):
    return struct.pack('!BBH', 3, 0, 4 + len(d)) + d

def find_alt(t, name):
    for a in list(t.elt_list) + list(getattr(t, 'ext_list', []) or []):
        if a.name == name:
            return a
    raise KeyError(name)

def main(out, workdir, verbose=False):
    types = asnper.load(FILES, workdir)
    sc = asnper.Schema(types)
    rng = random.Random(501)
    covered = set()
    p = Pcap()
    marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    msg_t = types['Message']
    body_t = types['MessageBody']
    names = [a.name for a in list(body_t.elt_list) + list(body_t.ext_list)]
    recorded = []

    def newgen(): return asnper.Gen(sc, rng, covered, skip=SKIP)

    def message(alt, depth, p_ext=0.5, p_opt=0.5, seq=None, hop=None):
        g = newgen(); g.p_ext = p_ext; g.p_opt = p_opt
        common = g.gen(types['MessageCommonInfo'], depth, '')
        a = find_alt(body_t, alt)
        g.mark((body_t.name, alt))
        body = (alt, g.gen(a, depth, ''))
        if seq is not None: common['sequenceNumber'] = seq
        if hop is not None: common['hopCount'] = hop
        covered.update(g.new)
        return sc.encode(msg_t, {'body': body, 'common': common}).bytes(), g

    mark('UDP: random instances of every message type that add coverage')
    sp = 3000
    for alt in names:
        kept = 0
        for attempt in range(150):
            if kept >= 5: break
            d, g = message(alt, rng.choice((5, 7, 9)), rng.choice((0.3, 0.6, 0.9)), rng.choice((0.4, 0.7)))
            if not g.new and kept > 0: continue
            sp += 1
            recorded.append(d)
            p.udp(A, B, sp, 2099, tpkt(d))
            kept += 1
    mark('Route information with price information (PriceInfoSpec / PriceElement)')
    for attempt in range(3000):
        d, g = message('accessConfirmation', 10, 0.7, 0.95)
        if ('visit', 'PriceElement') in g.new:
            sp += 1
            p.udp(A, B, sp, 2099, tpkt(d))
            recorded.append(d)
            break
    mark('TCP: the same message types over one connection, two messages in a segment, a message split over two segments')
    for i, alt in enumerate(names):
        d, g = message(alt, 5, 0.5, 0.5)
        p.tcp(A, B, 40000, 2099, tpkt(d))
    d1, _ = message('serviceRequest', 4); d2, _ = message('serviceRelease', 4)
    p.tcp(B, A, 40001, 2099, tpkt(d1) + tpkt(d2))
    d3, _ = message('accessRequest', 5)
    t = tpkt(d3)
    p.tcp(A, B, 40002, 2099, t[:9])
    p.tcp(A, B, 40002, 2099, t[9:])
    p.write(os.path.join(out, 'h501-coverage.pcap'))

    mq = Pcap(); mq.ts = 1700100000.0
    step = max(1, len(recorded) // 40)
    for i, d in enumerate(recorded[::step]):
        cut = 1 + (i * 7) % max(1, len(d) - 1)
        mq.udp(A, B, 5000 + i, 2099, tpkt(d[:cut]))
    mq.udp(A, B, 5100, 2099, b'')
    mq.udp(A, B, 5101, 2099, tpkt(bytes([0xff] * 64)))
    mq.udp(A, B, 5102, 2099, b'\x03\x00\x00\x06\x80')
    mq.write(os.path.join(out, 'h501-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))
    print(len(p.frames), 'frames,', len(mq.frames), 'malformed')

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
