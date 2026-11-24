#!/usr/bin/env python3
# Generates test/captures/lppe_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the LPPe coverage captures. Usage: mklppe.py <outdir> [cand]

lppe-coverage.pcap (Exported PDU, DLT 252, dissector "lpp"): LPP messages
whose EPDU (identifier 1, OMA LPPe) carries an LPPe message in the
OCTET STRING EPDU-Body; packet-lpp.c hands it to the "lppe" dissector.
A few frames name "lppe" directly. LPPe is unaligned PER; the messages
are encoded from the type tree read out of the generated packet-lppe.c
and packet-lpp.c (perschema.py, which merges both files).
lppe-coverage-malformed.pcap: frames that only malformed input reaches.
All values are made up; the capture holds no key material."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import random
import heapq
from perschema import PerSchema, Bits

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.environ.get('WS_DISS', os.path.join(SRCDIR, 'epan/dissectors'))
sc = PerSchema([D + '/packet-lpp.c', D + '/packet-lppe.c'], 'lppe?', seed=int(os.environ.get('SEED', '2802')))
R = sc.rng
sc.avoid_re = r'criticalExtensionsFuture|spare\d|messageClassExtension'
sc.force_re = r'LPP_MessageBody|_IEs$|EPDU_Sequence$'
BADFILE = os.path.join(HERE, 'bad.txt')
BAD = set(int(x) for x in open(BADFILE).read().split()) if os.path.exists(BADFILE) else set()
LPPE_VISIT = [None]


def octets_of(w):
    b = w.tobytes()
    o = Bits()
    sc.uncon_len(o, len(b))
    o.octets(b)
    return o


def tune():
    sc.opt_skip = R.choice([0.0, 0.1, 0.2, 0.35])
    sc.ext_prob = R.choice([0.1, 0.25, 0.4, 0.6])


EPDU_ID = [1]


def h_epdu_id(s, w):
    v = 1 if R.random() < 0.9 else R.choice([2, 255])
    EPDU_ID[0] = v
    w.put(v - 1, 8)


def h_epdu_body(s, w):
    """the LPPe message of an EPDU with identifier 1; the visit set of the
    candidate then only holds what the LPPe encoding touched"""
    if EPDU_ID[0] == 1:
        main, s.visit = s.visit, (set() if s.visit is not None else None)
        inner = s.enc('dissect_lppe_OMA_LPPe_MessageExtension')
        if main is not None:
            LPPE_VISIT[0] = (LPPE_VISIT[0] or set()) | s.visit
        s.visit = main
        w.b += octets_of(inner).b
    else:
        n = R.choice([1, 3])
        s.uncon_len(w, n)
        for _ in range(n):
            w.put(R.randrange(256), 8)


sc.hooks['dissect_lpp_EPDU_ID'] = h_epdu_id
sc.hooks['dissect_lpp_EPDU_Body'] = h_epdu_body


def h_civic(s, w):
    """the civicLocation octets go to the XML dissector: a small
    pidf-lo civic address document"""
    parts = ['<country>AU</country>', '<A1>NSW</A1>', '<A3>Sydney</A3>', '<RD>Example</RD>',
             '<HNO>%d</HNO>' % R.randrange(1, 200), '<PC>2000</PC>']
    doc = ('<civicAddress xmlns="urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr">'
           + ''.join(R.sample(parts, R.randrange(1, len(parts) + 1))) + '</civicAddress>').encode()
    if s.visit is not None:
        s.visit.add(('civic', len(doc) % 7))
    s.uncon_len(w, len(doc))
    w.octets(doc)


sc.hooks['dissect_lppe_T_civicLocation'] = h_civic


def exported_pdu(name, payload):
    n = name.encode()
    n += b'\0' * (-len(n) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def pcap(recs):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252)
    for i, rec in enumerate(recs):
        out += struct.pack('<IIII', 1700000000 + i, 0, len(rec), len(rec)) + rec
    return out


def candidates(n):
    cand = []
    for i in range(n):
        tune()
        LPPE_VISIT[0] = set()
        sc.visit = set()
        p = exported_pdu('lpp', sc.enc('dissect_lpp_LPP_Message').tobytes())
        cand.append((p, LPPE_VISIT[0]))
    sc.visit = None
    return cand


def select(cand, budget):
    chosen, seen, used = [], set(), 0
    heap = [(-len(c[1]) / len(c[0]), i) for i, c in enumerate(cand)]
    heapq.heapify(heap)
    while heap:
        neg, i = heapq.heappop(heap)
        new = len(cand[i][1] - seen)
        if new == 0:
            continue
        ratio = new / len(cand[i][0])
        if heap and ratio < -heap[0][0] - 1e-12:
            heapq.heappush(heap, (-ratio, i))
            continue
        if used + len(cand[i][0]) > budget:
            continue
        chosen.append(i)
        seen |= cand[i][1]
        used += len(cand[i][0])
    return sorted(chosen)


def direct_frames(k):
    """LPPe messages handed to the "lppe" dissector directly (Exported PDU)"""
    out = []
    for _ in range(k):
        tune()
        out.append(exported_pdu('lppe', sc.enc('dissect_lppe_OMA_LPPe_MessageExtension').tobytes()))
    return out


def malformed(cand, pick, recs):
    r = random.Random(2802)
    out = [cand[i][0] for i in sorted(BAD) if i < len(cand)][:40]
    hdr = len(exported_pdu('lpp', b''))
    for p in recs:
        body = p[hdr:] if p[:12].find(b'lpp') >= 0 else p[len(exported_pdu('lppe', b'')):]
        n = len(p) - len(body)
        if len(body) < 6:
            continue
        out.append(p[:n] + body[:r.randrange(1, len(body))])
        q = bytearray(p)
        for _ in range(3):
            q[r.randrange(n, len(q))] ^= 1 << r.randrange(8)
        out.append(bytes(q))
    for b in (b'', b'\x00', b'\xff\xff\xff'):
        out.append(exported_pdu('lppe', b))
    return out


NCAND = int(os.environ.get('NCAND', '3000'))
BUDGET = int(os.environ.get('BUDGET', '70000'))


def main(out, mode='final'):
    cand = candidates(NCAND)
    if mode == 'cand':
        open(os.path.join(out, 'lppe-cand.pcap'), 'wb').write(pcap([p for p, v in cand]))
        return
    good = [i for i in range(len(cand)) if i not in BAD]
    pick = [good[j] for j in select([cand[i] for i in good], BUDGET)]
    direct = direct_frames(3)
    recs = [cand[i][0] for i in pick] + direct
    open(os.path.join(out, 'layout.txt'), 'w').write('lpp %d\nlppe %d\n' % (len(pick), len(direct)))
    open(os.path.join(out, 'lppe-coverage.pcap'), 'wb').write(pcap(recs))
    open(os.path.join(out, 'lppe-coverage-malformed.pcap'), 'wb').write(pcap(malformed(cand, pick, recs)))
    print('main: %d frames of %d candidates (%d bad)' % (len(recs), len(cand), len(BAD)))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'final')
