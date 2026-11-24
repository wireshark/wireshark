#!/usr/bin/env python3
# Generates test/captures/xnap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the XnAP coverage captures: mkxnap.py <outdir> [-v]

xnap-coverage.pcap            valid traffic, no malformed frames
xnap-coverage-malformed.pcap  truncations, bad PLMNs, undecodable containers, ...

Needs asn1tools (see README.md); helper modules asngen.py, capio.py,
cnfscan.py, cfg_xnap.py and pool_xnap.json (container payloads that the NR
RRC / LTE RRC dissectors accept) are in the same directory.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import json
import random
import struct
HERE = os.path.dirname(os.path.abspath(__file__))
import asngen
import capio
import cfg_xnap as cfg

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else HERE
VERBOSE = '-v' in sys.argv
spec = asngen.Spec('xnap', 'XnAP')
POOL = {k: [cfg.dec(x) for x in v] for k, v in json.load(open(os.path.join(HERE, 'pool_xnap.json'))).items()}
PROFILES = [(0.35, 0.05, 1), (0.7, 0.25, 2), (1.0, 0.5, 1)]
try:
    ATTEMPTS = json.load(open(os.path.join(HERE, 'attempts.json')))
except Exception:
    ATTEMPTS = {}
try:
    DROP = set(json.load(open(os.path.join(HERE, 'drop.json'))))   # keys of frames the dissector never accepted
except Exception:
    DROP = set()
DROPPED = []
KEYS = []
frames = []     # (label, src, dst, sport, dport, ppid, [pdu...] | 'frag:..')
A, B = '192.0.2.1', '192.0.2.2'
PROCS = {m: (k, p[4], p[5]) for p in spec.procs for k, m in ((0, p[1]), (1, p[2]), (2, p[3])) if m}
PORT = cfg.PORT
sport_next = [40000]


def mkgen(rng, prof, scen='gnb'):
    opt, ext, lm = prof
    g = cfg.make_gen(spec, rng, ext=ext, opt=opt, list_max=lm)
    g.alpha = bytes([0, 1, 2, 3, 0x55, 0xaa, 0x80, 0xff])
    g.mode = 'build'
    g.pool = POOL
    g.scen = scen
    g.seen = set()
    return g


def keyed(key, msg, prof, scen='gnb', want=None):
    """PDU of message `msg`, reproducible from `key` (+ attempt number); `want`: a set of
    handoff keys of which at least one has to be present"""
    kind, code, crit = PROCS[msg]
    for extra in range(60 if want is None else 4):
        rng = random.Random('xnap/%s/%d' % (key, ATTEMPTS.get(key, 0) * 60 + extra))
        g = mkgen(rng, prof, scen)
        try:
            body = g.gen_encode(msg)
        except Exception:
            continue
        p = capio.pdu(kind, code, crit, body)
        if len(p) >= 16000:
            continue
        if want is not None and not (g.seen & want):
            continue
        return p
    return None


def add(label, pdus, ppid=61, dport=PORT, sport=None, src=A, dst=B, keys=()):
    if sport is None:
        sport = sport_next[0]; sport_next[0] += 1
    if any(k in DROP for k in keys):
        DROPPED.append((label, src, dst, sport, dport, ppid, pdus))
        return
    frames.append((label, src, dst, sport, dport, ppid, pdus))
    KEYS.append(list(keys))


# --- 1. every message of every procedure, three profiles (each on its own association,
#        so the node types of the Xn Setup frames below do not influence them) ------------
n = 0
for pname, imsg, sout, uout, code, crit in spec.procs:
    for msg in (imsg, sout, uout):
        if not msg:
            continue
        for pi, prof in enumerate(PROFILES):
            key = '%s/%d' % (msg, pi)
            p = keyed(key, msg, prof)
            if p is None:
                continue
            add('%s profile %d' % (msg, pi), [p], ppid=61 if (n % 7) else 0, keys=[key])
            n += 1
if VERBOSE:
    print('messages', n)

# --- 2. node types learnt from Xn Setup: containers decoded as NR RRC or LTE RRC ----------
STATE = set(cfg.STATE_KEYS)
for si, scen in enumerate(cfg.SCENARIOS):
    sp = 41000 + si
    g = cfg.make_gen(spec, random.Random('prelude' + scen))
    for rev, kind, code, crit, body in cfg.prelude(spec, scen, lambda rng: mkgen(rng, (0.0, 0.0, 1), scen)):
        add('Xn Setup %s (%s)' % ('response' if rev else 'request', scen), [capio.pdu(kind, code, crit, body)],
            sport=sp if not rev else PORT, dport=PORT if not rev else sp, src=B if rev else A, dst=A if rev else B)
    k = 0
    for pname, imsg, sout, uout, code, crit in spec.procs:
        for msg in (imsg, sout, uout):
            if not msg or msg.startswith('XnSetup'):
                continue
            key = 'state/%s/%s' % (scen, msg)
            # which of the messages can carry a node type dependent container?
            p = keyed(key, msg, PROFILES[2], scen, want=STATE)
            if p is None:
                continue
            for rev in (False, True):
                add('%s (%s, %s)' % (msg, scen, 'B->A' if rev else 'A->B'), [p], sport=sp if not rev else PORT,
                    dport=PORT if not rev else sp, src=B if rev else A, dst=A if rev else B, keys=[key])
                k += 1

# the ranmode reproducer: setup (B: gNB), reconfiguration complete A->B, setup (B: ng-eNB)
PLMN = b'\x00\xf1\x10'
gnb = b'\x00' + PLMN + b'\x50' + b'\x01\x02\x03\x04'
ngenb = b'\x40' + PLMN + b'\x00' + b'\x12\x34\x50'


def ie(ie_id, value, crit=0):
    return struct.pack('>H', ie_id) + bytes([crit << 6]) + capio.lenenc(len(value)) + value


def imsg_pdu(proc, ies):
    body = b'\x00' + struct.pack('>H', len(ies)) + b''.join(ies)
    return b'\x00' + bytes([proc]) + b'\x00' + capio.lenenc(len(body)) + body


resp = b'\x04' + capio.lenenc(2) + b'\x00\x00'
for pdus_, d, lab in (([imsg_pdu(17, [ie(14, gnb)])], 'B', 'Xn Setup Request, B is a gNB'),
                      ([imsg_pdu(8, [ie(60, resp, 1)])], 'A', 'S-NG-RAN node Reconfiguration Complete A->B (M-to-S container)'),
                      ([imsg_pdu(17, [ie(14, ngenb)])], 'B', 'Xn Setup Request, B is an ng-eNB')):
    add(lab, pdus_, sport=42000 if d == 'A' else PORT, dport=PORT if d == 'A' else 42000, src=A if d == 'A' else B, dst=B if d == 'A' else A)

# --- 3. PrivateIE-ID: global, local and global again (fixed state leak) -------------------
for i, privs in enumerate(([('global', '1.3.6.1.4.1.99999.1'), ('local', 7)],
                            [('local', 3), ('global', '1.2.3.4'), ('local', 9)],
                            [('local', 65535)], [('global', '2.999.1')])):
    body = spec.comp.encode('PrivateMessage', {'privateIEs': [
        {'id': pid, 'criticality': 'ignore', 'value': bytes(range(1 + j, 5 + j))} for j, pid in enumerate(privs)]})
    kind, code, crit = PROCS['PrivateMessage']
    add('PrivateMessage %d' % i, [capio.pdu(kind, code, crit, body)])

# --- 4. several PDUs in a packet, fragmented DATA ------------------------------------------
names = [m for pn, m, so, uo, c, cr in spec.procs[:3]]
multi = [keyed('multi%d' % i, m, PROFILES[0]) for i, m in enumerate(names)]
mk = ['multi%d' % i for i in range(3)]
add('three PDUs in one packet', multi, keys=mk)
frames.append(('fragmented', A, B, 43000, PORT, 61, 'frag:' + spec.procs[1][1])); KEYS.append(['frag'])
add('reverse direction', [multi[1]], src=B, dst=A, sport=PORT, dport=43001, keys=mk[1:2])

tsn = {}


def build_frames(fl, vtag0=0x11110000):
    pk = []
    for i, f in enumerate(fl):
        label, src, dst, sport, dport, ppid, pdus = f
        key = (src, dst, sport, dport)
        tsn.setdefault(key, 1000)
        if isinstance(pdus, str) and pdus.startswith('frag:'):
            pdu = keyed('frag', pdus[5:], PROFILES[1])
            third = (len(pdu) + 2) // 3
            parts = [pdu[:third], pdu[third:2 * third], pdu[2 * third:]]
            for j, part in enumerate(parts):
                fl_ = 2 if j == 0 else (1 if j == 2 else 0)
                pk.append(capio.eth(capio.ipv4(capio.sctp_packet([capio.data_chunk(part, tsn[key], ppid, 0, 5, fl_)], sport, dport, vtag0 + (1 if src == A else 2)), src, dst)))
                tsn[key] += 1
            continue
        chunks = []
        for p in pdus:
            chunks.append(capio.data_chunk(p, tsn[key], ppid, 0, tsn[key] & 0xffff))
            tsn[key] += 1
        pk.append(capio.eth(capio.ipv4(capio.sctp_packet(chunks, sport, dport, vtag0 + (1 if src == A else 2)), src, dst)))
    return pk


pk = build_frames(frames)
capio.write_pcap(os.path.join(OUT, 'xnap-coverage.pcap'), pk)
print('xnap-coverage.pcap', len(pk), 'frames')
with open(os.path.join(OUT, 'xnap-coverage.idx'), 'w') as f:
    k = 1
    for fr in frames:
        f.write('%d %s\n' % (k, fr[0]))
        k += 3 if isinstance(fr[6], str) else 1
json.dump(KEYS, open(os.path.join(OUT, 'xnap-coverage.keys.json'), 'w'))
if os.environ.get('MKFAST'):
    sys.exit(0)      # only the main capture (used by fixup.py)

# --- malformed capture ------------------------------------------------------------------
mal = list(DROPPED)


def addm(label, pdus, **kw):
    mal.append((label, kw.get('src', A), kw.get('dst', B), kw.get('sport', 44000), PORT, 61, pdus))


for k in range(0, len(frames), max(1, len(frames) // 25)):
    f = frames[k]
    if isinstance(f[6], list) and f[6]:
        p = f[6][0]
        for cut in (len(p) // 2, 5):
            addm('truncated %s at %d' % (f[0], cut), [p[:cut]], sport=44000 + k)
addm('bad PDU length', [bytes([0, 17, 0, 0x7f, 0, 0, 0])])
addm('empty', [b''])
addm('unknown procedure code', [capio.pdu(0, 200, 'reject', b'\x00\x00\x00')])
addm('unsuccessful outcome without a type', [capio.pdu(2, 99, 'ignore', b'')])
addm('choice extension', [bytes([0x60])])
for i in range(6):
    gx = mkgen(random.Random('badplmn%d' % i), PROFILES[1])
    gx.override['PLMN-Identity'] = lambda g: bytes([0xab, 0xcd, 0xef])
    for pn, m, so, uo, c, cr in spec.procs[:6]:
        try:
            body = gx.gen_encode(m)
            addm('non-decimal PLMN %s' % m, [capio.pdu(0, c, cr, body)], sport=45000 + i)
        except Exception:
            pass
# random container payloads that the RRC/NGAP/F1AP dissectors reject; with and without node types
for scen in cfg.SCENARIOS:
    sp = 46000 + len(mal)
    for rev, kind, code, crit, body in cfg.prelude(spec, scen, lambda rng: mkgen(rng, (0.0, 0.0, 1), scen)):
        addm('Xn Setup %s' % scen, [capio.pdu(kind, code, crit, body)], sport=sp if not rev else PORT, src=B if rev else A, dst=A if rev else B)
        mal[-1] = mal[-1][:3] + (sp if not rev else PORT, sp if rev else PORT) + mal[-1][5:]
    for i in range(12):
        gx = mkgen(random.Random('rawcont%s%d' % (scen, i)), PROFILES[2], scen)
        gx.pool = {}
        for pn, m, so, uo, c, cr in spec.procs:
            if m.startswith('XnSetup') or m not in PROCS:
                continue
            try:
                body = gx.gen_encode(m)
            except Exception:
                continue
            if not (gx.seen & set(cfg.STATE_KEYS)):
                continue
            mal.append(('random containers %s (%s)' % (m, scen), A, B, sp, PORT, 61, [capio.pdu(0, c, cr, body)]))
mp = build_frames(mal, 0x22220000)
capio.write_pcap(os.path.join(OUT, 'xnap-coverage-malformed.pcap'), mp)
print('xnap-coverage-malformed.pcap', len(mp), 'frames')
