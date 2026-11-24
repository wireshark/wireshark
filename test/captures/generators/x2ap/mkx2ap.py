#!/usr/bin/env python3
# Generates test/captures/x2ap_coverage.pcap.gz, x2ap_nested.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the X2AP coverage captures: mkx2ap.py <outdir> [-v]

x2ap-coverage.pcap            valid traffic, no malformed frames
x2ap-coverage-malformed.pcap  nesting past the limit, truncations, bad PLMNs, ...

Needs asn1tools (see README.md); helper modules asngen.py, capio.py,
mkcommon.py, cfg_x2ap.py and pool_x2ap.json (container payloads that the
LTE RRC/S1AP/NGAP dissectors accept) are in the same directory.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import json
import random
HERE = os.path.dirname(os.path.abspath(__file__))
import asngen
import capio
import cfg_x2ap as cfg

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else HERE
VERBOSE = '-v' in sys.argv
spec = asngen.Spec('x2ap', 'X2AP')
POOL = {k: [cfg.dec(x) for x in v] for k, v in json.load(open(os.path.join(HERE, 'pool_x2ap.json'))).items()}
if 'ServedNRCell-Information/measurementTimingConfiguration' in POOL:
    POOL['*/measurementTimingConfiguration'] = POOL['ServedNRCell-Information/measurementTimingConfiguration']
# (generated value profile) -> optional presence, extension probability, list length
PROFILES = [(0.35, 0.05, 1), (0.7, 0.25, 2), (1.0, 0.5, 1)]
try:
    ATTEMPTS = json.load(open(os.path.join(HERE, 'attempts.json')))
except Exception:
    ATTEMPTS = {}      # key -> extra seed; bumped by fixup.py for frames the dissector rejects
KEYS = []           # per main capture frame: the keys of the PDUs it holds
frames = []     # (label, ip src, ip dst, sport, dport, ppid, [pdu...], flags)
A, B = '192.0.2.10', '192.0.2.20'


def mkgen(rng, prof):
    opt, ext, lm = prof
    g = cfg.make_gen(spec, rng, ext=ext, opt=opt, list_max=lm)
    g.alpha = bytes([0, 1, 2, 3, 0x55, 0xaa, 0x80, 0xff])
    g.mode = 'build'
    g.pool = POOL
    return g


def msg_pdu(kind, code, crit, g, msg):
    body = g.gen_encode(msg)
    p = capio.pdu(kind, code, crit, body)
    return p


def keyed(key, kind, code, crit, msg, prof):
    """a PDU of message `msg`, reproducible from `key` (+ attempt number)"""
    for extra in range(20):
        rng = random.Random('x2ap/%s/%d' % (key, ATTEMPTS.get(key, 0) * 20 + extra))
        g = mkgen(rng, prof)
        try:
            p = msg_pdu(kind, code, crit, g, msg)
        except Exception:
            continue
        if len(p) < 16000:
            return p
    raise RuntimeError(key)


def add(label, pdus, ppid=27, dport=36422, sport=36422, src=A, dst=B, keys=()):
    frames.append((label, src, dst, sport, dport, ppid, pdus))
    KEYS.append(list(keys))


# --- 1. every message of every procedure, three profiles ----------------------
n = 0
for pname, imsg, sout, uout, code, crit in spec.procs:
    for kind, msg in ((0, imsg), (1, sout), (2, uout)):
        if not msg:
            continue
        for pi, prof in enumerate(PROFILES):
            key = '%s/%d' % (msg, pi)
            p = keyed(key, kind, code, crit, msg, prof)
            add('%s profile %d' % (msg, pi), [p], ppid=27 if (n % 7) else 0, keys=[key])
            n += 1
if VERBOSE:
    print('messages', n)

# --- 2. X2AP-Message nesting just under the limit -----------------------------
g = mkgen(random.Random('nest'), PROFILES[0])
code_xfer = [x for x in spec.procs if x[1] == 'X2APMessageTransfer'][0][4]


def transfer(inner, rng_seed):
    """X2APMessageTransfer PDU carrying `inner` (a complete X2AP-PDU) in the X2AP-Message IE"""
    g = mkgen(random.Random('%s/%d' % (rng_seed, ATTEMPTS.get('xfer' + rng_seed, 0))), PROFILES[0])
    ies = g.ie_list('X2APMessageTransfer-IEs', force_all=True, drop=('id-x2APMessage',))
    ies = [i for i in ies if i['id'] != 102]
    if inner is not None:
        # X2AP-Message ::= OCTET STRING: the open type holds the length-prefixed string
        ies.append({'id': 102, 'criticality': 'reject', 'value': spec.comp.encode('X2AP-Message', inner)})
    body = spec.comp.encode('X2APMessageTransfer', {'protocolIEs': ies})
    return capio.pdu(0, code_xfer, 'reject', body)


def nested(depth):
    p = transfer(None, 'n0')
    for i in range(depth):
        p = transfer(p, 'n%d' % (i + 1))
    return p


# the generated X2AP-Message IE of the random frames was dropped (SKIP): the outer
# message plus one and two nested X2AP-PDUs decode fully (limit X2AP_MAX_NESTED_MESSAGES 2)
inner_hom = None
for depth in (0, 1, 2):
    add('X2APMessageTransfer nested %d (limit 2)' % depth, [nested(depth)])
# a nested handover request and a nested error indication
hr = [x for x in spec.procs if x[1] == 'HandoverRequest'][0]
ei = [x for x in spec.procs if x[1] == 'ErrorIndication'][0]
for lab, pr, k, m in (('HandoverRequest', hr, 0, 'HandoverRequest'), ('ErrorIndication', ei, 0, 'ErrorIndication')):
    inner = keyed('inner' + lab, 0, pr[4], pr[5], m, PROFILES[0])
    add('X2APMessageTransfer carrying %s' % lab, [transfer(inner, 'x' + lab)], keys=['inner' + lab, 'xfer' + 'x' + lab])
    # and that wrapped once more (second level)
    add('X2APMessageTransfer(X2APMessageTransfer(%s))' % lab, [transfer(transfer(inner, 'y' + lab), 'z' + lab)], keys=['inner' + lab, 'xfer' + 'y' + lab, 'xfer' + 'z' + lab])

# two nested chunks in one SCTP packet: each chunk has its own depth budget
add('two chunks, nested 2 each', [nested(2), nested(2)])

# --- 3. PrivateIE-ID: global, local and global again (fixed state leak) -------
pm = [x for x in spec.procs if x[1] == 'PrivateMessage'][0]
for i, privs in enumerate(([('global', '1.3.6.1.4.1.99999.1'), ('local', 7)],
                            [('local', 3), ('global', '1.2.3.4'), ('local', 9)],
                            [('local', 65535)], [('global', '2.999.1')])):
    body = spec.comp.encode('PrivateMessage', {'privateIEs': [
        {'id': pid, 'criticality': 'ignore', 'value': bytes(range(1 + j, 5 + j))} for j, pid in enumerate(privs)]})
    add('PrivateMessage %d' % i, [capio.pdu(0, pm[4], pm[5], body)])

# --- 4. several PDUs in one packet, fragmented DATA, a second association ------
multi = [keyed('multi%d' % i, 0, c, cr, m, PROFILES[0]) for i, (pn, m, so, uo, c, cr) in enumerate(spec.procs[:3])]
mk = ['multi%d' % i for i in range(3)]
add('three PDUs in one packet', multi, keys=mk)
frames.append(('fragmented', A, B, 36422, 36422, 27, 'frag:' + spec.procs[0][1])); KEYS.append(['frag'])
add('other association (port 36423 via PPID)', [multi[0]], dport=36423, sport=50000, keys=mk[:1])
add('reverse direction', [multi[1]], src=B, dst=A, keys=mk[1:2])

# --- write ---------------------------------------------------------------------
tsn = {}


def build_frames(fl, vtag0=0x11110000):
    pk = []
    for i, f in enumerate(fl):
        label, src, dst, sport, dport, ppid, pdus = f
        key = (src, dst, sport, dport)
        tsn.setdefault(key, 1000)
        chunks = []
        if isinstance(pdus, str) and pdus.startswith('frag:'):
            m = [x for x in spec.procs if x[1] == pdus[5:]][0]
            pdu = keyed('frag', 0, m[4], m[5], m[1], PROFILES[1])
            third = (len(pdu) + 2) // 3
            parts = [pdu[:third], pdu[third:2 * third], pdu[2 * third:]]
            for j, part in enumerate(parts):
                fl_ = 2 if j == 0 else (1 if j == 2 else 0)
                pk.append(capio.eth(capio.ipv4(capio.sctp_packet([capio.data_chunk(part, tsn[key], ppid, 0, 5, fl_)], sport, dport, vtag0 + (1 if src == A else 2)), src, dst)))
                tsn[key] += 1
            continue
        for j, p in enumerate(pdus):
            chunks.append(capio.data_chunk(p, tsn[key], ppid, 0, tsn[key] & 0xffff))
            tsn[key] += 1
        pk.append(capio.eth(capio.ipv4(capio.sctp_packet(chunks, sport, dport, vtag0 + (1 if src == A else 2)), src, dst)))
    return pk


pk = build_frames(frames)
capio.write_pcap(os.path.join(OUT, 'x2ap-coverage.pcap'), pk)
print('x2ap-coverage.pcap', len(pk), 'frames')

# --- the nesting reproducers (small, for the test): just under and past the limit -----------
nest = []
for depth in (2, 3, 4, 40, 300):
    nest.append(('nested %d' % depth, A, B, 36422, 36422, 27, [nested(depth)]))
np_ = build_frames(nest, 0x33330000)
capio.write_pcap(os.path.join(OUT, 'x2ap-nested.pcap'), np_)
print('x2ap-nested.pcap', len(np_), 'frames')

# --- malformed capture -----------------------------------------------------------
mal = []


def addm(label, pdus, **kw):
    mal.append((label, kw.get('src', A), kw.get('dst', B), 36422, 36422, 27, pdus))


for depth in (3, 4, 40, 300):
    addm('nested %d' % depth, [nested(depth)])
# truncations of a few valid PDUs and bad lengths
for k in range(0, len(frames), max(1, len(frames) // 25)):
    f = frames[k]
    if isinstance(f[6], list) and f[6]:
        p = f[6][0]
        for cut in (len(p) // 2, 5):
            addm('truncated %s at %d' % (f[0], cut), [p[:cut]])
addm('bad PDU length', [bytes([0, 17, 0, 0x7f, 0, 0, 0])])
addm('empty', [b''])
addm('unknown procedure code', [capio.pdu(0, 200, 'reject', b'\x00\x00\x00')])
addm('unsuccessful outcome without a type', [capio.pdu(2, 99, 'ignore', b'')])
addm('choice extension', [bytes([0x60])])
# PLMN with non-decimal digits in an ECGI inside a Handover Request and fixed-size violations
gx = mkgen(random.Random('bad'), PROFILES[2])
gx.override.pop('PLMN-Identity')
for i in range(6):
    gx = mkgen(random.Random('badplmn%d' % i), PROFILES[1])
    gx.override['PLMN-Identity'] = lambda g: bytes([0xab, 0xcd, 0xef])
    for pn, m, so, uo, c, cr in spec.procs[:6]:
        try:
            addm('non-decimal PLMN %s' % m, [msg_pdu(0, c, cr, gx, m)])
        except Exception:
            pass
# random container payloads that the RRC/S1AP/NGAP/F1AP dissectors reject
for i in range(40):
    gx = mkgen(random.Random('rawcont%d' % i), PROFILES[2])
    gx.pool = {}
    gx.mode = 'probe'; gx.used = []
    for pn, m, so, uo, c, cr in spec.procs:
        if m in ('HandoverRequest', 'HandoverRequestAcknowledge', 'SgNBAdditionRequestAcknowledge', 'SeNBAdditionRequest', 'X2SetupRequest', 'ENDCX2SetupRequest', 'RLFIndication', 'HandoverReport', 'ENDCConfigurationTransfer', 'SCGFailureInformationReport', 'UERadioCapabilityIDMappingResponse', 'SgNBChangeRequired'):
            gx.used = []; gx.ambig = False
            try:
                addm('random containers %s' % m, [msg_pdu(0, c, cr, gx, m)])
            except Exception:
                pass
mp = build_frames(mal, 0x22220000)
capio.write_pcap(os.path.join(OUT, 'x2ap-coverage-malformed.pcap'), mp)
print('x2ap-coverage-malformed.pcap', len(mp), 'frames')
# frame number -> label and keys (used by fixup.py and the README)
with open(os.path.join(OUT, 'x2ap-coverage.idx'), 'w') as f:
    k = 1
    for fr, ks in zip(frames, KEYS):
        f.write('%d %s\n' % (k, fr[0]))
        None
        k += 3 if isinstance(fr[6], str) else 1
json.dump(KEYS, open(os.path.join(OUT, 'x2ap-coverage.keys.json'), 'w'))
