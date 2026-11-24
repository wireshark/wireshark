#!/usr/bin/env python3
# Generates test/captures/h450_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.450 coverage captures.  Usage: mkh450.py <outdir> <workdir> [-v]

Run it on a machine with the Wireshark source tree: the .asn files of
H.450.x, H.225 and H.235 are parsed with the parser of
tools/dissector_generators/asn2wrs.py (<workdir> receives parsetab.py) and
the operation table of epan/dissectors/packet-h450.c is read to learn which
argument, result and error parameter types belong to which operation code.
The aligned PER encodings come from asnper.py (a small PER encoder and
random value generator driven by that syntax tree) and _ros.py (the H.450.1
service APDU and the Remote Operations APDUs).  Everything is built with
Python struct; nothing comes from a real network.

H.450 is carried in the h4501SupplementaryService field of the H.225.0
H323-UU-PDU (Q.931 Facility in TPKT over TCP port 1720, as in real calls).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import random
import re
import asnper
import _ros
from _lib import Pcap

H450 = ['Addressing-Data-Elements', 'Call-Completion-Operations', 'Call-Diversion-Operations', 'Call-Hold-Operations',
        'Call-Intrusion-Operations', 'Call-Offer-Operations', 'Call-Park-Pickup-Operations', 'Call-Transfer-Operations',
        'Call-Waiting-Operations', 'Common-Information-Operations', 'H225-generic-parameters-definition',
        'H4501-General-Error-List', 'H4501-Supplementary-ServiceAPDU-Structure',
        'Manufacturer-specific-service-extension-definition', 'Message-Waiting-Indication-Operations', 'Name-Operations']
FILES = ['h225/H323-MESSAGES.asn', 'h235/H235-SECURITY-MESSAGES.asn', 'h245/MULTIMEDIA-SYSTEM-CONTROL.asn'] + \
        ['h450/%s.asn' % x for x in H450]
SRC = os.path.join(SRCDIR, 'epan/dissectors/packet-h450.c')
SKIP = {'tunnelledSignallingMessage', 'h4501SupplementaryService', 'tokens', 'cryptoTokens', 'integrityCheckValue'}
EP1, EP2 = '192.0.2.10', '192.0.2.20'

def tpkt(d): return struct.pack('!BBH', 3, 0, 4 + len(d)) + d

def q931(msgtype, uuie, callref=1, from_dest=False):
    cr = struct.pack('!H', callref | (0x8000 if from_dest else 0))
    return bytes([0x08, 0x02]) + cr + bytes([msgtype]) + bytes([0x7E]) + struct.pack('!H', len(uuie) + 1) + bytes([0x05]) + uuie

def parse_tables():
    """[(module, name, code, argfunc, resfunc)] and [(modules, name, code, parfunc)] from packet-h450.c"""
    src = open(SRC).read()
    ops, errs = [], []
    for kind, start, end in (('op', 'static const h450_op_t h450_op_tab[] = {', '};'),
                             ('err', 'static const h450_err_t h450_err_tab[] = {', '};')):
        body = src.split(start)[1].split(end)[0]
        mods = []
        for line in body.splitlines():
            m = re.match(r'/\* --- Modules? (.*?) --- ', line)
            if m:
                mods = m.group(1).split()
                continue
            m = re.match(r'\s*/\* (\S+)\s*\*/ \{\s*(\d+),\s*(\w+)(?:,\s*(\w+))? \},', line)
            if m:
                n, c, a, b = m.groups()
                if kind == 'op':
                    ops.append((mods[0], n, int(c), a, b))
                else:
                    errs.append((mods, n, int(c), a))
    return ops, errs

def main(out, workdir, verbose=False):
    types = asnper.load(FILES, workdir)
    objs = types.pop('__objs__')
    sc = asnper.Schema(types)
    rng = random.Random(450)
    ops, errs = parse_tables()
    covered = set()
    p = Pcap()
    marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    uu_t = types['H323-UserInformation']
    uupdu = types['H323-UU-PDU']
    body_t = [e.val for e in uupdu.elt_list if e.val.name == 'h323-message-body'][0]

    def obj(mod, name):
        return objs.get((mod, name)) or next((o for (m, n), o in objs.items() if n == name), None)

    def gen(t, depth, p_ext, p_opt):
        g = asnper.Gen(sc, rng, covered, skip={'tokens', 'cryptoTokens'})
        g.p_ext = p_ext; g.p_opt = p_opt
        v = g.gen(t, depth, '')
        return v, g

    # ---- operation catalogue: (code, name, argtype|None, restype|None)
    catalogue = []
    for mod, name, code, af, rf in ops:
        o = obj(mod, name)
        if o is None:
            continue
        argt = o.val.get('&ArgumentType') if af != 'NULL' else None
        rest = o.val.get('&ResultType') if rf != 'NULL' else None
        catalogue.append((code, name, argt, rest, af == 'NULL', rf == 'NULL'))
    errcat = []
    for mods, name, code, pf in errs:
        o = next((objs[(m, name)] for m in mods if (m, name) in objs), None) or obj(mods[0], name)
        part = o.val.get('&ParameterType') if (o is not None and pf != 'NULL') else None
        errcat.append((code, name, part))

    def enc(t, v):
        return sc.encode(t, v).bytes() or b'\x00'

    def addr():
        v, _ = gen(types['AliasAddress'], 3, 0.3, 0.5)
        return v

    recorded = []
    sport = [30000]
    def facility(apdus_h4501, from_dest=False, sp=None):
        """H.225 Facility with the given H4501 octet strings, sent in Q.931/TPKT/TCP"""
        g = asnper.Gen(sc, rng, set(), skip=SKIP); g.p_opt = 0.0; g.p_ext = 0.0
        pdu = g.gen(uupdu, 3, '')
        a = [x for x in list(body_t.elt_list) + list(body_t.ext_list) if x.name == 'facility'][0]
        pdu['h323-message-body'] = ('facility', g.gen(a, 3, ''))
        pdu['h4501SupplementaryService'] = apdus_h4501
        u = sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes()
        recorded.append((apdus_h4501, u))
        sport[0] += 1
        p.tcp(EP1, EP2, sp or sport[0], 1720, tpkt(q931(0x62, u, callref=sport[0] & 0x7fff)))

    iid = [0]
    def nextid():
        iid[0] += 1
        return iid[0]

    # ------------------------------------------------------------------
    mark('Invoke APDUs of every operation of the H.450 table with random arguments (kept when they add coverage)')
    invs = []
    for code, name, argt, rest, noarg, nores in catalogue:
        kept = 0
        for attempt in range(60):
            if kept >= (4 if argt is not None else 2): break
            if argt is not None:
                v, g = gen(argt, rng.choice((3, 4, 5, 6)), rng.choice((0.2, 0.6, 0.9)), rng.choice((0.3, 0.6, 0.9)))
                if kept > 0 and not g.new: continue
                covered.update(g.new)
                a = enc(argt, v)
            else:
                a = None if kept == 0 else b'\x00'     # no argument / an argument the table does not know
            i = nextid()
            invs.append((i, code, a))
            kept += 1
    # targeted: the optional extension of checkRestriction, whose random chance is small
    for code, name, argt, rest, noarg, nores in catalogue:
        if name not in ('checkRestriction', 'divertingLegInformation3'):
            continue
        for attempt in range(400):
            v, g = gen(argt, 5, 0.9, 0.97)
            if 'extension' in v:
                invs.append((nextid(), code, enc(argt, v)))
                break
    # three APDUs of different operations per H.225 message; a few with a network facility extension
    k = 0
    while k < len(invs):
        n = 1 + (k % 3)
        grp = invs[k:k + n]; k += n
        h = _ros.service(sc, types, [(lambda w, i=i, c=c, a=a: _ros.invoke(w, i, ('local', c), a)) for i, c, a in grp],
                         nfe=(('endpoint', addr(), 'anyEntity', None) if k % 5 == 0 else None),
                         interp=(k % 3 if k % 4 == 0 else None))
        facility([h])
    mark('ReturnResult APDUs of every operation that has a result type')
    ress = []
    for code, name, argt, rest, noarg, nores in catalogue:
        if rest is None and nores:
            # table has no result type: empty result and a result with data (UNSUPPORTED RESULT TYPE)
            ress.append((code, None))
            if len([1 for _, r in ress if r == b'\x01\x02']) < 3:
                ress.append((code, b'\x01\x02'))        # data for a result the table does not know: UNSUPPORTED RESULT TYPE
            continue
        if rest is None:
            continue
        kept = 0
        for attempt in range(60):
            if kept >= 3: break
            v, g = gen(rest, rng.choice((3, 4, 5, 6)), rng.choice((0.2, 0.6, 0.9)), rng.choice((0.3, 0.6, 0.9)))
            if kept > 0 and not g.new: continue
            covered.update(g.new)
            ress.append((code, enc(rest, v)))
            kept += 1
    for k in range(0, len(ress), 3):
        grp = ress[k:k + 3]
        h = _ros.service(sc, types, [(lambda w, c=c, r=r, i=nextid(): _ros.result(w, i, ('local', c) if r is not None else None, r)) for c, r in grp])
        facility([h], from_dest=True)
    mark('ReturnError APDUs of every error code of the table, with and without a parameter')
    errs_l = []
    for code, name, part in errcat:
        kept = 0
        for attempt in range(40):
            if kept >= (3 if part is not None else 2): break
            if part is not None:
                v, g = gen(part, rng.choice((3, 4, 5)), rng.choice((0.2, 0.8)), rng.choice((0.3, 0.9)))
                if kept > 0 and not g.new: continue
                covered.update(g.new)
                errs_l.append((code, enc(part, v)))
            else:
                errs_l.append((code, None if (kept == 0 or len([1 for _, r in errs_l if r == b'\x00\x01']) >= 3) else b'\x00\x01'))
            kept += 1
    for k in range(0, len(errs_l), 3):
        grp = errs_l[k:k + 3]
        h = _ros.service(sc, types, [(lambda w, c=c, r=r, i=nextid(): _ros.error(w, i, ('local', c), r)) for c, r in grp])
        facility([h], from_dest=True)
    mark('Unknown local and global (object identifier) operation and error codes, linked ids, rejects')
    unk = [
        lambda w: _ros.invoke(w, nextid(), ('local', 4242), b'\x00\x01\x02'),
        lambda w: _ros.invoke(w, nextid(), ('global', [1, 3, 6, 1, 4, 1, 9999, 1]), b'\x05'),
        lambda w: _ros.invoke(w, nextid(), ('local', 9), None, linked=3),
        lambda w: _ros.result(w, nextid(), ('local', 4242), b'\x00\x01'),
        lambda w: _ros.result(w, nextid(), ('global', [1, 3, 6, 1, 4, 1, 9999, 1]), b'\x05'),
        lambda w: _ros.result(w, nextid()),
        lambda w: _ros.error(w, nextid(), ('local', 4243), b'\x00'),
        lambda w: _ros.error(w, nextid(), ('global', [1, 3, 6, 1, 4, 1, 9999, 2]), None),
    ]
    for a in unk:
        facility([_ros.service(sc, types, [a])])
    for kind, probs in (('general', (0, 1, 2, 7)), ('invoke', range(0, 8)), ('returnResult', range(0, 3)),
                        ('returnError', range(0, 5))):
        for pr in probs:
            facility([_ros.service(sc, types, [lambda w, kind=kind, pr=pr: _ros.reject(w, nextid(), kind, pr)])])
    mark('Network facility extensions (entity types, addresses) and interpretation APDUs; several h4501SupplementaryService items in one UU-PDU')
    for se in ('endpoint', 'anyEntity'):
        for de in ('endpoint', 'anyEntity'):
            for ip in (None, 0, 1, 2):
                f = lambda w: _ros.invoke(w, nextid(), ('local', 7), enc(types['DummyArg'], ('extensionSeq', [])))
                facility([_ros.service(sc, types, [f], nfe=(se, addr(), de, addr() if ip != 1 else None), interp=ip)])
    dummy = enc(types['DummyArg'], ('extensionSeq', []))
    ctres = enc(types['CTIdentifyRes'], gen(types['CTIdentifyRes'], 4, 0.3, 0.5)[0])
    two = [_ros.service(sc, types, [lambda w: _ros.invoke(w, nextid(), ('local', 7), dummy)]),
           _ros.service(sc, types, [lambda w: _ros.result(w, nextid(), ('local', 7), ctres),
                                    lambda w: _ros.error(w, nextid(), ('local', 5), None)])]
    facility(two)
    p.write(os.path.join(out, 'h450-coverage.pcap'))

    # ---------------------------------------------------- malformed ----
    mq = Pcap(); mq.ts = 1700100000.0
    step = max(1, len(recorded) // 50)
    for i, (hl, u) in enumerate(recorded[::step]):
        h = hl[0]
        cut = 1 + (i * 5) % max(1, len(h) - 1)
        g = asnper.Gen(sc, rng, set(), skip=SKIP); g.p_opt = 0.0; g.p_ext = 0.0
        pdu = g.gen(uupdu, 3, '')
        a = [x for x in list(body_t.elt_list) + list(body_t.ext_list) if x.name == 'facility'][0]
        pdu['h323-message-body'] = ('facility', g.gen(a, 3, ''))
        pdu['h4501SupplementaryService'] = [h[:cut]]
        uu = sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes()
        mq.tcp(EP1, EP2, 6000 + i, 1720, tpkt(q931(0x62, uu)))
    mq.write(os.path.join(out, 'h450-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))
    print(len(p.frames), 'frames,', len(mq.frames), 'malformed;', len(catalogue), 'ops,', len(errcat), 'errors')

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
