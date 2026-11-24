#!/usr/bin/env python3
# Generates test/captures/qsig_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the QSIG coverage captures. Usage: mkqsig.py <outdir> [-v]

qsig-coverage.pcap: Q.931 FACILITY (and SETUP, ALERTING, CONNECT, ...)
messages in LAPD frames (link type LINUX_LAPD, SAPI 0) whose Facility IE
carries ROSE components (Q.932): an invoke of every QSIG operation (local
opcode, and the global opcode 1.3.12.9.<n>), the return results, the
return errors with and without parameter, and the QSIG information
elements of codeset 4 (transit counter) and 5 (party category). QSIG is
the default Q.932 facility encoding, so local opcodes reach it at default
preferences. The arguments are encoded from the type tree read out of
packet-qsig.c (berschema.py); everything else is built with struct. All
values are made up.
qsig-coverage-malformed.pcap: damaged and cut components."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import random
from berschema import Schema, tlv

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv
SRC = os.environ.get('QSIG_C', os.path.join(SRCDIR, 'epan/dissectors/packet-qsig.c'))
sc = Schema(SRC, 'qsig', seed=4488)
text = sc.src
random.seed(4488)
# PSS1InformationElement carries a Q.931 information element: make them valid
GOOD_IES = [bytes([0x28, 3]) + b'abc', bytes([0x04, 3, 0x88, 0x90, 0xa3]), bytes([0x70, 4, 0x81]) + b'123',
            bytes([0x1e, 2, 0x80, 0x82]), bytes([0x14, 1, 0x0a])]
sc.fixed['dissect_qsig_PSS1InformationElement_U'] = lambda s_: GOOD_IES[s_.rng.randrange(len(GOOD_IES))]

def table(name):
    return re.search(r'static const qsig_%s_t qsig_%s_tab\[\] = \{(.*?)\n\};' % (name, name), text, re.S).group(1)

OPS = [(int(o), n, a if a != 'NULL' else None, r if r != 'NULL' else None)
       for n, o, a, r in re.findall(r'/\* ([\w-]+)\s*\*/ \{\s*(\d+), (\w+), (\w+) \}', table('op'))]
ERRS = [(int(c), n, p if p != 'NULL' else None)
        for n, c, p in re.findall(r'/\* ([\w -]+?)\s*\*/ \{\s*(\d+), (\w+) \}', table('err'))]

def typ(pdu):
    """dissect_X_PDU -> dissect_X (the type function the schema knows)"""
    name = pdu[len('dissect_'):-len('_PDU')]
    m = re.search(r'static int dissect_%s_PDU\(.*?\n\}\n' % re.escape(name), text, re.S)
    t = re.search(r'offset = (dissect_qsig_\w+)\(false', m.group(0))
    return t.group(1)

def fit(fn, limit=190):
    best = None
    for _ in range(120):
        a = sc.enc(fn)
        if len(a) <= limit:
            return a
        if best is None or len(a) < len(best):
            best = a
    return best

def integer(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return tlv(0, 2, False, v.to_bytes(n, 'big', signed=True))

def oid(arcs):
    out = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        b = [a & 0x7f]
        a >>= 7
        while a:
            b.insert(0, 0x80 | (a & 0x7f)); a >>= 7
        out += bytes(b)
    return tlv(0, 6, False, out)

def invoke(iid, op, arg=b'', glob=None, linked=None):
    code = oid([1, 3, 12, 9, op]) if glob else integer(op)
    lk = tlv(2, 0, False, integer(linked)) if linked is not None else b''
    return tlv(2, 1, True, integer(iid) + lk + code + arg)

def retres(iid, op, res=None, glob=False):
    b = integer(iid)
    if op is not None:
        b += tlv(0, 16, True, (oid([1, 3, 12, 9, op]) if glob else integer(op)) + (res or b''))
    return tlv(2, 2, True, b)

def reterr(iid, ec, par=b''):
    return tlv(2, 3, True, integer(iid) + integer(ec) + par)

def reject(iid, kind, val):
    return tlv(2, 4, True, (integer(iid) if iid is not None else tlv(0, 5, False, b'')) + tlv(2, kind, False, bytes([val])))

class Link:
    def __init__(self, tei=64):
        self.tei = tei
        self.ns = {0: 0, 1: 0}
        self.cref = 1

    def msg(self, comps, user_side=True, mtype=0x62, extra=b'', cref=None, pp=0x91, ies=b''):
        ie = (bytes([pp]) if pp is not None else b'') + b''.join(bytes(c) for c in comps)
        if len(ie) > 250:
            return None
        q931 = bytes([0x08, 0x01, (cref or self.cref) | (0x00 if user_side else 0x80), mtype]) + extra + \
            (bytes([0x1c, len(ie)]) + ie if pp is not None else b'') + ies
        return self.lapd(q931, user_side)

    def lapd(self, q931, user_side=True):
        d = 0 if user_side else 1
        ns = self.ns[d]; self.ns[d] = (ns + 1) % 128
        lapd = bytes([(0 << 2) | ((0 if user_side else 1) << 1), (self.tei << 1) | 1,
                      ns << 1, (self.ns[1 - d] << 1)])
        hdr = struct.pack('>HHH8sH', 3 if user_side else 4, 1, 0, bytes([0 if user_side else 1]) + b'\0' * 7, 0x0030)
        return hdr + lapd + q931

def pcap(frames):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 177)
    frames = [f for f in frames if f]
    for i, f in enumerate(frames):
        out += struct.pack('<IIII', 1000 + i, 0, len(f), len(f)) + f
    return out

notes = []
def build_main():
    L = Link()
    fr = []
    iid = [1]
    def nid():
        iid[0] = iid[0] % 120 + 1
        return iid[0]
    def add(comps, note, user=True, **kw):
        m = L.msg(comps, user, **kw)
        if m is None:
            return
        fr.append(m); notes.append(note)
    # invokes of every operation with an argument (3 encodings each, local opcodes)
    for rnd in range(3):
        for op, name, a, r in OPS:
            if a:
                add([invoke(nid(), op, fit(typ(a)))], 'invoke %d %s (%d)' % (op, name, rnd), user=(op & 1) == 0)
    # operations without an argument PDU: with an argument (unsupported) and without
    for op, name, a, r in OPS:
        if not a:
            add([invoke(nid(), op, tlv(0, 16, True, integer(1) + integer(2)))], 'invoke %d %s with an unsupported argument' % (op, name))
            add([invoke(nid(), op)], 'invoke %d %s without argument' % (op, name))
    # global opcodes 1.3.12.9.n for every operation (once)
    for op, name, a, r in OPS:
        add([invoke(nid(), op, fit(typ(a)) if a else b'', glob=True)], 'invoke %d %s, global opcode' % (op, name))
    # return results
    for rnd in range(3):
        for op, name, a, r in OPS:
            if r:
                add([retres(nid(), op, fit(typ(r)))], 'result %d %s (%d)' % (op, name, rnd), user=False)
    for op, name, a, r in OPS:
        if r:
            add([retres(nid(), op, fit(typ(r)), glob=True)], 'result %d %s, global opcode' % (op, name), user=False)
    for op, name, a, r in [o for o in OPS if not o[3]][:6]:
        add([retres(nid(), op, tlv(0, 16, True, integer(7)))], 'result %d %s with an unsupported result' % (op, name), user=False)
    for op, name, a, r in [o for o in OPS if not o[3]][:3]:
        add([retres(nid(), op)], 'result %d %s without result' % (op, name), user=False)
    add([retres(nid(), None)], 'result without operation', user=False)
    # return errors
    for ec, name, p in ERRS:
        if p and ec == 1008:
            continue
        if p:
            for _ in range(2):
                add([reterr(nid(), ec, fit(typ(p)))], 'error %d %s with parameter' % (ec, name), user=False)
        else:
            add([reterr(nid(), ec)], 'error %d %s' % (ec, name), user=False)
    for ec, name, p in [e for e in ERRS if not e[2]][:4]:
        add([reterr(nid(), ec, tlv(0, 16, True, integer(3)))], 'error %d %s with an unsupported parameter' % (ec, name), user=False)
    add([reterr(nid(), 9999)], 'error with an unknown code', user=False)
    # an operation that QSIG does not know (undecoded) and an unknown global opcode
    add([invoke(nid(), 900, tlv(0, 16, True, b''))], 'invoke of an operation QSIG does not know')
    add([invoke(nid(), 901, tlv(0, 16, True, b''), glob=True)], 'invoke with an unknown global opcode')
    add([retres(nid(), 900, tlv(0, 16, True, b''))], 'result of an operation QSIG does not know', user=False)
    # linked invokes, several components in one Facility IE, rejects
    ops = [o for o in OPS if o[2]]
    add([invoke(nid(), ops[0][0], fit(typ(ops[0][2])), linked=3), invoke(nid(), ops[1][0], fit(typ(ops[1][2]))),
         retres(nid(), OPS[0][0])], 'invoke with linked id, a second invoke and a result in one IE')
    for kind, vals in ((0, (0, 1, 2)), (1, (0, 1, 2, 3, 4)), (2, (0, 1, 2)), (3, (0, 1, 2, 3))):
        for v in vals:
            add([reject(nid(), kind, v)], 'reject kind %d problem %d' % (kind, v), user=False)
    add([reject(None, 0, 1)], 'reject without invoke id', user=False)
    # the same components in other messages (SETUP, ALERTING, CONNECT, DISCONNECT, RELEASE, REGISTER)
    for mt, n in ((0x05, 'SETUP'), (0x01, 'ALERTING'), (0x07, 'CONNECT'), (0x45, 'DISCONNECT'), (0x4d, 'RELEASE'),
                  (0x5a, 'RELEASE COMPLETE'), (0x64, 'REGISTER'), (0x03, 'PROGRESS')):
        op, name, a, r = ops[len(notes) % len(ops)]
        add([invoke(nid(), op, fit(typ(a)))], 'invoke %s in %s' % (name, n), mtype=mt)
    # Q.931 information elements of QSIG: codeset 4 transit counter, codeset 5 party category
    for tc in (0x01, 0x05, 0xff):
        add([], 'codeset 4 transit counter %d' % tc, pp=None, mtype=0x05, ies=bytes([0x94, 0x31, 1, tc]))
    add([], 'codeset 4 transit counter, empty', pp=None, mtype=0x05, ies=bytes([0x94, 0x31, 0]))
    for pc in (0x00, 0x01, 0x02, 0x03, 0x08, 0xff):
        add([], 'codeset 5 party category %d' % pc, pp=None, mtype=0x05, ies=bytes([0x95, 0x32, 1, pc]))
    add([], 'codeset 5 party category, empty', pp=None, mtype=0x05, ies=bytes([0x95, 0x32, 0]))
    add([], 'codeset 4 unknown IE 0x30', pp=None, mtype=0x05, ies=bytes([0x94, 0x30, 2, 1, 2]))
    add([], 'codeset 5 unknown IE 0x33', pp=None, mtype=0x05, ies=bytes([0x95, 0x33, 2, 1, 2]))
    add([], 'transit counter and party category together', pp=None, mtype=0x05, ies=bytes([0x94, 0x31, 1, 3, 0x95, 0x32, 1, 2]))
    return fr

def build_malformed():
    r = random.Random(932)
    L = Link(65)
    fr = []
    comps = []
    for op, name, a, rr in OPS:
        if a:
            comps.append(bytes(invoke(op + 1, op, fit(typ(a)))))
    for c in comps:
        c = bytearray(c)
        cut = r.randrange(4, len(c))
        fr.append(L.msg([bytes(c[:cut])]))
    for c in comps:
        c = bytearray(c)
        for _ in range(3):
            c[r.randrange(5, len(c))] = r.randrange(256)
        fr.append(L.msg([bytes(c)]))
    for op, name, a, rr in OPS:
        if rr:
            c = bytearray(retres(op, op, fit(typ(rr))))
            c[r.randrange(5, len(c))] ^= 0x55
            fr.append(L.msg([bytes(c)], False))
            c = bytearray(retres(op, op, fit(typ(rr))))
            fr.append(L.msg([bytes(c[:r.randrange(4, len(c))])], False))
    for ec, name, p in ERRS:
        if p:
            c = bytearray(reterr(ec, ec, fit(typ(p))))
            fr.append(L.msg([bytes(c[:r.randrange(4, len(c))])], False))
    for ec, name, p in ERRS:
        if p and ec == 1008:
            for _ in range(3):
                fr.append(L.msg([reterr(9, ec, fit(typ(p)))], False))
    fr.append(L.msg([retres(5, 30)], False))
    fr.append(L.msg([invoke(5, 4, b'\x30\x80\x00\x00')]))
    return fr

def main():
    m = build_main()
    open(os.path.join(OUT, 'qsig-coverage.pcap'), 'wb').write(pcap(m))
    b = build_malformed()
    open(os.path.join(OUT, 'qsig-coverage-malformed.pcap'), 'wb').write(pcap(b))
    print('frames', len(m), 'malformed', len(b), 'ops', len(OPS), 'errs', len(ERRS))
    if VERBOSE:
        for i, n in enumerate(notes, 1):
            print(i, n)

main()
