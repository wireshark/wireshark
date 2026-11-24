#!/usr/bin/env python3
# Generates test/captures/q932_ros_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Q.932 ROS coverage captures. Usage: mkq932-ros.py <outdir> [-v]

q932-ros-coverage.pcap: Q.931 FACILITY messages
in LAPD frames (link type LINUX_LAPD, SAPI 0) whose Facility IE carries
Remote Operations Service Element components (packet-q932-ros.c): invoke,
return result, return error and reject in every form (invoke id present or
absent, linked id, local and global operation and error codes, with and
without argument/result/parameter, every problem value), including
components for operations that QSIG knows (so the argument is dispatched),
operations nobody registered ("Undecoded") and several components in one
Facility IE. Everything is built with struct (one QSIG argument comes from
berschema.py). All values are made up.
q932-ros-coverage-malformed.pcap: damaged and cut components."""
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
sc = Schema(SRC, "qsig", seed=4488)
text = sc.src
random.seed(4488)
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
    for _ in range(80):
        a = sc.enc(fn)
        if len(a) <= limit:
            return a
    return a

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
    lk = tlv(2, 0, False, integer(linked)[2:]) if linked is not None else b''
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
    known = [o for o in OPS if o[2]]
    NOARG = OPS[0][0]
    ARGB = fit(typ(OPS[0][2]))
    NORES = [o for o in OPS if o[3]][0]
    RESB = fit(typ(NORES[3]))
    NORES = NORES[0]
    def arg(i):
        op, name, a, r = known[i % len(known)]
        return op, fit(typ(a))
    absent = lambda: tlv(0, 5, False, b'')
    # ---- invoke
    for i in range(6):
        op, a = arg(i * 7)
        add([invoke(nid(), op, a)], 'invoke, local opcode %d with its argument' % op)
    add([invoke(nid(), NOARG, ARGB)], 'invoke, local opcode (%d)' % NOARG)
    add([invoke(nid(), 800, tlv(0, 16, True, integer(1)))], 'invoke, unregistered local opcode (undecoded)')
    add([invoke(nid(), 1234567, tlv(0, 16, True, b''))], 'invoke, large local opcode')
    for i in range(3):
        op, a = arg(i * 11 + 2)
        add([invoke(nid(), op, a, glob=True)], 'invoke, global opcode 1.3.12.9.%d with its argument' % op)
    add([invoke(nid(), 900, tlv(0, 16, True, b''), glob=True)], 'invoke, global opcode that no one registered')
    add([tlv(2, 1, True, integer(5) + oid([2, 5, 4, 3]) + tlv(0, 16, True, b''))], 'invoke, global opcode 2.5.4.3')
    add([tlv(2, 1, True, integer(6) + oid([1, 2, 840, 113549, 1, 1, 5]) + tlv(0, 16, True, b''))], 'invoke, long global opcode')
    add([tlv(2, 1, True, absent() + integer(NOARG) + ARGB)], 'invoke, absent invoke id')
    for v in (0, 1, 127, 128, 255, 256, 32767, 65536, -1, -129):
        add([tlv(2, 1, True, integer(v) + integer(NOARG) + ARGB)], 'invoke id %d' % v)
    for lk in (1, 300):
        op, a = arg(5)
        add([invoke(nid(), op, a, linked=lk)], 'invoke, linked id %d' % lk)
    add([tlv(2, 1, True, integer(9) + tlv(2, 1, False, b'') + integer(NOARG) + ARGB)], 'invoke, linked id absent (NULL)')
    # ---- return result
    for i in range(4):
        r_ops = [o for o in OPS if o[3]]
        op, name, a, r = r_ops[(i * 5) % len(r_ops)]
        add([retres(nid(), op, fit(typ(r)))], 'result, local opcode %d with its result' % op, user=False)
    r_ops = [o for o in OPS if o[3]]
    op, name, a, r = r_ops[2]
    add([retres(nid(), op, fit(typ(r)), glob=True)], 'result, global opcode %d' % op, user=False)
    add([retres(nid(), 77, tlv(0, 16, True, integer(1)))], 'result, unregistered opcode (undecoded)', user=False)
    add([retres(nid(), 4)], 'result, opcode without result', user=False)
    add([retres(nid(), None)], 'result without opcode and result', user=False)
    add([tlv(2, 2, True, absent())], 'result, absent invoke id', user=False)
    add([tlv(2, 2, True, absent() + tlv(0, 16, True, integer(NORES) + RESB))], 'result, absent invoke id and opcode', user=False)
    # ---- return error
    for ec in (0, 1, 2, 3, 5, 8, 11, 25, 43, 1000):
        add([reterr(nid(), ec)], 'error, local code %d' % ec, user=False)
    for ec, name, p in [e for e in ERRS if e[2]][:3]:
        add([reterr(nid(), ec, fit(typ(p)))], 'error %d with its parameter' % ec, user=False)
    add([tlv(2, 3, True, integer(3) + oid([1, 3, 12, 9, 5]))], 'error, global code', user=False)
    add([tlv(2, 3, True, integer(3) + oid([1, 3, 12, 9, 5]) + tlv(0, 16, True, integer(1)))], 'error, global code with parameter', user=False)
    add([tlv(2, 3, True, absent() + integer(1))], 'error, absent invoke id', user=False)
    # ---- reject
    for kind, vals in ((0, (0, 1, 2, 3)), (1, (0, 1, 2, 3, 4, 5)), (2, (0, 1, 2, 3)), (3, (0, 1, 2, 3, 4, 5))):
        for v in vals:
            add([reject(nid(), kind, v)], 'reject, problem kind %d value %d' % (kind, v), user=False)
    add([reject(None, 0, 1)], 'reject, absent invoke id', user=False)
    # ---- several components, other messages and protocol profiles
    op0, a0 = arg(1); op1, a1 = arg(9)
    add([invoke(nid(), op0, a0), retres(nid(), NORES, RESB), reject(nid(), 1, 0)], 'invoke, result and reject in one Facility IE')
    add([invoke(nid(), op0, a0), invoke(nid(), op1, a1)], 'two invokes in one Facility IE')
    for mt, n in ((0x05, 'SETUP'), (0x01, 'ALERTING'), (0x07, 'CONNECT'), (0x45, 'DISCONNECT'), (0x4d, 'RELEASE'),
                  (0x5a, 'RELEASE COMPLETE'), (0x64, 'REGISTER')):
        add([invoke(nid(), op0, a0)], 'invoke in %s' % n, mtype=mt)
    return fr

def build_malformed():
    r = random.Random(77)
    L = Link(65)
    fr = []
    comps = []
    for op, name, a, rr in OPS[:40]:
        if a:
            comps.append(bytes(invoke(op + 1, op, fit(typ(a)))))
    comps.append(bytes(retres(3, 30))); comps.append(bytes(reterr(3, 4))); comps.append(bytes(reject(3, 1, 2)))
    comps.append(bytes(invoke(3, 4, glob=True)))
    for c in comps:
        for _ in range(2):
            cut = r.randrange(2, len(c))
            fr.append(L.msg([bytes(c[:cut])]))
    for c in comps:
        c = bytearray(c)
        for _ in range(3):
            c[r.randrange(2, len(c))] = r.randrange(256)
        fr.append(L.msg([bytes(c)]))
    fr.append(L.msg([tlv(2, 1, True, integer(5))]))
    fr.append(L.msg([tlv(2, 1, True, integer(5) + tlv(0, 4, False, b'x'))]))
    fr.append(L.msg([tlv(2, 4, True, integer(5) + tlv(2, 9, False, b'\x01'))]))
    fr.append(L.msg([tlv(2, 4, True, integer(5) + tlv(2, 1, False, b'\x01\x02'))]))
    return fr

def main():
    m = build_main()
    open(os.path.join(OUT, 'q932-ros-coverage.pcap'), 'wb').write(pcap(m))
    b = build_malformed()
    open(os.path.join(OUT, 'q932-ros-coverage-malformed.pcap'), 'wb').write(pcap(b))
    print('frames', len(m), 'malformed', len(b))
    if VERBOSE:
        for i, n in enumerate(notes, 1):
            print(i, n)

main()
