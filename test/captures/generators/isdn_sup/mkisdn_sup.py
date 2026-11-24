#!/usr/bin/env python3
# Generates test/captures/isdn_sup_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ISDN-SUP coverage captures. Usage: mkisdn_sup.py <outdir>

isdn_sup-coverage.pcap: Q.931 FACILITY messages in LAPD frames (link type
LINUX_LAPD) that carry ETSI supplementary services components (ROSE):
invoke, return result and return error for every operation and error of
packet-isdn-sup.c, the Freephone operations with global opcodes, and
components for operations that have no argument/result PDU. The ETSI
operations (local opcodes) are only dispatched with the Q.932 preference
q932.facility_encoding:ETSI; the global opcodes are reached at default
preferences.
isdn_sup-coverage-malformed.pcap: damaged components.

The arguments are encoded from the type tree read out of packet-isdn-sup.c
(berschema.py); LAPD, Q.931 and ROSE framing is built here with struct.
All values are made up."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys
import random
from berschema import Schema, tlv

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get('ISDN_SUP_C', os.path.join(SRCDIR, 'epan/dissectors/packet-isdn-sup.c'))
sc = Schema(SRC, 'isdn_sup', seed=774)
text = sc.src


def pdu_type(name):
    """dissect_XArg_PDU -> dissect_isdn_sup_XArg"""
    m = re.search(r'static int dissect_%s_PDU\(.*?\n\}\n' % name, text, re.S)
    t = re.search(r'offset = (dissect_isdn_sup_\w+)\(false', m.group(0))
    return t.group(1)


OPS = [(int(o), n, a if a != 'NULL' else None, r if r != 'NULL' else None)
       for n, o, a, r in re.findall(r'/\* ([\w-]+)\s*\*/ \{\s*(\d+), (\w+), (\w+) \}',
                                    re.search(r'static const isdn_sup_op_t isdn_sup_op_tab\[\] = \{(.*?)\n\};', text, re.S).group(1))]
ERRS = [(int(c), n) for n, c in re.findall(r'/\* ([\w-]+)\s*\*/ \{\s*(\d+), NULL \}',
                                           re.search(r'static const isdn_sup_err_t isdn_sup_err_tab\[\] = \{(.*?)\n\};', text, re.S).group(1))]
GLOBALS = [(int(k), n, a) for n, k, a in re.findall(r'/\* ([\w-]+)\s*\*/ \{ fPHOID"\.(\d+)", (\w+), NULL \}',
                                                 re.search(r'static const isdn_sup_global_op_t isdn_sup_global_op_tab\[\] = \{(.*?)\n\};', text, re.S).group(1))]


def typ(pdu):
    return pdu_type(pdu[len('dissect_'):-len('_PDU')])


def fit(fn, limit=170):
    for _ in range(60):
        a = sc.enc(fn)
        if len(a) <= limit:
            return a
    return a


def integer(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return tlv(0, 2, False, v.to_bytes(n, 'big', signed=True))


def invoke(iid, op, arg=b'', glob=None):
    code = tlv(0, 6, False, glob) if glob else integer(op)
    return tlv(2, 1, True, integer(iid) + code + arg)


def retres(iid, op, res=None):
    b = integer(iid)
    if op is not None:
        b += tlv(0, 16, True, integer(op) + (res or b''))
    return tlv(2, 2, True, b)


def reterr(iid, ec, par=b''):
    return tlv(2, 3, True, integer(iid) + integer(ec) + par)


def reject(iid, kind, val):
    return tlv(2, 4, True, integer(iid) + tlv(2, kind, False, bytes([val])))


def fph_oid(k):
    return bytes([0x04, 0x00, 0x81, 0x52, 0x01, k])      # 0.4.0.210.1.k


# ---- LAPD / Q.931
class Link:
    def __init__(self, tei=64):
        self.tei = tei
        self.ns = {0: 0, 1: 0}
        self.cref = 1

    def facility(self, comps, user_side=True, msg=0x62, extra=b'', cref=None):
        ie = bytes([0x91]) + b''.join(comps)
        q931 = bytes([0x08, 0x01, (cref or self.cref) | (0x00 if user_side else 0x80), msg]) + extra + \
            bytes([0x1c, len(ie)]) + ie
        d = 0 if user_side else 1
        ns = self.ns[d]; self.ns[d] = (ns + 1) % 128
        # LAPD: SAPI 0, C/R by direction, I frame
        lapd = bytes([(0 << 2) | ((0 if user_side else 1) << 1), (self.tei << 1) | 1,
                      ns << 1, (self.ns[1 - d] << 1)])
        hdr = struct.pack('>HHH8sH', 3 if user_side else 4, 1, 0, bytes([0 if user_side else 1]) + b'\0' * 7, 0x0030)
        return hdr + lapd + q931


def pcap(frames):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 177)
    for i, f in enumerate(frames):
        out += struct.pack('<IIII', 1000 + i, 0, len(f), len(f)) + f
    return out


def build_main():
    L = Link()
    fr = []
    iid = [1]

    def nid():
        iid[0] = iid[0] % 120 + 1
        return iid[0]

    def add(comps, user=True, **kw):
        fr.append(L.facility(comps, user, **kw))

    # invokes of every operation (three encodings each)
    for rnd in range(3):
        for op, name, a, r in OPS:
            if a:
                add([invoke(nid(), op, fit(typ(a)))], user=(op & 1) == 0)
    # operations without an argument PDU, with an argument: the
    # "unsupported argument type" expert info ("ISDN-SUP: Use the argument
    # type expert info for unsupported arguments"), and without argument
    for op, name, a, r in OPS:
        if not a:
            add([invoke(nid(), op, tlv(0, 16, True, integer(1) + integer(2)))])
            add([invoke(nid(), op)])
    # return results of every operation that has a result PDU
    for rnd in range(3):
        for op, name, a, r in OPS:
            if r:
                add([retres(nid(), op, fit(typ(r)))], user=False)
    # return results with a body for operations without result PDU
    # (unsupported result type), and results without a body
    for op, name, a, r in [o for o in OPS if not o[3]][:4]:
        add([retres(nid(), op, tlv(0, 16, True, integer(7)))], user=False)
    add([retres(nid(), None)], user=False)
    # return errors with and without a parameter (unsupported error type)
    for ec, name in ERRS:
        add([reterr(nid(), ec)], user=False)
    for ec, name in ERRS[:4]:
        add([reterr(nid(), ec, tlv(0, 16, True, integer(3)))], user=False)
    # Freephone operations with global opcodes
    for rnd in range(3):
        for k, name, a in GLOBALS:
            add([invoke(nid(), 0, fit(typ(a)), glob=fph_oid(k))])
    # global opcode that no one registered
    add([invoke(nid(), 0, tlv(0, 16, True, b''), glob=fph_oid(9))])
    # several components in one Facility IE; rejects
    ops = [o for o in OPS if o[2]]
    add([invoke(nid(), ops[0][0], fit(typ(ops[0][2]))), invoke(nid(), ops[1][0], fit(typ(ops[1][2], ))),
         retres(nid(), 30, fit(typ(OPS[0][3])))])
    for kind, vals in ((0, (0, 1, 2)), (1, (0, 1, 2, 3, 4)), (2, (0, 1, 2)), (3, (0, 1, 2, 3))):
        for v in vals:
            add([reject(nid(), kind, v)], user=False)
    # the same messages from the network side with a dummy call reference
    # and a REGISTER message (a facility IE in other messages)
    add([invoke(nid(), 7, fit(typ(dict((o, a) for o, n, a, r in OPS)[7])))], user=False, msg=0x64, cref=0)
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
        fr.append(L.facility([bytes(c[:cut])]))
    for c in comps:
        c = bytearray(c)
        for _ in range(3):
            c[r.randrange(5, len(c))] = r.randrange(256)
        fr.append(L.facility([bytes(c)]))
    fr.append(L.facility([retres(5, 30)], False))      # opcode, no result: empty choice
    for op, name, a, rr in OPS:
        if rr:
            c = bytearray(retres(op, op, fit(typ(rr))))
            c[r.randrange(5, len(c))] ^= 0x55
            fr.append(L.facility([bytes(c)], False))
    return fr


def main(out):
    m = build_main()
    open(os.path.join(out, 'isdn_sup-coverage.pcap'), 'wb').write(pcap(m))
    print('main capture: %d frames' % len(m))
    b = build_malformed()
    open(os.path.join(out, 'isdn_sup-coverage-malformed.pcap'), 'wb').write(pcap(b))
    print('malformed capture: %d frames' % len(b))


if __name__ == '__main__':
    main(sys.argv[1])
