#!/usr/bin/env python3
# Generates test/captures/q932_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Q.932 coverage captures. Usage: mkq932.py <outdir> [-v]

q932-coverage.pcap: Q.931 messages in LAPD frames (link type LINUX_LAPD, SAPI 0)
with Q.932 information elements: Facility IEs (protocol profiles ROSE,
CMIP, ACSE, networking extensions; the Network Facility Extension, Network
Protocol Profile and Interpretation components; DSE and ACSE APDUs and
unknown components, which are "not supported" expert infos; ROSE invokes of
QSIG operations whose arguments use the addressing data elements of Q.932)
and Notification indicator IEs. Q.932 is reached by the Q.931 IE table, QSIG
is the default facility encoding. The addressing types are encoded from the
type tree read out of packet-qsig.c and packet-q932.c (berschema.py);
everything else is built with struct. All values are made up.
q932-coverage-malformed.pcap: damaged components."""
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
s9 = Schema(os.path.join(SRCDIR, 'epan/dissectors/packet-q932.c'), 'q932', seed=932)
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


GOOD_IES = [bytes([0x28, 3]) + b'abc', bytes([0x04, 3, 0x88, 0x90, 0xa3]), bytes([0x70, 4, 0x81]) + b'123',
            bytes([0x1e, 2, 0x80, 0x82]), bytes([0x14, 1, 0x0a])]
sc.fixed['dissect_qsig_PSS1InformationElement_U'] = lambda s_: GOOD_IES[s_.rng.randrange(len(GOOD_IES))]

def party():
    return fit9('dissect_q932_PartyNumber')

def fit9(fn, limit=100):
    best = None
    for _ in range(80):
        a = s9.enc(fn)
        if len(a) <= limit:
            return a
        if best is None or len(a) < len(best):
            best = a
    return best

def nfe(src=0, dst=1, with_addr=True):
    body = tlv(2, 0, False, bytes([src]))
    if with_addr:
        body += tlv(2, 1, True, party())
    body += tlv(2, 2, False, bytes([dst]))
    if with_addr:
        body += tlv(2, 3, True, party())
    return tlv(2, 10, True, body)

def npp(v):
    return tlv(2, 18, False, bytes([v]))

def interp(v):
    return tlv(2, 11, False, bytes([v]))

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
    # Network Facility Extension, with and without addresses
    for i in range(4):
        add([nfe(i & 1, (i >> 1) & 1)], 'network facility extension with addresses (%d)' % i)
    add([nfe(0, 1, False)], 'network facility extension without addresses')
    # Network Protocol Profile
    for v in (19, 32, 0, 254):
        add([npp(v)], 'network protocol profile %d' % v)
    # Interpretation component
    for v in (0, 1, 2, 3):
        add([interp(v)], 'interpretation component %d' % v)
    # combined: NFE + NPP + interpretation + ROSE invoke
    known = [o for o in OPS if o[2]]
    for i in range(6):
        op, name, a, r = known[(i * 13) % len(known)]
        add([nfe(), npp(19), interp(i % 3), invoke(nid(), op, fit(typ(a)))], 'NFE, NPP, interpretation and invoke of %s' % name)
    # protocol profiles
    op, name, a, r = known[0]
    for pp, n in ((0x91, 'ROSE'), (0x92, 'CMIP'), (0x93, 'ACSE'), (0x9f, 'networking extensions'), (0x80, 'unknown 0x80'), (0x95, 'unknown 0x95')):
        add([invoke(nid(), op, fit(typ(a)))], 'invoke with protocol profile %s' % n, pp=pp)
    # DSE and ACSE APDUs, unknown components
    for tag, n in ((12, 'begin'), (14, 'end'), (15, 'continue'), (17, 'abort')):
        add([tlv(2, tag, True, b'\x01\x02\x03')], 'DSE %s APDU (not supported)' % n)
    for tag, n in ((0, 'aarq'), (1, 'aare'), (2, 'rlrq'), (3, 'rlre'), (4, 'abrt')):
        add([tlv(1, tag, True, b'\x01\x02\x03')], 'ACSE %s APDU (not supported)' % n)
    add([tlv(2, 20, True, b'\x01')], 'unknown context component 20')
    add([tlv(2, 9, False, b'\x01')], 'unknown context component 9')
    add([tlv(1, 9, True, b'\x01')], 'unknown application component 9')
    add([tlv(0, 16, True, b'\x02\x01\x01')], 'universal SEQUENCE component')
    add([tlv(3, 4, True, b'\x01')], 'private class component')
    # ROSE components: invoke, result, error, reject (local opcodes -> QSIG)
    for i in range(4):
        op, name, a, r = known[(i * 17 + 3) % len(known)]
        add([invoke(nid(), op, fit(typ(a)))], 'invoke %s' % name)
    r_ops = [o for o in OPS if o[3]]
    for i in range(3):
        op, name, a, r = r_ops[(i * 7) % len(r_ops)]
        add([retres(nid(), op, fit(typ(r)))], 'result %s' % name, user=False)
    add([reterr(nid(), 1)], 'error 1', user=False)
    add([reject(nid(), 1, 0)], 'reject', user=False)
    # every operation once: their arguments use the addressing data elements
    for op, name, a, r in OPS:
        if a:
            add([invoke(nid(), op, fit(typ(a)))], 'invoke %d %s (all operations)' % (op, name))
    # empty Facility IE (only the protocol profile)
    add([], 'Facility IE with only a protocol profile')
    # Facility IE of length 0 and 1 handled by Q.931 / Q.932
    L2 = L
    fr.append(L2.lapd(bytes([0x08, 0x01, 0x01, 0x62, 0x1c, 0x00]))); notes.append('Facility IE of length 0')
    # Notification indicator
    for nd in (0, 1, 2, 4, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4f, 0x60, 0x68, 0x69, 0x6a, 0x6e, 0x6f, 0x74, 0x79, 0x7a, 0x7b, 0x03, 0x40, 0x22, 0x7f):
        fr.append(L.lapd(bytes([0x08, 0x01, 0x01, 0x6e, 0x27, 1, 0x80 | nd]))); notes.append('notification indicator %d' % nd)
    fr.append(L.lapd(bytes([0x08, 0x01, 0x01, 0x6e, 0x27, 2, 0x01, 0x82]))); notes.append('notification indicator, two octets (ext clear)')
    fr.append(L.lapd(bytes([0x08, 0x01, 0x01, 0x6e, 0x27, 3, 0x03, 0x01, 0x82]))); notes.append('notification indicator with ASN.1 data')
    fr.append(L.lapd(bytes([0x08, 0x01, 0x01, 0x6e, 0x27, 0]))); notes.append('notification indicator empty')
    fr.append(L.lapd(bytes([0x08, 0x01, 0x01, 0x6e, 0x27, 4, 0x01, 0x02, 0x03, 0x84]))); notes.append('notification indicator, long value')
    # Facility IE -> ROSE invoke callTransferComplete (12) whose basicCallInfoElements
    # (PSS1InformationElement) holds another Facility IE, nested as deep as the
    # one-octet IE length allows (re-entrancy of the file-scope ROS state)
    def blen(n):
        return bytes([n]) if n < 0x80 else bytes([0x81, n])
    def tl(t, v):
        return bytes([t]) + blen(len(v)) + v
    def fac(inner):
        arg = tl(0x30, bytes([0x0a, 0x01, 0x00, 0x81, 0x00]) + (tl(0x40, inner) if inner else b''))
        inv = tl(0xa1, bytes([0x02, 0x01, 0x01, 0x02, 0x01, 0x0c]) + arg)
        body = bytes([0x91]) + inv
        return bytes([0x1c, len(body)]) + body
    ie_ = b''
    depths = []
    while True:
        nxt = fac(ie_)
        if len(nxt) > 250:
            break
        ie_ = nxt
        depths.append(ie_)
    for d in (depths[0], depths[1], depths[len(depths) // 2], depths[-1]):
        fr.append(L.lapd(bytes([0x08, 0x02, 0x00, 0x01, 0x62]) + d)); notes.append('reproducer: nested Facility IEs, %d octets' % len(d))
    return fr

def build_malformed():
    r = random.Random(32)
    L = Link(65)
    fr = []
    comps = []
    for i in range(4):
        comps.append(bytes(nfe(i & 1, i >> 1)))
    comps.append(bytes(npp(19))); comps.append(bytes(interp(1)))
    for op, name, a, rr in OPS[:60]:
        if a:
            comps.append(bytes(invoke(op + 1, op, fit(typ(a)))))
    for c in comps:
        for _ in range(2):
            fr.append(L.msg([bytes(c[:r.randrange(2, len(c))])]))
        c = bytearray(c)
        for _ in range(3):
            c[r.randrange(2, len(c))] = r.randrange(256)
        fr.append(L.msg([bytes(c)]))
    fr.append(L.msg([b'\xaa']))
    fr.append(L.msg([b'\xaa\x85\x01']))
    fr.append(L.msg([b'\x1f']))
    fr.append(L.msg([bytes([0xa1, 0x81])]))
    fr.append(L.lapd(bytes([0x08, 0x01, 0x01, 0x62, 0x1c, 0x05, 0x91, 0xa1, 0x10])))
    for i in range(5):
        fr.append(L.lapd(bytes([0x08, 0x01, 0x01, 0x6e, 0x27, 5]) + bytes(r.randrange(256) for _ in range(5))))
    return fr

def main():
    m = build_main()
    open(os.path.join(OUT, 'q932-coverage.pcap'), 'wb').write(pcap(m))
    b = build_malformed()
    open(os.path.join(OUT, 'q932-coverage-malformed.pcap'), 'wb').write(pcap(b))
    print('frames', len(m), 'malformed', len(b))
    if VERBOSE:
        for i, n in enumerate(notes, 1):
            print(i, n)

main()
