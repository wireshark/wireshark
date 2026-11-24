#!/usr/bin/env python3
# Generates test/captures/gias_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gias.c.  Usage: mkgias.py <outdir> [-v]
GIAS is a generated CORBA dissector for the NSG GIAS IDL.  It is reached
(a) explicitly, when an IOR seen earlier maps an object key to
IDL:GIAS/<Interface>:1.0 (the registered modules), and (b) by the GIOP
heuristic by operation name.  The argument bodies are filler (zero octets or
00 00 00 01 words) of the smallest size the dissector accepts, found with
gias_disc.py; see gias_ops.py."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import util as u
from cdr import giop, iiop_profile, ior, reply_10, reply_12, request_10, request_12, sys_exc
from gias_ops import OPS, MODULES, REQ_N, REP_N

SRC, DST = '192.0.2.1', '192.0.2.2'

def key_of(mod): return ('gias-' + mod).encode()

def filler(kind, n, le=False):
    if kind == 0:
        return b'\0' * n
    w = b'\1\0\0\0' if le else b'\0\0\0\1'
    return (w * (n // 4 + 1))[:n]

class Gen:
    def __init__(self):
        self.o = []; self.rid = 1000
    def req(self, minor, key, op, body, le=False, sport=42000, dport=42001, resp=3):
        self.rid += 1
        if minor == 2:
            r = request_12(self.rid, ('key', key), op, (lambda c: c.raw(body)), le, flags=resp)
        else:
            r = request_10(self.rid, key, op, minor=minor, le=le, args_fn=lambda c: c.raw(body))
        self.o.append(u.udp(sport, dport, giop(minor, 0, r.bytes(), le)))
        return self.rid
    def rep(self, minor, rid, status, body_fn, le=False, sport=42001, dport=42000):
        r = (reply_12 if minor == 2 else reply_10)(rid, status, body_fn, le)
        self.o.append(u.udp(sport, dport, giop(minor, 1, r.bytes(), le), src=DST, dst=SRC))

def main_frames():
    g = Gen()
    # 1. IORs: Reply to "resolve" teaches the object key -> IDL:GIAS/<Interface>:1.0
    for m in MODULES:
        rid = g.req(2, b'naming', 'resolve', struct.pack('>I', 0))
        g.rep(2, rid, 0, lambda c, m=m: ior(c, 'IDL:%s:1.0' % m, [(0, iiop_profile('gias.example.test', 2809, key_of(m), 0))]))
    # 2. every operation of every interface, explicit dissection
    for pi, (op, mod) in enumerate(OPS):
        key = key_of(mod)
        for kind in (0, 1):
            rn = REQ_N.get('%d:%d' % (pi, kind)); pn = REP_N.get('%d:%d' % (pi, kind))
            if rn is None or pn is None:
                continue
            rid = g.req(2, key, op, filler(kind, rn))
            g.rep(2, rid, 0, lambda c, k=kind, n=pn: c.raw(filler(k, n)))
        # little endian
        rn = REQ_N.get('%d:1' % pi); pn = REP_N.get('%d:1' % pi)
        if rn is not None and pn is not None:
            rid = g.req(2, key, op, filler(1, rn, True), le=True)
            g.rep(2, rid, 0, lambda c, n=pn: c.raw(filler(1, n, True)), le=True)
    # 3. heuristic dissection (object key unknown): operations with a unique name
    from collections import Counter
    names = Counter(op for op, _ in OPS)
    for pi, (op, mod) in enumerate(OPS):
        if names[op] != 1:
            continue
        rn = REQ_N.get('%d:0' % pi); pn = REP_N.get('%d:0' % pi)
        if rn is None or pn is None:
            continue
        rid = g.req(2, b'unknown-key', op, filler(0, rn), sport=42100, dport=42101)
        g.rep(2, rid, 0, lambda c, n=pn: c.raw(filler(0, n)), sport=42101, dport=42100)
    # 4. user exceptions (UCO::ProcessingFault, SystemFault, InvalidInputParameter) and an unknown one
    pi = OPS.index(('create', 'GIAS/CreationMgr'))
    rn = REQ_N['%d:0' % pi]
    def details(c):
        c.string('ProcessingFault'); c.boolean(True); c.string('something went wrong')
    for exid, extra in (('IDL:UCO/ProcessingFault:1.0', None), ('IDL:UCO/SystemFault:1.0', None),
                        ('IDL:UCO/InvalidInputParameter:1.0', ['bad1', 'bad2']),
                        ('IDL:UCO/InvalidInputParameter:1.0', []), ('IDL:UCO/Unknown:1.0', None)):
        rid = g.req(2, key_of('GIAS/CreationMgr'), 'create', filler(0, rn))
        def body(c, exid=exid, extra=extra):
            c.string(exid); details(c)
            if extra is not None:
                c.ulong(len(extra))
                for s in extra: c.string(s)
        g.rep(2, rid, 1, body)
    # user exception on the heuristic path, GIOP 1.0
    rid = g.req(0, b'unknown-key', 'get_timeout', b'')
    g.rep(0, rid, 1, lambda c: (c.string('IDL:UCO/SystemFault:1.0'), details(c)))
    # system exception from a GIAS operation
    rid = g.req(2, key_of('GIAS/CreationMgr'), 'create', filler(0, rn))
    g.rep(2, rid, 2, lambda c: sys_exc(c))
    # a request for an operation GIAS does not have, on a GIAS object
    rid = g.req(2, key_of('GIAS/CreationMgr'), 'no_such_operation', b'\0\0\0\0')
    g.rep(2, rid, 0, lambda c: c.raw(b'\0\0\0\0'))
    # GIAS on TCP (IIOP)
    t = u.Conn(g.o, 43000, 2809)
    t.send(giop(2, 0, request_12(1, ('key', key_of('GIAS/CatalogMgr')), 'get_data_model_manager',
              lambda c: None).bytes()))
    t.recv(giop(2, 1, reply_12(1, 0, lambda c: ior(c, 'IDL:GIAS/DataModelMgr:1.0', [(0, iiop_profile('x', 1, b'dm', 0))])).bytes()))
    t.fin()
    return g.o

def mal_frames():
    g = Gen()
    for m in MODULES[:3]:
        rid = g.req(2, b'naming', 'resolve', struct.pack('>I', 0))
        g.rep(2, rid, 0, lambda c, m=m: ior(c, 'IDL:%s:1.0' % m, [(0, iiop_profile('gias.example.test', 2809, key_of(m), 0))]))
    # truncated arguments and replies for operations that take arguments
    for pi, (op, mod) in enumerate(OPS):
        rn = REQ_N.get('%d:0' % pi); pn = REP_N.get('%d:0' % pi)
        if mod not in MODULES[:3]:
            continue
        if rn:
            g.req(2, key_of(mod), op, b'\xff' * (rn - 4), sport=42200, dport=42201)
        if pn:
            rid = g.req(2, key_of(mod), op, filler(0, rn or 0), sport=42200, dport=42201)
            g.rep(2, rid, 0, lambda c, n=pn: c.raw(b'\xff' * (n - 4)), sport=42201, dport=42200)
    # huge sequence counts
    pi = [i for i, (op, m) in enumerate(OPS) if REQ_N.get('%d:0' % i, 0) > 0][0]
    op, mod = OPS[pi]
    g.req(2, key_of(mod), op, b'\xff' * REQ_N['%d:0' % pi], sport=42200, dport=42201)
    return g.o

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_frames()
    u.write_pcap(os.path.join(out, 'gias-coverage.pcap'), m)
    u.gz(os.path.join(out, 'gias-coverage.pcap'))
    mm = mal_frames()
    u.write_pcap(os.path.join(out, 'gias-coverage-malformed.pcap'), mm)
    if '-v' in sys.argv:
        print(len(m), len(mm))
