#!/usr/bin/env python3
# Helper module for the dcerpc_nspi capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""nspi_fuzzall.py: structured + biased random NSPI traffic over CO DCE/RPC/TCP.
Every opnum 0..20 request/response with random stubs, plus GetProps (9),
QueryRows (3), GetMatches (5) and GetHierarchyInfo (12) responses whose
SRow/SRowSet carry SPropValues of every property type (wire discriminator
sometimes != ulPropTag & 0xffff), with random counts and string lengths;
NDR and NDR64, LE and BE.  argv: [seed] [out.pcap]"""
import os
import random
import struct
import sys
from nspi_common import nspi_rpc, pcap, HANDLE, SETTINGS

seed = int(sys.argv[1]) if len(sys.argv) > 1 else 0
out = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(os.path.abspath(__file__))[0] + '.pcap'
rng = random.Random(seed)
V32 = [0, 1, 2, 3, 4, 8, 0x10, 0xff, 0x100, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff]
PT = [0, 1, 2, 3, 4, 5, 6, 7, 0xa, 0xb, 0xd, 0x14, 0x1e, 0x1f, 0x40, 0x48, 0x102,
      0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007, 0x1014, 0x101e, 0x101f, 0x1040, 0x1048, 0x1102, 0xffff]


def rnd(n):
    b = b''
    while len(b) < n:
        r = rng.random()
        if r < 0.4:
            b += struct.pack('<I', rng.choice(V32))
        elif r < 0.6:
            b += struct.pack('<I', 0x20000 + 4 * rng.randrange(64))
        else:
            b += bytes([rng.randrange(256)])
    return b[:n]


class W:
    def __init__(s):
        s.b = b''
        s.pid = 0x20000
    def u32(s, v):
        s.b += b'\0' * (-len(s.b) % 4) + struct.pack('<I', v & 0xffffffff)
    def ptr(s, null=False):
        if null:
            s.u32(0)
        else:
            s.pid += 4
            s.u32(s.pid)
    def raw(s, x):
        s.b += x
    def cnt(s, n):
        return n if rng.random() < 0.9 else rng.choice(V32)


def propvalue_fixed(w, deferred):
    """Write one SPropValue inline; append deferred writers."""
    t = rng.choice(PT)
    tag = (rng.randrange(0x3000, 0x3100) << 16) | t
    disc = t if rng.random() < 0.85 else rng.choice(PT)
    w.u32(tag); w.u32(0); w.u32(disc)
    n = rng.choice([0, 1, 2, 3, 5, 17])
    if disc in (2, 0xb):
        w.raw(struct.pack('<H', rng.randrange(65536)))
    elif disc in (3, 0xa, 1, 0xd):
        w.u32(rng.choice(V32))
    elif disc == 0x40:
        w.u32(1); w.u32(2)
    elif disc in (0x1e, 0x1f, 0x48):
        null = rng.random() < 0.1
        w.ptr(null)
        if not null:
            def d(w=w, disc=disc):
                if disc == 0x48:
                    w.raw(bytes(16))
                else:
                    sz = 1 if disc == 0x1e else 2
                    ln = rng.choice([0, 1, 3, 8])
                    w.u32(w_cnt(ln)); w.u32(rng.choice([0, 0, 1])); w.u32(w_cnt(ln))
                    w.raw(rnd(ln * sz))
            deferred.append(d)
    elif disc == 0x102:
        w.u32(n); null = rng.random() < 0.1; w.ptr(null)
        if not null:
            deferred.append(lambda: (w.u32(w_cnt(n)), w.raw(rnd(n))))
    elif disc in (0x1002, 0x1003, 0x1048, 0x101f, 0x1040):
        w.u32(n); w.ptr()
        esz = {0x1002: 2, 0x1003: 4, 0x1048: 4, 0x101f: 4, 0x1040: 8}[disc]
        deferred.append(lambda: (w.u32(w_cnt(n)), w.raw(rnd(n * esz))))
    elif disc == 0x101e:
        w.u32(n); w.ptr()
        def d():
            w.u32(w_cnt(n))
            for i in range(n):
                w.ptr(rng.random() < 0.1)
            for i in range(n):
                ln = rng.choice([0, 1, 4, 9])
                w.u32(w_cnt(ln)); w.u32(0); w.u32(w_cnt(ln)); w.raw(rnd(ln))
        deferred.append(d)
    elif disc == 0x1102:
        w.u32(n); w.ptr()
        def d():
            w.u32(w_cnt(n))
            lens = []
            for i in range(n):
                ln = rng.choice([0, 1, 4]); lens.append(ln)
                w.u32(ln); w.ptr(rng.random() < 0.1)
            for ln in lens:
                w.u32(w_cnt(ln)); w.raw(rnd(ln))
        deferred.append(d)
    else:
        w.raw(rnd(rng.choice([0, 4, 8])))


def w_cnt(n):
    return n if rng.random() < 0.9 else rng.choice(V32)


def srow(w, deferred):
    n = rng.choice([0, 1, 2, 4, 8])
    w.u32(0); w.u32(n); null = rng.random() < 0.05; w.ptr(null)
    if null:
        return
    def d():
        w.u32(w_cnt(n))
        dd = []
        for i in range(n):
            propvalue_fixed(w, dd)
        for f in dd:
            f()
    deferred.append(d)


def rowset(w):
    # SRowSet **: top ref, unique ptr, conformant struct (max_count first)
    w.ptr()
    n = rng.choice([0, 1, 2, 3])
    w.u32(w_cnt(n)); w.u32(n)
    dd = []
    for i in range(n):
        srow(w, dd)
    for f in dd:
        f()


def run_deferred(dd):
    for f in dd:
        f()


def maybe_trunc(b):
    r = rng.random()
    if r < 0.1:
        return b[:rng.randrange(len(b) + 1)]
    if r < 0.2:
        b = bytearray(b)
        for _ in range(rng.randrange(1, 4)):
            if b:
                b[rng.randrange(len(b))] = rng.randrange(256)
        return bytes(b)
    return b


frames = []
port = 50100
for le in (True, False):
    for ndr64 in (False, True):
        port += 1
        t, r = nspi_rpc(frames, port, ndr64=ndr64, le=le)
        for i in range(150):
            op = rng.choice([3, 5, 9, 12, 0, 1, 7] + list(range(21)))
            req = rnd(rng.choice([0, 8, 24, 64, 128]))
            if op == 9:
                w = W(); w.raw(HANDLE); w.u32(0); w.raw(SETTINGS); w.ptr(); w.u32(1); w.u32(1); w.u32(0x3001001f)
                req = w.b
            w = W()
            if op == 9:
                w.ptr(); dd = []; srow(w, dd); run_deferred(dd); w.u32(0)
            elif op == 3:
                w.raw(SETTINGS); rowset(w); w.u32(0)
            elif op == 5:
                w.raw(SETTINGS); w.u32(2); w.u32(1); w.ptr(); w.u32(1); w.u32(0); w.u32(5); rowset(w); w.u32(0)
            elif op == 12:
                w.raw(SETTINGS); w.u32(3); rowset(w); w.u32(0)
            else:
                w.raw(rnd(rng.choice([0, 4, 16, 64, 200])))
            if not le:   # big-endian: just byteswap 32-bit words crudely
                bb = w.b + b'\0' * (-len(w.b) % 4)
                w.b = b''.join(struct.pack('>I', struct.unpack('<I', bb[k:k+4])[0]) for k in range(0, len(bb), 4))
            r.call(op, maybe_trunc(req), maybe_trunc(w.b))
pcap(out, frames)
print(out, len(frames))
