#!/usr/bin/env python3
# Generates test/captures/dcerpc_rs_pgo_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DCE/RPC RS_PGO
dissector (epan/dissectors/packet-dcerpc-rs_pgo.c, DCE security registry
person/group/org interface 4c878280-3000-0000-0d00-028714000000 v1).

Connectionless DCE/RPC over UDP (port 135, found by the DCE/RPC
heuristics). The stubs follow what the dissector reads, including its
fixed "XXX" skips: a 32 bit integer is aligned to 4, a 16 bit one to 2,
names are a 32 bit size (including the final NUL) and that many octets.
Top level [ref] pointers have no wire representation. Every packet is
built from scratch with struct (dcelib.py); no captured traffic is used.

Usage: mkdcerpc_rs_pgo.py <output directory>

Writes:
  dcerpc_rs_pgo-coverage.pcap            (clean, for test/captures)
  dcerpc_rs_pgo-coverage-malformed.pcap  (oversize names, short stubs)
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from dcelib import CL, pcap, uuid_bytes  # noqa: E402

RS_PGO = '4c878280-3000-0000-0d00-028714000000'

SITE = '5a7e1d00-1111-4222-8333-444455556666'
SRC = 'c0c0a000-0001-4002-8003-000000000004'
PGO_ID = '0000006c-0000-11d0-a000-0800090a0b0c'

# query types (rs_pgo_query_t)
Q_NAME, Q_ID, Q_UNIX, Q_NEXT, Q_NONE = range(5)


class W:
    """Stub writer that mirrors the dissector's reads."""
    def __init__(self, le=True):
        self.b = bytearray()
        self.le = le
        self.e = '<' if le else '>'

    def pad(self, n):
        self.b += b'\0' * ((-len(self.b)) % n)

    def u8(self, v):
        self.b += bytes([v])

    def u16(self, v):
        self.pad(2)
        self.b += struct.pack(self.e + 'H', v)

    def u32(self, v):
        self.pad(4)
        self.b += struct.pack(self.e + 'I', v)

    def skip(self, n, fill=0):
        self.b += bytes([fill]) * n

    def uuid(self, u):
        self.pad(4)
        self.b += uuid_bytes(u, self.le)

    def time(self, t):
        self.b += struct.pack(self.e + 'I', t)

    def name(self, s, size=None):
        """sec_rgy_name_t / sec_rgy_pname_t: size (with NUL), octets"""
        data = s.encode('ascii') + b'\0' if s is not None else b''
        self.u32(len(data) if size is None else size)
        self.b += data

    # structures
    def domain(self, d):
        self.u32(d)

    def flags(self, f):
        self.u32(f)

    def pgo_item(self, uid, unix_num, quota, flags, fullname):
        self.uuid(uid)
        self.u32(unix_num)
        self.u32(quota)
        self.flags(flags)
        self.skip(4)                     # XXX in the dissector
        self.name(fullname)

    def cache(self, site=SITE, p=1700000100, g=1700000200, o=0):
        self.uuid(site)
        self.time(p)
        self.time(g)
        self.time(o)                     # 0: "No time specified"

    def status(self, st):
        self.u32(st)

    def cursor(self, src, handle, valid):
        self.uuid(src)
        self.u32(handle)
        self.u32(valid)

    def query_key(self, q, **kw):
        self.u16(q)
        self.skip(4)
        if q == Q_NAME:
            self.name(kw.get('name', 'admin'))
        elif q == Q_ID:
            self.uuid(kw.get('uid', PGO_ID))
            self.name(kw.get('scope', '/.:/sec'))
        elif q == Q_UNIX:
            self.u32(kw.get('unix', 1001))
            self.name(kw.get('scope', '/.:/sec'))
        elif q == Q_NEXT:
            self.name(kw.get('scope', 'principal'))

    def bytes(self):
        return bytes(self.b)


def calls(F, le, cport):
    """Every opnum of rs_pgo with its response; returns nothing, appends
    to F."""
    rpc = CL(F, RS_PGO, 1, le, cport=cport, sport=135)

    def call(opnum, q, r):
        rpc.call(opnum, q.bytes(), r.bytes() if r is not None else None)

    def W_():
        return W(le)

    # 0 add: person "alice", alias + required + projlist_ok
    q = W_()
    q.domain(0)                          # person
    q.skip(4)
    q.name('alice')
    q.pgo_item(PGO_ID, 1001, 50, 0x7, 'Alice Example')
    r = W_()
    r.cache()
    r.status(0)
    call(0, q, r)
    # 0 add: group "staff", no flags, empty full name; short response
    # (status only, the "8 octets or less" path)
    q = W_()
    q.domain(1)                          # group
    q.skip(4)
    q.name('staff')
    q.pgo_item(PGO_ID, 100, 0, 0x0, '')
    r = W_()
    r.status(0x17122003)
    call(0, q, r)
    # 1 delete
    q = W_()
    q.domain(2)                          # org
    q.name('research')
    r = W_()
    r.cache()
    r.status(0)
    call(1, q, r)
    # 1 delete with a short response
    q = W_()
    q.domain(0)
    q.name('bob')
    r = W_()
    r.status(0)
    call(1, q, r)
    # 2 replace: alias only, full name of one octet (just the NUL)
    q = W_()
    q.domain(0)
    q.name('alice')
    q.pgo_item(PGO_ID, 1001, 75, 0x1, '')
    r = W_()
    r.cache()
    r.status(0)
    call(2, q, r)
    # 2 replace: required only, name of size 0
    q = W_()
    q.domain(1)
    q.name('wheel')
    q.uuid(PGO_ID)
    q.u32(0)
    q.u32(0)
    q.flags(0x2)
    q.skip(4)
    q.name(None, 0)
    r = W_()
    r.cache(o=1700000300)
    r.status(0x17122001)
    call(2, q, r)
    # 3 rename
    q = W_()
    q.domain(0)
    q.name('alice')
    q.name('alice2')
    r = W_()
    r.cache()
    r.status(0)
    call(3, q, r)
    # 4 get: one per query key arm, responses with and without a result
    for i, (qk, kw) in enumerate([(Q_NAME, {'name': 'alice'}),
                                  (Q_ID, {}),
                                  (Q_UNIX, {'unix': 1001}),
                                  (Q_NEXT, {'scope': 'principal'}),
                                  (Q_NONE, {}),
                                  (7, {})]):
        q = W_()
        q.domain(i % 3)
        q.query_key(qk, **kw)
        q.u32(i & 1)                     # allow_aliases
        q.skip(4)                        # XXX in the dissector
        q.cursor(SRC, i, 1)
        r = W_()
        r.cursor(SRC, i + 1, 1)
        r.cache()
        if i < 4:
            r.u32(0)                     # status ok: a result follows
            r.skip(4)                    # XXX in the dissector
            r.name('alice' if i != 3 else 'bob')
            r.pgo_item(PGO_ID, 1001 + i, 10 * i, [0x4, 0x3, 0x5, 0x0][i],
                       'Full Name %d' % i)
        else:
            r.u32(0x17122003)            # no result
            r.skip(4)
        call(4, q, r)
    # 5 key_transfer: every requested result type and an unknown one,
    # every query key arm in the response
    for i, (rt, qk, kw) in enumerate([(Q_NAME, Q_ID, {}),
                                      (Q_ID, Q_NAME, {'name': 'alice'}),
                                      (Q_UNIX, Q_NAME, {'name': 'carol'}),
                                      (Q_NEXT, Q_UNIX, {'unix': 4242}),
                                      (Q_NONE, Q_NEXT, {'scope': 'group'}),
                                      (9, Q_NONE, {})]):
        q = W_()
        q.skip(4)
        q.domain(i % 3)
        q.u8(rt)
        q.query_key(qk, **kw)
        ans = {Q_ID: (Q_NAME, {'name': 'alice'}),
               Q_NAME: (Q_ID, {}),
               Q_UNIX: (Q_UNIX, {'unix': 4242}),
               Q_NEXT: (Q_NEXT, {'scope': 'group'}),
               Q_NONE: (8, {})}[qk]
        r = W_()
        r.query_key(ans[0], **ans[1])
        r.cache()
        r.status(0)
        call(5, q, r)
    # 6 add_member, full and short response
    for short in (False, True):
        q = W_()
        q.domain(1)
        q.name('staff')
        q.name('alice' if not short else 'bob')
        r = W_()
        if not short:
            r.cache()
        r.status(0)
        call(6, q, r)
    # 7 delete_member
    q = W_()
    q.domain(1)
    q.name('staff')
    q.name('bob')
    r = W_()
    r.cache()
    r.status(0)
    call(7, q, r)
    # 8 is_member
    q = W_()
    q.skip(4)
    q.domain(1)
    q.name('staff')
    q.skip(4)
    q.name('alice')
    r = W_()
    r.cache()
    r.status(0)
    call(8, q, r)
    # 9 get_members (no response dissector: the response is stub data)
    q = W_()
    q.domain(1)
    q.skip(4)
    q.name('staff')
    q.cursor(SRC, 0, 0)
    q.u32(20)
    r = W_()
    r.u32(0)
    call(9, q, r)


def main_frames():
    F = []
    calls(F, True, 40100)
    calls(F, False, 40200)
    return F


def malformed_frames():
    F = []
    le = True
    rpc = CL(F, RS_PGO, 1, le, cport=40300, sport=135)
    # oversize sec_rgy_name_t (1025) in delete: throws after the size
    q = W(le)
    q.domain(0)
    q.name('x' * 8, 1025)
    rpc.call(1, q.bytes(), None)
    # oversize sec_rgy_pname_t (257) in add's pgo item
    q = W(le)
    q.domain(0)
    q.skip(4)
    q.name('alice')
    q.uuid(PGO_ID)
    q.u32(1)
    q.u32(2)
    q.flags(0)
    q.skip(4)
    q.name('y' * 8, 257)
    rpc.call(0, q.bytes(), None)
    # name size larger than the stub
    q = W(le)
    q.domain(0)
    q.name('short', 200)
    rpc.call(1, q.bytes(), None)
    # every opnum truncated, request and response
    for opnum in range(10):
        rpc.call(opnum, b'\x01\x00', b'\x01')
    # the get response's result with an oversize name
    q = W(le)
    q.domain(0)
    q.query_key(Q_NONE)
    q.u32(0)
    q.skip(4)
    q.cursor(SRC, 1, 1)
    r = W(le)
    r.cursor(SRC, 2, 1)
    r.cache()
    r.u32(0)
    r.skip(4)
    r.name('z' * 4, 5000)
    rpc.call(4, q.bytes(), r.bytes())
    # an unknown opnum (10), not in the table
    rpc.call(10, b'\0' * 4, b'\0' * 4)
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_rs_pgo-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_rs_pgo-coverage-malformed.pcap'),
         malformed_frames())


if __name__ == '__main__':
    main()
