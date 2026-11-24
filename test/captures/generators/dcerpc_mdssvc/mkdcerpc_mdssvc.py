#!/usr/bin/env python3
# Generates test/captures/dcerpc_mdssvc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the mdssvc DCE/RPC dissector
(packet-dcerpc-mdssvc.c, the Spotlight metadata search service, generated
by Pidl from mdssvc.idl and mdssvc.cnf) and the Spotlight blob dissector
it calls ("afp_spotlight" in packet-afp.c).

Connection-oriented DCE/RPC over TCP: a client binds to the mdssvc
interface (885d85fb-c754-4062-a0e7-6872ce0064f4 version 2.0) and calls
every opnum 0-3; the server answers each. The DCE/RPC heuristic on TCP
finds the PDUs, so no Decode As is needed. Every packet is built from
scratch with struct (rpcgen.py); no captured traffic is used. There is
a little endian and a big endian NDR connection; NDR64 is not used
because the conformance file reads the Spotlight blob pointer and its
counts as 4-octet NDR fields (see the malformed capture). A third
connection holds the reproducer of "MDSSVC: Handle a NULL Spotlight
blob, limit it to its length" (mdssvc_blob_bounds.py), unchanged except
for the client port.

Usage: mkdcerpc_mdssvc.py <output directory>

Writes:
  dcerpc_mdssvc-coverage.pcap            the main capture
  dcerpc_mdssvc-coverage-malformed.pcap  malformed blobs and Spotlight data
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from rpcgen import TCP, RPC, NDR, pcap  # noqa: E402

UUID_MDSSVC = '885d85fb-c754-4062-a0e7-6872ce0064f4'
VER = (2, 0)
P = struct.pack
SPOTLIGHT_TIME_DELTA = 280878921600

# Spotlight element and complex (ToC) types
T_NULL, T_COMPLEX, T_INT64, T_BOOL, T_FLOAT = 0x0000, 0x0200, 0x8400, 0x0100, 0x8500
T_DATA, T_CNIDS, T_UUID, T_DATE = 0x0700, 0x8700, 0x0e00, 0x8600
C_ARRAY, C_STRING, C_UTF16, C_DICT, C_CNIDS, C_FILEMETA = 0x0a00, 0x0c00, 0x1c00, 0x0d00, 0x1a00, 0x1b00


class Spotlight:
    """Spotlight RPC data: a header, the elements (64-bit words: length
    in words, type, count or ToC index) and a ToC of the complex types"""
    def __init__(self, be=False):
        self.e = '>' if be else '<'
        self.be = be
        self.data = b''
        self.toc = []

    def q(self, lo, ty, hi):
        return P(self.e + 'Q', lo | (ty << 16) | (hi << 32))

    def _complex(self, ctype, hi):
        self.toc.append(self.q((16 + len(self.data)) // 8, ctype, hi))
        self.data += self.q(1, T_COMPLEX, len(self.toc))

    def array(self, n):
        self._complex(C_ARRAY, n)

    def dict(self, n):
        self._complex(C_DICT, n)

    def complex(self, ctype, hi=1):
        self._complex(ctype, hi)

    def _data(self, raw):
        raw += b'\0' * ((-len(raw)) % 8)
        self.data += self.q(1 + len(raw) // 8, T_DATA, 0) + raw

    def string(self, s):
        raw = s.encode()
        self._complex(C_STRING, 8 - len(raw) % 8)
        self._data(raw)

    def utf16(self, s, bom):
        raw = (b'\xff\xfe' + s.encode('utf-16-le')) if bom else s.encode('utf-16-be')
        self._complex(C_UTF16, 8 - len(raw) % 8)
        self._data(raw)

    def filemeta(self, inner):
        self._complex(C_FILEMETA, 1)
        self._data(inner)

    def int64(self, vals):
        self.data += self.q(1 + len(vals), T_INT64, len(vals)) + b''.join(P(self.e + 'q', v) for v in vals)

    def boolean(self, v):
        self.data += self.q(1, T_BOOL, v)

    def null(self, n):
        self.data += self.q(1, T_NULL, n)

    def uuid(self, uuids):
        self.data += self.q(1 + 2 * len(uuids), T_UUID, len(uuids)) + b''.join(uuids)

    def float(self, vals):
        self.data += self.q(1 + len(vals), T_FLOAT, len(vals)) + b''.join(P(self.e + 'd', v) for v in vals)

    def date(self, secs):
        self.data += self.q(1 + len(secs), T_DATE, len(secs))
        self.data += b''.join(P(self.e + 'Q', (s + SPOTLIGHT_TIME_DELTA) << 24) for s in secs)

    def cnids(self, ids, unk1=0, unk2=0):
        if ids is None:
            self.data += self.q(1, T_CNIDS, 0)
            return
        self.data += self.q(2 + len(ids), T_CNIDS, 0) + self.q(len(ids), unk1, unk2)
        self.data += b''.join(P(self.e + 'Q', i) for i in ids)

    def raw_element(self, ty, words=1, hi=0):
        self.data += self.q(words, ty, hi) + b'\0' * (8 * (words - 1))

    def bytes(self):
        hi = (8 + len(self.data)) // 8         # ToC position, minus 8, in words
        lo = hi + len(self.toc) + 1            # query length, minus 8, in words
        b = b'md031234' if self.be else b'432130dm'
        b += P(self.e + 'Q', (hi << 32) | lo)
        b += self.data
        b += self.q(len(self.toc) + 1, 0, 0) + b''.join(self.toc)
        return b


def fetch_request(be=False):
    """A fetchAttributes request: an array with the selector, a dictionary,
    and one element of every type"""
    sl = Spotlight(be)
    inner = Spotlight(not be)
    inner.array(1)
    inner.int64([7])
    sl.array(19)
    sl.string('fetchAttributes:forOIDArray:context:')        # 1
    sl.int64([0x1234, 0x5678])                                # 2
    sl.dict(4)                                                # 1
    sl.string('kMDItemDisplayName')
    sl.utf16('Résumé.txt', bom=True)
    sl.string('kMDItemFSSize')
    sl.int64([4096])
    sl.boolean(1)                                             # 1
    sl.boolean(0)                                             # 1
    sl.null(2)                                                # 2
    sl.uuid([bytes(range(16))])                               # 1
    sl.float([1.5])                                           # 1
    sl.date([1700000000])                                     # 1
    sl.cnids([101, 102], 0x0a, 0x0b)                          # 1
    sl.cnids(None)                                            # 1
    sl.utf16('BigEndian', bom=False)                          # 1
    sl.filemeta(inner.bytes())                                # 1
    sl.filemeta(b'')                                          # 1
    sl.complex(C_CNIDS)                                       # 1: unknown complex type
    sl.int64([9])
    sl.raw_element(0x1234)                                    # 1: unknown element type
    sl.raw_element(T_DATA, 2)                                 # 1: data outside a string
    sl.boolean(1)                                             # top level
    return sl.bytes()


def fetch_reply(be=False):
    """A reply: an array with a CNID array and a dictionary of values"""
    sl = Spotlight(be)
    sl.array(2)
    sl.cnids([101], 0, 0)
    sl.dict(2)
    sl.string('kMDItemPath')
    sl.string('/Volumes/share/Résumé.txt')
    return sl.bytes()


def blob(n, sl, size=None, present=True):
    """mdssvc_blob: length, size, then the unique pointer, max count,
    offset and actual count of the octets (what the cnf reads)"""
    n.u32(len(sl) if present else 0)
    n.u32((size if size is not None else len(sl)) if present else 0)
    n.ptr(present)
    if present:
        n.u32(size if size is not None else len(sl))
        n.u32(0)
        n.u32(len(sl))
        n.raw(sl)


def calls(rpc, le, extra):
    def N():
        return NDR(le)
    handle = bytes([0, 0, 0, 0]) + bytes(range(0x41, 0x51))
    # 0 open
    q = N()
    q.u32(0x2a)                 # device_id
    q.u32(0x17)                 # unkn2
    q.u32(0)                    # unkn3
    for s in ('/Volumes/share', 'share'):
        q.u32(1025)
        q.u32(0)
        q.u32(len(s) + 1)
        q.raw(s.encode() + b'\0')
    r = N()
    r.u32(0x2a)
    r.u32(0x17)
    r.u32(0)
    s = '/srv/share'
    r.u32(1025)
    r.u32(0)
    r.u32(len(s) + 1)
    r.raw(s.encode() + b'\0')
    r.handle(handle)
    rpc.call(0, q.bytes(), r.bytes())
    # 1 unknown1
    q = N()
    q.handle(handle)
    for v in (0, 0x2a, 0x17, 0, 501, 20):
        q.u32(v)
    r = N()
    for v in (0, 0x6b000001, 0):
        r.u32(v)
    rpc.call(1, q.bytes(), r.bytes())
    # 2 cmd: a fetchAttributes request (little and big endian Spotlight
    # data) and a reply; a reply with a NULL blob; a blob shorter than
    # its size
    for be in (False, True):
        sl = fetch_request(be)
        q = N()
        q.handle(handle)
        for v in (0, 0x2a, 0x17, 0, 0x6b000001):
            q.u32(v)
        blob(q, sl, size=len(sl) + 64)
        for v in (0, 0x10000, 1, 0x10000, 0, 0):
            q.u32(v)
        r = N()
        r.u32(1)                # fragment
        blob(r, fetch_reply(be))
        r.u32(0)                # unkn9
        rpc.call(2, q.bytes(), r.bytes())
    # a reply blob with 8 octets after the Spotlight data
    q = N()
    q.handle(handle)
    for v in (0, 0x2a, 0x17, 0, 0x6b000001):
        q.u32(v)
    blob(q, fetch_reply(not le))
    for v in (0, 0x10000, 1, 0x10000, 0, 0):
        q.u32(v)
    r = N()
    r.u32(2)
    blob(r, fetch_reply(not le) + b'\0' * 8)
    r.u32(0x55667788)
    rpc.call(2, q.bytes(), r.bytes())
    q = N()
    q.handle(handle)
    for v in (0, 0x2a, 0x17, 0, 0x6b000001):
        q.u32(v)
    blob(q, b'', present=False)
    for v in (0, 0x10000, 1, 0x10000, 0, 0):
        q.u32(v)
    r = N()
    r.u32(0)
    blob(r, b'', present=False)
    r.u32(0x11223344)
    rpc.call(2, q.bytes(), r.bytes())
    # 3 close
    q = N()
    q.handle(handle)
    for v in (0, 0x2a, 0x17, 0):
        q.u32(v)
    r = N()
    r.handle(bytes(20))
    r.u32(0)
    rpc.call(3, q.bytes(), r.bytes())
    if extra:
        rpc.call(4, b'\0' * 8, b'\0' * 4)


def reproducer(F, port):
    """mdssvc_blob_bounds.py: a cmd request and reply with a small
    Spotlight blob, and a reply whose blob pointer is NULL, followed by
    unkn9 0x11223344"""
    sl = b'432130dm' + P('<Q', (3 << 32) | 4)
    sl += P('<Q', 0x0000000184000002) + P('<q', 42)
    sl += P('<Q', 0x0000000000000001)

    def blob4(s):
        pad = b'\0' * ((-len(s)) % 4)
        return P('<IIIIII', len(s), len(s), 0x00020000, len(s), 0, len(s)) + s + pad

    def cmd_request(s):
        return b'\0' * 20 + P('<5I', 0, 1, 0x17, 0, 0x6b000001) + blob4(s) + P('<6I', 0, 0x10000, 1, 0x10000, 0, 0)
    t = TCP(F, port)
    r = RPC(t, UUID_MDSSVC, VER)
    r.bind()
    resp = P('<I', 7) + P('<IIIIII', len(sl), len(sl), 0x00020000, len(sl), 0, len(sl)) + sl
    resp += P('<I', 0x11223344)
    r.call(2, cmd_request(sl), resp)
    resp = P('<I', 7) + P('<III', 0, 0, 0) + P('<I', 0x11223344)
    r.call(2, cmd_request(sl), resp)
    t.fin()


def main_frames():
    F = []
    for cport, le in ((50001, True), (50002, False)):
        t = TCP(F, cport)
        rpc = RPC(t, UUID_MDSSVC, VER, le)
        rpc.bind()
        calls(rpc, le, cport == 50001)
        t.fin()
    reproducer(F, 50601)
    return F


def malformed_frames():
    F = []
    t = TCP(F, 50101)
    rpc = RPC(t, UUID_MDSSVC, VER)
    rpc.bind()

    def reply(sl, length=None):
        r = NDR()
        r.u32(1)
        r.u32(len(sl))
        r.u32(len(sl))
        r.ptr(True)
        r.u32(len(sl))
        r.u32(0)
        r.u32(length if length is not None else len(sl))
        r.raw(sl)
        r.u32(0)
        rpc.call(2, b'\0' * 20 + b'\0' * 20 + b'\0' * 12 + b'\0' * 24, r.bytes())
    # blob actual count beyond the stub
    reply(fetch_reply(), length=0x100000)
    # ToC offset < 8, > INT_MAX; query length < 8, > INT_MAX
    for hdr in (P('<Q', 0), P('<Q', (0x7fffffff << 32) | 4), P('<Q', 4 << 32), P('<Q', (2 << 32) | 0xffffffff)):
        reply(b'432130dm' + hdr + b'\0' * 24)
    # no ToC entries
    sl = Spotlight()
    sl.boolean(1)
    b = bytearray(sl.bytes())
    b[24:32] = P('<Q', 0)
    reply(bytes(b))
    # NULL subquery counts above the query count and above 20; a date
    # count above the safety limit
    for build in (lambda s: (s.array(1), s.null(3)),
                  lambda s: (s.array(100), s.null(30)),
                  lambda s: (s.array(1), s.date([0] * 21))):
        sl = Spotlight()
        build(sl)
        reply(sl.bytes())
    # an element of length 0
    sl = Spotlight()
    sl.raw_element(T_BOOL, 0)
    sl.boolean(1)
    reply(sl.bytes())
    t.fin()
    # NDR64: the cnf reads 4-octet pointer and counts
    t = TCP(F, 50102)
    rpc = RPC(t, UUID_MDSSVC, VER, True, True)
    rpc.bind()
    r = NDR(True, True)
    r.u32(1)
    sl = fetch_reply()
    r.u32(len(sl))
    r.u32(len(sl))
    r.ptr(True)
    r.count(len(sl))
    r.count(0)
    r.count(len(sl))
    r.raw(sl)
    r.u32(0)
    rpc.call(2, b'\0' * 96, r.bytes())
    t.fin()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_mdssvc-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_mdssvc-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
