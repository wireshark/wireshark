#!/usr/bin/env python3
# Generates test/captures/dcerpc_fileexp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic coverage captures for the DCE/DFS File Exporter
(FILEEXP, packet-dcerpc-fileexp.c) dissector.

Connectionless DCE/RPC (ncadg_ip_udp) over UDP port 135, which carries the
interface UUID in every packet, so no Decode As is needed. Every packet is
built with struct; nothing comes from a real network.

Usage: mkdcerpc_fileexp.py <outdir>
Writes dcerpc-fileexp-coverage.pcap and dcerpc-fileexp-coverage-malformed.pcap.
"""
import os
import struct
import sys
import uuid

FILEEXP = ('4d37f2dd-ed93-0000-02c0-37cf1e000000', 4)

# ---------------------------------------------------------------- framing


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


C = (192, 0, 2, 50)
S = (192, 0, 2, 60)


def udp(src, dst, sport, dport, payload, from_client):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 0, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    mc, ms = bytes.fromhex('020000000050'), bytes.fromhex('020000000060')
    eth = (ms + mc) if from_client else (mc + ms)
    return eth + b'\x08\x00' + ip + u


def cl(ptype, opnum, seq, act, stub, big):
    """Connectionless DCE/RPC header (80 octets) and stub."""
    drep = b'\x00\x00\x00' if big else b'\x10\x00\x00'
    e = '>' if big else '<'
    u = uuid.UUID(FILEEXP[0])
    a = uuid.UUID(act)
    ifu = u.bytes if big else u.bytes_le
    actb = a.bytes if big else a.bytes_le
    hdr = struct.pack('BBBB', 4, ptype, 0x28 if ptype == 0 else 0x0a, 0)
    hdr += drep + b'\x00' + b'\x00' * 16 + ifu + actb
    hdr += struct.pack(e + 'IIIHHHHH', 1, FILEEXP[1], seq, opnum, 0xffff,
                       0xffff, len(stub), 0)
    hdr += b'\x00\x00'
    assert len(hdr) == 80
    return hdr + stub


class Frames(list):
    def pair(self, opnum, req, resp=None, big=False):
        seq = len(self)
        act = '6b8c0000-0000-4000-8000-%012x' % seq
        port = 40000 + seq % 1000
        self.append(udp(C, S, port, 135, cl(0, opnum, seq, act, req, big), True))
        if resp is not None:
            self.append(udp(S, C, 135, port, cl(2, opnum, seq, act, resp, big),
                            False))


# ---------------------------------------------------------------- NDR


class W:
    """NDR writer; alignment is relative to the start of the stub."""

    def __init__(self, big=False):
        self.b = bytearray()
        self.e = '>' if big else '<'
        self.big = big

    def align(self, n):
        self.b += b'\0' * (-len(self.b) % n)
        return self

    def u8(self, v):
        self.b += struct.pack('B', v)
        return self

    def u16(self, v):
        self.align(2)
        self.b += struct.pack(self.e + 'H', v)
        return self

    def u32(self, *vs):
        for v in vs:
            self.align(4)
            self.b += struct.pack(self.e + 'I', v & 0xffffffff)
        return self

    def raw(self, b):
        self.b += b
        return self

    def guid(self, s):
        self.align(4)
        u = uuid.UUID(s)
        self.b += u.bytes if self.big else u.bytes_le
        return self

    # --- fileexp structures, in the order the dissector reads them

    def fid(self, vol=0x1111, vnode=0x2222, unique=0x3333):
        return self.u32(0, 1, 0, vol, vnode, unique)

    def hyper(self, hi, lo):
        return self.u32(hi, lo)

    def flags(self, v):
        return self.u32(v)

    def netaddr(self, typ, data=bytes(14)):
        self.u16(typ)
        if typ:
            for x in data:
                self.u8(x)
        else:
            self.raw(bytes(14))
        return self

    def namestring(self, s, size=None):
        b = s.encode()
        self.u32(len(b) if size is None else size)
        if size is None or size < 256:
            self.raw(b)
        return self

    def netdata(self, typ, data, name, size=None):
        self.netaddr(typ, data)
        self.raw(b'\0' * 4)
        return self.namestring(name, size)

    def taggedname(self, s, tag=0, length=None):
        b = s.encode()
        n = len(b) if length is None else length
        self.u32(tag)
        self.u16(n)
        if n < 254:
            self.raw(b.ljust(257, b'\0'))
        return self

    def fidtaggedname(self, s, vnode=0x44, length=None):
        self.fid(vnode=vnode)
        return self.taggedname(s, length=length)

    def taggedpath(self, s, tag=0):
        b = s.encode()
        self.u32(tag)
        self.u16(len(b))
        return self.raw(b.ljust(1025, b'\0'))

    def acl(self, acl_len, body=b''):
        self.u32(acl_len)
        self.raw(struct.pack(self.e + 'II', 0, acl_len))
        self.guid('a1a2a3a4-b1b2-c1c2-d1d2-e1e2e3e4e5e6')
        self.guid('0c0c0c0c-1111-2222-3333-444455556666')
        if acl_len >= 38:
            assert len(body) == acl_len - 38
            self.raw(body)
        return self

    def storestatus(self, mask):
        self.u32(mask, 1600000000, 250000, 1600000100, 260000, 1600000200,
                 270000, 1000, 100, 0o644, 0, 4096, 0, 8192)
        self.guid('00000000-0000-0000-0000-000000000000')
        return self.u32(0, 0, 0o022, 0, 0, 1, 2, 3, 4, 5, 6)

    def token(self, typ, tid=(0, 0x77)):
        return self.u32(tid[0], tid[1], 1700003600, 0, typ, 0, 0xffffffff,
                        0, 0)

    def recordlock(self):
        self.u16(1).u16(0)
        return self.u32(0, 100, 4321, 7, 1, 0, 0)

    def volsync(self):
        return self.u32(0, 0x1111, 0, 42, 5, 10, 0, 0)

    def fetchstatus(self, n=1):
        self.u32(1, 1 + n % 3, 1, 0, 4096 * n, 0, 7, 1000, 1000, 100,
                 0x7f, 0x01, 1700000000, 0o100644, 0x2222, 0x3333,
                 1690000000, 1, 1690000001, 2, 1690000002, 3, 1690000003, 4)
        self.guid('11111111-2222-3333-4444-555555555555')
        self.guid('66666666-7777-8888-9999-aaaaaaaaaaaa')
        return self.u32(0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    def connparams(self, mask):
        self.u32(mask)
        return self.u32(*range(1, 21))

    def returndesc(self, tokenid, typ, flags):
        self.fid()
        self.u32(0, tokenid, 0, typ)
        return self.flags(flags)

    def st(self, v):
        return self.u32(v)


# A few status codes from dce_error_vals (packet-dcerpc-dce122.c): the
# first and last error codes of the table and one value not in it.
ST_OK = 0
ST_ERRS = [539918337,   # first error code: "event already in set"
           543465481,   # "No such fileset entry"
           556904451,   # "ACL entry not found"
           704852032,   # last entry: "zlc_Init() returning .ld"
           12345]       # not in the table, shown as a number

FLAGS = [0xffffffff, 0x1, 0x2, 0]
TKN_ALL = 0x3ffff
SET_ALL = 0xfff
CONN_ALL = 0x3000f


def b(big):
    return W(big)


def build_opnum(frames, op, v, big=False):
    """One request/response pair of opnum op, variant v. Variant 0 uses
    status 0 and every flag set, the other variants an error status and
    other values, so both sides of every branch are taken."""
    st = ST_OK if v == 0 else ST_ERRS[(op + v) % len(ST_ERRS)]
    fl = FLAGS[v % len(FLAGS)]
    tkn = TKN_ALL if v == 0 else (0x1 if v == 1 else 0)
    mask = SET_ALL if v == 0 else (0x1 if v == 1 else 0)
    vnode = [1, 0x2222, 2, 0x5555][v % 4]
    rq, rs = b(big), b(big)
    if op == 0:     # SetContext
        if v == 0:
            data = bytes([0, 135, 192, 0, 2, 60]) + bytes(8)
            rq.u32(1700000000).netdata(2, data, 'host/fx.example.com')
        elif v == 1:
            data = bytes([0, 0, 198, 51, 100, 7]) + bytes(8)
            rq.u32(1700000001).netdata(2, data, '')
        elif v == 2:
            rq.u32(1700000002).netdata(0, bytes(14), 'p')
        else:
            # principal name size >= 256: the string is not read
            rq.u32(1700000003).netdata(0, bytes(14), '', size=300)
        rq.flags(fl).guid('12345678-9abc-def0-1234-56789abcdef0').u32(v, 7)
        rs.st(st)
    elif op == 1:   # LookupRoot
        rq.fid(vnode=vnode).hyper(0, v).flags(fl)
        rs.fid(vnode=vnode).fetchstatus().token(tkn).volsync().st(st)
    elif op == 2:   # FetchData
        rq.fid(vnode=vnode).hyper(0, 3).u32(0, 8192 * v, 4096).flags(fl)
        rs.u32(4096 + v)        # pipe_t size only
    elif op == 3:   # FetchAcl
        rq.fid(vnode=vnode).u32(v % 2).hyper(0, 1).flags(fl)
        acl_len = [46, 38, 20, 46][v % 4]
        rs.acl(acl_len, bytes(range(1, 9)) if acl_len == 46 else b'')
        rs.fetchstatus().volsync().st(st)
    elif op == 4:   # FetchStatus
        rq.fid(vnode=vnode).hyper(0, 1).flags(fl)
        rs.fetchstatus(v).token(tkn).volsync().st(st)
    elif op == 5:   # StoreData
        rq.fid(vnode=vnode).storestatus(mask).u32(0, 4096, 512).hyper(0, 1)
        rq.flags(fl)
        rs.fetchstatus().volsync().st(st)
    elif op == 6:   # StoreAcl
        acl_len = [54, 38, 0, 54][v % 4]
        rq.fid(vnode=vnode).acl(acl_len, b'\x01\x02' * 8 if acl_len == 54 else b'')
        rq.u32(v % 2).fid(vnode=0x99).hyper(0, 1).flags(fl)
        rs.fetchstatus().volsync().st(st)
    elif op == 7:   # StoreStatus
        rq.fid(vnode=vnode).storestatus(mask).hyper(0, 1).flags(fl)
        rs.fetchstatus().volsync().st(st)
    elif op == 8:   # RemoveFile
        rq.fid(vnode=vnode).fidtaggedname('old.txt').hyper(0, 0x77)
        rq.hyper(0, 1).flags(fl)
        rs.fetchstatus(1).fetchstatus(2).fid().volsync().st(st)
    elif op == 9:   # CreateFile
        if v == 3:  # tag name length >= 254: the name is not read
            rq.fid(vnode=vnode).taggedname('', length=300)
        else:
            rq.fid(vnode=vnode).taggedname('new%d.txt' % v)
        rq.storestatus(mask).hyper(0, 1).flags(fl)
        rs.fid(vnode=0x100 + v).fetchstatus(1).fetchstatus(2).token(tkn)
        rs.volsync().st(st)
    elif op == 10:  # Rename
        rq.fid(vnode=vnode).fidtaggedname('a.txt').fid(vnode=0x66)
        rq.taggedname('b.txt').hyper(0, 0x78).hyper(0, 1).flags(fl)
        rs.fetchstatus(1).fetchstatus(2).fid().fetchstatus(3).fid()
        rs.fetchstatus(4).volsync().st(st)
    elif op == 11:  # Symlink
        rq.fid(vnode=vnode).taggedname('link').taggedpath('/:/target/file')
        rq.storestatus(mask).hyper(0, 1).flags(fl)
        rs.fid().fetchstatus(1).fetchstatus(2).token(tkn).volsync().st(st)
    elif op == 12:  # HardLink
        rq.fid(vnode=vnode).taggedname('hard').fid(vnode=0x67).hyper(0, 1)
        rq.flags(fl)
        rs.fetchstatus(1).fetchstatus(2).volsync().st(st)
    elif op == 13:  # MakeDir
        rq.fid(vnode=vnode).taggedname('dir').storestatus(mask).hyper(0, 1)
        rq.flags(fl)
        rs.fid().fetchstatus(1).fetchstatus(2).token(tkn).volsync().st(st)
    elif op == 14:  # RemoveDir
        rq.fid(vnode=vnode).fidtaggedname('dir').u32(0, 0x79).hyper(0, 1)
        rq.flags(fl)
        rs.fetchstatus(1).fid().fetchstatus(2).volsync().st(st)
    elif op == 15:  # Readdir
        rq.fid(vnode=vnode).hyper(0, 0).u32(8192).hyper(0, 1).flags(fl)
        rs.u32(0, 512 * (v + 1)).volsync()
    elif op == 16:  # Lookup
        rq.fid(vnode=vnode).taggedname('file').hyper(0, 1).flags(fl)
        rs.fid().fetchstatus(1).fetchstatus(2).token(tkn).volsync().st(st)
    elif op == 17:  # GetToken
        rq.fid(vnode=vnode).token(tkn).hyper(0, 1).flags(fl)
        rs.token(tkn).recordlock().fetchstatus().volsync().st(st)
    elif op == 18:  # ReleaseTokens
        n = [2, 1, 0, 3][v % 4]
        rq.u32(n, 0, n)
        for i in range(n):
            rq.returndesc(0x80 + i, TKN_ALL if i == 0 else 0x5, FLAGS[i % 4])
        rq.flags(fl)
        rs.st(st)
    elif op == 19:  # GetTime
        rs.u32(1700000000, 123456, 10, 20).st(st)
    elif op == 20:  # MakeMountPoint
        rq.fid(vnode=vnode).taggedname('mnt').taggedname('cell.example')
        rq.u16(v).taggedname('root.fs').storestatus(mask).hyper(0, 1)
        rq.flags(fl)
        rs.fid().fetchstatus(1).fetchstatus(2).volsync().st(st)
    elif op == 21:  # GetStatistics (no arguments decoded)
        pass
    elif op == 22:  # BulkFetchVV (no response arguments decoded)
        rq.hyper(0, 0x10).u32(3).flags(fl).u32(0, 0)
    elif op == 23:  # BulkKeepAlive
        rq.u32(2).flags(fl).u32(0, 0)
        rs.u32(0).st(st)
    elif op == 24:  # ProcessQuota
        rq.fid(vnode=vnode).hyper(0, 1).flags(fl)
        rs.raw(bytes(92)).fetchstatus().volsync().st(st)
    elif op == 25:  # GetServerInterfaces
        rs.st(st)
    elif op == 26:  # SetParams
        cm = CONN_ALL if v == 0 else (0x10000 if v == 1 else 0)
        rq.flags(fl).connparams(cm)
        rs.connparams(cm).st(st)
    elif op == 27:  # BulkFetchStatus (no response arguments decoded)
        rq.fid(vnode=vnode).hyper(0, 0).u32(4096).hyper(0, 1).flags(fl)
    frames.pair(op, bytes(rq.b), bytes(rs.b), big)


def main_capture():
    f = Frames()
    # Every opnum twice: status 0 with every flag, then an error status.
    for v in (0, 1):
        for op in range(28):
            build_opnum(f, op, v)
    # Extra variants for the remaining branches (fid vnode 2, flags 0x2
    # and 0, ACL lengths 20 and 0, no principal name, tag name length
    # >= 254, empty and longer ReleaseTokens lists, other status codes).
    for v in (2, 3):
        for op in (0, 3, 4, 6, 9, 18, 26):
            build_opnum(f, op, v)
    # Big endian.
    for op in (0, 9, 17, 18, 20, 26):
        build_opnum(f, op, 0, big=True)
    # Reproducer from the review (fileexp_returns_skipped.py): ReleaseTokens
    # with 2 afsReturnDesc entries, which were not decoded before the fix.
    fid = struct.pack('<6I', 0, 1, 0, 0x1111, 0x2222, 0x3333)
    desc = fid + struct.pack('<4I', 0, 5, 0, 6)
    stub = struct.pack('<III', 2, 0, 2) + (desc + struct.pack('<I', 0x77)) * 2 \
        + struct.pack('<I', 0x99)
    f.pair(18, stub)
    return f


def malformed_capture():
    f = Frames()
    # Reproducer fileexp_acl_wrap.py: StoreAcl with acl_len 0xffffffff,
    # which moved the offset back before the fix; now an exception.
    fid = struct.pack('<6I', 0, 1, 0, 0x1111, 0x2222, 0x3333)
    acl = struct.pack('<III', 0xffffffff, 0, 0xffffffff) + b'\x11' * 16 + b'\x22' * 16
    f.pair(6, fid + acl + struct.pack('<I', 0x41414141) + fid
           + struct.pack('<IIII', 7, 8, 9, 10))
    # Reproducer fileexp_pipe_size_string.py: FetchData response with the
    # pipe data after the size (a "Long frame" warning).
    req = fid + struct.pack('<IIIIII', 0, 0, 0, 0, 4096, 0)
    f.pair(2, req, struct.pack('<I', 0x1000) + b'DATA' * 4)
    # Tag path length beyond the packet.
    w = W().fid().taggedname('l')
    w.u32(0).u16(2000).raw(b'x' * 20)
    f.pair(11, bytes(w.b))
    # Every request and response cut short.
    for op in range(28):
        rq = W().fid(vnode=0x2222).u32(0)
        f.pair(op, bytes(rq.b)[:10], b'\x01\x02\x03')
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dcerpc-fileexp-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'dcerpc-fileexp-coverage-malformed.pcap'),
               malformed_capture())


if __name__ == '__main__':
    main()
