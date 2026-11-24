#!/usr/bin/env python3
# Generates the profinet_cba captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic PROFINET CBA (DCOM over DCE/RPC, plus PN-RT) captures.

usage: mkprofinet_cba.py <outdir> [-v]

Writes profinet-cba-coverage.pcapng (main capture) and
profinet-cba-coverage-malformed.pcapng (coverage number only).
Every packet is built with struct; nothing comes from a real network.
"""
import struct
import sys
import os

NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
ETH, RAW = 0, 1


def guid(s):
    p = s.split('-')
    return (struct.pack('<IHH', int(p[0], 16), int(p[1], 16), int(p[2], 16))
            + bytes.fromhex(p[3] + p[4]))


def cba(n):
    return guid('cba%05x-6c97-11d1-8271-00a02442df7d' % n)


def ipb(s):
    return bytes(int(x) for x in s.split('.'))


def ip_csum(h):
    s = 0
    for i in range(0, len(h), 2):
        s += (h[i] << 8) + h[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


# ---------------------------------------------------------------- NDR builder
class B:
    """Stub builder; alignment is relative to the start of the stub."""

    def __init__(self):
        self.b = bytearray()

    def __len__(self):
        return len(self.b)

    def al(self, n):
        self.b += b'\0' * ((-len(self.b)) % n)
        return self

    def raw(self, d):
        self.b += d
        return self

    def u8(self, v):
        self.b += struct.pack('<B', v)
        return self

    def u16(self, v):
        self.al(2)
        self.b += struct.pack('<H', v)
        return self

    def u32(self, v):
        self.al(4)
        self.b += struct.pack('<I', v)
        return self

    def u64(self, v):
        self.al(8)
        self.b += struct.pack('<Q', v)
        return self

    def dbl(self, v):
        self.al(8)
        self.b += struct.pack('<d', v)
        return self

    def ptr(self, nonnull=True):
        return self.u32(0x20000 if nonnull else 0)

    def hr(self, v=0):
        return self.u32(v)

    def this(self):
        self.raw(struct.pack('<HHII', 5, 7, 0, 0) + b'\x11' * 16 + struct.pack('<I', 0))
        return self

    def that(self):
        self.raw(struct.pack('<II', 0, 0))
        return self

    def lpwstr(self, s):
        w = (s + '\0').encode('utf-16-le')
        n = len(w) // 2
        self.al(4)
        self.raw(struct.pack('<III', n, 0, n) + w)
        return self

    def bstr(self, s):
        w = (s + '\0').encode('utf-16-le')
        n = len(w) // 2
        self.al(4)
        self.raw(struct.pack('<III', n, len(w), n) + w)
        return self

    def variant(self, vt, fn=None):
        self.al(8)
        self.raw(struct.pack('<IIHHHHI', 24, 0, vt, 0, 0, 0, vt))
        if fn:
            fn(self)
        return self

    def v_i4(self, v):
        return self.variant(3, lambda b: b.u32(v))

    def v_r8(self, v):
        return self.variant(5, lambda b: b.dbl(v))

    def v_str(self, s):
        return self.variant(8, lambda b: b.ptr().bstr(s))

    def v_bool(self, v):
        return self.variant(11, lambda b: b.u16(v))

    def pmip(self, iid, oxid, oid, ipid, ip='192.0.2.2'):
        """pointer to MInterfacePointer holding a standard OBJREF."""
        self.ptr()
        sb = struct.pack('<H', 7) + (ip + '\0').encode('utf-16-le') + b'\0\0'
        sec = struct.pack('<HH', 10, 0xffff) + b'\0\0' + b'\0\0'
        dsa = struct.pack('<HH', (len(sb) + len(sec)) // 2, len(sb) // 2) + sb + sec
        o = struct.pack('<II', 0x574f454d, 1) + iid
        o += struct.pack('<IIII', 0, 1, oxid & 0xffffffff, oxid >> 32)
        o += struct.pack('<II', oid & 0xffffffff, oid >> 32) + ipid + dsa
        self.u32(len(o)).u32(len(o)).raw(o)
        return self


def sub(fn):
    b = B()
    fn(b)
    return b


# ---------------------------------------------------------------- DCE/RPC
def co_hdr(ptype, flags, body, call_id):
    return struct.pack('<BBBB4sHHI', 5, 0, ptype, flags, b'\x10\0\0\0',
                       16 + len(body), 0, call_id) + body


def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)


def bind(call_id, ifaces):
    body = struct.pack('<HHIB3x', 5840, 5840, 0, len(ifaces))
    for i, (u, v) in enumerate(ifaces):
        body += struct.pack('<HB1x', i, 1) + u + struct.pack('<HH', v, 0) + guid(NDR) + struct.pack('<I', 2)
    return co_hdr(11, 3, body, call_id)


def bind_ack(call_id, n):
    sec = b'135\0'
    body = struct.pack('<HHIH', 5840, 5840, 0x1234, len(sec)) + sec
    body = pad4(body)
    body += struct.pack('<B3x', n)
    for _ in range(n):
        body += struct.pack('<HH', 0, 0) + guid(NDR) + struct.pack('<I', 2)
    return co_hdr(12, 3, body, call_id)


def request(call_id, ctx, opnum, obj, stub):
    flags = 3 | (0x80 if obj else 0)
    body = struct.pack('<IHH', len(stub), ctx, opnum) + (obj or b'') + stub
    return co_hdr(0, flags, body, call_id)


def response(call_id, ctx, stub):
    body = struct.pack('<IHBB', len(stub), ctx, 0, 0) + stub
    return co_hdr(2, 3, body, call_id)


# ---------------------------------------------------------------- capture
class Cap:
    def __init__(self):
        self.recs = []        # (ifid, bytes)
        self.t = 0
        self.marks = []

    def mark(self, name):
        self.marks.append((len(self.recs) + 1, name))

    def add(self, ifid, data):
        self.recs.append((ifid, data))

    def write(self, fn):
        def blk(t, body):
            body += b'\0' * ((-len(body)) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 1, 0, 65535))
        out += blk(1, struct.pack('<HHI', 101, 0, 65535))
        for i, (ifid, r) in enumerate(self.recs):
            ts = (1700000000 + i) * 1000000
            out += blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(r), len(r)) + r)
        with open(fn, 'wb') as f:
            f.write(out)


class Flow:
    """One TCP connection (DCE/RPC CO), client -> server."""

    def __init__(self, cap, cli, srv, cport, sport, ifid=ETH, cmac=b'\x02\0\0\0\0\x01', smac=b'\x02\0\0\0\0\x02'):
        self.cap, self.ifid = cap, ifid
        self.cli, self.srv = ipb(cli), ipb(srv)
        self.cport, self.sport = cport, sport
        self.cmac, self.smac = cmac, smac
        self.seq = {True: 1000, False: 5000}
        self.call = 0

    def tcp(self, to_srv, payload):
        src, dst = (self.cli, self.srv) if to_srv else (self.srv, self.cli)
        sp, dp = (self.cport, self.sport) if to_srv else (self.sport, self.cport)
        tcph = struct.pack('>HHIIBBHHH', sp, dp, self.seq[to_srv], self.seq[not to_srv], 0x50, 0x18, 65535, 0, 0)
        self.seq[to_srv] += len(payload)
        iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 40 + len(payload), 1, 0, 64, 6, 0, src, dst)
        iph = iph[:10] + struct.pack('>H', ip_csum(iph)) + iph[12:]
        eth = b''
        if self.ifid == ETH:
            sm, dm = (self.cmac, self.smac) if to_srv else (self.smac, self.cmac)
            eth = dm + sm + b'\x08\x00'
        self.cap.add(self.ifid, eth + iph + tcph + payload)

    def pdu(self, to_srv, pdu):
        self.tcp(to_srv, pdu)

    def bind(self, ifaces):
        self.call += 1
        self.tcp(True, bind(self.call, ifaces))
        self.tcp(False, bind_ack(self.call, len(ifaces)))

    def rpc(self, ctx, op, obj, req, rsp, rsp_obj=None):
        """req, rsp: B builders (without this/that), or None for no response."""
        self.call += 1
        rq = B().this()
        rq.raw(bytes(req.b))
        self.tcp(True, request(self.call, ctx, op, obj, bytes(rq.b)))
        if rsp is not None:
            rs = B().that()
            rs.raw(bytes(rsp.b))
            self.tcp(False, response(self.call, ctx, bytes(rs.b)))

    def raw_rpc(self, ctx, op, obj, reqstub, rspstub=None):
        self.call += 1
        self.tcp(True, request(self.call, ctx, op, obj, reqstub))
        if rspstub is not None:
            self.tcp(False, response(self.call, ctx, rspstub))


def pipe(flow, calls):
    """Send all requests, then all responses (DCE/RPC calls in flight together)."""
    ids = []
    for ctx, op, obj, req, rsp in calls:
        flow.call += 1
        ids.append(flow.call)
        flow.tcp(True, request(flow.call, ctx, op, obj, bytes(B().this().raw(bytes(req.b)).b)))
    for cid, (ctx, op, obj, req, rsp) in zip(ids, calls):
        flow.tcp(False, response(cid, ctx, bytes(B().that().raw(bytes(rsp.b)).b)))


def udp_frame(cap, ifid, sip, dip, sport, dport, payload, dmac=b'\x02\0\0\0\0\x02', smac=b'\x02\0\0\0\0\x01'):
    udph = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28 + len(payload), 1, 0, 64, 17, 0, ipb(sip), ipb(dip))
    iph = iph[:10] + struct.pack('>H', ip_csum(iph)) + iph[12:]
    eth = dmac + smac + b'\x08\x00' if ifid == ETH else b''
    cap.add(ifid, eth + iph + udph + payload)


def rt_frame(cap, ifid, dmac, frameid, data, cycle=1, status=0x35, smac=b'\x02\0\0\0\0\x02'):
    p = struct.pack('>H', frameid) + data
    pad = max(0, 44 - len(p) - 4)
    p += b'\0' * pad + struct.pack('>HBB', cycle, status, 0)
    cap.add(ifid, dmac + smac + b'\x88\x92' + p)


def cbadata(version, items, flags=0, count=None):
    """CBA connection data: items = [(consid or None, qc, data)]"""
    out = b''
    for cid, qc, d in items:
        hdr = 2 + (4 if cid is not None else 0) + 1
        out += struct.pack('<H', hdr + len(d)) + (struct.pack('<I', cid) if cid is not None else b'') + bytes([qc]) + d
    return struct.pack('<BBH', version, flags, len(items) if count is None else count) + out


IF = {  # name -> (uuid number)
    'PDEV': 0x01, 'PDEV2': 0x06, 'BROWSE': 0x02, 'BROWSE2': 0x07, 'PERSIST': 0x05, 'PERSIST2': 0x08,
    'PC': 0x03, 'PCEVENT': 0x04, 'LDEV': 0x11, 'LDEV2': 0x17, 'STATE': 0x12, 'STATEEV': 0x13,
    'TIME': 0x14, 'GERR': 0x15, 'GERREV': 0x16, 'RTAUTO': 0x51, 'RTAUTO2': 0x52, 'SYSPROP': 0x62,
    'MGT': 0x41, 'MGT2': 0x46, 'CB': 0x42, 'CB2': 0x47, 'SERVER': 0x43, 'SERVER2': 0x48,
    'SRT': 0x45, 'SYNC': 0x44,
}
ORDER = list(IF)
CTX = {n: i for i, n in enumerate(ORDER)}


def g(n):
    return guid('%08x-0000-4000-8000-%012x' % (0xc0de0000 + n, n))


def mk_main(cap):
    ip_cli, ip_srv = '192.0.2.1', '192.0.2.2'
    fa = Flow(cap, ip_cli, ip_srv, 49152, 135)
    fb = Flow(cap, ip_srv, ip_cli, 49300, 49301, cmac=b'\x02\0\0\0\0\x02', smac=b'\x02\0\0\0\0\x01')
    ifs = [(cba(IF[n]), 0) for n in ORDER]
    P, L1, L2, A1, A2, A3 = g(1), g(2), g(3), g(4), g(5), g(6)
    C1, C2, C3 = g(7), g(8), g(9)
    S = CTX

    def rq(n, op, obj, req=None, rsp=None, f=None):
        (f or fa).rpc(S[n], op, obj, req or B(), rsp)

    ok = lambda b: b.hr(0)

    cap.mark('bind')
    fa.bind(ifs)
    fb.bind([(cba(IF['CB']), 0), (cba(IF['CB2']), 0)])  # ctx 0,1 in flow B
    CB0, CB1 = 0, 1

    # ------------------------------------------------ ICBAPhysicalDevice
    cap.mark('pdev')
    rq('PDEV', 7, P, None, B().ptr().bstr('Example Producer').hr())
    rq('PDEV', 8, P, None, B().ptr(False).hr(1))
    rq('PDEV', 9, P, None, B().ptr().v_str('SN-0815').hr())
    rq('PDEV', 10, P, None, B().dbl(44000.5).hr())
    rq('PDEV', 11, P, None, B().u16(2).u16(3).hr())
    # get_LogicalDevice with an empty name (no name remembered), then LD1/LD2
    rq('PDEV', 12, P, B().ptr(False), B().pmip(cba(IF['LDEV']), 0x1000, 0x1000, g(20)).hr())
    rq('PDEV', 12, P, B().ptr().bstr('LD1'), B().pmip(cba(IF['LDEV']), 0x1001, 0x1001, L1).hr())
    rq('PDEV', 12, P, B().ptr().bstr('LD2'), B().pmip(cba(IF['LDEV']), 0x1002, 0x1002, L2).hr())
    # no interface pointer in the response, E_FAIL
    rq('PDEV', 12, P, B().ptr().bstr('LD3'), B().ptr(False).hr(0x80004005))
    rq('PDEV2', 13, P, None, B().u16(0xffff).u16(0).hr())
    rq('PDEV2', 14, P, None, B().u16(1).u16(2).u16(3).u16(4).hr())
    rq('PDEV2', 15, P, None, B().u32(0x12345678).hr())

    # ------------------------------------------------ Browse / Persist
    cap.mark('browse')
    rq('BROWSE', 7, P, None, B().u32(42).hr())
    rq('BROWSE', 7, P, None, B().u32(0).hr(0x80004005))
    rq('BROWSE', 8, P, B().u32(0).u32(10), B().ptr().v_str('Item1').ptr().v_i4(8).ptr().v_i4(3).hr())
    rq('BROWSE', 8, P, B().u32(5).u32(1), B().ptr(False).ptr(False).ptr(False).hr(0x8004CB01))
    rq('BROWSE2', 9, P, B().u32(1), B().u32(7).hr())
    rq('BROWSE2', 10, P, B().u32(2).u32(0).u32(5),
       B().ptr().v_str('X').ptr().v_i4(1).ptr().v_i4(2).hr())
    rq('BROWSE2', 10, P, B().u32(2).u32(0).u32(5), B().ptr(False).ptr(False).ptr(False).hr(0x80070057))
    rq('PERSIST', 7, P, None, B().hr())
    rq('PERSIST2', 8, P, None, B().ptr().v_str('LD1').ptr().v_i4(0).hr())
    rq('PERSIST2', 8, P, None, B().ptr(False).ptr(False).hr(0x8004CB0D))

    # ------------------------------------------------ PhysicalDevicePC
    cap.mark('pdevpc')
    rq('PC', 3, P, B().pmip(cba(IF['PCEVENT']), 0x1100, 0x1100, g(21)), B().u32(0x77).hr())
    rq('PC', 4, P, B().u32(0x77), B().hr())
    rq('PC', 5, P, B().pmip(cba(IF['PCEVENT']), 0x1100, 0x1100, g(21)), B().u32(0x78).hr())
    rq('PC', 6, P, B().u32(0x78), B().hr())
    rq('PCEVENT', 3, g(21), B().u32(0x77).pmip(cba(IF['LDEV']), 0x1001, 0x1001, L1).hr(0), B().hr())
    rq('PCEVENT', 4, g(21), B().u32(0x77), B().hr())

    # ------------------------------------------------ LogicalDevice
    cap.mark('ldev')
    rq('LDEV', 7, L1, None, B().ptr().bstr('LD1').hr())
    rq('LDEV', 7, L1, None, B().ptr(False).hr(1))
    rq('LDEV', 13, L1, None, B().ptr(False).hr(0x80004005))  # no ACCO pointer
    # ACCO of LD1: interface on object 0x2001
    rq('LDEV', 13, L1, None, B().pmip(cba(IF['SERVER']), 0x2001, 0x2001, A1).hr())
    # RTAuto of LD1 (2nd interface of the same object), also with NULL name
    rq('LDEV', 14, L1, B().ptr().bstr('RT1'), B().pmip(cba(IF['RTAUTO']), 0x2001, 0x2001, A2).hr())
    rq('LDEV', 14, L1, B().ptr(False), B().ptr(False).hr(0x80004005))
    # LD2: ACCO on object 0x2002 (a second ACCO for the SRT connection)
    rq('LDEV', 13, L2, None, B().pmip(cba(IF['SERVER']), 0x2002, 0x2002, A3).hr())
    rq('LDEV2', 15, L1, None, B().u16(2).u16(0).u16(1).u16(100).hr())
    rq('LDEV2', 16, L1, None, B().ptr().bstr('ID-1').ptr().bstr('V1.0').hr())
    rq('LDEV2', 16, L1, None, B().ptr(False).ptr(False).hr(1))

    def safearray(b, vartype, elems):
        b.ptr().ptr()
        b.u32(1).u16(1)           # dims32, dims16
        b.u16(0x0080)             # features
        b.u32(1).u16(0).u16(vartype).u32(vartype)   # element size, locks, vt16, vt32
        b.u32(len(elems)).ptr()   # elements, pointer
        b.u32(len(elems)).u32(0)  # bound elements, low bound
        b.u32(len(elems))         # array size
        for e in elems:
            b.u8(e)
        return b

    rq('LDEV2', 17, L1, None, safearray(B(), 16, [0x01, 0x05, 0x02, 0x07]).hr())
    rq('LDEV2', 17, L1, None, safearray(B(), 16, [0x01, 0x05, 0x02]).hr())  # odd size

    # Fixed bug 1: an OBJREF with OID 0 gives an interface without parent object; a later
    # call on its IPID must not dereference the parent ("Unknown LDev" note only)
    cap.mark('fix-null-parent')
    rq('LDEV', 14, g(80), B().ptr(False), B().pmip(cba(IF['LDEV']), 0x7100, 0, g(81)).hr())
    rq('LDEV', 13, g(81), None, B().pmip(cba(IF['SERVER']), 0x7101, 0x7101, g(82)).hr())
    # Fixed bug 2: the physical device interface made by get_LogicalDevice is not a
    # logical device; get_ACCO on its IPID must not link the ACCO to it
    cap.mark('fix-pdev-as-ldev')
    rq('PDEV', 12, g(83), B().ptr().bstr('LDX'), B().pmip(cba(IF['LDEV']), 0x7102, 0x7102, g(84)).hr())
    rq('LDEV', 13, g(83), None, B().pmip(cba(IF['SERVER']), 0x7103, 0x7103, g(85)).hr())

    # ------------------------------------------------ State / Time / GroupError / RTAuto
    cap.mark('state')
    rq('STATE', 7, P, None, B().u16(3).hr())
    rq('STATE', 7, P, None, B().u16(9).hr(0x80004005))
    for op in (8, 9, 10):
        rq('STATE', op, P, None, B().hr())
    rq('STATE', 11, P, B().pmip(cba(IF['STATEEV']), 0x1200, 0x1200, g(22)), B().u32(0x55).hr())
    rq('STATE', 12, P, B().u32(0x55), B().hr())
    rq('STATEEV', 3, g(22), B().u16(3).u16(2), B().hr())
    rq('STATEEV', 3, g(22), B().u16(12).u16(13), B().hr())
    rq('TIME', 7, P, None, B().dbl(45000.25).hr())
    rq('TIME', 8, P, B().dbl(45001.75), B().hr())
    rq('GERR', 7, P, None, B().u16(1).u32(0x66).hr())
    rq('GERR', 7, P, None, B().u16(11).u32(0x66).hr(0x80004005))
    rq('GERR', 8, P, B().pmip(cba(IF['GERREV']), 0x1300, 0x1300, g(23)), B().u32(0x66).hr())
    rq('GERR', 9, P, B().u32(0x66), B().hr())
    rq('GERREV', 3, g(23), B().u16(2).u16(1), B().hr())
    rq('GERREV', 3, g(23), B().u16(15).u16(4), B().hr())
    rq('RTAUTO', 7, A2, None, B().ptr().bstr('RT1').hr())
    rq('RTAUTO', 8, A2, None, B().u16(1).u16(0).hr())
    rq('RTAUTO2', 9, A2, None, B().ptr().bstr('RT-ID').ptr().bstr('RT-V').hr())

    # ------------------------------------------------ ICBAAccoMgt
    cap.mark('mgt')

    def addconn(b, prov, qt, qv, state, items):
        b.lpwstr(prov).u16(qt).u16(qv).u8(state).u32(len(items)).u32(len(items))
        var = B()
        for (pi, ci, pers, subst, eps) in items:
            b.ptr(pi is not None).ptr(ci is not None).u16(pers).al(4)
            b.ptr(subst is not None).ptr(eps is not None)
        return var

    # AddConnections: build fixed part then variable part
    def add_connections(items, prov='192.0.2.2!LD1'):
        b = B().lpwstr(prov).u16(0).u16(500).u8(1).u32(len(items)).u32(len(items))
        for (pi, ci, pers, subst, eps) in items:
            b.ptr(pi is not None).ptr(ci is not None).u16(pers).al(4)
            b.ptr(subst is not None).ptr(eps is not None)
        for (pi, ci, pers, subst, eps) in items:
            if pi is not None:
                b.lpwstr(pi)
            if ci is not None:
                b.lpwstr(ci)
            if subst is not None:
                b.v_i4(subst)
            if eps is not None:
                b.v_i4(eps)
        return b

    rq('MGT', 3, A1, add_connections([('Prov.Item1', 'Cons.Item1', 0, None, None),
                                      ('Prov.Item2', 'Cons.Item2', 1, 7, 2),
                                      (None, None, 2, None, 1)]),
       B().ptr().u32(3).u32(0x10).u16(1).hr(0).u32(0x11).u16(1).hr(1).u32(0x12).u16(2).hr(0x8004CB05).hr())
    rq('MGT', 3, A1, add_connections([]), B().ptr(False).hr(0x80004005))
    rq('MGT', 4, A1, B().u32(2).u32(2).u32(0x10).u32(0x11), B().ptr().u32(2).hr(0).hr(1).hr())
    rq('MGT', 4, A1, B().u32(1).u32(1).u32(0x12), B().ptr(False).hr(0x80004005))
    rq('MGT', 5, A1, None, B().hr())
    rq('MGT', 6, A1, B().u8(1).u32(2).u32(2).u32(0x10).u32(0x11), B().ptr().u32(2).hr(0).hr(0).hr())
    rq('MGT', 7, A1, None, B().u32(100).u32(3).hr())
    rq('MGT', 8, A1, None, B().u32(2).ptr().u32(2)
       .u32(0x10).u8(1).u16(1).hr(0).u32(0x11).u8(0).u16(2).hr(0).hr())
    rq('MGT', 8, A1, None, B().u32(0).ptr(False).hr(1))
    b = B().u32(12).ptr().u32(12)
    for i in range(12):
        b.u32(0x40 + i).u8(i & 1).u16(i).hr(0)
    rq('MGT', 8, A1, None, b.hr())

    def getconn_resp(items, stride_pad=True):
        """ICBAAccoMgt::GetConnections response, items = (prov, provitem, consitem, subst, eps, ...)"""
        b = B().ptr().u32(len(items))
        for (pr, pi, ci, sub_, ep) in items:
            b.ptr(pr is not None).ptr(pi is not None).ptr(ci is not None)
            b.ptr(sub_ is not None).ptr(ep is not None)
            b.u16(0).u16(100).u8(1).u16(1).u16(2).hr(0)
        for (pr, pi, ci, sub_, ep) in items:
            if pr is not None:
                b.lpwstr(pr)
            if pi is not None:
                b.lpwstr(pi)
            if ci is not None:
                b.lpwstr(ci)
            if sub_ is not None:
                b.v_i4(sub_)
            if ep is not None:
                b.v_i4(ep)
        return b.hr()

    rq('MGT', 9, A1, B().u32(2).u32(2).u32(0x10).u32(0x11),
       getconn_resp([('192.0.2.2!LD1', 'P.Item1', 'C.Item1', 5, 6), (None, None, None, None, None)]))
    rq('MGT', 9, A1, B().u32(0).u32(0), B().ptr(False).hr(0x80004005))
    rq('MGT', 10, A1, B().lpwstr('RT1').u16(0x30).u16(10), B().u16(8).hr())
    rq('MGT', 10, A1, B().lpwstr('RT1').u16(0x77).u16(10), B().u16(0).hr(0x8004CB0B))
    rq('MGT', 11, A1, None, B().u16(3).hr())
    rq('MGT', 12, A1, B().u16(4), B().hr())
    rq('MGT', 13, A1, None, B().u32(0xabcdef).hr())
    rq('MGT2', 14, A1, None, B().u32(0).ptr(False).hr())
    rq('MGT2', 14, A1, None, (lambda b: [b.u32(i) for i in range(0x20, 0x2c)] and b)(B().u32(12).ptr().u32(12)).hr())

    def consconn_resp(items):
        b = B().ptr().u32(len(items))
        for (a, c, d, e_, f_) in items:
            b.ptr(a is not None).ptr(c is not None).ptr(d is not None)
            b.ptr(e_ is not None).ptr(f_ is not None)
            b.u16(0x20).u16(50).u8(0).u16(2).hr(1)
        for (a, c, d, e_, f_) in items:
            if a is not None:
                b.lpwstr(a)
            if c is not None:
                b.lpwstr(c)
            if d is not None:
                b.lpwstr(d)
            if e_ is not None:
                b.v_i4(e_)
            if f_ is not None:
                b.v_i4(f_)
        return b.hr()

    rq('MGT2', 15, A1, B().u32(1).u32(1).u32(0x10), consconn_resp([('192.0.2.2!LD1', 'PI', 'CI', 1, 2)]))
    rq('MGT2', 15, A1, B().u32(0).u32(0), B().ptr(False).hr(1))

    def diag(items):
        b = B().ptr().u32(len(items))
        for (st, pers, ver, err) in items:
            b.u8(st).u16(pers).u16(ver).hr(err).hr(0)
        return b.hr()

    rq('MGT2', 16, A1, B().u32(0).u32(0), B().ptr(False).hr(1))
    rq('MGT2', 17, A1, None, B().u32(3).ptr().u32(3).u32(0x31).u32(0x32).u32(0x33).hr())
    rq('MGT2', 17, A1, None, B().u32(0).ptr(False).hr())
    rq('MGT2', 17, A1, None, B().u32(12).ptr().u32(12)
       .u32(1).u32(2).u32(3).u32(4).u32(5).u32(6).u32(7).u32(8).u32(9).u32(10).u32(11).u32(12).hr())

    def provconn(items):
        b = B().ptr().u32(len(items))
        for (cs, pi, ep) in items:
            b.ptr(cs is not None).ptr(pi is not None).u32(0x100).ptr(ep is not None)
            b.u16(0x30).u16(20).u8(1).hr(0)
        for (cs, pi, ep) in items:
            if cs is not None:
                b.lpwstr(cs)
            if pi is not None:
                b.lpwstr(pi)
            if ep is not None:
                b.v_i4(ep)
        return b.hr()

    rq('MGT2', 18, A1, B().u32(1).u32(1).u32(0x31), provconn([('192.0.2.77!CONS', 'PI', 9), (None, None, None)]))
    rq('MGT2', 18, A1, B().u32(0).u32(0), B().ptr(False).hr(1))
    rq('MGT2', 19, A1, B().u32(1).u32(4).u32(4).raw(b'\xde\xad\xbe\xef'), B().u32(0))
    rq('MGT2', 19, A1, B().u32(7).u32(0).u32(0), B().u32(4).raw(b'abcd'))
    rq('MGT2', 19, A1, B().u32(0x77).u32(0).u32(0), B().u32(0))

    # ------------------------------------------------ ICBAAccoSync
    cap.mark('sync')
    rq('SYNC', 3, A1, B().u32(2).u32(2).ptr().ptr(False).lpwstr('Item.A'),
       B().ptr().u32(2).ptr().u16(0x80).u32(1).u32(2).hr(0).ptr(False).u16(0x1c).u32(3).u32(4).hr(1)
       .v_i4(77).hr())
    rq('SYNC', 3, A1, B().u32(0).u32(0), B().ptr(False).hr(0x80004005))
    rq('SYNC', 4, A1, B().u32(2).u32(2).ptr().ptr().ptr(False).ptr(False)
       .lpwstr('Item.W').v_i4(5),
       B().ptr().u32(2).hr(0).hr(1).hr())
    rq('SYNC', 5, A1, B().u32(1).u32(1).ptr().ptr().u16(0x40).u32(5).u32(6)
       .lpwstr('Item.Q').v_i4(6),
       B().ptr().u32(1).hr(0).hr())
    rq('SYNC', 5, A1, B().u32(1).u32(1).ptr(False).ptr(False).u16(0x40).u32(5).u32(6), B().ptr(False).hr(1))

    # ------------------------------------------------ ICBAAccoServer (DCOM)
    cap.mark('server')

    def connect_req(cons, qt, qv, items, cons_ifc=None, v2=False):
        b = B().lpwstr(cons).u16(qt).u16(qv).u8(1)
        if v2:
            if cons_ifc:
                b.pmip(*cons_ifc)
            else:
                b.ptr(False)
        else:
            if cons_ifc:
                b.pmip(*cons_ifc)
            else:
                b.ptr(False)
        b.u32(len(items)).u32(len(items))
        for it in items:
            if v2:
                pi, td, cid, eps = it
                b.ptr(pi is not None).u16(len(td) if td else 0).al(4).ptr(bool(td)).ptr(eps is not None).u32(cid)
            else:
                pi, vt, cid, eps = it
                b.ptr(pi is not None).u16(vt).al(4).ptr(eps is not None).u32(cid)
        for it in items:
            if v2:
                pi, td, cid, eps = it
                if pi is not None:
                    b.lpwstr(pi)
                if td:
                    b.u32(len(td))
                    for t in td:
                        b.u16(t)
                if eps is not None:
                    b.v_i4(eps)
            else:
                pi, vt, cid, eps = it
                if pi is not None:
                    b.lpwstr(pi)
                if eps is not None:
                    b.v_i4(eps)
        return b

    def connect_resp(first, outs, hr=0):
        b = B().u8(first).ptr(bool(outs))
        if outs:
            b.u32(len(outs))
        for pid, h in outs:
            b.u32(pid).hr(h)
        return b.hr(hr)

    CONS = ('192.0.2.77!CONS', 0, 100)
    consifc = (cba(IF['CB']), 0x3001, 0x3001, C1)
    rq('SERVER', 3, A1, connect_req('192.0.2.77!CONS', 0, 100,
                                    [('Prov.Item1', 8, 0x100, None), ('Prov.Item2', 3, 0x101, 5),
                                     (None, 3, 0x102, None)], consifc),
       connect_resp(1, [(0x201, 0), (0x202, 1), (0, 0x8004CB05)]))
    # same ConsIDs again (existing connections are found), global HRESULT response
    rq('SERVER', 3, A1, connect_req('192.0.2.77!CONS', 0, 100, [('Prov.Item1', 8, 0x100, None)], consifc),
       B().u8(0).ptr(False).hr(0x80004005))
    # a consumer that is not "ip!name", and an unknown provider object (no ldev)
    rq('SERVER', 3, A1, connect_req('nobang', 0, 100, [('X', 3, 0x110, None)], consifc),
       connect_resp(0, [(0x210, 0)]))
    rq('SERVER', 3, g(90), connect_req('192.0.2.77!CONS', 0, 100, [('X', 3, 0x111, None)], None),
       connect_resp(0, [(0x211, 0)]))
    # Connect2 with type descriptions (also reached through the parent object's interface A2)
    rq('SERVER2', 8, A2, connect_req('192.0.2.77!CONS', 0, 100,
                                     [('Prov.Item3', [8], 0x120, None), ('Prov.Item4', [0x2003, 4], 0x121, 3),
                                      (None, [], 0x122, None)], consifc, v2=True),
       connect_resp(1, [(0x221, 0), (0x222, 0), (0x223, 1)]))
    # Connect2 without consumer interface pointer
    rq('SERVER2', 8, A1, connect_req('192.0.2.78!CONS', 0, 100, [('Prov.Item5', [3], 0x130, None)], None, v2=True),
       connect_resp(0, [(0x231, 0)]))
    # Connect2: a consumer interface pointer without IPID (no interface), an unknown
    # provider object, a consumer name without '!' and a host that is not an address
    nullifc = (cba(IF['CB']), 0x3003, 0x3003, b'\0' * 16)
    rq('SERVER2', 8, A1, connect_req('192.0.2.79!CONS', 0, 100, [('Prov.Item6', [3], 0x140, None)], nullifc, v2=True),
       connect_resp(0, [(0x241, 0)]))
    rq('SERVER2', 8, g(90), connect_req('192.0.2.77!CONS', 0, 100, [('Prov.Item6', [3], 0x141, None)], None, v2=True),
       connect_resp(0, [(0x242, 0)]))
    rq('SERVER2', 8, A1, connect_req('nobang', 0, 100, [('Prov.Item6', [3], 0x142, None)], None, v2=True),
       connect_resp(0, [(0x243, 0)]))
    rq('SERVER', 3, A1, connect_req('no-such-host!CONS', 0, 100, [('Prov.Item7', 3, 0x150, None)], None),
       connect_resp(0, [(0x251, 0)]))
    # connections for the pipelined Disconnect below
    rq('SERVER', 3, A1, connect_req('192.0.2.77!CONS', 0, 100, [('Prov.Item8', 3, 0x160, None)], consifc),
       connect_resp(0, [(0x261, 0)]))
    rq('SERVER', 7, A1, B().lpwstr('192.0.2.77!CONS'), B().hr())
    rq('SERVER', 6, A1, B().u8(1).u32(2).u32(2).u32(0x201).u32(0x202), B().ptr().u32(2).hr(0).hr(0).hr())
    rq('SERVER', 6, A1, B().u8(0).u32(0).u32(0), B().ptr(False).hr(0x80004005))

    # --- callback data (server calls the consumer, flow B)
    cap.mark('callback')
    d1 = cbadata(1, [(0x100, 0x80, b'\x01\x02\x03\x04'), (0x101, 0x1c, b'\x05'), (0x102, 0x40, b'')])
    fb.rpc(CB0, 3, C1, B().u32(len(d1)).u32(len(d1)).raw(d1), B().hr())
    d2 = cbadata(1, [(0x100, 0x00, b'\x09'), (0x7777, 0xc0, b'\x0a\x0b')])   # bad QC, unknown consid
    fb.rpc(CB0, 3, C1, B().u32(len(d2)).u32(len(d2)).raw(d2), B().hr())
    d3 = cbadata(0x10, [(0x100, 0x84, b'\x01'), (0x101, 0x80, b'\x02\x03')])
    fb.rpc(CB0, 3, C1, B().u32(len(d3)).u32(len(d3)).raw(d3), B().hr())
    d4 = cbadata(0x11, [(None, 0x80, b'\x01')])
    fb.rpc(CB0, 3, C1, B().u32(len(d4)).u32(len(d4)).raw(d4), B().hr())
    d5 = cbadata(7, [])             # unknown buffer version
    fb.rpc(CB0, 3, C1, B().u32(len(d5)).u32(len(d5)).raw(d5), B().hr())
    d6 = cbadata(1, [], flags=2)    # timestamps flag: not handled
    fb.rpc(CB0, 3, C1, B().u32(len(d6)).u32(len(d6)).raw(d6), B().hr())
    fb.rpc(CB0, 3, g(91), B().u32(len(d1)).u32(len(d1)).raw(d1), B().hr())   # unknown consumer
    fb.rpc(CB1, 4, C1, B(), B().hr())            # Gnip
    fb.rpc(CB1, 4, C1, B(), B().hr(1))
    # GetConnectionData: consumer data pulled by the provider
    rq('SERVER2', 9, A1, B().lpwstr('192.0.2.77!CONS'),
       B().u32(len(d1)).ptr().u32(len(d1)).raw(d1).hr())
    rq('SERVER2', 9, A1, B().lpwstr('nobang'), B().u32(0).ptr(False).hr(0x80004005))
    rq('SERVER2', 9, A1, B().lpwstr('192.0.2.77!CONS'), B().u32(len(d4)).ptr().u32(len(d4)).raw(d4).hr())

    # --- disconnect (DCOM)
    cap.mark('disconnect')
    rq('SERVER', 4, A1, B().u32(2).u32(2).u32(0x201).u32(0x202), B().ptr().u32(2).hr(0).hr(1).hr())
    rq('SERVER', 4, A1, B().u32(1).u32(1).u32(0x201), B().ptr(False).hr(0x80004005))
    # two Disconnect requests in flight for the same ProvID, then both responses
    pipe(fa, [(S['SERVER'], 4, A1, B().u32(1).u32(1).u32(0x261), B().ptr().u32(1).hr(0).hr()),
              (S['SERVER'], 4, A1, B().u32(1).u32(1).u32(0x261), B().ptr().u32(1).hr(0).hr())])
    rq('SERVER', 4, g(90), B().u32(1).u32(1).u32(0x201), B().ptr().u32(1).hr(0).hr())
    rq('SERVER', 5, A1, B().lpwstr('192.0.2.77!CONS'), B().hr())
    rq('SERVER', 5, A1, B().lpwstr('192.0.2.77!CONS'), B().hr(1))
    rq('SERVER', 5, A1, B().lpwstr('nobang'), B().hr())
    rq('SERVER', 5, A1, B().lpwstr('no-such-host!X'), B().hr())

    # ------------------------------------------------ ICBAAccoServerSRT
    cap.mark('srt')
    MAC1 = b'\x02\0\0\0\0\x09'
    MAC2 = b'\x02\0\0\0\0\x0a'

    def connectcr(cons, qt, qv, mac, flags, crs, ifc):
        b = B().lpwstr(cons).u16(qt).u16(qv)
        if ifc:
            b.pmip(*ifc)
        else:
            b.ptr(False)
        b.raw(mac).al(4).u32(flags).u32(len(crs)).u32(len(crs))
        for (crid, ln) in crs:
            b.u16(crid).u16(ln)
        return b

    def connectcr_resp(first, mac, outs, hr=0):
        b = B().u8(first).raw(mac).ptr(bool(outs))
        if outs:
            b.u32(len(outs))
        for pcrid, h in outs:
            b.u32(pcrid).hr(h)
        return b.hr(hr)

    cons2 = (cba(IF['CB']), 0x3002, 0x3002, C2)
    rq('SRT', 3, A3, connectcr('192.0.2.77!CONS2', 0x30, 1, MAC1, 3, [(0xc001, 40), (0xc002, 24)], cons2),
       connectcr_resp(1, b'\x02\0\0\0\0\x02', [(5, 0), (6, 0)]))
    # the same frame again (found), a flags value without the two bits
    rq('SRT', 3, A3, connectcr('192.0.2.77!CONS2', 0x30, 1, MAC1, 0, [(0xc001, 40)], cons2),
       connectcr_resp(0, b'\x02\0\0\0\0\x02', [(5, 0)]))
    # a second consumer MAC, global error response
    rq('SRT', 3, A3, connectcr('192.0.2.77!CONS3', 0x30, 1, MAC2, 2, [(0xc010, 24)], None),
       connectcr_resp(0, b'\x02\0\0\0\0\x02', [], 0x8004CB1B))
    # a ConnectCR without a consumer ldev / provider ldev: not tracked
    rq('SRT', 3, A3, connectcr('nobang', 0x30, 1, MAC1, 0, [(0xc020, 24)], None),
       connectcr_resp(0, b'\x02\0\0\0\0\x02', [(9, 0)]))
    rq('SRT', 3, g(92), connectcr('192.0.2.77!CONS2', 0x30, 1, MAC1, 0, [(0xc021, 24)], None),
       connectcr_resp(0, b'\x02\0\0\0\0\x02', [(9, 0)]))
    # ConnectCR with 120 frames: more than the call table keeps
    rq('SRT', 3, A3, connectcr('192.0.2.77!CONS3', 0x30, 1, MAC2, 0, [(0xc100 + i, 8) for i in range(110)], None),
       B().u8(0).raw(b'\x02\0\0\0\0\x02').ptr(False).hr(0x80004005))

    def srt_connect(pcrid, state, last, items):
        b = B().u32(pcrid).u8(state).u8(last).u32(len(items)).u32(len(items))
        for (pi, td, cid, rl) in items:
            b.ptr(pi is not None).u16(len(td) if td else 0).al(4).ptr(bool(td)).u32(cid).u16(rl).al(4)
        for (pi, td, cid, rl) in items:
            if pi is not None:
                b.lpwstr(pi)
            if td:
                b.u32(len(td))
                for t in td:
                    b.u16(t)
        return b

    rq('SRT', 5, A3, srt_connect(5, 1, 1, [('SRT.Item1', [3], 0x300, 8), ('SRT.Item2', [8, 0x2003], 0x301, 12),
                                            (None, None, 0x302, 8)]),
       B().ptr().u32(3).u32(0x401).hr(0).u32(0x402).hr(0).u32(0).hr(1).hr())
    rq('SRT', 5, A3, srt_connect(5, 0, 0, [('SRT.Item1', [3], 0x300, 8)]), B().ptr(False).hr(0x80004005))
    rq('SRT', 5, A3, srt_connect(77, 1, 1, [('X', [3], 0x310, 8)]), B().ptr(False).hr(0))   # unknown ProvCRID

    cap.mark('rt')
    rtc = lambda data, crid=0xc001, cyc=1, mac=MAC1: rt_frame(cap, ETH, mac, crid, data, cyc)
    # frame c001: items at offsets 4 (len 8), 12 (len 12), 24 (len 8)
    rtc(cbadata(0x11, [(None, 0x80, b'\x01\x02\x03\x04\x05'), (None, 0x80, b'\x01' * 9), (None, 0x80, b'\x07' * 5)]))
    rtc(cbadata(0x11, [(None, 0x84, b'\x11\x12\x13\x14\x15'), (None, 0x80, b'\x01' * 9), (None, 0x1c, b'\x07' * 5)]), cyc=2)
    # a hole of two zero octets in front of the second item, and an unknown QC (expert info)
    f = cbadata(0x11, [(None, 0x80, b'\x01\x02\x03\x04\x05')], count=2)
    f += b'\0\0' + struct.pack('<H', 12) + bytes([0x33]) + b'\x01' * 9
    rtc(f, cyc=3)
    # frame ID without a ConnectCR: no frame, but still decoded
    rtc(cbadata(0x11, [(None, 0x80, b'\x01\x02')]), crid=0xc777, cyc=4)
    # the same CRID but another consumer MAC
    rtc(cbadata(0x11, [(None, 0x80, b'\x01\x02')]), cyc=5, mac=MAC2)
    # UDP 34962 carrying PN-RT with a CBA payload
    rt = struct.pack('>H', 0xc001) + cbadata(0x11, [(None, 0x80, b'\x01\x02\x03\x04\x05')]) + b'\0' * 20
    rt += struct.pack('>HBB', 8, 0x35, 0)
    udp_frame(cap, ETH, ip_srv, ip_cli, 34962, 34962, rt, dmac=MAC1)

    cap.mark('srt-end')
    rq('SRT', 8, A3, B().u8(1).u32(2).u32(2).u32(0x401).u32(0x402), B().ptr().u32(2).hr(0).hr(0).hr())
    rq('SRT', 8, A3, B().u8(0).u32(0).u32(0), B().ptr(False).hr(0x80004005))
    rq('SRT', 6, A3, B().u32(2).u32(2).u32(0x401).u32(0x402), B().ptr().u32(2).hr(0).hr(1).hr())
    rq('SRT', 6, A3, B().u32(1).u32(1).u32(0x401), B().ptr(False).hr(0x80004005))
    # SRT Connect on an object without a logical device
    rq('SRT', 5, g(92), srt_connect(5, 1, 1, [('X', [3], 0x320, 8)]), B().ptr(False).hr(0))
    # a frame that two DisconnectCR calls in flight both disconnect
    rq('SRT', 3, A3, connectcr('192.0.2.77!CONS2', 0x30, 1, MAC2, 0, [(0xc030, 24)], cons2),
       connectcr_resp(0, b'\x02\0\0\0\0\x02', [(8, 0)]))
    pipe(fa, [(S['SRT'], 4, A3, B().u32(1).u32(1).u32(8), B().ptr().u32(1).hr(0).hr()),
              (S['SRT'], 4, A3, B().u32(1).u32(1).u32(8), B().ptr().u32(1).hr(0).hr())])
    rq('SRT', 4, A3, B().u32(2).u32(2).u32(5).u32(6), B().ptr().u32(2).hr(0).hr(0).hr())
    rq('SRT', 4, A3, B().u32(1).u32(1).u32(5), B().ptr(False).hr(0))                 # no longer connected
    rq('SRT', 4, A3, B().u32(1).u32(1).u32(99), B().ptr(False).hr(0x80004005))      # unknown ProvCRID
    rq('SRT', 4, g(92), B().u32(1).u32(1).u32(5), B().ptr(False).hr(0))
    # DisconnectMe of the consumer that owns the frames 0xc010 and 0xc100...
    rq('SRT', 7, A3, B().lpwstr('192.0.2.77!CONS3'), B().hr())
    rq('SRT', 7, A3, B().lpwstr('192.0.2.77!CONS3'), B().hr(1))
    rq('SRT', 7, A3, B().lpwstr('nobang'), B().hr())
    # data after the DisconnectCR: out of range, frame not found
    rtc(cbadata(0x11, [(None, 0x80, b'\x01\x02\x03\x04\x05')]), cyc=9)

    # callback ICBAAccoCallback2 on a SRT consumer (Gnip)
    fb.rpc(CB1, 4, C2, B(), B().hr())
    return fa


def mk_raw_repro(cap):
    """PN-RT over UDP in a capture without link layer (CBA heuristic, no DL destination)."""
    f = Flow(cap, '198.51.100.1', '198.51.100.2', 50000, 135, ifid=RAW)
    f.bind([(cba(IF['PDEV']), 0), (cba(IF['SRT']), 0)])
    P, L, A = g(60), g(61), g(62)
    f.rpc(0, 12, P, B().ptr().bstr('LDR'), B().pmip(cba(IF['LDEV']), 0x5001, 0x5001, L, ip='198.51.100.2').hr())
    f.rpc(0, 12, P, B().ptr().bstr('LDR'), B().pmip(cba(IF['LDEV']), 0x5001, 0x5001, L, ip='198.51.100.2').hr())
    # the ACCO interface of LDR
    f.rpc(1, 3, L, B().lpwstr('198.51.100.1!RAWCONS').u16(0x30).u16(1).ptr(False)
          .raw(b'\x02\0\0\0\0\x19').al(4).u32(0).u32(1).u32(1).u16(0xc0a1).u16(40),
          B().u8(1).raw(b'\x02\0\0\0\0\x02').ptr().u32(1).u32(3).hr(0).hr())
    rt = struct.pack('>H', 0xc0a1) + cbadata(0x11, [(None, 0x80, b'\x01\x02\x03\x04\x05')]) + b'\0' * 20
    rt += struct.pack('>HBB', 8, 0x35, 0)
    udp_frame(cap, RAW, '198.51.100.2', '198.51.100.1', 34962, 34962, rt)
    # PN-RT over UDP with an Ethernet link layer to a frame ID that has no ConnectCR
    return f


def mk_malformed(cap):
    f = Flow(cap, '203.0.113.1', '203.0.113.2', 50100, 135)
    ifs = [(cba(IF[n]), 0) for n in ORDER]
    f.bind(ifs)
    S = CTX
    P, L, A = g(70), g(71), g(72)

    def rq(n, op, obj, req=None, rsp=None):
        f.rpc(S[n], op, obj, req or B(), rsp)

    rq('PDEV', 12, P, B().ptr().bstr('MLD'), B().pmip(cba(IF['LDEV']), 0x7001, 0x7001, L, ip='203.0.113.2').hr())
    rq('LDEV', 13, L, None, B().pmip(cba(IF['SERVER']), 0x7002, 0x7002, A, ip='203.0.113.2').hr())
    # ---- the fixed bugs of the review (p8)
    # 1. NULL parent (OID 0): ldev lookup
    X = g(73)
    rq('LDEV', 14, g(74), B().ptr(False), B().pmip(cba(IF['LDEV']), 0x7100, 0, X).hr())
    rq('LDEV', 13, X, None, B().ptr(False).hr())
    # 2. a pdev interface used as ldev
    PD = g(75)
    rq('PDEV', 12, PD, B().ptr().bstr('MLD2'), B().pmip(cba(IF['LDEV']), 0x7003, 0x7003, g(76), ip='203.0.113.2').hr())
    rq('LDEV', 13, PD, None, B().pmip(cba(IF['SERVER']), 0x7004, 0x7004, g(77), ip='203.0.113.2').hr())
    # 3. Connect with array sizes past the end
    def conn_big(n, off=0):
        b = B().lpwstr('203.0.113.1!MC').u16(0).u16(100).u8(1).ptr(False).u32(1).u32(n)
        return b.raw(b'\0' * 32)
    rq('SERVER', 3, A, conn_big(0xffffffff), B().u8(0).ptr(False).hr(1))
    rq('SERVER', 3, A, conn_big(0x10000), B().u8(0).ptr(False).hr(1))
    b = B().lpwstr('203.0.113.1!MC').u16(0).u16(100).u8(1).ptr(False).u32(1).u32(0xffffff00)
    rq('SERVER2', 8, A, b, B().u8(0).ptr(False).hr(1))
    rq('SERVER', 4, A, B().u32(1).u32(0xfffffff0).u32(5), B().ptr(False).hr(1))
    rq('SRT', 6, A, B().u32(1).u32(0xfffffff0).u32(5), B().ptr(False).hr(1))
    rq('SRT', 4, A, B().u32(1).u32(0xfffffff0).u32(5), B().ptr(False).hr(1))
    rq('SRT', 3, A, B().lpwstr('203.0.113.1!MC').u16(0x30).u16(1).ptr(False).raw(b'\x02\0\0\0\0\x44').al(4)
       .u32(0).u32(1).u32(0xfffffff0).u16(0xc200).u16(8), B().u8(0).raw(b'\0' * 6).ptr(False).hr(1))
    # SRT Connect: a frame (ConnectCR) first, then huge array and type description sizes
    rq('SRT', 3, A, B().lpwstr('203.0.113.1!MC').u16(0x30).u16(1).ptr(False).raw(b'\x02\0\0\0\0\x44').al(4)
       .u32(0).u32(1).u32(1).u16(0xc200).u16(8), B().u8(1).raw(b'\x02\0\0\0\0\x02').ptr().u32(1).u32(42).hr().hr())
    rq('SRT', 5, A, B().u32(42).u8(1).u8(1).u32(1).u32(0xfffffff0), B().ptr(False).hr(1))
    # PN-RT frames for the frame set up above: truncated CBA data, a hole running off the end,
    # an item longer than the frame (they have to come before the frames PROFINET IO takes)
    rt_frame(cap, ETH, b'\x02\0\0\0\0\x44', 0xc200, struct.pack('<BBH', 0x11, 0, 3) + b'\0' * 12)
    rt_frame(cap, ETH, b'\x02\0\0\0\0\x44', 0xc200, struct.pack('<BBH', 0x11, 0, 1) + struct.pack('<H', 2) + b'\x80')
    rt_frame(cap, ETH, b'\x02\0\0\0\0\x44', 0xc200, struct.pack('<BBH', 0x11, 0, 1) + struct.pack('<H', 400) + b'\x80' * 8)

    b = B().u32(42).u8(1).u8(1).u32(1).u32(1).ptr().u16(1).al(4).ptr().u32(1).u16(8).al(4)
    b.lpwstr('MX').u32(0xfffffff0)
    rq('SRT', 5, A, b, B().ptr(False).hr(1))
    # a typedesc size of 5000 (past the table limit of 1000 in Connect2)
    b = B().lpwstr('203.0.113.1!MC').u16(0).u16(100).u8(1).ptr(False).u32(1).u32(1)
    b.ptr().u16(1).al(4).ptr().ptr(False).u32(0x900).lpwstr('MP').u32(5000)
    b.raw(b'\x08\0' * 5000)
    rq('SERVER2', 8, A, b, B().u8(0).ptr(False).hr(1))
    # 4. quadratic Connect: 6000 connections of 16 bytes (the connection cap is 5000)
    n = 6000
    b = B().lpwstr('203.0.113.1!MC').u16(0).u16(100).u8(1).ptr(False).u32(n).u32(n)
    for i in range(n):
        b.ptr(False).u16(3).al(4).ptr(False).u32(0x10000 + i)
    stub = B().this().raw(bytes(b.b))
    # fragment the request in DCE/RPC (first/last fragments)
    f.call += 1
    body = bytes(stub.b)
    FR = 4000
    frs = [body[i:i + FR] for i in range(0, len(body), FR)]
    for k, fr in enumerate(frs):
        fl = (1 if k == 0 else 0) | (2 if k == len(frs) - 1 else 0) | 0x80
        hdr = struct.pack('<IHH', len(body), S['SERVER'], 3) + A + fr
        f.tcp(True, struct.pack('<BBBB4sHHI', 5, 0, 0, fl, b'\x10\0\0\0', 16 + len(hdr), 0, f.call) + hdr)
    f.tcp(False, response(f.call, S['SERVER'], bytes(B().that().u8(0).ptr(False).hr(1).b)))
    # ---- truncated and odd packets
    # odd SAFEARRAY element count in PBAddressInfo
    # truncated requests (cut after the DCOM this)
    for n_, op, obj in (('SERVER', 3, A), ('SRT', 3, A), ('SRT', 5, A), ('MGT', 3, A), ('MGT2', 18, A),
                        ('SYNC', 3, A), ('SYNC', 4, A), ('SYNC', 5, A), ('SERVER2', 9, A)):
        f.raw_rpc(S[n_], op, obj, bytes(B().this().b) + b'\0\0\0\0\x05\0\0\0')
    for n_, op in (('MGT', 8), ('MGT', 9), ('MGT2', 15), ('MGT2', 16), ('MGT2', 18), ('SYNC', 3)):
        f.raw_rpc(S[n_], op, A, bytes(B().this().b), bytes(B().that().ptr().u32(1000).b))
    f.raw_rpc(S['SRT'], 3, A, bytes(B().this().b), bytes(B().that().u8(1).raw(b'\0\0').b))
    f.raw_rpc(S['SERVER'], 3, A, bytes(B().this().b), bytes(B().that().u8(1).ptr().u32(5).b))
    f.raw_rpc(S['SYNC'], 3, A, bytes(B().this().b), bytes(B().that().ptr().u32(9).b))
    # callback data with an item shorter than its header and a truncated item
    d = struct.pack('<BBH', 1, 0, 1) + struct.pack('<H', 2) + b'\0\0\0\0\0\0'
    f.raw_rpc(S['CB'], 3, A, bytes(B().this().u32(len(d)).u32(len(d)).raw(d).b), bytes(B().that().hr().b))
    d = struct.pack('<BBH', 1, 0, 5) + struct.pack('<H', 30) + b'\0' * 8
    f.raw_rpc(S['CB'], 3, A, bytes(B().this().u32(len(d)).u32(len(d)).raw(d).b), bytes(B().that().hr().b))
    d = struct.pack('<BBH', 0x11, 0, 2) + b'\0\0\0\0\0\0\0\0'
    f.raw_rpc(S['CB'], 3, A, bytes(B().this().u32(len(d)).u32(len(d)).raw(d).b), bytes(B().that().hr().b))
    # PBAddressInfo with a truncated array
    f.raw_rpc(S['LDEV2'], 17, L, bytes(B().this().b), bytes(B().that().ptr().ptr().u32(1).u16(1).u16(0x80)
                                                       .u32(1).u16(0).u16(16).u32(16).u32(4).ptr()
                                                       .u32(4).u32(0).u32(100).u8(1).b))
    # get_ACCO response without data; GetDiagnosis with a huge length
    f.raw_rpc(S['MGT2'], 19, A, bytes(B().this().u32(1).u32(0x7fffffff).u32(1).u8(1).b),
              bytes(B().that().u32(0x7fffffff).b))
    # Browse responses cut short
    f.raw_rpc(S['BROWSE'], 8, A, bytes(B().this().u32(0).u32(1).b), bytes(B().that().ptr().b))
    # ConnectCR response for an unknown call (no request info)
    f.tcp(False, response(900, S['SRT'], bytes(B().that().u8(1).raw(b'\0' * 6).ptr(False).hr().b)))
    f.tcp(False, response(901, S['SERVER'], bytes(B().that().u8(1).ptr(False).hr().b)))
    f.tcp(False, response(902, S['SRT'], bytes(B().that().ptr(False).hr().b)))
    f.tcp(False, response(903, S['SERVER2'], bytes(B().that().u32(0).ptr().u32(4).raw(cbadata(1, [])).hr().b)))
    # PN-RT: a version we do not take and flags set (not claimed by CBA; PROFINET IO takes them)
    rt_frame(cap, ETH, b'\x02\0\0\0\0\x44', 0xc001, cbadata(0x12, [(None, 0x80, b'\x01\x02')]), 6)
    rt_frame(cap, ETH, b'\x02\0\0\0\0\x44', 0xc001, cbadata(0x11, [(None, 0x80, b'\x01\x02')], flags=1), 7)
    # 16 bit QC values in the Sync calls (the field is an 8 bit one)
    rq('SYNC', 3, A, B().u32(1).u32(1).ptr().lpwstr('I'),
       B().ptr().u32(1).ptr(False).u16(0x1234).u32(1).u32(2).hr(0).hr())
    rq('SYNC', 5, A, B().u32(1).u32(1).ptr(False).ptr(False).u16(0xff40).u32(5).u32(6), B().ptr(False).hr(1))
    # PN-RT: cyclic frame IDs outside the CBA range (class 3 and UDP multicast)
    rt_frame(cap, ETH, b'\x02\0\0\0\0\x44', 0xfb10, cbadata(0x11, [(None, 0x80, b'\x01\x02')]), 10)
    rt_frame(cap, ETH, b'\x02\0\0\0\0\x44', 0x0200, cbadata(0x11, [(None, 0x80, b'\x01\x02')]), 11)
    return f


def mk_fixes(cap):
    """Reproducers of the review findings that raise an error expert info (array size past
    the end of the data) or are large (more connections than the cap)."""
    f = Flow(cap, '192.0.2.101', '192.0.2.102', 52000, 135)
    f.bind([(cba(IF[n]), 0) for n in ('PDEV', 'LDEV', 'SERVER', 'SERVER2', 'SRT')])
    P, L = g(100), g(101)

    def rq(ctx, op, obj, req, rsp):
        f.rpc(ctx, op, obj, req, rsp)

    rq(0, 12, P, B().ptr().bstr('FIX'), B().pmip(cba(IF['LDEV']), 0x8001, 0x8001, L, ip='192.0.2.102').hr())
    # Connect / Connect2 / Disconnect with an array size of 4G / 16M entries
    def conn_big(n):
        return B().lpwstr('192.0.2.101!FC').u16(0).u16(100).u8(1).ptr(False).u32(1).u32(n).raw(b'\0' * 32)
    rq(2, 3, L, conn_big(0xffffffff), B().u8(0).ptr(False).hr(1))
    rq(3, 8, L, B().lpwstr('192.0.2.101!FC').u16(0).u16(100).u8(1).ptr(False).u32(1).u32(0xffffff00).raw(b'\0' * 32),
       B().u8(0).ptr(False).hr(1))
    rq(2, 4, L, B().u32(1).u32(0xfffffff0).u32(5), B().ptr(False).hr(1))
    # ConnectCR sets up a frame; SRT DisconnectCR / Connect with huge array and type description sizes
    rq(4, 3, L, B().lpwstr('192.0.2.101!FC').u16(0x30).u16(1).ptr(False).raw(b'\x02\0\0\0\0\x55').al(4)
       .u32(0).u32(1).u32(1).u16(0xc300).u16(8), B().u8(1).raw(b'\x02\0\0\0\0\x02').ptr().u32(1).u32(7).hr().hr())
    rq(4, 4, L, B().u32(1).u32(0xfffffff0).u32(7), B().ptr(False).hr(1))
    rq(4, 5, L, B().u32(7).u8(1).u8(1).u32(1).u32(0xfffffff0), B().ptr(False).hr(1))
    b = B().u32(7).u8(1).u8(1).u32(1).u32(1).ptr().u16(1).al(4).ptr().u32(1).u16(8).al(4)
    b.lpwstr('FX').u32(0xfffffff0)
    rq(4, 5, L, b, B().ptr(False).hr(1))
    # more connections in one Connect than the connection cap (5000), in DCE/RPC fragments
    n = 5100
    b = B().lpwstr('192.0.2.101!FC').u16(0).u16(100).u8(1).ptr(False).u32(n).u32(n)
    for i in range(n):
        b.ptr(False).u16(3).al(4).ptr(False).u32(0x10000 + i)
    body = bytes(B().this().raw(bytes(b.b)).b)
    f.call += 1
    frs = [body[i:i + 4000] for i in range(0, len(body), 4000)]
    for k, fr in enumerate(frs):
        fl = (1 if k == 0 else 0) | (2 if k == len(frs) - 1 else 0) | 0x80
        hdr = struct.pack('<IHH', len(body), 2, 3) + L + fr
        f.tcp(True, struct.pack('<BBBB4sHHI', 5, 0, 0, fl, b'\x10\0\0\0', 16 + len(hdr), 0, f.call) + hdr)
    f.tcp(False, response(f.call, 2, bytes(B().that().u8(0).ptr(False).hr(1).b)))
    mk_bug(cap)
    return f


def mk_bug(cap):
    """ICBAAccoMgt2::DiagConsConnections response with entries (last 4 frames of the fixes capture): used an
    uninitialised proto_item when there is no tree (packet-dcom-cba-acco.c, dissect_ICBAAccoMgt2_DiagConsConnections_resp)."""
    f = Flow(cap, '192.0.2.201', '192.0.2.202', 51000, 135)
    f.bind([(cba(IF['MGT2']), 0)])
    b = B().ptr().u32(2)
    for (st, pers, ver, err) in [(1, 0, 1, 0), (0, 2, 3, 0x8004CB08)]:
        b.u8(st).u16(pers).u16(ver).hr(err).hr(0)
    f.rpc(0, 16, g(95), B().u32(2).u32(2).u32(0x10).u32(0x11), b.hr())
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    cap = Cap()
    mk_main(cap)
    cap.mark('raw')
    mk_raw_repro(cap)
    fn = os.path.join(out, 'profinet-cba-coverage.pcapng')
    cap.write(fn)
    if verbose:
        for n, name in cap.marks:
            print(n, name)
        print(len(cap.recs), 'frames', os.path.getsize(fn), 'octets')
    cap = Cap()
    mk_malformed(cap)
    fn = os.path.join(out, 'profinet-cba-coverage-malformed.pcapng')
    cap.write(fn)
    if verbose:
        print(len(cap.recs), 'malformed frames', os.path.getsize(fn), 'octets')
    cap = Cap()
    mk_fixes(cap)
    fn = os.path.join(out, 'profinet-cba-fixes.pcapng')
    cap.write(fn)
    if verbose:
        print(len(cap.recs), 'fix reproducer frames', os.path.getsize(fn), 'octets')


if __name__ == '__main__':
    main()
