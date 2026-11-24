#!/usr/bin/env python3
# Generates test/captures/dcerpc_nt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""mkdcerpc_nt.py <outdir>: synthetic captures for the shared DCE/RPC
helpers in packet-dcerpc-ndr.c (NDR primitives) and packet-dcerpc-nt.c
(policy handle tracking, UNICODE/LSA/ASCII strings, SIDs, NTTIME, status
codes, account flags, logon hours, SID arrays, data blobs, ...).

These files have no port or interface of their own; they are reached
through the interfaces that use them. The capture has connection-oriented
DCE/RPC over TCP to LSARPC, SAMR, WINREG, SRVSVC, DRSUAPI and the
hand-written NETLOGON and SPOOLSS dissectors, single calls of WKSSVC,
ATSVC, WITNESS and EVENTLOG for helpers only they use, and SMB2
CREATE/READ/CLOSE for the GUID handle tracking. The LSA connection has
policy handle life cycles, including shortened versions of the
ndrnt_polhnd_reclose.py and ndrnt_polhnd_collide.py
reproducers.

The PIDL interfaces are marshalled by ndrgen.py (from
../dcerpc-drsuapi-coverage, with NTTIME and NTTIME_1sec fixed) from the
Pidl NDR trees of their IDL files (<iface>.json, written by idl2json.pl);
the NETLOGON, SPOOLSS, WITNESS and EVENTLOG stubs are built by hand
below. Everything is built with
struct; nothing comes from a real network. Addresses are from
192.0.2.0/24.

Writes dcerpc_nt-coverage.pcap and dcerpc_nt-coverage-malformed.pcap.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct

HERE = os.path.dirname(os.path.abspath(__file__))
from ndrgen import Gen, Ctx, Ptr, TCP, RPC, write_pcap  # noqa: E402
from pidljson import pidl_json

DOM = 'S-1-5-21-1004336348-1177238915-682003330'


# ------------------------------------------------------------------ values
def sid_bytes(s):
    p = s.split('-')
    subs = [int(x) for x in p[3:]]
    return struct.pack('<BB', int(p[1]), len(subs)) + int(p[2]).to_bytes(6, 'big') + \
        b''.join(struct.pack('<I', x) for x in subs)


def ace(atype, flags, mask, sid):
    body = struct.pack('<I', mask) + sid_bytes(sid)
    return struct.pack('<BBH', atype, flags, 4 + len(body)) + body


def acl(aces):
    body = b''.join(aces)
    return struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body


def secdesc():
    """Self-relative security descriptor with owner, group, SACL, DACL."""
    owner = sid_bytes(DOM + '-500')
    group = sid_bytes(DOM + '-513')
    sacl = acl([ace(2, 0xc0, 0x000f003f, 'S-1-1-0')])
    dacl = acl([ace(0, 0x00, 0x000f07ff, DOM + '-500'),
                ace(1, 0x02, 0x00020015, 'S-1-5-32-544')])
    off = 20
    o_own, o_grp = off, off + len(owner)
    o_sacl = o_grp + len(group)
    o_dacl = o_sacl + len(sacl)
    hdr = struct.pack('<BBHIIII', 1, 0, 0x8014, o_own, o_grp, o_sacl, o_dacl)
    return hdr + owner + group + sacl + dacl


SD = secdesc()


class Handles:
    """Policy handle values. Every handle is unique in the capture unless
    a scenario reuses one on purpose (Wireshark's handle table is global)."""

    def __init__(self):
        self.n = 0

    def new(self, tag):
        self.n += 1
        return struct.pack('<I', 0) + tag.encode()[:4].ljust(4, b'_') + \
            struct.pack('<I', self.n) + bytes(range(0x40, 0x48))


H = Handles()
NULLH = bytes(20)


def lstr(x):
    """lsa_String value for ndrgen: length, size, pointer to UTF-16 units."""
    u = [ord(c) for c in x]
    return {'length': 2 * len(u), 'size': 2 * len(u), 'string': Ptr(u)}


def wstr(x):
    """winreg_String value: NUL terminated."""
    u = [ord(c) for c in x] + [0]
    return {'name_len': 2 * len(u), 'name_size': 2 * len(u), 'name': Ptr(u)}


# ------------------------------------------------------------------ ndrgen hooks
def gen_handle(g, ctx):
    return H.new('none')


def push_raw4(g, v, S, B):
    if S:
        g.align(4)
        g.buf += v


def gen_guid(g, ctx):
    return bytes(range(0xa0, 0xb0))


def gen_sid2(g, ctx):
    g.strno += 1
    return DOM + '-%d' % (1000 + g.strno)


def push_sid2(g, v, S, B):
    """dom_sid2: conformant array of sub-authorities, read by
    dissect_ndr_nt_SID() as a uint3264 count and the SID."""
    if S:
        b = sid_bytes(v)
        g.u3264(b[1])
        g.buf += b


def gen_sdbuf(g, ctx):
    return SD


def push_sdbuf(wide):
    """sec_desc_buf of lsa.cnf (uint32 lengths) and samr.cnf (uint3264)."""
    def f(g, v, S, B):
        put = g.u3264 if wide else g.u32
        if S:
            put(len(v) if v is not None else 0)
            g.ptr(v is not None)
        if B and v is not None:
            put(len(v))
            g.buf += v
    return f


def push_blob(g, el, v, S, B):
    if not S:
        return
    if 'NDR_REMAINING' in str(el['PROPERTIES'].get('flag', '')):
        g.buf += v
    else:
        g.u3264(len(v))
        g.buf += v


def make_gen(name, extra=None, wide_sd=False):
    hooks = {
        'gen:policy_handle': gen_handle, 'push:policy_handle': push_raw4,
        'gen:GUID': gen_guid, 'push:GUID': push_raw4,
        'gen:dom_sid2': gen_sid2, 'push:dom_sid2': push_sid2,
        'gen:sec_desc_buf': gen_sdbuf, 'push:sec_desc_buf': push_sdbuf(wide_sd),
        # lsa.cnf dissects a security_descriptor as a sec_desc_buf
        'gen:security_descriptor': gen_sdbuf, 'push:security_descriptor': push_sdbuf(wide_sd),
    }
    hooks.update(extra or {})
    g = Gen(pidl_json(name), hooks)
    g.blob_push = push_blob
    g.byname = {f['NAME']: f for f in g.funcs.values()}
    return g


def marshal(g, func, direction, v, le, ndr64, result):
    g.start(le, ndr64)
    for el in func['ELEMENTS']:
        if direction in el['DIRECTION']:
            g.push_levels(el, el['LEVELS'], 0, v[el['NAME']], True, True)
    if direction == 'out' and func['RETURN_TYPE']:
        g.u32(result)
    return bytes(g.buf)


def values(g, func, alt=0, null=False, arms=None):
    """Generated values for every parameter ([in] and [out]). arms picks
    the case of a union type: {union type name: case value}."""
    c = Ctx()
    c.alt, c.null = alt, null
    v = {}
    for d in ('in', 'out'):
        for uname, case in (arms or {}).items():
            cases = [a['CASE'] for a in g.types[uname]['ELEMENTS']]
            g.rr[uname] = [i for i, cs in enumerate(cases)
                           if (cs == 'default' and case == 'default') or
                           (cs != 'default' and case != 'default' and g.ev(cs) == case)][0]
        c.direction = d
        els, vv = g.gen_call(func['OPNUM'], d, c)
        for k, x in vv.items():
            v.setdefault(k, x)
    return v


class Iface:
    """One PIDL interface on its own TCP connection."""

    def __init__(self, F, g, port, le=True, ndr64=False, cut=False):
        self.F, self.cut = F, cut
        self.g, self.le, self.ndr64 = g, le, ndr64
        ver = tuple(int(x) for x in g.iface['VERSION'].split('.'))
        self.t = TCP(F, port)
        self.r = RPC(self.t, g.iface['UUID'].strip('"'), ver, le, ndr64)
        self.r.bind()

    def call(self, fname, ov=None, alt=0, null=False, result=0, resp=True, ovout=None, arms=None):
        """One request and response. ov sets parameters (both ways), ovout
        only in the response. Returns the request frame number."""
        g = self.g
        func = g.byname[fname]
        v = values(g, func, alt, null, arms)
        v.update(ov or {})
        g.fixup(func['ELEMENTS'], v)
        req = marshal(g, func, 'in', v, self.le, self.ndr64, result)
        v.update(ovout or {})
        rsp = marshal(g, func, 'out', v, self.le, self.ndr64, result) if resp else None
        if self.cut:
            req, rsp = req[:len(req) // 2], rsp and rsp[:len(rsp) // 2]
        n = len(self.F) + 1
        self.r.call(func['OPNUM'], req, rsp)
        return n

    def fin(self):
        self.t.fin()


# ------------------------------------------------------------------ hand-built NDR
class W:
    """NDR writer for the hand-written dissectors. Embedded pointees are
    deferred to the end of the top-level parameter, and the pointees of a
    pointee follow it, the order Wireshark's NDR pointer code reads."""

    def __init__(self, le=True, ndr64=False):
        self.le, self.ndr64 = le, ndr64
        self.e = '<' if le else '>'
        self.buf = bytearray()
        self.refid = 0x00020000
        self.pending = None

    def align(self, n):
        if n == 3:
            n = 4 if self.ndr64 else 2
        elif n == 5:
            n = 8 if self.ndr64 else 4
        while len(self.buf) % n:
            self.buf.append(0)

    def put(self, fmt, v, al=None):
        self.align(al or struct.calcsize(fmt))
        self.buf += struct.pack(self.e + fmt, v)
        return self

    def u8(self, v): return self.put('B', v)
    def u16(self, v): return self.put('H', v)
    def u32(self, v): return self.put('I', v)
    def u64(self, v, al=8): return self.put('Q', v, al)

    def u3264(self, v):
        return self.u64(v) if self.ndr64 else self.u32(v)

    def raw(self, b, al=1):
        self.align(al)
        self.buf += b
        return self

    def ptr(self, fn):
        """Unique/full pointer: referent ID now, pointee deferred."""
        if fn is None:
            self.u3264(0)
            return
        self.refid += 4
        self.u3264(self.refid)
        self.pending.append(fn)

    def run(self, lst):
        for fn in lst:
            sub = []
            saved, self.pending = self.pending, sub
            fn()
            self.pending = saved
            self.run(sub)

    def top(self, fn):
        """One top-level parameter and then its deferred pointees."""
        lst = []
        self.pending = lst
        fn()
        self.pending = None
        self.run(lst)
        return self

    def topptr(self, fn):
        """A top-level unique pointer parameter."""
        return self.top(lambda: self.ptr(fn))

    # strings
    def cvstr(self, s, nul=True):
        units = list(struct.unpack('<%dH' % len(s), s.encode('utf-16-le'))) + ([0] if nul else [])
        self.u3264(len(units))
        self.u3264(0)
        self.u3264(len(units))
        for u in units:
            self.u16(u)

    def ustr(self, s):
        """UNICODE_STRING: length, size, pointer to a conformant varying
        array without a terminating NUL."""
        self.align(5)
        if s is None:
            self.u16(0).u16(0)
            self.ptr(None)
        else:
            n = len(s.encode('utf-16-le'))
            self.u16(n).u16(n)
            self.ptr(lambda: self.cvstr(s, False))
        if self.ndr64:
            self.align(5)

    def strp(self, s):
        """[unique][string] wchar_t *"""
        self.ptr(None if s is None else (lambda: self.cvstr(s)))
        return self

    def sid(self, s):
        b = sid_bytes(s)
        self.u3264(b[1])
        self.raw(b)

    def psid(self, s):
        self.ptr(None if s is None else (lambda: self.sid(s)))

    def bytes(self):
        return bytes(self.buf)


class Hand:
    """A hand-built interface on its own TCP connection."""

    def __init__(self, F, uuid, ver, port, le=True, ndr64=False, sport=49155, cut=False):
        self.le, self.ndr64, self.cut = le, ndr64, cut
        self.t = TCP(F, port, sport)
        self.r = RPC(self.t, uuid, ver, le, ndr64)
        self.r.bind()

    def w(self):
        return W(self.le, self.ndr64)

    def call(self, opnum, req, resp):
        req = req.bytes() if isinstance(req, W) else req
        resp = resp.bytes() if isinstance(resp, W) else resp
        if self.cut:
            req, resp = req[:len(req) // 2], resp[:len(resp) // 2]
        self.r.call(opnum, req, resp)

    def fin(self):
        self.t.fin()


# ------------------------------------------------------------------ NETLOGON
NETLOGON = '12345678-1234-abcd-ef00-01234567cffb'
NTTIME0 = 133500000000000000


def nl_authenticator(w, n=1):
    w.align(4)
    w.raw(bytes(range(n, n + 8)))
    w.u32(1700000000 + n)


def nl_identity(w, user, wks='WKS01'):
    w.ustr('EXAMPLE')
    w.u32(0x00000820)
    w.u64(0x0000000100000002, 4)       # LogonID, a duint32
    w.ustr(user)
    w.ustr(wks)


def nl_level(w, level, user):
    """LEVEL union: short level, aligned pointer to the logon info. The
    interactive logon has an empty (not NULL) workstation name."""
    w.u16(level)
    w.align(4)

    def interactive():
        nl_identity(w, user, '')
        w.raw(bytes(range(16)))
        w.raw(bytes(range(16, 32)))

    def network():
        nl_identity(w, user)
        w.raw(b'\x11\x22\x33\x44\x55\x66\x77\x88')
        for n in (24, 24):
            w.align(4)
            w.u16(n).u16(n)
            w.ptr(lambda n=n: (w.u3264(n), w.u3264(0), w.u3264(n), w.raw(bytes(range(0x30, 0x30 + n)))))
    w.ptr({1: interactive, 2: network}[level])


def nl_sam_info(w, groups, info2=False, info4=False):
    for i in range(6):
        w.u64(NTTIME0 + i * 10000000, 4)
    for s in ('alice', 'Alice Example', 'logon.cmd', '\\\\srv\\profiles\\alice', '\\\\srv\\home\\alice', 'H:'):
        w.ustr(s)
    w.u16(12).u16(1)
    w.u32(1104).u32(513)
    w.u32(len(groups))

    def garray():
        w.u3264(len(groups))
        for rid, attrs in groups:
            w.u32(rid).u32(attrs)
    w.ptr(garray if groups else None)
    w.u32(0x00000020 | 0x00000200)     # user flags: extra sids, resource groups
    w.raw(bytes(range(0x50, 0x60)))
    w.ustr('DC01')
    w.ustr('EXAMPLE')
    w.psid(DOM)
    w.u32(0).u32(0)
    w.u32(0x00000210)
    for i in range(7):
        w.u32(0)
    if info2:
        extra = [('S-1-18-1', 0x7), (DOM + '-1200', 0x20000007), ('S-1-5-32-544', 0x1f)]
        w.u32(len(extra))

        def sids():
            w.u3264(len(extra))
            for s, a in extra:
                w.psid(s)
                w.u32(a)
        w.ptr(sids)
    if info4:
        for s in ('example.test', 'alice@example.test') + ('',) * 10:
            w.ustr(s if s else None)


def nl_validation(w, level):
    w.u16(level)
    w.align(4)
    groups = [(513, 7), (512, 0x1f), (1105, 0x20000004)]
    if level == 2:
        w.ptr(lambda: nl_sam_info(w, groups))
    elif level == 3:
        w.ptr(lambda: nl_sam_info(w, groups, info2=True))
    elif level == 6:
        w.ptr(lambda: nl_sam_info(w, groups, info2=True, info4=True))
    elif level == 7:
        w.ptr(lambda: nl_ticket_logon(w))


def claims_blob(w):
    """A claims set metadata blob: MES type serialization header, then a
    pointer to CLAIMS_SET_METADATA with no claims set."""
    b = W(True, False)
    b.raw(struct.pack('<BBHI', 1, 0x10, 8, 0xcccccccc))
    b.raw(struct.pack('<Q', 24))
    b.top(lambda: b.ptr(lambda: (b.u32(0), b.ptr(None), b.u16(0), b.u32(0), b.u16(0), b.u32(0), b.ptr(None))))
    return b.bytes()


def nl_ticket_logon(w):
    blob = claims_blob(w)
    w.u64(0x0000000100000001)
    w.u32(0).u32(0)
    w.ustr('KDC')
    w.ptr(None)
    w.ptr(None)
    w.u32(len(blob))
    w.ptr(lambda: (w.u3264(len(blob)), w.raw(blob)))
    w.u32(0)
    w.ptr(None)


def netlogon_part(F, port, ndr64=False, cut=False):
    nl = Hand(F, NETLOGON, (1, 0), port, ndr64=ndr64, cut=cut)
    srv, wks = '\\\\DC01', 'WKS01'
    if not ndr64:
        # NetrLogonUasLogon: strings by pointer, UNIX times
        w = nl.w()
        w.topptr(lambda: w.cvstr(srv)).top(lambda: w.cvstr('alice')).top(lambda: w.cvstr(wks))
        r = nl.w()

        def uas():
            r.strp('alice')
            r.u32(1).u32(0x7).u32(12).u32(1)
            for i in range(7):
                r.u32(1700000000 + i * 3600)
            r.strp('WKS01')
            r.strp('EXAMPLE')
            r.strp('logon.cmd')
            r.u32(0)
        r.topptr(uas).top(lambda: r.u32(0))
        nl.call(0, w, r)
    # NetrLogonSamLogon, interactive and network logons, validation 2 and 3
    for level, val in ((1, 2), (2, 3)):
        w = nl.w()
        w.topptr(lambda: w.cvstr(srv)).topptr(lambda: w.cvstr(wks))
        w.topptr(lambda: nl_authenticator(w, 1)).topptr(lambda: nl_authenticator(w, 9))
        w.top(lambda: w.u16(level)).top(lambda: nl_level(w, level, 'alice')).top(lambda: w.u16(val))
        r = nl.w()
        r.topptr(lambda: nl_authenticator(r, 17)).top(lambda: nl_validation(r, val))
        r.top(lambda: r.u8(1)).top(lambda: r.u32(0))
        nl.call(2, w, r)
    # NetrLogonSamLogonEx, validation 6 (SAM_INFO4) and 7 (ticket logon
    # with a claims blob in a MES header)
    for val in (6, 7):
        w = nl.w()
        w.topptr(lambda: w.cvstr(srv)).topptr(lambda: w.cvstr(wks))
        w.top(lambda: w.u16(2)).top(lambda: nl_level(w, 2, 'bob')).top(lambda: w.u16(val)).top(lambda: w.u32(0))
        r = nl.w()
        r.top(lambda: nl_validation(r, val)).top(lambda: r.u8(1)).top(lambda: r.u32(0)).top(lambda: r.u32(0))
        nl.call(0x27, w, r)
    # NetrDatabaseDeltas: a user delta (logon hours, account flags) and
    # an alias member delta (SID array)
    w = nl.w()
    w.top(lambda: w.cvstr(srv)).top(lambda: w.cvstr(wks))
    w.top(lambda: nl_authenticator(w, 1)).top(lambda: nl_authenticator(w, 9))
    w.top(lambda: w.u32(0)).top(lambda: w.u64(5, 4)).top(lambda: w.u32(0xffff))
    r = nl.w()

    def delta_user():
        for s in ('carol', 'Carol Example'):
            r.ustr(s)
        r.u32(1106).u32(513)
        for s in ('\\\\srv\\home\\carol', 'H:', 'logon.cmd', 'A user', 'WKS01,WKS02'):
            r.ustr(s)
        r.u64(NTTIME0, 4).u64(NTTIME0 + 1, 4)
        r.align(4)
        r.u16(168)
        r.ptr(lambda: (r.u3264(21), r.u3264(0), r.u3264(21), r.raw(b'\xff' * 21)))
        r.u16(0).u16(3)
        r.u64(NTTIME0 + 2, 4).u64(0x7fffffffffffffff, 4)
        r.u32(0x00000ffd)
        r.raw(bytes(16)).raw(bytes(16))
        r.u8(1).u8(0).u8(0)
        r.ustr('comment')
        r.ustr(None)
        r.u16(1).u16(1252)
        r.u8(0).u32(0)
        r.ptr(None)
        r.u32(4)
        r.u32(len(SD))
        r.ptr(lambda: (r.u32(len(SD)), r.raw(SD)))
        for i in range(4):
            r.ustr(None)
        for i in range(4):
            r.u32(0)

    def delta_alias_member():
        sids = [DOM + '-1106', DOM + '-1107', 'S-1-5-32-545']
        r.align(5)
        r.u32(len(sids))

        def arr():
            r.u3264(len(sids))
            for s in sids:
                r.psid(s)
        r.ptr(arr)
        if r.ndr64:
            r.align(5)
        for i in range(4):
            r.u32(0)

    def deltas():
        r.u32(2)

        def arr():
            r.u3264(2)
            for dtype, rid, fn in ((5, 1106, delta_user), (12, 544, delta_alias_member)):
                r.u16(dtype)
                r.u16(dtype)
                r.align(4)
                r.u32(rid)
                r.u16(dtype)
                r.align(4)
                r.ptr(fn)
        r.ptr(arr)
    r.top(lambda: nl_authenticator(r, 17)).top(lambda: r.u64(6, 4)).topptr(deltas).top(lambda: r.u32(0))
    nl.call(7, w, r)
    if not ndr64:
        # NetrLogonControl: a WERROR result
        w = nl.w()
        w.topptr(lambda: w.cvstr(srv)).top(lambda: w.u32(1)).top(lambda: w.u32(1))
        r = nl.w()
        r.top(lambda: (r.u32(1), r.ptr(None))).top(lambda: r.u32(0x00000032))
        nl.call(12, w, r)
        # DsrGetDcName: GUIDs
        w = nl.w()
        w.topptr(lambda: w.cvstr(srv)).topptr(lambda: w.cvstr('example.test'))
        w.topptr(lambda: w.raw(bytes(range(0xa0, 0xb0)), 4)).topptr(lambda: w.raw(bytes(range(0xb0, 0xc0)), 4))
        w.top(lambda: w.u32(0x40000000))
        r = nl.w()

        def dcinfo():
            r.strp('\\\\DC01.example.test').strp('\\\\192.0.2.60')
            r.u32(1)
            r.raw(bytes(range(0xa0, 0xb0)), 4)
            r.strp('example.test').strp('example.test')
            r.u32(0xe00003fd)
            r.strp('Default-First-Site-Name').strp('Default-First-Site-Name')
        r.topptr(dcinfo).top(lambda: r.u32(0))
        nl.call(0x14, w, r)
    nl.fin()


# ------------------------------------------------------------------ LSA
FRAMES = {}      # scenario name -> frame numbers, printed for the README/tests


def lsa_part(F):
    g = make_gen('lsa')
    lsa = Iface(F, g, 50001)
    fr = FRAMES.setdefault('lsa', {})

    def openp(h, result=0):
        return lsa.call('lsa_OpenPolicy2', {'handle': h}, result=result)

    def use(h):
        return lsa.call('lsa_QueryInfoPolicy', {'handle': h}, arms={'lsa_PolicyInformation': 3})

    def close(h):
        return lsa.call('lsa_Close', {'handle': h}, ovout={'handle': NULLH})

    hp = H.new('LSAP')
    fr['open_p'] = openp(hp)
    for level in (3, 12, 2, 1):
        lsa.call('lsa_QueryInfoPolicy', {'handle': hp}, arms={'lsa_PolicyInformation': level})
    lsa.call('lsa_QuerySecurity', {'handle': hp})
    lsa.call('lsa_LookupSids', {'handle': hp})
    lsa.call('lsa_LookupNames', {'handle': hp})
    lsa.call('lsa_LookupSids2', {'handle': hp})
    ha = H.new('LSAA')
    lsa.call('lsa_OpenAccount', {'handle': hp, 'acct_handle': ha})
    lsa.call('lsa_QuerySecurity', {'handle': ha})
    lsa.call('lsa_EnumPrivsAccount', {'handle': ha})
    close(ha)
    hs = H.new('LSAS')
    lsa.call('lsa_OpenSecret', {'handle': hp, 'sec_handle': hs})
    lsa.call('lsa_QuerySecret', {'sec_handle': hs})
    lsa.call('lsa_QuerySecurity', {'handle': hs})
    close(hs)
    # A handle closed four times (the ndrnt_polhnd_reclose.py reproducer,
    # shortened): every close refers to the open and to the first close.
    hr = H.new('RCLS')
    fr['reclose_open'] = openp(hr)
    fr['reclose_use'] = use(hr)
    fr['reclose_closes'] = [close(hr) for i in range(4)]
    # Handles whose octets 4-7 are the same (ndrnt_polhnd_collide.py,
    # shortened): each keeps its own open and close frames.
    hc = [struct.pack('<I', 0) + b'\x11\x22\x33\x44' + struct.pack('<I', i + 1) + bytes(8) for i in range(4)]
    fr['collide_opens'] = [openp(h) for h in hc]
    fr['collide_uses'] = [use(h) for h in reversed(hc)]
    fr['collide_closes'] = [close(h) for h in hc]
    # A handle value opened again without a close in between
    hx = H.new('ROPN')
    fr['reopen_open1'] = openp(hx)
    fr['reopen_use1'] = use(hx)
    fr['reopen_open2'] = openp(hx)
    fr['reopen_use2'] = use(hx)
    fr['reopen_close'] = close(hx)
    # A handle value opened, closed, opened and closed again
    hy = H.new('AGIN')
    fr['again_open1'] = openp(hy)
    fr['again_close1'] = close(hy)
    fr['again_open2'] = openp(hy)
    fr['again_use2'] = use(hy)
    fr['again_close2'] = close(hy)
    fr['again_close3'] = close(hy)
    # A handle whose open is not in the capture, used and closed, and used
    # after the close
    hu = H.new('UNKN')
    fr['unknown_use'] = use(hu)
    fr['unknown_close'] = close(hu)
    fr['unknown_after'] = use(hu)
    # Two OpenPolicy2 calls whose responses, in one TCP segment, return
    # the same handle: the second is the same open, not a reopen
    hd = H.new('DUPL')
    func = g.byname['lsa_OpenPolicy2']
    v = values(g, func)
    v['handle'] = hd
    reqs, rsps = b'', b''
    for i in range(2):
        lsa.r.call_id += 1
        reqs += lsa.r.pdu(0, struct.pack('<IHH', 0, 0, 44) + marshal(g, func, 'in', v, True, False, 0), lsa.r.call_id)
        rsps += lsa.r.pdu(2, struct.pack('<IHBB', 0, 0, 0, 0) + marshal(g, func, 'out', v, True, False, 0), lsa.r.call_id)
    lsa.t.send(True, reqs)
    fr['dup_open'] = len(F) + 1
    lsa.t.send(False, rsps)
    fr['dup_use'] = use(hd)
    close(hd)
    # A null handle, and an open that fails
    fr['null_use'] = use(NULLH)
    fr['failed_open'] = lsa.call('lsa_OpenPolicy2', {'handle': NULLH}, result=0xc0000022)
    fr['close_p'] = close(hp)
    lsa.fin()
    # NDR big endian and NDR64
    for port, le, ndr64 in ((50002, False, False), (50003, True, True)):
        lsa = Iface(F, g, port, le, ndr64)
        h = H.new('LSA%d' % (port - 50000))
        openp(h)
        for level in (3, 12):
            lsa.call('lsa_QueryInfoPolicy', {'handle': h}, arms={'lsa_PolicyInformation': level})
        lsa.call('lsa_LookupSids', {'handle': h})
        lsa.call('lsa_QuerySecurity', {'handle': h})
        hs = H.new('LSS%d' % (port - 50000))
        lsa.call('lsa_OpenSecret', {'handle': h, 'sec_handle': hs})
        lsa.call('lsa_QuerySecret', {'sec_handle': hs})
        close(hs)
        close(h)
        lsa.fin()


# ------------------------------------------------------------------ SAMR
def samr_part(F):
    g = make_gen('samr', wide_sd=True)
    fr = FRAMES.setdefault('samr', {})
    for port, le, ndr64 in ((50011, True, False), (50012, False, False), (50013, True, True)):
        full = port == 50011
        sm = Iface(F, g, port, le, ndr64)
        hc = H.new('SMC%d' % (port % 10))
        fr.setdefault('connect', []).append(sm.call('samr_Connect5', {'connect_handle': hc}))
        if full:
            hc2 = H.new('SMC2')
            sm.call('samr_Connect2', {'connect_handle': hc2})
            sm.call('samr_Shutdown', {'connect_handle': hc2})
        sm.call('samr_EnumDomains', {'connect_handle': hc})
        sm.call('samr_LookupDomain', {'connect_handle': hc, 'domain_name': lstr('EXAMPLE')})
        hd = H.new('SMD%d' % (port % 10))
        sm.call('samr_OpenDomain', {'connect_handle': hc, 'domain_handle': hd})
        for level in ((1, 2, 3, 8, 13) if full else (2,)):
            sm.call('samr_QueryDomainInfo', {'domain_handle': hd}, arms={'samr_DomainInfo': level})
        sm.call('samr_EnumDomainUsers', {'domain_handle': hd})
        sm.call('samr_GetAliasMembership', {'domain_handle': hd})
        for level in ((1, 2, 3, 4, 5) if full else (4,)):
            sm.call('samr_QueryDisplayInfo', {'domain_handle': hd}, arms={'samr_DispInfo': level})
        hu = H.new('SMU%d' % (port % 10))
        fr.setdefault('createuser', []).append(
            sm.call('samr_CreateUser2', {'domain_handle': hd, 'user_handle': hu,
                                         'account_name': lstr('carol%d' % (port % 10))}))
        for level in ((3, 5, 21) if full else (21,)):
            sm.call('samr_QueryUserInfo', {'user_handle': hu}, arms={'samr_UserInfo': level})
        sm.call('samr_GetGroupsForUser', {'user_handle': hu})
        sm.call('samr_QuerySecurity', {'handle': hu})
        if full:
            hg, ha, hu2 = H.new('SMG1'), H.new('SMA1'), H.new('SMU9')
            sm.call('samr_OpenGroup', {'domain_handle': hd, 'group_handle': hg})
            sm.call('samr_OpenAlias', {'domain_handle': hd, 'alias_handle': ha})
            sm.call('samr_OpenUser', {'domain_handle': hd, 'user_handle': hu2})
            sm.call('samr_GetMembersInAlias', {'alias_handle': ha})
            sm.call('samr_AddMultipleMembersToAlias', {'alias_handle': ha})
            for h in (hc, hd, hg, ha, hu2):
                sm.call('samr_QuerySecurity', {'handle': h})
            sm.call('samr_GetDomPwInfo')
            sm.call('samr_OemChangePasswordUser2', {'server': Ptr({'length': 0, 'size': 0, 'string': Ptr([])})})
            sm.call('samr_ChangePasswordUser3')
            sm.call('samr_DeleteDomainGroup', {'group_handle': hg}, ovout={'group_handle': NULLH})
            sm.call('samr_DeleteDomAlias', {'alias_handle': ha}, ovout={'alias_handle': NULLH})
            sm.call('samr_Close', {'handle': hu2}, ovout={'handle': NULLH})
            # error status
            sm.call('samr_OpenUser', {'domain_handle': hd, 'user_handle': NULLH}, null=True, alt=1,
                    result=0xc0000064)
        fr.setdefault('deleteuser', []).append(
            sm.call('samr_DeleteUser', {'user_handle': hu}, ovout={'user_handle': NULLH}))
        sm.call('samr_Close', {'handle': hd}, ovout={'handle': NULLH})
        sm.call('samr_Close', {'handle': hc}, ovout={'handle': NULLH})
        sm.fin()


# ------------------------------------------------------------------ WINREG
def winreg_part(F):
    g = make_gen('winreg')
    fr = FRAMES.setdefault('winreg', {})
    wr = Iface(F, g, 50021)
    hk = H.new('HKLM')
    fr['openhklm'] = wr.call('winreg_OpenHKLM', {'handle': hk})
    hs = H.new('SOFT')
    fr['openkey'] = wr.call('winreg_OpenKey', {'parent_handle': hk, 'handle': hs,
                                               'keyname': wstr('SOFTWARE\\Example')})
    wr.call('winreg_QueryInfoKey', {'handle': hs})
    wr.call('winreg_EnumKey', {'handle': hs})
    wr.call('winreg_EnumValue', {'handle': hs})
    wr.call('winreg_QueryValue', {'handle': hs})
    wr.call('winreg_GetKeySecurity', {'handle': hs})
    wr.call('winreg_GetVersion', {'handle': hs})
    hn = H.new('NEWK')
    wr.call('winreg_CreateKey', {'handle': hs, 'new_handle': hn})
    wr.call('winreg_SetValue', {'handle': hn})
    fr['closekey'] = wr.call('winreg_CloseKey', {'handle': hn}, ovout={'handle': NULLH})
    wr.call('winreg_DeleteKey', {'handle': hs})
    wr.call('winreg_CloseKey', {'handle': hs}, ovout={'handle': NULLH})
    wr.call('winreg_CloseKey', {'handle': hk}, ovout={'handle': NULLH})
    wr.fin()


# ------------------------------------------------------------------ SRVSVC
def srvsvc_part(F):
    g = make_gen('srvsvc')
    sv = Iface(F, g, 50031)
    sv.call('srvsvc_NetShareEnumAll', arms={'srvsvc_NetShareCtr': 1})
    sv.call('srvsvc_NetShareGetInfo', arms={'srvsvc_NetShareInfo': 2})
    sv.call('srvsvc_NetSrvGetInfo', arms={'srvsvc_NetSrvInfo': 101})
    sv.call('srvsvc_NetRemoteTOD')
    sv.call('srvsvc_NetShareCheck')
    h = H.new('SHDL')
    sv.call('srvsvc_NetShareDelStart', {'hnd': h})
    sv.call('srvsvc_NetShareDelCommit', {'hnd': Ptr(h)}, ovout={'hnd': Ptr(NULLH)})
    sv.fin()


# ------------------------------------------------------------------ WKSSVC
def wkssvc_part(F):
    """NetWkstaGetInfo: the only integer the Pidl dissectors put in the
    Info column (PIDL_SET_COL_INFO on a uint32)."""
    g = make_gen('wkssvc')
    wk = Iface(F, g, 50071)
    wk.call('wkssvc_NetWkstaGetInfo', arms={'wkssvc_NetWkstaInfo': 100})
    wk.fin()


# ------------------------------------------------------------------ ATSVC
def atsvc_part(F):
    """JobGetInfo: uint8 bitmaps read by dissect_ndr_uint8() into a value."""
    g = make_gen('atsvc')
    at = Iface(F, g, 50111)
    at.call('atsvc_JobGetInfo')
    at.fin()


# ------------------------------------------------------------------ WITNESS
WITNESS = 'ccd8c074-d0e5-4a40-92b4-d074faa6ba28'


def witness_part(F, port=50081, malformed=False):
    """AsyncNotify responses: a resource change (NOALIGN struct with a
    NUL terminated UTF-16 name). The malformed capture has an unknown type,
    whose data blob takes the rest of the stub including the status."""
    wi = Hand(F, WITNESS, (1, 1), port)
    h = H.new('WITN')
    msgs = [(1, struct.pack('<II', 8 + 2 * 8, 1) + 'share01\0'.encode('utf-16-le'))]
    if malformed:
        msgs = [(99, b'\x01\x02\x03\x04\x05\x06\x07')]
    for mtype, msg in msgs:
        w = wi.w()
        w.top(lambda: w.raw(h, 4))
        r = wi.w()

        def resp(mtype=mtype, msg=msg):
            r.u32(mtype).u32(len(msg)).u32(1)
            r.ptr(lambda: (r.u3264(len(msg)), r.raw(msg)))
        r.topptr(resp).top(lambda: r.u32(0))
        wi.call(3, w, r)
    wi.fin()


# ------------------------------------------------------------------ EVENTLOG
EVENTLOG = '82273fdc-e32a-18c3-3f78-827929dc23ea'


def u16z(s):
    return s.encode('utf-16-le') + b'\0\0'


def evrecord(number, strings, sid, raw, src='Src', host='Host'):
    """An EVENTLOGRECORD (not NDR: offsets into the record)."""
    names = u16z(src) + u16z(host)
    strs = b''.join(u16z(x) for x in strings)
    hdr_len = 56
    str_off = hdr_len + len(names) + len(raw)
    sid_off = str_off + len(strs) if sid else 0
    body = names + raw + strs + (sid or b'')
    body += b'\0' * ((-(hdr_len + len(body) + 4)) % 4)
    total = hdr_len + len(body) + 4
    hdr = struct.pack('<6IHHHHIIIIII', total, 0x654c664c, number, 1700000000,
                      1700000001, 0x40000000 | number, 4, len(strings), 3, 0,
                      0, str_off if strings else 0, len(sid or b''), sid_off,
                      len(raw), hdr_len + len(names) if raw else 0)
    return hdr + body + struct.pack('<I', total)


def eventlog_part(F):
    """ReadEventLogW: the raw data of the record is a NUL terminated
    ASCII string."""
    ev = Hand(F, EVENTLOG, (0, 0), 50091)
    h = H.new('EVTL')
    rec = evrecord(1, ['one'], sid_bytes(DOM + '-500'), b'raw data\0')
    w = ev.w()
    w.top(lambda: w.raw(h, 4)).top(lambda: w.u32(5)).top(lambda: w.u32(0)).top(lambda: w.u32(0x10000))
    r = ev.w()
    r.u32(len(rec)).raw(rec)
    r.u32(len(rec)).u32(0).u32(0)
    ev.call(10, w, r)
    ev.fin()


# ------------------------------------------------------------------ SPOOLSS
SPOOLSS = '12345678-1234-abcd-ef00-0123456789ab'


def spoolss_part(F, port=50061, cut=False):
    """OpenPrinterEx/ClosePrinter (dissect_nt_policy_hnd and a handle
    name), GetPrinter with a buffer (uint8 arrays) and DOS error codes,
    GetCorePrinterDrivers (an HRESULT)."""
    fr = FRAMES.setdefault('spoolss', {})
    sp = Hand(F, SPOOLSS, (1, 0), port, cut=cut)
    h = H.new('PRNT')
    w = sp.w()
    w.topptr(lambda: w.cvstr('\\\\SRV01\\Printer1'))
    w.topptr(lambda: w.cvstr('RAW'))
    w.top(lambda: (w.u32(0), w.ptr(None)))
    w.top(lambda: w.u32(0x00000008))
    w.top(lambda: (w.u32(1), w.ptr(lambda: (w.u32(1), w.u32(28), w.strp('WKS01'), w.strp('alice'),
                                            w.u32(2600), w.u32(6), w.u32(1), w.u32(9)))))
    r = sp.w()
    r.top(lambda: r.raw(h, 4)).top(lambda: r.u32(0))
    fr['openprinterex'] = len(F) + 1
    sp.call(0x45, w, r)
    # GetPrinter level 2 with a buffer of 16 octets; the answer is
    # ERROR_INSUFFICIENT_BUFFER with no buffer
    w = sp.w()
    w.top(lambda: w.raw(h, 4)).top(lambda: w.u32(2))
    w.topptr(lambda: (w.u32(16), w.raw(bytes(16))))
    w.top(lambda: w.u32(16))
    r = sp.w()
    r.top(lambda: r.ptr(None)).top(lambda: r.u32(0x200)).top(lambda: r.u32(122))
    sp.call(8, w, r)
    # GetCorePrinterDrivers: an HRESULT
    w = sp.w()
    w.top(lambda: w.ptr(None)).top(lambda: w.cvstr('Windows x64')).top(lambda: w.u32(0))
    w.top(lambda: w.u32(0)).top(lambda: w.u32(0))
    r = sp.w()
    r.top(lambda: r.u32(0)).top(lambda: r.u32(0)).top(lambda: r.u32(0x80070005))
    sp.call(0x66, w, r)
    # RFNPCNEX: a printer name notification (an array of uint16)
    w = sp.w()
    w.top(lambda: w.raw(h, 4)).top(lambda: w.u32(1)).top(lambda: w.ptr(None))
    r = sp.w()
    pname = 'Printer1\0'.encode('utf-16-le')

    def notify_info():
        r.u32(1)                       # conformance of the struct comes first
        r.u32(2).u32(0).u32(1)
        r.u16(0).u16(1).u32(1).u32(7).u32(1)
        r.u32(len(pname))
        r.ptr(lambda: (r.u32(len(pname) // 2), r.raw(pname)))
    r.topptr(notify_info).top(lambda: r.u32(0))
    sp.call(0x43, w, r)
    w = sp.w()
    w.top(lambda: w.raw(h, 4))
    r = sp.w()
    r.top(lambda: r.raw(NULLH, 4)).top(lambda: r.u32(0))
    fr['closeprinter'] = len(F) + 1
    sp.call(0x1d, w, r)
    sp.fin()


# ------------------------------------------------------------------ DRSUAPI
def drs_gen_sid(g, ctx):
    rid = [0x1f4, 0x201, 0][ctx.alt % 3]
    return (bytes([1, 5, 0, 0, 0, 0, 0, 5]) +
            struct.pack('<5I', 21, 0x11111111, 0x22222222, 0x33333333, rid))


def drs_push_sid(g, v, S, B):
    if S:
        g.align(4)
        g.buf += v


def drs_gen_bindinfo(g, ctx):
    t = g.types['drsuapi_DsBindInfo']
    arms = t['ELEMENTS']
    while True:
        i = g.next_rr('drsuapi_DsBindInfo', len(arms))
        if arms[i]['CASE'] != 'default' or ctx.direction == 'in':
            break
    u = g.gen_union(t, ctx, i)
    return {'length': u[0], 'info': u}


def drs_push_bindinfo(g, v, S, B):
    """drsuapi_DsBindInfoCtr (manual in drsuapi.cnf): uint3264 length,
    then the union whose uint32 discriminant is the length again."""
    if not S:
        return
    cv, arm, av = v['info']
    start = len(g.buf)
    g.u3264(0)
    lpos = len(g.buf)
    g.u32(0)
    body = len(g.buf)
    g.noalign = True
    g.push_element(arm, av, True, True, 'drsuapi_DsBindInfo')
    g.noalign = False
    n = len(g.buf) - body
    if arm['CASE'] != 'default':
        n = cv
    g.buf[lpos:lpos + 4] = struct.pack(g.e + 'I', n)
    g.buf[start:lpos] = struct.pack(g.e + ('Q' if g.ndr64 else 'I'), n)


def drsuapi_part(F, port=50041, badsid=False):
    """DsBind with the fall-back bind info (a data blob that takes the rest
    of the stub) and DsGetNCChanges level 6 replies (28 octet SIDs, data
    blobs with a length, NTTIME_1sec times)."""
    extra = {
        'gen:dom_sid28': drs_gen_sid, 'push:dom_sid28': drs_push_sid,
        'gen:drsuapi_DsBindInfoCtr': drs_gen_bindinfo,
        'push:drsuapi_DsBindInfoCtr': drs_push_bindinfo,
        'gen:drsuapi_DsBindInfoFallBack': lambda g, ctx: {'info': bytes(range(1, 11))},
    }
    if badsid:
        # 6 sub-authorities: 32 octets in a 28 octet field
        extra['gen:dom_sid28'] = lambda g, ctx: (bytes([1, 6, 0, 0, 0, 0, 0, 5]) +
                                                 struct.pack('<6I', 21, 1, 2, 3, 4, 500))
    g = make_gen('drsuapi', extra)
    g.maxdepth = 14
    dr = Iface(F, g, port)
    hb = H.new('DRSB')
    arms = [a['CASE'] for a in g.types['drsuapi_DsBindInfo']['ELEMENTS']]
    fb = arms.index('default')
    out = values(g, g.byname['drsuapi_DsBind'], arms={'drsuapi_DsBindInfo': 28})['bind_info']
    g.rr['drsuapi_DsBindInfo'] = fb
    dr.call('drsuapi_DsBind', {'bind_handle': hb}, ovout={'bind_info': out})
    for k in range(2):
        dr.call('drsuapi_DsGetNCChanges', {'bind_handle': hb}, alt=k,
                arms={'drsuapi_DsGetNCChangesCtr': 6, 'drsuapi_DsGetNCChangesRequest': 8})
    dr.call('drsuapi_DsUnbind', {'bind_handle': hb}, ovout={'bind_handle': NULLH})
    dr.fin()


# ------------------------------------------------------------------ SMB2
def smb2_part(F):
    """SMB2 CREATE and CLOSE: the file id is tracked as a GUID handle by
    dissect_nt_guid_hnd()."""
    fr = FRAMES.setdefault('smb2', {})
    t = TCP(F, 50101, 445)
    fid = struct.pack('<QQ', 0x0000000000000011, 0x00000000deadbeef)
    sess, tree = 0x0000400000000001, 7

    def hdr(cmd, mid, resp):
        return (b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ', 64, 1, 0, cmd, 1, 1 if resp else 0, 0, mid, 0xfeff, tree, sess) +
                bytes(16))

    def nb(p):
        return struct.pack('>I', len(p)) + p
    name = 'docs\\report.txt'.encode('utf-16-le')
    create = struct.pack('<HBBIQQIIIIIHHII', 57, 0, 0, 2, 0, 0, 0x0012019f, 0x80, 7, 1, 0x40, 120, len(name), 0, 0) + name
    fr['create'] = len(F) + 1
    t.send(True, nb(hdr(5, 2, False) + create))
    times = struct.pack('<QQQQ', NTTIME0, NTTIME0, NTTIME0, NTTIME0)
    cresp = struct.pack('<HBBI', 89, 0, 0, 1) + times + struct.pack('<QQII', 4096, 100, 0x80, 0) + fid + \
        struct.pack('<II', 0, 0) + b'\0'
    t.send(False, nb(hdr(5, 2, True) + cresp))
    read = struct.pack('<HBBIQ', 49, 0x50, 0, 100, 0) + fid + struct.pack('<IIIHHB', 0, 0, 0, 0, 0, 0)
    t.send(True, nb(hdr(8, 3, False) + read))
    t.send(False, nb(hdr(8, 3, True) + struct.pack('<HBBIII', 17, 0x50, 0, 4, 0, 0) + b'data'))
    fr['close'] = len(F) + 1
    t.send(True, nb(hdr(6, 4, False) + struct.pack('<HHI', 24, 0, 0) + fid))
    t.send(False, nb(hdr(6, 4, True) + struct.pack('<HHI', 60, 0, 0) + bytes(32) + struct.pack('<QQI', 0, 0, 0)))
    t.fin()


# ------------------------------------------------------------------ malformed
def malformed(M):
    """Paths only malformed input reaches: a 28 octet SID field holding a
    longer SID, the witness data blob that eats the status, and requests
    and responses of the interfaces above cut in half."""
    drsuapi_part(M, 50241, badsid=True)
    witness_part(M, 50281, malformed=True)
    g = make_gen('lsa')
    lsa = Iface(M, g, 50201, cut=True)
    h = H.new('MLSA')
    lsa.call('lsa_OpenPolicy2', {'handle': h})
    for level in (3, 12):
        lsa.call('lsa_QueryInfoPolicy', {'handle': h}, arms={'lsa_PolicyInformation': level})
    for f in ('lsa_LookupSids', 'lsa_QuerySecurity', 'lsa_QuerySecret', 'lsa_Close'):
        lsa.call(f)
    lsa.fin()
    g = make_gen('samr', wide_sd=True)
    for port, ndr64 in ((50211, False), (50212, True)):
        sm = Iface(M, g, port, ndr64=ndr64, cut=True)
        for f in ('samr_Connect5', 'samr_LookupDomain', 'samr_OpenDomain', 'samr_GetAliasMembership',
                  'samr_OemChangePasswordUser2', 'samr_QuerySecurity'):
            sm.call(f)
        sm.call('samr_QueryDisplayInfo', arms={'samr_DispInfo': 4})
        sm.call('samr_QueryUserInfo', arms={'samr_UserInfo': 21})
        sm.call('samr_QueryDomainInfo', arms={'samr_DomainInfo': 2})
        sm.fin()
    netlogon_part(M, 50251, cut=True)
    netlogon_part(M, 50252, ndr64=True, cut=True)
    spoolss_part(M, 50261, cut=True)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    F = []
    lsa_part(F)
    samr_part(F)
    winreg_part(F)
    srvsvc_part(F)
    netlogon_part(F, 50051)
    netlogon_part(F, 50052, ndr64=True)
    spoolss_part(F)
    drsuapi_part(F)
    wkssvc_part(F)
    atsvc_part(F)
    witness_part(F)
    eventlog_part(F)
    smb2_part(F)
    write_pcap(os.path.join(out, 'dcerpc_nt-coverage.pcap'), F)
    for k, v in FRAMES.items():
        print(k, v)
    M = []
    malformed(M)
    write_pcap(os.path.join(out, 'dcerpc_nt-coverage-malformed.pcap'), M)


if __name__ == '__main__':
    main()
