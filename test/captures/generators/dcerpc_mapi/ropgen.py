#!/usr/bin/env python3
# Helper module for the dcerpc_mapi capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ropgen.py: build MAPI ROP and AUX payloads from mapi_spec.json (made by
extract_spec.py from the generated dissector).

The payloads follow what packet-dcerpc-mapi.c parses, which is not always
the IDL:
- a union switched on a plain integer field always takes level 0 (the
  generated code passes the field's initial value); only enum fields set
  the switch value;
- a conformant array inside a ROP buffer has as many elements as the last
  NDR conformant run said: 0 in requests and EcDoRpc, the maximum count of
  rgbOut in EcDoRpcExt/EcDoRpcExt2 responses (the caller passes it as K);
- embedded pointers are NULL (a non-NULL one would be followed in the
  outer stub)."""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = json.load(open(os.path.join(HERE, 'mapi_spec.json')))
EL, ST, UN = SPEC['elems'], SPEC['structs'], SPEC['unions']
EN, BM, CONST = SPEC['enums'], SPEC['bitmaps'], SPEC['consts']
AL = SPEC['align']

# Arms whose payload is huge (fixed 0x8000 octet "wrap" arrays): use once.
BIG = 1000

U8 = [0, 1, 2, 3, 0x10, 0x7f, 0xff]
U16 = [0, 1, 2, 0x1234, 0x7fff, 0xffff]
U32 = [0, 1, 2, 0x12345678, 0x7fffffff, 0xffffffff]
WORDS = ['Inbox', 'Calendar', 'Contacts', 'Drafts', 'Outbox', 'Sent Items',
         'Deleted Items', 'Journal', 'Notes', 'Tasks', 'IPM.Note', 'admin']


class Overrun(Exception):
    pass


class Gen:
    """One payload; usage counts union arms across payloads."""
    usage = {}

    def __init__(self, k=0, le=True, ndr64=False, seed=0, base=0):
        self.k = k
        self.e = '<' if le else '>'
        self.ndr64 = ndr64
        self.buf = bytearray()
        self.seed = seed
        self.n = 0
        self.ended = False      # a "remaining" blob swallowed the rest
        self.overrun = False    # ... and more fields were wanted after it
        self.depth = 0
        self.base = base        # offset of buf[0] in the tvb (for align8)
        self.arms = set()       # (union, case index) used in this payload
        self.needs_align = False  # must start at the same offset mod 8 as base

    # ---- scalars
    def put(self, b):
        if self.ended:
            self.overrun = True
        self.buf += b

    def align(self, fn, which=0):
        a = AL.get(fn, [0, 0])[which]
        if which == 1 and not self.ndr64:
            return
        n = {5: 8 if self.ndr64 else 4, 3: 4 if self.ndr64 else 2}.get(a, a)
        if n > 1:
            self.needs_align = True
            self.put(bytes((-(self.base + len(self.buf))) % n))

    def pick(self, seq):
        self.n += 1
        return seq[(self.seed + self.n) % len(seq)]

    def u(self, bits, v=None):
        if v is None:
            v = self.pick({8: U8, 16: U16, 32: U32, 64: [0, 1, 0x0123456789abcdef]}[bits])
        fmt = {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}[bits]
        self.put(struct.pack(self.e + fmt, v & ((1 << bits) - 1)))

    def string(self):
        return self.pick(WORDS)

    # ---- spec walkers
    def elem(self, name, vars_=None, var=None):
        e = EL[name]
        k = e['kind']
        if k in ('u8', 'u16', 'u32', 'u64'):
            bits = int(k[1:])
            v = None
            if var is not None and vars_ is not None and var in vars_:
                v = vars_[var]
            self.u(bits, v)
        elif k == 'enum':
            bits = EN[e['target']]
            if bits == 1632:
                bits = 32 if self.ndr64 else 16
            self.align(e['target'])
            v = vars_.get(var) if (vars_ is not None and var) else None
            if v is None:
                v = self.pick([0, 1, 2, 3, 4])
            self.u(bits, v)
            if e.get('store') and vars_ is not None and var:
                vars_[var] = v
        elif k == 'bitmap':
            self.align(e['target'])
            bits, mask = BM[e['target']]
            low = mask & -mask if mask else 1
            unk = (~mask) & ((1 << bits) - 1)
            unk = unk & -unk
            self.u(bits, self.pick([mask, 0, low | unk, low]))
        elif k == 'uuid':
            self.put(struct.pack(self.e + 'IHH', 0x12345678 + self.n, 0x9abc, 0xdef0) + bytes(range(8)))
            self.n += 1
        elif k == 'policy':
            self.put(bytes(4) + bytes(range(1, 17)))
        elif k == 'str':
            self.put(self.string().encode() + b'\0')
        elif k == 'wstr':
            self.put(self.string().encode('utf-16-le') + b'\0\0')
        elif k == 'blob_rem':
            self.put(b'blob-data:' + self.string().encode() + bytes(range(16)))
            self.ended = True
        elif k == 'blob_len':
            data = self.string().encode()
            self.u(64 if self.ndr64 else 32, len(data))
            self.put(data)
        elif k == 'struct':
            self.align(e['target'])
            self.struct(e['target'])
            self.align(e['target'], 1)
        elif k == 'union':
            lev = e['level']
            if 'var' in lev:
                level = vars_.get(lev['var'], 0) if vars_ is not None else 0
            elif 'const' in lev:
                level = lev['const']
            else:
                level = 0
            self.union(e['target'], level)
        elif k == 'ucarray':
            if self.k:
                self.arms.add(('uca', e['elem']))
            for _ in range(self.k):
                self.elem(e['elem'])
        elif k == 'fixarr':
            if e['n'] > BIG:
                self.put(bytes(e['n']))
            else:
                for _ in range(e['n']):
                    self.elem(e['elem'])
        elif k == 'embptr':
            self.u(64 if self.ndr64 else 32, 0)
        elif k == 'vstring':
            data = ('/' + self.string()).encode() + b'\0'
            self.u(64 if self.ndr64 else 32, 0)
            self.u(64 if self.ndr64 else 32, len(data))
            self.put(data)
        elif k == 'alias':
            self.elem(e['elem'], vars_, var)
        else:
            raise ValueError('cannot build %s %s' % (name, e))

    def struct(self, name):
        if name in MANUAL:
            return MANUAL[name](self)
        s = ST[name]
        vars_ = {v: 0 for v in s['vars']}
        stored = set()
        for en, var in s['elems']:
            e = EL[en]
            if var and e['kind'] == 'enum' and e.get('store'):
                stored.add(var)
        # choose the union arms first, then write the switch fields
        plan = {}
        for en, var in s['elems']:
            e = EL[en]
            if e['kind'] == 'union' and var and var in stored and var not in plan:
                plan[var] = self.choose(e['target'])
        vars_.update(plan)
        self.depth += 1
        if self.depth > 60:
            raise Overrun(name)
        for en, var in s['elems']:
            self.elem(en, vars_, var)
        self.depth -= 1

    def cases(self, uname):
        return UN[uname]['cases']

    def choose(self, uname, allowed=None):
        """Pick a level for union uname: the least used arm."""
        cs = self.cases(uname)
        opts = []
        for i, (v, fn) in enumerate(cs):
            if v is None:
                # the default arm: a value no case has
                vals = {c for c, _ in cs if c is not None}
                v = next(x for x in range(0x7d, 0x10000) if x not in vals)
            if allowed is not None and v not in allowed:
                continue
            big = fn is not None and arm_is_big(fn)
            opts.append((Gen.usage.get((uname, i), 0) * (100 if big else 1), i, v, big))
        if self.depth > 8:
            # deep: prefer arms without data
            light = [o for o in opts if cs[o[1]][1] is None]
            if light:
                opts = light
        if self.depth > 3:
            # bounded: drop arms that recurse back into this union, so a
            # restriction (SRestriction_CTR) terminates (the dissector has
            # no recursion guard; see README)
            term = [o for o in opts if not reaches(cs[o[1]][1], uname)]
            if term:
                opts = term
        opts.sort(key=lambda o: (o[0], (o[1] * 7 + self.seed) % len(cs)))
        return opts[0][2]

    def union(self, uname, level):
        u = UN[uname]
        cs = u['cases']
        self.align(uname)
        if u['encap']:
            level = self.choose(uname)
            self.u(u['encap'], level)
            if u['align8']:
                pad = (-(self.base + len(self.buf))) % 8
                self.put(bytes(pad))
        idx = None
        for i, (v, fn) in enumerate(cs):
            if v == level:
                idx = i
                break
        if idx is None:
            for i, (v, fn) in enumerate(cs):
                if v is None:
                    idx = i
        if idx is None:
            return
        Gen.usage[(uname, idx)] = Gen.usage.get((uname, idx), 0) + 1
        self.arms.add((uname, idx))
        fn = cs[idx][1]
        if fn:
            self.depth += 1
            self.elem(fn)
            self.depth -= 1


_reach = {}


def reaches(fn, uname):
    """Can element fn reach union uname (so choosing it may recurse)?"""
    if fn is None:
        return False
    key = (fn, uname)
    if key in _reach:
        return _reach[key]
    _reach[key] = False       # break cycles
    r = _elem_reaches(fn, uname, set())
    _reach[key] = r
    return r


def _elem_reaches(fn, uname, seen):
    if fn in seen:
        return False
    seen.add(fn)
    e = EL[fn]
    k = e['kind']
    if k == 'union':
        if e['target'] == uname:
            return True
        return any(_elem_reaches(f, uname, seen) for _, f in UN[e['target']]['cases'] if f)
    if k == 'struct':
        return any(_elem_reaches(f, uname, seen) for f, _ in ST[e['target']]['elems'])
    if k in ('alias', 'ucarray', 'fixarr', 'embptr'):
        return _elem_reaches(e['elem'], uname, seen)
    return False


def arm_is_big(fn, seen=None):
    seen = seen or set()
    if fn in seen:
        return False
    seen.add(fn)
    e = EL[fn]
    if e['kind'] == 'fixarr':
        return e['n'] > BIG
    if e['kind'] == 'struct' and e['target'] in ST:
        return any(arm_is_big(x, seen) for x, _ in ST[e['target']]['elems'])
    if e['kind'] in ('alias', 'ucarray'):
        return arm_is_big(e['elem'], seen)
    return False


# ---------------------------------------------------------------- manual
def m_logon_repl(g):
    """Logon_repl (mapi.cnf): ReturnValue 0 with private (LogonFlags 1)
    or public layout, 0x478 redirect, or another error."""
    form = g.pick(['private', 'public', 'redirect', 'error'])
    g.u(8, 1)
    if form == 'private':
        g.u(32, 0)
        g.u(8, 1)
        for i in range(13):
            g.u(64, 0x100000000 + i)
        g.u(8, 1)
        g.elem('mapi_dissect_element_Logon_repl_MailboxGuid')
        g.u(16, 1)
        g.elem('mapi_dissect_element_Logon_repl_ReplGuid')
        g.u(64, 0x01d9000000000000)
        g.u(64, 0x01d9000000000000)
        g.elem('mapi_dissect_element_Logon_repl_StoreState')
    elif form == 'public':
        g.u(32, 0)
        g.u(8, 0)
        for i in range(13):
            g.u(64, 0x200000000 + i)
        g.u(16, 2)
        g.elem('mapi_dissect_element_Logon_repl_ReplGuid')
        g.elem('mapi_dissect_element_Logon_repl_PerUserGuid')
    elif form == 'redirect':
        g.u(32, 0x478)
        g.u(8, 1)
        name = b'mail2.example.com\0'
        g.u(8, len(name))
        g.put(name)
    else:
        g.u(32, 0x80040111)


def m_sync_upload_continue(g):
    g.u(8, 0)
    g.u(8, 1)
    data = b'state-stream-data'
    g.u(32, len(data))
    g.put(data)


def m_sync_import_move(g):
    g.u(8, 0)
    g.u(8, 2)
    for data in (b'\x01' * 22, b'\x02' * 22, b'\x03' * 16, b'\x04' * 22, b'\x05' * 22):
        g.u(32, len(data))
        g.put(data)


def m_clientinfo(g):
    """AUX_PERF_CLIENTINFO: the dissector takes the string and address
    offsets as offsets into the whole AuxInfo buffer (g.base is where
    this structure's AUX_HEADER data starts in it)."""
    start = g.base + len(g.buf)
    fixed = 4 + 2 + 9 * 2 + 2 + 2
    mach = 'CLIENT01'.encode('utf-16-le') + b'\0\0'
    user = 'user1'.encode('utf-16-le') + b'\0\0'
    v6 = g.pick([False, True])
    ip = bytes([192, 0, 2, 50]) if not v6 else bytes.fromhex('20010db8000000000000000000000032')
    mask = bytes([255, 255, 255, 0]) if not v6 else bytes([255] * 8 + [0] * 8)
    adapter = 'Ethernet0'.encode('utf-16-le') + b'\0\0'
    mac = bytes.fromhex('020000000050')
    o = start + fixed
    om = o
    ou = om + len(mach)
    oi = ou + len(user)
    ok = oi + len(ip)
    oa = ok + len(mask)
    oc = oa + len(adapter)
    g.u(32, 1000000)
    g.u(16, 1)
    for v in (om, ou, len(ip), oi, len(mask), ok, oa, 6, oc):
        g.u(16, v)
    g.u(16, g.pick([1, 2]))
    g.u(16, 0)
    g.put(mach + user + ip + mask + adapter + mac)


MANUAL = {
    'mapi_dissect_struct_Logon_repl': m_logon_repl,
    'mapi_dissect_struct_SyncUploadStateStreamContinue_req': m_sync_upload_continue,
    'mapi_dissect_struct_SyncImportMessageMove_req': m_sync_import_move,
    'mapi_dissect_struct_AUX_PERF_CLIENTINFO': m_clientinfo,
}


def rop(ropid, request, k=0, le=True, ndr64=False, seed=0, base=2):
    """One RopInput/RopOutput: RopId and its union arm."""
    g = Gen(k=k, le=le, ndr64=ndr64, seed=seed, base=base)
    g.u(8, ropid)
    try:
        g.union('mapi_dissect_RopRequest' if request else 'mapi_dissect_RopReply', ropid)
    except Overrun as x:
        g.overrun = True
        g.unbounded = str(x)
    return g


def rop_ids(request):
    return [v for v, fn in UN['mapi_dissect_RopRequest' if request else 'mapi_dissect_RopReply']['cases']
            if v is not None]


def aux_block(version, typ, seed=0, base=0, le=True):
    """One AUX_HEADER with its data (Size covers header and data)."""
    g = Gen(k=0, le=le, seed=seed, base=base + 4)
    if version in (1, 2):
        g.union('mapi_dissect_AuxDataVersion%d' % version, typ)
        body = bytes(g.buf)
        hdr = struct.pack(g.e + 'HBB', 4 + len(body), version, typ)
    else:
        body = b''
        hdr = struct.pack(g.e + 'HB', 3, version)
    return hdr + body, g


def lz77_compress(data):
    """Plain LZ77 ([MS-XCA] 2.3) as tvbuff_lz77.c decodes it."""
    out = bytearray()
    flags = 0
    nflags = 0
    flag_pos = len(out)
    out += b'\0\0\0\0'
    nibble_pos = None
    i = 0

    def flag(bit):
        nonlocal flags, nflags, flag_pos
        flags = (flags << 1) | bit
        nflags += 1
        if nflags == 32:
            out[flag_pos:flag_pos + 4] = struct.pack('<I', flags & 0xffffffff)
            flags = 0
            nflags = 0
            flag_pos = len(out)
            out.extend(b'\0\0\0\0')

    heads = {}
    while i < len(data):
        best_len, best_off = 0, 0
        for j in reversed(heads.get(data[i:i + 3], [])[-16:]):
            if i - j > 8192:
                continue
            n = 0
            while i + n < len(data) and data[j + n] == data[i + n] and n < 300:
                n += 1
            if n > best_len:
                best_len, best_off = n, i - j
        if best_len >= 3:
            l = best_len - 3
            if l < 7:
                out += struct.pack('<H', ((best_off - 1) << 3) | l)
            else:
                out += struct.pack('<H', ((best_off - 1) << 3) | 7)
                l -= 7
                n = min(l, 15)
                if nibble_pos is None:
                    nibble_pos = len(out)
                    out.append(n)
                else:
                    out[nibble_pos] |= n << 4
                    nibble_pos = None
                if l >= 15:
                    l2 = l - 15
                    if l2 < 255:
                        out.append(l2)
                    else:
                        out.append(255)
                        out += struct.pack('<H', best_len - 3)
            flag(1)
            for x in range(i, i + best_len):
                heads.setdefault(data[x:x + 3], []).append(x)
            i += best_len
        else:
            out.append(data[i])
            flag(0)
            heads.setdefault(data[i:i + 3], []).append(i)
            i += 1
    # end marker: the next flag bit is a match at the end of the input
    rest = 32 - nflags
    flags = (flags << rest) | ((1 << rest) - 1)
    out[flag_pos:flag_pos + 4] = struct.pack('<I', flags & 0xffffffff)
    return bytes(out)
