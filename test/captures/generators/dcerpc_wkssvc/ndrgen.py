# Helper module for the dcerpc_wkssvc capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ndrgen.py: build synthetic NDR stubs for a Pidl-generated Wireshark
DCE/RPC dissector from the Pidl NDR tree of its IDL (dumped to JSON by
idl2json.pl).  Values are generated (round robin over union arms, enum
values and bitmap patterns) and marshalled the way the Wireshark Pidl
backend reads them: NDR32 or NDR64, little or big endian.

Also has the pcap/TCP/DCE-RPC framing helpers used by the mk*.py scripts.
Everything is built with struct; nothing comes from a real network.
"""
import json
import re
import struct

SCALARS = {
    'char': 1, 'int8': 1, 'uint8': 1, 'int16': 2, 'uint16': 2,
    'int1632': 3, 'uint1632': 3, 'int32': 4, 'uint32': 4, 'int3264': 5,
    'uint3264': 5, 'hyper': 8, 'int64': 8, 'udlong': 8, 'dlong': 8,
    'NTTIME': 8, 'NTTIME_1sec': 8, 'NTTIME_hyper': 8, 'time_t': 4,
    'WERROR': 4, 'NTSTATUS': 4, 'HRESULT': 4, 'ipv4address': 4,
    'boolean32': 4,
}
# NTTIME_1sec is read with 8 octet alignment by dissect_ndr_nt_NTTIME_1sec()
SCALAR_ALIGN = {'NTTIME': 4, 'NTTIME_1sec': 8, 'udlong': 4, 'dlong': 4}


class Ptr:
    """A non-NULL unique/full pointer to v (ref pointers hold v directly)."""
    def __init__(self, v):
        self.v = v


class Ctx:
    def __init__(self):
        self.null = False      # unique pointers NULL
        self.depth = 0
        self.alt = 0           # selects alternative scalar values
        self.direction = 'in'


class Gen:
    """Value generator and NDR marshaller for one interface."""

    def __init__(self, jsonfile, hooks=None, consts=None):
        d = json.load(open(jsonfile))
        self.types = d['types']
        self.funcs = {f['OPNUM']: f for f in d['functions']}
        self.iface = d['iface']
        self.rr = {}            # round robin counters per type
        self.used_arms = {}     # union name -> set of arm cases used
        self.hooks = hooks or {}
        self.consts = dict(consts or {})
        for t in self.types.values():
            if t['TYPE'] == 'ENUM':
                for name, val in self.enum_values(t):
                    self.consts[name] = val
        self.strno = 0
        self.seen = set()
        self.newkeys = 0
        self.maxdepth = 10
        self.skip_arms = set()
        self.mark_ptrs = False
        self.bitmap_rr = False   # bitmap patterns per type instead of per call

    # ------------------------------------------------------------ helpers
    def ev(self, expr):
        expr = expr.strip()
        if expr.startswith('case '):
            expr = expr[5:]
        e = re.sub(r'[A-Za-z_]\w*', lambda m: str(self.consts.get(m.group(0), m.group(0))), expr)
        return int(eval(e, {}, {}))

    def enum_values(self, t):
        out = []
        n = 0
        for el in t['ELEMENTS']:
            if '=' in el:
                name, v = el.split('=', 1)
                name = name.strip()
                try:
                    n = self.ev(v)
                except Exception:
                    n = 0
            else:
                name = el.strip()
            out.append((name, n))
            self.consts[name] = n
            n += 1
        return out

    def mark(self, key):
        if key not in self.seen:
            self.seen.add(key)
            self.newkeys += 1

    def next_rr(self, key, n):
        i = self.rr.get(key, 0)
        self.rr[key] = i + 1
        return i % n

    def resolve(self, tname):
        t = self.types.get(tname)
        while t is not None and t['TYPE'] == 'TYPEDEF':
            t = self.types.get(t.get('DATA_TYPE'))
        return t

    # ------------------------------------------------------- generation
    def gen_scalar(self, tname, ctx, name=''):
        alt = ctx.alt
        if tname in ('WERROR', 'NTSTATUS', 'HRESULT'):
            return [0, 5, 0xc0000022, 0x80070057][alt % 4] if tname != 'WERROR' else [0, 5, 0x57, 0x6ba][alt % 4]
        if tname in ('hyper', 'int64', 'udlong', 'dlong', 'NTTIME', 'NTTIME_hyper'):
            return [0x01d9a1b2c3d4e5f6, 0, 0x0000000100000002][alt % 3]
        if tname == 'NTTIME_1sec':
            return [13300000000, 0, 1][alt % 3]
        if tname in ('uint8', 'int8', 'char'):
            return [0x41, 0, 0xff][alt % 3]
        if tname in ('uint16', 'int16'):
            return [0x1234, 0, 0xffff][alt % 3]
        if tname == 'ipv4address':
            return 0xc0000263
        return [7, 0, 0xffffffff, 1][alt % 4]

    def gen_type(self, tname, ctx, switch=None):
        h = self.hooks.get('gen:' + tname)
        if h:
            return h(self, ctx)
        if tname in SCALARS:
            return self.gen_scalar(tname, ctx)
        t = self.types.get(tname)
        if t is None:
            raise KeyError(tname)
        if t['TYPE'] == 'ENUM':
            vals = self.enum_values(t)
            i = self.next_rr(tname, len(vals) + 1)
            if i == len(vals):
                return 0x7ff0 if t['BASE_TYPE'] in ('uint16', 'uint1632', 'uint8') and t['BASE_TYPE'] != 'uint8' else (0x7f if t['BASE_TYPE'] == 'uint8' else 0x7ff0)
            return vals[i][1]
        if t['TYPE'] == 'BITMAP':
            allbits = 0
            for el in t['ELEMENTS'] or []:
                m = re.match(r'^\s*\w+\s*\((.*)\)\s*$', el) or re.match(r'^\s*\w+\s*=(.*)$', el)
                if m:
                    allbits |= self.ev(m.group(1))
            bits = {'uint8': 8, 'uint16': 16, 'uint32': 32, 'hyper': 64, 'uint1632': 16}.get(t['BASE_TYPE'], 32)
            mask = (1 << bits) - 1
            free = ~allbits & mask
            unk = free & -free if free else 0
            if self.bitmap_rr:
                i = self.next_rr(('bitmap', tname, ctx.direction), 3)
            else:
                i = ctx.alt % 3
            self.mark(('bitmap', tname, i))
            return [allbits, 0, (allbits & 1) | unk][i]
        if t['TYPE'] == 'STRUCT':
            return self.gen_struct(t, ctx)
        if t['TYPE'] == 'UNION':
            return self.gen_union(t, ctx, switch)
        raise ValueError(t['TYPE'])

    def gen_struct(self, t, ctx):
        v = {}
        ctx.depth += 1
        for el in t['ELEMENTS']:
            v[el['NAME']] = self.gen_element(el, ctx, t['NAME'])
        ctx.depth -= 1
        self.fixup(t['ELEMENTS'], v)
        return v

    def gen_union(self, t, ctx, switch=None):
        arms = t['ELEMENTS']
        if switch is not None:
            i = switch
        else:
            while True:
                i = self.next_rr(t['NAME'], len(arms))
                if (t['NAME'], arms[i]['CASE']) not in self.skip_arms:
                    break
        arm = arms[i]
        case = arm['CASE']
        if case == 'default':
            cases = [self.ev(a['CASE']) for a in arms if a['CASE'] != 'default']
            cv = 99
            while cv in cases:
                cv += 1
        else:
            cv = self.ev(case)
        self.used_arms.setdefault(t['NAME'], set()).add(case)
        self.mark(('arm', t['NAME'], case))
        if arm['TYPE'] == 'EMPTY':
            return (cv, None, None)
        ctx.depth += 1
        val = self.gen_element(arm, ctx, t['NAME'])
        ctx.depth -= 1
        return (cv, arm, val)

    def gen_element(self, el, ctx, parent=''):
        h = self.hooks.get('gen:%s.%s' % (parent, el['NAME']))
        if h:
            return h(self, el, ctx)
        return self.gen_levels(el, el['LEVELS'], 0, ctx)

    def array_len(self, ctx):
        return 2 if ctx.depth <= 3 else 1

    def gen_levels(self, el, levels, i, ctx):
        l = levels[i]
        if l['TYPE'] == 'POINTER':
            if l['POINTER_TYPE'] != 'ref' and (ctx.null or ctx.depth > self.maxdepth):
                return None
            if self.mark_ptrs:
                self.mark(('ptr', id(el), i))
            ctx.depth += 1
            v = self.gen_levels(el, levels, i + 1, ctx)
            ctx.depth -= 1
            return v if l['POINTER_TYPE'] == 'ref' else Ptr(v)
        if l['TYPE'] == 'ARRAY':
            nxt = levels[i + 1]
            if l['IS_ZERO_TERMINATED'] and nxt['TYPE'] == 'DATA' and nxt['DATA_TYPE'] in ('uint16', 'uint8'):
                self.strno += 1
                s = '%s%d' % (el['NAME'][:12], self.strno % 10)
                return [ord(c) for c in s] + [0]
            if l['IS_FIXED'] or str(l.get('SIZE_IS') or '').isdigit():
                n = int(l['SIZE_IS'])
            elif nxt['TYPE'] == 'DATA' and nxt['DATA_TYPE'] in ('uint8', 'uint16') and 'charset' in el['PROPERTIES']:
                self.strno += 1
                s = 'str%d' % (self.strno % 10)
                return [ord(c) for c in s] + [0]
            else:
                n = self.array_len(ctx)
            ctx.depth += 1
            out = [self.gen_levels(el, levels, i + 1, ctx) for _ in range(n)]
            ctx.depth -= 1
            if nxt['TYPE'] == 'DATA' and nxt['DATA_TYPE'] == 'uint8' and not l['IS_FIXED']:
                out = list(range(0x30, 0x30 + n))
            return out
        if l['TYPE'] == 'SWITCH':
            return self.gen_levels(el, levels, i + 1, ctx)
        if l['TYPE'] == 'SUBCONTEXT':
            return self.gen_levels(el, levels, i + 1, ctx)
        if l['TYPE'] == 'DATA':
            if l['DATA_TYPE'] == 'DATA_BLOB':
                return bytes(range(0x61, 0x61 + 3 + ctx.alt % 4))
            return self.gen_type(l['DATA_TYPE'], ctx)
        raise ValueError(l['TYPE'])

    def fixup(self, elements, v):
        """Make size_is/length_is/switch_is fields agree with the values."""
        names = {e['NAME']: e for e in elements}
        for el in elements:
            val = v.get(el['NAME'])
            for l in el['LEVELS']:
                if val is None:
                    break
                if l['TYPE'] == 'POINTER':
                    if l['POINTER_TYPE'] != 'ref':
                        val = val.v
                    continue
                if l['TYPE'] == 'ARRAY':
                    if not isinstance(val, list):
                        break
                    n = len(val)
                    for key in ('SIZE_IS', 'LENGTH_IS'):
                        ex = l.get(key)
                        if not ex or l.get('IS_FIXED'):
                            continue
                        m = re.match(r'^\(?\*?\s*(\w+)\)?\s*(?:([+\-*/])\s*(\d+))?$', str(ex).strip())
                        if not m or m.group(1) not in names or m.group(1) == el['NAME']:
                            continue
                        op, k = m.group(2), int(m.group(3) or 0)
                        x = {None: n, '+': n - k, '-': n + k, '*': n // max(k, 1), '/': n * k}[op]
                        tgt = v.get(m.group(1))
                        if isinstance(tgt, int):
                            v[m.group(1)] = max(x, 0)
                        elif isinstance(tgt, Ptr) and isinstance(tgt.v, int):
                            tgt.v = max(x, 0)
                    break
                if l['TYPE'] == 'SWITCH':
                    ex = l['SWITCH_IS'].lstrip('*').strip()
                    if isinstance(val, Ptr):
                        val = val.v
                    if ex in names and isinstance(val, tuple):
                        if isinstance(v.get(ex), int):
                            v[ex] = val[0]
                        elif isinstance(v.get(ex), Ptr) and isinstance(v[ex].v, int):
                            v[ex].v = val[0]
                    break
                if l['TYPE'] == 'DATA':
                    break

    def gen_call(self, opnum, direction, ctx):
        f = self.funcs[opnum]
        v = {}
        els = [e for e in f['ELEMENTS'] if direction in e['DIRECTION']]
        for el in els:
            hk = self.hooks.get('gen:%s.%s' % (f['NAME'], el['NAME']))
            v[el['NAME']] = hk(self, el, ctx) if hk else self.gen_levels(el, el['LEVELS'], 0, ctx)
        self.fixup(els, v)
        return els, v

    # ------------------------------------------------------- marshalling
    def start(self, le=True, ndr64=False):
        self.buf = bytearray()
        self.e = '<' if le else '>'
        self.ndr64 = ndr64
        self.refid = 0x00020000
        self.noalign = False

    def align(self, n):
        if n == 3:
            n = 4 if self.ndr64 else 2
        elif n == 5:
            n = 8 if self.ndr64 else 4
        if self.noalign or n <= 1:
            return
        while len(self.buf) % n:
            self.buf.append(0)

    def put(self, fmt, v, al=None):
        sz = struct.calcsize(fmt)
        self.align(al if al is not None else sz)
        self.buf += struct.pack(self.e + fmt, v)

    def u8(self, v): self.put('B', v & 0xff)
    def u16(self, v): self.put('H', v & 0xffff)
    def u32(self, v): self.put('I', v & 0xffffffff)
    def u64(self, v, al=8): self.put('Q', v & 0xffffffffffffffff, al)

    def u3264(self, v):
        if self.ndr64:
            self.u64(v)
        else:
            self.u32(v)

    def ptr(self, nonnull):
        if nonnull:
            self.refid += 4
            self.u3264(self.refid)
        else:
            self.u3264(0)

    def push_scalar(self, tname, v):
        sz = SCALARS[tname]
        if sz == 1:
            self.u8(v)
        elif sz == 2:
            self.u16(v)
        elif sz == 3:
            if self.ndr64:
                self.u32(v)
            else:
                self.u16(v)
        elif sz == 4:
            if tname == 'ipv4address':
                self.align(4)
                self.buf += struct.pack('>I', v)
            else:
                self.u32(v)
        elif sz == 5:
            self.u3264(v)
        elif tname == 'NTTIME':
            # FILETIME: low and high 32-bit words, each in the stub's byte
            # order (dissect_nttime() reads it so)
            self.u32(v & 0xffffffff)
            self.u32(v >> 32)
        else:
            self.u64(v, SCALAR_ALIGN.get(tname, 8))

    def type_align(self, tname):
        if tname in SCALARS:
            return SCALAR_ALIGN.get(tname, SCALARS[tname])
        t = self.types[tname]
        if t['TYPE'] in ('ENUM', 'BITMAP'):
            return SCALARS.get(t['BASE_TYPE'], 4)
        return t['ALIGN'] or 4

    def push_type(self, tname, v, S, B, parent=None):
        h = self.hooks.get('push:' + tname)
        if h:
            return h(self, v, S, B)
        if tname in SCALARS:
            if S:
                self.push_scalar(tname, v)
            return
        t = self.types[tname]
        if t['TYPE'] in ('ENUM', 'BITMAP'):
            if S:
                self.push_scalar(t['BASE_TYPE'], v)
            return
        if t['TYPE'] == 'STRUCT':
            els = t['ELEMENTS']
            if S:
                if t.get('SURROUNDING'):
                    sel = [e for e in els if e['NAME'] == t['SURROUNDING']][0]
                    sv = v[sel['NAME']]
                    if sel['LEVELS'][0]['TYPE'] == 'ARRAY' and sel['LEVELS'][0]['IS_CONFORMANT']:
                        self.u3264(len(sv))
                self.align(t['ALIGN'])
                for el in els:
                    # [flag(LIBNDR_FLAG_ALIGN5)] makes the Wireshark Pidl
                    # backend align the element to 4 (NDR32) or 8 (NDR64)
                    if 'LIBNDR_FLAG_ALIGN5' in str(el.get('PROPERTIES', {}).get('flag', '')):
                        self.align(5)
                    self.push_element(el, v[el['NAME']], True, False, tname)
                if self.ndr64:
                    self.align(t['ALIGN'])
            if B:
                for el in els:
                    self.push_element(el, v[el['NAME']], False, True, tname)
            return
        if t['TYPE'] == 'UNION':
            cv, arm, av = v
            if S:
                if not t['PROPERTIES'].get('nodiscriminant'):
                    st = t.get('SWITCH_TYPE') or 'uint32'
                    self.push_scalar(st, cv) if st in SCALARS else self.push_type(st, cv, True, False)
                self.align(t['ALIGN'])
            if arm is not None:
                self.push_element(arm, av, S, B, tname)
            return
        raise ValueError(t['TYPE'])

    def push_element(self, el, v, S, B, parent=''):
        h = self.hooks.get('push:%s.%s' % (parent, el['NAME']))
        if h:
            return h(self, el, v, S, B)
        self.push_levels(el, el['LEVELS'], 0, v, S, B)

    def push_levels(self, el, levels, i, v, S, B):
        l = levels[i]
        if l['TYPE'] == 'POINTER':
            ref = l['POINTER_TYPE'] == 'ref'
            if S and not (l['LEVEL'] == 'TOP' and ref):
                self.ptr(ref or v is not None)
            if B and (ref or v is not None):
                self.push_levels(el, levels, i + 1, v if ref else v.v, True, True)
            return
        if l['TYPE'] == 'ARRAY':
            nxt = levels[i + 1]
            n = len(v)
            inline = l['IS_FIXED'] or l['IS_INLINE'] or l['IS_SURROUNDING']
            if inline:
                if S:
                    if l['IS_VARYING']:
                        self.u3264(0)
                        self.u3264(n)
                    for x in v:
                        self.push_levels(el, levels, i + 1, x, True, False)
                if B:
                    for x in v:
                        self.push_levels(el, levels, i + 1, x, False, True)
                return
            if l['IS_CONFORMANT']:
                self.u3264(n)
            if l['IS_VARYING']:
                self.u3264(0)
                self.u3264(n)
            for x in v:
                self.push_levels(el, levels, i + 1, x, True, False)
            for x in v:
                self.push_levels(el, levels, i + 1, x, False, True)
            return
        if l['TYPE'] in ('SWITCH', 'SUBCONTEXT'):
            return self.push_levels(el, levels, i + 1, v, S, B)
        if l['TYPE'] == 'DATA':
            if l['DATA_TYPE'] == 'DATA_BLOB':
                return self.blob_push(self, el, v, S, B)
            return self.push_type(l['DATA_TYPE'], v, S, B)
        raise ValueError(l['TYPE'])

    def stub(self, opnum, direction, ctx, le=True, ndr64=False):
        f = self.funcs[opnum]
        els, v = self.gen_call(opnum, direction, ctx)
        self.start(le, ndr64)
        for el in els:
            hk = self.hooks.get('push:%s.%s' % (f['NAME'], el['NAME']))
            if hk:
                hk(self, el, v[el['NAME']], True, True)
            else:
                self.push_levels(el, el['LEVELS'], 0, v[el['NAME']], True, True)
        if direction == 'out' and f['RETURN_TYPE']:
            self.push_type(f['RETURN_TYPE'], self.gen_scalar(f['RETURN_TYPE'], ctx), True, False)
        return bytes(self.buf)


# ------------------------------------------------------------------ pcap
UUID_NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
UUID_NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'


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
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


class TCP:
    """One TCP connection with a handshake; seq/ack kept per side."""
    MSS = 1460

    def __init__(self, frames, cport, sport=49155,
                 cip=(192, 0, 2, 50), sip=(192, 0, 2, 60)):
        self.frames = frames
        self.c = (bytes(cip), cport, 0x10000000 + cport * 7)
        self.s = (bytes(sip), sport, 0x20000000 + cport * 11)
        self.cseq, self.sseq = self.c[2], self.s[2]
        self.seg(True, b'', 0x02)
        self.cseq += 1
        self.seg(False, b'', 0x12)
        self.sseq += 1
        self.seg(True, b'', 0x10)

    def send(self, from_client, data):
        for i in range(0, len(data), self.MSS):
            self.seg(from_client, data[i:i + self.MSS])

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.cseq if from_client else self.sseq
        ack = self.sseq if from_client else self.cseq
        if flags == 0x02:
            ack = 0
        opts = struct.pack('>BBH', 2, 4, 1460) if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', src[1], dst[1], seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        ph = src[0] + dst[0] + struct.pack('>BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000, 64, 6, 0, src[0], dst[0])
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        mc, ms = bytes.fromhex('020000000050'), bytes.fromhex('020000000060')
        eth = (ms + mc) if from_client else (mc + ms)
        self.frames.append(eth + b'\x08\x00' + ip + tcp + payload)
        if from_client:
            self.cseq += len(payload)
        else:
            self.sseq += len(payload)

    def fin(self):
        self.seg(True, b'', 0x11)
        self.cseq += 1
        self.seg(False, b'', 0x11)
        self.sseq += 1
        self.seg(True, b'', 0x10)


class RPC:
    """Connection-oriented DCE/RPC on a TCP connection."""
    FRAG = 4096

    def __init__(self, tcp, uuid, ver, le=True, ndr64=False):
        self.tcp, self.le, self.ndr64 = tcp, le, ndr64
        self.e = '<' if le else '>'
        self.call_id = 0
        self.uuid, self.ver = uuid, ver

    def uuid_bytes(self, u):
        h = u.replace('-', '')
        a, b, c = int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)
        return struct.pack(self.e + 'IHH', a, b, c) + bytes.fromhex(h[16:])

    def pdu(self, ptype, body, call_id, flags=0x03):
        drep = bytes([0x10 if self.le else 0x00, 0, 0, 0])
        hdr = struct.pack(self.e + 'BBBB', 5, 0, ptype, flags) + drep
        hdr += struct.pack(self.e + 'HHI', 16 + len(body), 0, call_id)
        return hdr + body

    def bind(self):
        self.call_id += 1
        ts = (UUID_NDR64, 1) if self.ndr64 else (UUID_NDR, 2)
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0) + struct.pack(self.e + 'B3x', 1)
        body += struct.pack(self.e + 'HBx', 0, 1) + self.uuid_bytes(self.uuid)
        body += struct.pack(self.e + 'I', self.ver[0] | (self.ver[1] << 16))
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(True, self.pdu(11, body, self.call_id))
        sec = b'49155\0'
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0x12345) + struct.pack(self.e + 'H', len(sec)) + sec
        body += b'\0' * ((-(16 + len(body))) % 4)
        body += struct.pack(self.e + 'B3x', 1) + struct.pack(self.e + 'HH', 0, 0)
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(False, self.pdu(12, body, self.call_id))

    def _frags(self, from_client, opnum, stub):
        n = max(1, (len(stub) + self.FRAG - 1) // self.FRAG)
        for i in range(n):
            part = stub[i * self.FRAG:(i + 1) * self.FRAG]
            flags = (0x01 if i == 0 else 0) | (0x02 if i == n - 1 else 0)
            if from_client:
                body = struct.pack(self.e + 'IHH', len(part), 0, opnum) + part
                self.tcp.send(True, self.pdu(0, body, self.call_id, flags))
            else:
                body = struct.pack(self.e + 'IHBB', len(part), 0, 0, 0) + part
                self.tcp.send(False, self.pdu(2, body, self.call_id, flags))

    def call(self, opnum, req, resp):
        self.call_id += 1
        self._frags(True, opnum, req)
        if resp is not None:
            self._frags(False, opnum, resp)
