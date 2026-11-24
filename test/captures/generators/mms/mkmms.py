#!/usr/bin/env python3
# Generates test/captures/mms_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MMS coverage captures: mkmms.py <outdir> [-v]

A small ASN.1 reader parses mms.asn (path in ASN, default: the tree) and a
BER encoder builds values for it, rotating through the CHOICE branches, so
that every confirmed request/response service, the unconfirmed services,
the error and reject PDUs and so on appear.  Hand-built IEC 61850 PDUs
(reports, select with value, RCB access) follow.  Everything is synthetic
(addresses from 192.0.2.0/24).  MMS is carried in TPKT/COTP on TCP 102 and
reached through the COTP heuristic; two frames use Exported PDU "mms".
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys

ASN = os.path.join(SRCDIR, 'epan/dissectors/asn1/mms/mms.asn')

# ---------------------------------------------------------------- ASN.1
def tokenize(text):
    text = re.sub(r'--[^\n]*?(--|\n)', lambda m: '\n' if m.group(1) == '\n' else ' ', text)
    return re.findall(r'::=|\.\.\.|\.\.|[A-Za-z][A-Za-z0-9_-]*|-?\d+|[{}\[\]();,|]|"[^"]*"', text)

class T:
    def __init__(self, kind, **kw):
        self.kind = kind; self.tag = None; self.explicit = None
        self.fields = []; self.elem = None; self.name = None; self.enum = []
        self.optional = False; self.default = False
        self.__dict__.update(kw)

class Parser:
    def __init__(self, toks):
        self.t = toks; self.i = 0; self.types = {}
    def peek(self, n=0):
        return self.t[self.i + n] if self.i + n < len(self.t) else None
    def next(self):
        v = self.t[self.i]; self.i += 1; return v
    def skip_balanced(self, o, c):
        d = 0
        while True:
            v = self.next()
            if v == o: d += 1
            elif v == c:
                d -= 1
                if d == 0: return
    def parse_module(self):
        while self.peek() != 'ReportedOptFlds': self.i += 1
        while self.i < len(self.t):
            if self.peek() == 'END': break
            n = self.next()
            if self.peek() == '::=':
                self.next(); self.types[n] = self.parse_type()
            else:  # value assignment: name Type ::= value
                while self.peek() != '::=': self.i += 1
                self.next(); self.next()
    def parse_named(self):
        enum = []
        self.next()  # {
        while True:
            v = self.next()
            if v == '}': break
            if v == ',': continue
            if self.peek() == '(':
                self.next(); num = self.next(); self.next()
                enum.append((v, int(num)))
        return enum
    def parse_type(self):
        tag = None; explicit = None
        if self.peek() == '[':
            self.next(); tag = int(self.next()); self.next()
            if self.peek() == 'IMPLICIT': self.next(); explicit = False
            elif self.peek() == 'EXPLICIT': self.next(); explicit = True
        v = self.next()
        if v in ('SEQUENCE', 'SET'):
            if self.peek() == 'OF':
                self.next(); t = T('seqof', elem=self.parse_type())
            elif self.peek() == 'SIZE':
                self.next(); self.skip_balanced('(', ')'); self.next(); t = T('seqof', elem=self.parse_type())
            else:
                t = T('seq'); t.fields = self.parse_fields()
                if v == 'SET': t.kind = 'seq'
        elif v == 'CHOICE':
            t = T('choice'); t.fields = self.parse_fields()
        elif v == 'INTEGER':
            t = T('int')
            if self.peek() == '{': t.enum = self.parse_named()
        elif v == 'ENUMERATED':
            t = T('enum'); t.enum = self.parse_named()
        elif v == 'BIT':
            self.next(); t = T('bits')
            if self.peek() == '{': self.parse_named()
        elif v == 'OCTET': self.next(); t = T('octets')
        elif v == 'OBJECT': self.next(); t = T('oid')
        elif v in ('BOOLEAN', 'NULL', 'REAL'): t = T(v.lower())
        elif v in ('VisibleString', 'GraphicString', 'UTF8String', 'GeneralizedTime'): t = T('str', name=v)
        elif v == 'EXTERNALt' or v == 'EXTERNAL': t = T('external')
        elif v == 'ANY': t = T('null')
        else: t = T('ref', name=v)
        while self.peek() == '(':
            self.skip_balanced('(', ')')
        t.tag = tag; t.explicit = explicit
        return t
    def parse_fields(self):
        self.next()  # {
        fields = []
        while True:
            if self.peek() == '}': self.next(); break
            if self.peek() == ',': self.next(); continue
            if self.peek() == '...': self.next(); continue
            # name Type, or Type alone (SEQUENCE OF CHOICE members always have names here)
            name = self.next()
            t = self.parse_type()
            t.name = t.name if t.kind in ('ref', 'str') else None
            t.fname = name
            while self.peek() in ('OPTIONAL', 'DEFAULT'):
                v = self.next()
                if v == 'OPTIONAL': t.optional = True
                else:
                    t.default = True
                    if self.peek() == '{': self.skip_balanced('{', '}')
                    else: self.next()
            fields.append(t)
        return fields

def load(path=ASN):
    p = Parser(tokenize(open(path).read())); p.parse_module()
    p.types.update({'AP-title': T('oid'), 'AP-invocation-identifier': T('int'),
                    'AE-qualifier': T('int'), 'AE-invocation-identifier': T('int'),
                    'EXTERNALt': T('external')})
    return p.types

# ---------------------------------------------------------------- BER
def blen(n):
    if n < 128: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big'); return bytes([0x80 | len(b)]) + b
def ident(cls, cons, tag):
    b = (cls << 6) | (0x20 if cons else 0)
    if tag < 31: return bytes([b | tag])
    out = [tag & 0x7f]; tag >>= 7
    while tag: out.insert(0, 0x80 | (tag & 0x7f)); tag >>= 7
    return bytes([b | 31]) + bytes(out)
def tlv(cls, cons, tag, content):
    return ident(cls, cons, tag) + blen(len(content)) + content
def ctx(tag, content, cons=True): return tlv(2, cons, tag, content)
def uni(tag, content, cons=False): return tlv(0, cons, tag, content)
def i2b(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return v.to_bytes(n, 'big', signed=True)
def bint(v): return uni(2, i2b(v))
def vstr(s): return uni(26, s.encode())

UTAG = {'int': 2, 'enum': 10, 'bits': 3, 'octets': 4, 'null': 5, 'oid': 6, 'boolean': 1, 'real': 9,
        'seq': 16, 'seqof': 16, 'external': 8}
STRTAG = {'VisibleString': 26, 'GraphicString': 25, 'UTF8String': 12, 'GeneralizedTime': 24}

class Gen:
    def __init__(self, types):
        self.types = types; self.n = 0; self.mind = {}
    def rnd(self, m):
        self.n += 1
        # deterministic scrambling
        x = (self.n * 2654435761) & 0xffffffff
        return (x >> 8) % m
    def res(self, t):
        while t.kind == 'ref': t = self.types[t.name]
        return t
    def is_choice(self, t):
        return self.res(t).kind == 'choice'
    # minimal depth of a type (to terminate recursion)
    def depth(self, t, seen=()):
        if t.kind == 'ref':
            if t.name in seen: return 99
            if t.name in self.mind: return self.mind[t.name]
            d = self.depth(self.types[t.name], seen + (t.name,))
            if not seen: self.mind[t.name] = d
            return d
        if t.kind == 'seq':
            return 1 + max([self.depth(f, seen) for f in t.fields if not f.optional and not f.default] or [0])
        if t.kind == 'choice':
            return 1 + min(self.depth(f, seen) for f in t.fields)
        if t.kind == 'seqof': return 1
        return 0
    def prim(self, t, rt):
        k = rt.kind; nm = t.name if t.kind == 'ref' else None
        r = self.rnd(6)
        if k == 'int':
            if rt.enum: return i2b(rt.enum[r % len(rt.enum)][1])
            return i2b([0, 1, 2, 5, 70000, -3][r])
        if k == 'enum': return i2b(rt.enum[r % len(rt.enum)][1])
        if k == 'boolean': return bytes([0xff if r & 1 else 0])
        if k == 'null': return b''
        if k == 'real': return bytes([0x80, 0x00, 0x01]) if r & 1 else b'\x40'
        if k == 'oid': return bytes.fromhex('2903' + '0405') if r & 1 else bytes.fromhex('2a0304')
        if k == 'bits':
            return bytes([6, 0x52, 0x00]) if r % 5 else b'\x00'
        if k == 'octets':
            if nm == 'TimeOfDay': return bytes(range(6)) if r & 1 else bytes(range(4))
            if nm == 'UtcTime': return bytes([0x50, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a])
            if nm == 'FloatingPoint': return bytes([8, 0x3f, 0x80, 0, 0])
            return bytes([1, 2, 3, 4, 5])[:1 + r % 5]
        if k == 'str':
            if rt.name == 'GeneralizedTime': return b'20260101120000Z'
            return ['LLN0', 'Ld1', 'a$b', 'X', 'DataSet1', ''][r].encode()
        raise Exception(k)
    def enc(self, t, depth=0, force=None):
        """Encode type t including its own tag (if any)."""
        rt = self.res(t)
        # the base encoding (without t's tag)
        if rt.kind == 'choice':
            body_tag = None
            fields = rt.fields
            if depth > 4:
                best = min(self.depth(f) for f in fields)
                cand = [f for f in fields if self.depth(f) == best]
            else: cand = fields
            f = cand[self.rnd(len(cand))] if force is None else [x for x in fields if x.fname == force][0]
            inner = self.enc(f, depth + 1)
            base = inner; implicit_ok = False
        elif rt.kind == 'seq':
            c = b''
            for f in rt.fields:
                if (f.optional or f.default):
                    if depth > 3 or self.rnd(3) == 0: continue
                c += self.enc(f, depth + 1)
            base = (0, True, 16, c)
        elif rt.kind == 'seqof':
            cnt = 0 if depth > 4 else 1 + self.rnd(2)
            base = (0, True, 16, b''.join(self.enc(rt.elem, depth + 1) for _ in range(cnt)))
        elif rt.kind == 'external':
            base = (0, True, 8, uni(6, bytes.fromhex('2903')) + ctx(0, uni(5, b'')))
        else:
            ut = UTAG.get(rt.kind) or STRTAG[rt.name]
            base = (0, False, ut, self.prim(t, rt))
        tag = t.tag if t.tag is not None else None
        # effective explicit/implicit
        if tag is None:
            if rt.kind == 'choice': return base
            return tlv(*base)
        ex = t.explicit
        if ex is None: ex = True  # EXPLICIT TAGS module default
        if rt.kind == 'choice': ex = True
        if ex or rt.kind == 'choice':
            inner = base if rt.kind == 'choice' else tlv(*base)
            return ctx(tag, inner)
        # implicit
        return tlv(2, base[1], tag, base[3])

# ---------------------------------------------------------------- frames
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Net:
    def __init__(self):
        self.frames = []; self.seq = {}
    def raw(self, payload, sport, dport, seq, ack, flags, src, dst):
        s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
        opt = b'\x02\x04\x05\xb4' if flags & 2 else b''
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), len(self.frames) + 1, 0, 64, 6, 0, s, d)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        ph = s + d + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        eth = b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00'
        if src == '192.0.2.2': eth = eth[6:12] + eth[0:6] + eth[12:]
        self.frames.append((1, eth + ip + tcp + payload))
    def handshake(self, cport, sport):
        self.seq[cport] = 1000; self.seq[sport] = 5000
        self.raw(b'', cport, sport, 1000, 0, 0x02, '192.0.2.1', '192.0.2.2')
        self.raw(b'', sport, cport, 5000, 1001, 0x12, '192.0.2.2', '192.0.2.1')
        self.raw(b'', cport, sport, 1001, 5001, 0x10, '192.0.2.1', '192.0.2.2')
        self.seq[cport] = 1001; self.seq[sport] = 5001
    def tcp(self, payload, sport, dport, src='192.0.2.1', dst='192.0.2.2', flags=0x18):
        seq = self.seq.get(sport, 1000); self.seq[sport] = seq + len(payload)
        self.raw(payload, sport, dport, seq, self.seq.get(dport, 5000), flags, src, dst)
        return len(self.frames)
    def epdu(self, name, payload):
        n = name.encode(); n += b'\0' * (-len(n) % 4)
        self.frames.append((252, struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload))
    def write(self, fn):
        # pcapng with two interfaces (Ethernet, Exported PDU)
        def blk(t, body):
            body += b'\0' * (-len(body) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 1, 0, 0))
        out += blk(1, struct.pack('<HHI', 252, 0, 0))
        for i, (lt, fr) in enumerate(self.frames):
            ts = (1700000000 + i) * 1000000
            out += blk(6, struct.pack('<IIIII', 0 if lt == 1 else 1, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
        open(fn, 'wb').write(out)

def tpkt(mms):
    cotp = b'\x02\xf0\x80'
    return struct.pack('!BBH', 3, 0, 4 + len(cotp) + len(mms)) + cotp + mms

# MMSpdu tags: confirmed-Request 0, Response 1, Error 2, Unconfirmed 3, reject 4,
# cancel-Req 5/6/7, initiate 8/9/10, conclude 11/12/13

def iec_flows(net, send, creq, cresp, invid, mark):
    """IEC 61850-8-1 mapping paths of mms.cnf, hand built."""
    st = len(net.frames) + 1
    vmd = lambda n: ctx(0, n.encode(), False)
    dom = lambda d, i: ctx(1, vstr(d) + vstr(i))
    # ObjectName inside an explicit [0] (VariableSpecification.name)
    def read_req(names, with_result=False):
        items = b''.join(uni(16, ctx(0, dom(d, i)), True) for d, i in names)
        vas = ctx(0, items)
        return ctx(4, (ctx(0, b'\xff', False) if with_result else b'') + ctx(1, vas))
    def write_req(name, data):
        d, i = name
        vas = ctx(0, uni(16, ctx(0, dom(d, i)), True))
        return ctx(5, vas + ctx(0, data))
    def ok(data): return data          # AccessResult success is the Data choice itself
    def fail(code): return ctx(0, i2b(code), False)
    def read_resp(results, vas=b''):
        return ctx(4, (ctx(0, vas) if vas else b'') + ctx(1, b''.join(results)))
    D_int = lambda v: ctx(5, i2b(v), False); D_uns = lambda v: ctx(6, i2b(v), False)
    D_bool = lambda v: ctx(3, bytes([v]), False)
    D_bits = lambda pad, b: ctx(4, bytes([pad]) + b, False)
    D_vis = lambda s: ctx(10, s.encode(), False)
    D_oct = lambda b: ctx(9, b, False)
    D_struct = lambda *m: ctx(2, b''.join(m))
    D_array = lambda *m: ctx(1, b''.join(m))
    D_btime = lambda b: ctx(12, b, False)
    D_utc = lambda b: ctx(17, b, False)
    D_float = lambda: ctx(7, bytes([8, 0x42, 0x28, 0, 0]), False)

    # 1. GetServerDirectory / GetLogicalDeviceDirectory / GetDataSetDirectory / GetDataDirectory
    def getnamelist(cls, scope):
        return ctx(1, ctx(0, ctx(0, i2b(cls), False)) + ctx(1, scope))
    idents = lambda *n: ctx(1, ctx(0, b''.join(vstr(x) for x in n)) + ctx(1, b'\x00', False))
    i = invid(); send(creq(getnamelist(9, ctx(0, b'', False)), i))
    send(cresp(idents('IED1LD0', 'IED1LD1'), i), False)
    i = invid(); send(creq(getnamelist(0, ctx(1, b'IED1LD0', False)), i))
    send(cresp(idents('LLN0$DC$NamPlt', 'MMXU1$MX$TotW'), i), False)
    # continueAfter and a response without moreFollows
    i = invid(); send(creq(ctx(1, ctx(0, ctx(0, i2b(0), False)) + ctx(1, ctx(1, b'IED1LD0', False)) + ctx(2, b'MMXU1$MX', False)), i))
    send(cresp(ctx(1, ctx(0, vstr('MMXU1$ST'))), i), False)
    i = invid(); send(creq(getnamelist(2, ctx(1, b'IED1LD0', False)), i))
    send(cresp(idents('LLN0$dsAnalog', 'LLN0$dsStatus'), i), False)
    # a getNameList response without a request (transaction not found)
    send(cresp(idents("X"), 9999), False)
    i = invid(); send(creq(ctx(12, dom('IED1LD0', 'LLN0$dsAnalog')), i))
    send(cresp(ctx(12, ctx(0, b'\xff', False) + ctx(1, uni(16, ctx(0, dom('IED1LD0', 'MMXU1$MX$TotW$mag$f')), True))), i), False)
    i = invid(); send(creq(ctx(6, ctx(0, dom('IED1LD0', 'MMXU1$MX$TotW'))), i))
    send(cresp(ctx(6, ctx(0, b'\xff', False) + ctx(2, ctx(2, ctx(1, uni(16, ctx(0, vstr('mag')) + ctx(1, ctx(5, b'\x08', False)), True))))), i), False)
    mark('IEC 61850 directory services (GetServerDirectory, LogicalDevice, DataSet, DataDirectory)', st)

    # 2. read / write of data values with the special item IDs
    st = len(net.frames) + 1
    LD = 'IED1LD0'
    def rw(item, result, wdata=None):
        i = invid()
        send(creq(read_req([(LD, item)]), i))
        send(cresp(read_resp([result]), i), False)
    rw('MMXU1$MX$TotW$mag$f', D_float())
    rw('XCBR1$CF$Pos$ctlModel', D_int(1))
    None
    rw('XCBR1$ST$Pos$q', D_bits(3, b'\x00\x00'))
    rw('XCBR1$ST$Pos$q', D_bits(3, b'\xfc\xf8'))
    rw('XCBR1$ST$Pos$q', D_bits(3, b'\x40'))       # one octet: no quality bit list
    rw('XCBR1$CO$Pos$SBOw$Check', D_bits(6, b'\xc0'))
    rw('XCBR1$CO$Pos$Oper$Check', D_bits(6, b'\x80'))
    rw('XCBR1$CO$Pos$Oper$Check', D_bits(0, b''))   # empty check bit string
    rw('LLN0$ST$Beh$stVal', D_int(1))
    rw('LLN0$ST$Mod$stVal', D_int(1))
    rw('LLN0$ST$Health$stVal', D_int(1))
    rw('XCBR1$CO$Pos$Oper$origin$orCat', D_int(2))
    rw('XCBR1$CO$Pos$orCat', D_int(2))
    rw('LLN0$BR$brcbA01', fail(3))
    None
    # GetBRCBValues / GetURCBValues: structure with all attributes
    brcb = D_struct(D_vis('rpt1'), D_bool(1), D_vis('IED1LD0/LLN0$dsAnalog'), D_uns(2), D_bits(6, b'\x7f\xc0'),
                    D_uns(100), D_bits(2, b'\x30'), D_uns(1000), D_bool(0), D_oct(b'\0\0\0\0\0\0\0\1'), D_uns(500))
    rw('LLN0$BR$brcbA01', brcb)
    rw('LLN0$RP$urcbA01', brcb)
    # mixed results in one response (failure then success)
    i = invid(); send(creq(read_req([(LD, 'MMXU1$MX$TotW$mag$f'), (LD, 'MMXU1$MX$Hz$mag$f')], True), i))
    send(cresp(read_resp([fail(10), D_float()], ctx(0, uni(16, ctx(0, dom(LD, 'MMXU1$MX$TotW$mag$f')), True))), i), False)
    # all Data types in one response, binary-time 4 and 6 octets and days >= 19742
    i = invid(); send(creq(read_req([(LD, 'LLN0$dsAll')]), i))
    send(cresp(read_resp([D_array(D_int(1), D_int(-2)), D_struct(D_bool(1), D_uns(7)), D_bits(0, b'\xaa'), D_oct(b'\x01\x02'),
                          D_vis('abc'), D_btime(b'\x00\x00\x03\xe8'), D_btime(b'\x00\x00\x03\xe8\x4d\x00'),
                          D_btime(b'\x00\x00\x03\xe8\xff\xff'), ctx(13, b'\x12', False), ctx(14, b'\x04\xf0', False),
                          ctx(15, b'\x2a\x03\x04', False), ctx(16, 'mms'.encode(), False),
                          D_utc(bytes([0x65, 0x9f, 0xa0, 0x00, 0x80, 0x00, 0x00, 0x0a])),
                          ctx(8, b'\x80\x00\x01', False), D_float()]), i), False)
    # write of values: plain, then SelectWithValue (SBOw) and Oper
    i = invid(); send(creq(write_req((LD, 'XCBR1$CO$Pos$Oper$ctlVal'), D_bool(1)), i))
    send(cresp(ctx(5, ctx(1, b'', False) + ctx(0, i2b(3), False)), i), False)
    sbow = D_struct(D_bool(1), D_struct(D_int(2), D_oct(b'iedctl')), D_uns(5),
                    D_utc(bytes([0x65, 0x9f, 0xa0, 0x00, 0x80, 0x00, 0x00, 0x0a])), D_bool(0), D_bits(6, b'\xc0'))
    i = invid(); send(creq(write_req((LD, 'XCBR1$CO$Pos$SBOw'), sbow), i))
    send(cresp(ctx(5, ctx(1, b'', False)), i), False)
    # origin as the fourth data element (no ctlVal boolean: struct at count 4)
    sbow2 = D_struct(D_bool(1), D_uns(1), D_struct(D_int(1), D_oct(b'x')), D_uns(9))
    i = invid(); send(creq(write_req((LD, 'XCBR1$CO$Pos$SBOw'), sbow2), i))
    send(cresp(ctx(5, ctx(0, i2b(7), False)), i), False)
    i = invid(); send(creq(write_req((LD, 'LLN0$BR$brcbA01$RptEna'), D_bool(1)), i))
    send(cresp(ctx(5, ctx(1, b'', False)), i), False)
    i = invid(); send(creq(write_req((LD, 'LLN0$BR$brcbA01$RptEna'), D_bool(1)), i))
    send(cresp(ctx(5, ctx(0, i2b(3), False)), i), False)
    mark('IEC 61850 read/write of values (quality, check, ctlModel, RCB, SBOw, all Data types)', st)

    # 3. reports (unconfirmed InformationReport on VMD-specific "RPT")
    st = len(net.frames) + 1
    def report(flags, extra_tail=()):
        res = [D_vis('IED1LD0/LLN0$BR$brcbA01')]
        pad = 6
        res.append(D_bits(pad, struct.pack('>H', flags)))
        if flags & 0x4000: res.append(D_uns(41))
        if flags & 0x2000: res.append(D_btime(b'\x01\x02\x03\x04\x4d\x00'))
        if flags & 0x0800: res.append(D_vis('IED1LD0/LLN0$dsAnalog'))
        if flags & 0x0200: res.append(D_bool(0))
        if flags & 0x0100: res.append(D_oct(b'\0\0\0\0\0\0\0\x07'))
        if flags & 0x0080: res.append(D_uns(3))
        if flags & 0x0040: res.extend([D_uns(0), D_bool(0)])
        res.append(D_bits(6, b'\xc0'))                       # inclusion bit string
        if flags & 0x0400: res.extend([D_vis('LD0/MMXU1$MX$TotW'), D_vis('LD0/MMXU1$MX$Hz')])
        res.extend([D_float(), D_int(3)])
        if flags & 0x1000: res.extend([D_bits(2, b'\x40'), D_bits(2, b'\x20')])
        res.extend(extra_tail)
        vas = ctx(1, vmd('RPT'))
        return ctx(3, ctx(0, vas + ctx(0, b''.join(res))))
    for fl in (0x7fc0, 0x4000, 0x2800, 0x0200, 0x0180, 0x1400, 0x0000, 0x5ec0):
        send(report(fl), False)
    send(report(0x7fc0, (D_int(1), D_int(2), D_int(3))), False)   # more results than the 14 known slots
    send(ctx(3, ctx(0, ctx(1, vmd('OTHER')) + ctx(0, D_vis('x') + D_bits(6, b'\x00\x00')))), False)  # not RPT
    # CommandTermination: unconfirmed report naming ...$Oper (domain specific)
    ct = ctx(3, ctx(0, ctx(1, dom(LD, 'XCBR1$CO$Pos$Oper')) + ctx(0, D_struct(D_bool(1), D_int(2)))))
    send(ct, False)
    ct2 = ctx(3, ctx(0, ctx(1, dom(LD, 'XCBR1$CO$Pos$Oper')) + ctx(0, fail(2))))
    send(ct2, False)
    # unconfirmed status and event notification (generated structure)
    mark('IEC 61850 reports and CommandTermination', st)

    # 4. state tracking: response before request, repeated invoke IDs, request without response
    st = len(net.frames) + 1
    i = invid(); send(cresp(read_resp([D_int(1)]), 700), False)             # response to unknown request
    send(creq(read_req([(LD, 'LLN0$ST$Mod$stVal')]), 701))
    send(creq(read_req([(LD, 'LLN0$ST$Beh$stVal')]), 701))                     # same invoke ID again
    send(cresp(read_resp([D_int(1)]), 701), False)
    send(ctx(2, ctx(0, i2b(701), False) + ctx(2, ctx(0, ctx(0, i2b(1), False))) ), False)  # error answer
    # TimeOfDay in unconfirmed event notification of generated content
    mark('Invoke ID tracking (unknown response, repeated invoke ID, error answer)', st)

def malformed(outdir):
    net = Net(); net.handshake(49153, 102)
    def send(pdu): net.tcp(tpkt(pdu), 49153, 102)
    D = lambda tag, b: ctx(tag, b, False)
    def rpt(items):
        return ctx(3, ctx(0, ctx(1, ctx(0, b'RPT', False)) + ctx(0, b''.join(items))))
    # ReportedOptFlds with one octet only (was a read of two octets)
    send(rpt([D(10, b'rpt'), D(4, b'\x06\xff'), D(4, b'\x06\xc0')]))
    send(rpt([D(10, b'rpt'), D(4, b'\x00')]))
    # binary-time and UtcTime of the wrong length
    send(rpt([D(10, b'rpt'), D(4, b'\x06\x20\x00'), D(12, b'\x01\x02\x03\x04\x05')]))
    send(rpt([D(10, b'rpt'), D(17, b'\x01\x02\x03\x04\x05\x06\x07'), D(17, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09')]))
    # UtcTime in a write (SelectWithValue) of the wrong length
    nm = ctx(0, ctx(1, vstr('LD') + vstr('XCBR1$CO$Pos$SBOw')))
    sb = ctx(2, D(3, b'\x01') + ctx(2, D(5, b'\x01') + D(9, b'ab')) + D(6, b'\x01') + D(17, b'\x01\x02') + D(3, b'\x00') + D(4, b'\x06'))
    send(ctx(0, bint(1) + ctx(5, ctx(0, uni(16, nm, True)) + ctx(0, sb))))
    # quality bits with one octet and the check bit string empty
    for item, data in (('XCBR1$ST$Pos$q', D(4, b'\x00')), ('XCBR1$CO$Pos$Oper$Check', D(4, b''))):
        nm = ctx(0, ctx(1, vstr('LD') + vstr(item)))
        send(ctx(0, bint(2) + ctx(4, ctx(1, ctx(0, uni(16, nm, True))))))
        send(ctx(1, bint(2) + ctx(4, ctx(1, data))))
    # truncated / broken PDUs by Exported PDU
    good = ctx(0, bint(3) + ctx(4, ctx(1, ctx(0, uni(16, ctx(0, ctx(1, vstr('LD') + vstr('A$B'))), True)))))
    for cut in (3, 7, 12, len(good) - 2):
        net.epdu('mms', good[:cut])
    net.epdu('mms', b'\xa0\x80\x02\x01\x01\x00\x00')              # indefinite length
    net.epdu('mms', b'\xbf\x7f\x03\x02\x01\x01')                  # high tag number
    net.epdu('mms', ctx(0, bint(1) + ctx(120, b'')))              # unknown service
    net.epdu('mms', ctx(1, bint(1) + ctx(120, b'')))
    net.epdu('mms', ctx(9, ctx(0, b'', False)))                   # initiate response without required fields
    net.epdu('mms', ctx(3, ctx(5, b'')))                          # unknown unconfirmed service
    net.epdu('mms', ctx(2, ctx(0, i2b(1), False)))                # error PDU without service error
    net.epdu('mms', ctx(0, bint(1) + ctx(1, ctx(0, ctx(0, ctx(1, b'\x01\x00', False))))))  # getNameList with bad class
    net.epdu('mms', ctx(0, bint(1) + ctx(0, ctx(5, b''))) )
    net.epdu('mms', b'\xa3\x03\xa0\x01')
    # COTP heuristic rejects: one octet, primitive class, unknown PDU tag, indefinite length, short body
    for pdu in (b'\xa0', b'\x80\x01\x00', b'\xae\x01\x00', b'\xa0\x80\x00\x00', b'\xa0\x10\x02\x01\x01'):
        send(pdu)
    net.write(os.path.join(outdir, 'mms-coverage-malformed.pcapng'))

def main(outdir, verbose=False):
    os.makedirs(outdir, exist_ok=True)
    types = load(); g = Gen(types)
    net = Net(); ranges = []
    C, S = 49152, 102
    net.handshake(C, S)
    def send(pdu, client=True, note=None):
        if client: return net.tcp(tpkt(pdu), C, S)
        return net.tcp(tpkt(pdu), S, C, '192.0.2.2', '192.0.2.1')
    def mark(name, start): ranges.append((name, start, len(net.frames)))
    inv = [0]
    def invid():
        inv[0] += 1; return inv[0]
    def creq(inner, invoke=None, mods=b''):
        return ctx(0, bint(invoke or invid()) + mods + inner)
    def cresp(inner, invoke):
        return ctx(1, bint(invoke) + inner)

    # --- 1. Initiate / conclude / cancel / reject / error PDUs
    st = len(net.frames) + 1
    svc = lambda n: g.enc(types['ServiceSupportOptions'], 0)
    ireq = ctx(8, ctx(0, i2b(65000), False) + ctx(1, i2b(10), False) + ctx(2, i2b(10), False) + ctx(3, i2b(5), False) +
               ctx(4, ctx(0, i2b(1), False) + ctx(1, b'\x05\xf1\x00', False) + ctx(2, b'\x03\xee\x1c\x00\x00\x04\x08\x00\x00\x79\xef\x18', False)))
    send(ireq)
    iresp = ctx(9, ctx(0, i2b(65000), False) + ctx(1, i2b(8), False) + ctx(2, i2b(8), False) + ctx(3, i2b(4), False) +
                ctx(4, ctx(0, i2b(1), False) + ctx(1, b'\x05\xf1\x00', False) + ctx(2, b'\x03\xee\x1c\x00\x00\x04\x08\x00\x00\x79\xef\x18', False)))
    send(iresp, False)
    for _ in range(3):
        send(g.enc(T('ref', name='Initiate-RequestPDU', tag=8, explicit=False)), True)
        send(g.enc(T('ref', name='Initiate-ResponsePDU', tag=9, explicit=False)), False)
    send(g.enc(T('ref', name='Initiate-ErrorPDU', tag=10, explicit=False)), False)
    for _ in range(2):
        send(g.enc(T('ref', name='Initiate-ErrorPDU', tag=10, explicit=False)), False)
    net.epdu('mms', ctx(11, b'', False)); net.epdu('mms', ctx(12, b'', False))
    send(g.enc(T('ref', name='Conclude-ErrorPDU', tag=13, explicit=False)), False)
    send(ctx(5, i2b(7), False)); send(ctx(6, i2b(7), False), False)
    send(g.enc(T('ref', name='Cancel-ErrorPDU', tag=7, explicit=False)), False)
    for _ in range(30):
        send(g.enc(T('ref', name='RejectPDU', tag=4, explicit=False)), False)
    mark('initiate, conclude, cancel, reject', st)

    # --- 2. every ConfirmedServiceRequest / Response branch
    csr = types['ConfirmedServiceRequest']; csp = types['ConfirmedServiceResponse']
    for rounds in range(2):
        st = len(net.frames) + 1
        for f in csr.fields:
            i = invid()
            send(creq(g.enc(f, 1), i))
            resp = [x for x in csp.fields if x.fname == f.fname or x.fname.lower().startswith(f.fname.lower()[:8])]
            rf = None
            for x in csp.fields:
                if x.tag == f.tag: rf = x
            send(cresp(g.enc(rf, 1), i), False)
        mark('every confirmed service request and response (round %d)' % (rounds + 1), st)
    st = len(net.frames) + 1
    for _ in range(120):
        send(g.enc(T('ref', name='Confirmed-ErrorPDU', tag=2, explicit=False)), False)
    mark('Confirmed-Error PDUs (all service error classes)', st)
    st = len(net.frames) + 1
    ucs = types['UnconfirmedService']
    for _ in range(12):
        send(ctx(3, g.enc(ucs, 1)), False)
    mark('unconfirmed services (generated)', st)
    # request with modifiers
    st = len(net.frames) + 1
    for _ in range(6):
        i = invid()
        mods = b''
        # listOfModifier is an untagged SEQUENCE OF Modifier: tag 0x30 is used by the generator layout
        mod = uni(16, g.enc(types['Modifier'], 1), True)
        send(creq(g.enc(csr.fields[4], 1), i, mod))
    # cs-request-detail [79] (a CHOICE with one INTEGER alternative) after the service
    for k in (0, 1, 2):
        i = invid()
        send(ctx(0, bint(i) + g.enc(csr.fields[k], 1) + ctx(79, bint(5))))
    send(ctx(3, g.enc(ucs, 1) + ctx(79, bint(5))), False)
    mark('requests with listOfModifier and cs-request-detail', st)

    # --- 3. IEC 61850 flows (hand built)
    iec_flows(net, send, creq, cresp, invid, mark)

    # --- 4. two EPDU frames: the NULL itemId reproducer and a plain report
    st = len(net.frames) + 1
    net.epdu('mms', bytes.fromhex('a00e020101a109a003800100a1028000'))
    mark('Exported PDU mms (itemid_str NULL reproducer)', st)
    net.write(os.path.join(outdir, 'mms-coverage.pcapng'))
    malformed(outdir)
    if verbose:
        for r in ranges: print('%d-%d %s' % (r[1], r[2], r[0]))
        print(len(net.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
