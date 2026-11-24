# Helper module for the li_ps_pdu capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""A small ASN.1 reader and BER encoder, for building synthetic payloads from the
ASN.1 modules in the Wireshark tree.

It reads the subset of X.680 the module uses (SEQUENCE, SET, CHOICE,
SEQUENCE OF / SET OF, ENUMERATED, INTEGER, BIT STRING, OCTET STRING, BOOLEAN,
NULL, OBJECT IDENTIFIER, RELATIVE-OID, character strings, GeneralizedTime,
tags with IMPLICIT / EXPLICIT / AUTOMATIC defaults) and writes values the
generator picks: every optional component present (or none), one alternative
of each CHOICE chosen by use count so that every alternative turns up, and
per-type overrides for the types that the dissector decodes further.
"""
import re

TOK = re.compile(r'::=|\.\.\.|\.\.|[{}()\[\],|;]|-?\d+|[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)*|"[^"]*"')
STRKINDS = {'UTF8String': 12, 'NumericString': 18, 'PrintableString': 19, 'IA5String': 22,
            'VisibleString': 26, 'GeneralizedTime': 24, 'UTCTime': 23}
UNI = {'SEQ': 16, 'SET': 17, 'SEQOF': 16, 'SETOF': 17, 'BOOL': 1, 'INT': 2, 'BITS': 3, 'OCTETS': 4,
       'NULL': 5, 'OID': 6, 'ROID': 13, 'ENUM': 10, 'REAL': 9}


def tokenize(text):
    out = []
    for line in text.splitlines():
        line = re.sub(r'--.*?(--|$)', ' ', line)
        out.extend(TOK.findall(line))
    return out


class Recursion(Exception):
    pass


class Module:
    def __init__(self, name, default_tags):
        self.name = name
        self.default = default_tags     # 'IMPLICIT', 'EXPLICIT' or 'AUTOMATIC'
        self.types = {}
        self.values = {}


class Parser:
    def __init__(self, toks, mod):
        self.t, self.p, self.mod = toks, 0, mod

    def peek(self, n=0):
        return self.t[self.p + n] if self.p + n < len(self.t) else None

    def get(self):
        v = self.t[self.p]
        self.p += 1
        return v

    def expect(self, v):
        g = self.get()
        if g != v:
            raise SyntaxError('expected %s got %s near %s' % (v, g, ' '.join(self.t[self.p - 8:self.p + 8])))

    def block(self, o='{', c='}'):
        self.expect(o)
        d, start = 1, self.p
        while d:
            g = self.get()
            d += (g == o) - (g == c)
        return self.t[start:self.p - 1]

    def tag(self):
        """[class number] [IMPLICIT|EXPLICIT]  ->  (cls, num, mode) or None"""
        if self.peek() != '[':
            return None
        toks = self.block('[', ']')
        cls = 2
        if toks[0] in ('UNIVERSAL', 'APPLICATION', 'PRIVATE'):
            cls = {'UNIVERSAL': 0, 'APPLICATION': 1, 'PRIVATE': 3}[toks[0]]
            toks = toks[1:]
        num = int(toks[0])
        mode = None
        if self.peek() in ('IMPLICIT', 'EXPLICIT'):
            mode = self.get()
        return (cls, num, mode)

    def constraint(self, t):
        while self.peek() == '(':
            toks = self.block('(', ')')
            self.apply(t, toks)

    @staticmethod
    def split(toks, sep):
        parts, cur, d = [], [], 0
        for x in toks:
            if x in '({[':
                d += 1
            if x in ')}]':
                d -= 1
            if x == sep and d == 0:
                parts.append(cur)
                cur = []
            else:
                cur.append(x)
        parts.append(cur)
        return parts

    def apply(self, t, toks):
        if not toks:
            return
        if toks[0] == 'SIZE':
            inner = toks[2:toks.index(')') if ')' in toks[2:] and '(' not in toks[2:] else len(toks) - 1]
            # SIZE ( a .. b [, ...] )   or SIZE(n)
            depth, end = 0, None
            for i, x in enumerate(toks[1:], 1):
                if x == '(':
                    depth += 1
                if x == ')':
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            inner = toks[2:end]
            first = self.split(inner, ',')[0]
            if '..' in first:
                i = first.index('..')
                t['size'] = (first[i - 1], first[i + 1])
            else:
                t['size'] = (first[0], first[0])
            return
        if toks[0] in ('FROM', 'CONTAINING', 'WITH'):
            return
        first = self.split(toks, ',')[0]
        if '..' in first:
            i = first.index('..')
            t['range'] = (first[i - 1], first[i + 1])
        elif len(first) == 1:
            t['range'] = (first[0], first[0])

    def type(self):
        tag = self.tag()
        tk = self.get()
        t = self.builtin(tk)
        t['tag'] = tag
        self.constraint(t)
        return t

    def builtin(self, tk):
        if tk in ('SEQUENCE', 'SET'):
            nx = self.peek()
            if nx == '{':
                return self.seq(tk)
            t = {'k': 'SEQOF' if tk == 'SEQUENCE' else 'SETOF', 'size': None}
            if nx == '(' or nx == 'SIZE':
                if nx == 'SIZE':
                    toks = None
                    self.get()
                    toks = ['SIZE', '('] + self.block('(', ')') + [')']
                else:
                    toks = self.block('(', ')')
                self.apply(t, toks)
            self.expect('OF')
            if self.peek()[:1].islower() and self.peek(1) not in (',', '}', None, ')'):
                self.get()
            t['elem'] = self.type()
            return t
        if tk == 'CHOICE':
            alts = []
            for part in self.split(self.block(), ','):
                if not part or part == ['...']:
                    continue
                sp = Parser(part[1:] + ['<end>'], self.mod)
                alts.append((part[0], sp.type()))
            return {'k': 'CHOICE', 'alts': alts}
        if tk == 'ENUMERATED':
            items, nxt = [], 0
            for part in self.split(self.block(), ','):
                if not part or part == ['...']:
                    continue
                if len(part) >= 4 and part[1] == '(':
                    nxt = int(part[2])
                items.append((part[0], nxt))
                nxt += 1
            return {'k': 'ENUM', 'items': items}
        if tk == 'INTEGER':
            named = []
            if self.peek() == '{':
                for part in self.split(self.block(), ','):
                    if len(part) >= 4:
                        named.append((part[0], int(part[2])))
            return {'k': 'INT', 'range': None, 'named': named}
        if tk == 'BIT':
            self.expect('STRING')
            named = []
            if self.peek() == '{':
                for part in self.split(self.block(), ','):
                    if len(part) >= 4:
                        named.append((part[0], int(part[2])))
            return {'k': 'BITS', 'size': None, 'named': named}
        if tk == 'OCTET':
            self.expect('STRING')
            return {'k': 'OCTETS', 'size': None}
        if tk in STRKINDS:
            return {'k': 'STR', 'kind': tk, 'size': None}
        if tk == 'BOOLEAN':
            return {'k': 'BOOL'}
        if tk == 'NULL':
            return {'k': 'NULL'}
        if tk == 'REAL':
            return {'k': 'REAL'}
        if tk == 'OBJECT':
            self.expect('IDENTIFIER')
            return {'k': 'OID'}
        if tk == 'RELATIVE-OID':
            return {'k': 'ROID'}
        return {'k': 'REF', 'name': tk}

    def seq(self, kind):
        comps = []
        for part in self.split(self.block(), ','):
            if not part or part == ['...']:
                continue
            if part[0] == 'COMPONENTS':
                raise SyntaxError('COMPONENTS OF not supported')
            sp = Parser(part[1:] + ['<end>'], self.mod)
            t = sp.type()
            rest = sp.t[sp.p:-1]
            opt = 'OPTIONAL' in rest or 'DEFAULT' in rest
            comps.append((part[0], t, opt))
        return {'k': 'SEQ' if kind == 'SEQUENCE' else 'SET', 'comps': comps}


def parse(text):
    """Return the modules of a file: name -> Module."""
    toks = tokenize(text)
    mods = {}
    i = 0
    while i < len(toks):
        # module header: Name [{oid}] DEFINITIONS [X TAGS] ::= BEGIN
        if toks[i] == 'DEFINITIONS':
            name = toks[i - 1]
            j = i - 1
            if toks[j] == '}':
                d = 0
                while True:
                    d += (toks[j] == '}') - (toks[j] == '{')
                    if d == 0:
                        break
                    j -= 1
                name = toks[j - 1]
            dflt = 'EXPLICIT'
            k = i + 1
            if toks[k] in ('IMPLICIT', 'EXPLICIT', 'AUTOMATIC') and toks[k + 1] == 'TAGS':
                dflt = toks[k]
            m = Module(name, dflt)
            b = toks.index('BEGIN', i)
            e = len(toks)
            for q in range(b, len(toks)):
                if toks[q] == 'END':
                    e = q
                    break
            body = toks[b + 1:e]
            m.imports = {}
            if body and body[0] == 'IMPORTS':
                end = body.index(';')
                names = []
                q = 1
                while q < end:
                    x = body[q]
                    if x == ',':
                        pass
                    elif x == 'FROM':
                        src = body[q + 1]
                        for n in names:
                            m.imports[n] = src
                        names = []
                        q += 1
                        if q + 1 < end and body[q + 1] == '{':
                            d = 0
                            q += 1
                            while True:
                                d += (body[q] == '{') - (body[q] == '}')
                                if d == 0:
                                    break
                                q += 1
                    else:
                        names.append(x)
                    q += 1
                body = body[end + 1:]
            p = Parser(body, m)
            while p.p < len(body):
                name = p.get()
                if p.peek() == '::=':
                    p.get()
                    m.types[name] = p.type()
                else:
                    # value assignment: Type ::= value
                    p.type()
                    p.expect('::=')
                    if p.peek() == '{':
                        p.block()
                    else:
                        m.values[name] = p.get()
            mods[m.name] = m
            i = e
        i += 1
    return mods


def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def btag(cls, constructed, num):
    first = (cls << 6) | (0x20 if constructed else 0)
    if num < 31:
        return bytes([first | num])
    out = [num & 0x7f]
    num >>= 7
    while num:
        out.insert(0, 0x80 | (num & 0x7f))
        num >>= 7
    return bytes([first | 0x1f] + out)


def tlv(cls, constructed, num, content):
    return btag(cls, constructed, num) + blen(len(content)) + content


def b128(v):
    enc = [v & 0x7f]
    v >>= 7
    while v:
        enc.append(0x80 | (v & 0x7f))
        v >>= 7
    return bytes(reversed(enc))


def oid_body(dotted):
    a = [int(x) for x in dotted.split('.')]
    return bytes([a[0] * 40 + a[1]]) + b''.join(b128(v) for v in a[2:])


def int_body(v):
    n = 1
    while True:
        try:
            return v.to_bytes(n, 'big', signed=True)
        except OverflowError:
            n += 1


class Ctx:
    def __init__(self, k=0, full=True):
        self.k = k
        self.full = full
        self.stack = []
        self.minimal = False
        self.sparse = False
        self.field = None
        self.skip = set()       # optional component names to leave out


class Encoder:
    def __init__(self, text_files, module, overrides=None):
        self.mods = {}
        for f in text_files:
            with open(f) as fh:
                self.mods.update(parse(fh.read()))
        self.mod = self.mods[module]
        self.overrides = overrides or {}
        self.used = {}
        self.reached = set()      # (id of choice, alternative) used
        self.covered = set()      # ids of the type nodes encoded so far
        self._cu = {}
        self._cu_n = -1
        self.skip = set()         # component names ignored when looking for unused nodes
        self.unknown = set()
        self.fo = {}              # field name -> function(enc, t, mod, ctx) giving the primitive contents

    # ---- lookups
    def find(self, name, mod):
        if '.' in name:
            q, n = name.split('.', 1)
            if q in self.mods and n in self.mods[q].types:
                return self.mods[q].types[n], self.mods[q]
            if q in self.mods:
                src = getattr(self.mods[q], 'imports', {}).get(n)
                if src in self.mods and n in self.mods[src].types:
                    return self.mods[src].types[n], self.mods[src]
            self.unknown.add(name)
            return {'k': 'OCTETS', 'size': None, 'tag': None}, mod
        if name in mod.types:
            return mod.types[name], mod
        if name in self.overrides and name not in mod.types:
            return {'k': 'OCTETS', 'size': None, 'tag': None}, mod
        src = getattr(mod, 'imports', {}).get(name)
        if src is not None:
            if src in self.mods and name in self.mods[src].types:
                return self.mods[src].types[name], self.mods[src]
            self.unknown.add(name)
            return {'k': 'OCTETS', 'size': None, 'tag': None}, mod
        for m in self.mods.values():
            if name in m.types:
                return m.types[name], m
        self.unknown.add(name)
        return {'k': 'OCTETS', 'size': None, 'tag': None}, mod

    def value(self, v, mod):
        try:
            return int(v)
        except ValueError:
            pass
        if v in mod.values:
            return self.value(mod.values[v], mod)
        for m in self.mods.values():
            if v in m.values:
                return self.value(m.values[v], m)
        raise KeyError(v)

    def base_kind(self, t, mod):
        while t['k'] == 'REF':
            t, mod = self.find(t['name'], mod)
        return t['k']

    # ---- cost: can the type be encoded without running into recursion
    def feasible(self, t, mod, stack=()):
        k = t['k']
        if k == 'REF':
            key = t['name']
            if key in stack:
                return False
            d, m2 = self.find(key, mod)
            return self.feasible(d, m2, stack + (key,))
        if k in ('SEQ', 'SET'):
            return all(self.feasible(ct, mod, stack) for n, ct, opt in t['comps'] if not opt)
        if k == 'CHOICE':
            return any(self.feasible(at, mod, stack) for n, at in t['alts'])
        if k in ('SEQOF', 'SETOF'):
            return (t['size'] is None or t['size'][0] in ('0',)) or self.feasible(t['elem'], mod, stack)
        return True

    def cu(self, t, mod):
        """Does the type contain a node that no value has used yet?"""
        if self._cu_n != len(self.covered):
            self._cu, self._cu_n = {}, len(self.covered)
        key = id(t)
        if key in self._cu:
            return self._cu[key]
        if key not in self.covered:
            self._cu[key] = True
            return True
        self._cu[key] = False       # in progress: cycles count as covered
        k = t['k']
        r = False
        if k == 'REF':
            d, m2 = self.find(t['name'], mod)
            r = self.cu(d, m2)
        elif k in ('SEQ', 'SET'):
            r = any([self.cu(ct, mod) for n, ct, o in t['comps'] if n not in self.skip])
        elif k == 'CHOICE':
            r = any([self.cu(at, mod) for n, at in t['alts']])
        elif k in ('SEQOF', 'SETOF'):
            r = self.cu(t['elem'], mod)
        self._cu[key] = r
        return r

    # ---- encoding
    def encode(self, typename, ctx):
        t, mod = self.find(typename, self.mod)
        return self.enc(t, mod, ctx, typename)

    def enc(self, t, mod, ctx, name=None):
        if name in self.fo and t.get('tag'):
            self.covered.add(id(t))
            tt, mm = t, mod
            while tt['k'] == 'REF':
                tt, mm = self.find(tt['name'], mm)
                self.covered.add(id(tt))
            return tlv(t['tag'][0], False, t['tag'][1], self.fo[name](self, t, mod, ctx))
        cls, num, constr, content = self.parts(t, mod, ctx, name)
        if cls is None:
            return content
        return tlv(cls, constr, num, content)

    def parts(self, t, mod, ctx, name=None):
        """(cls, num, constructed, content) of the outermost tag, or
        (None, ..., encoded bytes) for an untagged CHOICE."""
        k = t['k']
        self.covered.add(id(t))
        if k == 'REF':
            n = t['name']
            if n in ctx.stack and ctx.stack.count(n) >= 1:
                raise Recursion(n)
            d, m2 = self.find(n, mod)
            ctx.stack.append(n)
            try:
                if n in self.overrides:
                    self.covered.add(id(d))
                    p = self.overrides[n](self, d, m2, ctx)
                    if p is None:
                        p = self.parts(d, m2, ctx, n)
                else:
                    p = self.parts(d, m2, ctx, n)
            finally:
                ctx.stack.pop()
        else:
            p = self.kind_parts(t, mod, ctx)
        tag = t.get('tag')
        if tag is None:
            return p
        cls, num, mode = tag
        if mode is None:
            mode = mod.default
        if mode == 'AUTOMATIC':
            mode = 'IMPLICIT'
        if p[0] is None or mode == 'EXPLICIT':
            return (cls, num, True, self.pack(p))
        return (cls, num, p[2], p[3])

    @staticmethod
    def pack(p):
        if p[0] is None:
            return p[3]
        return tlv(p[0], p[2], p[1], p[3])

    def seq_of(self, comps, mod, ctx):
        out = b''
        for n, ct, opt in comps:
            if opt:
                if ctx.minimal or not ctx.full or not self.feasible(ct, mod, tuple(ctx.stack)):
                    continue
                if n in ctx.skip:
                    continue
                if ctx.sparse and not self.cu(ct, mod):
                    continue
                try:
                    ctx.field = n
                    out += self.enc(ct, mod, ctx, n)
                except Recursion:
                    continue
            else:
                ctx.field = n
                out += self.enc(ct, mod, ctx, n)
        return out

    def kind_parts(self, t, mod, ctx):
        k = t['k']
        if k in ('SEQ', 'SET'):
            return (0, UNI[k], True, self.seq_of(t['comps'], mod, ctx))
        if k == 'CHOICE':
            cands = [(i, n, at) for i, (n, at) in enumerate(t['alts'])
                     if self.feasible(at, mod, tuple(ctx.stack))]
            used = self.used.setdefault(id(t), {})
            if ctx.minimal:
                i, n, at = cands[0]
            elif ctx.sparse:
                i, n, at = min(cands, key=lambda c: (0 if self.cu(c[2], mod) else 1, used.get(c[0], 0), c[0]))
            else:
                i, n, at = min(cands, key=lambda c: (used.get(c[0], 0), c[0]))
            used[i] = used.get(i, 0) + 1
            self.reached.add((id(t), i))
            ctx.field = n
            return (None, 0, False, self.enc(at, mod, ctx, n))
        if k in ('SEQOF', 'SETOF'):
            lb = self.value(t['size'][0], mod) if t['size'] else 0
            ub = t['size'] and t['size'][1]
            ub = None if ub in (None, 'MAX') else self.value(ub, mod)
            n = max(lb, 1 + (ctx.k % 2) if not ctx.minimal else lb)
            if ub is not None:
                n = min(n, ub)
            if not self.feasible(t['elem'], mod, tuple(ctx.stack)):
                n = 0
            return (0, UNI[k], True, b''.join(self.enc(t['elem'], mod, ctx) for _ in range(n)))
        if k == 'ENUM':
            items = t['items']
            idx = 0 if ctx.minimal else ctx.k % len(items)
            return (0, 10, False, int_body(items[idx][1]))
        if k == 'INT':
            rng = t.get('range')
            if rng:
                lb = -2 ** 31 if rng[0] == 'MIN' else self.value(rng[0], mod)
                ub = 2 ** 31 - 1 if rng[1] == 'MAX' else self.value(rng[1], mod)
                v = lb if ctx.minimal else [lb, ub if ub - lb < 2 ** 31 else lb + 5, (lb + min(ub, lb + 1000)) // 2, lb + 1 if ub > lb else lb][ctx.k % 4]
            elif t['named']:
                v = t['named'][ctx.k % len(t['named'])][1]
            else:
                v = 1 + ctx.k % 5 if not ctx.minimal else 1
            return (0, 2, False, int_body(v))
        if k == 'BITS':
            sz = t['size']
            if sz:
                lb = self.value(sz[0], mod)
                ub = lb if sz[1] == 'MAX' else self.value(sz[1], mod)
            else:
                lb = ub = 0
            if sz and lb != ub and not ctx.minimal:
                nbits = min(ub, lb + 3)
            elif sz:
                nbits = lb
            else:
                nbits = 8
            nb = (nbits + 7) // 8
            data = bytes((0xa5 ^ (i * 0x11) ^ ctx.k) & 0xff for i in range(nb))
            if nbits % 8:
                data = data[:-1] + bytes([data[-1] & (0xff << (8 - nbits % 8)) & 0xff])
            return (0, 3, False, bytes([(-nbits) % 8]) + data)
        if k == 'OCTETS':
            sz = t['size']
            lb = self.value(sz[0], mod) if sz else 0
            ub = None if (not sz or sz[1] == 'MAX') else self.value(sz[1], mod)
            n = lb if (ub == lb or ctx.minimal) else max(lb, 4 if ub is None else min(ub, 4))
            n = max(n, 1) if ub != lb and lb == 0 else n
            return (0, 4, False, bytes(((i * 0x25 + 0x11 + ctx.k * 7) & 0xff) for i in range(n)))
        if k == 'STR':
            return self.string(t, mod, ctx)
        if k == 'BOOL':
            return (0, 1, False, bytes([0xff if (ctx.k + 1) % 2 else 0]))
        if k == 'NULL':
            return (0, 5, False, b'')
        if k == 'OID':
            return (0, 6, False, oid_body('1.3.6.1.4.1.' + str(1 + ctx.k)))
        if k == 'ROID':
            return (0, 13, False, b128(4) + b128(19) + b128(19) + b128(3) + b128(1 + ctx.k % 5))
        if k == 'REAL':
            return (0, 9, False, b'\x80\x00\x01')
        raise ValueError(k)

    def string(self, t, mod, ctx):
        kind = t['kind']
        sz = t['size']
        lb = self.value(sz[0], mod) if sz else 0
        ub = None if (not sz or sz[1] == 'MAX') else self.value(sz[1], mod)
        if kind == 'GeneralizedTime':
            s = '20251107%02d3000Z' % (ctx.k % 24)
        elif kind == 'UTCTime':
            s = '2511071230Z'
        else:
            n = lb if (ub == lb or ctx.minimal) else max(lb, 8 if ub is None else min(ub, 8), 1)
            alpha = '0123456789' if kind == 'NumericString' else 'abcdefghijklmnopqrstuvwxyz'
            s = ((('Synth' if kind != 'NumericString' else '') + alpha * 20))[:n] if kind != 'NumericString' else (alpha * 3)[:n]
        return (0, STRKINDS[kind], False, s.encode())
