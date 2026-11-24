# Helper module for the umts_pcap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small ASN.1 reader and ALIGNED PER encoder for building synthetic
E1AP and E2AP messages from the ASN.1 modules in the Wireshark tree.

It reads the subset of X.680/X.681/X.683 the 3GPP and O-RAN modules use
(SEQUENCE, CHOICE, SEQUENCE OF, ENUMERATED, INTEGER, BIT STRING,
OCTET STRING, character strings, REAL, information object classes and
sets, parameterized containers) and writes values the generator chooses:
every optional component, one alternative of each CHOICE selected by a
variant number, every IE of an IE set. It follows the PER encoding that
epan/dissectors/packet-per.c expects.
"""
import re

INF = float('inf')

_tok_re = re.compile(r'::=|\.\.\.|\.\.|\[\[|\]\]|[{}()\[\],|;@.&<>:^!]'
                     r'|-?\d+|[A-Za-z][A-Za-z0-9-]*|"[^"]*"')


def tokenize(text):
    out = []
    for line in text.splitlines():
        # comments run from -- to the end of the line or to the next --
        line = re.sub(r'--.*?(--|$)', ' ', line)
        out.extend(_tok_re.findall(line))
    # join & and the field name
    res = []
    i = 0
    while i < len(out):
        if out[i] == '&' and i + 1 < len(out):
            res.append('&' + out[i + 1])
            i += 2
        else:
            res.append(out[i])
            i += 1
    return res


def is_upper(name):
    return name[:1].isupper()


class Module:
    def __init__(self, name):
        self.name = name
        self.types = {}      # name -> type
        self.params = {}     # name -> formal parameter names
        self.values = {}     # name -> raw value token
        self.classes = {}    # name -> (fields, syntax)
        self.objects = {}    # name -> (classname, tokens)
        self.sets = {}       # name -> (classname, elements)
        self.imports = {}    # symbol -> module name


class Parser:
    def __init__(self, toks):
        self.t = toks
        self.p = 0

    def peek(self, n=0):
        i = self.p + n
        return self.t[i] if i < len(self.t) else None

    def get(self):
        v = self.t[self.p]
        self.p += 1
        return v

    def expect(self, v):
        g = self.get()
        if g != v:
            raise SyntaxError('expected %s got %s at %d: %s' % (v, g, self.p, ' '.join(self.t[self.p - 10:self.p + 10])))

    def block(self, open_='{', close='}'):
        """Return the tokens inside a balanced block starting at the current token."""
        self.expect(open_)
        depth = 1
        start = self.p
        while depth:
            g = self.get()
            if g == open_:
                depth += 1
            elif g == close:
                depth -= 1
        return self.t[start:self.p - 1]


def split_top(toks, sep=','):
    parts, cur, depth = [], [], 0
    for x in toks:
        if x in '({[':
            depth += 1
        elif x in ')}]':
            depth -= 1
        if x == sep and depth == 0:
            parts.append(cur)
            cur = []
        else:
            cur.append(x)
    parts.append(cur)
    return [p for p in parts if p]


def parse_range(toks):
    """(lb, ub, ext) from the tokens of a range constraint."""
    parts = split_top(toks)
    ext = any(p == ['...'] for p in parts)
    first = parts[0]
    if 'SIZE' in first:
        return None
    if '|' in first:
        # a union such as (0|15..269): PER sees the smallest and largest
        # values (the alternatives are listed in ascending order)
        alts = []
        cur = []
        for x in first:
            if x == '|':
                alts.append(cur)
                cur = []
            else:
                cur.append(x)
        alts.append(cur)
        lb = alts[0][alts[0].index('..') - 1] if '..' in alts[0] else alts[0][0]
        ub = alts[-1][alts[-1].index('..') + 1] if '..' in alts[-1] else alts[-1][0]
        return (lb, ub, ext)
    if '..' in first:
        i = first.index('..')
        return (first[i - 1], first[i + 1], ext)
    return (first[0], first[0], ext)


def parse_constraints(p, t):
    """Parse ( ... ) constraints after a type and attach them to the type dict."""
    while p.peek() == '(':
        toks = p.block('(', ')')
        apply_constraint(t, toks)
    return t


def apply_constraint(t, toks):
    if not toks:
        return
    if toks[0] == 'SIZE':
        sp = Parser(toks[1:])
        inner = sp.block('(', ')')
        rng = parse_range(inner)
        rest = toks[1 + len(inner) + 2:]
        ext = rng[2] or ('...' in rest)
        t['size'] = (rng[0], rng[1], ext)
        return
    if toks[0] == '{':
        # table constraint ({Set}) or ({Set}{@id})
        sp = Parser(toks)
        s = sp.block()
        t['set'] = s[0]
        return
    if toks[0] in ('FROM', 'CONTAINING', 'WITH'):
        return
    # value range, possibly followed by SIZE inside (e.g. (SIZE(..)) handled above)
    parts = split_top(toks)
    if parts and parts[0] and parts[0][0] == 'SIZE':
        apply_constraint(t, parts[0])
        if any(x == ['...'] for x in parts[1:]):
            lb, ub, _ = t['size']
            t['size'] = (lb, ub, True)
        return
    rng = parse_range(toks)
    if rng:
        t['range'] = rng


def parse_type(p):
    tk = p.get()
    if tk == 'SEQUENCE' or tk == 'SET':
        nx = p.peek()
        if nx == '{':
            return parse_seq(p)
        t = {'k': 'SEQOF', 'size': None}
        if nx == '(':
            toks = p.block('(', ')')
            apply_constraint(t, toks)
        elif nx == 'SIZE':
            p.get()
            toks = p.block('(', ')')
            apply_constraint(t, ['SIZE', '('] + toks + [')'])
        p.expect('OF')
        if p.peek()[:1].islower() and p.peek(1) not in (',', '}', None):
            p.get()  # element name
        t['elem'] = parse_type(p)
        return t
    if tk == 'CHOICE':
        return parse_choice(p)
    if tk == 'ENUMERATED':
        toks = p.block()
        root, ext, inext = [], [], False
        for part in split_top(toks):
            if part == ['...']:
                inext = True
                continue
            (ext if inext else root).append(part[0])
        return parse_constraints(p, {'k': 'ENUM', 'root': root, 'ext': ext, 'extensible': inext})
    if tk == 'INTEGER':
        if p.peek() == '{':
            p.block()
        return parse_constraints(p, {'k': 'INT', 'range': None})
    if tk == 'BIT':
        p.expect('STRING')
        named = []
        if p.peek() == '{':
            named = p.block()
        return parse_constraints(p, {'k': 'BITS', 'size': None, 'named': named})
    if tk == 'OCTET':
        p.expect('STRING')
        return parse_constraints(p, {'k': 'OCTETS', 'size': None})
    if tk in ('UTCTime', 'GeneralizedTime'):
        return parse_constraints(p, {'k': 'STR', 'kind': 'VisibleString', 'size': None, 'time': tk})
    if tk in ('PrintableString', 'VisibleString', 'IA5String', 'UTF8String', 'NumericString'):
        return parse_constraints(p, {'k': 'STR', 'kind': tk, 'size': None})
    if tk == 'BOOLEAN':
        return parse_constraints(p, {'k': 'BOOL'})
    if tk == 'NULL':
        return {'k': 'NULL'}
    if tk == 'REAL':
        return parse_constraints(p, {'k': 'REAL'})
    if tk == 'OBJECT':
        p.expect('IDENTIFIER')
        return parse_constraints(p, {'k': 'OID'})
    # reference
    if p.peek() == '.':
        p.get()
        field = p.get()
        t = {'k': 'CF', 'cls': tk, 'field': field, 'set': None}
        return parse_constraints(p, t)
    t = {'k': 'REF', 'name': tk, 'actuals': None}
    if p.peek() == '{':
        toks = p.block()
        acts = []
        for part in split_top(toks):
            if part[0] == '{':
                acts.append(('set', part[1]))
            else:
                acts.append(('val', part[0]))
        t['actuals'] = acts
    return parse_constraints(p, t)


def parse_seq(p):
    toks = p.block()
    comps, extcomps, ext = [], [], False
    for part in split_top(toks):
        if part == ['...']:
            ext = True
            continue
        if part[0] == '[[':
            raise SyntaxError('extension groups not supported')
        name = part[0]
        sp = Parser(part[1:] + ['<end>'])
        t = parse_type(sp)
        rest = sp.t[sp.p:-1]
        opt = 'OPTIONAL' in rest or 'DEFAULT' in rest
        (extcomps if ext else comps).append((name, t, opt))
    return {'k': 'SEQ', 'comps': comps, 'extcomps': extcomps,
            'extensible': ext}


def parse_choice(p):
    toks = p.block()
    alts, extalts, ext = [], [], False
    for part in split_top(toks):
        if part == ['...']:
            ext = True
            continue
        name = part[0]
        sp = Parser(part[1:] + ['<end>'])
        t = parse_type(sp)
        (extalts if ext else alts).append((name, t))
    return {'k': 'CHOICE', 'alts': alts, 'extalts': extalts, 'extensible': ext}


def parse_module(text):
    p = Parser(tokenize(text))
    mods = []
    while p.peek() is not None:
        name = p.get()
        m = Module(name)
        if p.peek() == '{':
            p.block()
        while p.get() != 'BEGIN':
            pass
        if p.peek() == 'EXPORTS':
            while p.get() != ';':
                pass
        if p.peek() == 'IMPORTS':
            p.get()
            syms = []
            while True:
                g = p.get()
                if g == ';':
                    break
                if g == 'FROM':
                    mod = p.get()
                    if p.peek() == '{':
                        p.block()
                    for s in syms:
                        m.imports[s] = mod
                    syms = []
                    continue
                if g == ',':
                    continue
                if g == '{':
                    # parameterized import reference Foo {}
                    p.p -= 1
                    p.block()
                    continue
                syms.append(g)
        while p.peek() != 'END':
            parse_assignment(p, m)
        p.get()
        mods.append(m)
    return mods


def parse_assignment(p, m):
    name = p.get()
    nx = p.peek()
    if nx == '{':
        formals = []
        for part in split_top(p.block()):
            formals.append(part[-1])
        p.expect('::=')
        m.params[name] = formals
        m.types[name] = parse_type(p)
        return
    if nx == '::=':
        p.get()
        if p.peek() == 'CLASS':
            p.get()
            fields = {}
            for part in split_top(p.block()):
                fname = part[0]
                ftype = None
                if len(part) > 1 and part[1] not in ('OPTIONAL', 'UNIQUE', 'DEFAULT'):
                    ftype = part[1]
                default = None
                if 'DEFAULT' in part:
                    default = part[part.index('DEFAULT') + 1]
                fields[fname] = (ftype, default)
            syntax = []
            if p.peek() == 'WITH':
                p.get()
                p.expect('SYNTAX')
                words = []
                for x in p.block():
                    if x in ('[', ']'):
                        continue
                    if x.startswith('&'):
                        syntax.append((tuple(words), x))
                        words = []
                    else:
                        words.append(x)
            m.classes[name] = (fields, syntax)
            return
        m.types[name] = parse_type(p)
        return
    # name Type ::= value | object | object set
    typ = p.get()
    while p.peek() != '::=':
        p.get()
    p.get()
    if p.peek() == '{':
        toks = p.block()
        if is_upper(name):
            elems = []
            for part in split_top(toks, '|'):
                for sub in split_top(part, ','):
                    if sub == ['...']:
                        continue
                    if sub[0] == '{':
                        elems.append(('obj', sub[1:-1]))
                    else:
                        elems.append(('ref', sub[0]))
            m.sets[name] = (typ, elems)
        else:
            m.objects[name] = (typ, toks)
        return
    m.values[name] = p.get()


class Bits:
    def __init__(self):
        self.bits = []

    def b(self, val, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((val >> i) & 1)

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)

    def octets(self, data):
        self.align()
        for c in data:
            self.b(c, 8)

    def raw_bits(self, data, nbits):
        for i in range(nbits):
            self.bits.append((data[i // 8] >> (7 - i % 8)) & 1)

    def lendet(self, n):
        self.align()
        if n < 128:
            self.b(n, 8)
        elif n < 16384:
            self.b(0x8000 | n, 16)
        else:
            raise ValueError('fragmented length %d not supported' % n)

    def get(self):
        bits = self.bits + [0] * ((8 - len(self.bits) % 8) % 8)
        out = bytearray()
        for i in range(0, len(bits), 8):
            v = 0
            for bit in bits[i:i + 8]:
                v = (v << 1) | bit
            out.append(v)
        return bytes(out)


class Ctx:
    def __init__(self, k=0, full=True, vals=None):
        self.k = k
        self.full = full
        self.minimal = False
        self.stack = []
        self.vals = vals or {}


class Spec:
    def __init__(self, files, overrides=None):
        self.mods = {}
        for f in files:
            with open(f) as fh:
                for m in parse_module(fh.read()):
                    self.mods[m.name] = m
        self.overrides = overrides or {}
        self._cost = {}
        self._busy = set()
        self._taint = 0
        self._used = {}

    # ---- name resolution ----
    def find(self, kind, name, mod):
        m = self.mods.get(mod)
        if m is not None:
            d = getattr(m, kind)
            if name in d:
                return d[name], m.name
            if name in m.imports and m.imports[name] in self.mods:
                d2 = getattr(self.mods[m.imports[name]], kind)
                if name in d2:
                    return d2[name], m.imports[name]
        for m in self.mods.values():
            d = getattr(m, kind)
            if name in d:
                return d[name], m.name
        raise KeyError('%s %s not found (from %s)' % (kind, name, mod))

    def value(self, v, mod, env=None):
        if v is None:
            return None
        if env and v in env:
            return self.value(env[v][1], env[v][2], None)
        try:
            return int(v)
        except ValueError:
            pass
        raw, m2 = self.find('values', v, mod)
        return self.value(raw, m2)

    def type_of(self, name, mod):
        return self.find('types', name, mod)

    def objset(self, setname, mod):
        """Flatten an object set into a list of (fields dict, module)."""
        (cls, elems), m2 = self.find('sets', setname, mod)
        out = []
        for kind, x in elems:
            if kind == 'obj':
                out.append((self.parse_object(cls, x, m2), m2))
            else:
                try:
                    (c2, toks), m3 = self.find('objects', x, m2)
                    out.append((self.parse_object(c2, toks, m3), m3))
                except KeyError:
                    out.extend(self.objset(x, m2))
        return out

    def cls(self, name, mod):
        return self.find('classes', name, mod)[0]

    def parse_object(self, cls, toks, mod):
        fields, syntax = self.cls(cls, mod)
        res = {}
        p = Parser(list(toks) + ['<end>'])
        while p.peek() != '<end>':
            best = None
            for words, f in syntax:
                if tuple(p.t[p.p:p.p + len(words)]) == words:
                    if best is None or len(words) > len(best[0]):
                        best = (words, f)
            if best is None and p.peek() == 'TYPE':
                # LCS-AP writes TYPE where its class says EXTENSION
                for words, f in syntax:
                    if words[:1] == ('EXTENSION',):
                        best = (('TYPE',), f)
            if best is None:
                raise SyntaxError('object syntax at %s' % p.t[p.p:p.p + 5])
            p.p += len(best[0])
            f = best[1]
            if f[1:2].isupper():
                res[f] = parse_type(p)
            else:
                res[f] = p.get()
        for f, (ftype, default) in fields.items():
            if f not in res and default is not None:
                res[f] = default
        res['__cls'] = cls
        return res

    # ---- cost (finite encoding?) ----
    def cost(self, t, env, mod):
        key = (id(t), mod, tuple(sorted((k, v[1]) for k, v in (env or {}).items())))
        if key in self._cost:
            return self._cost[key]
        if key in self._busy:
            self._taint += 1
            return INF
        self._busy.add(key)
        before = self._taint
        c = self._cost_calc(t, env, mod)
        self._busy.discard(key)
        # an infinite cost found while a type was still being costed may
        # be wrong, so only finite costs or clean results are kept
        if c < INF or self._taint == before:
            self._cost[key] = c
        return c

    def _cost_calc(self, t, env, mod):
        k = t['k']
        if k == 'REF':
            name = t['name']
            if name in self.overrides:
                return 1
            if env and name in env:
                return 1
            d, m2 = self.type_of(name, mod)
            return 1 + self.cost(d, self.bind(name, t, env, mod, m2), m2)
        if k == 'SEQ':
            if self.is_iefield(t):
                objs = self.ie_objects(t, env, mod)
                if not objs:
                    return INF
                return 1 + min(self.obj_cost(o, om) for o, om in objs)
            return 1 + sum(self.cost(ct, env, mod) for n, ct, opt in t['comps'] if not opt)
        if k == 'CHOICE':
            return 1 + min([self.cost(at, env, mod) for n, at in t['alts'] + t['extalts']] + [INF])
        if k == 'SEQOF':
            lb = self.size(t, env, mod)[0]
            if not lb:
                return 1
            e = self.deref_iefield(t['elem'], env, mod)
            if e:
                objs = [o for o in self.ie_objects(e[0], e[1], e[2]) if self.obj_cost(*o) < INF]
                return 1 if len(objs) >= lb else INF
            return 1 + lb * self.cost(t['elem'], env, mod)
        return 1

    def obj_cost(self, o, om):
        c = 0
        for f, v in o.items():
            if isinstance(v, dict):
                c = max(c, self.cost(v, None, om))
        return c

    # ---- parameterized types ----
    def bind(self, name, t, env, mod, defmod):
        formals = self.mods[defmod].params.get(name)
        if not formals:
            return None
        acts = t['actuals'] or []
        newenv = {}
        for f, (kind, v) in zip(formals, acts):
            if env and v in env:
                newenv[f] = env[v]
            else:
                newenv[f] = (kind, v, mod)
        return newenv

    def size(self, t, env, mod):
        s = t.get('size')
        if not s:
            return (None, None, False)
        return (self.value(s[0], mod, env), self.value(s[1], mod, env), s[2])

    def is_iefield(self, t):
        return t['k'] == 'SEQ' and any(ct['k'] == 'CF' for n, ct, o in t['comps'])

    def deref_iefield(self, t, env, mod):
        """If t (a REF) leads to an IE field SEQUENCE, return (seq, env, mod)."""
        seen = 0
        while t['k'] == 'REF' and seen < 10:
            if t['name'] in self.overrides or (env and t['name'] in env):
                return None
            d, m2 = self.type_of(t['name'], mod)
            env = self.bind(t['name'], t, env, mod, m2)
            t, mod = d, m2
            seen += 1
        if self.is_iefield(t):
            return (t, env, mod)
        return None

    def ie_objects(self, t, env, mod):
        for n, ct, o in t['comps']:
            if ct['k'] == 'CF' and ct.get('set'):
                s = ct['set']
                if env and s in env:
                    return self.objset(env[s][1], env[s][2])
                return self.objset(s, mod)
        return []

    # ---- encoding ----
    def enc_int(self, w, v, lb, ub, ext=False):
        if ext:
            w.b(0, 1)
        if lb is None or ub is None:
            # unconstrained: length + two's complement
            n = 1
            while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
                n += 1
            w.lendet(n)
            w.octets((v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big'))
            return
        r = ub - lb + 1
        x = v - lb
        if r == 1:
            return
        if r <= 255:
            w.b(x, max(1, (r - 1).bit_length()))
        elif r == 256:
            w.align()
            w.b(x, 8)
        elif r <= 65536:
            w.align()
            w.b(x, 16)
        else:
            nb = max(1, (x.bit_length() + 7) // 8)
            w.b(nb - 1, 3 if (ub - lb) > 0xffffffff else 2)
            w.align()
            w.b(x, 8 * nb)

    def enc_len(self, w, n, lb, ub, ext=False):
        """Length of a SEQUENCE OF."""
        if ext:
            w.b(0, 1)
        if ub is None:
            w.lendet(n)
        elif lb == ub and ub < 65536:
            return
        elif ub < 65536:
            self.enc_int(w, n, lb, ub)
        else:
            w.lendet(n)

    def enc_octets(self, w, t, data, env=None, mod=None):
        lb, ub, ext = self.size(t, env, mod)
        if ext:
            w.b(0, 1)
        n = len(data)
        if ub == 0:
            return
        if lb is not None and lb == ub and ub <= 2:
            for c in data:
                w.b(c, 8)
        elif lb is not None and lb == ub and lb < 65536:
            w.octets(data)
        else:
            if ub is not None:
                self.enc_int(w, n, lb or 0, ub)
            else:
                w.lendet(n)
            if n:
                w.octets(data)

    def enc_bits(self, w, t, nbits, data, env=None, mod=None):
        lb, ub, ext = self.size(t, env, mod)
        if ext:
            w.b(0, 1)
        if ub == 0:
            return
        if lb is not None and lb == ub and ub <= 16:
            w.raw_bits(data, nbits)
        elif lb is not None and lb == ub and lb < 65536:
            w.align()
            w.raw_bits(data, nbits)
        else:
            if ub is not None and ub < 65536:
                self.enc_int(w, nbits, lb or 0, ub)
            else:
                w.lendet(nbits)
            if nbits:
                w.align()
                w.raw_bits(data, nbits)

    def enc_str(self, w, t, s, env=None, mod=None):
        data = s.encode()
        if t['kind'] == 'UTF8String':
            w.lendet(len(data))
            w.octets(data)
            return
        lb, ub, ext = self.size(t, env, mod)
        if ext:
            w.b(0, 1)
        if ub == 0:
            return
        aligned = True
        if lb is not None and lb == ub and ub <= 2:
            aligned = False
        if ub is not None and ub < 2:
            aligned = False
        if ub is None:
            w.lendet(len(data))
        elif lb != ub:
            self.enc_int(w, len(data), lb or 0, ub)
        if aligned:
            w.align()
        for c in data:
            w.b(c, 8)

    def opentype(self, w, inner):
        data = inner.get() or b'\x00'
        w.lendet(len(data))
        w.octets(data)

    def pattern(self, n, ctx):
        return bytes(((i * 0x25 + 0x11 + ctx.k * 7) & 0xff) for i in range(n))

    def enc(self, w, t, env, mod, ctx):
        k = t['k']
        if k == 'REF':
            return self.enc_ref(w, t, env, mod, ctx)
        if k == 'SEQ':
            if self.is_iefield(t):
                objs = [o for o in self.ie_objects(t, env, mod) if self.obj_cost(*o) < INF]
                if ctx.minimal:
                    objs.sort(key=lambda o: self.obj_cost(*o))
                    o = objs[0]
                else:
                    o = objs[ctx.k % len(objs)]
                return self.enc_iefield(w, t, mod, o, ctx)
            return self.enc_seq(w, t, env, mod, ctx)
        if k == 'CHOICE':
            cands = [(i, n, at) for i, (n, at) in enumerate(t['alts'] + t['extalts'])
                     if self.cost(at, env, mod) < INF]
            if ctx.minimal:
                cands.sort(key=lambda c: self.cost(c[2], env, mod))
                i, n, at = cands[0]
            elif ctx.vals.get('ext') and any(c[0] >= len(t['alts']) for c in cands):
                # prefer the extension alternatives (the rotating choice
                # reaches them last)
                ec = [c for c in cands if c[0] >= len(t['alts'])]
                used = self._used.setdefault(id(t), {})
                i, n, at = min(ec, key=lambda c: (used.get(c[0], 0), c[0]))
                used[i] = used.get(i, 0) + 1
            else:
                # the alternative used least often so far at this place, so
                # that every alternative turns up
                used = self._used.setdefault(id(t), {})
                i, n, at = min(cands, key=lambda c: (used.get(c[0], 0), c[0]))
                used[i] = used.get(i, 0) + 1
            nroot = len(t['alts'])
            if t['extensible']:
                w.b(1 if i >= nroot else 0, 1)
            if i < nroot:
                if nroot > 1:
                    self.enc_int(w, i, 0, nroot - 1)
                self.enc(w, at, env, mod, ctx)
            else:
                self.enc_nsnn(w, i - nroot)
                inner = Bits()
                self.enc(inner, at, env, mod, ctx)
                self.opentype(w, inner)
            return
        if k == 'ENUM':
            nroot, next_ = len(t['root']), len(t['ext'])
            idx = 0 if ctx.minimal else ctx.k % (nroot + next_)
            return self.enc_enum(w, t, idx)
        if k == 'INT':
            rng = t.get('range')
            if not rng:
                return self.enc_int(w, 1 + ctx.k % 5, None, None)
            lb, ub = self.value(rng[0], mod, env), self.value(rng[1], mod, env)
            v = lb if ctx.minimal else [lb, ub, (lb + ub) // 2, lb + 1 if ub > lb else lb][ctx.k % 4]
            return self.enc_int(w, v, lb, ub, rng[2])
        if k == 'BITS':
            lb, ub, ext = self.size(t, env, mod)
            if lb is None:
                n = 8
            elif ctx.minimal or lb == ub:
                n = lb
            else:
                n = [lb, min(ub, lb + 64), min(ub, max(lb, 32))][ctx.k % 3]
            return self.enc_bits(w, t, n, self.pattern((n + 7) // 8, ctx), env, mod)
        if k == 'OCTETS':
            lb, ub, ext = self.size(t, env, mod)
            if lb is None:
                n = 4
            elif lb == ub:
                n = lb
            elif ctx.minimal:
                n = max(lb, 1)
            else:
                n = max(lb, min(ub, [4, 1, 16][ctx.k % 3]))
            return self.enc_octets(w, t, self.pattern(n, ctx), env, mod)
        if k == 'STR':
            lb, ub, ext = self.size(t, env, mod)
            lb = lb or 1
            n = lb if lb == ub else max(lb, min(ub or 8, 8))
            s = ('Synth' + 'abcdefghijklmnopqrstuvwxyz' * 10)[:n]
            return self.enc_str(w, t, s, env, mod)
        if k == 'BOOL':
            w.b(0 if ctx.minimal else (ctx.k + 1) % 2, 1)
            return
        if k == 'NULL':
            return
        if k == 'REAL':
            w.lendet(3)
            w.octets(b'\x80\x00\x01')
            return
        if k == 'OID':
            w.lendet(4)
            w.octets(b'\x2b\x06\x01\x04')
            return
        if k == 'SEQOF':
            lb, ub, ext = self.size(t, env, mod)
            e = self.deref_iefield(t['elem'], env, mod)
            if e:
                seq, eenv, emod = e
                objs = [o for o in self.ie_objects(seq, eenv, emod) if self.obj_cost(*o) < INF]
                if ctx.minimal or not ctx.full:
                    must = [o for o in objs if o[0].get('&presence') == 'mandatory']
                    objs = must if len(must) >= (lb or 0) else objs[:lb]
                if ub is not None:
                    objs = objs[:ub]
                self.enc_len(w, len(objs), lb, ub, ext)
                for o in objs:
                    self.enc_iefield(w, seq, emod, o, ctx)
                return
            if ctx.minimal:
                n = lb or 0
            else:
                n = max(lb or 0, 1)
                if ub is not None:
                    n = min(n, ub)
            self.enc_len(w, n, lb, ub, ext)
            for i in range(n):
                self.enc(w, t['elem'], env, mod, ctx)
            return
        raise ValueError('cannot encode %s' % k)

    def enc_nsnn(self, w, n):
        if n < 64:
            w.b(0, 1)
            w.b(n, 6)
        else:
            w.b(1, 1)
            w.lendet(1)
            w.b(n, 8)

    def enc_enum(self, w, t, idx):
        nroot, next_ = len(t['root']), len(t['ext'])
        if t['extensible']:
            w.b(1 if idx >= nroot else 0, 1)
        if idx < nroot:
            self.enc_int(w, idx, 0, nroot - 1)
        else:
            self.enc_nsnn(w, idx - nroot)

    def enc_seq(self, w, t, env, mod, ctx):
        present = []
        for n, ct, opt in t['comps']:
            if opt:
                present.append(not ctx.minimal and self.cost(ct, env, mod) < INF)
        extp = []
        if t['extcomps'] and ctx.full and not ctx.minimal:
            extp = [self.cost(ct, env, mod) < INF for n, ct, opt in t['extcomps']]
        if t['extensible']:
            w.b(1 if any(extp) else 0, 1)
        for p_ in present:
            w.b(1 if p_ else 0, 1)
        i = 0
        for n, ct, opt in t['comps']:
            if opt:
                p_ = present[i]
                i += 1
                if not p_:
                    continue
            self.enc(w, ct, env, mod, ctx)
        if any(extp):
            self.enc_nsnn(w, len(extp) - 1)
            for p_ in extp:
                w.b(1 if p_ else 0, 1)
            for (n, ct, opt), p_ in zip(t['extcomps'], extp):
                if p_:
                    inner = Bits()
                    self.enc(inner, ct, env, mod, ctx)
                    self.opentype(w, inner)

    def enc_iefield(self, w, t, mod, o, ctx, fixed=None):
        obj, omod = o
        fields = self.cls(obj['__cls'], omod)[0]
        for n, ct, opt in t['comps']:
            if ct['k'] != 'CF':
                self.enc(w, ct, None, mod, ctx)
                continue
            f = ct['field']
            v = obj.get(f)
            if f[1:2].isupper():
                inner = Bits()
                if v is None:
                    raise ValueError('object lacks %s' % f)
                self.enc(inner, v, None, omod, ctx)
                self.opentype(w, inner)
            else:
                ftype = fields[f][0]
                self.enc_fixed(w, ftype, v, omod)

    def enc_fixed(self, w, typename, v, mod):
        """Encode the value v (identifier or number) of the named type."""
        t, m2 = self.type_of(typename, mod)
        while t['k'] == 'REF':
            t, m2 = self.type_of(t['name'], m2)
        if t['k'] == 'ENUM':
            return self.enc_enum(w, t, (t['root'] + t['ext']).index(v))
        if t['k'] == 'INT':
            rng = t['range']
            lb, ub = self.value(rng[0], m2), self.value(rng[1], m2)
            return self.enc_int(w, self.value(v, mod), lb, ub, rng[2])
        if t['k'] == 'CHOICE':
            # PrivateIE-ID etc: not used for fixed values here
            raise ValueError('fixed CHOICE value')
        raise ValueError('fixed value of %s' % t['k'])

    def enc_ref(self, w, t, env, mod, ctx):
        name = t['name']
        if name in self.overrides:
            d, m2 = self.type_of(name, mod)
            return self.overrides[name](self, w, d, m2, ctx)
        d, m2 = self.type_of(name, mod)
        newenv = self.bind(name, t, env, mod, m2)
        saved = ctx.minimal
        # recursion: the same type with the same actual parameters
        key = (name, tuple(sorted((k, v[1]) for k, v in (newenv or {}).items())))
        if key in ctx.stack or len(ctx.stack) > 40:
            ctx.minimal = True
        ctx.stack.append(key)
        try:
            if t.get('size') or t.get('range'):
                d = dict(d)
                if t.get('size'):
                    d['size'] = t['size']
                if t.get('range'):
                    d['range'] = t['range']
            self.enc(w, d, newenv, m2, ctx)
        finally:
            ctx.stack.pop()
            ctx.minimal = saved

    # ---- top level ----
    def procedures(self, setname, mod):
        return self.objset(setname, mod)

    def pdu(self, pdutype, mod, kind, o, ctx):
        """Encode an AP PDU: CHOICE alternative kind (0 initiating,
        1 successful, 2 unsuccessful) for the elementary procedure o."""
        t, m2 = self.type_of(pdutype, mod)
        w = Bits()
        nroot = len(t['alts'])
        if t['extensible']:
            w.b(0, 1)
        self.enc_int(w, kind, 0, nroot - 1)
        at = t['alts'][kind][1]
        seq, m3 = self.type_of(at['name'], m2)
        self.enc_iefield(w, seq, m3, o, ctx)
        return w.get()

    def encode(self, typename, mod, ctx):
        t, m2 = self.type_of(typename, mod)
        w = Bits()
        ctx.stack.append(typename)
        self.enc(w, t, None, m2, ctx)
        ctx.stack.pop()
        return w.get() or b'\x00'
