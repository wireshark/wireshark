# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""A small ASN.1 (X.680 subset) parser and a BER generator, enough for
ISO8571-FTAM.asn: it reads the module and produces valid BER for any type
in it, filling optional components and choosing CHOICE alternatives
according to a random generator, so that one generator covers every PDU
type and every component without a hand written encoder per PDU."""
import random
import re

from x500lib import tlv, ber_int, oid_enc

TOK = re.compile(r'''::=|\.\.|[{}()\[\],.&|]|"[^"]*"|-?\d+|[A-Za-z][A-Za-z0-9-]*|\S''')

UNIV = {'BOOLEAN': 1, 'INTEGER': 2, 'BIT STRING': 3, 'OCTET STRING': 4, 'NULL': 5,
        'OBJECT IDENTIFIER': 6, 'EXTERNAL': 8, 'ENUMERATED': 10, 'SEQUENCE': 16,
        'SET': 17, 'GraphicString': 25, 'GeneralizedTime': 24, 'UTCTime': 23,
        'PrintableString': 19, 'IA5String': 22, 'NumericString': 18,
        'VisibleString': 26, 'GeneralString': 27}
STRINGS = ('GraphicString', 'GeneralizedTime', 'UTCTime', 'PrintableString', 'IA5String',
           'NumericString', 'VisibleString', 'GeneralString')


class T:
    """kind: seq, set, choice, seqof, setof, int, bits, octs, bool, null, oid,
    ext, enum, str, any, ref; tag: (class, number, explicit) or None"""

    def __init__(self, kind, **kw):
        self.kind = kind
        self.tag = None
        self.__dict__.update(kw)


def tokens(text):
    text = re.sub(r'--[^\n]*', '', text)
    return TOK.findall(text)


class Parser:
    def __init__(self, text):
        self.t = tokens(text)
        self.i = 0
        self.types = {}
        self.implicit = 'IMPLICIT' in self.t[:self.t.index('BEGIN')]
        i = self.t.index('BEGIN')
        self.i = i + 1
        while self.t[self.i] != 'END':
            name = self.t[self.i]
            assert self.t[self.i + 1] == '::=', (name, self.t[self.i + 1])
            self.i += 2
            self.types[name] = self.type_()

    def peek(self, n=0):
        return self.t[self.i + n]

    def next(self):
        v = self.t[self.i]
        self.i += 1
        return v

    def skip_balanced(self, open_, close):
        depth = 0
        while True:
            v = self.next()
            if v == open_:
                depth += 1
            elif v == close:
                depth -= 1
                if depth == 0:
                    return

    def constraint(self):
        toks = []
        while self.peek() == '(':
            start = self.i
            self.skip_balanced('(', ')')
            toks += self.t[start:self.i]
        return self.parse_cons(toks)

    @staticmethod
    def parse_cons(toks):
        """(lo, hi) of a SIZE or value range constraint, else None."""
        nums = [int(x) for x in toks if re.fullmatch(r'-?\d+', x)]
        if not nums or 'MIN' in toks or 'MAX' in toks:
            return None
        return (nums[0], nums[-1])

    def type_(self):
        tag = None
        tags = []
        while self.peek() == '[':
            self.next()
            cls = 2
            if self.peek() in ('APPLICATION', 'UNIVERSAL', 'PRIVATE'):
                cls = {'UNIVERSAL': 0, 'APPLICATION': 1, 'PRIVATE': 3}[self.next()]
            num = int(self.next())
            assert self.next() == ']'
            mode = 'IMPLICIT' if getattr(self, 'implicit', False) else None
            if self.peek() in ('IMPLICIT', 'EXPLICIT'):
                mode = self.next()
            tags.append((cls, num, mode))
        t = self.base_type()
        # apply the tags, innermost first
        for cls, num, mode in reversed(tags):
            inner = t
            while inner.kind == 'ref' and False:
                pass
            explicit = mode != 'IMPLICIT' or inner.kind in ('choice', 'any')
            if explicit:
                t = T('wrap', inner=inner)
                t.tag = (cls, num, True)
            elif inner.kind != 'ref' and inner.kind != 'wrap' and inner.tag is None:
                inner.tag = (cls, num, False)
                t = inner
            else:
                t = T('wrap', inner=inner)
                t.tag = (cls, num, False)
        return t

    def named_list(self):
        names = []
        assert self.next() == '{'
        while True:
            n = self.next()
            if n == '}':
                break
            if n == ',':
                continue
            if self.peek() == '(':
                self.next()
                v = int(self.next())
                assert self.next() == ')'
                names.append((n, v))
            else:
                names.append((n, None))
        return names

    def base_type(self):
        v = self.next()
        if v in ('SEQUENCE', 'SET'):
            if self.peek() == 'OF':
                self.next()
                self.constraint()
                inner = self.type_()
                return T('seqof' if v == 'SEQUENCE' else 'setof', inner=inner)
            return self.components('seq' if v == 'SEQUENCE' else 'set')
        if v == 'CHOICE':
            t = self.components('choice')
            return t
        if v == 'INTEGER':
            names = self.named_list() if self.peek() == '{' else []
            return T('int', names=names, cons=self.constraint())
        if v == 'BIT':
            assert self.next() == 'STRING'
            names = self.named_list() if self.peek() == '{' else []
            self.constraint()
            return T('bits', names=names)
        if v == 'OCTET':
            assert self.next() == 'STRING'
            return T('octs', cons=self.constraint())
        if v == 'OBJECT':
            assert self.next() == 'IDENTIFIER'
            return T('oid')
        if v == 'ENUMERATED':
            nl = self.named_list()
            nl = [(n, i if x is None else x) for i, (n, x) in enumerate(nl)]
            return T('enum', names=nl)
        if v == 'BOOLEAN':
            return T('bool')
        if v == 'NULL':
            return T('null')
        if v == 'EXTERNAL':
            return T('ext')
        if v in STRINGS:
            return T('str', name=v, cons=self.constraint())
        if v == 'TYPE-IDENTIFIER':
            assert self.next() == '.'
            assert self.next() == '&'
            what = self.next()
            self.constraint()
            if what == 'id':
                return T('oid', open_id=True)
            return T('any')
        return T('ref', name=v)

    def components(self, kind):
        assert self.next() == '{'
        comps = []
        while True:
            if self.peek() == '}':
                self.next()
                break
            if self.peek() in (',', '..', '.'):
                self.next()
                continue
            name = self.next()
            ty = self.type_()
            opt = False
            if self.peek() == 'OPTIONAL':
                self.next()
                opt = True
            elif self.peek() == 'DEFAULT':
                self.next()
                opt = True
                if self.peek() == '{':
                    self.skip_balanced('{', '}')
                else:
                    self.next()
            comps.append((name, ty, opt))
        return T(kind, comps=comps)


class Gen:
    """BER generation. mode: 'full' fills every component (up to the depth
    limit), 'min' only the mandatory ones, 'mix' chooses at random."""

    OIDS = ['1.0.8571.5.1', '1.0.8571.5.3', '1.0.8571.5.2', '1.0.8571.1.1', '1.0.8571.2.1',
            '1.3.14.5.5.9', '1.3.9999.1.5.9', '1.2.3.4.5', '1.0.8571.2.3', '1.0.8571.4.1']

    def __init__(self, text, seed=1, maxdepth=7):
        self.p = Parser(text)
        self.rnd = random.Random(seed)
        self.maxdepth = maxdepth
        self.mode = 'full'
        self.type_hooks = {}     # type name -> f(gen) -> content bytes of an OCTET STRING
        self.int_hooks = {}      # field name -> f(gen) -> int
        self.path = []
        self.skip = set()        # optional components never filled
        self.choice_count = {}
        self.last_oid = None
        self.cost = {}
        self.compute_costs()

    # --- cost: smallest number of nodes needed, for bounding recursion
    def compute_costs(self):
        INF = 10 ** 9
        self.cost = {n: INF for n in self.p.types}
        for _ in range(60):
            changed = False
            for n, t in self.p.types.items():
                c = self.tcost(t)
                if c < self.cost[n]:
                    self.cost[n] = c
                    changed = True
            if not changed:
                break

    def tcost(self, t):
        INF = 10 ** 9
        k = t.kind
        if k == 'ref':
            return self.cost.get(t.name, INF) + 0
        if k == 'wrap':
            return 1 + self.tcost(t.inner)
        if k in ('seq', 'set'):
            return 1 + sum(self.tcost(c[1]) for c in t.comps if not c[2])
        if k == 'choice':
            return 1 + min(self.tcost(c[1]) for c in t.comps)
        return 1

    def alt_index(self, t, depth):
        key = id(t)
        n = self.choice_count.get(key, 0)
        self.choice_count[key] = n + 1
        if depth >= self.maxdepth:
            costs = [self.tcost(c[1]) for c in t.comps]
            return costs.index(min(costs))
        return n % len(t.comps)

    # --- encoding
    def enc_tag(self, tag, constructed, content):
        cls, num, _ = tag
        first = (cls << 6) | (0x20 if constructed else 0)
        if num < 31:
            return bytes([first | num]) + self.len_(len(content)) + content
        b = []
        n = num
        while n:
            b.insert(0, n & 0x7f)
            n >>= 7
        b = [x | 0x80 for x in b[:-1]] + [b[-1]]
        return bytes([first | 31]) + bytes(b) + self.len_(len(content)) + content

    @staticmethod
    def ber_uint(v):
        n = 1
        while v >= 1 << (8 * n - 1):
            n += 1
        return v.to_bytes(n, 'big')

    @staticmethod
    def len_(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(b)]) + b

    def resolve(self, t):
        while t.kind == 'ref':
            if t.name not in self.p.types:
                raise KeyError(t.name)
            tag = t.tag
            t = self.p.types[t.name]
            if tag:
                raise AssertionError('tag on ref handled in wrap')
        return t

    def enc(self, t, depth=0, universal_default=True):
        """Return BER of a value of type t, with t's own tag(s)."""
        if t.kind == 'ref':
            h = self.type_hooks.get(t.name)
            if h:
                return self.enc_tag((0, 4, False), False, h(self))
            return self.enc(self.p.types[t.name], depth)
        if t.kind == 'wrap':
            inner = t.inner
            if t.tag[2]:                     # explicit
                return self.enc_tag(t.tag, True, self.enc(inner, depth + 1))
            # implicit: replace the outer tag of the inner encoding
            return self.reimpl(t.tag, inner, depth)
        return self.enc_base(t, depth)

    def reimpl(self, tag, inner, depth):
        """Encode inner type with its outer tag replaced (IMPLICIT)."""
        while inner.kind == 'ref':
            h = self.type_hooks.get(inner.name)
            if h:
                return self.enc_tag(tag, False, h(self))
            inner = self.p.types[inner.name]
        if inner.kind == 'wrap':
            if inner.tag[2]:
                # implicit over an explicit tag: content is the tagged value's content
                return self.enc_tag(tag, True, self.enc(inner.inner, depth + 1))
            return self.reimpl(tag, inner.inner, depth)
        if inner.kind == 'choice':
            return self.enc_tag(tag, True, self.enc_base(inner, depth))
        return self.enc_base(inner, depth, override=tag)

    def prim(self, t, override, utag, content, constructed=False):
        tag = override or t.tag or (0, utag, False)
        return self.enc_tag(tag, constructed, content)

    def enc_base(self, t, depth, override=None):
        k = t.kind
        r = self.rnd
        if k in ('seq', 'set'):
            parts = []
            for name, ct, opt in t.comps:
                if opt:
                    if depth >= self.maxdepth or self.mode == 'min' or name in self.skip:
                        continue
                    if self.mode == 'mix' and r.random() < 0.4:
                        continue
                self.path.append(name)
                try:
                    parts.append(self.enc(ct, depth + 1))
                finally:
                    self.path.pop()
            return self.prim(t, override, 16 if k == 'seq' else 17, b''.join(parts), True)
        if k == 'choice':
            i = self.alt_index(t, depth)
            body = self.enc(t.comps[i][1], depth + 1)
            if override:
                return self.enc_tag(override, True, body)
            return body
        if k in ('seqof', 'setof'):
            n = 0 if depth >= self.maxdepth else (1 if self.mode == 'min' else r.choice([1, 2]))
            if self.mode == 'full' and depth < self.maxdepth:
                n = 2 if r.random() < 0.3 else 1
            items = b''.join(self.enc(t.inner, depth + 1) for _ in range(n))
            return self.prim(t, override, 16 if k == 'seqof' else 17, items, True)
        if k == 'int':
            h = self.int_hooks.get(self.path[-1]) if self.path else None
            if h:
                v = h(self)
            elif t.names:
                v = t.names[r.randrange(len(t.names))][1]
            else:
                cands = [0, 1, 5, 100, 1000, 70000]
                if t.cons:
                    lo, hi = t.cons
                    cands = [c for c in cands if lo <= c <= hi] or [lo, hi]
                v = r.choice(cands)
            if v >= 1 << 63 or v < -(1 << 63):
                raise ValueError(v)
            return self.prim(t, override, 2, ber_int(v) if v >= 0 and v < 1 << 31 else self.ber_uint(v))
        if k == 'enum':
            v = t.names[r.randrange(len(t.names))][1]
            return self.prim(t, override, 10, ber_int(v))
        if k == 'bits':
            nbits = (max([n[1] for n in t.names]) + 1) if t.names else r.choice([8, 12, 24])
            val = 0
            if t.names:
                for _, b in t.names:
                    if r.random() < 0.6:
                        val |= 1 << b
            else:
                val = r.getrandbits(nbits)
            nbytes = (nbits + 7) // 8
            data = bytearray(nbytes)
            for b in range(nbits):
                if val >> b & 1:
                    data[b // 8] |= 0x80 >> (b % 8)
            return self.prim(t, override, 3, bytes([nbytes * 8 - nbits]) + bytes(data))
        if k == 'octs':
            n = r.randrange(1, 8)
            if t.cons:
                n = r.choice([t.cons[0], t.cons[1]]) if t.cons[0] != t.cons[1] else t.cons[0]
            return self.prim(t, override, 4, bytes(r.randrange(48, 127) for _ in range(n)))
        if k == 'bool':
            return self.prim(t, override, 1, bytes([r.choice([0, 0xff])]))
        if k == 'null':
            return self.prim(t, override, 5, b'')
        if k == 'oid':
            o = self.pick_oid()
            self.last_oid = o
            return self.prim(t, override, 6, oid_enc(o))
        if k == 'str':
            u = UNIV[t.name]
            s = {'GeneralizedTime': b'20261101120000Z', 'UTCTime': b'261101120000Z',
                 'NumericString': b'12345'}.get(t.name, b'h248 test')
            if t.cons:
                n = t.cons[1] if t.cons[1] <= 12 else t.cons[0] + 2
                s = (b'20261105' * 12)[:n] if t.cons[0] == t.cons[1] == 8 else (b'abcdefgh.example' * 8)[:max(t.cons[0], min(n, 40))]
            return self.prim(t, override, u, s)
        if k == 'ext':
            o = self.pick_oid()
            self.last_oid = o
            inner = self.any_value()
            body = self.enc_tag((0, 6, False), False, oid_enc(o)) + self.enc_tag((2, 0, True), True, inner)
            return self.prim(t, override, 8, body, True)
        if k == 'any':
            # open type: the dissector calls the dissector of the last OID read
            v = self.any_value()
            if override:
                return self.enc_tag(override, False, v)
            return v
        raise ValueError(k)

    FTAM_OIDS = ('1.0.8571.1.1', '1.0.8571.2.1', '1.3.14.5.2.2')

    def pick_oid(self):
        r = self.rnd
        x = r.random()
        if x < 0.35:
            return r.choice(['1.0.8571.5.1', '1.0.8571.5.3'])
        if x < 0.7:
            return r.choice(self.FTAM_OIDS)
        return r.choice(self.OIDS)

    def any_value(self):
        """Content of an open type: what the dissector registered for the
        OID read just before expects (an FTAM PDU for the FTAM OIDs)."""
        o = self.last_oid
        if o in self.FTAM_OIDS:
            if getattr(self, 'nest', 0) >= 1:
                return b'\x30\x00'
            self.nest = 1
            mode, self.mode = self.mode, 'min'
            try:
                return self.enc(dict(self.pdu_alternatives())['f-terminate-request'], 4)
            finally:
                self.mode = mode
                self.nest = 0
        return self.rnd.choice([b'\x04\x04text', b'\x02\x01\x05', b'\x30\x00'])

    def make(self, name):
        return self.enc(self.p.types[name])

    def make_alt(self, name, idx):
        """Encode a CHOICE type with alternative number idx."""
        t = self.p.types[name]
        self.choice_count[id(t)] = idx
        return self.enc(t)

    def pdu_alternatives(self):
        """(path, type) of every alternative of PDU, flattened."""
        out = []
        for outer, ot, _ in self.p.types['PDU'].comps:
            t = self.p.types[ot.name]
            for name, ct, _ in t.comps:
                out.append((name, ct))
        return out
