# Helper module for the h450_ros capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Aligned PER encoder and random value generator driven by the ASN.1
syntax tree that tools/dissector_generators/asn2wrs.py builds (parser
only; nothing of its code generation is used).  Used to build H.225 /
H.235 / H.245 messages with Python for the coverage capture.  Run it on
the VM: it needs the Wireshark source tree for the .asn files."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import sys
import random
import collections

TOOLS = os.path.join(SRCDIR, 'tools/dissector_generators')
ASN = os.path.join(SRCDIR, 'epan/dissectors/asn1', '')

def load(files, workdir):
    sys.path.insert(0, TOOLS)
    cwd = os.getcwd()
    os.chdir(workdir)
    import asn2wrs as A
    lexer = A.lex.lex(module=A, debug=0)
    parser = A.yacc.yacc(module=A, method='LALR', debug=0, outputdir='.')
    parser.defaulted_states = {}
    A.lexer = lexer
    A.g_conform = A.EthCnf()
    types = {}
    by_mod = {}
    def tag(t, mod):
        if not isinstance(t, A.Type) or getattr(t, '_mod', None) is not None:
            return
        t._mod = mod
        v = getattr(t, 'val', None)
        if isinstance(v, A.Type):
            tag(v, mod)
        for lst in ('elt_list', 'ext_list', 'elt_list2'):
            for e in getattr(t, lst, []) or []:
                if isinstance(e, A.Type):
                    tag(e, mod)
                elif hasattr(e, 'val') and isinstance(e.val, A.Type):
                    tag(e.val, mod)
    objs = {}
    for f in files:
        data = A.ignore_comments(open(ASN + f).read())
        for m in A.yacc.parse(data, lexer=lexer, debug=0):
            mod = str(m.ident.__class__.__name__) + f
            for a in m.body.assign_list:
                if a.__class__.__name__ == 'ObjectAssignment':
                    # OPERATION / ERROR objects: tag the inline types with the module
                    for v in a.val.values():
                        if isinstance(v, A.Type):
                            tag(v, mod)
                    objs[(os.path.basename(f)[:-4], a.ident)] = a
                    continue
                if hasattr(a, 'name') and a.name:
                    tag(a, mod)
                    by_mod.setdefault(mod, {})[a.name] = a
                    types.setdefault(a.name, a)
    os.chdir(cwd)
    types['__by_mod__'] = by_mod
    types['__objs__'] = objs
    return types

# --------------------------------------------------------------- bits ---
class PW:
    def __init__(self):
        self.bits = []
    def put(self, v, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((v >> i) & 1)
        return self
    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)
        return self
    def flag(self, b):
        return self.put(1 if b else 0, 1)
    def raw(self, data):
        for b in data:
            self.put(b, 8)
        return self
    def cint(self, v, lo, hi):
        r = hi - lo + 1
        v -= lo
        assert 0 <= v < r, (v, lo, hi)
        if r == 1:
            return self
        if r <= 255:
            return self.put(v, (r - 1).bit_length())
        if r == 256:
            self.align(); return self.put(v, 8)
        if r <= 65536:
            self.align(); return self.put(v, 16)
        n = max(1, (v.bit_length() + 7) // 8)
        maxn = ((r - 1).bit_length() + 7) // 8
        self.cint(n, 1, maxn)
        self.align()
        return self.put(v, 8 * n)
    def length(self, n):
        assert n < 16384
        self.align()
        if n < 128:
            return self.put(n, 8)
        return self.put(0x8000 | n, 16)
    def small(self, n):
        assert n < 64
        return self.put(n, 7)
    def bytes(self):
        self.align()
        return bytes(int(''.join(map(str, self.bits[i:i + 8])), 2) for i in range(0, len(self.bits), 8)) if self.bits else b''

def open_type(w, inner):
    data = inner.bytes() or b'\0'
    w.length(len(data)).raw(data)

class CList(list):
    pass

# ------------------------------------------------------------ schema ----
BAD = {'ToBeSigned'}

class Schema:
    def __init__(self, types):
        self.by_mod = types.pop('__by_mod__')
        self.types = types
        self.mindepth = {}
        self._compute_mindepth()

    def lookup(self, t):
        return self.by_mod.get(getattr(t, '_mod', None), {}).get(t.val) or self.types.get(t.val)

    def resolve(self, t):
        """follow references; returns (type, merged constraint or None)"""
        cl = [t.constr] if t.constr is not None else []
        seen = 0
        while t.type == 'Type_Ref':
            mod = getattr(t, '_mod', None)
            t = self.lookup(t)
            if t is None:
                return None, None
            if t.constr is not None:
                cl.append(t.constr)
            seen += 1
            assert seen < 50
        return t, CList(cl)

    # constraint helpers
    @staticmethod
    def _num(x):
        if isinstance(x, (int, float)):
            return int(x)
        s = str(x)
        if s in ('MIN', 'MAX'):
            return s
        try:
            return int(s)
        except ValueError:
            return None

    def size_of(self, c):
        if isinstance(c, CList):
            for x in c:
                r = self.size_of(x)
                if r is not None:
                    return r
            return None
        """(lo, hi, ext) of a SIZE constraint, hi None if unbounded"""
        if c is None:
            return None
        if c.type == 'Size':
            s = c.subtype
            ext = bool(getattr(c, 'ext', False)) or bool(getattr(s, 'ext', False))
            if s.type == 'SingleValue':
                n = self._num(s.subtype)
                return (n, n, ext)
            if s.type == 'ValueRange':
                lo, hi = self._num(s.subtype[0]), self._num(s.subtype[1])
                return (0 if lo == 'MIN' else lo, None if hi == 'MAX' else hi, ext)
        if c.type == 'Intersection':
            for sub in c.subtype:
                r = self.size_of(sub)
                if r:
                    return r
        return None

    def range_of(self, c):
        if isinstance(c, CList):
            for x in c:
                r = self.range_of(x)
                if r is not None:
                    return r
            return None
        """(lo, hi, ext) of a value constraint; lo/hi None if open"""
        if c is None:
            return None
        if c.type == 'SingleValue':
            n = self._num(c.subtype)
            return (n, n, bool(getattr(c, 'ext', False)))
        if c.type == 'ValueRange':
            lo, hi = self._num(c.subtype[0]), self._num(c.subtype[1])
            return (None if lo == 'MIN' else lo, None if hi == 'MAX' else hi, bool(getattr(c, 'ext', False)))
        if c.type == 'Intersection':
            for sub in c.subtype:
                r = self.range_of(sub)
                if r:
                    return r
        return None

    def alphabet_of(self, c):
        if isinstance(c, CList):
            for x in c:
                r = self.alphabet_of(x)
                if r is not None:
                    return r
            return None
        if c is None:
            return None
        if c.type == 'From':
            s = c.subtype
            if s.type == 'SingleValue':
                return str(s.subtype).strip('"')
            if s.type == 'ValueRange':
                lo, hi = str(s.subtype[0]).strip('"'), str(s.subtype[1]).strip('"')
                return ''.join(chr(x) for x in range(ord(lo), ord(hi) + 1))
            return None
        if c.type == 'Intersection':
            for sub in c.subtype:
                r = self.alphabet_of(sub)
                if r:
                    return r
        return None

    # element access
    @staticmethod
    def seq_parts(t):
        root = list(t.elt_list)
        root += list(getattr(t, 'elt_list2', []) or [])
        ext = list(getattr(t, 'ext_list', []) or [])
        return root, ext, hasattr(t, 'ext_list')

    @staticmethod
    def elt_name(e):
        return e.val.name

    def _compute_mindepth(self):
        # minimal nesting depth needed to build a value of each named type
        INF = 10 ** 6
        allt = [x for m in self.by_mod.values() for x in m.values()]
        md = {id(x): INF for x in allt}
        def d(t, cache):
            if t.name in BAD and t.type != 'Type_Ref' and t.name == getattr(t, 'name', None) and t in allt:
                return INF
            if t.type == 'Type_Ref':
                rt = self.lookup(t)
                key = id(rt) if rt is not None else None
                return md.get(key, INF) + 1 if key in md else INF
            if t.type == 'SequenceType':
                root, ext, _ = self.seq_parts(t)
                m = 0
                for e in root:
                    if not getattr(e, 'optional', 0) and not getattr(e, 'default', None):
                        m = max(m, d(e.val, cache))
                return m + 1
            if t.type == 'ChoiceType':
                alts = list(t.elt_list)
                return min([d(a, cache) for a in alts] or [INF]) + 1
            if t.type in ('SequenceOfType', 'SetOfType'):
                s = self.size_of(t.constr)
                if s and s[0]:
                    return d(t.val, cache) + 1
                return 1
            if t.type in ('OpenType', 'AnyType'):
                return INF
            return 1
        changed = True
        while changed:
            changed = False
            for t in allt:
                v = d(t, None)
                if v < md[id(t)]:
                    md[id(t)] = v; changed = True
        self.mindepth = md

    def tdepth(self, t):
        if t.type == 'Type_Ref':
            rt = self.lookup(t)
            return self.mindepth.get(id(rt), 10 ** 6) if rt is not None else 10 ** 6
        if t.type == 'SequenceType':
            root, _, _ = self.seq_parts(t)
            return 1 + max([self.tdepth(e.val) for e in root if not getattr(e, 'optional', 0)] or [0])
        if t.type == 'ChoiceType':
            return 1 + min([self.tdepth(a) for a in t.elt_list] or [10 ** 6])
        if t.type in ('SequenceOfType', 'SetOfType'):
            s = self.size_of(t.constr)
            return 1 + (self.tdepth(t.val) if s and s[0] else 0)
        if t.type in ('OpenType', 'AnyType'):
            return 10 ** 6
        return 1

    # ----------------------------------------------------------- encode --
    def encode(self, t, v, w=None):
        w = w if w is not None else PW()
        self._enc(w, t, v, None)
        return w

    def _enc(self, w, t, v, constr_in):
        base, constr = self.resolve(t)
        ty = base.type
        if base.name == 'Extension' and 'h450/' in str(getattr(base, '_mod', '')) and isinstance(v, tuple) and v[0] == '__ext__':
            # H.450 Extension{} (parameterised by an information object set the parser cannot expand):
            # extensionId OBJECT IDENTIFIER, extensionArgument as an open type
            o = oid_bytes(v[1])
            w.length(len(o)).raw(o)
            w.length(len(v[2])).raw(v[2])
            return
        if ty == 'BooleanType':
            w.flag(v)
        elif ty == 'NullType':
            pass
        elif ty == 'IntegerType':
            self._int(w, base, constr, v)
        elif ty == 'EnumeratedType':
            names = [x.ident for x in base.val]
            ext = [x.ident for x in getattr(base, 'ext', []) or []]
            isext = getattr(base, 'ext', None) is not None   # ext is None when the type is not extensible
            if isext:
                w.flag(v in ext)
            if v in ext:
                w.small(ext.index(v))
            else:
                w.cint(names.index(v), 0, len(names) - 1)
        elif ty == 'ChoiceType':
            self._choice(w, base, v)
        elif ty == 'SequenceType':
            self._seq(w, base, v)
        elif ty in ('SequenceOfType', 'SetOfType'):
            self._seqof(w, base, constr, v)
        elif ty == 'OctetStringType':
            self._octets(w, constr, v)
        elif ty == 'BitStringType':
            self._bits(w, constr, v)
        elif ty in ('IA5StringType', 'PrintableStringType', 'NumericStringType', 'VisibleStringType',
                    'BMPStringType', 'GeneralStringType', 'GeneralizedTime', 'UTCTime'):
            self._str(w, ty, constr, v)
        elif ty == 'ObjectIdentifierType':
            w_oid = oid_bytes(v)
            w.length(len(w_oid)).raw(w_oid)
        elif ty in ('OpenType', 'AnyType'):
            w.length(len(v)).raw(v)
        else:
            raise NotImplementedError(ty)

    def _int(self, w, base, constr, v):
        r = self.range_of(constr)
        if r is None:
            # unconstrained: signed, length + 2's complement
            n = max(1, (v.bit_length() + 8) // 8) if v >= 0 else max(1, ((~v).bit_length() + 8) // 8)
            w.length(n).raw((v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big'))
            return
        lo, hi, ext = r
        if ext:
            w.flag(not (lo is None or hi is None or lo <= v <= hi))
        if lo is not None and hi is not None:
            w.cint(v, lo, hi)
        elif lo is not None:
            n = max(1, ((v - lo).bit_length() + 7) // 8)
            w.length(n).raw((v - lo).to_bytes(n, 'big'))
        else:
            n = max(1, (v.bit_length() + 8) // 8)
            w.length(n).raw((v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big'))

    def _choice(self, w, t, v):
        name, val = v
        root = list(t.elt_list)
        ext = list(getattr(t, 'ext_list', []) or [])
        isext = hasattr(t, 'ext_list')
        names = [a.name for a in root]
        enames = [a.name for a in ext]
        if isext:
            w.flag(name in enames)
        if name in enames:
            w.small(enames.index(name))
            inner = PW()
            self._enc(inner, ext[enames.index(name)], val, None)
            open_type(w, inner)
        else:
            i = names.index(name)
            w.cint(i, 0, len(root) - 1)
            self._enc(w, root[i], val, None)

    def _seq(self, w, t, v):
        root, ext, isext = self.seq_parts(t)
        # extension additions present?
        ext_present = [self.elt_name(e) in v for e in ext]
        extbit = any(ext_present)
        if isext:
            w.flag(extbit)
        for e in root:
            if getattr(e, 'optional', 0) or getattr(e, 'default', None) is not None:
                w.flag(self.elt_name(e) in v)
        for e in root:
            n = self.elt_name(e)
            if n in v:
                self._enc(w, e.val, v[n], None)
            else:
                assert getattr(e, 'optional', 0) or getattr(e, 'default', None) is not None, 'missing ' + n
        if extbit:
            # bitmap of all extension additions
            w.small(len(ext) - 1)
            for p in ext_present:
                w.flag(p)
            for e, p in zip(ext, ext_present):
                if p:
                    inner = PW()
                    self._enc(inner, e.val, v[self.elt_name(e)], None)
                    open_type(w, inner)

    def _seqof(self, w, t, constr, v):
        s = self.size_of(constr)
        n = len(v)
        if s is None:
            w.length(n)
        else:
            lo, hi, ext = s
            if ext:
                w.flag(not (lo <= n and (hi is None or n <= hi)))
            if hi is None:
                w.length(n)
            elif lo == hi:
                pass
            else:
                w.cint(n, lo, hi)
        for x in v:
            self._enc(w, t.val, x, None)

    def _octets(self, w, constr, v):
        s = self.size_of(constr)
        n = len(v)
        if s is None or s[1] is None:
            w.length(n); w.raw(v); return
        lo, hi, ext = s
        if ext:
            w.flag(not (lo <= n <= hi))
        if lo == hi:
            if hi > 2:
                w.align()
            w.raw(v); return
        w.cint(n, lo, hi)
        w.align()
        w.raw(v)

    def _bits(self, w, constr, v):
        data, nbits = v
        s = self.size_of(constr)
        bits = [(data[i // 8] >> (7 - i % 8)) & 1 for i in range(nbits)]
        if s is None or s[1] is None:
            w.length(nbits); w.align()
            for b in bits: w.put(b, 1)
            return
        lo, hi, ext = s
        if ext:
            w.flag(not (lo <= nbits <= hi))
        if lo == hi:
            if hi > 16:
                w.align()
        else:
            w.cint(nbits, lo, hi)
            w.align()
        for b in bits:
            w.put(b, 1)

    def _str(self, w, ty, constr, v):
        s = self.size_of(constr)
        alph = self.alphabet_of(constr)
        if ty == 'NumericStringType' and alph is None:
            alph = ' 0123456789'
        if ty == 'GeneralStringType':
            data = v.encode('latin-1')
            w.length(len(data)); w.raw(data); return
        if ty == 'BMPStringType':
            b, codes = 16, [ord(c) for c in v]
            maxcode = 0xffff
            chars = codes
        elif alph is not None:
            sa = sorted(set(alph))
            nb = (len(sa) - 1).bit_length() or 1
            b = 1
            while b < nb:
                b *= 2
            if ord(sa[-1]) < (1 << b):
                chars = [ord(c) for c in v]
            else:
                chars = [sa.index(c) for c in v]
        else:
            b = 8
            chars = [ord(c) for c in v]
        n = len(v)
        lo = hi = None
        if s:
            lo, hi, ext = s
            if ext:
                w.flag(not (lo <= n <= (hi if hi is not None else n)))
        if s is None or hi is None:
            w.length(n)
            aligned = True
        elif lo == hi:
            aligned = hi > 2        # packet-per.c aligns every known-multiplier string but SIZE(0..2) (X.691 only if bits > 16)
        else:
            w.cint(n, lo, hi)
            aligned = hi >= 2       # same rule as dissect_per_restricted_character_string_sorted()
        if ty == 'BMPStringType':
            aligned = True          # dissect_per_BMPString() always aligns after the length
        if aligned:
            w.align()
        for c in chars:
            w.put(c, b)

def oid_bytes(arcs):
    out = bytearray()
    first = arcs[0] * 40 + arcs[1]
    for a in [first] + list(arcs[2:]):
        enc = [a & 0x7f]
        a >>= 7
        while a:
            enc.append(0x80 | (a & 0x7f)); a >>= 7
        out += bytes(reversed(enc))
    return bytes(out)

# ---------------------------------------------------------- generator ---
class Gen:
    """Random values.  `covered` collects (type, what) pairs; skip/override
    handle fields whose content other dissectors parse."""
    def __init__(self, schema, rng, covered=None, overrides=None, skip=()):
        self.s = schema
        self.rng = rng
        self.covered = covered if covered is not None else set()
        self.new = set()
        self.overrides = overrides or {}
        self.skip = set(skip)
        self.p_opt = 0.5
        self.p_ext = 0.5

    def mark(self, key):
        if key not in self.covered:
            self.new.add(key)

    def gen(self, t, depth, path=''):
        s = self.s
        name = t.name
        key = path + '/' + (name or '?')
        for pat, fn in self.overrides.items():
            if key.endswith(pat):
                return fn(self, t, depth)
        base, constr = s.resolve(t)
        ty = base.type
        r = self.rng
        if base.name:
            self.mark(('visit', base.name))
        if ty == 'BooleanType':
            v = r.random() < 0.5
            return v
        if ty == 'NullType':
            return None
        if ty == 'IntegerType':
            rg = s.range_of(constr)
            if rg is None:
                return r.randint(0, 1000)
            lo, hi, ext = rg
            if lo is None: lo = (hi - 1000) if hi is not None else 0
            if hi is None: hi = lo + 100000
            c = r.random()
            if c < 0.2: return lo
            if c < 0.4: return hi
            return r.randint(lo, min(hi, lo + 70000)) if hi - lo > 70000 else r.randint(lo, hi)
        if ty == 'EnumeratedType':
            names = [x.ident for x in base.val]
            ext = [x.ident for x in getattr(base, 'ext', []) or []]
            allv = names + ext
            return r.choice(allv)
        if ty == 'ChoiceType':
            return self.gen_choice(base, depth, base.name or name or '')
        if ty == 'SequenceType':
            return self.gen_seq(base, depth, base.name or name or '')
        if ty in ('SequenceOfType', 'SetOfType'):
            sz = s.size_of(constr)
            lo, hi = 0, 3
            if sz:
                lo = sz[0] or 0
                hi = sz[1] if sz[1] is not None else lo + 3
            n = r.randint(lo, min(hi, lo + 2))
            eb, _ec = s.resolve(base.val)
            if eb is not None and eb.name == 'Extension' and 'h450/' in str(getattr(eb, '_mod', '')):
                return [('__ext__', [1, 3, 6, 1, 4, 1, r.randint(1, 5000), r.randint(1, 9)],
                         bytes(r.randrange(256) for _ in range(r.randint(0, 6)))) for _ in range(r.randint(1, 2))]
            if (depth <= 0 or s.tdepth(base.val) >= 10 ** 5) and lo == 0:
                n = 0
            return [self.gen(base.val, depth - 1, path + '/' + (name or '')) for _ in range(n)]
        if ty == 'OctetStringType':
            sz = s.size_of(constr)
            lo, hi = (sz[0], sz[1]) if sz else (0, 8)
            if hi is None: hi = lo + 8
            n = r.randint(lo, min(hi, lo + 8))
            return bytes(r.randrange(256) for _ in range(n))
        if ty == 'BitStringType':
            sz = s.size_of(constr)
            lo, hi = (sz[0], sz[1]) if sz else (0, 16)
            if hi is None: hi = lo + 16
            n = r.randint(lo, min(hi, lo + 16))
            data = bytes(r.randrange(256) for _ in range((n + 7) // 8))
            if n % 8:
                data = data[:-1] + bytes([data[-1] & (0xff << (8 - n % 8)) & 0xff])
            return (data, n)
        if ty in ('IA5StringType', 'PrintableStringType', 'NumericStringType', 'VisibleStringType',
                  'BMPStringType', 'GeneralStringType', 'GeneralizedTime', 'UTCTime'):
            sz = s.size_of(constr)
            lo, hi = (sz[0], sz[1]) if sz else (0, 10)
            if hi is None: hi = lo + 10
            n = r.randint(lo, min(hi, lo + 10))
            alph = s.alphabet_of(constr)
            if alph is None and ty in ('GeneralizedTime', 'UTCTime'):
                alph = '0123456789'
            if alph is None:
                alph = ' 0123456789' if ty == 'NumericStringType' else 'abcdefghijklmnopqrstuvwxyz0123456789.-'
            return ''.join(r.choice(alph) for _ in range(n))
        if ty == 'ObjectIdentifierType':
            return [1, 3, 6, 1, 4, 1, r.randint(1, 5000), r.randint(1, 20)]
        if ty in ('OpenType', 'AnyType'):
            return b'\x00'
        raise NotImplementedError(ty)

    def unvisited(self, t):
        b, _ = self.s.resolve(t)
        return b is not None and bool(b.name) and ('visit', b.name) not in self.covered \
            and ('visit', b.name) not in self.new

    def gen_choice(self, t, depth, path):
        r = self.rng
        root = list(t.elt_list)
        ext = list(getattr(t, 'ext_list', []) or [])
        cands = [(a, False) for a in root] + ([(a, True) for a in ext] if r.random() < self.p_ext else [])
        ok = [(a, e) for a, e in cands if self.s.tdepth(a) <= max(depth, 0) + 1 and a.name not in self.skip
              and a.type not in ('OpenType', 'AnyType')]
        if not ok:
            best = min(self.s.tdepth(a) for a in root)
            ok = [(a, False) for a in root if self.s.tdepth(a) == best]
        # prefer alternatives that are new
        fresh = [(a, e) for a, e in ok if (path, a.name) not in self.covered or self.unvisited(a)]
        a, e = r.choice(fresh if fresh and r.random() < 0.8 else ok)
        self.mark((path, a.name))
        return (a.name, self.gen(a, depth - 1, path))

    def gen_seq(self, t, depth, path):
        r = self.rng
        root, ext, isext = self.s.seq_parts(t)
        v = {}
        for e in root:
            n = self.s.elt_name(e)
            opt = getattr(e, 'optional', 0) or getattr(e, 'default', None) is not None
            ft = e.val
            if n in self.skip and opt:
                continue
            if opt:
                fresh = (path, n) not in self.covered or self.unvisited(ft)
                can = self.s.tdepth(ft) <= depth + 1 and ft.type not in ('OpenType', 'AnyType')
                if not can or (r.random() > (0.9 if fresh else self.p_opt)):
                    continue
                self.mark((path, n))
            v[n] = self.gen(ft, depth - 1, path)
        if isext and ext and r.random() < self.p_ext:
            for e in ext:
                n = self.s.elt_name(e)
                opt = getattr(e, 'optional', 0)
                ft = e.val
                if n in self.skip and opt:
                    continue
                can = self.s.tdepth(ft) <= depth + 1 and ft.type not in ('OpenType', 'AnyType')
                if opt and (not can or r.random() > 0.5):
                    continue
                if not opt and not can:
                    return {k: x for k, x in v.items()}  # cannot satisfy: no extensions
                self.mark((path, n))
                v[n] = self.gen(ft, depth - 1, path)
        return v
