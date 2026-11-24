# Helper module for the gsm_map capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""A small ASN.1 module parser and BER value generator, enough for the GSM
MAP modules in epan/dissectors/asn1/gsm_map.  It builds BER encodings of
made-up values (not random: the choices rotate with a variant number) for
any type, and extracts the OPERATION and ERROR definitions."""
import re
import os
import struct
import zlib

TOK = re.compile(r'''::=|'[0-9A-Fa-f ]*'[BH]|\.\.\.|\.\.|\[\[|\]\]|"[^"]*"|&?[A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*|-?\d+|[{}()\[\],|<>;:@.&!^*=]''')

def tokenize(text):
    out = []
    for line in text.split('\n'):
        # comments: -- ... -- or -- to end of line
        line = re.sub(r'--.*?--', ' ', line)
        line = re.sub(r'--.*$', ' ', line)
        out.extend(TOK.findall(line))
    return out

UNIV = {'BOOLEAN': 1, 'INTEGER': 2, 'BITSTRING': 3, 'OCTETSTRING': 4, 'NULL': 5, 'OID': 6,
        'ENUMERATED': 10, 'SEQUENCE': 16, 'SET': 17, 'NumericString': 18, 'PrintableString': 19,
        'TeletexString': 20, 'IA5String': 22, 'UTCTime': 23, 'GeneralizedTime': 24,
        'VisibleString': 26, 'GraphicString': 25, 'GeneralString': 27, 'UTF8String': 12,
        'BMPString': 30, 'REAL': 9}
CHARSTR = ('NumericString', 'PrintableString', 'TeletexString', 'IA5String', 'VisibleString',
           'GeneralString', 'GraphicString', 'UTF8String', 'BMPString', 'UTCTime', 'GeneralizedTime')

class Module:
    def __init__(self, name, tagging):
        self.name, self.tagging = name, tagging
        self.types = {}
        self.imports = {}
        self.ops = {}      # name -> tokens inside braces
        self.errors = {}
        self.values = {}   # integer values

class Parser:
    def __init__(self, toks, mod):
        self.t, self.i, self.m = toks, 0, mod
    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else None
    def next(self):
        v = self.t[self.i]; self.i += 1; return v
    def accept(self, v):
        if self.peek() == v:
            self.i += 1; return True
        return False
    def expect(self, v):
        if self.next() != v:
            raise SyntaxError('expected %s near %s' % (v, self.t[max(0, self.i - 6):self.i + 4]))
    def skip_balanced(self, open_, close):
        depth = 0
        while True:
            x = self.next()
            if x == open_: depth += 1
            elif x == close:
                depth -= 1
                if depth == 0: return
    def parse_constraint(self):
        """( ... ) -> dict with size / range if recognisable"""
        res = {}
        start = self.i
        self.skip_balanced('(', ')')
        toks = self.t[start:self.i]
        s = ' '.join(toks)
        m = re.search(r'SIZE \( (-?\w+) (?:\.\. (-?\w+|MAX) )?\)', s)
        if m:
            lo = self.num(m.group(1)); hi = self.num(m.group(2)) if m.group(2) else lo
            res['size'] = (lo, hi)
        else:
            m = re.match(r'\( (-?\w+) \.\. (-?\w+|MAX) \)$', s)
            if m:
                res['range'] = (self.num(m.group(1)), self.num(m.group(2)))
            elif re.match(r'\( (-?\d+) \)$', s):
                v = int(toks[1]); res['range'] = (v, v)
        return res
    def num(self, x):
        if x is None: return None
        if re.match(r'-?\d+$', x): return int(x)
        if x == 'MAX': return None
        if x == 'MIN': return 0
        return self.m.values.get(x, 0)
    def parse_tag(self):
        self.expect('[')
        cls = 2
        if self.peek() in ('APPLICATION', 'PRIVATE', 'UNIVERSAL'):
            cls = {'UNIVERSAL': 0, 'APPLICATION': 1, 'PRIVATE': 3}[self.next()]
        n = int(self.next())
        self.expect(']')
        mode = None
        if self.peek() in ('IMPLICIT', 'EXPLICIT'):
            mode = self.next()
        return (cls, n, mode)
    def parse_type(self):
        tag = None
        if self.peek() == '[':
            tag = self.parse_tag()
        t = self.parse_base()
        if tag:
            cls, n, mode = tag
            if mode is None:
                mode = 'IMPLICIT' if self.m.tagging == 'IMPLICIT' else 'EXPLICIT'
            if t.get('tag'):       # tag on a tagged ref: keep outermost, remember
                t = {'k': 'wrap', 'inner': t}
            t['tag'] = (cls, n, mode)
        return t
    def parse_base(self):
        x = self.next()
        t = {'k': None, 'tag': None}
        if x == 'BOOLEAN': t['k'] = 'bool'
        elif x == 'NULL': t['k'] = 'null'
        elif x == 'INTEGER':
            t['k'] = 'int'; t['named'] = []
            if self.peek() == '{': t['named'] = self.parse_named()
            while self.peek() == '(':
                t.update(self.parse_constraint())
        elif x == 'ENUMERATED':
            t['k'] = 'enum'; t['named'] = self.parse_named()
        elif x == 'BIT':
            self.expect('STRING'); t['k'] = 'bits'; t['named'] = []
            if self.peek() == '{': t['named'] = self.parse_named()
            while self.peek() == '(': t.update(self.parse_constraint())
        elif x == 'OCTET':
            self.expect('STRING'); t['k'] = 'octets'
            while self.peek() == '(': t.update(self.parse_constraint())
        elif x == 'OBJECT':
            self.expect('IDENTIFIER'); t['k'] = 'oid'
        elif x == 'ANY':
            t['k'] = 'any'
            if self.peek() == 'DEFINED':
                self.next(); self.expect('BY'); self.next()
        elif x in CHARSTR:
            t['k'] = 'str'; t['name'] = x
            while self.peek() == '(': t.update(self.parse_constraint())
        elif x in ('SEQUENCE', 'SET'):
            size = {}
            if self.peek() == '(':
                size = self.parse_constraint()
            elif self.peek() == 'SIZE':
                # SIZE (..) without outer parens
                self.i += 0
                save = self.i
                self.next()
                size = self.parse_constraint()
                size = {'size': size.get('range') or size.get('size')} if size else {}
            if self.peek() == 'OF':
                self.next()
                # optional "name" before the type (rare)
                el = self.parse_type()
                t['k'] = 'seqof' if x == 'SEQUENCE' else 'setof'
                t['elem'] = el; t.update(size)
            else:
                t['k'] = 'seq' if x == 'SEQUENCE' else 'set'
                t['comps'] = self.parse_comps()
        elif x == 'CHOICE':
            t['k'] = 'choice'; t['comps'] = self.parse_comps()
        elif x == 'CLASS':
            raise SyntaxError('class')
        else:
            # type reference, maybe Module.Type or Class.&field
            if self.peek() == '.' and self.peek(1) and self.peek(1).startswith('&'):
                self.next(); f = self.next()
                t['k'] = 'oid' if f.endswith('Id') or 'Identifier' in f or f == '&extensionId' else 'any'
                # constraint ({Set}{@x})
                while self.peek() == '(':
                    self.skip_balanced('(', ')')
                return t
            if self.peek() == '.' and self.peek(1) and re.match(r'[A-Z]', self.peek(1)):
                self.next(); x = self.next()
            t['k'] = 'ref'; t['name'] = x
            while self.peek() == '(':
                c = self.parse_constraint()
                t.update(c)
        return t
    def parse_named(self):
        self.expect('{')
        out = []
        val = 0
        while True:
            x = self.next()
            if x == '}': break
            if x == ',': continue
            if x == '...': continue
            # name ( number )
            if self.peek() == '(':
                self.next(); v = self.next()
                if re.match(r'-?\d+$', v): val = int(v)
                else: val = self.m.values.get(v, val)
                self.expect(')')
                out.append((x, val))
            else:
                out.append((x, val))
            val += 1
        return out
    def parse_comps(self):
        self.expect('{')
        comps = []
        while True:
            x = self.peek()
            if x == '}':
                self.next(); break
            if x == ',':
                self.next(); continue
            if x == '...':
                self.next()
                if self.peek() == '!':
                    self.next()
                    while self.peek() not in (',', '}'): self.next()
                continue
            if x in ('[[', ']]'):
                self.next(); continue
            if x == 'COMPONENTS':
                self.next(); self.expect('OF')
                ref = self.parse_type()
                comps.append((None, {'k': 'componentsof', 'ref': ref}, False))
                continue
            name = self.next()
            ty = self.parse_type()
            opt = False
            if self.peek() == 'OPTIONAL':
                self.next(); opt = True
            elif self.peek() == 'DEFAULT':
                self.next(); opt = True
                if self.peek() == '{':
                    self.skip_balanced('{', '}')
                else:
                    self.next()
            comps.append((name, ty, opt))
        return comps

def parse_module(text):
    toks = tokenize(text)
    # header
    i = 0
    while toks[i] != 'DEFINITIONS': i += 1
    j = i + 1
    tagging = 'EXPLICIT'
    while toks[j] != '::=':
        if toks[j] in ('IMPLICIT', 'EXPLICIT', 'AUTOMATIC'): tagging = toks[j]
        j += 1
    name = toks[0]
    mod = Module(name, tagging)
    k = j + 1
    assert toks[k] == 'BEGIN'
    k += 1
    # exports / imports
    if toks[k] == 'EXPORTS':
        while toks[k] != ';': k += 1
        k += 1
    if k < len(toks) and toks[k] == 'IMPORTS':
        k += 1
        syms = []
        while toks[k] != ';':
            if toks[k] == 'FROM':
                modname = toks[k + 1]; k += 2
                if toks[k] == '{':
                    d = 0
                    while True:
                        if toks[k] == '{': d += 1
                        if toks[k] == '}':
                            d -= 1
                            if d == 0: k += 1; break
                        k += 1
                for s in syms: mod.imports[s] = modname
                syms = []
            elif toks[k] == ',':
                k += 1
            else:
                syms.append(toks[k]); k += 1
        k += 1
    body = toks[k:]
    # drop the trailing END
    while body and body[-1] == 'END': body.pop()
    # first pass: integer values
    for a in range(len(body) - 4):
        if body[a + 1] == 'INTEGER' and body[a + 2] == '::=' and re.match(r'-?\d+$', body[a + 3]):
            mod.values[body[a]] = int(body[a + 3])
    p = Parser(body, mod)
    while p.i < len(body):
        x = p.peek()
        if p.peek(1) == '::=':
            name = p.next(); p.next()
            if p.peek() == 'CLASS':
                p.next(); p.skip_balanced('{', '}')
                continue
            try:
                mod.types[name] = p.parse_type()
            except SyntaxError:
                raise
            # information object set "X MAP-EXTENSION ::= {...}" handled below
            continue
        # value / object assignment: name Type ::= value
        name = p.next()
        typ = p.next()
        if p.peek() == '::=' or typ in ('OPERATION', 'ERROR', 'OBJECT', 'INTEGER') or True:
            # find ::=
            while p.peek() != '::=':
                p.next()
            p.next()
            if p.peek() == '{':
                start = p.i
                p.skip_balanced('{', '}')
                if typ == 'OPERATION': mod.ops[name] = body[start + 1:p.i - 1]
                elif typ == 'ERROR': mod.errors[name] = body[start + 1:p.i - 1]
            else:
                p.next()
                # e.g. local:2 style values with 3 tokens
                while p.peek() == ':':
                    p.next(); p.next()
    return mod

def load_all(asn_dir, files):
    mods = {}
    for f in files:
        with open(os.path.join(asn_dir, f)) as fh:
            try:
                m = parse_module(fh.read())
            except Exception as e:
                raise RuntimeError('%s: %r' % (f, e))
        mods[m.name] = m
        m.file = f
    return mods

# ------------------------------------------------------------------------
def tlv_raw(cls, constructed, num, content):
    first = (cls << 6) | (0x20 if constructed else 0)
    if num < 31:
        ident = bytes([first | num])
    else:
        parts = []
        n = num
        parts.append(n & 0x7f); n >>= 7
        while n:
            parts.append(0x80 | (n & 0x7f)); n >>= 7
        ident = bytes([first | 31]) + bytes(reversed(parts))
    l = len(content)
    if l < 0x80: lb = bytes([l])
    elif l < 0x100: lb = bytes([0x81, l])
    else: lb = bytes([0x82, l >> 8, l & 0xff])
    return ident + lb + content

class Gen:
    """Generate BER for a type.  variant picks CHOICE arms, ENUM and INTEGER
    values; popt is the chance an OPTIONAL component is present."""
    def __init__(self, mods, overrides=None):
        self.mods = mods
        self.glob = {}
        for m in mods.values():
            for n, t in m.types.items():
                self.glob.setdefault(n, []).append((m, t))
        self.overrides = overrides or {}
        self.variant = 0
        self.popt = 1.0
        self.seed = 0
        self.counter = 0
        self.ext_enabled = False
        self.ext_n = 0

    def resolve(self, mod, name):
        if name in mod.types: return mod, mod.types[name]
        if name in mod.imports and mod.imports[name] in self.mods:
            return self.resolve(self.mods[mod.imports[name]], name)
        if name in self.glob:
            return self.glob[name][0]
        raise KeyError(name)

    def h(self, *a):
        return zlib.crc32(repr(a).encode()) & 0x7fffffff

    def want(self, path, optional):
        if not optional: return True
        if self.popt >= 1.0: return True
        if self.popt <= 0.0: return False
        return (self.h(self.seed, path) % 1000) / 1000.0 < self.popt

    # parts = (cls, constructed, num, content, is_choice)
    def enc(self, t, mod, path, depth=0, tname=None):
        k = t['k']
        if k == 'wrap':
            inner = self.enc(t['inner'], mod, path, depth, tname)
            return self.apply_tag(inner, t['tag'])
        if k == 'ref':
            m2, t2 = self.resolve(mod, t['name'])
            ov = self.overrides.get(t['name'])
            if ov:
                parts = ov(self, t2, path)
                if parts is not None:
                    parts = parts
                    return self.apply_tag(parts, t.get('tag')) if t.get('tag') else parts
            parts = self.enc(t2, m2, path + '/' + t['name'], depth + 1, (t['name'],) + (tname or ()))
            if t.get('tag'): parts = self.apply_tag(parts, t['tag'])
            return parts
        if depth > 40:
            return self.leaf_min(t)
        parts = self.enc_base(t, mod, path, depth, tname)
        if t.get('tag'): parts = self.apply_tag(parts, t['tag'])
        return parts

    def leaf_min(self, t):
        return (0, False, 5, b'', False)

    def apply_tag(self, parts, tag):
        cls, num, mode = tag
        if mode == 'EXPLICIT' or parts[4]:
            return (cls, True, num, tlv_raw(parts[0], parts[1], parts[2], parts[3]), False)
        return (cls, parts[1], num, parts[3], False)

    def pick(self, path, n):
        return (self.h(self.variant, path) + self.variant) % n if n else 0

    def enc_base(self, t, mod, path, depth, tname):
        k = t['k']
        if k == 'bool':
            return (0, False, 1, b'\xff' if (self.variant + self.h(path)) % 2 == 0 else b'\x00', False)
        if k == 'null':
            return (0, False, 5, b'', False)
        if k == 'int':
            v = self.int_value(t, path)
            return (0, False, 2, self.int_bytes(v), False)
        if k == 'enum':
            vals = [v for _, v in t['named']] or [0]
            return (0, False, 10, self.int_bytes(vals[self.pick(path, len(vals))]), False)
        if k == 'octets':
            return (0, False, 4, self.octets(t, path, tname), False)
        if k == 'bits':
            return (0, False, 3, self.bits(t, path), False)
        if k == 'oid':
            return (0, False, 6, bytes.fromhex('2a0304') if self.variant % 2 == 0 else bytes.fromhex('04000001000101' '03'), False)
        if k == 'any':
            return (0, True, 16, b'', False)
        if k == 'str':
            lo = t.get('size', (1, 1))[0] or 1
            return (0, False, UNIV[t['name']], (b'a1' * 10)[:max(lo, 2)], False)
        if k in ('seq', 'set'):
            content = b''
            comps = self.flat(t['comps'], mod)
            for name, ct, opt in comps:
                if not self.want(path + '/' + str(name), opt): continue
                if name == 'extType' or name == 'extId' or ct.get('skip'): continue
                if ct['k'] == 'ref' and ct['name'] in ('ExtensionContainer', 'SLR-ArgExtensionContainer', 'PCS-Extensions') and opt:
                    if not self.ext_present(path): continue
                parts = self.enc(ct, mod, path + '/' + str(name), depth + 1)
                content += tlv_raw(*parts[:4])
            return (0, True, 16 if k == 'seq' else 17, content, False)
        if k in ('seqof', 'setof'):
            lo, hi = t.get('size', (1, 2)) if t.get('size') else (1, 2)
            lo = lo or 0
            n = max(lo, 1) if depth < 9 else lo
            if self.variant % 3 == 1 and (hi is None or hi >= 2) and depth < 8:
                n = max(n, 2)
            content = b''
            for i in range(n):
                parts = self.enc(t['elem'], mod, path + '/[%d]' % i, depth + 1)
                content += tlv_raw(*parts[:4])
            return (0, True, 16 if k == 'seqof' else 17, content, False)
        if k == 'choice':
            comps = self.flat(t['comps'], mod)
            comps = [c for c in comps if c[0] is not None]
            if depth > 8:
                idx = 0
            else:
                idx = self.pick(path, len(comps))
            for tries in range(len(comps)):
                name, ct, _ = comps[(idx + tries) % len(comps)]
                try:
                    parts = self.enc(ct, mod, path + '/' + name, depth + 1)
                except KeyError:
                    continue
                return (parts[0], parts[1], parts[2], parts[3], True)
            return (0, False, 5, b'', True)
        raise ValueError(k)

    def ext_present(self, path):
        if not self.ext_enabled: return False
        self.ext_n += 1
        return self.ext_n % 3 == 1

    def flat(self, comps, mod):
        out = []
        for name, ct, opt in comps:
            if ct['k'] == 'componentsof':
                m2, t2 = self.resolve(mod, ct['ref']['name'])
                out.extend(self.flat(t2['comps'], m2))
            else:
                out.append((name, ct, opt))
        return out

    def int_bytes(self, v):
        if v >= 0:
            n = max(1, (v.bit_length() + 8) // 8)
        else:
            n = max(1, ((-v - 1).bit_length() + 8) // 8)
        return v.to_bytes(n, 'big', signed=True)

    def int_value(self, t, path):
        if t.get('named'):
            vals = [v for _, v in t['named']]
            return vals[self.pick(path, len(vals))]
        r = t.get('range')
        if r:
            lo, hi = r
            if hi is None: hi = lo + 1000
            if hi < lo: hi = lo
            choices = [lo, hi, (lo + hi) // 2, min(hi, lo + 1)]
            return choices[self.pick(path, 4)]
        return [0, 1, 2, 127, 128, 255, 1000, 65536][self.pick(path, 8)]

    def octets(self, t, path, tname):
        sz = t.get('size')
        if sz:
            lo, hi = sz
            if hi is None: hi = lo + 8
            hi = min(hi, lo + 12 if lo < 200 else lo)
            n = [lo, hi, (lo + hi) // 2][self.pick(path, 3)]
        else:
            n = [0, 1, 4, 9][self.pick(path, 4)]
        for nm in (tname or ()):
            ov = self.overrides.get('OCT:' + nm)
            if ov:
                b = ov(self, n, path)
                if b is not None: return b
                break
        return bytes(((i * 7 + self.h(path)) & 0x7f) | 0x10 for i in range(n)) if n else b''

    def bits(self, t, path):
        sz = t.get('size')
        named = t.get('named')
        if sz:
            lo, hi = sz
            nbits = lo if hi is None else [lo, hi][self.pick(path, 2)]
        elif named:
            nbits = max(v for _, v in named) + 1
        else:
            nbits = 8
        nb = (nbits + 7) // 8
        unused = nb * 8 - nbits
        data = bytearray(nb)
        if named:
            for _, v in named:
                if v < nbits and (v + self.variant + self.h(path)) % 2 == 0:
                    data[v // 8] |= 0x80 >> (v % 8)
        else:
            data = bytearray(((0xa5 ^ (i * 0x33)) & 0xff) for i in range(nb))
        if nb:
            data[-1] &= (0xff << unused) & 0xff
        return bytes([unused]) + bytes(data)

def get_ops(mods, mod_filter=None):
    """name -> dict(code, arg, res, errors, mod)"""
    ops = {}
    for m in mods.values():
        for n, toks in m.ops.items():
            d = {'name': n, 'mod': m, 'arg': None, 'res': None, 'errors': [], 'code': None}
            i = 0
            while i < len(toks):
                x = toks[i]
                if x == 'ARGUMENT':
                    i += 1
                    # optional "name Type" or Type, possibly with tag
                    d['arg'] = toks[i]
                    if toks[i] == '[':
                        d['arg'] = None
                elif x == 'RESULT':
                    i += 1
                    d['res'] = toks[i] if toks[i] not in ('ERRORS', 'CODE', 'LINKED', 'RETURN') else None
                elif x == 'ERRORS':
                    i += 1
                    depth = 0
                    while True:
                        if toks[i] == '{': depth += 1
                        elif toks[i] == '}':
                            depth -= 1
                            if depth == 0: break
                        elif toks[i] not in ('|', ','):
                            d['errors'].append(toks[i])
                        i += 1
                elif x == 'CODE':
                    j = i + 1
                    if toks[j] == 'local' and toks[j + 1] == ':':
                        d['code'] = int(toks[j + 2]) if re.match(r'\d+$', toks[j + 2]) else m.values.get(toks[j + 2])
                i += 1
            ops[n] = d
    return ops

def get_errors(mods):
    errs = {}
    for m in mods.values():
        for n, toks in m.errors.items():
            d = {'name': n, 'param': None, 'code': None, 'mod': m}
            i = 0
            while i < len(toks):
                if toks[i] == 'PARAMETER':
                    d['param'] = toks[i + 1]
                if toks[i] == 'CODE' and toks[i + 1] == 'local':
                    v = toks[i + 3]
                    d['code'] = int(v) if re.match(r'\d+$', v) else m.values.get(v)
                i += 1
            errs[n] = d
    return errs
