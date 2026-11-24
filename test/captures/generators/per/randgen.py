#!/usr/bin/env python3
# Helper module for the per capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Random value generator for asn1tools specifications (synthetic data).
Walks the parsed ASN.1 and builds Python values that asn1tools can encode.
CHOICE alternatives, optional members and extension additions are cycled
pseudo randomly so that many different PDUs come out of a few seeds."""
import random
import asn1tools


class Gen:
    def __init__(self, files, codec, seed=1):
        self.parsed = asn1tools.parse_files(files)
        self.spec = asn1tools.compile_files(files, codec)
        self.rng = random.Random(seed)
        self.types = {}
        self.vals = {}
        for mn, m in self.parsed.items():
            for tn, t in m['types'].items():
                self.types.setdefault(tn, (mn, t))
            for vn, v in m.get('values', {}).items():
                self.vals[vn] = v
        self.depth = 0
        self.maxdepth = 6

    def resolve(self, t):
        seen = 0
        while t['type'] in self.types and seen < 20:
            base = self.types[t['type']][1]
            nt = dict(base)
            for k in ('restricted-to', 'size', 'from'):
                if k in t:
                    nt[k] = t[k]
            t = nt
            seen += 1
        return t

    def num(self, x, default):
        if isinstance(x, int):
            return x
        if isinstance(x, str):
            if x == 'MIN' or x == 'MAX':
                return default
            v = self.vals.get(x)
            if isinstance(v, dict):
                v = v.get('value')
            if isinstance(v, int):
                return v
        return default

    def ranges(self, t, key='restricted-to'):
        r = t.get(key)
        out = []
        if not r:
            return out
        for x in r:
            if x is None or x == '...':
                continue
            if isinstance(x, tuple):
                out.append((x[0], x[1]))
            else:
                out.append((x, x))
        return out

    def integer(self, t):
        rs = self.ranges(t)
        if not rs:
            return self.rng.choice([0, 1, 5, 127, 128, 255, 256, 1000, 65535, 65536, 70000,
                                    -1, -128, -129, 100000, 1 << 24, (1 << 32) - 1, 1 << 32,
                                    1 << 33, 1 << 40, 1 << 48, (1 << 63) - 1, 1 << 63,
                                    (1 << 64) - 1, -(1 << 31), -(1 << 40)])
        lo, hi = rs[self.rng.randrange(len(rs))]
        lo = self.num(lo, -(1 << 31))
        hi = self.num(hi, (1 << 32) if lo >= 0 else (1 << 31))
        if hi < lo:
            hi = lo
        c = self.rng.random()
        if c < 0.25:
            return lo
        if c < 0.5:
            return hi
        if hi - lo > 1 << 62:
            return lo + self.rng.randrange(1 << 62)
        return self.rng.randint(lo, hi)

    def sizerange(self, t, dlo=0, dhi=6):
        rs = self.ranges(t, 'size')
        if not rs:
            return dlo, dhi
        lo, hi = rs[self.rng.randrange(len(rs))]
        lo = self.num(lo, 0)
        hi = self.num(hi, max(lo, dhi))
        return lo, min(hi, max(lo, dhi) if hi - lo > 64 else hi)

    def count(self, t, dlo=1, dhi=3):
        lo, hi = self.sizerange(t, dlo, dhi)
        if hi - lo > 8:
            hi = lo + 8
        c = self.rng.random()
        if c < 0.3:
            return lo
        if c < 0.5:
            return min(hi, lo + 1)
        return self.rng.randint(lo, max(lo, hi))

    def string(self, t, alphabet):
        a = t.get('from')
        if a:
            chars = []
            for x in a:
                if isinstance(x, tuple):
                    chars += [chr(c) for c in range(ord(x[0]), ord(x[1]) + 1)] if isinstance(x[0], str) else []
                elif isinstance(x, str):
                    chars.append(x)
            if chars:
                alphabet = ''.join(chars)
        n = self.count(t, 0, 12)
        return ''.join(self.rng.choice(alphabet) for _ in range(n))

    def value(self, t, top=False):
        t = self.resolve(t)
        ty = t['type']
        r = self.rng
        if ty == 'BOOLEAN':
            return r.random() < 0.5
        if ty == 'INTEGER':
            return self.integer(t)
        if ty == 'NULL':
            return None
        if ty == 'ENUMERATED':
            names = [m[0] if isinstance(m, tuple) else m for m in t['values'] if m is not None]
            return r.choice(names)
        if ty == 'BIT STRING':
            n = self.count(t, 1, 40) if t.get('size') else r.choice([0, 1, 7, 8, 9, 16, 24, 33, 64, 100])
            if t.get('named-bits') and not t.get('size'):
                n = r.choice([1, 3, 8, 9, 13])
            return (bytes(r.randrange(256) for _ in range((n + 7) // 8)), n)
        if ty == 'OCTET STRING':
            n = self.count(t, 0, 20)
            return bytes(r.randrange(256) for _ in range(n))
        if ty == 'OBJECT IDENTIFIER':
            return r.choice(['1.2.840.113549.1.1.11', '0.0.8.245.0.8', '2.5.4.3', '1.3.6.1.4.1.311.2.1.4',
                             '2.999.1.2.3', '1.3.14.3.2.26'])
        if ty in ('IA5String', 'PrintableString', 'VisibleString', 'ISO646String', 'GeneralString'):
            return self.string(t, 'abcXYZ019 .-')
        if ty == 'NumericString':
            return self.string(t, '0123456789 ')
        if ty == 'BMPString':
            return self.string(t, 'abcä€Ж')
        if ty == 'UTF8String':
            return self.string(t, 'abcä€Ж')
        if ty == 'UniversalString':
            return self.string(t, 'abcä€')
        if ty == 'UTCTime':
            return r.choice(['990101120000Z', '2601021530+0100'])
        if ty == 'GeneralizedTime':
            return '20260102153000Z'
        if ty == 'REAL':
            return r.choice([0.0, 1.5, -2.25, 1e10, 3.0e-5, 100.0])
        if ty in ('SEQUENCE', 'SET'):
            self.depth += 1
            out = {}
            ext = False
            for m in t['members']:
                if m is None:
                    ext = True
                    continue
                if m['type'] == 'COMPONENTS OF':
                    continue
                prob = 0.5 if (m.get('optional') or 'default' in m) else 1.0
                if ext:
                    prob = 0.5
                if self.depth > self.maxdepth and (m.get('optional') or ext or 'default' in m):
                    prob = 0.0
                if r.random() < prob:
                    out[m['name']] = self.value(m)
            self.depth -= 1
            return out
        if ty == 'CHOICE':
            alts = [m for m in t['members'] if m is not None]
            if self.depth > self.maxdepth:
                alts = [m for m in alts if self.resolve(m)['type'] in ('NULL', 'BOOLEAN', 'INTEGER', 'ENUMERATED')] or alts
            m = r.choice(alts)
            self.depth += 1
            v = self.value(m)
            self.depth -= 1
            return (m['name'], v)
        if ty in ('SEQUENCE OF', 'SET OF'):
            self.depth += 1
            n = self.count(t, 0, 2) if self.depth <= self.maxdepth else (self.sizerange(t, 0, 1)[0])
            out = [self.value(t['element']) for _ in range(n)]
            self.depth -= 1
            return out
        raise ValueError('unsupported ' + ty)

    def pdu(self, name, tries=50):
        mn, t = self.types[name]
        last = None
        for _ in range(tries):
            self.depth = 0
            try:
                v = self.value(t)
                return v, self.spec.encode(name, v)
            except Exception as e:
                last = e
        raise RuntimeError('%s: %s' % (name, last))
