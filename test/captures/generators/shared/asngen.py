#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Random aligned-PER PDU generator for X2AP/XnAP, driven by the .asn files.

asn1tools cannot handle the information object sets of the 3GPP modules,
so the container types ProtocolIE-Container{{X}} etc. are rewritten to plain
types holding OCTET STRING open types.  The IE tables, the elementary
procedures and the id constants are read from the .asn text with regexes.
The open type contents are encoded recursively with asn1tools.
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import asn1tools
import glob
import re
import random
import struct

ASN_DIR = os.path.join(SRCDIR, 'epan/dissectors/asn1', '')


class Spec:
    def __init__(self, name, prefix):
        self.name = name            # x2ap / xnap
        self.prefix = prefix        # X2AP / XnAP (module prefix)
        d = ASN_DIR + name + '/'
        txt = {}
        for f in sorted(glob.glob(d + '*.asn')):
            t = open(f, encoding='utf-8').read().replace('\xa0', ' ')
            txt[f.rsplit('/',1)[1].split('-',1)[1][:-4]] = t
        self.txt = txt
        self.consts = {}
        for m in re.finditer(r'^\s*([\w-]+)\s+(?:INTEGER|[\w-]+)\s*::=\s*(\d+)\s*$', txt['Constants'] + txt['CommonDataTypes'], re.M):
            self.consts[m.group(1)] = int(m.group(2))
        self.tables = {}     # set name -> [(idname, crit, typeexpr, presence)]
        self.aliases = {}
        self.used = set()    # (kind, params)
        self.pdu_txt = txt['PDU-Contents'] + '\n' + txt['IEs']
        self._parse_tables()
        self._parse_procs()
        self._build()

    def _parse_tables(self):
        pat = re.compile(r'\{\s*ID\s+([\w-]+)\s+(?:FIRST\s+)?CRITICALITY\s+(\w+)\s+(?:FIRST\s+)?(?:TYPE|EXTENSION)\s+(.+?)\s+PRESENCE\s+(\w+)\s*\}')
        for m in re.finditer(r'^([\w-]+)\s+\w+-PROTOCOL-(?:IES|EXTENSION)\s*::=\s*\{(.*?)^\}', self.pdu_txt, re.M | re.S):
            ents = []
            for e in pat.finditer(m.group(2)):
                ents.append((e.group(1), e.group(2), e.group(3).strip(), e.group(4)))
                self.alias_for(e.group(3).strip())
            self.tables[m.group(1)] = ents

    def _parse_procs(self):
        d = self.txt['PDU-Descriptions']
        self.procs = []
        for m in re.finditer(r'^([\w-]+)\s+\w+-ELEMENTARY-PROCEDURE\s*::=\s*\{\s*INITIATING MESSAGE\s+([\w-]+)(?:\s+SUCCESSFUL OUTCOME\s+([\w-]+))?(?:\s+UNSUCCESSFUL OUTCOME\s+([\w-]+))?\s+PROCEDURE CODE\s+([\w-]+)(?:\s+CRITICALITY\s+(\w+))?', d, re.M):
            self.procs.append((m.group(1), m.group(2), m.group(3), m.group(4), self.consts[m.group(5)], m.group(6) or 'ignore'))

    def alias_for(self, texpr):
        if re.fullmatch(r'[\w-]+', texpr):
            return texpr
        if texpr not in self.aliases:
            self.aliases[texpr] = 'GenAlias%d' % len(self.aliases)
        return self.aliases[texpr]

    def _rewrite(self, t):
        def sub(kind):
            def f(m):
                s = m.group(1)
                self.used.add((kind, s))
                return '%s-%s ' % (kind, s)
            return f
        t = re.sub(r'ProtocolIE-Container\s*\{\s*\{\s*([\w-]+)\s*\}\s*\}', sub('PIC'), t)
        t = re.sub(r'ProtocolIE-Single-Container\s*\{\s*\{\s*([\w-]+)\s*\}\s*\}', sub('PISC'), t)
        t = re.sub(r'ProtocolExtensionContainer\s*\{\s*\{\s*([\w-]+)\s*\}\s*\}', sub('PEC'), t)
        t = re.sub(r'PrivateIE-Container\s*\{\s*\{\s*([\w-]+)\s*\}\s*\}', sub('PRIV'), t)
        t = re.sub(r'ProtocolIE-ContainerPair\s*\{\s*\{\s*([\w-]+)\s*\}\s*\}', sub('PICP'), t)
        return t

    def _build(self):
        P = self.prefix
        mods = []
        mods.append(self.txt['CommonDataTypes'])
        mods.append(self.txt['Constants'])
        body = {}
        for k in ('IEs', 'PDU-Contents'):
            body[k] = self._rewrite(self.txt[k])
        # container module
        hdr = re.search(r'^(%s-Containers\s*\{.*?\}\s*DEFINITIONS[^:]*::=)' % P, self.txt['Containers'], re.M | re.S).group(1)
        c = hdr + '\nBEGIN\nIMPORTS maxPrivateIEs, maxProtocolExtensions, maxProtocolIEs, Criticality, Presence, PrivateIE-ID, ProtocolIE-ID FROM %s-CommonDataTypes;\n' % P
        c += 'PIF ::= SEQUENCE { id ProtocolIE-ID, criticality Criticality, value OCTET STRING }\n'
        c += 'PRF ::= SEQUENCE { id PrivateIE-ID, criticality Criticality, value OCTET STRING }\n'
        c += 'PIFP ::= SEQUENCE { id ProtocolIE-ID, firstCriticality Criticality, firstValue OCTET STRING, secondCriticality Criticality, secondValue OCTET STRING }\n'
        for kind, s in sorted(self.used):
            n = '%s-%s' % (kind, s)
            if kind == 'PIC':
                c += '%s ::= SEQUENCE (SIZE (0..maxProtocolIEs)) OF PIF\n' % n
            elif kind == 'PISC':
                c += '%s ::= PIF\n' % n
            elif kind == 'PEC':
                c += '%s ::= SEQUENCE (SIZE (1..maxProtocolExtensions)) OF PIF\n' % n
            elif kind == 'PRIV':
                c += '%s ::= SEQUENCE (SIZE (1..maxPrivateIEs)) OF PRF\n' % n
            elif kind == 'PICP':
                c += '%s ::= SEQUENCE (SIZE (0..maxProtocolIEs)) OF PIFP\n' % n
        for expr, name in sorted(self.aliases.items(), key=lambda x: x[1]):
            c += '%s ::= %s\n' % (name, expr)
        c += 'END\n'
        # make IEs / contents modules import the generated names: they import from
        # Containers by name; our names are not imported, so list them in the IMPORTS
        gen = ', '.join('%s-%s' % (k, s) for k, s in sorted(self.used))
        for k in body:
            body[k] = re.sub(r'FROM\s+%s-Containers' % P, 'FROM %s-Containers' % P, body[k])
            # add imports for generated names to the first IMPORTS clause
            body[k] = re.sub(r'IMPORTS', 'IMPORTS PIF, PRF, PIFP, ' + gen + ' FROM %s-Containers\n' % P, body[k], count=1)
        self.container_txt = c
        allm = [self.txt['CommonDataTypes'], self.txt['Constants'], c, body['IEs'], body['PDU-Contents']]
        # aliases for TYPE expressions that are not plain names (rare)
        self.parsed = asn1tools.parse_string('\n'.join(allm))
        self.types = {}
        for mod in self.parsed.values():
            for tn, td in mod['types'].items():
                self.types[tn] = td
        self.comp = asn1tools.compile_dict(self.parsed, 'per')

    # -- value generation --------------------------------------------------
    def num(self, x):
        if isinstance(x, int):
            return x
        if x in self.consts:
            return self.consts[x]
        if x == 'MIN':
            return -1000
        if x == 'MAX':
            return 1000
        raise KeyError(x)


NOVALUE = object()


class Gen:
    """Random value generator. `rng` is a random.Random; `ext` the probability of
    leaving the root of an extensible constraint / adding extension members."""
    MAXDEPTH = 60

    def __init__(self, spec, rng, ext=0.15, opt=0.6, list_max=3):
        self.s = spec
        self.rng = rng
        self.ext = ext
        self.opt = opt
        self.list_max = list_max
        self.depth = 0
        self.override = {}   # type name -> callable(gen) -> value
        self.force = {}      # type name -> value generator

    def encode(self, tname, val):
        return self.s.comp.encode(tname, val)

    def ie_list(self, setname, force_all=False, drop=()):
        out = []
        for idn, crit, texpr, pres in self.s.tables[setname]:
            if idn in drop:
                continue
            if pres == 'optional' or pres == 'conditional':
                if not force_all and self.rng.random() > self.opt:
                    continue
            tn = self.s.alias_for(texpr)
            self._opt = True
            enc = self.gen_encode(tn)
            if enc is NOVALUE:
                continue
            out.append({'id': self.s.consts[idn], 'criticality': crit, 'value': enc})
        return out

    def gen_encode(self, tn):
        """generate and encode a value of type tn; retries (without extensions after a
        few failures) because asn1tools cannot encode everything."""
        save = self.ext
        last = None
        for attempt in range(12):
            if attempt >= 3:
                self.ext = 0
            try:
                self.depth = 0
                v = self.gen_named(tn)
                if v is NOVALUE:
                    return NOVALUE
                return self.encode(tn, v)
            except Exception as e:      # noqa
                last = e
            finally:
                self.ext = save
        raise last

    _opt = False
    handoff = ()          # keys: type names or 'Parent/member'
    mode = 'build'        # 'probe' or 'build'
    pool = {}             # key -> list of values known to dissect cleanly
    deep = 10             # depth beyond which optional members are left out
    ambig = False
    only = None           # probe: the only handoff key generated
    scen = None
    alpha = bytes(range(256))   # byte values used for octet/bit strings
    used = None           # probe: list of (key, value) generated in this value

    seen = None

    def hook(self, key, v):
        if key not in self.handoff:
            return v
        if self.seen is not None:
            self.seen.add(key)
        if self.mode == 'probe':
            if self.only and key != self.only:
                p = self.pool.get(key + '@' + self.scen if self.scen else key)
                if p:
                    return self.rng.choice(p)
                if self._opt:
                    return NOVALUE
                self.ambig = True
                return v
            if self.used:
                self.ambig = True
                return NOVALUE if self._opt else v
            self.used.append((key, v))
            return v
        p = self.pool.get(key + '@' + self.scen if self.scen else key)
        if p:
            return self.rng.choice(p)
        return NOVALUE if self._opt else v

    def gen_named(self, tn):
        v = self._gen_named(tn)
        if v is NOVALUE:
            return v
        return self.hook(tn, v)

    def _gen_named(self, tn):
        if tn in self.override:
            r = self.override[tn](self)
            if r is not NOVALUE or self._opt:
                return r
        td = self.s.types[tn]
        return self.gen(td, tn)

    def gen(self, td, tn=None):
        if self.depth > self.MAXDEPTH:
            raise RecursionError
        self.depth += 1
        try:
            return self._gen(td, tn)
        finally:
            self.depth -= 1

    def _range(self, rt, default=(0, 1000)):
        """returns (lo, hi, extensible)"""
        lo, hi = default
        ext = False
        if rt:
            for r in rt:
                if r == '...' or r is None:
                    ext = True
                elif isinstance(r, tuple):
                    lo, hi = self.s.num(r[0]) if r[0] != 'MIN' else -(2**31), (self.s.num(r[1]) if r[1] != 'MAX' else 2**31)
                else:
                    lo = hi = self.s.num(r)
        return lo, hi, ext

    def _size(self, td, default=(0, 1000)):
        sz = td.get('size')
        if sz is None:
            return None
        lo, hi, ext = self._range(sz, default)
        return lo, hi, ext

    def pick(self, lo, hi, small=True):
        r = self.rng.random()
        if r < 0.25:
            return lo
        if r < 0.5:
            return hi if hi - lo < 2**40 else lo
        if hi - lo > 100000:
            return lo + self.rng.randint(0, 100000)
        return self.rng.randint(lo, hi)

    def _gen(self, td, tn):
        ty = td['type']
        rng = self.rng
        if ty.startswith('PIC-') or ty.startswith('PICP-'):
            kind, s = ty.split('-', 1)
            if kind == 'PIC':
                return self.ie_list(s)
        if ty.startswith('PISC-'):
            ies = self.ie_list(ty.split('-', 1)[1], force_all=True)
            return ies[0] if ies else {'id': 0, 'criticality': 'reject', 'value': b''}
        if ty.startswith('PEC-'):
            if self.depth > self.deep - 3 or not self.s.tables.get(ty.split('-', 1)[1]):
                return NOVALUE
            ies = self.ie_list(ty.split('-', 1)[1], force_all=False)
            if not ies:
                ies = self.ie_list(ty.split('-', 1)[1], force_all=True)
            return ies
        if ty.startswith('PRIV-'):
            return [{'id': ('local', rng.randint(0, 65535)) if rng.random() < .5 else ('global', '1.2.3.4'),
                     'criticality': 'ignore', 'value': bytes(rng.randrange(256) for _ in range(rng.randint(0, 4)))}]
        if ty in self.s.types and ty not in ('INTEGER', 'BOOLEAN'):
            # reference; size / range overrides of the reference are ignored
            return self.gen_named(ty)
        if ty == 'SEQUENCE':
            v = {}
            ext_seen = False
            for m in td['members']:
                if m is None or m == '...':
                    ext_seen = True
                    continue
                if isinstance(m, list):      # extension addition group
                    continue
                optional = m.get('optional') or 'default' in m
                if ext_seen:
                    if rng.random() > self.ext * 2 or self.depth > self.deep - 2:
                        continue
                elif optional and (rng.random() > self.opt or self.depth > self.deep):
                    continue
                try:
                    self._opt = bool(optional or ext_seen)
                    x = self.gen(m, None)
                    if x is not NOVALUE:
                        if tn and ('%s/%s' % (tn, m['name'])) in self.handoff:
                            x = self.hook('%s/%s' % (tn, m['name']), x)
                        elif ('*/' + m['name']) in self.handoff:
                            x = self.hook('*/' + m['name'], x)
                except RecursionError:
                    if optional or ext_seen:
                        continue
                    raise
                if x is NOVALUE:
                    continue
                v[m['name']] = x
            return v
        if ty == 'SEQUENCE OF':
            lo, hi, ext = self._size(td, (0, 1000)) or (0, 1000, False)
            hi = min(hi, lo + self.list_max)
            n = rng.randint(lo, hi) if lo < hi else lo
            if n == 0 and rng.random() < .7 and hi > 0:
                n = max(lo, 1)
            out = []
            for _ in range(n):
                self._opt = False
                out.append(self.gen(td['element'], None))
            return out
        if ty == 'CHOICE':
            mem = [m for m in td['members'] if m not in (None, '...') and not isinstance(m, list)]
            # root members only, up to extension marker
            root = []
            for m in td['members']:
                if m is None or m == '...':
                    break
                root.append(m)
            allm = mem if rng.random() < self.ext else (root or mem)
            for _ in range(6):
                m = rng.choice(allm)
                try:
                    return (m['name'], self.gen(m, None))
                except RecursionError:
                    if self.depth < 20:
                        raise
            raise RecursionError
        if ty == 'ENUMERATED':
            names = []
            root = True
            for v in td['values']:
                if v is None or v == '...':
                    root = False
                    continue
                names.append((v[0], root))
            rootn = [n for n, r in names if r] or [n for n, r in names]
            alln = [n for n, r in names]
            return rng.choice(alln if rng.random() < self.ext else rootn)
        if ty == 'INTEGER':
            lo, hi, ext = self._range(td.get('restricted-to'), (0, 2**31))
            if ext and rng.random() < self.ext:
                return hi + rng.randint(1, 5)
            return self.pick(lo, hi)
        if ty == 'BOOLEAN':
            return rng.random() < .5
        if ty == 'NULL':
            return None
        if ty == 'BIT STRING':
            sz = self._size(td, (0, 64))
            lo, hi, ext = sz if sz else (0, 64, False)
            hi = min(hi, max(lo, 40)) if hi > 64 else hi
            n = lo if (lo == hi) else rng.choice((lo, hi, rng.randint(lo, hi)))
            nb = (n + 7) // 8
            data = bytes(rng.choice(self.alpha) for _ in range(nb))
            if n % 8:
                data = data[:-1] + bytes([data[-1] & (0xff << (8 - n % 8)) & 0xff])
            return (data, n)
        if ty == 'OCTET STRING':
            sz = self._size(td, (0, 16))
            lo, hi, ext = sz if sz else (0, 16, False)
            hi = min(hi, lo + (80 if self.mode == 'probe' else 8))
            n = rng.randint(lo, hi)
            if self.mode == 'probe' and rng.random() < 0.45:
                # all zero bits are a valid PER encoding of many structures
                b = bytearray(n)
                if rng.random() < 0.4 and n:
                    for _ in range(rng.randint(1, 2)):
                        b[rng.randrange(n)] = rng.choice((1, 2, 0x40, 0x80, 0xff, 0x20))
                return bytes(b)
            return bytes(rng.choice(self.alpha) for _ in range(n))
        if ty in ('PrintableString', 'VisibleString', 'IA5String', 'UTF8String', 'BMPString', 'NumericString'):
            sz = self._size(td, (0, 16))
            lo, hi, ext = sz if sz else (0, 16, False)
            hi = min(hi, lo + 12)
            n = rng.randint(lo, hi)
            alpha = 'abcdefghijklmnopqrstuvwxyz0123456789 ' if ty != 'NumericString' else '0123456789 '
            return ''.join(rng.choice(alpha) for _ in range(n))
        if ty == 'OBJECT IDENTIFIER':
            return '1.2.3.4'
        raise ValueError('type %s' % ty)
