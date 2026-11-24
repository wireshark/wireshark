# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build sample BER values for the types of ASN.1 modules.

The ASN.1 modules are parsed and compiled with asn1tools (pip package
asn1tools; the sgp22/sgp32 modules of the Wireshark tree, with reduced
stand-ins for the PKIX modules in asn/). A Sampler walks the parsed type
definitions and builds a Python value for any type: every CHOICE
alternative and every OPTIONAL member is reached by varying the 'variant'
number, so that encoding a type for variants 0..N gives PDUs that
together use all alternatives. Nothing here is random: the same variant
always gives the same value.
"""
import os

import datetime
import sys
import zlib

import asn1tools

# Data files (asn/) sit beside the generator that uses this module.
HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
MODULES = ('PKIX1Explicit88.asn', 'PKIX1Implicit88.asn', 'PEDefinitions.asn',
           'RSPDefinitions.asn', 'SGP32Definitions.asn')


def h(*parts):
    return zlib.crc32('/'.join(str(p) for p in parts).encode())


class Sampler:
    def __init__(self, asn_dir=None, modules=MODULES):
        d = asn_dir or os.path.join(HERE, 'asn')
        files = [os.path.join(d, m) for m in modules]
        self.spec = asn1tools.parse_files(files)
        self.comp = asn1tools.compile_files(files, 'ber')
        self.depth = 0
        self.overrides = {}     # type name -> function(variant, path) -> value
        self.member_overrides = {}   # member name -> function(variant, path) -> value
        self.skip_members = set()    # OPTIONAL members that are never included

    # ----------------------------------------------------------- lookups
    def find(self, name, module):
        mod = self.spec[module]
        if name in mod['types']:
            return mod['types'][name], module
        for m, names in mod['imports'].items():
            if name in names:
                return self.find(name, m)
        for m in self.spec:
            if name in self.spec[m]['types']:
                return self.spec[m]['types'][name], m
        raise KeyError(name)

    # ---------------------------------------------------------- sampling
    def value(self, t, module, variant, path):
        """A value for the type descriptor t (a dict, or a type name)."""
        tn = t['type']
        if tn in self.overrides and 'members' not in t:
            return self.overrides[tn](variant, path)
        builtin = ('SEQUENCE', 'SET', 'CHOICE', 'SEQUENCE OF', 'SET OF', 'INTEGER', 'BOOLEAN',
                   'NULL', 'OCTET STRING', 'BIT STRING', 'OBJECT IDENTIFIER', 'UTF8String',
                   'PrintableString', 'IA5String', 'VisibleString', 'UTCTime', 'GeneralizedTime',
                   'ENUMERATED', 'NumericString', 'TeletexString', 'BMPString')
        if tn not in builtin:
            ref, m = self.find(tn, module)
            merged = dict(ref)
            for k in ('size', 'restricted-to'):
                if k in t:
                    merged[k] = t[k]
            if tn in self.overrides:
                return self.overrides[tn](variant, path)
            return self.value(merged, m, variant, path + '/' + tn)
        self.depth += 1
        try:
            return getattr(self, 'v_' + tn.replace(' ', '_'))(t, module, variant, path)
        finally:
            self.depth -= 1

    def v_SEQUENCE(self, t, module, variant, path):
        out = {}
        for i, m in enumerate(t.get('members', [])):
            if not isinstance(m, dict):
                continue
            name = m['name']
            if name in self.skip_members and m.get('optional'):
                continue
            if m.get('optional') or 'default' in m:
                # variant 0 includes every optional member; the others
                # vary
                if variant and (h(path, name, variant) % 3 == 0):
                    continue
                if 'default' in m and variant % 2 == 0:
                    continue
            if self.depth > 24:
                if m.get('optional') or 'default' in m:
                    continue
            if name in self.member_overrides:
                out[name] = self.member_overrides[name](variant, path)
                continue
            out[name] = self.value(m, module, variant, path + '/' + name)
        return out

    v_SET = v_SEQUENCE

    def v_CHOICE(self, t, module, variant, path):
        alts = [m for m in t['members'] if isinstance(m, dict)]
        if self.depth > 24:
            # avoid unbounded recursion: the first alternative that is not a container
            i = 0
        else:
            i = (variant + h(path)) % len(alts)
        m = alts[i]
        return (m['name'], self.value(m, module, variant // len(alts) if variant else 0, path + '/' + m['name']))

    def v_SEQUENCE_OF(self, t, module, variant, path):
        n = 1 + (variant % 2)
        if self.depth > 24:
            return []
        el = t['element']
        return [self.value(el, module, variant + j, path + '/[]') for j in range(n)]

    v_SET_OF = v_SEQUENCE_OF

    def sz(self, t, default=(1, 8)):
        s = t.get('size')
        if not s:
            return default
        x = s[0]
        if isinstance(x, tuple):
            lo, hi = x
            if hi == 'MAX':
                hi = lo + 8
            return lo, hi
        return x, x

    def v_INTEGER(self, t, module, variant, path):
        nn = t.get('named-numbers')
        if nn:
            vals = sorted(nn.values())
            return vals[(variant + h(path)) % len(vals)]
        rt = t.get('restricted-to')
        if rt:
            lo, hi = rt[0]
            if lo == 'MIN':
                lo = 0
            if hi == 'MAX':
                hi = lo + 1000
            span = int(hi) - int(lo) + 1
            return int(lo) + (variant * 7 + h(path)) % min(span, 50)
        return 1 + (variant + h(path)) % 100

    def v_BOOLEAN(self, t, module, variant, path):
        return bool((variant + h(path)) % 2)

    def v_NULL(self, t, module, variant, path):
        return None

    def v_OCTET_STRING(self, t, module, variant, path):
        lo, hi = self.sz(t, (2, 12))
        n = lo if variant % 2 == 0 else min(hi, lo + 1 + variant % 3)
        n = max(n, 0)
        return bytes((h(path, i) + variant) & 0xff for i in range(n))

    def v_BIT_STRING(self, t, module, variant, path):
        nb = t.get('named-bits')
        if t.get('size'):
            lo, hi = self.sz(t)
            nbits = lo
        elif nb:
            nbits = max(int(b) for _, b in nb) + 1
        else:
            nbits = 16
        nbytes = (nbits + 7) // 8
        data = bytearray((h(path, i, variant) | 0x11) & 0xff for i in range(nbytes))
        if nbits % 8:
            data[-1] &= (0xff << (8 - nbits % 8)) & 0xff
        return (bytes(data), nbits)

    def v_OBJECT_IDENTIFIER(self, t, module, variant, path):
        return '1.3.6.1.4.1.32473.%d' % (1 + variant % 5)

    def string(self, t, variant, path, alphabet):
        lo, hi = self.sz(t, (1, 16))
        n = max(lo, min(hi, 6 + variant % 3))
        return ''.join(alphabet[(h(path, i) + variant) % len(alphabet)] for i in range(n))

    def v_UTF8String(self, t, module, variant, path):
        return self.string(t, variant, path, 'abcdefghijklmnopqrstuvwxyz')

    v_IA5String = v_PrintableString = v_VisibleString = v_UTF8String
    v_NumericString = v_TeletexString = v_UTF8String

    def v_UTCTime(self, t, module, variant, path):
        return datetime.datetime(2026, 11, 1 + variant % 28, 12, 0, 0)

    def v_GeneralizedTime(self, t, module, variant, path):
        return datetime.datetime(2026, 11, 1 + variant % 9, 12, 0, 0)

    def v_ENUMERATED(self, t, module, variant, path):
        vals = [m for m in t['values'] if isinstance(m, tuple)]
        return vals[(variant + h(path)) % len(vals)][0]

    # ------------------------------------------------------------ public
    def sample(self, name, module, variant, **fixed):
        t, m = self.find(name, module)
        self.fixed = fixed
        return self.value({'type': name}, module, variant, name)

    def encode(self, name, module, variant):
        v = self.sample(name, module, variant)
        return self.comp.modules[module][name].encode(v)
