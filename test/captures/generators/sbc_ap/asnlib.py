# Helper module for the sbc_ap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Random ASN.1 value generator and PER encoder front end for the UMTS
dissectors (RRC, RANAP, RNSAP, RRLP).  Needs the asn1tools package
(pip install asn1tools); it compiles the ASN.1 files of the Wireshark tree
(epan/dissectors/asn1/<name>/) and encodes random values with it.

RANAP and RNSAP use information object classes that asn1tools cannot
compile, so prep_ranap() rewrites the protocol IE containers into plain
SEQUENCE OF { id, criticality, value OCTET STRING } and Gen fills the open
type values from the IE sets it parsed out of the specification."""
import os
HERE = os.path.dirname(os.path.abspath(__file__))
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import glob
import random
import re
import sys

import asn1tools
from asn1tools.codecs import per as _per
from asn1tools.codecs import uper as _uper

TREE = os.environ.get('WS_TREE', os.path.join(SRCDIR))


def K(t, name):
    """isinstance by class name (per and uper have separate class trees)."""
    return any(c.__name__ == name for c in type(t).__mro__)


def strip_comments(t):
    return re.sub(r'--.*?(--|$)', '', t, flags=re.M)


def _body(t):
    t = strip_comments(t)
    i = t.index('BEGIN')
    j = t.rindex('END')
    b = t[i + 5:j]
    b = re.sub(r'\bIMPORTS\b.*?;', '', b, count=1, flags=re.S)
    b = re.sub(r'\bEXPORTS\b.*?;', '', b, count=1, flags=re.S)
    return b


def _balanced(t, i):
    """t[i] == '{' : return index after the matching '}'."""
    d = 0
    for k in range(i, len(t)):
        if t[k] == '{':
            d += 1
        elif t[k] == '}':
            d -= 1
            if d == 0:
                return k + 1
    raise ValueError('unbalanced')


GM = {'ngap': 'GM ::= SEQUENCE { procedureCode ProcedureCode, criticality Criticality, value OCTET STRING }',
      'lppa': 'GM ::= SEQUENCE { procedureCode ProcedureCode, criticality Criticality, value OCTET STRING }',
      's1ap': 'GM ::= SEQUENCE { procedureCode ProcedureCode, criticality Criticality, value OCTET STRING }',
      'sabp': 'GM ::= SEQUENCE { procedureCode ProcedureCode, criticality Criticality, value OCTET STRING }',
      'sbc-ap': 'GM ::= SEQUENCE { procedureCode ProcedureCode, criticality Criticality, value OCTET STRING }',
      'rua': 'GM ::= SEQUENCE { procedureCode ProcedureCode, criticality Criticality, value OCTET STRING }',
      'ranap': 'GM ::= SEQUENCE { procedureCode ProcedureCode, criticality Criticality, value OCTET STRING }',
      'rnsap': 'GM ::= SEQUENCE { procedureID ProcedureID, criticality Criticality, transactionID TransactionID, value OCTET STRING }'}


def fix_size_refs(text):
    """asn1tools drops a SIZE constraint put on a reference to a plain OCTET/BIT STRING
    alias (X ::= OCTET STRING; Y ::= X (SIZE (3))): inline those aliases."""
    t = strip_comments(text)
    al = dict((m.group(1), m.group(2)) for m in re.finditer(r'^([A-Z][\w-]*)\s*::=\s*(OCTET STRING|BIT STRING)\s*$', t, re.M))
    for n, base in al.items():
        t = re.sub(r'(?<![\w-])%s(\s*\(\s*SIZE)' % re.escape(n), base + r'\1', t)
    return t


def prep_ranap(name, cls):
    """name: ranap or rnsap, cls: RANAP / RNSAP.  Returns (asn text, ie sets, procedures)."""
    d = '%s/epan/dissectors/asn1/%s/' % (TREE, name)
    P = cls.upper()
    bodies = {}
    for f in ('CommonDataTypes', 'Constants', 'Containers', 'IEs', 'PDU-Contents', 'PDU-Descriptions', 'SonTransfer-IEs'):
        if os.path.exists('%s%s-%s.asn' % (d, P, f)):
            bodies[f] = _body(open('%s%s-%s.asn' % (d, P, f)).read())
    # constants
    consts = dict((m.group(1), int(m.group(2))) for m in
                  re.finditer(r'^([\w-]+)\s+\w[\w-]*\s*::=\s*(\d+)\s*$', bodies['Constants'], re.M))
    ids = consts
    # procedures
    procs = []
    for m in re.finditer(r'^([\w-]+)\s+%s-ELEMENTARY-PROCEDURE\s*::=\s*\{(.*?)\n\}' % P, bodies['PDU-Descriptions'], re.M | re.S):
        s = m.group(2)
        if 'PROCEDURE CODE' not in s and 'PROCEDURE ID' not in s:
            continue
        mid = re.search(r'PROCEDURE\s+ID\s*\{\s*procedureCode\s+([\w-]+)\s*,\s*ddMode\s+(\w+)', s)
        g = lambda k: (re.search(k + r'\s+([\w-]+)', s) or [None, None])[1]
        procs.append(dict(name=m.group(1), init=g('INITIATING MESSAGE'), succ=g('SUCCESSFUL OUTCOME'),
                          unsucc=g('UNSUCCESSFUL OUTCOME'), outcome=g(r'(?<!UN)(?<!SUCCESSFUL )OUTCOME'),
                          code=ids[mid.group(1) if mid else g('PROCEDURE CODE')], dd=mid.group(2) if mid else None, crit=g('CRITICALITY') or 'ignore'))
    text = bodies['CommonDataTypes'] + bodies['Constants'] + bodies.get('SonTransfer-IEs', '') + bodies['IEs'] + bodies['PDU-Contents']
    # numeric value references (INTEGER ::= othername)
    def fixval(m):
        v = consts.get(m.group(3))
        return '%s %s ::= %s' % (m.group(1), m.group(2), v) if v is not None else m.group(0)
    text = re.sub(r'^([\w-]+)\s+(INTEGER)\s*::=\s*([A-Za-z][\w-]*)\s*$', fixval, text, flags=re.M)
    # object sets
    sets = {}
    for m in re.finditer(r'^([\w-]+)\s+%s-(PROTOCOL-IES|PROTOCOL-IES-PAIR|PROTOCOL-EXTENSION|PRIVATE-IES)\s*::=\s*\{' % P, text, re.M):
        end = _balanced(text, m.end() - 1)
        inner = text[m.end():end - 1]
        ents = []
        for e in re.finditer(r'\{\s*ID\s+([\w-]+)\s+(?:FIRST\s+)?CRITICALITY\s+(\w+)\s+(?:FIRST\s+)?(?:TYPE|EXTENSION)\s+([\w-]+)'
                             r'(?:\s+SECOND\s+CRITICALITY\s+(\w+)\s+SECOND\s+TYPE\s+([\w-]+))?\s+PRESENCE\s+(\w+)\s*\}', inner):
            ents.append(dict(id=ids.get(e.group(1)), idname=e.group(1), crit=e.group(2), type=e.group(3),
                             crit2=e.group(4), type2=e.group(5), presence=e.group(6)))
        sets[m.group(1)] = ents
    # drop classes and object sets
    out = []
    pos = 0
    for m in re.finditer(r'^([\w-]+)\s+(%s-(PROTOCOL-IES|PROTOCOL-IES-PAIR|PROTOCOL-EXTENSION|PRIVATE-IES|ELEMENTARY-PROCEDURE))\s*::=\s*(CLASS\s*)?\{' % P, text, re.M):
        if m.start() < pos:
            continue
        end = _balanced(text, m.end() - 1)
        # CLASS has a WITH SYNTAX block
        mm = re.match(r'\s*WITH\s+SYNTAX\s*\{', text[end:])
        if mm:
            end = _balanced(text, end + mm.end() - 1)
        out.append(text[pos:m.start()])
        pos = end
    out.append(text[pos:])
    text = ''.join(out)
    # parameterized aliases:  Name { CLASS : P } ::= ProtocolIE-ContainerList { 1, max, {P} }
    alias = {}
    # note: removing shifts positions; redo search each time (done by loop restart below)
    while True:
        m = re.search(r'^([\w-]+)\s*\{\s*%s-[\w-]+\s*:\s*\w+\s*\}\s*::=\s*(Protocol[\w-]+)\s*\{' % P, text, re.M)
        if not m:
            break
        end = _balanced(text, m.end() - 1)
        args = [a.strip() for a in text[m.end():end - 1].split(',')]
        alias[m.group(1)] = (m.group(2), args[:-1])
        text = text[:m.start()] + text[end:]
    kinds = {'ProtocolIE-Container': 'IESET', 'ProtocolIE-Single-Container': 'ISET', 'ProtocolIE-SingleContainer': 'ISET',
             'ProtocolIE-ContainerList': 'IESET', 'ProtocolIE-ContainerPair': 'PAIRSET',
             'ProtocolIE-ContainerPairList': 'PAIRSET', 'ProtocolExtensionContainer': 'EXTSET',
             'PrivateIE-Container': 'PRIVSET'}
    pat = re.compile(r'\b(%s)\s*\{' % '|'.join(sorted(list(kinds) + list(alias), key=len, reverse=True)))
    def expand(kind, args, setname):
        if kind == 'ProtocolIE-Container':
            return 'SEQUENCE (SIZE (0..maxProtocolIEs)) OF SEQUENCE { id-IESET-%s ProtocolIE-ID, criticality Criticality, value OCTET STRING }' % setname
        if kind in ('ProtocolIE-Single-Container', 'ProtocolIE-SingleContainer'):
            return 'SEQUENCE { id-ISET-%s ProtocolIE-ID, criticality Criticality, value OCTET STRING }' % setname
        if kind == 'ProtocolIE-ContainerList':
            return 'SEQUENCE (SIZE (%s..%s)) OF %s' % (args[0], args[1], expand('ProtocolIE-Container', [], setname))
        if kind == 'ProtocolIE-ContainerPair':
            return ('SEQUENCE (SIZE (0..maxProtocolIEs)) OF SEQUENCE { id-PAIRSET-%s ProtocolIE-ID, firstCriticality Criticality, '
                    'firstValue OCTET STRING, secondCriticality Criticality, secondValue OCTET STRING }' % setname)
        if kind == 'ProtocolIE-ContainerPairList':
            return 'SEQUENCE (SIZE (%s..%s)) OF %s' % (args[0], args[1], expand('ProtocolIE-ContainerPair', [], setname))
        if kind == 'ProtocolExtensionContainer':
            return ('SEQUENCE (SIZE (1..maxProtocolExtensions)) OF SEQUENCE { id-EXTSET-%s ProtocolExtensionID, criticality Criticality, '
                    'extensionValue OCTET STRING }' % setname)
        if kind == 'PrivateIE-Container':
            return 'SEQUENCE (SIZE (1..maxPrivateIEs)) OF SEQUENCE { id-PRIVSET-%s PrivateIE-ID, criticality Criticality, value OCTET STRING }' % setname
        raise KeyError(kind)
    while True:
        m = pat.search(text)
        if not m:
            break
        end = _balanced(text, m.end() - 1)
        inner = text[m.end():end - 1]
        setname = re.findall(r'[A-Za-z][\w-]*', inner)[-1]
        k = m.group(1)
        if k in alias:
            k, args = alias[k]
            args = [a for a in args]
        else:
            args = [a.strip() for a in inner.split(',')[:-1]]
            if k in ('ProtocolIE-ContainerList', 'ProtocolIE-ContainerPairList'):
                args = [a.strip() for a in inner.split(',')][:2]
        text = text[:m.start()] + expand(k, args, setname) + text[end:]
    if not re.search(r'ProtocolExtensionID\s*::=', text):
        text += '\nProtocolExtensionID ::= INTEGER (0..65535)\n'
    mod = ('%s-ALL DEFINITIONS AUTOMATIC TAGS ::=\nBEGIN\n%s\n'
           'PDU ::= CHOICE { initiatingMessage GM, successfulOutcome GM, unsuccessfulOutcome GM, outcome GM, ... }\n'
           '%s\nEND\n') % (P, text, GM[name])
    return fix_size_refs(mod), sets, procs


class Raw(bytes):
    """A hook result that is already the open type contents (not to be encoded)."""


class Gen:
    def __init__(self, codec, rnd=None, sets=None, procs=None, hooks=None):
        self.c = codec
        self.r = rnd or random.Random(1)
        self.sets = sets or {}
        self.procs = procs or []
        self.hooks = hooks or {}
        self.popt = 0.5        # probability to include an optional member
        self.padd = 0.2        # probability to include an extension addition
        self.maxdepth = 40
        self.maxlist = 3
        self.pext = 0.05       # chance of an out of range value in extensible types
        self.strict = False
        self.forced = {}       # CHOICE type or member name -> alternative to pick

    # --- leaf helpers
    def rbytes(self, n):
        return bytes(self.r.getrandbits(8) for _ in range(n))

    def size(self, lo, hi, cap=None):
        lo = 0 if lo in (None, 'MIN') else lo
        if hi in (None, 'MAX'):
            hi = lo + (cap if cap is not None else 6)
        if cap is not None:
            hi = min(hi, max(lo, lo + cap))
        x = self.r.random()
        if x < 0.25:
            return lo
        if x < 0.4:
            return hi
        return self.r.randint(lo, hi)

    def gen(self, t, depth=0, nohook=False):
        if depth > self.maxdepth:
            raise RecursionError('too deep')
        h = None if nohook else (self.hooks.get(t.name) or self.hooks.get(getattr(t, 'type_name', None)))
        if h is None:
            for pred, fn in getattr(self, 'rules', ()):
                if pred(t):
                    h = fn
                    break
        if h is not None:
            v = h(self, t, depth)
            if v is not None:
                return v
        if K(t, 'Recursive'):
            return self.gen(t._inner, depth)
        r = self.r
        if K(t, 'Boolean'):
            return r.random() < 0.5
        if K(t, 'Null'):
            return None
        if K(t, 'Integer'):
            lo, hi = t.minimum, t.maximum
            if lo is None:
                return r.choice([0, 1, 5, 100, 70000, -3, 2 ** 31 - 1])
            x = r.random()
            if t.has_extension_marker and r.random() < self.pext:
                return hi + r.randint(1, 1000)
            if x < 0.2:
                return lo
            if x < 0.4:
                return hi
            if hi - lo > 1000000 and x < 0.7:
                return lo + r.randint(0, 1000)
            return r.randint(lo, hi)
        if K(t, 'Enumerated'):
            ks = list(t.root_index_to_data.values())
            if t.additions_index_to_data and r.random() < self.padd:
                return r.choice(list(t.additions_index_to_data.values()))
            return r.choice(ks)
        if K(t, 'BitString'):
            n = self.size(t.minimum, t.maximum, 24)
            b = bytearray(self.rbytes((n + 7) // 8))
            if n % 8 and b:
                b[-1] &= (0xff00 >> (n % 8)) & 0xff     # the padding bits are zero
            return (bytes(b), n)
        if K(t, 'OctetString'):
            return self.rbytes(self.size(t.minimum, t.maximum, 8))
        if K(t, 'KnownMultiplierStringType'):
            n = self.size(t.minimum, t.maximum, 10)
            alpha = sorted(t.permitted_alphabet.encode_map) or list(range(32, 127))
            if not t.permitted_alphabet.encode_map:
                alpha = sorted(t.PERMITTED_ALPHABET.encode_map) or list(range(32, 127))
            return ''.join(chr(r.choice(alpha)) for _ in range(n))
        if K(t, 'UTF8String'):
            return ''.join(r.choice('abcdefgh') for _ in range(r.randint(0, 8)))
        if K(t, 'ObjectIdentifier'):
            return '1.2.%d.%d' % (r.randint(1, 100), r.randint(1, 100))
        if K(t, 'SequenceOf'):
            el = t.element_type
            if K(el, 'Recursive'):
                el = el._inner
            if K(el, 'Sequence') and el.root_members and re.match(r'id-(IESET|PAIRSET|EXTSET|PRIVSET)-', el.root_members[0].name):
                return self.container(t, el, depth)
            lo = t.minimum if t.minimum not in (None, 'MIN') else 0
            hi = t.maximum if t.maximum not in (None, 'MAX') else lo + self.maxlist
            hi = min(hi, max(lo, self.maxlist if depth < self.maxdepth // 2 else lo))
            n = r.randint(lo, hi)
            if depth > self.maxdepth // 2:
                n = lo
            return [self.gen(el, depth + 1) for _ in range(n)]
        if K(t, 'Sequence'):
            return self.sequence(t, depth)
        if K(t, 'Choice'):
            alts = list(t.root_index_to_member.values())
            if t.additions_index_to_member and r.random() < self.padd:
                alts = alts + list(t.additions_index_to_member.values())
            r.shuffle(alts)
            fa = self.forced.get(getattr(t, 'type_name', None)) or self.forced.get(t.name)
            if fa:
                alts = [x for x in list(t.root_index_to_member.values()) + list((t.additions_index_to_member or {}).values())
                        if x.name == fa] + alts
            err = None
            for a in alts:
                try:
                    return (a.name, self.gen(a, depth + 1))
                except RecursionError as e:
                    err = e
            raise err
        raise NotImplementedError(type(t))

    def sequence(self, t, depth):
        d = {}
        r = self.r
        m0 = t.root_members[0].name if t.root_members else ''
        if m0.startswith('id-ISET-'):
            e = r.choice(self.sets[m0[8:]]) if self.sets.get(m0[8:]) else None
            if e is None:
                return {m0: r.randint(0, 65535), 'criticality': 'ignore', 'value': self.rbytes(r.randint(0, 3))}
            return {m0: e['id'], 'criticality': e['crit'], 'value': self.enc(e['type'])}
        self.members(t, d, depth)
        if t.additions is not None and r.random() < self.padd:
            for a in t.additions:
                if r.random() < 0.6:
                    if K(a, 'AdditionGroup'):
                        try:
                            sub = {}
                            self.members(a, sub, depth)
                            d.update(sub)
                        except RecursionError:
                            pass
                    else:
                        try:
                            d[a.name] = self.gen(a, depth + 1)
                        except RecursionError:
                            pass
        return d

    def members(self, t, d, depth):
        for m in t.root_members:
            opt = m.optional or m.default is not None
            if opt and (r_ := self.r.random()) > (self.popt if depth < self.maxdepth // 2 else 0.0):
                continue
            if opt:
                try:
                    d[m.name] = self.gen(m, depth + 1)
                except RecursionError:
                    pass
            else:
                d[m.name] = self.gen(m, depth + 1)

    def enc(self, typename, value=None):
        if typename == 'NULL':
            return Raw(b'\x00')
        t = self.c.types[typename]
        if value is None:
            value = self.gen(t.type, 0)
        if isinstance(value, Raw):
            return bytes(value)
        try:
            # an open type holds at least one octet (a zero bit encoding is padded to one)
            return t.encode(value) or b'\x00'
        except Exception:
            if os.environ.get('GENDEBUG'):
                print('ENCODE FAIL', typename, narrow(t.type, value), file=sys.stderr)
            raise

    def container(self, t, el, depth):
        m0 = el.root_members[0].name
        kind, sname = re.match(r'id-(\w+?)-(.*)$', m0).groups()
        r = self.r
        ents = self.sets.get(sname, [])
        out = []
        for e in ents:
            if e['presence'] == 'mandatory' or r.random() < self.popt:
                out.append(self.ie(kind, m0, e, depth))
        while ents and len(out) < (t.minimum or 0):
            out.append(self.ie(kind, m0, r.choice(ents), depth))
        if r.random() < 0.03 or (not ents and t.minimum):
            out.append({m0: r.randint(2000, 65535) if kind != 'PRIVSET' else r.choice([('local', 7), ('global', '1.2.%d.4' % r.randint(1, 99))]), 'criticality': 'ignore',
                        'value' if kind != 'EXTSET' else 'extensionValue': self.rbytes(r.randint(0, 1) * 2)}
                       if kind != 'PAIRSET' else {m0: 65000, 'firstCriticality': 'ignore', 'firstValue': b'', 'secondCriticality': 'ignore', 'secondValue': b''})
        return out

    def ie(self, kind, m0, e, depth):
        if kind == 'PAIRSET':
            return {m0: e['id'], 'firstCriticality': e['crit'], 'firstValue': self.enc(e['type']),
                    'secondCriticality': e['crit2'], 'secondValue': self.enc(e['type2'])}
        return {m0: e['id'], 'criticality': e['crit'],
                'extensionValue' if kind == 'EXTSET' else 'value': self.enc(e['type'])}

    # --- PDUs
    def pdu(self, proc, which):
        """RANAP/RNSAP PDU for a procedure dict: which in init, succ, unsucc, outcome."""
        tn = proc[which]
        if not tn:
            return None
        body = self.enc(tn)
        alt = {'init': 'initiatingMessage', 'succ': 'successfulOutcome', 'unsucc': 'unsuccessfulOutcome', 'outcome': 'outcome'}[which]
        if proc.get('dd'):
            g = {'procedureID': {'procedureCode': proc['code'], 'ddMode': proc['dd']}, 'criticality': proc['crit'],
                 'transactionID': self.r.choice([('shortTransActionId', self.r.randint(0, 127)), ('longTransActionId', self.r.randint(0, 32767))]),
                 'value': body}
        else:
            g = {'procedureCode': proc['code'], 'criticality': proc['crit'], 'value': body}
        return self.c.types['PDU'].encode((alt, g))


def compile_spec(name, codec):
    """Returns (compiled, sets, procs) for ranap/rnsap (aligned PER), rrc/rrlp (unaligned)."""
    d = '%s/epan/dissectors/asn1/%s/' % (TREE, name)
    if name in ('ranap', 'rnsap', 's1ap', 'sabp', 'sbc-ap', 'rua', 'ngap', 'lppa'):
        text, sets, procs = prep_ranap(name, name)
        return asn1tools.compile_string(text, codec), sets, procs
    if name == 'rrlp':
        comp = _body(open(d + 'RRLP-Components.asn').read())
        msg = _body(open(d + 'RRLP-Messages.asn').read())
        text = ('RRLP-ALL DEFINITIONS AUTOMATIC TAGS ::=\nBEGIN\n'
                'Ext-GeographicalInformation ::= OCTET STRING (SIZE (1..20))\n'
                'VelocityEstimate ::= OCTET STRING (SIZE (4..7))\n'
                'ExtensionContainer ::= SEQUENCE { privateExtensionList [0] SEQUENCE (SIZE (1..10)) OF SEQUENCE { extId OBJECT IDENTIFIER, extType OCTET STRING OPTIONAL } OPTIONAL, pcs-Extensions [1] SEQUENCE { ... } OPTIONAL, ... }\n'
                + comp + msg + '\nEND\n')
        return asn1tools.compile_string(fix_size_refs(text), codec), {}, []
    files = sorted(glob.glob(d + '*.asn'))
    return asn1tools.compile_string(fix_size_refs('\n'.join(open(f).read() for f in files)), codec), {}, []


def narrow(t, v, path=''):
    """Debug: find the innermost member whose value does not encode."""
    def ok(tt, vv):
        e = _uper.Encoder() if 'uper' in type(t).__module__ else _per.Encoder()
        try:
            tt.encode(vv, e)
            e.as_bytearray()
            return True
        except Exception:
            return False
    if K(t, 'Recursive'):
        t = t._inner
    if K(t, 'Sequence'):
        for m in list(t.root_members) + list(t.additions or []):
            if K(m, 'AdditionGroup'):
                for mm in m.root_members:
                    if mm.name in v and not ok(mm, v[mm.name]):
                        return narrow(mm, v[mm.name], path + '/' + mm.name)
            elif m.name in v and not ok(m, v[m.name]):
                return narrow(m, v[m.name], path + '/' + m.name)
    elif K(t, 'SequenceOf'):
        for n in range(1, len(v) + 1):
            if not ok(t, v[:n]):
                path += '{prefix %d of %d; min %s max %s; el %s}' % (n, len(v), t.minimum, t.maximum, type(t.element_type).__name__)
                break
        for i, x in enumerate(v):
            if not ok(t.element_type, x):
                return narrow(t.element_type, x, path + '[%d]' % i)
    elif K(t, 'Choice'):
        for m in list(t.root_index_to_member.values()) + list((t.additions_index_to_member or {}).values()):
            if m.name == v[0] and not ok(m, v[1]):
                return narrow(m, v[1], path + '/' + m.name)
    return path, type(t).__name__, repr(v)[:200]
