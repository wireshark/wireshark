#!/usr/bin/env python3
# Generates test/captures/z3950_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Z39.50 (and MARC) coverage captures for packet-z3950.c.

Usage: mkz3950.py <outdir> [-v]
Writes z3950-coverage.pcap (valid PDUs, TCP port 210) and
z3950-coverage-malformed.pcap.

The PDUs and the record syntaxes carried in EXTERNAL are generated from
the ASN.1 of the dissector (epan/dissectors/asn1/z3950/*.asn) with the
asn1tools package (pip install asn1tools; a copy is in ./pylib): a random
value generator that cycles through the CHOICE alternatives and optional
members so that every PDU and syntax type is produced several times,
with fixed seeds.  asn1tools cannot encode EXTERNAL, so those fields are
built here: the encoder writes a marker, and the BER tree is rewritten to
put the EXTERNAL (OID plus the encoded record, or MARC octets) in its place.
Handwritten PDUs cover the nesting (RPN, GRS-1), MARC and the odd cases.
Nothing here handles keys or encryption (Z39.50 has none)."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import collections
import datetime
import random
import re
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
import asn1tools

TREE = os.environ.get('WS_TREE', os.path.join(SRCDIR))
ASN_DIR = TREE + '/epan/dissectors/asn1/z3950/'

# ----------------------------------------------------------------- BER utils


def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + blen(len(content)) + content


def ctag(num, constructed=True):
    """Context-specific tag bytes."""
    first = 0x80 | (0x20 if constructed else 0)
    if num < 31:
        return bytes([first | num])
    out = [first | 31]
    parts = []
    while True:
        parts.append(num & 0x7f)
        num >>= 7
        if not num:
            break
    parts.reverse()
    for i, p in enumerate(parts):
        out.append(p | (0x80 if i < len(parts) - 1 else 0))
    return bytes(out)


def oid_bytes(s):
    a = [int(x) for x in s.split('.')]
    out = bytearray([a[0] * 40 + a[1]])
    for v in a[2:]:
        parts = [v & 0x7f]
        v >>= 7
        while v:
            parts.append((v & 0x7f) | 0x80)
            v >>= 7
        out += bytes(reversed(parts))
    return bytes(out)


def oid_tlv(s, tag=0x06):
    return tlv(tag, oid_bytes(s))


def int_content(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return v.to_bytes(n, 'big', signed=True)


class Node:
    def __init__(self, tag, cons, data):
        self.tag = tag          # tag bytes
        self.cons = cons
        self.data = data        # bytes (primitive) or list of Node


def parse(b, i=0, end=None):
    end = len(b) if end is None else end
    out = []
    while i < end:
        t0 = i
        first = b[i]
        i += 1
        if first & 0x1f == 0x1f:
            while b[i] & 0x80:
                i += 1
            i += 1
        tag = bytes(b[t0:i])
        ln = b[i]
        i += 1
        if ln & 0x80:
            n = ln & 0x7f
            ln = int.from_bytes(b[i:i + n], 'big')
            i += n
        cons = bool(first & 0x20)
        if cons:
            out.append(Node(tag, True, parse(b, i, i + ln)))
        else:
            out.append(Node(tag, False, bytes(b[i:i + ln])))
        i += ln
    return out


def ser(n):
    if n.cons:
        content = b''.join(ser(c) for c in n.data)
    else:
        content = n.data
    return tlv(n.tag, content)


# ------------------------------------------------------------------ the ASN.1

def asn_text():
    def strip(t):
        return re.sub(r'--.*?(--|$)', '', t, flags=re.M)
    a = strip(open(ASN_DIR + 'z3950.asn').read())
    a = a[a.index('Z39-50-APDU-1995'):]                # drop the OID module
    a = re.sub(r'\bANY\b', 'OCTET STRING', a)
    e = strip(open(ASN_DIR + 'z3950-externals.asn').read())
    o = strip(open(ASN_DIR + 'z3950-oclc.asn').read())
    txt = a + '\n' + e + '\n' + o
    txt = re.sub(r'\b(OCTET|BIT)\s+STRING', r'\1 STRING', txt)
    txt = re.sub(r'OBJECT\s+IDENTIFIER', 'OBJECT IDENTIFIER', txt)
    txt = re.sub(r'SEQUENCE\s+OF', 'SEQUENCE OF', txt)
    txt = re.sub(r'\bEXTERNAL\b', 'EXTMARK', txt)
    txt = re.sub(r'\bEND\b', 'EXTMARK ::= SEQUENCE { marker OCTET STRING }\nEND', txt)
    return txt


OID_BIB1 = '1.2.840.10003.3.1'
OID_DIAG_BIB1 = '1.2.840.10003.4.1'
OID_MARC21 = '1.2.840.10003.5.10'
# record syntaxes and ESs the dissector registers: OID, ASN.1 type
SYNTAXES = [
    ('1.2.840.10003.5.100', 'Explain-Record'),
    ('1.2.840.10003.5.101', 'SutrsRecord'),
    ('1.2.840.10003.5.102', 'OPACRecord'),
    ('1.2.840.10003.5.103', 'BriefBib'),
    ('1.2.840.10003.5.105', 'GenericRecord'),
    ('1.2.840.10003.5.106', 'TaskPackage'),
    ('1.2.840.10003.4.2', 'DiagnosticFormat'),
    ('1.2.840.10003.8.1', 'PromptObject'),
    ('1.2.840.10003.8.2', 'DES-RN-Object'),
    ('1.2.840.10003.8.3', 'KRBObject'),
    ('1.2.840.10003.10.1', 'SearchInfoReport'),
    ('1.2.840.10003.10.1000.17.1', 'OCLC-UserInformation'),
    (OID_MARC21, None),
    ('1.2.3.4.5.6', None),                    # no dissector registered
]
ANY_OIDS = ['1.2.840.10003.5.1', '1.2.840.10003.5.10', '1.2.840.10003.5.101',
            '1.2.840.10003.5.105', '1.2.840.10003.5.100', '1.2.840.10003.3.2',
            '1.2.840.10003.9.1', '2.5.4.3', '1.2.840.10003.5.104']
WORDS = ['alpha', 'Beta', 'gamma delta', 'title', 'Smith, J.', 'Default', 'F', 'B', 'brief',
         'Books', 'Cats', 'A very long element set name for the test', 'x', '']


def marc_record(variant=0):
    """A MARC21 record (valid), a few shapes."""
    fields = [('001', b'ocm12345678 '), ('005', b'20260102153000.0'),
              ('008', b'260102s2026    xxu           000 0 eng d')]
    data = [('020', b'  \x1faISBN 9780000000002\x1fqpaper'),
            ('245', b'10\x1faThe test record /\x1fcA. Author.'),
            ('260', b'  \x1faPlace :\x1fbPublisher,\x1fc2026.')]
    if variant % 3 == 1:
        data = [('100', b'1 \x1faAuthor, A.'), ('245', b'00\x1faOnly one subfield')]
    if variant % 3 == 2:
        fields = [('001', b'1')]
        data = [('650', b' 0\x1faTopic\x1fvSub1\x1fxSub2\x1fyYear\x1fzPlace')]
    ents = []
    body = b''
    for tag, d in fields + data:
        d = d + b'\x1e'
        ents.append('%s%04d%05d' % (tag, len(d), len(body)))
        body += d
    directory = ''.join(ents).encode() + b'\x1e'
    base = 24 + len(directory)
    total = base + len(body) + 1
    leader = (b'%05d' % total + b'nam a22' + b'%05d' % base + b' a 4500')
    assert len(leader) == 24, len(leader)
    return leader + directory + body + b'\x1d'


class Gen:
    def __init__(self, seed=1):
        txt = asn_text()
        self.parsed = asn1tools.parse_string(txt)
        self.spec = asn1tools.compile_string(txt, 'ber')
        self.rng = random.Random(seed)
        self.types = {}
        for mn, m in self.parsed.items():
            for tn, t in m['types'].items():
                self.types.setdefault(tn, t)
        self.cyc = collections.Counter()
        self.depth = 0
        self.maxdepth = 7
        self.externals = {}         # marker index -> (oid, inner, mode, extra)
        self.nsyn = 0
        self.ext_depth = 0
        self.marc_n = 0
        self.forced = None

    # ---- helpers
    def resolve(self, t):
        seen = 0
        while t['type'] in self.types and t['type'] != 'EXTMARK' and seen < 20:
            base = self.types[t['type']]
            nt = dict(base)
            for k in ('restricted-to', 'size', 'from', 'named-numbers', 'named-bits'):
                if k in t:
                    nt[k] = t[k]
            t = nt
            seen += 1
        return t

    def pick(self, key, n):
        """Index in range(n) that was used least for this key."""
        counts = [self.cyc[(key, i)] for i in range(n)]
        m = min(counts)
        i = self.rng.choice([k for k in range(n) if counts[k] == m])
        self.cyc[(key, i)] += 1
        return i

    def printable(self, lo=1, hi=12):
        n = self.rng.randint(lo, hi)
        return ''.join(self.rng.choice('abcdefghij XYZ0189-.') for _ in range(n))

    def oid_choice(self, options):
        return options[self.pick(tuple(options), len(options))]

    # ---- value generation
    def value(self, t, ctx=''):
        name = t.get('name', '')
        tn = t['type']
        r = self.rng
        # hooks on type and member names
        if tn == 'EXTMARK':
            return self.external(ctx)
        if tn == 'AttributeSetId':
            return self.oid_choice([OID_BIB1, OID_BIB1, '1.2.840.10003.3.2', '1.2.840.10003.3.5'])
        if tn == 'ReferenceId':
            if r.random() < 0.6:
                return self.printable(1, 10).encode()
            return bytes(r.randrange(256) for _ in range(r.randint(1, 6)))
        if name == 'diagnosticSetId':
            return self.oid_choice([OID_DIAG_BIB1, OID_DIAG_BIB1, '1.2.840.10003.4.2'])
        if name == 'condition':
            return [1, 2, 3, 100, 108, 1001, 9999, 0][self.pick('cond', 8)]
        if name == 'attributeType':
            return [1, 2, 3, 4, 5, 6, 7, 1][self.pick('atype', 8)]
        if name == 'numeric' and ctx.endswith('attributeValue'):
            return [1, 2, 3, 4, 5, 6, 7, 1003, 1016, 1035, 99999][self.pick('aval', 11)]
        if name in ('preferredRecordSyntax', 'direct-reference') or tn == 'RecordSyntaxOid':
            return self.oid_choice([s[0] for s in SYNTAXES])
        if name == 'recordSyntax' and tn == 'OBJECT IDENTIFIER':
            return self.oid_choice([s[0] for s in SYNTAXES])
        t = self.resolve(t)
        ty = t['type']
        if ty == 'EXTMARK':
            return self.external(ctx)
        if name == 'general' or name == 'binaryInfo' and False:
            if r.random() < 0.6:
                return self.printable(1, 10).encode()
        if ty == 'BOOLEAN':
            return self.pick(('bool', name, ctx), 2) == 1
        if ty == 'INTEGER':
            nn = t.get('named-numbers')
            if nn:
                vals = sorted(nn.values())
                if r.random() < 0.1:
                    return 12345
                return vals[self.pick(('int', name, ctx), len(vals))]
            return [0, 1, 2, 3, 5, 10, 100, 127, 128, 1000, 65536, 70000, -1, -129, 1 << 31, 1 << 40][
                self.pick(('int', name), 16)]
        if ty == 'NULL':
            return None
        if ty == 'OCTET STRING':
            return bytes(r.randrange(256) for _ in range(r.randint(0, 12)))
        if ty == 'OBJECT IDENTIFIER':
            return self.oid_choice(ANY_OIDS)
        if ty in ('GeneralString', 'VisibleString'):
            if r.random() < 0.15:
                return ''
            return WORDS[self.pick('word', len(WORDS))] or self.printable()
        if ty == 'GeneralizedTime':
            return datetime.datetime(2026, 11, 12, 9, 15, 0, tzinfo=datetime.timezone.utc)
        if ty == 'ObjectDescriptor':
            return self.printable(1, 6)
        if ty == 'BIT STRING':
            nb = t.get('named-bits')
            if nb:
                defined = [int(b[1]) for b in nb]
                n = max(defined) + 1
                bits = [(i in defined) and r.random() < 0.6 for i in range(n)]
                if r.random() < 0.2:
                    bits = [i in defined for i in range(n)]
                data = bytearray((n + 7) // 8)
                for i, b in enumerate(bits):
                    if b:
                        data[i // 8] |= 0x80 >> (i % 8)
                return (bytes(data), n)
            n = r.choice([1, 8, 13, 16, 20])
            return (bytes(r.randrange(256) for _ in range((n + 7) // 8)), n)
        if ty in ('SEQUENCE', 'SET'):
            self.depth += 1
            out = {}
            for m in t['members']:
                if m is None:
                    continue
                if m['type'] == 'COMPONENTS OF':
                    continue
                opt = m.get('optional') or 'default' in m
                if opt:
                    if self.depth > self.maxdepth:
                        continue
                    if self.pick(('opt', ctx, m['name']), 3) == 0:
                        continue
                out[m['name']] = self.value(m, ctx + '/' + m['name'])
            self.depth -= 1
            return out
        if ty == 'CHOICE':
            alts = [m for m in t['members'] if m is not None]
            if self.depth > self.maxdepth:
                simple = [m for m in alts if self.resolve(m)['type'] in (
                    'NULL', 'BOOLEAN', 'INTEGER', 'GeneralString', 'VisibleString', 'OCTET STRING',
                    'OBJECT IDENTIFIER')]
                alts = simple or alts[:1]
            i = self.pick(('ch', ctx, name), len(alts))
            m = alts[i]
            self.depth += 1
            v = self.value(m, ctx + '/' + m['name'])
            self.depth -= 1
            return (m['name'], v)
        if ty in ('SEQUENCE OF', 'SET OF'):
            self.depth += 1
            n = self.pick(('n', ctx), 3) + (1 if self.depth <= self.maxdepth else 0)
            if self.depth > self.maxdepth:
                n = 0
            out = [self.value(t['element'], ctx + '/item') for _ in range(max(n, 1) if self.depth <= self.maxdepth else 0)]
            self.depth -= 1
            return out
        raise ValueError('unsupported ' + ty)

    # ---- externals
    def external(self, ctx):
        """Marker value for an EXTERNAL; the real one is built later."""
        idx = len(self.externals)
        if self.forced is not None and self.ext_depth == 0:
            oid, tn = SYNTAXES[self.forced]
        else:
            oid, tn = SYNTAXES[self.pick('syn', len(SYNTAXES))]
            if self.depth > 5 or self.ext_depth > 2:
                oid, tn = SYNTAXES[1]
        mode = 'single'
        extra = {}
        if tn is None and oid == OID_MARC21:
            inner = marc_record(self.marc_n)
            self.marc_n += 1
            mode = 'octet'
        elif tn is None:
            inner = tlv(0x04, b'private data')
        else:
            saved = (self.depth, self.ext_depth)
            self.ext_depth += 1
            self.depth = 0
            v = self.gen_top(tn)
            inner = self.encode(tn, v)
            self.depth, self.ext_depth = saved
        k = self.pick('extmode', 8)
        if k == 5:
            extra['indirect'] = 7
        if k == 7 and mode == 'single':
            mode = 'arbitrary'
        self.externals[idx] = (oid, inner, mode, extra)
        return {'marker': b'@@%d' % idx}

    def build_external(self, idx):
        oid, inner, mode, extra = self.externals[idx]
        c = b''
        if oid:
            c += oid_tlv(oid)
        if 'indirect' in extra:
            c += tlv(0x02, int_content(extra['indirect']))
        if 'descr' in extra:
            c += tlv(0x07, extra['descr'].encode())
        if mode == 'single':
            c += tlv(0xa0, inner)
        elif mode == 'octet':
            c += tlv(0x81, inner)
        else:
            c += tlv(0x82, b'\x00' + inner)
        return c

    def fix(self, nodes):
        for n in nodes:
            if n.cons:
                if (len(n.data) == 1 and not n.data[0].cons and n.data[0].tag == b'\x04' and
                        n.data[0].data.startswith(b'@@')):
                    idx = int(n.data[0].data[2:])
                    content = self.build_external(idx)
                    if n.tag == b'\x30':
                        n.tag = b'\x28'
                    n.data = parse(content)
                else:
                    self.fix(n.data)
        return nodes

    def gen_top(self, tn):
        t = dict(self.types[tn])
        t['name'] = ''
        last = None
        for _ in range(100):
            self.depth = 0
            try:
                v = self.value(t, tn)
                self.spec.encode(tn, v)
                return v
            except Exception as e:     # the encoder rejected a value: try again
                last = e
        raise RuntimeError('%s: %s' % (tn, last))

    def encode(self, tn, v):
        b = self.spec.encode(tn, v)
        nodes = parse(b)
        self.fix(nodes)
        return b''.join(ser(n) for n in nodes)

    def pdu(self, alt=None):
        """A random PDU; alt names a CHOICE alternative of PDU."""
        t = self.types['PDU']
        names = [m['name'] for m in t['members']]
        for _ in range(100):
            m = [x for x in t['members'] if x['name'] == alt][0]
            self.depth = 0
            try:
                v = (alt, self.value(m, alt))
                b = self.spec.encode('PDU', v)
                break
            except Exception as e:
                last = e
        else:
            raise RuntimeError('%s: %s' % (alt, last))
        nodes = parse(b)
        self.fix(nodes)
        return b''.join(ser(n) for n in nodes)

    def present_with(self, k, n=2, kind='presentResponse'):
        """A response whose records use syntax number k of SYNTAXES."""
        self.forced = k
        recs = []
        for i in range(n):
            self.depth = 0
            recs.append({'name': 'Default%d' % i, 'record': ('retrievalRecord', self.external('rec'))})
        self.forced = None
        if kind == 'presentResponse':
            v = ('presentResponse', {'numberOfRecordsReturned': n, 'nextResultSetPosition': 0,
                                     'presentStatus': 0, 'records': ('responseRecords', recs)})
        else:
            v = ('searchResponse', {'resultCount': n, 'numberOfRecordsReturned': n,
                                    'nextResultSetPosition': 1, 'searchStatus': True,
                                    'records': ('responseRecords', recs)})
        b = self.spec.encode('PDU', v)
        nodes = parse(b)
        self.fix(nodes)
        return b''.join(ser(x) for x in nodes)

    def pdu_names(self):
        return [m['name'] for m in self.types['PDU']['members']]


# ----------------------------------------------------------------- packets

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def tcp_pkt(payload, sport, dport, seq, ack, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    s = socket.inet_aton(src)
    d = socket.inet_aton(dst)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    ph = s + d + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + tcp


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)


class Conn:
    """One or more TCP connections to port 210 (client 192.0.2.1)."""

    def __init__(self):
        self.frames = []
        self.cport = 40000
        self.new_conn()
        self.ranges = []

    def new_conn(self, port=210):
        self.cport += 1
        self.port = port
        self.cseq = self.sseq = 5000

    def send(self, data, to_server=True, seg=None):
        pieces = [data] if not seg else [data[:seg], data[seg:]]
        for p in pieces:
            if not p:
                continue
            if to_server:
                self.frames.append(tcp_pkt(p, self.cport, self.port, self.cseq, self.sseq))
                self.cseq += len(p)
            else:
                self.frames.append(tcp_pkt(p, self.port, self.cport, self.sseq, self.cseq, 0x18,
                                           '192.0.2.2', '192.0.2.1'))
                self.sseq += len(p)

    def mark(self, name):
        self.ranges.append((name, len(self.frames) + 1))
        self.sizes = getattr(self, 'sizes', [])
        self.sizes.append(sum(len(f) for f in self.frames))


def is_request(name):
    return name.endswith('Request') or name in ('close',)


# ------------------------------------------------------------ handwritten PDUs

def rpn_term(text=b'term', attr=(1, 4)):
    """AttributesPlusTerm with bib-1 use/structure attributes."""
    attrs = b''.join(tlv(0x30, tlv(ctag(120, False), int_content(t)) +
                         tlv(ctag(121, False), int_content(v))) for t, v in
                     (attr, (5, 100), (3, 1)))
    return tlv(ctag(102), tlv(ctag(44), attrs) + tlv(ctag(45, False), text))


def rpn_op(kind=0):
    return tlv(ctag(46), tlv(ctag(kind, False), b''))


def rpn_nested(depth, leaf=None):
    """RPNStructure chain: depth levels of rpnRpnOp, left-nested."""
    node = tlv(ctag(0), leaf or rpn_term())
    for i in range(depth):
        node = tlv(ctag(1), node + tlv(ctag(0), rpn_term(b'x%d' % i)) + rpn_op(i % 3))
    return node


def search_request(rpn, ref=b'q1'):
    q = tlv(ctag(21), tlv(ctag(1), oid_tlv(OID_BIB1) + rpn))
    body = (tlv(ctag(2, False), ref) + tlv(ctag(13, False), b'\x00') + tlv(ctag(14, False), b'\x01') +
            tlv(ctag(15, False), b'\x00') + tlv(ctag(16, False), b'\x01') +
            tlv(ctag(17, False), b'default') +
            tlv(ctag(18), tlv(ctag(105, False), b'Default')) + q)
    return tlv(ctag(22), body)


def grs1_record(depth, with_subtrees=True):
    """GenericRecord: SEQUENCE OF TaggedElement, optionally nested subtrees."""
    def tagged(content):
        # TaggedElement: tagType [1] opt, tagValue [2] StringOrNumeric, tagOccurrence [3] opt,
        # content [4] ElementData
        return tlv(0x30, tlv(ctag(1, False), b'\x03') +
                   tlv(ctag(2), tlv(ctag(2, False), b'\x05')) + tlv(ctag(4), content))
    leaf = tlv(ctag(1, False), b'leaf string')           # ElementData: string [1]?
    node = leaf
    for _ in range(depth):
        node = tlv(ctag(8), tlv(0x30, tagged(node)))      # subtree
    return tlv(0x30, tagged(node))


def pretty(b):
    return b.hex()


# --------------------------------------------------------------------- main

def ext_marker(gen, oid, tn, value, mode='single', raw=None):
    """Register an EXTERNAL holding a record of type tn (or raw octets)."""
    inner = gen.encode(tn, value) if raw is None else raw
    idx = len(gen.externals)
    gen.externals[idx] = (oid, inner, mode, {})
    return {'marker': b'@@%d' % idx}


def present_pdu(gen, markers, kind='presentResponse'):
    recs = [{'name': 'Default', 'record': ('retrievalRecord', m)} for m in markers]
    if kind == 'presentResponse':
        v = ('presentResponse', {'numberOfRecordsReturned': len(recs), 'nextResultSetPosition': 0,
                                 'presentStatus': 0, 'records': ('responseRecords', recs)})
    else:
        v = ('searchResponse', {'resultCount': len(recs), 'numberOfRecordsReturned': len(recs),
                                'nextResultSetPosition': 1, 'searchStatus': True,
                                'records': ('responseRecords', recs)})
    return fixed(gen, 'PDU', v)


def fixed(gen, tn, v):
    nodes = parse(gen.spec.encode(tn, v))
    gen.fix(nodes)
    return b''.join(ser(n) for n in nodes)


def grs_nested(depth, ext=False):
    def te(content, name):
        return {'tagValue': ('string', name), 'content': content}
    node = ('string', 'leaf')
    for i in range(depth):
        node = ('subtree', [te(node, 'level%d' % i), te(('numeric', i), 'n%d' % i)])
    return [te(node, 'top')]


def explain_nested(depth):
    def info(name, dt):
        e = {'elementName': name, 'elementTagPath': [{'tagType': 1, 'tagValue': ('string', name)}],
             'required': True, 'repeatable': False}
        if dt is not None:
            e['dataType'] = dt
        return e
    dt = ('primitive', 4)
    for i in range(depth):
        dt = ('structured', [info('inner%d' % i, dt), info('sibling%d' % i, ('primitive', 1))])
    return ('schemaInfo', {'schema': '1.2.840.10003.13.1', 'name': 'nested',
                           'recordStructure': [info('root', dt)]})


def search_pdu(gen, rpn, qtype='type-1'):
    v = ('searchRequest', {
        'smallSetUpperBound': 0, 'largeSetLowerBound': 1, 'mediumSetPresentNumber': 0,
        'replaceIndicator': True, 'resultSetName': 'default', 'databaseNames': ['Default'],
        'query': (qtype, {'attributeSet': OID_BIB1, 'rpn': rpn})})
    return fixed(gen, 'PDU', v)


def operand(text, use=4):
    return ('op', ('attrTerm', {'attributes': [
        {'attributeType': 1, 'attributeValue': ('numeric', use)},
        {'attributeType': 2, 'attributeValue': ('numeric', 3)},
        {'attributeType': 3, 'attributeValue': ('numeric', 1)},
        {'attributeType': 4, 'attributeValue': ('numeric', 1)},
        {'attributeType': 5, 'attributeValue': ('numeric', 100)},
        {'attributeType': 6, 'attributeValue': ('numeric', 1)}],
        'term': ('general', text)}))


def rpn_value(depth):
    node = operand(b'start')
    ops = [('and', None), ('or', None), ('and-not', None),
           ('prox', {'exclusion': False, 'distance': 3, 'ordered': True, 'relationType': 2,
                     'proximityUnitCode': ('known', 2)}),
           ('prox', {'distance': 1, 'ordered': False, 'relationType': 3,
                     'proximityUnitCode': ('private', 9)})]
    for i in range(depth):
        node = ('rpnRpnOp', {'rpn1': node, 'rpn2': operand(b'term%d' % i, 1 + i % 5),
                             'op': ops[i % len(ops)]})
    return node


def build_main(gen):
    c = Conn()
    names = gen.pdu_names()
    more = {'initRequest': 5, 'initResponse': 2, 'searchRequest': 8, 'searchResponse': 3,
            'presentRequest': 6, 'scanRequest': 6, 'scanResponse': 10, 'sortRequest': 6,
            'sortResponse': 2, 'extendedServicesRequest': 6, 'extendedServicesResponse': 3,
            'deleteResultSetResponse': 2, 'accessControlResponse': 2, 'resourceControlRequest': 2,
            'resourceReportResponse': 2, 'close': 2, 'segmentRequest': 2}
    plan = []
    for rnd in range(3):
        plan += names
    for nm, k in more.items():
        plan += [nm] * k
    c.mark('generated PDUs: every type, then more of the ones with many alternatives')
    for i, nm in enumerate(plan):
        pdu = gen.pdu(nm)
        while len(pdu) < 8:        # see README: PDUs under 8 octets are not framed
            pdu = gen.pdu(nm)
        seg = None
        if i % 17 == 5 and len(pdu) > 20:
            seg = 9 + (i % 7)              # reassembly over two segments
        c.send(pdu, is_request(nm), seg)
    c.mark('presentResponse/searchResponse with records of every syntax (forced), Explain repeated')
    reps = {0: 36, 1: 2, 2: 12, 3: 4, 4: 10, 5: 14, 6: 90, 7: 4, 8: 3, 9: 3, 10: 4, 11: 3, 12: 8}
    for k, (oid, tn) in enumerate(SYNTAXES):
        for j in range(reps.get(k, 2)):
            gen.maxdepth = 14 if tn in ('Explain-Record', 'GenericRecord', 'TaskPackage') else 8
            pdu = gen.present_with(k, 1 + j % 3, 'presentResponse' if j % 2 else 'searchResponse')
            gen.maxdepth = 7
            c.send(pdu, False)
    c.mark('nesting: RPN queries of 0-3, 31 and 32 levels, GRS-1 subtrees, Explain structured types')
    for d in (0, 1, 2, 3, 31, 32):
        c.send(search_pdu(gen, rpn_value(d)), True)
    c.send(search_pdu(gen, rpn_value(2), 'type-101'), True)
    for d in (1, 2, 3, 31):
        m = ext_marker(gen, '1.2.840.10003.5.105', 'GenericRecord', grs_nested(d))
        c.send(present_pdu(gen, [m]), False)
    for d in (1, 2, 3, 31):
        m = ext_marker(gen, '1.2.840.10003.5.100', 'Explain-Record', explain_nested(d))
        c.send(present_pdu(gen, [m]), False)
    c.mark('targeted: dateTime/numeric/oid terms, CompSpec, scan response with occurrences per database')
    for term in (('dateTime', datetime.datetime(2026, 11, 12, 9, 15, 0, tzinfo=datetime.timezone.utc)), ('numeric', 42), ('oid', OID_BIB1), ('null', None),
                 ('characterString', 'text'), ('integerAndUnit', {'value': 3, 'unitUsed': {
                     'unitSystem': 'SI', 'unitType': ('string', 'mass'), 'unit': ('string', 'kg'),
                     'scaleFactor': 3}})):
        node = ('op', ('attrTerm', {'attributes': [{'attributeType': 1, 'attributeValue': (
            'complex', {'list': [('string', 'x'), ('numeric', 2)], 'semanticAction': [1, 2]})},
            {'attributeSet': OID_BIB1, 'attributeType': 2, 'attributeValue': ('numeric', 3)}],
            'term': term}))
        c.send(search_pdu(gen, node), True)
    pv = ('presentRequest', {
        'resultSetId': 'default', 'resultSetStartPoint': 1, 'numberOfRecordsRequested': 2,
        'additionalRanges': [{'startingPosition': 5, 'numberOfRecords': 2}],
        'recordComposition': ('complex', {
            'selectAlternativeSyntax': True,
            'generic': {'schema': '1.2.840.10003.13.1', 'elementSpec': ('elementSetName', 'F')},
            'dbSpecific': [{'db': 'Default', 'spec': {'elementSpec': ('elementSetName', 'B')}}],
            'recordSyntax': [OID_MARC21, '1.2.840.10003.5.101']}),
        'preferredRecordSyntax': OID_MARC21, 'maxSegmentCount': 4})
    c.send(fixed(gen, 'PDU', pv), True)
    sv = ('scanResponse', {
        'scanStatus': 0, 'numberOfEntriesReturned': 2, 'positionOfTerm': 1, 'stepSize': 1,
        'entries': {'entries': [
            ('termInfo', {'term': ('general', b'alpha'), 'displayTerm': 'Alpha',
                          'suggestedAttributes': [{'attributeType': 1, 'attributeValue': ('numeric', 4)}],
                          'alternativeTerm': [{'attributes': [{'attributeType': 1,
                                                               'attributeValue': ('numeric', 4)}],
                                               'term': ('general', b'alfa')}],
                          'globalOccurrences': 12,
                          'byAttributes': [{'attributes': [{'attributeType': 1,
                                                            'attributeValue': ('numeric', 4)}],
                                            'occurrences': ('byDatabase', [
                                                {'db': 'Default', 'num': 3},
                                                {'db': 'Other'}])},
                                           {'attributes': [{'attributeType': 2, 'attributeValue': ('numeric', 3)}],
                                            'occurrences': ('global', 7)}]}),
            ('surrogateDiagnostic', ('defaultFormat', {
                'diagnosticSetId': OID_DIAG_BIB1, 'condition': 1, 'addinfo': ('v2Addinfo', 'bad')}))]},
        'attributeSet': OID_BIB1})
    c.send(fixed(gen, 'PDU', sv), False)
    c.mark('several records in one response, two PDUs in one segment, PDU over three segments')
    ms = [ext_marker(gen, OID_MARC21, None, None, 'octet', marc_record(i)) for i in range(3)]
    ms.append(ext_marker(gen, '1.2.840.10003.5.101', 'SutrsRecord', 'Some SUTRS text\nline 2'))
    big = present_pdu(gen, ms)
    c.send(big, False, seg=len(big) // 3)
    c.send(big[:len(big) // 2], False)
    c.send(big[len(big) // 2:] + gen.pdu('close'), False)
    c.mark('NESTING PAST THE LIMIT (error expert info z3950.nesting_too_deep): RPN 33/34, GRS-1 33, Explain 33')
    c.send(search_pdu(gen, rpn_value(33)), True)
    c.send(search_pdu(gen, rpn_value(34)), True)
    c.send(present_pdu(gen, [ext_marker(gen, '1.2.840.10003.5.105', 'GenericRecord', grs_nested(33))]), False)
    c.send(present_pdu(gen, [ext_marker(gen, '1.2.840.10003.5.100', 'Explain-Record', explain_nested(33))]), False)
    return c


def marc_bad(kind):
    r = bytearray(marc_record(0))
    if kind == 'short':
        return bytes(r[:20])
    if kind == 'length_chars':
        r[0:5] = b'12a45'
    elif kind == 'length_mismatch':
        r[0:5] = b'00099'
    elif kind == 'indicator':
        r[10] = ord('x')
    elif kind == 'indicator3':
        r[10] = ord('3')
    elif kind == 'subfield':
        r[11] = ord('?')
    elif kind == 'subfield3':
        r[11] = ord('3')
    elif kind == 'offset_chars':
        r[12:17] = b'12x45'
    elif kind == 'offset_out':
        r[12:17] = b'00010'
    elif kind == 'offset_far':
        r[12:17] = b'00999'
    elif kind == 'fieldlen':
        r[20] = ord('z')
    elif kind == 'fieldlen3':
        r[20] = ord('3')
    elif kind == 'startlen':
        r[21] = ord('y')
    elif kind == 'startlen3':
        r[21] = ord('3')
    elif kind == 'tag_chars':
        r[24:27] = b'0x1'
    elif kind == 'dirlen_chars':
        r[27:31] = b'00x4'
    elif kind == 'dirstart_chars':
        r[31:36] = b'0000x'
    elif kind == 'dir_outside':
        r[27:31] = b'9999'
        r[31:36] = b'09999'
    elif kind == 'trailer':
        return bytes(r) + b'extra'
    elif kind == 'long_leader_only':
        return bytes(r[:24])
    return bytes(r)


def build_malformed(gen):
    c = Conn()
    c.mark('nesting past the limit of 32: RPN, GRS-1, Explain structured, the original 400 levels')
    for d in (35, 36, 40):
        c.send(search_pdu(gen, rpn_value(d)), True)
    c.send(search_pdu(gen, rpn_value(3), 'type-1'), True)
    deep = search_request(rpn_nested(400))
    c.send(deep, True)
    for d in (34, 36):
        m = ext_marker(gen, '1.2.840.10003.5.105', 'GenericRecord', grs_nested(d))
        c.send(present_pdu(gen, [m]), False)
    for d in (34, 36):
        m = ext_marker(gen, '1.2.840.10003.5.100', 'Explain-Record', explain_nested(d))
        c.send(present_pdu(gen, [m]), False)
    c.mark('MARC records with invalid fields')
    for kind in ('short', 'length_chars', 'length_mismatch', 'indicator', 'indicator3', 'subfield',
                 'subfield3', 'offset_chars', 'offset_out', 'offset_far', 'fieldlen', 'fieldlen3',
                 'startlen', 'startlen3', 'tag_chars', 'dirlen_chars', 'dirstart_chars',
                 'dir_outside', 'trailer', 'long_leader_only'):
        m = ext_marker(gen, OID_MARC21, None, None, 'octet', marc_bad(kind))
        c.send(present_pdu(gen, [m]), False)
    c.mark('framing: PDUs under 8 octets, a cut length field, an unknown PDU, trailing data')
    # a valid DeleteResultSetRequest of 6 octets: tcp_dissect_pdus wants 8 octets first
    c.send(bytes.fromhex('ba049f200101'), True)
    c.send(gen.pdu('searchRequest'), True)
    c.send(bytes.fromhex('ba049f200101'), True)
    c.send(gen.pdu('close'), False)
    c.send(bytes([0xb4, 0x8f, 1, 2, 3, 4, 5, 6]), True)   # length of length runs past the end
    c.send(tlv(ctag(50), b'\x01\x02\x03\x04\x05\x06\x07\x08'), True)   # [50] is not a PDU
    c.send(tlv(0x30, b'\x02\x01\x01' * 3), True)
    c.send(gen.pdu('close') + b'\x00\x00\x00\x00\x00\x00\x00\x00', False)
    # a search request with a type-0 query (ANY; not implemented in the dissector)
    q0 = tlv(ctag(21), tlv(ctag(0), tlv(0x04, b'any query data')))
    body = (tlv(ctag(13, False), b'\x00') + tlv(ctag(14, False), b'\x01') +
            tlv(ctag(15, False), b'\x00') + tlv(ctag(16, False), b'\x01') +
            tlv(ctag(17, False), b'default') + tlv(ctag(18), tlv(ctag(105, False), b'Default')) + q0)
    c.send(tlv(ctag(22), body), True)
    c.mark('truncated PDUs (reached without reassembly) and records cut short')
    p = search_pdu(gen, rpn_value(2))
    c.send(p[:len(p) - 7], True)
    pr = present_pdu(gen, [ext_marker(gen, '1.2.840.10003.5.100', 'Explain-Record', explain_nested(2))])
    c.send(pr[:len(pr) // 2], False)
    c.send(gen.pdu('initRequest')[:30], True)
    return c


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    g = Gen(1)
    m = build_main(g)
    write_pcap(os.path.join(out, 'z3950-coverage.pcap'), m.frames)
    if '-v' in sys.argv:
        for (name, a), sz in zip(m.ranges, m.sizes + [sum(len(f) for f in m.frames)][:0]):
            print('%3d-  %s (bytes so far %d)' % (a, name, sz))
        print(len(m.frames), 'frames')
    x = build_malformed(g)
    write_pcap(os.path.join(out, 'z3950-coverage-malformed.pcap'), x.frames)
    if '-v' in sys.argv:
        for name, a in x.ranges:
            print('%3d-  %s' % (a, name))
        print(len(x.frames), 'malformed frames')
