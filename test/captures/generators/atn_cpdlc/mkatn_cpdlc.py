#!/usr/bin/env python3
# Generates test/captures/atn_cpdlc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
# Build synthetic ATN CPDLC captures for epan/dissectors/packet-atn-cpdlc.c
# (ICAO Doc 9705 CPDLC, plain and protected mode). Every packet is built
# here with struct and a small unaligned-PER encoder that is driven by the
# ASN.1 module epan/dissectors/asn1/atn-cpdlc/atn-cpdlc.asn; nothing comes
# from a real network.
#
# Stack: Ethernet / LLC (FE FE 03) / CLNP (20-octet ATN NSAPs, NSEL 0x21)
# / COTP (CR, CC, DT) / ATN-ULCS (session+presentation+ACSE in CR/CC,
# PER Fully-encoded-data in DT) / ATN-CPDLC (unaligned PER).
#
# Usage: mkatn_cpdlc.py <outdir> [<path to atn-cpdlc.asn>]
# The ASN.1 file defaults to $WIRESHARK_SRC (or the tree this script is in)
# /epan/dissectors/asn1/atn-cpdlc/atn-cpdlc.asn.
import re
import struct
import sys


class Bits:
    def __init__(self):
        self.b = []

    def put(self, val, n):
        for i in range(n - 1, -1, -1):
            self.b.append((val >> i) & 1)
        return self

    def octets(self, data):
        for c in data:
            self.put(c, 8)
        return self

    def add(self, other):
        self.b += other.b
        return self

    def padded(self):
        return self.b + [0] * (-len(self.b) % 8)

    def bytes_(self):
        b = self.padded()
        return bytes(int(''.join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


def nbits(rng):
    """Bits of a constrained whole number with 'rng' values (X.691 10.5)."""
    if rng <= 1:
        return 0
    return (rng - 1).bit_length()


# ---------------------------------------------------------------- ASN.1 parser
#
# Just enough of X.680 for this module: CHOICE, SEQUENCE (OPTIONAL,
# DEFAULT, extension marker and additions), SEQUENCE SIZE () OF,
# ENUMERATED, INTEGER (lb..ub), IA5String / NumericString (SIZE ()),
# BIT STRING [(SIZE (n))], NULL, RELATIVE-OID and type references.

TOKEN = re.compile(r'\s*(::=|\.\.\.|\.\.|[{}()\[\],;]|-?\d+|[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)')


def tokenize(text):
    text = '\n'.join(re.sub(r'--.*?(--|$)', ' ', line) for line in text.splitlines())
    toks, pos = [], 0
    while True:
        m = TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip():
                raise ValueError('cannot tokenize at %r' % text[pos:pos + 40])
            return toks
        toks.append(m.group(1))
        pos = m.end()


class Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def take(self, want=None):
        tok = self.t[self.i]
        if want is not None and tok != want:
            raise ValueError('expected %s, got %s at %d' % (want, tok, self.i))
        self.i += 1
        return tok

    def module(self, types):
        while self.peek() is not None:
            if self.peek(1) == 'DEFINITIONS':
                while self.take() != 'BEGIN':
                    pass
            elif self.peek() == 'IMPORTS':
                while self.take() != ';':
                    pass
            elif self.peek() == 'END':
                self.take()
            else:
                name = self.take()
                self.take('::=')
                types[name] = self.type_()

    def range_(self):
        lb = int(self.take())
        if self.peek() == '..':
            self.take()
            return lb, int(self.take())
        return lb, lb

    def size(self):
        self.take('SIZE')
        self.take('(')
        r = self.range_()
        self.take(')')
        return r

    def elements(self, named=True):
        """{ element, ..., element } -> (root, ext_marker, additions)."""
        self.take('{')
        root, adds, ext = [], [], False
        while self.peek() != '}':
            if self.peek() == '...':
                self.take()
                ext = True
            else:
                (adds if ext else root).append(self.element() if named else self.enum_item())
            if self.peek() == ',':
                self.take()
        self.take('}')
        return root, ext, adds

    def enum_item(self):
        name = self.take()
        self.take('(')
        v = int(self.take())
        self.take(')')
        return name, v

    def element(self):
        name = self.take()
        if self.peek() == '[':
            self.take('[')
            self.take()
            self.take(']')
        typ = self.type_()
        opt = None
        if self.peek() == 'OPTIONAL':
            self.take()
            opt = 'OPTIONAL'
        elif self.peek() == 'DEFAULT':
            self.take()
            self.take()
            opt = 'DEFAULT'
        return name, typ, opt

    def type_(self):
        tok = self.take()
        if tok == 'CHOICE':
            root, ext, adds = self.elements()
            return ('choice', root, ext, adds)
        if tok == 'SEQUENCE':
            if self.peek() == 'SIZE':
                lb, ub = self.size()
                self.take('OF')
                return ('seqof', lb, ub, self.type_())
            root, ext, adds = self.elements()
            return ('seq', root, ext, adds)
        if tok == 'ENUMERATED':
            root, ext, adds = self.elements(named=False)
            return ('enum', root, ext, adds)
        if tok == 'INTEGER':
            self.take('(')
            lb, ub = self.range_()
            self.take(')')
            return ('int', lb, ub)
        if tok in ('IA5String', 'NumericString'):
            self.take('(')
            lb, ub = self.size()
            self.take(')')
            return ('ia5' if tok == 'IA5String' else 'numeric', lb, ub)
        if tok == 'BIT':
            self.take('STRING')
            if self.peek() == '(':
                self.take('(')
                lb, ub = self.size()
                self.take(')')
                return ('bitstr', lb, ub)
            return ('bitstr', None, None)
        if tok == 'NULL':
            return ('null',)
        if tok == 'RELATIVE-OID':
            return ('reloid',)
        return ('ref', tok)


def load_types(path):
    with open(path) as f:
        types = {}
        Parser(tokenize(f.read())).module(types)
    return types


# ---------------------------------------------------------------- PER encoder

def length_det(w, n):
    """Unconstrained length determinant (X.691 10.9, unaligned)."""
    if n < 128:
        w.put(n, 8)
    elif n < 16384:
        w.put(2, 2).put(n, 14)
    else:
        raise ValueError('fragmentation not supported')
    return w


def open_type(w, inner):
    data = inner.bytes_() or b'\x00'
    length_det(w, len(data)).octets(data)
    return w


def ext_index(w, idx):
    """Normally small non-negative whole number (X.691 10.6)."""
    if idx < 64:
        return w.put(0, 1).put(idx, 6)
    raise ValueError('large extension index')


CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'


class Encoder:
    """Encodes values of the module in unaligned PER. Values are chosen
    so that repeated encodings walk through every CHOICE alternative and
    every ENUMERATED value, and alternately include all OPTIONAL/DEFAULT
    fields (with SEQUENCE OF at the upper size, capped) and none of them.
    'pick' can force the alternative of a named CHOICE once."""

    def __init__(self, types):
        self.types = types
        self.count = {}
        self.forced = {}
        self.textn = 0
        self.hits = set()

    def next(self, key, n):
        c = self.count.get(key, 0)
        self.count[key] = c + 1
        return c % n

    def text(self, n):
        s = ''.join(CHARS[(self.textn + i) % len(CHARS)] for i in range(n))
        self.textn += 1
        return s

    def enc(self, typ, key='', w=None):
        w = Bits() if w is None else w
        kind = typ[0]
        if kind == 'ref':
            name = typ[1]
            return self.enc(self.types[name], name, w)
        if kind == 'choice':
            _, root, ext, adds = typ
            if key in self.forced:
                idx = self.forced.pop(key)
            else:
                idx = self.next(key, len(root) + len(adds))
            self.hits.add((key, idx))
            if idx < len(root):
                if ext:
                    w.put(0, 1)
                w.put(idx, nbits(len(root)))
                return self.enc(root[idx][1], key + '.' + root[idx][0], w)
            w.put(1, 1)
            ext_index(w, idx - len(root))
            return open_type(w, self.enc(adds[idx - len(root)][1], key + '+', Bits()))
        if kind == 'seq':
            _, root, ext, adds = typ
            full = self.next(key, 2) == 0
            if ext:
                w.put(0, 1)
            for _, _, opt in root:
                if opt:
                    w.put(1 if full else 0, 1)
            for name, t, opt in root:
                if opt is None or full:
                    self.enc(t, key + '.' + name, w)
            return w
        if kind == 'seqof':
            _, lb, ub, t = typ
            if lb == ub:
                n = lb
            else:
                n = min(ub, lb + 1) if self.next(key + '#', 2) == 0 else lb
                w.put(n - lb, nbits(ub - lb + 1))
            for _ in range(n):
                self.enc(t, key + '[]', w)
            return w
        if kind == 'enum':
            _, root, ext, adds = typ
            idx = self.next(key, len(root))
            if ext:
                w.put(0, 1)
            return w.put(idx, nbits(len(root)))
        if kind == 'int':
            _, lb, ub = typ
            v = (lb, ub, (lb + ub) // 2)[self.next(key, 3)]
            return w.put(v - lb, nbits(ub - lb + 1))
        if kind == 'ia5':
            _, lb, ub = typ
            n = min(ub, max(lb, 4 + self.next(key + '#', 3)))
            if lb != ub:
                w.put(n - lb, nbits(ub - lb + 1))
            for c in self.text(n):
                w.put(ord(c), 7)
            return w
        if kind == 'numeric':
            _, lb, ub = typ
            n = lb
            if lb != ub:
                w.put(n - lb, nbits(ub - lb + 1))
            for c in '1215' + '0' * (n - 4):
                w.put(' 0123456789'.index(c), 4)
            return w
        if kind == 'bitstr':
            _, lb, ub = typ
            if lb is not None and lb == ub:
                return w.put(0x4ca5a5 & ((1 << lb) - 1), lb)
            length_det(w, 16)
            return w.put(0xbeef, 16)
        if kind == 'null':
            return w
        if kind == 'reloid':
            return w.put(1, 8).put(1, 8)
        raise ValueError(kind)

    # helpers for the hand-built parts

    def choice(self, typename, alt_name, body=None, w=None):
        """Encode alternative 'alt_name' of the named CHOICE type, with an
        explicit body or a generated one."""
        w = Bits() if w is None else w
        _, root, ext, adds = self.types[typename]
        names = [a[0] for a in root]
        idx = names.index(alt_name)
        if ext:
            w.put(0, 1)
        w.put(idx, nbits(len(root)))
        if body is None:
            body = self.enc(root[idx][1], typename + '.' + alt_name)
        return w.add(body)

    def unknown_alt(self, typename, idx, content=b'\x5a'):
        """An extension alternative that the module does not define."""
        _, root, ext, adds = self.types[typename]
        assert ext
        w = Bits().put(1, 1)
        ext_index(w, idx)
        return length_det(w, len(content)).octets(content)

    def enum_value(self, typename, v):
        _, root, ext, adds = self.types[typename]
        w = Bits()
        if v < len(root):
            if ext:
                w.put(0, 1)
            return w.put(v, nbits(len(root)))
        assert ext
        w.put(1, 1)
        return ext_index(w, v - len(root))


def header(e, msgid, ref=None, ack=None, dt=(2026, 10, 29, 12, 34, 56)):
    """ATCMessageHeader: messageRefNumber OPTIONAL, logicalAck DEFAULT."""
    w = Bits()
    w.put(0 if ref is None else 1, 1).put(0 if ack is None else 1, 1)
    w.put(msgid, 6)
    if ref is not None:
        w.put(ref, 6)
    y, mo, d, h, mi, s = dt
    w.put(y - 1996, 7).put(mo - 1, 4).put(d - 1, 5).put(h, 5).put(mi, 6).put(s, 6)
    if ack is not None:
        w.put(ack, 1)
    return w


def msg_data(e, direction, elems, route=None):
    """ATC{Up,Down}linkMessageData. elems are (index, body Bits) pairs of
    the element id CHOICE, route the constrainedData: None (absent), []
    (present, no routeClearanceData) or a list of RouteClearance Bits."""
    choice = 'ATCUplinkMsgElementId' if direction == 'up' else 'ATCDownlinkMsgElementId'
    _, root, ext, adds = e.types[choice]
    w = Bits().put(0 if route is None else 1, 1)
    w.put(len(elems) - 1, 3)                     # SIZE (1..5)
    for idx, body in elems:
        if idx < len(root):
            w.put(0, 1).put(idx, nbits(len(root))).add(body)
        else:
            w.put(1, 1)
            ext_index(w, idx - len(root))
            open_type(w, body)
    if route is not None:
        w.put(0, 1)                              # constrainedData extension bit
        w.put(1 if route else 0, 1)              # routeClearanceData
        if route:
            w.put(len(route) - 1, 1)             # SIZE (1..2)
            for r in route:
                w.add(r)
    return w


def atc_message(e, direction, msgid, elems, ref=None, ack=None, route=None):
    return header(e, msgid, ref, ack).add(msg_data(e, direction, elems, route))


def element_list(e, direction, rounds=1):
    """(index, body) for every element id alternative of the direction,
    'rounds' times (each round walks further through the choices)."""
    choice = 'ATCUplinkMsgElementId' if direction == 'up' else 'ATCDownlinkMsgElementId'
    _, root, ext, adds = e.types[choice]
    alts = root + adds
    out = []
    for _ in range(rounds):
        for idx, (name, t, _) in enumerate(alts):
            out.append((idx, e.enc(t, choice + '.' + name)))
    return out


def bitstring_of(w, payload):
    """Unconstrained BIT STRING holding the octets of 'payload' Bits."""
    return length_det(w, len(payload.padded())).add(Bits().put(0, 0)).octets(payload.bytes_())


# ---------------------------------------------------------------- ATN-ULCS

def pdv(ctx, payload):
    """Fully-encoded-data with one PDV-list, arbitrary encoding."""
    w = Bits()
    w.put(0, 1)                    # SIZE (1, ...): root, size 1 -> no length
    w.put(0, 1)                    # transfer-syntax-name absent
    w.put(0, 1).put(ctx - 1, 7)    # presentation-context-identifier (1..127, ...)
    w.put(2, 2)                    # arbitrary
    pb = payload.padded()
    length_det(w, len(pb))
    w.b += pb
    return w.bytes_()


def oid_bits(w, oid=bytes([0x2b, 0x1b, 0x03, 0x01])):
    w.put(len(oid), 8).octets(oid)


def user_info(w, payload):
    """Association-information with one EXTERNALt, arbitrary encoding."""
    w.put(0, 1)                    # SIZE (1, ...): root, size 1
    w.put(0, 3)                    # no direct/indirect reference, no descriptor
    w.put(2, 2)                    # encoding: arbitrary
    pb = payload.padded()
    length_det(w, len(pb))
    w.b += pb


def aarq(qual=None, payload=None):
    w = Bits()
    w.put(0, 1).put(0, 3)          # ACSE-apdu: ext 0, aarq
    w.put(0, 1)                    # AARQ ext bit
    bm = [0] * 15
    if qual is not None:
        bm[6] = 1                  # calling-AE-qualifier
    if payload is not None:
        bm[14] = 1                 # user-information
    for x in bm:
        w.put(x, 1)
    oid_bits(w)
    if qual is not None:
        w.put(0, 1).put(0, 1)      # AE-qualifier ext 0, form2
        w.put(1, 8).put(qual, 8)   # unconstrained INTEGER, 1 octet
    if payload is not None:
        user_info(w, payload)
    return w


def aare(payload=None, result=0):
    w = Bits()
    w.put(0, 1).put(1, 3)          # ACSE-apdu: ext 0, aare
    w.put(0, 1)                    # AARE ext bit
    bm = [0] * 11
    if payload is not None:
        bm[10] = 1                 # user-information
    for x in bm:
        w.put(x, 1)
    oid_bits(w)
    w.put(0, 1).put(result, 2)     # result (0..2, ...)
    w.put(0, 1)                    # result-source-diagnostic: acse-service-user
    w.put(0, 1).put(0, 4)          # null (0..14, ...)
    if payload is not None:
        user_info(w, payload)
    return w


def rlrq():
    return Bits().put(0, 1).put(2, 3).put(0, 1).put(1, 1).put(0, 1).put(0, 1).put(0, 2)


def rlre():
    return Bits().put(0, 1).put(3, 3).put(0, 1).put(1, 1).put(0, 1).put(0, 1).put(0, 2)


def spdu(first, second, acse):
    return bytes([first, second]) + acse.bytes_()


# ---------------------------------------------------------------- frames

def air_nsap(ars):
    # VER 0xc1 (all mobile ATSC), ARS = 24-bit aircraft address
    return bytes([0x47, 0x00, 0x27, 0xc1, 0x45, 0x55, 0x52, 0x00]) + ars.to_bytes(3, 'big') + \
        bytes([0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x21])


def gnd_nsap(n=1):
    # VER 0x81 (all fixed ATSC); last octet is the NSEL (0x21, transport)
    return bytes([0x47, 0x00, 0x27, 0x81, 0x45, 0x55, 0x52, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00,
                  0x20, 0x00, 0x00, 0x00, 0x02, n, 0x21])


def eth_clnp(src, dst, cotp):
    hdr_len = 9 + 1 + len(dst) + 1 + len(src)
    clnp = bytes([0x81, hdr_len, 1, 0x1e, 0x1c]) + struct.pack('>HH', hdr_len + len(cotp), 0)
    clnp += bytes([len(dst)]) + dst + bytes([len(src)]) + src + cotp
    llc = b'\xfe\xfe\x03' + clnp
    return b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + struct.pack('>H', len(llc)) + llc


def dt(src, dst, dstref, nr, payload):
    return eth_clnp(src, dst, bytes([4, 0xf0]) + struct.pack('>H', dstref) + bytes([0x80 | (nr & 0x7f)]) + payload)


def cr(src, dst, srcref, payload):
    return eth_clnp(src, dst, bytes([6, 0xe0, 0, 0]) + struct.pack('>H', srcref) + b'\x40' + payload)


def cc(src, dst, dstref, srcref, payload):
    return eth_clnp(src, dst, bytes([6, 0xd0]) + struct.pack('>HH', dstref, srcref) + b'\x40' + payload)


class Conn:
    """A COTP connection between one aircraft and one ground system.
    Downlink DTs carry the ground reference, uplink DTs the aircraft one."""

    def __init__(self, ars, gnd, aref, gref):
        self.air, self.gnd, self.aref, self.gref = air_nsap(ars), gnd, aref, gref
        self.nd = self.nu = 0

    def down(self, payload):
        p = dt(self.air, self.gnd, self.gref, self.nd, payload)
        self.nd += 1
        return p

    def up(self, payload):
        p = dt(self.gnd, self.air, self.aref, self.nu, payload)
        self.nu += 1
        return p

    def cr(self, payload):
        return cr(self.air, self.gnd, self.aref, payload)

    def cc(self, payload):
        return cc(self.gnd, self.air, self.aref, self.gref, payload)


# ---------------------------------------------------------------- CPDLC PDUs

class Cpdlc:
    def __init__(self, e):
        self.e = e
        self.msgid = 0

    def mid(self):
        self.msgid = (self.msgid + 1) % 64
        return self.msgid

    def atc(self, direction, elems, ref=None, ack=None, route=None):
        return atc_message(self.e, direction, self.mid(), elems, ref, ack, route)

    def route_clearance(self, full=True):
        """A RouteClearance with every optional field (or none)."""
        e = self.e
        if full:
            e.count['RouteClearance'] = 0
            e.count['RouteInformationAdditional'] = 0
        else:
            e.count['RouteClearance'] = 1
        return e.enc(('ref', 'RouteClearance'))

    # plain mode
    def ground(self, alt, body):
        return self.e.choice('GroundPDUs', alt, body)

    def aircraft(self, alt, body):
        return self.e.choice('AircraftPDUs', alt, body)

    # protected mode
    def prot_message(self, direction, msg=None, algid=None, integrity=b'\xa5\xa5\x0f\xf0'):
        """Protected{Uplink,Downlink}Message: extension bit, the two
        OPTIONAL bits, algorithmIdentifier (RELATIVE-OID), protectedMessage
        (CPDLCMessage BIT STRING with a PER ATC message), integrityCheck."""
        w = Bits().put(0, 1)
        w.put(0 if algid is None else 1, 1).put(0 if msg is None else 1, 1)
        if algid is not None:
            length_det(w, len(algid)).octets(algid)
        if msg is not None:
            bitstring_of(w, msg)
        length_det(w, len(integrity) * 8).octets(integrity)
        return w


def forward_message(e, c, up):
    """ATCForwardMessage: header (date/time, flight id, aircraft address)
    and the PER encoded message data as a BIT STRING."""
    w = Bits()
    w.put(2026 - 1996, 7).put(9, 4).put(28, 5).put(23, 5).put(59, 6).put(59, 6)
    flight = 'KLM1234'
    w.put(len(flight) - 2, 3)
    for ch in flight:
        w.put(ord(ch), 7)
    w.put(0x4ca001, 24)
    data = msg_data(e, 'up' if up else 'down', element_list_small(e, up))
    w.put(0 if up else 1, 1)
    return bitstring_of(w, data)


def element_list_small(e, up):
    d = 'up' if up else 'down'
    choice = 'ATCUplinkMsgElementId' if up else 'ATCDownlinkMsgElementId'
    _, root, _, _ = e.types[choice]
    return [(i, e.enc(root[i][1], choice + '.' + root[i][0])) for i in (0, 6, 20)]


def all_choice_alts(e):
    """(type name, index) of every alternative of every named CHOICE."""
    return {(name, i) for name, t in e.types.items() if t[0] == 'choice' and name not in HAND_BUILT
            for i in range(len(t[1]) + len(t[3]))}


# CHOICE types encoded by hand (PDUs, element ids) rather than by Encoder.enc
HAND_BUILT = {'GroundPDUs', 'AircraftPDUs', 'ProtectedGroundPDUs', 'ProtectedAircraftPDUs',
              'UplinkMessage', 'DownlinkMessage', 'ForwardMessage',
              'ATCUplinkMsgElementId', 'ATCDownlinkMsgElementId'}


def fill_missing(e, tries=40):
    """Extra uplink and downlink elements and route clearances that reach
    CHOICE alternatives the earlier encodings did not (round robin can
    keep missing an alternative of a choice that is only reached through
    another choice). Returns (up elements, down elements, routes)."""
    cands = []
    for direction in ('up', 'down'):
        choice = 'ATCUplinkMsgElementId' if direction == 'up' else 'ATCDownlinkMsgElementId'
        _, root, ext, adds = e.types[choice]
        cands += [(direction, idx, t, choice + '.' + name) for idx, (name, t, _) in enumerate(root + adds)]
    cands.append(('route', None, ('ref', 'RouteClearance'), ''))
    out = {'up': [], 'down': [], 'route': []}
    for _ in range(tries):
        if not all_choice_alts(e) - e.hits:
            break
        for kind, idx, t, key in cands:
            before = len(all_choice_alts(e) - e.hits)
            body = e.enc(t, key)
            if len(all_choice_alts(e) - e.hits) < before:
                out[kind].append(body if kind == 'route' else (idx, body))
    return out['up'], out['down'], out['route']


def chunks(lst, n):
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def build_main(e):
    pkts = []
    G = gnd_nsap(1)
    c = Cpdlc(e)
    ROUTE_FULL = [c.route_clearance(True), c.route_clearance(True)]
    ROUTE_MIN = [c.route_clearance(False)]
    nul = Bits()

    # ---------------------------------------------------------------
    # A. Plain CPDLC: AARQ calling-AE-qualifier 2 (cpdlc) in a DT with an
    # AircraftPDUs startdown in the user-information; AARE with a
    # GroundPDUs startup. ATN-ULCS hands everything to ATN-CPDLC.
    a = Conn(0x4ca001, G, 0x0101, 0x0201)
    sd = Bits().put(0, 1).add(e.choice('DownlinkMessage', 'aTCDownlinkMessage',
                                         c.atc('down', [(0, nul)])))
    pkts.append(a.down(pdv(1, aarq(qual=2, payload=c.aircraft('startdown', sd)))))
    su = e.choice('UplinkMessage', 'aTCUplinkMessage', c.atc('up', [(3, nul)], ref=1))
    pkts.append(a.up(pdv(1, aare(payload=c.ground('startup', su)))))
    # downlink: abort reasons (all root values and one extension value)
    for v in range(8):
        pkts.append(a.down(pdv(3, c.aircraft('abortUser', e.enum_value('CPDLCUserAbortReason', v)))))
    for v in range(9):
        pkts.append(a.down(pdv(3, c.aircraft('abortProvider', e.enum_value('CPDLCProviderAbortReason', v)))))
    # startdown: mode absent / mode dsc, noMessage / message
    pkts.append(a.down(pdv(3, c.aircraft('startdown', Bits().put(0, 1).add(
        e.choice('DownlinkMessage', 'noMessage', nul))))))
    pkts.append(a.down(pdv(3, c.aircraft('startdown', Bits().put(1, 1).put(1, 1).add(
        e.choice('DownlinkMessage', 'aTCDownlinkMessage', c.atc('down', [(1, nul)], ref=5, ack=0)))))))
    # send: every downlink element, five per message, with and without
    # constrained data
    for i, ch in enumerate(chunks(element_list(e, 'down', 2), 5)):
        route = [None, [], ROUTE_MIN, ROUTE_FULL][i % 4] if i < 8 else None
        pkts.append(a.down(pdv(3, c.aircraft('send', c.atc('down', ch, ref=i % 64 if i % 2 else None,
                                                         ack=i % 2 if i % 3 == 0 else None, route=route)))))
    pkts.append(a.down(pdv(3, e.unknown_alt('AircraftPDUs', 0))))
    # uplink
    for v in range(8):
        pkts.append(a.up(pdv(3, c.ground('abortUser', e.enum_value('CPDLCUserAbortReason', v)))))
    for v in range(9):
        pkts.append(a.up(pdv(3, c.ground('abortProvider', e.enum_value('CPDLCProviderAbortReason', v)))))
    pkts.append(a.up(pdv(3, c.ground('startup', e.choice('UplinkMessage', 'noMessage', nul)))))
    for i, ch in enumerate(chunks(element_list(e, 'up', 2), 5)):
        route = [None, [], ROUTE_MIN, ROUTE_FULL][i % 4] if i < 8 else None
        pkts.append(a.up(pdv(3, c.ground('send', c.atc('up', ch, ref=i % 64 if i % 2 else None,
                                                     ack=i % 2 if i % 3 == 0 else None, route=route)))))
    # elements that reach the remaining CHOICE alternatives
    fill_up, fill_down, fill_route = fill_missing(e)
    for ch in chunks(fill_up, 5):
        pkts.append(a.up(pdv(3, c.ground('send', c.atc('up', ch)))))
    for ch in chunks(fill_down, 5):
        pkts.append(a.down(pdv(3, c.aircraft('send', c.atc('down', ch)))))
    for ch in chunks(fill_route, 2):
        pkts.append(a.up(pdv(3, c.ground('send', c.atc('up', [(0, nul)], route=ch)))))
    pkts.append(a.up(pdv(3, c.ground('forward', forward_message(e, c, True)))))
    pkts.append(a.up(pdv(3, c.ground('forward', forward_message(e, c, False)))))
    for v in range(4):
        pkts.append(a.up(pdv(3, c.ground('forwardresponse', e.enum_value('ATCForwardResponse', v)))))
    pkts.append(a.up(pdv(3, e.unknown_alt('GroundPDUs', 0))))
    pkts.append(a.down(pdv(1, rlrq())))
    pkts.append(a.up(pdv(1, rlre())))

    # ---------------------------------------------------------------
    missing = all_choice_alts(e) - e.hits
    if missing:
        raise SystemExit('CHOICE alternatives not reached: %s' % sorted(missing))

    # ---------------------------------------------------------------
    # B. Protected mode CPDLC: AARQ calling-AE-qualifier 22 (pmcpdlc).
    b = Conn(0x4ca002, G, 0x0102, 0x0202)
    psd = Bits().put(0, 1).add(c.prot_message('down', c.atc('down', [(0, nul)]), algid=b'\x01'))
    pkts.append(b.down(pdv(1, aarq(qual=22, payload=e.choice('ProtectedAircraftPDUs', 'startdown', psd)))))
    psu = c.prot_message('up', c.atc('up', [(3, nul)], ref=1), algid=b'\x01')
    pkts.append(b.up(pdv(1, aare(payload=e.choice('ProtectedGroundPDUs', 'startup', psu)))))
    for v in range(14):
        pkts.append(b.down(pdv(3, e.choice('ProtectedAircraftPDUs', 'abortUser',
                                           e.enum_value('PMCPDLCUserAbortReason', v)))))
    for v in range(9):
        pkts.append(b.down(pdv(3, e.choice('ProtectedAircraftPDUs', 'abortProvider',
                                           e.enum_value('PMCPDLCProviderAbortReason', v)))))
    # startdown: mode absent, no optionals; mode dsc, algorithm identifier
    # {9 1} and a message
    pkts.append(b.down(pdv(3, e.choice('ProtectedAircraftPDUs', 'startdown',
                                       Bits().put(0, 1).add(c.prot_message('down'))))))
    pkts.append(b.down(pdv(3, e.choice('ProtectedAircraftPDUs', 'startdown', Bits().put(1, 1).put(1, 1).add(
        c.prot_message('down', c.atc('down', [(2, nul)]), algid=b'\x09\x01'))))))
    for i, ch in enumerate(chunks(element_list(e, 'down', 1), 5)):
        route = [None, ROUTE_FULL][i % 2] if i < 4 else None
        pkts.append(b.down(pdv(3, e.choice('ProtectedAircraftPDUs', 'send', c.prot_message(
            'down', c.atc('down', ch, route=route), algid=b'\x01' if i % 2 else None)))))
    pkts.append(b.down(pdv(3, e.unknown_alt('ProtectedAircraftPDUs', 0))))
    for v in range(14):
        pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'abortUser',
                                         e.enum_value('PMCPDLCUserAbortReason', v)))))
    for v in range(9):
        pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'abortProvider',
                                         e.enum_value('PMCPDLCProviderAbortReason', v)))))
    # clean versions of the AlgorithmIdentifier reproducer: startup with
    # only algorithmIdentifier {1}, and with a protected message too
    pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'startup',
                                     c.prot_message('up', algid=b'\x01', integrity=b'\xaa')))))
    pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'startup', c.prot_message(
        'up', c.atc('up', [(1, nul)]), algid=b'\x01', integrity=b'\xaa')))))
    for i, ch in enumerate(chunks(element_list(e, 'up', 1), 5)):
        route = [None, ROUTE_FULL][i % 2] if i < 4 else None
        pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'send', c.prot_message(
            'up', c.atc('up', ch, route=route), algid=b'\x81\x00' if i % 2 else None)))))
    pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'forward', forward_message(e, c, True)))))
    pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'forward', forward_message(e, c, False)))))
    for v in range(4):
        pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'forwardresponse',
                                         e.enum_value('ATCForwardResponse', v)))))
    pkts.append(b.up(pdv(3, e.unknown_alt('ProtectedGroundPDUs', 0))))
    return pkts, c, G


def build_conversations(e, c, G):
    """Frames that exercise how ATN-CPDLC is reached: heuristics in DT,
    CR and CC, direct calls in CR and CC, no conversation, ground to
    ground."""
    pkts = []
    nul = Bits()
    plain_down = c.aircraft('send', c.atc('down', [(0, nul)]))
    plain_up = c.ground('send', c.atc('up', [(0, nul)]))
    # For the heuristic, plain PDUs that the protected-mode trial decode
    # rejects by running out of data (a startdown/startup without a
    # message: the protected form needs an integrityCheck).
    # (The downlink one with mode dsc, so that ATN-CM rejects it too.)
    heur_plain_down = c.aircraft('startdown', Bits().put(1, 1).put(1, 1).add(
        e.choice('DownlinkMessage', 'noMessage', nul)))
    heur_plain_up = c.ground('startup', e.choice('UplinkMessage', 'noMessage', nul))
    prot_down = e.choice('ProtectedAircraftPDUs', 'send',
                         c.prot_message('down', c.atc('down', [(0, nul)]), algid=b'\x01'))
    prot_up = e.choice('ProtectedGroundPDUs', 'send',
                       c.prot_message('up', c.atc('up', [(0, nul)]), algid=b'\x01'))
    HEUR = {'plain_down': heur_plain_down, 'plain_up': heur_plain_up,
            'prot_down': prot_down, 'prot_up': prot_up}

    # H. AARQ without qualifier and AARE, then CM PDUs (downlink
    # cmContactResponse, uplink cmForwardResponse 2) on which both CPDLC
    # trial decodes run out of data, so ATN-CPDLC declines and ATN-CM
    # takes them. ATN-ULCS moves the last heuristic that succeeded to the
    # front of its list, so the uplink one comes after CPDLC heuristic
    # frames, where the CPDLC heuristic is tried first again.
    m = Conn(0x4cb014, G, 0x0124, 0x0224)
    pkts.append(m.down(pdv(1, aarq())))
    pkts.append(m.up(pdv(1, aare())))
    pkts.append(m.down(pdv(3, Bits().put(0, 1).put(1, 2).put(1, 1))))
    # C. AARQ without an AE qualifier, then a CPDLC PDU found by the
    # heuristic (marks the conversation plain or protected), then a PDU
    # passed directly. One connection per kind.
    for n, (kind, first) in enumerate(HEUR.items()):
        k = Conn(0x4cb000 + n, G, 0x0110 + n, 0x0210 + n)
        pkts.append(k.down(pdv(1, aarq())))
        pkts.append(k.up(pdv(1, aare())))
        second = HEUR['prot_' + kind.split('_')[1]] if kind.startswith('prot') else \
            (plain_down if kind.endswith('down') else plain_up)
        if kind.endswith('down'):
            pkts.append(k.down(pdv(3, first)))
            pkts.append(k.down(pdv(3, second)))
        else:
            pkts.append(k.up(pdv(3, first)))
            pkts.append(k.up(pdv(3, second)))

    # H (uplink).
    m = Conn(0x4cb015, G, 0x0125, 0x0225)
    pkts.append(m.down(pdv(1, aarq())))
    pkts.append(m.up(pdv(1, aare())))
    pkts.append(m.up(pdv(3, Bits().put(0, 1).put(5, 3).put(2, 2))))

    # D. COTP CR with SCN+CP and an AARQ with the CPDLC AE qualifier and a
    # startdown in the user-information (direct call, CR branch); CC with
    # SAC+CPA and an AARE carrying a startup (direct call, CC branch).
    d = Conn(0x4cb010, G, 0x0120, 0x0220)
    sd = Bits().put(0, 1).add(e.choice('DownlinkMessage', 'noMessage', nul))
    pkts.append(d.cr(spdu(0xe8, 0x02, aarq(qual=2, payload=c.aircraft('startdown', sd)))))
    pkts.append(d.cc(spdu(0xf0, 0x02, aare(payload=c.ground('startup', e.choice(
        'UplinkMessage', 'noMessage', nul))))))
    pkts.append(d.down(pdv(3, plain_down)))

    # E. CR with an AARQ without AE qualifier carrying a protected
    # send (heuristic, CR branch; a send rather than a startdown, which
    # ATN-CM would accept too), CC with an AARE carrying a protected
    # startup (direct, conversation now pmcpdlc).
    f = Conn(0x4cb011, G, 0x0121, 0x0221)
    pkts.append(f.cr(spdu(0xe8, 0x02, aarq(payload=prot_down))))
    psu = c.prot_message('up', c.atc('up', [(3, nul)]), algid=b'\x01')
    pkts.append(f.cc(spdu(0xf0, 0x02, aare(payload=e.choice('ProtectedGroundPDUs', 'startup', psu)))))

    # F. CR with an AARQ without user data, CC whose AARE carries a plain
    # startup: heuristic, CC branch.
    g = Conn(0x4cb012, G, 0x0122, 0x0222)
    pkts.append(g.cr(spdu(0xe8, 0x02, aarq())))
    pkts.append(g.cc(spdu(0xf0, 0x02, aare(payload=c.ground('startup', e.choice(
        'UplinkMessage', 'aTCUplinkMessage', c.atc('up', [(0, nul)])))))))

    # G. Clean version of the heuristic/no-conversation reproducer: user
    # data without any AARQ on the connection. ATN-CPDLC decodes it but
    # has no conversation, so it declines and ATN-CM takes it (an empty
    # cmLogonResponse).
    h = Conn(0x4cb013, G, 0x0123, 0x0223)
    pkts.append(h.up(pdv(3, Bits().octets(b'\x01'))))

    # (The cross-pass reproducer, atn_cpdlc_crosspass_state.py, is AARQ
    # without qualifier, CPDLC data found by the heuristic, then an AARQ
    # with the CM qualifier; its clean part is what the connections of C
    # do. Its user data 01 is also a valid CM PDU, and ATN-ULCS moves the
    # last successful heuristic to the front of the list, so it is not
    # used here: every heuristic frame of this capture is accepted by
    # exactly one of the CPDLC and CM heuristics.)

    # I. Two ground systems with the protected AE qualifier: neither up-
    # nor downlink, so ATN-CPDLC decodes them as aircraft PDUs and does not
    # decode the CPDLCMessage. Then plain mode.
    g1, g2 = gnd_nsap(2), gnd_nsap(3)
    pkts.append(dt(g1, g2, 0x0301, 0, pdv(1, aarq(qual=22))))
    pkts.append(dt(g1, g2, 0x0301, 1, pdv(3, prot_down)))
    pkts.append(dt(g1, g2, 0x0302, 0, pdv(1, aarq(qual=2))))
    pkts.append(dt(g1, g2, 0x0302, 1, pdv(3, plain_down)))
    # J. Two ground systems, AARQ without qualifier: the CPDLC heuristic
    # cannot tell up- from downlink and declines.
    pkts.append(dt(g1, g2, 0x0303, 0, pdv(1, aarq())))
    pkts.append(dt(g1, g2, 0x0303, 1, pdv(3, plain_down)))

    # K. On the protected connection of B: a send whose protectedMessage
    # is an empty BIT STRING (nothing to decode as an ATC message).
    b = Conn(0x4ca002, G, 0x0102, 0x0202)
    b.nu = 60
    w = Bits().put(0, 1).put(0, 1).put(1, 1)
    length_det(w, 0)
    length_det(w, 8).octets(b'\x55')
    pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'send', w))))
    # L. A DT with destination reference 0 and user data that only the
    # CPDLC heuristic decodes: no ATN conversation can match a zero
    # reference, so ATN-CPDLC declines (and ATN-CM rejects it).
    pkts.append(dt(G, air_nsap(0x4cb016), 0x0000, 0, pdv(3, heur_plain_up)))
    return pkts


def build_malformed(e):
    pkts = []
    G = gnd_nsap(1)
    c = Cpdlc(e)
    nul = Bits()
    # truncated PDUs on CPDLC conversations (direct call, exceptions)
    a = Conn(0x4cd001, G, 0x0181, 0x0281)
    pkts.append(a.down(pdv(1, aarq(qual=2))))
    pkts.append(a.up(pdv(1, aare())))
    full_down = c.aircraft('send', c.atc('down', element_list(e, 'down')[100:105]))
    full_up = c.ground('send', c.atc('up', element_list(e, 'up')[80:85], route=[c.route_clearance(True)]))
    for m, up in ((full_down, False), (full_up, True)):
        t = Bits()
        t.b = m.b[:len(m.b) // 2]
        pkts.append(a.up(pdv(3, t)) if up else a.down(pdv(3, t)))
    b = Conn(0x4cd002, G, 0x0182, 0x0282)
    pkts.append(b.down(pdv(1, aarq(qual=22))))
    pkts.append(b.up(pdv(1, aare())))
    pm = e.choice('ProtectedGroundPDUs', 'send', c.prot_message('up', c.atc('up', [(0, nul)]), algid=b'\x01'))
    t = Bits()
    t.b = pm.b[:len(pm.b) - 30]
    pkts.append(b.up(pdv(3, t)))
    # protected message whose CPDLCMessage content is truncated
    trunc = Bits()
    trunc.b = c.atc('up', element_list(e, 'up')[180:185]).b[:20]
    pkts.append(b.up(pdv(3, e.choice('ProtectedGroundPDUs', 'send', c.prot_message('up', trunc)))))
    # empty user data on a CPDLC conversation
    pkts.append(b.down(pdv(3, Bits())))
    # Known unfixed state issue (not malformed): AARQ without qualifier,
    # data found by the CPDLC heuristic, then an AARQ with the CM AE
    # qualifier on the same connection (as the review
    # atn_cpdlc_crosspass_state.py, with user data that only ATN-CPDLC
    # accepts). With -2 the data frame is handed to ATN-CM.
    x = Conn(0x4cd003, G, 0x0183, 0x0283)
    pkts.append(x.down(pdv(1, aarq())))
    pkts.append(x.up(pdv(1, aare())))
    pkts.append(x.up(pdv(3, c.ground('startup', e.choice('UplinkMessage', 'noMessage', nul)))))
    pkts.append(x.down(pdv(1, aarq(qual=1))))
    return pkts


def write_pcap(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1793232000 + i, 0, len(p), len(p)) + p)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    src = os.environ.get('WIRESHARK_SRC', os.path.join(SRCDIR))
    asn = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(src, 'epan/dissectors/asn1/atn-cpdlc/atn-cpdlc.asn')
    enc = Encoder(load_types(asn))
    main, cp, gnd = build_main(enc)
    main += build_conversations(enc, cp, gnd)
    write_pcap(os.path.join(out, 'atn_cpdlc-coverage.pcap'), main)
    write_pcap(os.path.join(out, 'atn_cpdlc-coverage-malformed.pcap'), build_malformed(Encoder(load_types(asn))))
