#!/usr/bin/env python3
# AIN coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AIN dissector (packet-ain.c).

AIN (Telcordia GR-1299 Advanced Intelligent Network) rides in ANSI TCAP,
which is carried the way it is in a real SS7 over IP network:

  Ethernet / IPv4 / SCTP (PPID 3) / M3UA DATA / SCCP UDT (ANSI) / ANSI TCAP

The SSP is 10.0.0.1, point code 1-1-1; the SCP is 10.0.0.2, point code
2-2-2; both use SSN 11 (inside the 5-14 range that is decoded as TCAP by
default).  Decode with -o mtp3.standard:ANSI (cfg/profiles/ain does that).

The argument and result values are built from ain_schema.py, which
extract_schema.py derives from the ber_sequence_t/ber_choice_t tables
of packet-ain.c, so the encodings follow exactly what the dissector
expects: every OPTIONAL component is present, and each operation is sent
again (with a new transaction) until every CHOICE alternative reachable
from it has been used once.

Usage: mkain.py [<output directory>]

Writes ain-coverage.pcap and ain-coverage-malformed.pcap. Every packet is
built here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from collections import Counter

from capgen import eth, ipv4, sctp, sctp_data, write_pcap  # noqa: E402

from ain_schema import TYPES, OPS  # noqa: E402

# ---------------------------------------------------------------- BER


def ber_tag(cls, constructed, tag):
    first = (cls << 6) | (0x20 if constructed else 0)
    if tag < 31:
        return bytes([first | tag])
    out = [tag & 0x7f]
    tag >>= 7
    while tag:
        out.insert(0, 0x80 | (tag & 0x7f))
        tag >>= 7
    return bytes([first | 0x1f] + out)


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(cls, constructed, tag, content):
    return ber_tag(cls, constructed, tag) + ber_len(len(content)) + content


def ber_int(v):
    n = 1
    while True:
        try:
            return v.to_bytes(n, 'big', signed=True)
        except OverflowError:
            n += 1


def ber_oid(dotted):
    arcs = [int(a) for a in dotted.split('.')]
    out = bytearray([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        enc = [a & 0x7f]
        a >>= 7
        while a:
            enc.insert(0, 0x80 | (a & 0x7f))
            a >>= 7
        out += bytes(enc)
    return bytes(out)


def bcd(digits):
    """BCD, first digit in the low nibble, odd count padded with 0xF."""
    if len(digits) % 2:
        digits += 'F'
    return bytes(int(digits[i + 1], 16) << 4 | int(digits[i], 16) for i in range(0, len(digits), 2))


UNI, APP, CON, PRI, ANY = 0, 1, 2, 3, 99

# ---------------------------------------------------------------- values
# Hand-written contents for the types with a hand-written FN_BODY in ain.cnf
# and for the ExtensionParameter.


def aindigits(n):
    # odd/even + nature of address, numbering plan (ISDN), BCD digits
    digits = ['9085551212', '2015550123', '7325554', '4115'][n % 4]
    return bytes([(0x80 if len(digits) % 2 else 0) | 0x03, 0x10]) + bcd(digits)


def carrierformat(n):
    # carrier selection, nature of carrier (interLATA) + 4 digits, 4 BCD digits
    return bytes([1 + n % 4, 0x34]) + bcd('0288')


def amaslpid(n):
    # 9 BCD digits padded with 0xF
    return bcd('123456789')


SPECIAL = {'AINDigits': aindigits, 'CarrierFormat': carrierformat, 'AMAslpID': amaslpid}

EXT_OID = '2.5.4.3'   # id-at-commonName: x509sat registers a BER dissector for it


class Encoder:
    """Encode values of the types in ain_schema.TYPES.

    full(name) gives the complete TLV of a type, content(name) the contents
    octets and whether they are constructed (used under an IMPLICIT tag).
    """

    def __init__(self):
        self.used = Counter()     # (choice type, alternative) -> times used
        self.new = set()          # alternatives used for the first time in this value
        self.n = Counter()        # per type counter to vary values
        self.seen = set()         # types encoded so far (each is a dissect_ain_*() function)
        self.memo = {}

    def mark(self, name):
        if name not in self.seen:
            self.seen.add(name)
            self.new.add(name)
            self.memo = {}

    def pending(self, name):
        """Types reachable from name that have not been encoded yet."""
        if name in self.memo:
            return self.memo[name]
        t = TYPES[name]
        k = t[0]
        sub = []
        if k in ('alias',):
            sub = [t[1]]
        elif k == 'tagged':
            sub = [t[4]]
        elif k == 'seq':
            sub = [f[4] for f in t[1]]
        elif k == 'seqof':
            sub = [t[3][4]]
        elif k == 'choice':
            sub = [t[1][i][5] for i, _ in self.reachable(name, frozenset())]
        out = set() if name in self.seen else {name}
        for x in sub:
            out |= self.pending(x)
        self.memo[name] = frozenset(out)
        return self.memo[name]

    # -- alternatives of a CHOICE that dissect_ber_choice() can reach
    def first_tags(self, name):
        t = TYPES[name]
        if t[0] == 'alias':
            return self.first_tags(t[1])
        if t[0] == 'choice':
            tags = set()
            for alt in t[1]:
                if alt[3] == -1:
                    tags |= self.first_tags(alt[5])
                elif 'NOOWNTAG' in alt[4]:
                    tags |= self.first_tags(alt[5])
                else:
                    tags.add((alt[2], alt[3]))
            return tags
        return {self.outer_tag(name)}

    def reachable(self, name, excl):
        alts = TYPES[name][1]
        seen = set()
        out = []
        any_seen = False
        for i, alt in enumerate(alts):
            if alt[3] == -1:
                # dissect_ber_choice() only tries the first untagged CHOICE
                # alternative, and only when no tagged one matched
                if not any_seen:
                    any_seen = True
                    inner_excl = excl | {(a[2], a[3]) for a in alts if a[3] != -1}
                    if self.reachable(alts[i][5], inner_excl) if TYPES[self.resolve(alt[5])][0] == 'choice' else True:
                        out.append((i, inner_excl))
                continue
            key = (alt[2], alt[3])
            if key not in seen and key not in excl:
                out.append((i, excl))
            seen.add(key)
        return out

    def resolve(self, name):
        while TYPES[name][0] == 'alias':
            name = TYPES[name][1]
        return name

    def outer_tag(self, name):
        t = TYPES[name]
        k = t[0]
        if k == 'alias':
            return self.outer_tag(t[1])
        if k == 'tagged':
            return (t[1], t[2])
        return (UNI, {'octets': 4, 'int': 2, 'string': None, 'seq': 16, 'seqof': 16,
                      'bool': 1, 'null': 5, 'bits': 3, 'oid': 6}.get(k) if k != 'string' else t[1])

    # -- encoders
    def content(self, name, excl=frozenset()):
        """Contents octets of a value of type name, and whether constructed."""
        t = TYPES[name]
        k = t[0]
        self.mark(name)
        n = self.n[name]
        self.n[name] += 1
        if name in SPECIAL:
            return SPECIAL[name](n), False
        if k == 'alias':
            self.n[name] -= 1
            return self.content(t[1], excl)
        if k == 'octets':
            lo, hi = t[1], t[2]
            if lo == hi and lo > 0:
                ln = lo
            elif hi < 0:
                ln = 4
            else:
                ln = min(hi, max(lo, 4))
            return bytes((0x11 * (i + 1) + n) & 0xff for i in range(ln)), False
        if k == 'int':
            lo, hi, vals = t[1], t[2], t[3]
            cands = [v for v in (vals or []) if (lo is None or lo <= v) and (hi is None or v <= hi)]
            if cands:
                v = cands[n % len(cands)]
            elif lo is not None:
                v = min(hi, lo + 1 + n)
            else:
                v = 1 + n
            return ber_int(v), False
        if k == 'string':
            lo, hi = t[2], t[3]
            ln = lo if lo == hi else min(hi if hi > 0 else 6, max(lo, 6))
            return 'ABCDEFGHIJKLMNOP'[:ln].encode(), False
        if k == 'bool':
            return b'\xff', False
        if k == 'null':
            return b'', False
        if k == 'bits':
            nbits = t[1]
            nbytes = (nbits + 7) // 8
            unused = nbytes * 8 - nbits
            v = ((1 << nbits) - 1) << unused
            return bytes([unused]) + v.to_bytes(nbytes, 'big'), False
        if k == 'oid':
            return ber_oid(EXT_OID if name == 'T_assignmentAuthority' else '1.2.840.10008.1.2'), False
        if k == 'any':
            return None, None  # handled in full()
        if k == 'tagged':
            _, cls, tag, impl, inner = t
            if impl and TYPES[self.resolve(inner)][0] != 'choice':
                return self.content(inner)
            return self.full(inner), True
        if k == 'seq':
            return b''.join(self.field(f[1], f[2], f[3], f[4]) for f in t[1]), True
        if k == 'seqof':
            lo, hi, item = t[1], t[2], t[3]
            cnt = max(lo, min(hi, 2))
            # one item per reachable alternative of an item CHOICE (up to the maximum)
            if TYPES[self.resolve(item[4])][0] == 'choice':
                cnt = max(cnt, min(hi, len(self.reachable(self.resolve(item[4]), frozenset()))))
            return b''.join(self.field(item[1], item[2], item[3], item[4]) for _ in range(cnt)), True
        if k == 'choice':
            return self.full(name, excl), True
        raise ValueError(name)

    def full(self, name, excl=frozenset()):
        self.mark(name)
        t = TYPES[name]
        k = t[0]
        if k == 'alias':
            return self.full(t[1], excl)
        if k == 'any':
            # ExtensionParameter.parameters: a DirectoryString for id-at-commonName
            return tlv(UNI, False, 19, b'AIN synthetic extension')
        if k == 'choice':
            alts = self.reachable(name, excl)
            # prefer the alternative leading to types not encoded yet,
            # then the least used one
            i, ex = min(alts, key=lambda a: (-len(self.pending(t[1][a[0]][5])),
                                             self.used[(name, a[0])], a[0]))
            self.used[(name, i)] += 1
            alt = t[1][i]
            return self.field(alt[2], alt[3], alt[4], alt[5], ex)
        if k == 'tagged':
            cls, tag = t[1], t[2]
            body, cons = self.content(name)
            return tlv(cls, cons, tag, body)
        body, cons = self.content(name)
        cls, tag = self.outer_tag(name)
        return tlv(cls, cons, tag, body)

    def seq_with(self, name, overrides):
        """A SEQUENCE with its mandatory components and the given ones only."""
        body = b''
        for f in TYPES[name][1]:
            if f[0] in overrides:
                body += overrides[f[0]]
            elif 'OPTIONAL' not in f[3]:
                body += self.field(f[1], f[2], f[3], f[4])
        return tlv(UNI, True, 16, body)

    def field(self, cls, tag, flags, fn, excl=frozenset()):
        """A component of a SEQUENCE or alternative of a CHOICE."""
        if 'NOOWNTAG' in flags:
            enc = self.full(fn, excl)
            if cls == UNI and tag != -1 and enc[0] & 0x1f != tag:
                # e.g. ENUMERATED components: the table carries the tag
                enc = bytes([(enc[0] & 0xe0) | tag]) + enc[1:]
            return enc
        if 'IMPLTAG' in flags:
            body, cons = self.content(fn, excl)
        else:
            body, cons = self.full(fn, excl), True
        return tlv(cls, cons, tag, body)


# ---------------------------------------------------------------- ANSI TCAP

def component_ids(*ids):
    return tlv(PRI, False, 15, bytes(ids))


def invoke(inv_id, opcode, arg, last=True):
    body = component_ids(inv_id) + tlv(PRI, False, 17, struct.pack('!H', opcode))
    if arg is not None:
        body += arg
    return tlv(PRI, True, 9 if last else 13, body)


def return_result(inv_id, res, last=True):
    body = component_ids(inv_id)
    if res is not None:
        body += res
    return tlv(PRI, True, 10 if last else 14, body)


def return_error(inv_id, errcode, param):
    body = component_ids(inv_id) + tlv(PRI, False, 20, bytes([errcode]))
    if param is not None:
        body += param
    return tlv(PRI, True, 11, body)


def reject(inv_id, problem):
    body = component_ids(inv_id) + tlv(PRI, False, 21, struct.pack('!H', problem)) + tlv(PRI, True, 18, b'')
    return tlv(PRI, True, 12, body)


def package(ptype, tid, components):
    """ptype 2 queryWithPerm, 4 response, 5 conversationWithPerm, 1 unidirectional."""
    return tlv(PRI, True, ptype, tlv(PRI, False, 7, tid) + tlv(PRI, True, 8, b''.join(components)))


# ---------------------------------------------------------------- SS7 over IP

def ansi_pc(network, cluster, member):
    return network << 16 | cluster << 8 | member


SSP = {'ip': bytes([10, 0, 0, 1]), 'mac': bytes.fromhex('020000000001'), 'pc': (1, 1, 1), 'port': 2906, 'vtag': 0x55535031}
SCP = {'ip': bytes([10, 0, 0, 2]), 'mac': bytes.fromhex('020000000002'), 'pc': (2, 2, 2), 'port': 2905, 'vtag': 0x53435031}
SSN = 11
tsn = {}


def sccp_addr(pc):
    # ANSI address indicator: national, route on SSN, SSN and PC present;
    # SSN first, then the point code member, cluster, network
    return bytes([0xc3, SSN, pc[2], pc[1], pc[0]])


def sccp_udt(src, dst, data):
    called = sccp_addr(dst['pc'])
    calling = sccp_addr(src['pc'])
    p1 = 3
    p2 = 2 + len(called) + 1
    p3 = 1 + len(called) + 1 + len(calling) + 1
    if len(data) <= 255:
        return (bytes([0x09, 0x00, p1, p2, p3]) + bytes([len(called)]) + called +
                bytes([len(calling)]) + calling + bytes([len(data)]) + data)
    # Long Unitdata: class 0, hop counter, four 2-octet pointers (called,
    # calling, data, no optional part) counted from their second octet,
    # long data with a 2-octet length
    p1 = 7
    p2 = 6 + len(called)
    p3 = 5 + len(called) + len(calling)
    return (bytes([0x13, 0x00, 0x0f]) + struct.pack('<HHHH', p1, p2, p3, 0) +
            bytes([len(called)]) + called + bytes([len(calling)]) + calling +
            struct.pack('<H', len(data)) + data)


def m3ua_data(src, dst, sccp, sls):
    pd = struct.pack('!IIBBBB', ansi_pc(*src['pc']), ansi_pc(*dst['pc']), 3, 2, 0, sls) + sccp
    param = struct.pack('!HH', 0x0210, 4 + len(pd)) + pd
    param += b'\0' * (-len(param) % 4)
    return struct.pack('!BBBBI', 1, 0, 1, 1, 8 + len(param)) + param


def sctp_packet(src, dst, payload):
    key = src['ip']
    tsn[key] = tsn.get(key, 0) + 1
    chunk = sctp_data(payload, tsn[key], 3, ssn=tsn[key] & 0xffff)
    return sctp(chunk, src['port'], dst['port'], dst['vtag'])


def frame(src, dst, tcap, sls=0):
    pkt = sctp_packet(src, dst, m3ua_data(src, dst, sccp_udt(src, dst, tcap), sls))
    return eth(ipv4(pkt, 132, src=src['ip'], dst=dst['ip'], ident=0, flags_frag=0x4000), 0x0800,
               dst=dst['mac'], src=src['mac'])


# ---------------------------------------------------------------- captures

def build():
    enc = Encoder()
    clean = []
    malformed = []
    tid_n = [0x00010000]

    def tid():
        tid_n[0] += 1
        return struct.pack('!I', tid_n[0])

    def add(caps, src, dst, tcap, note):
        caps.append((frame(src, dst, tcap, len(caps) & 0x0f), note))

    results = {c: p for c, _, p in OPS['res']}

    # The ReturnResult reproducer (it used to hit DISSECTOR_ASSERT_NOT_REACHED
    # in dissect_ain()): an Invoke and its ReturnResult in one component
    # sequence.  activityTest is known to AIN and has a result.
    code = 26886
    enc.new.clear()
    pkt = package(2, tid(), [invoke(1, code, enc.full('ActivityTestArg')),
                             return_result(1, enc.full(results[code]))])
    add(clean, SSP, SCP, pkt, 'reproducer: activityTest Invoke + ReturnResult in one package')

    # Every operation: queryWithPerm with the Invoke, and a response with the
    # ReturnResult for operations that have a result.  Repeat with a new
    # transaction while a CHOICE alternative is used for the first time.
    for code, ident, argtype in OPS['arg']:
        for rnd in range(40):
            if rnd and not (enc.pending(argtype) or (code in results and enc.pending(results[code]))):
                break
            enc.new.clear()
            arg = enc.full(argtype)
            res = enc.full(results[code]) if code in results else None
            if rnd and not enc.new:
                break
            t = tid()
            add(clean, SSP, SCP, package(2, t, [invoke(1, code, arg)]), '%s Invoke' % ident)
            if res is not None:
                add(clean, SCP, SSP, package(4, t, [return_result(1, res)]), '%s ReturnResult' % ident)

    # ReturnError for every AIN error code, each answering an Invoke
    # (AIN only names them in the Info column: dissect_ain() does not
    # dissect the error parameter).
    for errcode, ident, partype in OPS['err']:
        t = tid()
        add(clean, SSP, SCP, package(2, t, [invoke(1, 25603, enc.full('InfoAnalyzedArg'))]), 'infoAnalyzed Invoke')
        add(clean, SCP, SSP, package(4, t, [return_error(1, errcode, enc.full(partype))]), '%s ReturnError' % ident)

    # Reject of an AIN Invoke (ANSI TCAP does not pass rejects to AIN)
    t = tid()
    add(clean, SSP, SCP, package(2, t, [invoke(1, 26882, enc.full('EchoRequestArg'))]), 'echoRequest Invoke')
    add(clean, SCP, SSP, package(4, t, [reject(1, 515)]), 'Reject invoke-incorrectParameter')

    # Several components in one package: InvokeNotLast, ReturnResultNotLast,
    # and a constructed (segmented) AINDigits, which BER allows.
    t = tid()
    seg = tlv(UNI, False, 4, aindigits(0)[:3]) + tlv(UNI, False, 4, aindigits(0)[3:])
    nca = enc.seq_with('NCARequestArg', {'calledPartyID': tlv(CON, True, 15, seg)})
    add(clean, SSP, SCP, package(2, t, [invoke(1, 26118, enc.full('CTRClearArg'), last=False),
                                        invoke(2, 27393, nca)]), 'cTRClear InvokeNotLast + nCARequest, segmented calledPartyID')
    add(clean, SCP, SSP, package(4, t, [return_result(2, enc.full(results[27393]), last=False),
                                        return_result(2, enc.full(results[27393]))]),
        'nCARequest ReturnResultNotLast + ReturnResultLast')

    # Zero-length constructed encodings (BER 8.7.3) of the three types with a
    # hand-written body: the dissector gets no tvb and returns early.
    t = tid()
    zero = enc.seq_with('AnalyzeRouteArg', {'calledPartyID': tlv(CON, True, 15, b''),
                                            'carrier': tlv(CON, True, 41, b''),
                                            'aMAslpID': tlv(CON, True, 10, b'')})
    add(clean, SSP, SCP, package(2, t, [invoke(1, 25857, zero)]), 'analyzeRoute, empty constructed digits/carrier/AMAslpID')

    # ------------------------------------------------ malformed / warnings
    # The original reproducer, unchanged: private opcode 0x6101 is not an AIN
    # operation, so both components end in the "Unknown ..." expert infos.
    t = struct.pack('!I', 1)
    add(malformed, SSP, SCP, package(2, t, [invoke(1, 0x6101, tlv(PRI, True, 18, b'')),
                                            return_result(1, tlv(PRI, True, 18, tlv(UNI, False, 4, b'\x00')))]),
        'original reproducer, unknown operation 0x6101')
    # AINDigits too short for the numbering plan octet: exception
    t = tid()
    short = enc.seq_with('AnalyzeRouteArg', {'calledPartyID': tlv(CON, False, 15, b'\x83')})
    add(malformed, SSP, SCP, package(2, t, [invoke(1, 25857, short)]), 'analyzeRoute, 1 octet calledPartyID')
    # CarrierFormat of 1 octet: constraint warning, then an exception
    t = tid()
    short = enc.seq_with('AnalyzeRouteArg', {'carrier': tlv(CON, False, 41, b'\x01')})
    add(malformed, SSP, SCP, package(2, t, [invoke(1, 25857, short)]), 'analyzeRoute, 1 octet carrier')

    return clean, malformed, enc


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean, malformed, enc = build()
    write_pcap(os.path.join(out, 'ain-coverage.pcap'), [fr for fr, _ in clean], snaplen=65535,
               ts=lambda i: (1767225600 + i, 0))
    write_pcap(os.path.join(out, 'ain-coverage-malformed.pcap'), [fr for fr, _ in malformed],
               snaplen=65535, ts=lambda i: (1767225600 + i, 0))
    # Types (dissect_ain_*() functions) no value was built for: only the
    # generic ROS types, which dissect_ain() never calls
    missing = sorted(set(TYPES) - enc.seen)
    print('%d + %d frames; types not encoded: %s' % (len(clean), len(malformed), ' '.join(missing)), file=sys.stderr)


if __name__ == '__main__':
    main()
