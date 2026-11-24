#!/usr/bin/env python3
# ANSI MAP coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ANSI MAP dissector (packet-ansi_map.c, ANSI-41 Mobile Application Part).

ANSI MAP rides in ANSI TCAP, carried the way it is in an SS7 over IP
network:

  Ethernet / IPv4 / SCTP (PPID 3) / M3UA DATA / SCCP UDT or LUDT (ANSI) /
  ANSI TCAP

Decode with -o mtp3.standard:ANSI (cfg/profiles/ansi_map does that).

Network elements (ANSI point codes, SSNs in the 5-14 range ANSI MAP
registers):
  MSC-A  10.0.0.1  1-1-1  SSN 8      HLR   10.0.0.2  2-2-2  SSN 6
  VLR    10.0.0.3  3-3-3  SSN 7      MC    10.0.0.4  4-4-4  SSN 11
  MSC-B  10.0.0.21 21-21-21 SSN 8   relay 10.0.0.22 22-22-22 SSN 8

The argument and result values are built from ansi_map_schema.py, which
extract_schema.py derives from the ber_sequence_t/ber_choice_t tables
of packet-ansi_map.c, so every encoding follows what the dissector
expects: every OPTIONAL parameter is present.  The OCTET STRING
parameters with a hand-written decoder in the template get realistic
contents (several variants each, to reach their branches).

The TCAP payloads in the capture files ansi_map_*.pcap next to this script
(Exported PDU, linktype 252) are included: the ones that decode without a
malformed packet in the main capture, the others in the malformed capture.
They test "ANSI MAP: Dissect the SMS bearer data only once".

Usage: mkansi_map.py [<output directory>]

Writes ansi_map-coverage.pcap and ansi_map-coverage-malformed.pcap. Every
packet is built here or read from those captures, which are themselves
generated; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from collections import Counter

from capgen import eth, ipv4, read_pcap, sctp, sctp_data, write_pcap  # noqa: E402

from ansi_map_schema import TYPES, OPS, OCTATTR  # noqa: E402
from repro import reproducer_dir

# The IMSI parameters are typed with the GSM MAP IMSI (imported type)
TYPES['dissect_gsm_map_IMSI'] = ('octets', -1, -1)

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


def bcd(digits):
    """TBCD, first digit in the low nibble, odd count padded with 0xF."""
    if len(digits) % 2:
        digits += 'F'
    return bytes(int(digits[i + 1], 16) << 4 | int(digits[i], 16) for i in range(0, len(digits), 2))


UNI, APP, CON, PRI, ANY = 0, 1, 2, 3, 99


class Bits:
    def __init__(self):
        self.b = []

    def put(self, val, n):
        for i in range(n - 1, -1, -1):
            self.b.append((val >> i) & 1)

    def bytes(self):
        b = self.b + [0] * ((-len(self.b)) % 8)
        return bytes(int(''.join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


# ---------------------------------------------------------------- payloads
# IS-637 teleservice layer (SMS bearer data): Message Identifier, User Data
# (7-bit ASCII), Message Center Time Stamp, Priority Indicator


def is637_bearer(text='Hello from ANSI-41', msgtype=1, msgid=0x1234):
    mi = Bits()
    mi.put(msgtype, 4)           # MESSAGE_TYPE (1 deliver, 2 submit)
    mi.put(msgid, 16)            # MESSAGE_ID
    mi.put(0, 1)                 # HEADER_IND
    mi.put(0, 3)
    msg_id = bytes([0x00, 0x03]) + mi.bytes()
    ud = Bits()
    ud.put(2, 5)                 # MSG_ENCODING 7-bit ASCII
    ud.put(len(text), 8)         # NUM_FIELDS
    for c in text.encode():
        ud.put(c, 7)
    ud = ud.bytes()
    ts = bytes([0x26, 0x10, 0x27, 0x12, 0x30, 0x45])   # 2026-10-27 12:30:45, BCD
    return msg_id + bytes([0x01, len(ud)]) + ud + bytes([0x03, 6]) + ts + bytes([0x08, 0x01, 0x40])


# IS-683 (OTASP/OTAPA): forward Configuration Request for blocks 0 and 1,
# reverse Commit Response
IS683_FORWARD = bytes([0x00, 0x02, 0x00, 0x01])
IS683_REVERSE = bytes([0x05, 0x00])     # Commit Response, accepted
# IS-801 (position determination): session start, PD data message with no
# requests or responses (forward and reverse)
IS801_FORWARD = bytes([0x81, 0x00, 0x00])
IS801_REVERSE = bytes([0x81, 0x00, 0x00])

# CDMA2000 handoff IOS data: A1 elements (Cause, Channel Number / Band Class)
IOS_INVOKE = bytes([0x04, 0x01, 0x0f]) + bytes([0x5d, 0x03, 0x00, 0x01, 0x23])
IOS_RESPONSE = bytes([0x04, 0x01, 0x00])

# ---------------------------------------------------------------- values


def digits_variants():
    """DigitsType: type of digits, nature of number, numbering plan /
    encoding, then the digits.  One variant per branch of
    dissect_ansi_map_digits_type()."""
    v = []

    def d(tod, nat, np, enc, body):
        v.append(bytes([tod, nat, np << 4 | enc]) + body)

    num = '2015550123'
    d(1, 0x00, 2, 1, bytes([len(num)]) + bcd(num))            # E.164 BCD
    d(2, 0x01, 0, 1, bytes([7]) + bcd('5550123'))             # unknown plan, BCD
    d(3, 0x02, 0, 1, bytes([0]))                              # BCD, no digits
    d(4, 0x04, 0, 2, bytes([4]) + b'1234')                    # unknown plan, IA5
    d(5, 0x30, 0, 2, bytes([0]))                              # IA5, no digits
    d(6, 0x00, 0, 3, b'\x01\x02')                             # octet string
    d(7, 0x00, 0, 0, b'\x01')                                 # encoding not used
    d(8, 0x00, 1, 1, bytes([4]) + bcd('1234'))                # ISDN: not used
    d(0, 0x00, 3, 1, bytes([4]) + bcd('1234'))                # X.121: not used
    d(1, 0x00, 4, 1, bytes([4]) + bcd('1234'))                # telex: not used
    d(1, 0x00, 5, 1, bytes([4]) + bcd('1234'))                # maritime: not used
    d(1, 0x00, 2, 2, bytes([7]) + b'5551212')                 # E.164 IA5
    d(1, 0x00, 2, 3, bytes([2]) + b'\x12\x34')                # E.164 octet string
    d(1, 0x00, 2, 0, bytes([2]) + b'\x12\x34')                # E.164 encoding 0
    d(1, 0x00, 2, 1, bytes([0]))                              # E.164 no digits
    d(2, 0x00, 6, 1, bytes([15]) + bcd('310004123456789'))    # E.212 BCD
    d(2, 0x00, 7, 2, bytes([4]) + b'4321')                    # private IA5
    d(6, 0x00, 13, 3, bytes([0x07, 0x02, 0x02, 0x06]))        # PC 2-2-7 SSN 6
    d(6, 0x00, 13, 1, bytes([0x07, 0x02, 0x02, 0x06]))        # PC/SSN not octet string
    d(6, 0x00, 14, 3, bytes([10, 0, 0, 2]))                   # IP address
    d(9, 0x00, 8, 1, bytes([2]) + bcd('12'))                  # plan 8: not used
    return v


DIGITS = digits_variants()


def cycle(seq):
    return lambda n: seq[n % len(seq)]


SPECIAL = {
    'MINType': cycle([bcd('2015550123'), bcd('7325550199')]),
    'dissect_gsm_map_IMSI': cycle([bcd('310004123456789'), bcd('31000498765432')]),
    # the numbering plans the dissector flags as not used only in the
    # dedicated RoutingRequest frames
    'DigitsType': cycle([d for d in DIGITS if (d[2] >> 4) not in (1, 3, 4, 5, 8, 9, 10, 11, 12, 15)]),
    # type of subaddress user specified, odd, then the subaddress
    'Subaddress': cycle([bytes([0x98, 0x50, 0x12]), bytes([0x80, 0x01])]),
    # pitch high, cadence ShortShortLong; alert action reminder
    'AlertCode': cycle([bytes([0x43, 0x01]), bytes([0x81, 0x00])]),
    # tone, class, standard announcement, custom announcement
    'AnnouncementCode': cycle([bytes([0x01, 0x00, 0x05, 0x00]), bytes([0x63, 0x01, 0x20, 0x07])]),
    'AuthorizationPeriod': cycle([bytes([0x02, 0x05]), bytes([0x05, 0x01])]),
    'DeniedAuthorizationPeriod': cycle([bytes([0x01, 0x03]), bytes([0x03, 0x18])]),
    # market ID, switch number, ID number, segment counter
    'BillingID': cycle([bytes([0x01, 0x02, 0x03, 0x00, 0x10, 0x20, 0x00])]),
    'PilotBillingID': cycle([bytes([0x01, 0x02, 0x03, 0x00, 0x10, 0x21, 0x01])]),
    # 3, 4, 5 and 6 octets: each optional octet of the indicator
    'CallingFeaturesIndicator': cycle([bytes([0x55, 0x66, 0x77]), bytes([0x55, 0x66, 0x77, 0x88]),
                                       bytes([0x55, 0x66, 0x77, 0x88, 0x99]),
                                       bytes([0x55, 0x66, 0x77, 0x88, 0x99, 0x02])]),
    'CDMACallMode': cycle([bytes([0x07]), bytes([0xff, 0x1f])]),
    # frame offset / channel number, band class + long code mask, then
    # optionally NP_EXT / nominal power / preambles
    'CDMAChannelData': cycle([bytes([0x0a, 0x83, 0x08, 0x12, 0x34, 0x56, 0x78, 0x9a]),
                              bytes([0x0a, 0x83, 0x08, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xa5])]),
    'CDMAStationClassMark': cycle([bytes([0x52])]),
    'ChannelData': cycle([bytes([0x45, 0x01, 0x23])]),
    'ConfidentialityModes': cycle([bytes([0x07])]),
    'ControlChannelData': cycle([bytes([0x44, 0x01, 0x23, 0x01])]),
    'ExtendedMSCID': cycle([bytes([0x07, 0x01, 0x02, 0x03])]),
    'ExtendedSystemMyTypeCode': cycle([bytes([0x07, 0x09]), bytes([0x08, 0x22])]),
    'HandoffState': cycle([bytes([0x01])]),
    'InterMSCCircuitID': cycle([bytes([0x05, 0x17])]),
    'MessageWaitingNotificationCount': cycle([bytes([0x00, 0x03]), bytes([0x01, 0xff])]),
    'MessageWaitingNotificationType': cycle([bytes([0x07])]),
    'MSCID': cycle([bytes([0x01, 0x02, 0x03]), bytes([0x00, 0x7f, 0x05])]),
    # latitude, longitude, resolution (1 or 2 octets)
    'MSLocation': cycle([bytes([0x40, 0x12, 0x34, 0x80, 0x56, 0x78, 0x05]),
                         bytes([0x40, 0x12, 0x34, 0x80, 0x56, 0x78, 0x05, 0x01])]),
    'NAMPSCallMode': cycle([bytes([0x03])]),
    'NAMPSChannelData': cycle([bytes([0x05])]),
    'OneTimeFeatureIndicator': cycle([bytes([0x55, 0x15])]),
    'OriginationTriggers': cycle([bytes([0xff, 0x1f, 0xff, 0xff]), bytes([0x01, 0x00, 0x10, 0x80])]),
    'PACAIndicator': cycle([bytes([0x0b])]),
    # type, point code member/cluster/network, SSN
    'PC_SSN': cycle([bytes([0x06, 0x02, 0x02, 0x02, 0x06])]),
    'SMS_OriginationRestrictions': cycle([bytes([0x0e])]),
    'SystemCapabilities': cycle([bytes([0x3f])]),
    'TerminationTriggers': cycle([bytes([0x55, 0x01])]),
    'TransactionCapability': cycle([bytes([0xff, 0x2f])]),
    'CDMAServiceOption': cycle([bytes([0x00, 0x03]), bytes([0x00, 0x21]), bytes([0x80, 0x01])]),
    'CallingPartyName': cycle([bytes([0x10]) + b'ALICE']),
    'TriggerCapability': cycle([bytes([0xff, 0xff, 0x1f])]),
    'WINOperationsCapability': cycle([bytes([0x07])]),
    # TDP-R, TDP-N, EDP-R, EDP-N markers and trigger types (one unknown)
    'WIN_TriggerList': cycle([bytes([0xdc, 0x01, 0x02, 0xdd, 0x22, 0xde, 0x40, 0xdf, 0x41, 0xc8])]),
    'ControlNetworkID': cycle([bytes([0x01, 0x02, 0x03])]),
    'CDMA2000HandoffInvokeIOSData': cycle([IOS_INVOKE]),
    'CDMA2000HandoffResponseIOSData': cycle([IOS_RESPONSE]),
    'SMS_BearerData': cycle([is637_bearer(), is637_bearer('Second message', 2, 0x0042)]),
    'SMS_TeleserviceIdentifier': cycle([struct.pack('!H', v) for v in (4098, 4097, 4099, 4101, 4100)]),
    # never 1, 3 or 4 here: those hand the bearer data to IS-683/IS-801,
    # which only the dedicated frames below do
    'ServiceIndicator': cycle([bytes([v]) for v in (2, 0, 5, 6)]),
}


class Encoder:
    """Encode values of the types in ansi_map_schema.TYPES.

    full(name) gives the complete TLV of a type, content(name) the contents
    octets and whether they are constructed (used under an IMPLICIT tag).
    """

    def __init__(self):
        self.used = Counter()
        self.new = set()
        self.n = Counter()
        self.seen = set()
        self.memo = {}
        self.override = {}        # type name -> content, for the next uses
        self.skip = set()         # OPTIONAL parameters of these types are left out

    def mark(self, name):
        if name not in self.seen:
            self.seen.add(name)
            self.new.add(name)
            self.memo = {}

    def pending(self, name):
        """Types reachable from name that have not been encoded yet."""
        if name in self.memo:
            return self.memo[name]
        if name in self.skip:
            return frozenset()
        self.memo[name] = frozenset()       # recursion guard
        t = TYPES[name]
        k = t[0]
        sub = []
        if k == 'alias':
            sub = [t[1]]
        elif k == 'tagged':
            sub = [t[4]]
        elif k in ('seq', 'set'):
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

    def reachable(self, name, excl):
        alts = TYPES[name][1]
        seen = set()
        out = []
        any_seen = False
        for i, alt in enumerate(alts):
            if alt[3] == -1:
                if not any_seen:
                    any_seen = True
                    inner_excl = excl | {(a[2], a[3]) for a in alts if a[3] != -1}
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
        if k == 'seqof':
            return (UNI, t[4] if len(t) > 4 else 16)
        return (UNI, {'octets': 4, 'int': 2, 'seq': 16, 'set': 17,
                      'bool': 1, 'null': 5, 'gtime': 24}[k])

    def octets(self, name, n):
        if name in self.override:
            return self.override[name]
        if name in SPECIAL:
            return SPECIAL[name](n)
        if name in OCTATTR:
            ft, vals, mask = OCTATTR[name]
            vals = vals or [1]
            v = vals[n % len(vals)]
            if ft == 'FT_UINT16':
                return struct.pack('!H', v)
            if ft == 'FT_UINT8':
                return bytes([v & 0xff])
            return bytes([0x11, 0x22])
        return bytes((0x11 * (i + 1) + n) & 0xff for i in range(4))

    def content(self, name, excl=frozenset()):
        """Contents octets of a value of type name, and whether constructed."""
        t = TYPES[name]
        k = t[0]
        self.mark(name)
        n = self.n[name]
        self.n[name] += 1
        if name in SPECIAL or name in self.override:
            return self.octets(name, n), False
        if k == 'alias':
            self.n[name] -= 1
            return self.content(t[1], excl)
        if k == 'octets':
            return self.octets(name, n), False
        if k == 'int':
            lo, hi, vals = t[1], t[2], t[3]
            cands = [v for v in (vals or []) if (lo is None or lo <= v) and (hi is None or v <= hi)]
            if cands:
                v = cands[n % len(cands)]
            elif lo is not None:
                v = min(hi, lo + 1 + n % 4)
            else:
                v = 1 + n % 4
            return ber_int(v), False
        if k == 'null':
            return b'', False
        if k == 'bool':
            return b'\xff', False
        if k == 'gtime':
            return b'20261027123045Z', False
        if k == 'tagged':
            _, cls, tag, impl, inner = t
            if impl and TYPES[self.resolve(inner)][0] != 'choice':
                return self.content(inner)
            return self.full(inner), True
        if k in ('seq', 'set'):
            return b''.join(self.field(f[1], f[2], f[3], f[4]) for f in t[1]
                            if not ('OPTIONAL' in f[3] and f[4] in self.skip)), True
        if k == 'seqof':
            lo, hi, item = t[1], t[2], t[3]
            cnt = 2
            if TYPES[self.resolve(item[4])][0] == 'choice':
                cnt = max(cnt, len(self.reachable(self.resolve(item[4]), frozenset())))
            return b''.join(self.field(item[1], item[2], item[3], item[4]) for _ in range(cnt)), True
        if k == 'choice':
            return self.full(name, excl), True
        raise ValueError(name)

    def full(self, name, excl=frozenset()):
        self.mark(name)
        t = TYPES[name]
        k = t[0]
        if k == 'alias' and name not in SPECIAL:
            return self.full(t[1], excl)
        if k == 'choice':
            alts = self.reachable(name, excl)
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

    def field(self, cls, tag, flags, fn, excl=frozenset()):
        """A component of a SET/SEQUENCE or alternative of a CHOICE."""
        if 'NOOWNTAG' in flags:
            return self.full(fn, excl)
        if 'IMPLTAG' in flags:
            body, cons = self.content(fn, excl)
        else:
            body, cons = self.full(fn, excl), True
        return tlv(cls, cons, tag, body)

    def params(self, name):
        """The parameter set of an operation: [PRIVATE 18] SET.  ANSI TCAP
        hands the whole parameter set to ANSI MAP, which dissects it with
        implicit_tag set, so the [PRIVATE 18] tag stands for the SET tag."""
        t = TYPES[name]
        assert t[0] == 'tagged' and (t[1], t[2]) == (PRI, 18)
        self.mark(name)
        body, cons = self.content(t[4])
        return tlv(PRI, True, 18, body)

    def alt_tags(self, cls, tag, fn):
        """The (class, tag) pairs a SET component can start with."""
        if tag != -1:
            return {(cls, tag)}
        t = TYPES[self.resolve(fn)]
        out = set()
        for alt in t[1]:
            out |= self.alt_tags(alt[2], alt[3], alt[5])
        return out

    def fv(self, name, fieldname, content):
        """Parameter `fieldname` of the SET of `name` with the given contents."""
        t = TYPES[self.resolve(TYPES[name][4])]
        f = {f[0]: f for f in t[1]}[fieldname]
        return tlv(f[1], False, f[2], content)

    def mand(self, name, *extra):
        """Parameter set of `name` (an operation argument or result type):
        the given parameters, then the mandatory ones not among them."""
        t = TYPES[self.resolve(TYPES[name][4])]
        given = {first_tag(p) for p in extra}
        body = b''.join(extra)
        for f in t[1]:
            if 'OPTIONAL' not in f[3] and not (self.alt_tags(f[1], f[2], f[4]) & given):
                body += self.field(f[1], f[2], f[3], f[4])
        return tlv(PRI, True, 18, body)

    def params_with(self, name, only):
        """Only the listed parameters (by field name, in the given order)."""
        t = TYPES[self.resolve(TYPES[name][4])]
        fields = {f[0]: f for f in t[1]}
        body = b''
        for fname in only:
            if isinstance(fname, bytes):
                body += fname
                continue
            f = fields[fname]
            body += self.field(f[1], f[2], f[3], f[4])
        return tlv(PRI, True, 18, body)


def first_tag(b):
    cls, tag = b[0] >> 6, b[0] & 0x1f
    if tag == 0x1f:
        tag = 0
        i = 1
        while True:
            tag = tag << 7 | (b[i] & 0x7f)
            if not b[i] & 0x80:
                break
            i += 1
    return (cls, tag)


def param(tag, content, constructed=False):
    """A context-specific (IMPLICIT) ANSI MAP parameter."""
    return tlv(CON, constructed, tag, content)


def pset(*params):
    return tlv(PRI, True, 18, b''.join(params))


# ---------------------------------------------------------------- ANSI TCAP

def component_ids(*ids):
    return tlv(PRI, False, 15, bytes(ids))


def invoke(inv_id, opcode, arg, last=True, corr=None):
    ids = (inv_id,) if corr is None else (inv_id, corr)
    body = component_ids(*ids) + tlv(PRI, False, 17, struct.pack('!H', 0x0900 | opcode))
    if arg is not None:
        body += arg
    return tlv(PRI, True, 9 if last else 13, body)


def return_result(inv_id, res, last=True):
    body = component_ids(inv_id)
    if res is not None:
        body += res
    return tlv(PRI, True, 10 if last else 14, body)


def return_error(inv_id, errcode, param_set):
    body = component_ids(inv_id) + tlv(PRI, False, 20, bytes([errcode]))
    if param_set is not None:
        body += param_set
    return tlv(PRI, True, 11, body)


def reject(inv_id, problem, param_set=b''):
    body = component_ids(inv_id) + tlv(PRI, False, 21, struct.pack('!H', problem))
    if param_set is not None:
        body += tlv(PRI, True, 18, param_set)
    return tlv(PRI, True, 12, body)


UNI_PKG, QUERY_PERM, QUERY_NOPERM, RESPONSE, CONV_PERM, CONV_NOPERM = 1, 2, 3, 4, 5, 6


def package(ptype, tid, components):
    return tlv(PRI, True, ptype, tlv(PRI, False, 7, tid) + tlv(PRI, True, 8, b''.join(components)))


# ---------------------------------------------------------------- SS7 over IP

def node(i, ssn):
    return {'ip': bytes([10, 0, 0, i]), 'mac': bytes([2, 0, 0, 0, 0, i]), 'pc': (i, i, i),
            'port': 2904 + i, 'vtag': 0x41000000 + i, 'ssn': ssn}


MSC = node(1, 8)
HLR = node(2, 6)
VLR = node(3, 7)
MC = node(4, 11)
MSCB = node(21, 8)
RELAY = node(22, 8)
tsn = {}


def ansi_pc(network, cluster, member):
    return network << 16 | cluster << 8 | member


def sccp_addr(n):
    # ANSI address indicator: national, route on SSN, SSN and PC present;
    # SSN first, then the point code member, cluster, network
    return bytes([0xc3, n['ssn'], n['pc'][2], n['pc'][1], n['pc'][0]])


def sccp_udt(src, dst, data):
    called = sccp_addr(dst)
    calling = sccp_addr(src)
    if len(data) <= 255:
        p1 = 3
        p2 = 2 + len(called) + 1
        p3 = 1 + len(called) + 1 + len(calling) + 1
        return (bytes([0x09, 0x00, p1, p2, p3]) + bytes([len(called)]) + called +
                bytes([len(calling)]) + calling + bytes([len(data)]) + data)
    # Long Unitdata: class 0, hop counter, four 2-octet pointers
    p1 = 7
    p2 = 6 + len(called)
    p3 = 5 + len(called) + len(calling)
    return (bytes([0x13, 0x00, 0x0f]) + struct.pack('<HHHH', p1, p2, p3, 0) +
            bytes([len(called)]) + called + bytes([len(calling)]) + calling +
            struct.pack('<H', len(data)) + data)


def m3ua_data(src, dst, sccp, sls):
    pd = struct.pack('!IIBBBB', ansi_pc(*src['pc']), ansi_pc(*dst['pc']), 3, 2, 0, sls) + sccp
    prm = struct.pack('!HH', 0x0210, 4 + len(pd)) + pd
    prm += b'\0' * (-len(prm) % 4)
    return struct.pack('!BBBBI', 1, 0, 1, 1, 8 + len(prm)) + prm


def sctp_packet(src, dst, payload):
    key = (src['ip'], dst['ip'])
    tsn[key] = tsn.get(key, 0) + 1
    chunk = sctp_data(payload, tsn[key], 3, ssn=tsn[key] & 0xffff)
    return sctp(chunk, src['port'], dst['port'], dst['vtag'])


def frame(src, dst, tcap, sls=0):
    pkt = sctp_packet(src, dst, m3ua_data(src, dst, sccp_udt(src, dst, tcap), sls))
    return eth(ipv4(pkt, 132, src=src['ip'], dst=dst['ip'], ident=0, flags_frag=0x4000), 0x0800,
               dst=dst['mac'], src=src['mac'])


def write_frames(path, frames):
    """frames: (bytes, note) pairs."""
    write_pcap(path, [fr for fr, _ in frames], ts=lambda i: (1792540800 + i, 0))


def read_exported_pdus(path):
    """TCAP payloads of an Exported PDU (linktype 252) pcap."""
    out = []
    for rec in read_pcap(path):
        p = 0
        while p + 4 <= len(rec):
            t, ln = struct.unpack('!HH', rec[p:p + 4])
            p += 4 + ln
            if t == 0:
                break
        out.append(rec[p:])
    return out


# ---------------------------------------------------------------- captures

# A server-to-client direction per operation family is not modelled; the
# requests go from the serving MSC/VLR to the HLR (or the MC for SMS) and
# the results come back.
SMS_OPS = {51, 52, 53, 54, 55, 78, 101, 111}


def build(repro_dir):
    enc = Encoder()
    clean = []
    malformed = []
    tid_n = [0x20000000]

    def tid():
        tid_n[0] += 1
        return struct.pack('!I', tid_n[0])

    def add(caps, src, dst, tcap, note):
        caps.append((frame(src, dst, tcap, len(caps) & 0x0f), note))

    results = {c: p for c, p in OPS['res']}
    args = {c: p for c, p in OPS['arg']}

    # ------------------------------------------------ every operation
    # queryWithPerm with the Invoke, then a response with the ReturnResult.
    # Repeated in new transactions while a CHOICE alternative is used for
    # the first time.
    for code, argtype in OPS['arg']:
        src, dst = (MSC, MC) if code in SMS_OPS else (MSC, HLR)
        for rnd in range(10):
            if rnd and not (enc.pending(argtype) or (code in results and enc.pending(results[code]))):
                break
            enc.new.clear()
            arg = enc.params(argtype)
            res = enc.params(results[code]) if code in results else None
            if rnd and not enc.new:
                break
            t = tid()
            add(clean, src, dst, package(QUERY_PERM, t, [invoke(1, code, arg)]), 'op %d %s Invoke' % (code, argtype))
            if res is not None:
                add(clean, dst, src, package(RESPONSE, t, [return_result(1, res)]), 'op %d %s ReturnResult' % (code, results[code]))
    # Operations without parameters in ANSI MAP (Mobile On Channel, Flash
    # Request result) and the reserved/unknown ones: "Carries no data" or
    # "Unknown invokeData blob" (notes/warnings, not errors)
    for code in OPS['arg_nodata'] + [103, 105, 108, 109, 110, 120]:
        t = tid()
        add(clean, MSC, HLR, package(QUERY_PERM, t, [invoke(1, code, pset(param(21, SPECIAL['MSCID'](0))))]),
            'op %d Invoke without ANSI MAP decoding' % code)
        if code == 3:
            continue
        add(clean, HLR, MSC, package(RESPONSE, t, [return_result(1, pset(param(21, SPECIAL['MSCID'](0))))]),
            'op %d ReturnResult without ANSI MAP decoding' % code)
    # ReturnResults of operations with an Invoke but no result decoding
    for code, argtype in OPS['arg']:
        if code in results or code == 26:
            continue
        t = tid()
        add(clean, MSC, HLR, package(QUERY_PERM, t, [invoke(1, code, enc.params(argtype))]), 'op %d Invoke' % code)
        add(clean, HLR, MSC, package(RESPONSE, t, [return_result(1, pset(param(21, SPECIAL['MSCID'](1))))]),
            'op %d ReturnResult, unknown result data' % code)
    # Flash Request ReturnResult: "Carries no data"
    t = tid()
    add(clean, MSC, HLR, package(QUERY_PERM, t, [invoke(1, 26, enc.params(args[26]))]), 'FlashRequest Invoke')
    add(clean, HLR, MSC, package(RESPONSE, t, [return_result(1, pset())]), 'FlashRequest ReturnResult (no data)')

    # ------------------------------------------------ remaining hand-written branches
    # Each DigitsType variant at least once (they cycle over every digits
    # parameter above as well): RoutingRequest destination digits
    for i in range(len(DIGITS)):
        t = tid()
        p = enc.mand('RoutingRequest', enc.fv('RoutingRequest', 'destinationDigits', DIGITS[i]))
        add(clean, MSC, VLR, package(QUERY_PERM, t, [invoke(1, 16, p)]), 'RoutingRequest digits variant %d' % i)

    # ------------------------------------------------ SMS bearer data hand-off

    def bd(data):
        return param(105, data)

    def tele(v):
        return param(116, struct.pack('!H', v))

    def si(v):
        return param(193, bytes([v]))

    esn = param(9, b'\x9a\x12\x34\x56')
    mscid = param(21, SPECIAL['MSCID'](0))
    min_ = param(8, bcd('2015550123'))

    def sms(src, dst, plist, res=None, note=''):
        t = tid()
        add(clean, src, dst, package(QUERY_PERM, t, [invoke(1, 53, enc.mand('SMSDeliveryPointToPoint', *plist))]), 'SMSDPP ' + note)
        if res is not None:
            add(clean, dst, src, package(RESPONSE, t, [return_result(1, enc.mand('SMSDeliveryPointToPointRes', *res))]),
                'SMSDPP result ' + note)
        return t

    # IS-637: TeleserviceIdentifier after / before the bearer data, each
    # registered teleservice
    sms(MC, MSC, [bd(is637_bearer()), tele(4098), esn, min_], note='IS-637, teleservice after bearer data')
    sms(MC, MSC, [tele(4097), bd(is637_bearer('Page', 1, 7)), esn, min_], note='IS-637 paging, teleservice first')
    sms(MC, MSC, [tele(4099), bd(is637_bearer('VMN', 1, 8)), esn, min_], note='IS-637 VMN')
    sms(MC, MSC, [tele(4101), bd(is637_bearer('WEMT', 1, 9)), esn, min_], note='IS-637 WEMT')
    sms(MC, MSC, [tele(4100), bd(bytes([0x00, 0x03, 0x10, 0x00, 0xa0])), esn, min_], note='IS-637 WAP')
    sms(MC, MSC, [bd(is637_bearer()), tele(32513), esn, min_], note='teleservice not registered')
    # zero length bearer data and teleservice identifier
    sms(MC, MSC, [bd(b''), param(116, b''), esn, min_], note='empty bearer data and teleservice')
    # The ServiceIndicator only selects IS-683/IS-801 when there is no
    # TeleserviceIdentifier; it is a mandatory parameter of the ASN.1, so
    # these carry an empty one (no teleservice, no BER warning).
    notele = param(116, b'')
    # IS-683 OTASP (1) and OTAPA (3): ServiceIndicator after and before the
    # bearer data; the result's bearer data uses the ServiceIndicator saved
    # with the Invoke (reverse link)
    sms(MSC, HLR, [bd(IS683_FORWARD), notele, si(1), esn, min_], [bd(IS683_REVERSE)], note='IS-683 OTASP')
    sms(MSC, HLR, [si(3), bd(IS683_FORWARD), notele, esn, min_], [bd(IS683_REVERSE)], note='IS-683 OTAPA, ServiceIndicator first')
    # IS-801 position determination (4)
    sms(MSC, MC, [bd(IS801_FORWARD), notele, si(4), esn, min_], [bd(IS801_REVERSE)], note='IS-801')
    sms(MSC, MC, [si(4), notele, bd(IS801_FORWARD), esn, min_], [bd(IS801_REVERSE)], note='IS-801, ServiceIndicator first')
    # ServiceIndicator without a bearer-data dissector
    sms(MSC, MC, [bd(is637_bearer()), notele, si(2), esn, min_], [bd(is637_bearer())], note='TDMA OTASP: not handed off')
    # Repeated ServiceIndicator / TeleserviceIdentifier: the bearer data is
    # dissected once (the bug fixed on the branch re-dissected it each time)
    sms(MSC, MC, [bd(IS801_FORWARD), notele] + [si(4)] * 5 + [esn, min_], note='repeated ServiceIndicator')
    sms(MC, MSC, [bd(is637_bearer())] + [tele(4098)] * 5 + [esn, min_], note='repeated TeleserviceIdentifier')
    # InterSystemSMSDeliveryPointToPoint and SMSDeliveryForward carry it too
    t = tid()
    add(clean, MC, MSCB, package(QUERY_PERM, t, [invoke(1, 111, enc.mand('InterSystemSMSDeliveryPointToPoint', bd(is637_bearer()), tele(4098)))]),
        'InterSystemSMSDeliveryPointToPoint IS-637')

    # ------------------------------------------------ response matching
    # ansi_map.transaction.matchtype decides which saved Invoke a result
    # belongs to: the transaction ID only, TID and the Invoke's source
    # (the default), or TID, source and destination.  ANSI TCAP matches on
    # the TID only by default and gives ANSI MAP its operation code, which
    # ANSI MAP uses when it finds no saved Invoke.
    #
    # Same TID twice: Invoke VLR -> HLR RegistrationNotification, then
    # MSC-B -> MC LocationRequest with the same TID; result HLR -> VLR.
    # TCAP (TID only) matches the LocationRequest; ANSI MAP finds the
    # RegistrationNotification with TID+source and TID+source+destination,
    # the LocationRequest with TID only.
    t = tid()
    add(clean, VLR, HLR, package(QUERY_PERM, t, [invoke(1, 13, enc.params(args[13]))]), 'matching: RegistrationNotification VLR->HLR')
    add(clean, MSCB, MC, package(QUERY_PERM, t, [invoke(1, 15, enc.params(args[15]))]), 'matching: LocationRequest, same TID')
    add(clean, HLR, VLR, package(RESPONSE, t, [return_result(1, enc.mand('RegistrationNotificationRes'))]),
        'matching: result HLR->VLR')
    # Result through a relay: Invoke MSC -> HLR, result RELAY -> MSC: found
    # with TID only and TID+source, not with TID+source+destination.
    t = tid()
    add(clean, MSC, HLR, package(QUERY_PERM, t, [invoke(1, 6, enc.params(args[6]))]), 'relay: QualificationRequest MSC->HLR')
    add(clean, RELAY, MSC, package(RESPONSE, t, [return_result(1, enc.params(results[6]))]), 'relay: result RELAY->MSC')
    # Result sent to another node: Invoke MSC -> HLR, then an unrelated SMS
    # Invoke, then the result HLR -> MSC-B.  Only TID-only matching finds the
    # saved Invoke; with the default ANSI MAP uses the operation TCAP
    # matched.  It used to take the operation code of the previous packet
    # (SMS Delivery Point to Point), as in the stale_opcode reproducer.
    t = tid()
    add(clean, MSC, HLR, package(QUERY_PERM, t, [invoke(1, 13, enc.params(args[13]))]), 'stale_opcode: RegistrationNotification MSC->HLR')
    add(clean, MSC, MC, package(QUERY_PERM, tid(), [invoke(1, 53, enc.params(args[53]))]), 'stale_opcode: unrelated SMSDeliveryPointToPoint')
    add(clean, HLR, MSCB, package(RESPONSE, t, [return_result(1, enc.mand('RegistrationNotificationRes'))]),
        'stale_opcode: RegistrationNotification result HLR->MSC-B')

    # ------------------------------------------------ ReturnError and Reject
    # Info column names the matched operation (it used the previous
    # packet's operation code: the return_error reproducer)
    for code, err in ((13, 0x81), (15, 0x83), (53, 0x86), (27, 0x8e)):
        t = tid()
        add(clean, MSC, HLR, package(QUERY_PERM, t, [invoke(1, code, enc.params(args[code]))]), 'op %d Invoke' % code)
        add(clean, MSC, MC, package(QUERY_PERM, tid(), [invoke(1, 53, enc.params(args[53]))]), 'unrelated SMSDeliveryPointToPoint')
        add(clean, HLR, MSC, package(RESPONSE, t, [return_error(1, err, pset(param(21, SPECIAL['MSCID'](0))))]),
            'op %d ReturnError 0x%02x' % (code, err))
    # ReturnError with no parameter set (not passed to ANSI MAP) and a Reject
    t = tid()
    add(clean, MSC, HLR, package(QUERY_PERM, t, [invoke(1, 14, enc.params(args[14]))]), 'RegistrationCancellation Invoke')
    add(clean, HLR, MSC, package(RESPONSE, t, [return_error(1, 0x82, None)]), 'ReturnError without parameters')
    t = tid()
    add(clean, MSC, HLR, package(QUERY_PERM, t, [invoke(1, 15, enc.params(args[15]))]), 'LocationRequest Invoke')
    add(clean, HLR, MSC, package(RESPONSE, t, [reject(1, 0x0102)]), 'Reject')

    # ------------------------------------------------ TCAP package variants
    # InvokeNotLast + InvokeLast in a conversation (8 octet TID), then
    # ReturnResultNotLast + ReturnResultLast; queryWithoutPerm;
    # conversationWithoutPerm; unidirectional
    t1, t2 = tid(), tid()
    add(clean, MSC, HLR, package(QUERY_PERM, t1, [invoke(1, 27, enc.params(args[27]))]), 'AuthenticationDirective Invoke')
    # (both BaseStationChallenge: TCAP and ANSI MAP match on the transaction,
    # not the invoke ID, so every result gets the last Invoke's operation)
    add(clean, HLR, MSC, package(CONV_PERM, t2 + t1, [invoke(2, 29, enc.params(args[29]), last=False, corr=1),
                                                      invoke(3, 29, enc.params(args[29]), corr=1)]),
        'conversation: BaseStationChallenge InvokeNotLast + InvokeLast')
    # (ANSI TCAP matches a conversation on the last four octets of the TID)
    add(clean, MSC, HLR, package(CONV_NOPERM, t2 + t1, [return_result(2, enc.params(results[29]), last=False),
                                                        return_result(3, enc.params(results[29]))]),
        'conversation: ReturnResultNotLast + ReturnResultLast')
    add(clean, HLR, MSC, package(RESPONSE, t1, [return_result(1, enc.params(results[27]))]), 'AuthenticationDirective ReturnResult')
    t = tid()
    add(clean, VLR, HLR, package(QUERY_NOPERM, t, [invoke(1, 22, enc.params(args[22]))]), 'MSInactive queryWithoutPerm')
    add(clean, HLR, VLR, package(UNI_PKG, b'', [invoke(1, 20, enc.params(args[20]))]), 'UnreliableRoamerDataDirective unidirectional')

    # ------------------------------------------------ branch reproducers
    # The payloads of the ansi_map_*.pcap files.  Those that decode without
    # a Malformed-group expert info are used as they are; the others lack
    # mandatory parameters (BER "Missing field" warnings) or throw, so they
    # go to the malformed capture, and an equivalent with the mandatory
    # parameters is in the main capture.
    small = bytes([0x00, 0x03, 0x20, 0x01, 0x00])   # IS-637 Message Identifier

    def R(n):
        return read_exported_pdus(os.path.join(repro_dir, n))

    for i, p in enumerate(R('ansi_map_teleid.pcap')):
        add(clean, MC, MSC, p, 'reproducer teleid %d' % (i + 1))
    for p in R('ansi_map_layers_assert_teleid.pcap'):
        add(clean, MC, MSC, p, 'reproducer layers_assert_teleid: bearer data + 600 TeleserviceIdentifier')
    for n in ('ansi_map_amplify_small.pcap', 'ansi_map_amplify.pcap'):
        for p in R(n):
            add(clean, MC, MSC, p, 'reproducer %s: large bearer data + repeated TeleserviceIdentifier' % n[9:-5])
    for n in ('ansi_map_null_tid.pcap', 'ansi_map_tap.pcap', 'ansi_map_layers_assert.pcap',
              'ansi_map_amplify_si_small.pcap', 'ansi_map_amplify_si.pcap',
              'ansi_map_stale_opcode.pcap', 'ansi_map_return_error.pcap'):
        for i, p in enumerate(R(n)):
            add(malformed, MSC, HLR, p, 'reproducer %s %d' % (n[9:-5], i + 1))
    for i, p in enumerate(R('ansi_map_fuzz_1.pcap')):
        add(malformed, MSC, HLR, p, 'reproducer fuzz_1 %d' % (i + 1))
    # Equivalents with the mandatory parameters:
    # layers_assert: 600 ServiceIndicator (IS-801) after the bearer data
    add(clean, MSC, MC, package(QUERY_PERM, tid(), [invoke(1, 53, enc.mand(
        'SMSDeliveryPointToPoint', bd(small * 2), notele, *([si(4)] * 600)))]),
        'layers_assert: bearer data + 600 ServiceIndicator')
    # amplify_si_small: a 5000 octet bearer data and 10 ServiceIndicator
    add(clean, MSC, MC, package(QUERY_PERM, tid(), [invoke(1, 53, enc.mand(
        'SMSDeliveryPointToPoint', bd(small * 1000), notele, *([si(4)] * 10)))]),
        'amplify_si_small: large bearer data + 10 ServiceIndicator')
    # null_tid: unidirectional package with an Invoke and a ReturnResult
    # (no transaction ID)
    add(clean, MSC, MC, package(UNI_PKG, b'', [
        invoke(1, 53, enc.mand('SMSDeliveryPointToPoint', bd(is637_bearer()), tele(4098)), last=False),
        return_result(1, enc.mand('SMSDeliveryPointToPointRes', enc.fv('SMSDeliveryPointToPointRes', 'sms_CauseCode', b'\x00')))]),
        'null_tid: unidirectional SMSDPP Invoke + ReturnResult')
    # tap: unknown operation 120 between two SMSDeliveryPointToPoint
    for code in (53, 120, 53):
        p = enc.mand('SMSDeliveryPointToPoint', bd(small), tele(4098)) if code == 53 else pset()
        add(clean, MSC, MC, package(QUERY_PERM, tid(), [invoke(1, code, p)]), 'tap: op %d' % code)

    # MSLocation with a 1 and a 2 octet resolution (it used to be added
    # with length -1, which always threw), and a 1-octet
    # TeleserviceIdentifier (it used to be read from the enclosing tvb and
    # threw; now treated like an empty one)
    for i in (0, 1):
        add(clean, MSC, MSCB, package(QUERY_PERM, tid(), [invoke(1, 25, enc.mand(
            'HandoffToThird', enc.fv('HandoffToThird', 'msLocation', SPECIAL['MSLocation'](i))))]),
            'HandoffToThird, MSLocation with %d octet resolution' % (i + 1))
    add(clean, MC, MSC, package(QUERY_PERM, tid(), [invoke(1, 53, enc.mand(
        'SMSDeliveryPointToPoint', param(116, b'\x10'), bd(is637_bearer())))]),
        'SMSDPP, 1-octet TeleserviceIdentifier')

    # ------------------------------------------------ malformed
    # Known open core issue: 600 distinct SMS-BearerData parameters after a
    # TeleserviceIdentifier each go to IS-637 and hit the per-frame layer
    # limit (DISSECTOR_ASSERT in call_dissector_work()); same for 600 TCAP
    # components.
    many = tlv(PRI, True, 18, tele(4098) + bd(bytes([0x00, 0x03, 0x20, 0x01, 0x00])) * 600)
    add(malformed, MC, MSC, package(QUERY_PERM, tid(), [invoke(1, 53, many)]), '600 SMS-BearerData parameters (layer limit)')
    comps = [invoke(i & 0x7f, 53, pset(tele(4098), bd(bytes([0x00, 0x03, 0x20, 0x01, 0x00]))), last=False) for i in range(599)]
    comps.append(invoke(0x7f, 53, pset(tele(4098), bd(bytes([0x00, 0x03, 0x20, 0x01, 0x00])))))
    add(malformed, MC, MSC, package(QUERY_PERM, tid(), comps), '600 TCAP components (layer limit)')
    # Hand-written decoders given too few octets: exceptions
    short = [
        (13, pset(param(21, b'\x01')), 'RegistrationNotification, 1 octet MSCID'),
        (16, enc.mand('RoutingRequest', enc.fv('RoutingRequest', 'destinationDigits', b'\x01')), 'RoutingRequest, 1 octet Digits'),
        (16, enc.mand('RoutingRequest', enc.fv('RoutingRequest', 'destinationDigits', b'\x01\x00\x21')), 'RoutingRequest, Digits without the digit count'),
        (16, enc.mand('RoutingRequest', enc.fv('RoutingRequest', 'destinationDigits', b'\x01\x00\xd3\x01')), 'RoutingRequest, PC/SSN digits too short'),
        (7, enc.mand('QualificationDirective', enc.fv('QualificationDirective', 'callingFeaturesIndicator', b'\x01')),
         'QualificationDirective, 1 octet CallingFeaturesIndicator'),
        (7, enc.mand('QualificationDirective', enc.fv('QualificationDirective', 'callingFeaturesIndicator', b'\x01\x02')),
         'QualificationDirective, 2 octet CallingFeaturesIndicator'),
        (36, enc.mand('FacilitiesDirective2', enc.fv('FacilitiesDirective2', 'cdmaChannelData', b'\x01\x02\x03')),
         'FacilitiesDirective2, short CDMAChannelData'),
        (13, pset(param(22, b'')), 'RegistrationNotification, empty SystemMyTypeCode'),
        (53, pset(param(193, b''), bd(is637_bearer())), 'SMSDPP, empty ServiceIndicator'),
        (53, pset(bd(IS683_FORWARD[:1]), si(1)), 'SMSDPP, truncated IS-683 message'),
    ]
    # MSLocation without the resolution octet
    short.append((25, enc.mand('HandoffToThird', enc.fv('HandoffToThird', 'msLocation', SPECIAL['MSLocation'](0)[:6])),
                  'HandoffToThird, MSLocation without resolution'))
    for code, p, note in short:
        add(malformed, MSC, HLR, package(QUERY_PERM, tid(), [invoke(1, code, p)]), note)
    # A parameter set that is not a SET, and a truncated parameter
    add(malformed, MSC, HLR, package(QUERY_PERM, tid(), [invoke(1, 13, tlv(UNI, True, 16, mscid))]), 'SEQUENCE instead of SET')
    add(malformed, MSC, HLR, package(QUERY_PERM, tid(), [invoke(1, 13, b'\xf2\x05' + mscid[:3])]), 'truncated parameter set')
    return clean, malformed, enc


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean, malformed, enc = build(reproducer_dir(os.path.dirname(os.path.abspath(__file__)),
                                             ['ansi_map_gen.py', ('ansi_map_fuzz_gen.py', ['ansi_map_fuzz_1.pcap', '1'])]))
    write_frames(os.path.join(out, 'ansi_map-coverage.pcap'), clean)
    write_frames(os.path.join(out, 'ansi_map-coverage-malformed.pcap'), malformed)
    missing = sorted(set(TYPES) - enc.seen)
    print('%d + %d frames; types not encoded: %s' % (len(clean), len(malformed), ' '.join(missing)), file=sys.stderr)


if __name__ == '__main__':
    main()
