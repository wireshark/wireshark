#!/usr/bin/env python3
# Generates test/captures/gprscdr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the GPRSCDR dissector
(packet-gprscdr.c, generated from asn1/gprscdr).  Everything is built
with struct; nothing comes from a real network.
Usage: mkgprscdr.py <output directory>

The GPRS charging data records (BER, 3GPP TS 32.298) are carried in GTP'
(UDP port 3386) Data Record Transfer Requests: release 6 and earlier
records are GPRSCallEventRecord, later ones GPRSRecord.  The records are
encoded from the type structure of the dissector (gprscdr_schema.json,
written from the ber_sequence_t/ber_choice_t tables of packet-gprscdr.c
by extract_schema.py): one record of every record type with every
optional field present and the choices rotated from record to record.
CAMELInformationPDP is carried in the CAMEL Charging Information
Container of a GTP Create PDP Context Request.

Writes:
  gprscdr-coverage.pcap            one record of each type, GTP' packets
                                   with two records, CAMEL information
                                   and the reproducer of the fix
  gprscdr-coverage-malformed.pcap  unknown record type, bad TimeStamp,
                                   cut-short fields
"""
import json
import os
import sys
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (captured bytes, original length)
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload

def eth(dst, src, et, payload):
    return dst + src + struct.pack('>H', et) + payload

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    """Ethernet/IPv4/TCP segment with correct checksums."""
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    if flags == 0x02:
        ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0)
    h = h[:20] + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 10.0.0.1, server = 10.0.0.2."""
    def __init__(self, cport, sport, frames, cip='10.0.0.1', sip='10.0.0.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
    def _send(self, from_client, flags, data=b''):
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)
    def ack_c(self): self._send(True, 0x10)
    def ack_s(self): self._send(False, 0x10)
    def fin_s(self, data=b''): self._send(False, 0x19, data)
    def fin_c(self): self._send(True, 0x11)
    def close(self):
        self.fin_s(); self.fin_c(); self.ack_s()


HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = json.load(open(os.path.join(HERE, 'gprscdr_schema.json')))
TABLES, TYPES = SCHEMA['tables'], SCHEMA['types']

UNI = {'BOOLEAN': 1, 'INTEGER': 2, 'BITSTRING': 3, 'OCTETSTRING': 4, 'NULL': 5, 'OID': 6, 'ENUMERATED': 10,
       'UTF8String': 12, 'SEQUENCE': 16, 'SET': 17, 'NumericString': 18, 'PrintableString': 19,
       'IA5String': 22, 'GraphicString': 25, 'VisibleString': 26}
CLS = {'BER_CLASS_UNI': 0, 'BER_CLASS_APP': 1, 'BER_CLASS_CON': 2, 'BER_CLASS_PRI': 3}


def tlv(tag, content=b''):
    n = len(content)
    if n < 0x80:
        l = bytes([n])
    elif n < 0x100:
        l = bytes([0x81, n])
    else:
        l = bytes([0x82]) + struct.pack('>H', n)
    return bytes([tag]) + l + content


def ident(cls, cons, tag):
    if tag < 31:
        return bytes([(cls << 6) | (0x20 if cons else 0) | tag])
    enc = [tag & 0x7f]
    tag >>= 7
    while tag:
        enc.insert(0, 0x80 | (tag & 0x7f))
        tag >>= 7
    return bytes([(cls << 6) | (0x20 if cons else 0) | 0x1f]) + bytes(enc)


def retag(t, cls, tag):
    """Replace the identifier octet (a universal tag, one octet) of an
    encoded TLV, keeping the constructed bit."""
    return ident(cls, t[0] & 0x20, tag) + t[1:]


def tlv_tag(tagbytes, content=b''):
    return tagbytes + tlv(0, content)[1:]


def ber_int(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return v.to_bytes(n, 'big', signed=True)


def oid_bytes(s):
    p = [int(x) for x in s.split('.')]
    out = bytes([40 * p[0] + p[1]])
    for x in p[2:]:
        enc = [x & 0x7f]
        x >>= 7
        while x:
            enc.insert(0, 0x80 | (x & 0x7f))
            x >>= 7
        out += bytes(enc)
    return out


# Values of the external types (gsm_map) and of the types with their own decoding
TBCD = bytes.fromhex('2143658709f1')
EXT = {
    'AddressString': lambda: tlv(4, bytes.fromhex('91214365f7')),
    'ISDN_AddressString': lambda: tlv(4, bytes.fromhex('91214365f7')),
    'IMEI': lambda: tlv(4, bytes.fromhex('3a5a8201428a9f21')[:8]),
    'IMSI': lambda: tlv(4, bytes.fromhex('21436587092143f5')),
    'ch_CallReferenceNumber': lambda: tlv(4, bytes.fromhex('0102030405060708')),
    'er_PositionMethodFailure_Diagnostic': lambda: tlv(10, b'\x00'),
    'er_UnauthorizedLCSClient_Diagnostic': lambda: tlv(10, b'\x00'),
    'LCSClientExternalID': lambda: tlv(0x30, tlv(0x80, bytes.fromhex('91214365f7'))),
    'LCSClientInternalID': lambda: tlv(10, b'\x01'),
    'lcs_Ext_GeographicalInformation': lambda: tlv(4, bytes.fromhex('1080008000800080')[:7]),
    'lcs_LCSClientType': lambda: tlv(10, b'\x01'),
    'lcs_LCS_Priority': lambda: tlv(4, b'\x00'),
    'lcs_LocationType': lambda: tlv(0x30, tlv(0x80, b'\x00')),
    'ms_DefaultGPRS_Handling': lambda: tlv(10, b'\x00'),
    'ms_DefaultSMS_Handling': lambda: tlv(10, b'\x01'),
    'ms_NotificationToMSUser': lambda: tlv(10, b'\x00'),
    'ms_ServiceKey': lambda: tlv(2, b'\x64'),
    'RAIdentity': lambda: tlv(4, bytes.fromhex('62f2100001ff')),
    'ss_LocationMethod': lambda: tlv(10, b'\x00'),
}


class Enc:
    def __init__(self):
        self.c = 0            # rotating counter, varies the choices and values
        self.stack = []
        self.uli = 0
        self.cc = {}          # per CHOICE: alternatives used so far
        self.seen = set()     # types encoded
        self.ov = {}          # type name -> function giving an encoded value
        self.ts_lists = False  # SEQUENCE OF TimeStamp (the dissector rejects the elements)
        self.pdp = 0

    def tick(self):
        self.c += 1
        return self.c

    # --- a value of type fn (name as in the dissect_ function), natural tag
    def fn(self, fname, depth=0):
        if fname.startswith('dissect_gprscdr_'):
            return self.typ(fname[len('dissect_gprscdr_'):], depth)
        if fname == 'NULL':
            return tlv(5)
        base = fname.replace('dissect_gsm_map_', '').replace('dissect_gsm_', '')
        return EXT[base]()

    def typ(self, name, depth):
        t = TYPES[name]
        k = t['kind']
        c = self.tick()
        self.seen.add(name)
        if name in self.ov:
            return self.ov[name]()
        if name == 'TimeStamp':
            return tlv(4, bytes.fromhex('230517123045') + b'+' + bytes.fromhex('0200'))
        if name == 'MSTimeZone':
            return tlv(4, bytes([0x4a, c % 4]))
        if name == 'PLMN_Id':
            return tlv(4, bytes.fromhex('62f210'))
        if name == 'QoSInformation':
            return tlv(4, bytes.fromhex('23511b2c8ca9449402000000b401')[:12 + (c % 3) * 0])
        if name == 'PDPType':
            self.pdp += 1
            v = [b'\x01', bytes.fromhex('f121') + bytes([10, 0, 0, 1]), b'\x02', bytes.fromhex('f157') + bytes(range(16)),
                 bytes.fromhex('f001'), b'\x03', bytes.fromhex('f121')][self.pdp % 7]
            return tlv(4, v)
        if name == 'T_aRP':
            return tlv(4, bytes([0x49 + (c % 2) * 0x20]))
        if name == 'T_information':
            return tlv(4, b'AAAA')
        if t.get('special', '').startswith('uli'):
            self.uli += 1
            if t['special'] == 'uli1':      # GTP: geographic location type, MCC/MNC, LAC, CI/SAC/RAC
                v = [bytes([0]) + bytes.fromhex('62f2100001') + b'\x00\x02', bytes([1]) + bytes.fromhex('62f2100001') + b'\x00\x03',
                     bytes([2]) + bytes.fromhex('62f2100001') + b'\x05\xff'][self.uli % 3]
            else:                            # GTPv2: flags then the locations present
                plmn = bytes.fromhex('62f210')
                v = [bytes([0x18]) + plmn + b'\x00\x01' + plmn + b'\x00\x00\x00\x07',
                     bytes([0x01]) + plmn + b'\x00\x01\x00\x02',
                     bytes([0x02]) + plmn + b'\x00\x01\x00\x03',
                     bytes([0x04]) + plmn + b'\x00\x01\x00\x04',
                     bytes([0x20]) + plmn + b'\x00\x05',
                     bytes([0x40]) + plmn + b'\x00\x00\x00\x08',
                     bytes([0x80]) + plmn + b'\x00\x00\x00\x09'][self.uli % 7]
            return tlv(4, v)
        if 'alias' in t:
            return self.fn(t['alias'], depth)
        if k is None:
            raise Exception('type %s' % name)
        if k in ('integer', 'constrained_integer'):
            lo, hi = t.get('range') or (0, 1000)
            if k == 'integer':
                v = [1, 2, 0, 3][c % 4]
            else:
                v = min(hi, lo + c % 3)
            return tlv(2, ber_int(v))
        if k == 'boolean':
            return tlv(1, b'\xff' if c % 2 else b'\x00')
        if k == 'null':
            return tlv(5)
        if k == 'object_identifier_str':
            return tlv(6, oid_bytes('1.3.6.1.4.1.5.1.2.3'))
        if k in ('octet_string', 'constrained_octet_string'):
            lo, hi = t.get('range') or (1, 6)
            n = lo if lo == hi else min(hi, lo + c % 3)
            return tlv(4, bytes((0x10 + c + i) & 0xff for i in range(n)) if n else b'')
        if k in ('restricted_string', 'constrained_restricted_string'):
            lo, hi = t.get('range') or (1, 30)
            n = min(max(lo, 12), hi)
            s = ('internet.example.org' * 3)[:n].encode()
            return tlv(UNI[t['tag']], s)
        if k == 'bitstring':
            n = t['nbits']
            nb = (n + 7) // 8
            bits = ''.join('1' if (c % 2 == 0 or i % 2 == 0) else '0' for i in range(n)) + '0' * (nb * 8 - n)
            return tlv(3, bytes([nb * 8 - n]) + int(bits, 2).to_bytes(nb, 'big'))
        if k in ('sequence', 'set', 'sequence_of', 'set_of'):
            return self.constructed(name, t, depth)
        if k == 'choice':
            return self.choice(name, t, depth)
        raise Exception('kind %s' % k)

    def constructed(self, name, t, depth):
        ents = TABLES[t['table']]
        tag = 0x30 if t['kind'] in ('sequence', 'sequence_of') else 0x31
        body = b''
        self.stack.append(name)
        if t['kind'] in ('sequence_of', 'set_of'):
            if ents[0]['fn'] == 'dissect_gprscdr_TimeStamp' and not self.ts_lists:
                self.stack.pop()
                return tlv(tag, b'')
            for _ in range(1 + self.tick() % 2 if depth < 4 else 1):
                body += self.entry(ents[0], depth + 1)
        else:
            for e in ents:
                if 'OPTIONAL' in e['flags'] and (depth > 9 or e['fn'].replace('dissect_gprscdr_', '') in self.stack):
                    continue
                body += self.entry(e, depth + 1)
        self.stack.pop()
        return tlv(tag, body)

    def choice(self, name, t, depth, index=None):
        ents = TABLES[t['table']]
        self.stack.append(name)
        cand = [e for e in ents if e['fn'].replace('dissect_gprscdr_', '') not in self.stack] or ents
        self.cc[name] = self.cc.get(name, -1) + 1
        e = cand[(self.cc[name] if index is None else index) % len(cand)]
        out = self.entry(e, depth + 1)
        self.stack.pop()
        return out

    def wraps(self, fname):
        """True for a CHOICE (or ANY): with an implicit tag the alternative
        is carried inside the tagged element, as the dissector reads it."""
        while fname.startswith('dissect_gprscdr_'):
            n = fname[len('dissect_gprscdr_'):]
            if n == 'T_information':
                return True
            t = TYPES[n]
            if 'alias' in t:
                fname = t['alias']
                continue
            return t['kind'] == 'choice'
        return False

    def entry(self, e, depth):
        inner = self.fn(e['fn'], depth)
        fl = e['flags']
        if 'NOOWNTAG' in fl:
            if e['cls'] == 'BER_CLASS_UNI':
                tg = e['tag'].replace('BER_UNI_TAG_', '')
                tg = {'OCTETSTRING': 'OCTETSTRING', 'INTEGER': 'INTEGER'}.get(tg, tg)
                inner = retag(inner, 0, UNI.get(tg, UNI.get(tg.title(), inner[0] & 0x1f)))
            return inner
        tag = int(e['tag'])
        if 'IMPLTAG' in fl and not self.wraps(e['fn']):
            return retag(inner, CLS[e['cls']], tag)
        return tlv_tag(ident(CLS[e['cls']], 1, tag), inner)


def record(enc, top, tag):
    """One record of the CHOICE `top` with the alternative whose tag is `tag`."""
    ents = TABLES[top]
    e = [x for x in ents if int(x['tag']) == tag][0]
    enc.stack = [top]
    return enc.entry(e, 1)


def gtp_prime(records, rel, ver, seq, ext=None, fmt=1):
    drp = bytes([len(records), fmt, rel, ver]) + (bytes([ext]) if ext is not None else b'')
    for r in records:
        drp += struct.pack('>H', len(r)) + r
    ies = bytes([0x7e, 0x01, 0xfc]) + struct.pack('>H', len(drp)) + drp
    return struct.pack('>BBHH', 0x2e, 0xf0, len(ies), seq) + ies


def udp_frame(sport, dport, payload, src='10.0.0.1', dst='10.0.0.2'):
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 17, udp(sport, dport, payload)))


def create_pdp_camel(info, seq):
    ie = bytes([0x9b]) + struct.pack('>H', len(info)) + info
    body = struct.pack('>IHBB', 0, seq, 0, 0) + ie
    return struct.pack('>BBH', 0x32, 16, len(body) - 4) + body


def build(path_main, path_bad):
    enc = Enc()
    f = []
    seq = 0
    # release 6 and earlier: GPRSCallEventRecord; later: GPRSRecord (twice, so that
    # the rotating choices and values differ)
    for rnd in range(2):
        for e in TABLES['GPRSCallEventRecord_choice']:
            seq += 1
            f.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSCallEventRecord_choice', int(e['tag']))], 0x16, 0x07, seq)))
        for e in TABLES['GPRSRecord_choice']:
            seq += 1
            f.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSRecord_choice', int(e['tag']))], 0x17, 0x08, seq)))
    # several records in one packet; release identifier extension
    seq += 1
    f.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSRecord_choice', 78), record(enc, 'GPRSRecord_choice', 79)],
                                             0x10, 0x09, seq, ext=0x11)))
    # CAMEL information in a GTP Create PDP Context Request
    enc.stack = []
    for i in range(3):
        f.append(udp_frame(2123, 2123, create_pdp_camel(enc.typ('CAMELInformationPDP', 0), 100 + i)))
    # the reproducer of the fix (gprscdr_stale_objid.py): a record with a
    # ManagementExtension (OID and information) from which the stale string of
    # a later extension without identifier came; the second record is in
    # the malformed capture
    info = tlv(0xa2, tlv(0x04, b'AAAA'))
    ext1 = tlv(0x30, tlv(0x06, bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x9d, 0x2a, 0x01, 0x02, 0x03])) + info)
    enc.ov['ManagementExtensions'] = lambda: tlv(0x31, ext1)
    seq += 1
    f.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSCallEventRecord_choice', 22)], 0x16, 0x07, seq)))
    enc.ov = {}
    # a MSTimeZone of one octet: only a size constraint warning; the fix returns
    # before the second octet is read (it was read from another buffer)
    enc.ov['MSTimeZone'] = lambda: tlv(4, b'\x4a')
    seq += 1
    f.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSRecord_choice', 78)], 0x17, 0x08, seq)))
    enc.ov = {}
    pcap(path_main, f)
    sys.stderr.write('types not encoded: %s\n' % ' '.join(sorted(set(TYPES) - enc.seen)))

    g = []
    enc = Enc()
    info = tlv(0xa2, tlv(0x04, b'AAAA'))
    ext1 = tlv(0x30, tlv(0x06, bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x9d, 0x2a, 0x01, 0x02, 0x03])) + info)
    # a record type that is not in the CHOICE
    g.append(udp_frame(3386, 3386, gtp_prime([bytes([0xbf, 0x63, 0x03, 0x02, 0x01, 0x01])], 0x17, 0x08, 1)))
    g.append(udp_frame(3386, 3386, gtp_prime([tlv(0xb9, tlv(0x80, b'\x01'))], 0x16, 0x07, 2)))
    # bad TimeStamp (8 octets), a TimeStamp with a bad month and a MSTimeZone of
    # one octet (the fix returns before the second octet is read) and of three
    for name, val in (('TimeStamp', bytes(8)), ('TimeStamp', bytes.fromhex('231305123045') + b'+' + bytes.fromhex('0200')),
                      ('TimeStamp', bytes(12)), ('MSTimeZone', b'\x4a'), ('MSTimeZone', b'\x4a\x01\x02')):
        enc.ov[name] = lambda val=val: tlv(4, val)
        g.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSCallEventRecord_choice', 22)], 0x16, 0x07, 3)))
        g.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSRecord_choice', 78)], 0x17, 0x08, 3)))
        enc.ov = {}
    # cut-short records: the record length claims more than is present
    full = record(enc, 'GPRSRecord_choice', 79)
    for cut in (len(full) // 2, 20, 5):
        drp = bytes([1, 1, 0x17, 0x08]) + struct.pack('>H', len(full)) + full[:cut]
        ies = bytes([0x7e, 0x01, 0xfc]) + struct.pack('>H', len(drp)) + drp
        g.append(udp_frame(3386, 3386, struct.pack('>BBHH', 0x2e, 0xf0, len(ies), 5) + ies))
    # a truncated record inside a longer container (tag with a length beyond the value)
    g.append(udp_frame(3386, 3386, gtp_prime([bytes([0xb6, 0x84, 0x01, 0x02])], 0x16, 0x07, 6)))
    # indefinite length and an empty record
    g.append(udp_frame(3386, 3386, gtp_prime([bytes([0xb6, 0x80, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00])], 0x16, 0x07, 7)))
    g.append(udp_frame(3386, 3386, gtp_prime([b''], 0x17, 0x08, 8)))
    # release identifier extension below 16
    g.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSRecord_choice', 22)], 0x10, 0x09, 9, ext=0x05)))
    # the second reproducer: an extension without identifier after one with an OID
    ext2 = tlv(0x30, tlv(0x85, b'\x00') + info)
    for ext in (ext1, ext2):
        enc.ov['ManagementExtensions'] = lambda ext=ext: tlv(0x31, ext)
        g.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSCallEventRecord_choice', 22)], 0x16, 0x07, 10)))
    enc.ov = {}
    # a list of TimeStamp elements (the dissector expects only the content of the element)
    enc.ts_lists = True
    for tag in (92, 95, 97):
        g.append(udp_frame(3386, 3386, gtp_prime([record(enc, 'GPRSRecord_choice', tag)], 0x17, 0x08, 11)))
    enc.ts_lists = False
    # CAMEL information that is not a SET
    g.append(udp_frame(2123, 2123, create_pdp_camel(bytes([0x30, 0x03, 0x02, 0x01, 0x01]), 200)))
    g.append(udp_frame(2123, 2123, create_pdp_camel(bytes([0x31, 0x20, 0x01, 0x01, 0xff]), 201)))
    pcap(path_bad, g)


if __name__ == '__main__':
    out = sys.argv[1]
    build(os.path.join(out, 'gprscdr-coverage.pcap'), os.path.join(out, 'gprscdr-coverage-malformed.pcap'))
