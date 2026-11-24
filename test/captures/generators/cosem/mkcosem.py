#!/usr/bin/env python3
# Generates test/captures/cosem_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DLMS/COSEM dissector
(packet-cosem.c, generated from epan/dissectors/asn1/cosem/).

DLMS runs over UDP and TCP port 4059 (registered by default). The first
octet of the payload selects the framing: 0x7e an HDLC frame (with HCS,
FCS and segment reassembly), 0x90 an IEC 61334-4-32 LLC header, 0x00 a
wrapper header (version, source and destination wPort, length), any
other value a bare APDU. The ACSE APDUs (AARQ, AARE, RLRQ, RLRE) are BER;
their user-information carries an xDLMS InitiateRequest or
InitiateResponse. The xDLMS APDUs (get, set, action, event notification,
access, exception) carry A-XDR data of every type, including compact
arrays and datablocks that are reassembled across frames. Every packet
is built from scratch with struct; no captured traffic is used.

Usage: mkcosem.py <output directory>

Writes:
  cosem-coverage.pcap            every framing, ACSE APDU and xDLMS APDU
                                 the dissector decodes, every data type,
                                 HDLC and datablock reassembly, and the
                                 reproducer of "COSEM: Do not let a length
                                 move back, stop repeating empty compact
                                 elements" (nested arrays of null)
  cosem-coverage-malformed.pcap  lengths past the end of the packet
                                 (including the length wrap reproducers)
"""

import os
import struct
import sys

CLIENT = bytes([192, 0, 2, 1])
METER = bytes([192, 0, 2, 2])
CPORT = 50000
DLMS_PORT = 4059


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ether_ip(proto, l4, to_meter):
    src, dst = (CLIENT, METER) if to_meter else (METER, CLIENT)
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack('>H', ip_csum(hdr)) + hdr[12:]
    macs = (b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01' if to_meter
            else b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02')
    return macs + b'\x08\x00' + hdr + l4


def udp(payload, to_meter=True):
    sp, dp = (CPORT, DLMS_PORT) if to_meter else (DLMS_PORT, CPORT)
    return ether_ip(17, struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload, to_meter)


class Tcp:
    """One TCP connection, one segment per DLMS message."""
    def __init__(self):
        self.seq = {True: 1000, False: 5000}

    def seg(self, payload, to_meter, flags=0x18):
        sp, dp = (CPORT + 1, DLMS_PORT) if to_meter else (DLMS_PORT, CPORT + 1)
        s, a = self.seq[to_meter], self.seq[not to_meter]
        hdr = struct.pack('>HHIIBBHHH', sp, dp, s, a, 0x50, flags, 65535, 0, 0)
        self.seq[to_meter] += len(payload) + (1 if flags & 0x03 else 0)
        return ether_ip(6, hdr + payload, to_meter)


# --- BER helpers -----------------------------------------------------------

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + ber_len(len(content)) + content


def oid(*arcs):
    body = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        enc = [a & 0x7f]
        a >>= 7
        while a:
            enc.insert(0, 0x80 | (a & 0x7f))
            a >>= 7
        body += bytes(enc)
    return tlv(0x06, body)


def integer(v):
    return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big', signed=True))


APP_CTX_LN = oid(2, 16, 756, 5, 8, 1, 1)
APP_CTX_SN = oid(2, 16, 756, 5, 8, 1, 2)
MECH_LLS = oid(2, 16, 756, 5, 8, 2, 1)
MECH_GMAC = oid(2, 16, 756, 5, 8, 2, 5)


def x509_name(cn):
    # RDNSequence with one RDN: commonName PrintableString
    atv = tlv(0x30, oid(2, 5, 4, 3) + tlv(0x13, cn))
    return tlv(0x30, tlv(0x31, atv))


def conformance(bits):
    """[APPLICATION 31] IMPLICIT BIT STRING (SIZE(24))"""
    return b'\x5f\x1f' + ber_len(4) + b'\x00' + bits.to_bytes(3, 'big')


def initiate_request(key=None, qos=None, version=6, conf=0x007e1f, pdu=0x04b0):
    b = b'\x01'
    if key is None:
        b += b'\x00'
    else:
        b += b'\x01' + ber_len(len(key)) + key
    b += b'\x01'  # response-allowed
    if qos is None:
        b += b'\x00'
    else:
        b += b'\x01\x00' + bytes([qos])
    b += bytes([version]) + conformance(conf) + struct.pack('>H', pdu)
    return b


def initiate_response(qos=None, version=6, conf=0x00501f, pdu=0x01f4, vaa=7):
    b = b'\x08'
    if qos is None:
        b += b'\x00'
    else:
        b += b'\x01\x00' + bytes([qos])
    b += bytes([version]) + conformance(conf) + struct.pack('>HH', pdu, vaa)
    return b


def user_info(apdu):
    """[30] user-information: an OCTET STRING in a constructed [30]."""
    return tlv(0xbe, tlv(0x04, apdu))


# --- A-XDR helpers ---------------------------------------------------------

def alen(n):
    """A-XDR length: one octet below 0x80, else 0x80|n followed by n octets."""
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def d_null():
    return b'\x00'


def d_array(*elems, lenbytes=None):
    return b'\x01' + (lenbytes if lenbytes is not None else alen(len(elems))) + b''.join(elems)


def d_struct(*elems):
    return b'\x02' + alen(len(elems)) + b''.join(elems)


def d_bool(v):
    return b'\x03' + bytes([v])


def d_bits(nbits, data):
    return b'\x04' + alen(nbits) + data


def d_dlong(v):
    return b'\x05' + struct.pack('>i', v)


def d_dlong_u(v):
    return b'\x06' + struct.pack('>I', v)


def d_octets(data, lenbytes=None):
    return b'\x09' + (lenbytes if lenbytes is not None else alen(len(data))) + data


def d_visible(s):
    return b'\x0a' + alen(len(s)) + s


def d_utf8(s):
    return b'\x0c' + alen(len(s)) + s


def d_bcd(v):
    return b'\x0d' + bytes([v])


def d_int(v):
    return b'\x0f' + struct.pack('>b', v)


def d_long(v):
    return b'\x10' + struct.pack('>h', v)


def d_unsigned(v):
    return b'\x11' + bytes([v])


def d_long_u(v):
    return b'\x12' + struct.pack('>H', v)


def d_long64(v):
    return b'\x14' + struct.pack('>q', v)


def d_long64_u(v):
    return b'\x15' + struct.pack('>Q', v)


def d_enum(v):
    return b'\x16' + bytes([v])


def d_float32(v):
    return b'\x17' + struct.pack('>f', v)


def d_float64(v):
    return b'\x18' + struct.pack('>d', v)


def d_datetime(b12):
    return b'\x19' + b12


def d_date(b5):
    return b'\x1a' + b5


def d_time(b4):
    return b'\x1b' + b4


def d_dontcare():
    return b'\xff'


def d_compact(description, contents):
    return b'\x13' + description + alen(len(contents)) + contents


def date_time(year, month, dom, dow, hour, minute, second, hundredths, dev=0x8000, clock=0):
    return struct.pack('>HBBBBBBBhB', year, month, dom, dow, hour, minute, second,
                       hundredths, dev - 0x10000 if dev >= 0x8000 else dev, clock)


# --- xDLMS helpers ---------------------------------------------------------

def attr(class_id, obis, attr_id):
    return struct.pack('>H', class_id) + bytes(obis) + bytes([attr_id])


CLOCK = (0, 0, 1, 0, 0, 255)
ASSOC = (0, 0, 40, 0, 0, 255)
SAP = (0, 0, 41, 0, 0, 255)
LDN = (0, 0, 42, 0, 0, 255)
EVLOG = (0, 0, 99, 98, 7, 255)
ENERGY = (1, 0, 1, 8, 0, 255)
IID = 0xc1  # invoke id 1, confirmed, high priority


def wrapper(apdu, to_meter=True):
    src, dst = (0x0010, 0x0001) if to_meter else (0x0001, 0x0010)
    return struct.pack('>HHHH', 1, src, dst, len(apdu)) + apdu


def fcs16(data):
    cs = 0xffff
    for b in data:
        cs ^= b
        for _ in range(8):
            cs = (cs >> 1) ^ 0x8408 if cs & 1 else cs >> 1
    return cs ^ 0xffff


def hdlc(da, sa, control, info=b'', segmented=False, bad_fcs=False, force_hcs=False):
    """HDLC frame type 3: 7e, format (type 0xa, S bit, 11 bit length),
    destination and source address, control, HCS (if there is an
    information field), information, FCS, 7e."""
    has_info = bool(info) or force_hcs
    length = 2 + len(da) + len(sa) + 1 + (2 + len(info) if has_info else 0) + 2
    fmt = 0xa000 | (0x0800 if segmented else 0) | length
    hdr = struct.pack('>H', fmt) + da + sa + bytes([control])
    body = hdr
    if has_info:
        body += struct.pack('<H', fcs16(hdr)) + info
    fcs = fcs16(body)
    if bad_fcs:
        fcs ^= 0x5555
    return b'\x7e' + body + struct.pack('<H', fcs) + b'\x7e'


def hdlc_params(params, fmt=0x81, group=0x80):
    body = b''.join(bytes([p, len(v)]) + v for p, v in params)
    return bytes([fmt, group, len(body)]) + body


LLC_REQ = b'\xe6\xe6\x00'
LLC_RSP = b'\xe6\xe7\x00'
DA_1 = b'\x03'                   # one octet server address
DA_2 = b'\x02\x23'               # two octets (upper, lower)
DA_4 = b'\x00\x02\x00\x23'       # four octets
DA_3 = b'\x00\x02\x23'           # three octets (not a valid HDLC length)
SA = b'\x21'                     # client address 16


def build_main():
    F = []
    up = lambda p: F.append(udp(wrapper(p), True))
    down = lambda p: F.append(udp(wrapper(p), False))

    # ---- ACSE association ----
    # 1: AARQ with every field: protocol version, application context,
    # called/calling AP title (forms 1, 2, 3), AE qualifier (forms 1-4),
    # invocation identifiers, ACSE requirements, mechanism name, a
    # charstring authentication value, implementation information and an
    # InitiateRequest with a dedicated key and quality of service.
    aarq = (tlv(0x80, b'\x07\x80')
            + tlv(0xa1, APP_CTX_LN)
            + tlv(0xa2, x509_name(b'meter'))
            + tlv(0xa3, tlv(0x31, tlv(0x30, oid(2, 5, 4, 3) + tlv(0x13, b'm1'))))
            + tlv(0xa4, integer(5))
            + tlv(0xa5, integer(6))
            + tlv(0xa6, oid(1, 3, 6, 1, 4, 1, 99999, 1))
            + tlv(0xa7, integer(42))
            + tlv(0xa8, integer(7))
            + tlv(0xa9, integer(8))
            + tlv(0x8a, b'\x07\x80')
            + tlv(0x8b, MECH_LLS[2:])
            + tlv(0xac, tlv(0x80, b'12345678'))
            + tlv(0x9d, b'synthetic')
            + user_info(initiate_request(key=bytes(range(16)), qos=5)))
    up(tlv(0x60, aarq))
    # 2: AARE accepted, with responding AP title form 3, AE qualifier form 3,
    # invocation identifiers, ACSE requirements, mechanism name, a bitstring
    # authentication value and an InitiateResponse with quality of service.
    aare = (tlv(0x80, b'\x07\x80')
            + tlv(0xa1, APP_CTX_LN)
            + tlv(0xa2, integer(0))
            + tlv(0xa3, tlv(0xa1, integer(0)))
            + tlv(0xa4, tlv(0x13, b'meter-1'))
            + tlv(0xa5, tlv(0x13, b'ae-1'))
            + tlv(0xa6, integer(9))
            + tlv(0xa7, integer(10))
            + tlv(0x88, b'\x07\x80')
            + tlv(0x89, MECH_GMAC[2:])
            + tlv(0xaa, tlv(0x81, b'\x00\xa5\x5a'))
            + user_info(initiate_response(qos=3)))
    down(tlv(0x61, aare))
    # 3: AARQ with AE qualifier as an octet string, an EXTERNAL
    # authentication value (direct and indirect reference, octet-aligned
    # encoding) and the minimal InitiateRequest.
    ext = oid(1, 2, 3, 4) + integer(3) + tlv(0x81, b'\x01\x02\x03')
    aarq = (tlv(0xa1, APP_CTX_SN)
            + tlv(0xa3, tlv(0x04, b'\x01\x02\x03\x04'))
            + tlv(0xa7, tlv(0x04, b'\x05\x06'))
            + tlv(0x8b, MECH_GMAC[2:])
            + tlv(0xac, tlv(0xa2, ext))
            + user_info(initiate_request()))
    up(tlv(0x60, aarq))
    # 4: AARE rejected (permanent) by the ACSE service provider
    aare = (tlv(0xa1, APP_CTX_SN)
            + tlv(0xa2, integer(1))
            + tlv(0xa3, tlv(0xa2, integer(2)))
            + tlv(0xa4, x509_name(b'm'))
            + tlv(0xa5, tlv(0x31, tlv(0x30, oid(2, 5, 4, 3) + tlv(0x13, b'x'))))
            + user_info(initiate_response()))
    down(tlv(0x61, aare))
    # 5: AARQ with EXTERNAL in single-ASN1-type and arbitrary encodings
    # (two AARQs would need two packets: single-ASN1-type here)
    ext = oid(1, 2, 3, 5) + tlv(0xa0, tlv(0x04, b'\x01'))
    aarq = (tlv(0xa1, APP_CTX_LN)
            + tlv(0xa7, integer(1))
            + tlv(0xac, tlv(0xa2, ext)))
    up(tlv(0x60, aarq))
    # 6: AARQ with the arbitrary encoding and an "other" mechanism
    # authentication value
    ext = integer(4) + tlv(0x82, b'\x00\xff')
    aarq = (tlv(0xa1, APP_CTX_LN)
            + tlv(0xa6, tlv(0x13, b'client'))
            + tlv(0xac, tlv(0xa2, ext)))
    up(tlv(0x60, aarq))
    # 7: AARQ with an "other" authentication value
    aarq = (tlv(0xa1, APP_CTX_LN)
            + tlv(0xac, tlv(0xa3, oid(1, 2, 3, 6) + tlv(0x04, b'\xaa\xbb'))))
    up(tlv(0x60, aarq))
    # 8: AARE rejected (transient) by the ACSE service user
    aare = (tlv(0xa1, APP_CTX_LN)
            + tlv(0xa2, integer(2))
            + tlv(0xa3, tlv(0xa1, integer(13))))
    down(tlv(0x61, aare))

    # ---- Get ----
    # 9: Get-Request-Normal clock.time, no selective access
    up(b'\xc0\x01' + bytes([IID]) + attr(8, CLOCK, 2) + b'\x00')
    # 10: Get-Response-Normal with a date-time octet string
    down(b'\xc4\x01' + bytes([IID]) + b'\x00'
         + d_octets(date_time(2024, 3, 15, 5, 12, 30, 45, 50)))
    # 11: Get-Request-Normal profile_generic.buffer with selective access
    # (range descriptor)
    sel = d_struct(d_struct(d_long_u(8), d_octets(bytes(CLOCK)), d_int(2), d_long_u(0)),
                   d_octets(date_time(2024, 1, 1, 1, 0, 0, 0, 0)),
                   d_octets(date_time(0xffff, 0xfe, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff)),
                   d_array())
    up(b'\xc0\x01\xc2' + attr(7, EVLOG, 2) + b'\x01' + sel)
    # 12: Get-Response-Normal with a structure holding every planar type
    every = d_struct(
        d_null(), d_bool(1), d_bool(0), d_bits(12, b'\xab\xc0'), d_bits(16, b'\x12\x34'),
        d_dlong(-123456), d_dlong_u(3000000000),
        d_octets(b'\x01\x02\x03'),
        d_visible(b'METER-0001'), d_utf8('äöü'.encode()),
        d_bcd(0x42), d_int(-5), d_long(-1000), d_unsigned(200), d_long_u(60000),
        d_long64(-9000000000), d_long64_u(18000000000000000000),
        d_enum(30), d_float32(1.5), d_float64(-2.25),
        d_datetime(date_time(2024, 12, 31, 2, 23, 59, 59, 99)),
        d_date(b'\x07\xe8\x0c\x1f\x02'), d_time(b'\x17\x3b\x3b\x63'),
        d_dontcare(),
        d_array(d_unsigned(1), d_unsigned(2), d_unsigned(3)),
        d_array(),
        # long form lengths: 0x81 and 0x82
        d_octets(bytes(range(200)), lenbytes=b'\x81\xc8'),
        d_visible(b'x' * 3)[:1] + b'\x82\x00\x03' + b'abc',
    )
    down(b'\xc4\x01' + bytes([IID]) + b'\x00' + every)
    # 13: Get-Response-Normal with octet strings of 12 octets that are and
    # are not date-times (each check of the parser fails once) and that use
    # the "not specified" values
    dts = [
        date_time(2024, 0, 1, 1, 0, 0, 0, 0),         # month 0
        date_time(2024, 13, 1, 1, 0, 0, 0, 0),        # month 13
        date_time(2024, 0xfd, 0, 1, 0, 0, 0, 0),      # day 0
        date_time(2024, 0xfe, 32, 1, 0, 0, 0, 0),     # day 32
        date_time(2024, 1, 0xfd, 0, 0, 0, 0, 0),      # day of week 0
        date_time(2024, 1, 0xfe, 8, 0, 0, 0, 0),      # day of week 8
        date_time(2024, 1, 1, 0xff, 24, 0, 0, 0),     # hour 24
        date_time(2024, 1, 1, 7, 23, 60, 0, 0),       # minute 60
        date_time(2024, 1, 1, 7, 0xff, 0xff, 60, 0),  # second 60
        date_time(2024, 1, 1, 7, 0, 0, 0xff, 100),    # hundredths 100
        date_time(0xffff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
    ]
    down(b'\xc4\x01' + bytes([IID]) + b'\x00' + d_array(*[d_octets(d) for d in dts]))
    # 14: Get-Response-Normal with compact arrays: of long-unsigned, of a
    # structure, of an array, of a structure holding an array.  (The
    # dissector reads the type description at the start of the contents,
    # so the contents begin with the same octets.)
    c1 = d_compact(b'\x12', b'\x12\x00\x12\x34')
    c2 = d_compact(b'\x02\x02\x11\x12', b'\x02\x02\x11\x12\x00\x05')
    c3 = d_compact(b'\x01\x00\x02\x11', b'\x01\x00\x02\x11')
    c4 = d_compact(b'\x02\x02\x01\x00\x01\x11\x12', b'\x02\x02\x01\x00\x01\x11\x12\xab\xcd')
    c5 = d_compact(b'\x12', b'')
    down(b'\xc4\x01' + bytes([IID]) + b'\x00' + d_struct(c1, c2, c3, c4, c5))
    # 15: Get-Response-Normal with a data access result (failure)
    down(b'\xc4\x01' + bytes([IID]) + b'\x01\x03')
    # 16: Get-Response-Normal with a data access result of success
    down(b'\xc4\x01' + bytes([IID]) + b'\x01\x00')
    # 17: Get-Response-Normal with an unknown result choice
    down(b'\xc4\x01' + bytes([IID]) + b'\x02')
    # 18-20: Get-Response-With-Datablock, blocks 1 and 2 reassembled, the
    # third reports a data access result; then Get-Request-Next
    payload = d_array(*[d_struct(d_octets(date_time(2024, 5, 1, 3, h, 0, 0, 0)),
                                 d_dlong_u(1000 * h)) for h in range(6)])
    b1, b2 = payload[:50], payload[50:]
    down(b'\xc4\x02' + bytes([IID]) + b'\x00' + struct.pack('>I', 1) + b'\x00' + alen(len(b1)) + b1)
    up(b'\xc0\x02' + bytes([IID]) + struct.pack('>I', 1))
    down(b'\xc4\x02' + bytes([IID]) + b'\x01' + struct.pack('>I', 2) + b'\x00' + alen(len(b2)) + b2)
    down(b'\xc4\x02' + bytes([IID]) + b'\x01' + struct.pack('>I', 3) + b'\x01\x0e')
    # Get-Response-With-Datablock with an unknown result choice
    down(b'\xc4\x02' + bytes([IID]) + b'\x01' + struct.pack('>I', 4) + b'\x02')
    # Get-Request-With-List and Get-Response-With-List (not decoded)
    up(b'\xc0\x03' + bytes([IID]) + b'\x01' + attr(1, LDN, 2) + b'\x00')
    down(b'\xc4\x03' + bytes([IID]) + b'\x01\x00' + d_octets(b'LDN'))

    # ---- Set ----
    # Set-Request-Normal clock.time with a date-time
    up(b'\xc1\x01' + bytes([IID]) + attr(8, CLOCK, 2) + b'\x00'
       + d_octets(date_time(2024, 6, 1, 6, 8, 0, 0, 0)))
    # Set-Response-Normal success and failure
    down(b'\xc5\x01' + bytes([IID]) + b'\x00')
    down(b'\xc5\x01' + bytes([IID]) + b'\x03')
    # Set-Request-With-First-Datablock (with selective access) and
    # Set-Request-With-Datablock, reassembled
    payload = d_struct(d_visible(b'image-identifier'), d_dlong_u(65536), d_octets(bytes(40)))
    s1, s2 = payload[:30], payload[30:]
    up(b'\xc1\x02' + bytes([IID]) + attr(18, (0, 0, 44, 0, 0, 255), 2)
       + b'\x01' + d_unsigned(1) + b'\x00' + struct.pack('>I', 1) + alen(len(s1)) + s1)
    down(b'\xc5\x02' + bytes([IID]) + struct.pack('>I', 1))
    up(b'\xc1\x03' + bytes([IID]) + b'\x01' + struct.pack('>I', 2) + alen(len(s2)) + s2)
    down(b'\xc5\x03' + bytes([IID]) + b'\x00' + struct.pack('>I', 2))
    # Set-Request-With-List and Set-Response-With-List (not decoded)
    up(b'\xc1\x04' + bytes([IID]) + b'\x00')
    down(b'\xc5\x05' + bytes([IID]) + b'\x00')

    # ---- Action ----
    # Action-Request-Normal register.reset with and without parameters
    up(b'\xc3\x01' + bytes([IID]) + attr(3, ENERGY, 1) + b'\x01' + d_int(0))
    down(b'\xc7\x01' + bytes([IID]) + b'\x00\x00')
    up(b'\xc3\x01' + bytes([IID]) + attr(8, CLOCK, 6) + b'\x00')
    down(b'\xc7\x01' + bytes([IID]) + b'\x03\x00')
    # unknown method (beyond the names of the class) and unknown result value
    up(b'\xc3\x01' + bytes([IID]) + attr(8, CLOCK, 11) + b'\x00')
    up(b'\xc3\x01' + bytes([IID]) + attr(8, CLOCK, 12) + b'\x00')
    down(b'\xc7\x01' + bytes([IID]) + b'\xfa\x00')
    # Action-Request-Next-Pblock, Action-Response-With-Pblock (not decoded)
    up(b'\xc3\x02' + bytes([IID]) + struct.pack('>I', 1))
    down(b'\xc7\x02' + bytes([IID]) + b'\x00')

    # ---- Event notification, exception ----
    up(b'\xc2\x00' + attr(1, LDN, 2) + d_octets(b'name'))
    down(b'\xd8\x01\x02')

    # ---- Access ----
    # Access-Request with every request choice (and no date-time: the
    # dissector does not skip the octets of a date-time)
    spec = (alen(5)
            + b'\x01' + attr(1, SAP, 2)
            + b'\x02' + attr(15, ASSOC, 7)
            + b'\x03' + attr(9, (0, 0, 10, 0, 0, 255), 1)
            + b'\x04' + attr(7, EVLOG, 2) + b'\x01' + d_unsigned(2)
            + b'\x05' + attr(7, EVLOG, 4) + b'\x00')
    lod = alen(3) + d_null() + d_long_u(900) + d_null()
    up(b'\xd9' + struct.pack('>I', 0x40000001)
       + b'\x00' + spec + lod)
    # Access-Response with no date-time, a list of data and results
    spec = alen(2) + b'\x01' + attr(1, SAP, 2) + b'\x03' + attr(9, (0, 0, 10, 0, 0, 255), 1)
    lod = alen(2) + d_array(d_struct(d_long_u(1), d_octets(b'LDN-1'))) + d_null()
    down(b'\xda' + struct.pack('>I', 0x40000001) + b'\x00' + spec + lod
         + alen(2) + b'\x01\x00' + b'\x03\x04')

    # ---- Attribute and class names ----
    # every class the dissector knows, attribute 1 (logical_name), an
    # attribute without a name and an unknown class (warning expert info),
    # one per packet so each Info column shows it; an unknown OBIS code
    for cls, at in ((1, 1), (3, 3), (4, 5), (5, 9), (9, 2), (10, 2), (11, 2),
                    (17, 2), (20, 10), (21, 4), (22, 3), (23, 9), (30, 2),
                    (70, 4), (71, 11), (104, 2), (111, 19), (112, 11),
                    (113, 13), (115, 6), (9000, 2), (3, 20), (4242, 2)):
        up(b'\xc0\x01' + bytes([IID]) + attr(cls, ENERGY if cls < 9000 else (0, 0, 0, 0, 0, 0), at) + b'\x00')

    # ---- APDUs the dissector names but does not decode ----
    for tag in (0x05, 0x06, 0x0c, 0x0d, 0x0e, 0x16, 0x18, 0x0f, 0x77):
        up(bytes([tag]) + b'\x00')

    # ---- RLRQ / RLRE ----
    up(tlv(0x62, tlv(0x80, b'\x00') + user_info(initiate_request(conf=0x001e1d))))
    down(tlv(0x63, tlv(0x80, b'\x00') + user_info(initiate_response())))
    up(tlv(0x62, tlv(0xbe, b'')))
    down(tlv(0x63, tlv(0x80, b'\x01')))

    # ---- Other framings ----
    # bare APDU (no wrapper)
    F.append(udp(b'\xc0\x01' + bytes([IID]) + attr(8, CLOCK, 2) + b'\x00', True))
    # IEC 61334-4-32 LLC
    F.append(udp(b'\x90\x72\x00' + b'\xc0\x01' + bytes([IID]) + attr(1, LDN, 2) + b'\x00', True))
    # over TCP
    t = Tcp()
    F.append(t.seg(b'', True, 0x02))
    F.append(t.seg(b'', False, 0x12))
    F.append(t.seg(b'', True, 0x10))
    F.append(t.seg(wrapper(b'\xc0\x01' + bytes([IID]) + attr(8, CLOCK, 3) + b'\x00'), True))
    F.append(t.seg(wrapper(b'\xc4\x01' + bytes([IID]) + b'\x00' + d_long(60), False), False))

    # ---- HDLC ----
    def h(frame, to_meter=True):
        F.append(udp(frame, to_meter))
    # SNRM with the four parameters and an unknown one, UA with parameters
    h(hdlc(DA_1, SA, 0x93, hdlc_params([(5, b'\x80'), (6, b'\x00\x80'), (7, b'\x01'),
                                       (8, b'\x00\x00\x00\x01'), (9, b'\x07')])))
    h(hdlc(SA, DA_1, 0x73, hdlc_params([(5, b'\x80'), (6, b'\x80')])), False)
    # SNRM without an information field, UA with a non-0x81 format and
    # with a non-0x80 group identifier
    h(hdlc(DA_2, SA, 0x93))
    h(hdlc(SA, DA_2, 0x73), False)
    h(hdlc(SA, DA_2, 0x73, b'\x82\x00'), False)
    h(hdlc(DA_4, SA, 0x93, b'\x81\x81'))
    # I frame carrying an AARQ (minimal), RR, I frame with an AARE
    aarq = tlv(0x60, tlv(0xa1, APP_CTX_LN) + user_info(initiate_request()))
    h(hdlc(DA_4, SA, 0x10, LLC_REQ + aarq))
    h(hdlc(SA, DA_4, 0x31), False)
    aare = tlv(0x61, tlv(0xa1, APP_CTX_LN) + tlv(0xa2, integer(0))
               + tlv(0xa3, tlv(0xa1, integer(0))) + user_info(initiate_response()))
    h(hdlc(SA, DA_4, 0x30, LLC_RSP + aare), False)
    # Segmented I frames: a Get-Response-Normal in two HDLC segments,
    # reassembled in the second
    apdu = LLC_RSP + b'\xc4\x01' + bytes([IID]) + b'\x00' + d_octets(bytes(range(60)))
    h(hdlc(SA, DA_2, 0x52, apdu[:40], segmented=True), False)
    h(hdlc(DA_2, SA, 0x71))
    h(hdlc(SA, DA_2, 0x54, apdu[40:]), False)
    # RNR, DISC, FRMR, UI, an unknown control field, a 3 octet address
    # and a bad FCS
    h(hdlc(DA_1, SA, 0x95))
    h(hdlc(DA_1, SA, 0x53))
    h(hdlc(SA, DA_1, 0x97), False)
    h(hdlc(DA_1, SA, 0x13, b'\x01\x02'))
    h(hdlc(DA_1, SA, 0x0b))
    h(hdlc(DA_3, SA, 0x53))
    h(hdlc(DA_1, SA, 0x53, bad_fcs=True))

    # ---- Reproducer of the fix on the branch (decodes cleanly with it) ----
    # Compact array whose type description is array[65535] of
    # array[65535] of array[65535] of null: the null elements use no
    # content, so it used to take 65535^3 iterations.
    desc = b'\x01\xff\xff' * 3 + b'\x00'
    down(b'\xc4\x01\x81\x00' + b'\x13' + desc + bytes([len(desc)]) + desc)

    # Invalid planar type (warning expert info), ends the packet
    down(b'\xc4\x01' + bytes([IID]) + b'\x00' + d_struct(d_unsigned(1), b'\x07\x00'))
    # Access-Request with an invalid request choice (warning)
    up(b'\xd9' + struct.pack('>I', 2) + b'\x00' + alen(1) + b'\x09' + alen(0))
    return F


def build_malformed():
    F = []
    up = lambda p: F.append(udp(wrapper(p), True))
    down = lambda p: F.append(udp(wrapper(p), False))
    # Length wrap reproducers: octet string of 0xfffffff0 octets; an array
    # of 2^32-1 octet strings whose length would move back to the element
    down(b'\xc4\x01\x81\x00' + b'\x09\x84\xff\xff\xff\xf0' + b'\x00' * 16)
    down(b'\xc4\x01\x81\x00' + b'\x01\x84\xff\xff\xff\xff' + b'\x09\x84\xff\xff\xff\xfa')
    # Bit string, visible string, UTF8 string and compact array past the end
    down(b'\xc4\x01\x81\x00' + b'\x04\x84\xff\xff\xff\xff')
    down(b'\xc4\x01\x81\x00' + b'\x0a\x20abc')
    down(b'\xc4\x01\x81\x00' + b'\x0c\x84\x80\x00\x00\x00')
    down(b'\xc4\x01\x81\x00' + b'\x13\x12\x10\x00\x01')
    # Compact array of nulls only (warning) and an array description in
    # the contents that ends early
    down(b'\xc4\x01\x81\x00' + b'\x13\x00\x01\x00')
    # Truncated attribute descriptor and datablock
    up(b'\xc0\x01\xc1\x00\x08\x00')
    down(b'\xc4\x02\xc1\x00\x00\x00\x00\x01\x00\x20\x01')
    # InitiateRequest cut short, AARQ with a bad length
    up(b'\x01\x01\x10\x00\x01')
    up(b'\x60\x10\xa1\x09\x06\x07')
    # HDLC frame whose length exceeds the packet, I frame cut short
    F.append(udp(b'\x7e\xa0\x40\x03\x21\x10', True))
    F.append(udp(b'\x7e\xa0\x10\x03\x21\x10\x00\x00\xe6', True))
    # HDLC SNRM with parameters past the end
    F.append(udp(b'\x7e\xa0\x0e\x03\x21\x93\x00\x00\x81\x80\x14\x05\x10', True))
    # Data nested past the dissection depth limit
    down(b'\xc4\x01\x81\x00' + b'\x01\x01' * 200 + b'\x00')
    # HDLC DM: the dissector gives the control item the length of the
    # control offset, beyond the frame
    F.append(udp(hdlc(SA, DA_1, 0x1f), False))
    # the same with octets after the closing flag, so that it does not throw
    F.append(udp(hdlc(SA, DA_1, 0x1f) + bytes(8), False))
    # EXTERNAL with a data value descriptor (BER error)
    F.append(udp(wrapper(tlv(0x60, tlv(0xa1, APP_CTX_LN) + tlv(0xac, tlv(0xa2,
        oid(1, 2, 3, 4) + tlv(0x07, b'desc') + tlv(0x81, b'\x01'))))), True))
    # Access-Request and Access-Response with a date-time: its octets are
    # not skipped, so the specification is read from them
    up(b'\xd9' + struct.pack('>I', 0x40000001) + b'\x0c'
       + date_time(2024, 7, 4, 4, 10, 0, 0, 0) + b'\x01\x01' + attr(1, SAP, 2) + b'\x00')
    down(b'\xda' + struct.pack('>I', 0x40000001) + b'\x0c'
         + date_time(2024, 7, 4, 4, 10, 0, 0, 0) + b'\x00\x00\x00')
    # Exception-Response and Access-Response cut short
    down(b'\xd8\x01')
    down(b'\xda\x00\x00\x00\x01\x00\x00\x00\x01')
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'cosem-coverage.pcap'), build_main())
    pcap(os.path.join(out, 'cosem-coverage-malformed.pcap'), build_malformed())


if __name__ == '__main__':
    main()
