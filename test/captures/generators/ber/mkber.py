#!/usr/bin/env python3
# Generates test/captures/ber_coverage.ber.gz, ber_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the generic BER helpers
(epan/dissectors/packet-ber.c).

All packets are built from scratch with struct; no captured traffic is
used. The pcap uses the Exported PDU link type (252) so that each frame
can name the dissector it is for:

  "ber"             the unknown BER decoder (try_dissect_unknown_ber)
  "ber_file"        the BER file dissector without file data
  "pkix-cert"       X.509 certificates (x509af/x509if/x509sat/x509ce)
  "x509af"          a CRL (CertificateList)
  "glow"            Ember+ Glow (REAL, RELATIVE-OID, SET, SEQUENCE OF)
  "inap"            INAP (EMBEDDED PDV)
  "eth_withoutfcs"  Ethernet frames: LDAP on TCP 389, SNMP on UDP 161,
                    GOOSE, Kerberos on UDP 88

Usage: mkber.py <output directory>

Writes:
  ber-coverage.pcap            the main capture: no malformed packets, no
                               error expert infos; the only warnings are
                               the REAL overflow reproducer and size
                               constraint checks (frames 36-40)
  ber-coverage-malformed.pcap  "BER Error" warnings (PI_MALFORMED, so they
                               match _ws.malformed), exceptions and the
                               known two-pass reassembly issues
  ber-coverage.ber             a raw BER file (wiretap "ber" file type),
                               indefinite length so it also opens gzipped
  ber-coverage.cer             the first certificate as a raw .cer file
                               (the file name suffix selects the syntax)
"""

import os
import struct
import sys

# ---------------------------------------------------------------- BER


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def ident(cls, pc, tag):
    """cls: 0 UNI, 1 APP, 2 CON, 3 PRI; pc: True for constructed."""
    first = (cls << 6) | (0x20 if pc else 0)
    if tag < 31:
        return bytes([first | tag])
    t = [tag & 0x7f]
    tag >>= 7
    while tag:
        t.insert(0, 0x80 | (tag & 0x7f))
        tag >>= 7
    return bytes([first | 0x1f]) + bytes(t)


def tlv(tag, body):
    """tag is the identifier: an int (one octet) or bytes."""
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + enc_len(len(body)) + body


def tlv_long(tag, body, nlen):
    """Definite length in the long form with nlen length octets."""
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + bytes([0x80 | nlen]) + len(body).to_bytes(nlen, 'big') + body


def indef(tag, body):
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + b'\x80' + body + b'\x00\x00'


def seq(*items):
    return tlv(0x30, b''.join(items))


def set_(*items):
    return tlv(0x31, b''.join(items))


def integer(v, tag=0x02):
    if v == 0:
        b = b'\x00'
    else:
        n = (v.bit_length() + 8) // 8
        b = v.to_bytes(n, 'big', signed=True)
    return tlv(tag, b)


def oid_body(s):
    parts = [int(x) for x in s.split('.')]
    out = bytearray()
    first = [parts[0] * 40 + parts[1]] + parts[2:]
    for p in first:
        chunk = [p & 0x7f]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7f))
            p >>= 7
        out += bytes(chunk)
    return bytes(out)


def rel_oid_body(s):
    out = bytearray()
    for p in [int(x) for x in s.split('.')]:
        chunk = [p & 0x7f]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7f))
            p >>= 7
        out += bytes(chunk)
    return bytes(out)


def oid(s):
    return tlv(0x06, oid_body(s))


def ctx(n, body, constructed=True):
    return tlv(ident(2, constructed, n), body)


def app(n, body, constructed=True):
    return tlv(ident(1, constructed, n), body)


# ---------------------------------------------------------------- framing

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src, dst, ident_=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident_, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload


def eth(ip, src_mac=b'\x02\x00\x00\x00\x00\x01', dst_mac=b'\x02\x00\x00\x00\x00\x02'):
    return dst_mac + src_mac + b'\x08\x00' + ip


CLIENT = (192, 0, 2, 10)
SERVER = (198, 51, 100, 20)


def udp(src, dst, sport, dport, payload):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(struct.pack('!4s4sBBH', bytes(src), bytes(dst), 0, 17, len(u)) + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return eth(ipv4(17, u, src, dst))


class TcpConv:
    """A TCP connection with sequence numbers tracked per direction."""

    def __init__(self, cport, sport, client=None):
        self.cport, self.sport = cport, sport
        self.client = client or CLIENT
        self.seq = {True: 1000, False: 5000}

    def seg(self, to_server, payload, flags=0x18):
        if to_server:
            src, dst, sp, dp = self.client, SERVER, self.cport, self.sport
        else:
            src, dst, sp, dp = SERVER, self.client, self.sport, self.cport
        s = self.seq[to_server]
        a = self.seq[not to_server]
        t = struct.pack('!HHIIBBHHH', sp, dp, s, a, 5 << 4, flags, 65535, 0, 0) + payload
        c = csum(struct.pack('!4s4sBBH', bytes(src), bytes(dst), 0, 6, len(t)) + t)
        t = t[:16] + struct.pack('!H', c) + t[18:]
        self.seq[to_server] = s + len(payload) + (1 if flags & 0x03 else 0)
        return eth(ipv4(6, t, src, dst))

    def handshake(self):
        f = [self.seg(True, b'', 0x02)]
        f.append(self.seg(False, b'', 0x12))
        f.append(self.seg(True, b'', 0x10))
        return f


def exported_pdu(dissector_name, payload):
    """WIRESHARK_UPPER_PDU record naming a dissector (tag 12)."""
    name = dissector_name.encode()
    pad = (-len(name)) % 4
    tag = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    return tag + struct.pack('!HH', 0, 0) + payload


def write_pcap(fn, frames, linktype=252):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1748736000 + i, 0, len(fr), len(fr)))
            f.write(fr)


# ---------------------------------------------------------------- unknown BER

def all_universal_primitives():
    """A SEQUENCE with a valid value of every universal type that
    try_dissect_unknown_ber() decodes itself."""
    return seq(
        tlv(0x01, b'\xff'),                              # BOOLEAN TRUE
        tlv(0x01, b'\x00'),                              # BOOLEAN FALSE
        integer(5), integer(-129), integer(0),
        integer(0x7fffffffffffffff),                     # 8 octets
        tlv(0x02, b'\x00' + b'\xff' * 8),                # 9 octets, leading 0
        tlv(0x02, bytes(range(1, 13))),                  # 12 octets: as bytes
        tlv(0x03, b'\x03\xa8'),                          # BIT STRING, 3 unused bits
        tlv(0x03, b'\x00'),                              # empty BIT STRING
        tlv(0x03, b'\x00\x5a\xa5'),                      # BIT STRING, no padding
        tlv(0x04, b'\xde\xad\xbe\xef'),                  # OCTET STRING
        tlv(0x04, b''),                                  # empty OCTET STRING
        tlv(0x05, b''),                                  # NULL
        oid('1.3.6.1.4.1.37411.2.1.1'),                  # OBJECT IDENTIFIER
        oid('2.5.4.3'),                                  # known OID
        tlv(0x0d, rel_oid_body('1.2.300.70000')),        # RELATIVE-OID
        tlv(0x09, b''),                                  # REAL 0
        tlv(0x09, b'\x80\xfb\x05'),                      # REAL 5 * 2^-5
        tlv(0x09, b'\xc1\x00\x10\x03'),                  # REAL -3 * 2^16 (2 octet exponent)
        tlv(0x09, b'\x92\x00\x00\x02\x07'),              # REAL base 8, F=0, 3 octet exponent
        tlv(0x09, b'\xa4\x01\x01'),                      # REAL base 16, F=1
        tlv(0x09, b'\x83\x02\x00\x10\x01\x02'),  # REAL long-form exponent
        tlv(0x09, b'\x01' + b'  -42'),                   # REAL decimal NR1
        tlv(0x09, b'\x02' + b'12.5'),                    # REAL decimal NR2
        tlv(0x09, b'\x03' + b'125E-1'),                  # REAL decimal NR3
        tlv(0x09, b'\x40'),                              # REAL PLUS-INFINITY
        tlv(0x09, b'\x41'),                              # REAL MINUS-INFINITY
        tlv(0x09, b'\x42'),                              # REAL NOT-A-NUMBER
        tlv(0x09, b'\x43'),                              # REAL minus zero
        tlv(0x0a, b'\x03'),                              # ENUMERATED
        tlv(0x0c, 'grüße €'.encode()),    # UTF8String
        tlv(0x12, b'0123 456'),                          # NumericString
        tlv(0x13, b'Printable String'),                  # PrintableString
        tlv(0x14, b'Teletex \xc2e'),                     # TeletexString (T.61)
        tlv(0x16, b'user@example.com'),                  # IA5String
        tlv(0x17, b'251231235959Z'),                     # UTCTime
        tlv(0x18, b'20251231235959.25Z'),                # GeneralizedTime
        tlv(0x19, b'Graphic'),                           # GraphicString
        tlv(0x1a, b'Visible'),                           # VisibleString
        tlv(0x1b, b'General'),                           # GeneralString
        tlv(0x1c, 'Univ'.encode('utf-32-be')),           # UniversalString
        tlv(0x1e, 'BMP é'.encode('utf-16-be')),     # BMPString
    )


def unknown_ber_frames():
    f = []
    # 1: every universal primitive type
    f.append(all_universal_primitives())
    # 2: constructed types, non-universal classes, long tags and lengths
    f.append(seq(
        set_(integer(1), tlv(0x13, b'in a SET')),
        tlv(0x24, tlv(0x04, b'ab') + tlv(0x04, b'cd')),   # constructed OCTET STRING
        tlv(0x23, tlv(0x03, b'\x00\x01') + tlv(0x03, b'\x04\xf0')),  # constructed BIT STRING
        ctx(0, integer(7)),                               # [0] constructed
        app(2, integer(8)),                               # [APPLICATION 2] constructed
        tlv(ident(3, True, 3), integer(9)),               # [PRIVATE 3] constructed
        tlv(ident(1, False, 5), b'hello'),                # [APPLICATION 5] printable
        tlv(ident(2, False, 3), b'\x00\x01\xfe'),         # [3] not printable
        tlv(ident(3, False, 7), b''),                     # [PRIVATE 7] empty
        tlv(ident(1, False, 1000), b'long tag'),          # [APPLICATION 1000]
        tlv(ident(2, True, 200), integer(10)),            # [200] constructed
        tlv_long(0x04, b'L' * 3, 1),                      # long-form length 0x81
        tlv_long(0x04, b'M' * 300, 2),                    # long-form length 0x82
        tlv_long(0x04, b'N' * 2, 3),                      # 3 length octets
    ))
    # 3: indefinite lengths
    f.append(indef(0x30, integer(1) + indef(0x31, tlv(0x0c, b'x') + tlv(0x05, b''))
                   + indef(ident(2, True, 1), oid('1.2.3')) + indef(0x24, tlv(0x04, b'seg'))))
    # 4: repro ber_unknown_misc.py frame 1: NULL with three content
    #    octets "02 01 07"; they are skipped, not decoded as INTEGER 7
    f.append(seq(tlv(0x05, bytes.fromhex('020107'))))
    # 5: OCTET STRING and [CONTEXT 1] primitive holding BER (for the
    #    ber.decode_octetstring / ber.decode_primitive preferences), and
    #    some that do not look like BER
    f.append(seq(
        tlv(0x04, seq(integer(42), tlv(0x0c, b'inner'))),
        tlv(0x04, tlv(0x04, b'\x01\x02')),                # primitive inside: not decoded
        tlv(0x04, b'\x30\x05\x02\x01'),                   # wrong inner length
        tlv(ident(2, False, 1), seq(integer(43))),
        tlv(ident(2, False, 2), b'\x30\x09\x02'),
        tlv(ident(2, False, 4), b'\x7f'),
    ))
    # 6: a top-level primitive value
    f.append(integer(123456))
    return f


def real_overflow_frame():
    """repro ber_unknown_misc.py frame 2: a REAL with a 264 octet
    mantissa is an overflow ("REAL overflow" warning); epan/asn1.c kept
    the mantissa length in a uint8_t and showed a small finite value."""
    return tlv(0x09, b'\x80\x00' + b'\x01' * 264)


def unknown_ber_warning_frames():
    """Unknown BER values that give "BER Error" warnings (no exceptions)."""
    f = []
    # universal tags the unknown decoder does not handle
    f.append(seq(
        tlv(0x07, b'descriptor'),            # ObjectDescriptor
        tlv(0x08, b'\x00'),                  # EXTERNAL, primitive
        tlv(0x0e, b'\x01'),                  # reserved 14
        tlv(0x15, b'videotex'),              # VideotexString
        tlv(0x1d, b'char'),                  # CHARACTER STRING
    ))
    # lengths not valid for the type
    f.append(seq(
        tlv(0x02, b''),                      # INTEGER, length 0
        tlv(0x01, b'\x01\x02'),              # BOOLEAN, length 2
        tlv(0x03, b''),                      # BIT STRING, length 0
        tlv(0x03, b'\x08\x00'),              # BIT STRING, padding 8
        tlv(0x03, b'\x03\xff'),              # bits set in the padding
        tlv(0x09, b'\x44'),                  # REAL, reserved special value
        tlv(0x09, b'\x04' + b'1'),           # REAL, reserved decimal form
    ))
    # repro ber_unknown_misc.py frame 3: long-form tag that overflows
    f.append(bytes.fromhex('1f8fffffff7f0100'))
    # SEQUENCE whose length runs past the end
    f.append(b'\x30\x40' + integer(1))
    # long-form universal tag 128; a length clamped to INT32_MAX
    f.append(seq(b'\x1f\x81\x00\x00', b'\x04\x84\xff\xff\xff\xff'))
    return f


# ---------------------------------------------------------------- X.509

SHA256RSA = '1.2.840.113549.1.1.11'
RSA = '1.2.840.113549.1.1.1'
PRIVATE_OID = '1.3.6.1.4.1.32473.7'     # documentation enterprise number


def alg(o, params=tlv(0x05, b'')):
    return seq(oid(o), params)


def atv(o, value):
    return seq(oid(o), value)


def rdn(*atvs):
    return set_(*atvs)


def name(*rdns):
    return seq(*rdns)


def ext(o, value, critical=None):
    items = [oid(o)]
    if critical is not None:
        items.append(tlv(0x01, b'\xff' if critical else b'\x00'))
    items.append(tlv(0x04, value))
    return seq(*items)


def spki():
    rsakey = seq(integer(0x00c0ffee12345678 << 64 | 0x1122334455667789), integer(65537))
    return seq(alg(RSA), tlv(0x03, b'\x00' + rsakey))


def tbs(serial, issuer, validity, subject, extensions=None, version=2, extra=b'', key=None):
    items = []
    if version is not None:
        items.append(ctx(0, integer(version)))
    items += [integer(serial), alg(SHA256RSA), issuer, validity, subject, key or spki()]
    items.append(extra)
    if extensions is not None:
        items.append(ctx(3, seq(*extensions)))
    return seq(*items)


def certificate(tbs_):
    return seq(tbs_, alg(SHA256RSA), tlv(0x03, b'\x00' + bytes(range(32))))


def guide():
    """searchGuide: SET { objectClass [0], criteria [1] Criteria }"""
    item = lambda n, o: ctx(0, ctx(n, oid(o)))            # type [0] CriteriaItem
    crit = ctx(2, set_(item(0, '2.5.4.3'), item(4, '2.5.4.10'),
                       ctx(3, item(1, '2.5.4.4'))))         # or { .., .., not .. }
    return set_(ctx(0, oid('2.5.6.6')), ctx(1, crit))


def external_referrals():
    """id-ce-statusReferrals: SEQUENCE OF StatusReferral, each an
    otherReferral [1] INSTANCE OF (BER EXTERNAL, implicitly tagged)."""
    r = []
    # direct-reference to a registered OID, indirect-reference,
    # data-value-descriptor and single-ASN1-type [0] (DirectoryString)
    r.append(ctx(1, oid('2.5.4.3') + integer(3) + ctx(0, tlv(0x0c, b'Referral CN'))))
    # searchGuide: a SET (dissect_ber_set) through single-ASN1-type
    r.append(ctx(1, oid('2.5.4.14') + ctx(0, guide())))
    # octet-aligned [1] with a registered direct-reference
    r.append(ctx(1, oid('2.5.4.10') + ctx(1, tlv(0x13, b'Org'), constructed=False)))
    # octet-aligned [1] with an unregistered direct-reference
    r.append(ctx(1, oid(PRIVATE_OID) + ctx(1, b'\x01\x02\x03', constructed=False)))
    # arbitrary [2] BIT STRING
    r.append(ctx(1, oid(PRIVATE_OID) + ctx(2, b'\x04\xa0', constructed=False)))
    # single-ASN1-type [0] with NULL for an unregistered OID
    r.append(ctx(1, oid(PRIVATE_OID) + ctx(0, tlv(0x05, b''))))
    return seq(*r)


def cert1():
    """UTCTime validity with Z and with a +hhmm offset (the reproducer
    ber_utctime_offset.py; X.509 used to drop the offset time as
    malformed), and the extensions that need the BER helpers."""
    issuer = name(rdn(atv('2.5.4.6', tlv(0x13, b'XX'))),
                  rdn(atv('2.5.4.10', tlv(0x0c, b'Example BER Org'))),
                  rdn(atv('2.5.4.3', tlv(0x13, b'BER Test CA'))))
    subject = name(rdn(atv('2.5.4.3', tlv(0x1e, 'BER Subject'.encode('utf-16-be')))),
                   rdn(atv('2.5.4.3', tlv(0x14, b'Teletex CN')),
                       atv('2.5.4.10', tlv(0x1c, 'Univ'.encode('utf-32-be')))))
    validity = seq(tlv(0x17, b'2501010000Z'), tlv(0x17, b'260101000000+0100'))
    exts = [
        ext('2.5.29.15', tlv(0x03, b'\x05\xa0'), critical=True),     # keyUsage
        ext('2.5.29.19', seq(tlv(0x01, b'\xff'), integer(3))),       # basicConstraints
        ext('2.5.29.45', external_referrals()),                      # statusReferrals
        ext(PRIVATE_OID, tlv(0x05, b''), critical=False),            # unknown, NULL
        ext('1.2.840.113549.1.9.5', tlv(0x17, b'250601120000Z')),     # signingTime (UTCTime field)
        ext('1.3.6.1.5.5.7.48.1.5', tlv(0x05, b'')),                 # ocsp-nocheck NULL
        ext('2.5.29.16', seq(ctx(0, b'20250101000000Z', False),      # privateKeyUsagePeriod:
                             ctx(1, b'20251231235959Z', False))),    # IMPLICIT GeneralizedTime
    ]
    return certificate(tbs(0x7c0ffee0123456789abcdef0123456789abcdef1, issuer, validity, subject, exts,
                           extra=ctx(1, b'\x00\x5a', constructed=False)
                           + ctx(2, b'\x04\xf0', constructed=False)))


def cert2():
    """GeneralizedTime validity, version 1 without extensions; key usage
    with nine named bits in a second certificate below."""
    issuer = name(rdn(atv('2.5.4.3', tlv(0x0c, b'Gen CA'))))
    subject = name(rdn(atv('2.5.4.3', tlv(0x0c, b'Gen Subject'))))
    validity = seq(tlv(0x18, b'20250101000000Z'), tlv(0x18, b'20501231235959.5+0100'))
    return certificate(tbs(2, issuer, validity, subject, None, version=None))


def cert3():
    """Indefinite lengths throughout (BER, not DER), UTCTime with seconds
    and a -hhmm offset, and a key usage of nine named bits."""
    def iseq(*items):
        return indef(0x30, b''.join(items))
    issuer = iseq(indef(0x31, iseq(oid('2.5.4.3'), tlv(0x0c, b'Indef CA'))))
    subject = iseq(indef(0x31, iseq(oid('2.5.4.3'), tlv(0x0c, b'Indef Subject'))))
    validity = iseq(tlv(0x17, b'250101000000-0130'), tlv(0x17, b'3001010000+0000'))
    exts = indef(ident(2, True, 3), iseq(
        iseq(oid('2.5.29.15'), tlv(0x01, b'\xff'), tlv(0x04, tlv(0x03, b'\x07\x80\x80'))),
        iseq(oid('2.5.29.19'), tlv(0x04, seq())),
        iseq(oid('2.5.29.19'), tlv(0x04, b'\x30\x02\x00\x00')),
    ))
    tbs_ = iseq(indef(ident(2, True, 0), integer(2)), integer(3), iseq(oid(SHA256RSA), tlv(0x05, b'')),
                issuer, validity, subject, spki(), exts)
    return iseq(tbs_, iseq(oid(SHA256RSA)), tlv(0x03, b'\x00' + bytes(16)))


def crl():
    """CertificateList ("x509af"): thisUpdate / nextUpdate and three
    revocation dates with every UTCTime form."""
    issuer = name(rdn(atv('2.5.4.3', tlv(0x0c, b'CRL CA'))))
    revoked = seq(
        seq(integer(10), tlv(0x17, b'2502030405Z')),
        seq(integer(11), tlv(0x17, b'250203040506Z')),
        seq(integer(12), tlv(0x17, b'2502030405-0800')),
        seq(integer(13), tlv(0x18, b'20250203040506Z')),
    )
    t = seq(integer(1), alg(SHA256RSA), issuer, tlv(0x17, b'250201000000Z'),
            tlv(0x17, b'250301000000+0530'), revoked)
    return seq(t, alg(SHA256RSA), tlv(0x03, b'\x00' + bytes(8)))



def warning_cert():
    """A certificate whose extensions (each dissected through
    call_ber_oid_callback() by its OID) hit the "BER Error" checks of the
    helpers: wrong tags, constraint violations, malformed times."""
    def x(o, value):
        return ext(o, value)
    signing = '1.2.840.113549.1.9.5'           # cms SigningTime: Time (UTCTime)
    dob = '1.3.6.1.5.5.7.9.1'                  # pkixqualified dateOfBirth: GeneralizedTime
    exts = [
        x(PRIVATE_OID, integer(7)),                              # OID not implemented
        x('1.3.6.1.4.1.32473.8', integer(7) + b'\xff'),          # not implemented, not BER either
        x('2.5.29.32', b'\x30\x04' + seq(oid('1.3'))),           # SEQUENCE OF too many bytes
        x('2.5.29.15', tlv(0x04, b'\x80')),                      # BitString expected
        x('2.5.29.15', tlv(0x03, b'\x00\x80\x40')),              # unknown named bit
        x('2.5.29.19', set_()),                                  # Sequence expected
        x('2.5.29.19', seq(tlv(0x01, b'\xff'), integer(1), integer(2))),   # beyond the end
        x('2.5.29.19', b'\x30\x04' + tlv(0x01, b'\xff') + integer(3)),     # too many bytes
        x('2.5.29.32', set_()),                                  # SEQUENCE OF expected
        x('2.5.29.32', seq(integer(1))),                         # wrong field in SEQUENCE OF
        x('2.5.29.32', seq(seq(integer(1)))),                    # wrong field in SEQUENCE
        x('2.5.29.32', b'\x30\x03\x00\x01\x00'),                 # tag 0 item in SEQUENCE OF
        x('2.5.4.14', seq()),                                    # SET expected
        x('2.5.4.14', set_(ctx(0, oid('2.5.6.6')), ctx(5, integer(1)))),  # unknown member, missing criteria
        x('2.5.29.14', integer(5)),                              # OctetString expected
        x('2.5.4.6', tlv(0x0c, b'XX')),                          # String (PrintableString) expected
        x('1.2.840.113549.1.9.3', integer(1)),                   # Object Identifier expected
        x('1.3.6.1.5.5.7.48.1.5', integer(0)),                   # NULL expected
        x('1.3.6.1.5.5.7.48.1.5', tlv(0x05, b'\x00')),           # NULL with contents
        x(dob, tlv(0x17, b'2501010000Z')),                       # GeneralizedTime expected
        x(dob, tlv(0x18, b'2025010100Z')),                       # invalid length
        x(dob, tlv(0x18, b'2025-01-01T00:00')),                  # invalid format
        x(signing, tlv(0x17, b'250101000')),                     # UTCTime length 9
        x(signing, tlv(0x17, b'25010100a0Z')),                   # non-digit
        x(signing, tlv(0x17, b'25010100001Z')),                  # one-digit seconds
        x(signing, tlv(0x17, b'2501010000Z0')),                  # octets after Z
        x(signing, tlv(0x17, b'2501010000+01')),                 # short offset
        x(signing, tlv(0x17, b'2501010000+01a0')),               # offset not digits
        x(signing, tlv(0x17, b'2501010000X')),                   # neither Z nor +/-
        x('2.5.29.45', seq(                                      # statusReferrals
            ctx(1, oid('2.5.4.3') + tlv(0x07, b'descriptor') + ctx(0, tlv(0x0c, b'x'))),  # ObjectDescriptor
            ctx(1, ctx(0, tlv(0x0c, b'no direct-reference'))),   # no OID
            ctx(1, oid(PRIVATE_OID) + ctx(0, integer(5))),       # OID not implemented
            ctx(1, oid(PRIVATE_OID) + ctx(3, integer(5))),       # no encoding alternative matches
        )),
    ]
    # an empty RelativeDistinguishedName (SET SIZE (1..MAX)): too few items
    issuer = name(rdn(atv('2.5.4.3', tlv(0x0c, b'Warn CA'))), set_())
    subject = name(rdn(atv('2.5.4.3', tlv(0x0c, b'Warn Subject'))),
                   rdn(atv(PRIVATE_OID, tlv(0x05, b''))),        # not a string
                   rdn(atv('2.5.4.14', guide())))
    validity = seq(tlv(0x17, b'25010100'), tlv(0x17, b'3001010000Z'))   # notBefore too short
    return certificate(tbs(9, issuer, validity, subject, exts))


# ---------------------------------------------------------------- Glow

def real_tlv(body):
    return tlv(0x09, body)


def glow_root(*root_elements):
    """Root [APPLICATION 0] { RootElementCollection [APPLICATION 11]
    IMPLICIT SEQUENCE OF [0] RootElement }"""
    return app(0, app(11, b''.join(ctx(0, e) for e in root_elements)))


def glow_frames():
    f = []
    contents = set_(
        ctx(0, tlv(0x0c, b'gain')),
        ctx(1, tlv(0x0c, b'Output gain')),
        ctx(2, real_tlv(b'\xc0\xff\x0d')),                 # value REAL -6.5
        ctx(3, real_tlv(b'\xc0\x00\x60')),                 # minimum REAL -96
        ctx(4, integer(12)),                               # maximum Integer64
        ctx(5, integer(3)),                                # access readWrite
        ctx(9, tlv(0x01, b'\xff')),                        # isOnline
        ctx(13, integer(2)),                               # type real
        ctx(12, real_tlv(b'')),                            # default REAL 0
        ctx(18, tlv(0x0d, rel_oid_body('1.1.5'))),         # templateReference
    )
    param = app(1, ctx(0, integer(1)) + ctx(1, contents))
    qparam = app(9, ctx(0, tlv(0x0d, rel_oid_body('1.2.3'))) +
                 ctx(1, set_(ctx(0, tlv(0x0c, b'mute')), ctx(2, tlv(0x05, b'')))))
    qnode = app(10, ctx(0, tlv(0x0d, rel_oid_body('1.2'))) +
                ctx(1, set_(ctx(0, tlv(0x0c, b'node')), ctx(2, tlv(0x01, b'\xff')),
                            ctx(5, tlv(0x0d, rel_oid_body('7'))))))
    # Matrix with MatrixContents (SET with mandatory members)
    mcontents = set_(ctx(0, tlv(0x0c, b'router')), ctx(4, integer(16)), ctx(5, integer(8)),
                     ctx(2, integer(2)), ctx(8, tlv(0x0d, rel_oid_body('1.4'))))
    conns = app(16, ctx(0, integer(1)) + ctx(1, tlv(0x0d, rel_oid_body('2.3'))) + ctx(2, integer(1)))
    matrix = app(13, ctx(0, integer(4)) + ctx(1, mcontents) + ctx(5, seq(ctx(0, conns))))
    f.append(glow_root(param, qparam, qnode, matrix))
    # Template: [APPLICATION 24] IMPLICIT SET, and an indefinite-length
    # SET with indefinite-length members
    template = app(24, ctx(0, integer(5)) + ctx(2, tlv(0x0c, b'tmpl')))
    icontents = indef(0x31, indef(ident(2, True, 0), tlv(0x0c, b'indef')) +
                      ctx(2, real_tlv(b'\x80\x01\x03')))    # value REAL 6
    iparam = app(1, ctx(0, integer(2)) + ctx(1, icontents))
    eparam = app(1, ctx(0, integer(3)) + ctx(1, set_(ctx(0, tlv(0x0c, b'eoc')), b'\x00\x00')))
    f.append(glow_root(template, iparam, eparam))
    # Streams: StreamCollection [APPLICATION 6] of StreamEntry
    entries = b''.join(ctx(0, app(5, ctx(0, integer(i)) + ctx(1, v))) for i, v in
                       ((1, integer(-7)), (2, real_tlv(b'\x40')), (3, tlv(0x04, b'\x00\x01'))))
    f.append(app(0, app(6, entries)))
    # InvocationResult [APPLICATION 23]
    f.append(app(0, app(23, ctx(0, integer(9)) + ctx(1, tlv(0x01, b'\xff')) +
                        ctx(2, seq(ctx(0, real_tlv(b'\x03' + b'25E-2')), ctx(0, tlv(0x0c, b'ok')))))))
    return f


def glow_warning_frames():
    f = []
    # Template SET without the mandatory number [0], with an unknown
    # member [7]; MatrixContents without identifier/targetCount
    template = app(24, ctx(2, tlv(0x0c, b'no number')) + ctx(7, integer(1)))
    mcontents = set_(ctx(5, integer(8)))
    matrix = app(13, ctx(0, integer(4)) + ctx(1, mcontents))
    f.append(glow_root(template, matrix))
    # Parameter: number [0] missing (wrong field), a constructed REAL
    # value, an empty CHOICE (value [2] of length 0); ElementCollection
    # (SEQUENCE OF [0] Element) with an item tagged [1]
    p1 = app(1, ctx(1, set_(ctx(2, tlv(0x29, b'\x80\x01\x03')))))
    p2 = app(1, ctx(0, integer(2)) + ctx(1, set_(ctx(2, b''), ctx(12, tlv(0x29, b'\x80\x01\x03')))) +
             ctx(2, app(4, ctx(1, app(3, ctx(0, integer(1)))))))
    f.append(glow_root(p1, p2))
    # a RootElement with an unknown application tag (no CHOICE alternative
    # matches in either pass); a Matrix targetList item tagged [1]
    tmatrix = app(13, ctx(0, integer(5)) + ctx(3, seq(ctx(1, app(14, seq(ctx(0, integer(1))))))))
    f.append(glow_root(app(30, integer(1)), tmatrix))
    # a SET member whose length runs past the end of the SET
    bad = b'\x31\x05' + b'\xa0\x07' + tlv(0x0c, b'abc')
    f.append(glow_root(app(1, ctx(0, integer(1)) + ctx(1, bad))))
    return f


# ---------------------------------------------------------------- INAP

def inap_frames():
    """EventReportFacility (opcode 104) with a relayedComponent: an
    EMBEDDED PDV (dissect_ber_EmbeddedPDV_Type)."""
    pdv = oid('1.3.6.1.4.1.32473.9') + ctx(1, b'\x0a\x0b\x0c', constructed=False)
    arg = seq(ctx(1, ctx(1, pdv)))
    return [ctx(1, integer(1) + integer(104) + arg)]


# ---------------------------------------------------------------- LDAP

def ldap_msg(msgid, op, controls=None):
    items = integer(msgid) + op
    if controls is not None:
        items += ctx(0, b''.join(controls))
    return seq(items)


def os_(b):
    return tlv(0x04, b)


def ldap_frames():
    c = TcpConv(40389, 389)
    f = []
    # bindRequest, version 3, LDAPDN as a constructed OCTET STRING of
    # three segments (reassembled with a field), simple password
    dn = tlv(0x24, os_(b'cn=admin,') + os_(b'dc=example,') + os_(b'dc=com'))
    f.append(c.seg(True, ldap_msg(1, app(0, integer(3) + dn + ctx(0, b'secret', False)))))
    f.append(c.seg(False, ldap_msg(1, app(1, tlv(0x0a, b'\x00') + os_(b'') + os_(b'')))))
    # bindRequest with the simple password [0] as an indefinite-length
    # constructed string (implicitly tagged, EOC handled by the CHOICE)
    pw = indef(ident(2, True, 0), os_(b'sec') + os_(b'ret'))
    f.append(c.seg(True, ldap_msg(2, app(0, integer(3) + os_(b'cn=user') + pw))))
    f.append(c.seg(False, ldap_msg(2, app(1, tlv(0x0a, b'\x00') + os_(b'') + os_(b'')))))
    # searchRequest with a nested filter and attribute list, and a control
    flt = ctx(0, ctx(3, os_(b'objectClass') + os_(b'person')) +
              ctx(1, ctx(7, b'mail', False) + ctx(4, os_(b'cn') + seq(ctx(0, b'Ad', False), ctx(2, b'n', False)))) +
              ctx(2, ctx(5, os_(b'uidNumber') + os_(b'1000'))))
    base = indef(0x24, os_(b'dc=example,') + os_(b'dc=com'))     # indefinite, constructed
    srch = app(3, base + tlv(0x0a, b'\x02') + tlv(0x0a, b'\x00') +
               integer(0) + integer(30) + tlv(0x01, b'\x00') + flt + seq(os_(b'cn'), os_(b'mail')))
    ctl = [seq(os_(b'1.2.840.113556.1.4.319'), tlv(0x01, b'\xff'),
               os_(seq(integer(100), os_(b''))))]
    f.append(c.seg(True, ldap_msg(3, srch, ctl)))
    # searchResEntry: a constructed AttributeValue of one primitive
    # segment, and one of a constructed segment holding one segment
    one = tlv(0x24, os_(b'Admin'))
    nested = tlv(0x24, tlv(0x24, os_(b'admin@example.com')))
    entry = app(4, os_(b'cn=admin,dc=example,dc=com') + seq(
        seq(os_(b'cn'), set_(one)),
        seq(os_(b'mail'), set_(nested)),
        seq(os_(b'objectClass'), set_(os_(b'top'), os_(b'person')))))
    f.append(c.seg(False, ldap_msg(3, entry)))
    f.append(c.seg(False, ldap_msg(3, app(5, tlv(0x0a, b'\x00') + os_(b'') + os_(b'done')))))
    # repro ber_ldap_reasm_hf_minus1.py: addRequest whose AttributeValue
    # is a constructed OCTET STRING of two segments; LDAP passes hf_id -1
    # and the reassembly used to fail the "Unregistered hf" assertion
    val = tlv(0x24, os_(b'ab') + os_(b'cd'))
    attr = seq(os_(b'cn'), set_(val))
    f.append(c.seg(True, ldap_msg(4, app(8, os_(b'') + seq(attr)))))
    f.append(c.seg(False, ldap_msg(4, app(9, tlv(0x0a, b'\x00') + os_(b'') + os_(b'')))))
    # extendedReq (StartTLS OID) and unbindRequest
    f.append(c.seg(True, ldap_msg(5, app(23, ctx(0, b'1.3.6.1.4.1.1466.20037', False)))))
    # unbindRequest with an empty indefinite-length controls [0]
    f.append(c.seg(True, seq(integer(6) + app(2, b'', False) + indef(ident(2, True, 0), b''))))
    return f


# ---------------------------------------------------------------- SNMP

def varbind(o, value):
    return seq(oid(o), value)


def snmp_frames():
    f = []
    cport = 40161
    # v1 get-request and get-response
    pdu = ctx(0, integer(1001) + integer(0) + integer(0) + seq(varbind('1.3.6.1.2.1.1.1.0', tlv(0x05, b''))))
    f.append(udp(CLIENT, SERVER, cport, 161, seq(integer(0), os_(b'public'), pdu)))
    pdu = ctx(2, integer(1001) + integer(0) + integer(0) + seq(
        varbind('1.3.6.1.2.1.1.1.0', os_(b'BER test agent')),
        varbind('1.3.6.1.2.1.1.3.0', app(3, b'\x01\x02\x03', False)),
        varbind('1.3.6.1.2.1.31.1.1.1.6.1', app(6, b'\x00\xff\xff\xff\xff\xff\xff\xff\xff', False))))
    f.append(udp(SERVER, CLIENT, 161, cport, seq(integer(0), os_(b'public'), pdu)))
    # v2c get-bulk with a negative request-id
    pdu = ctx(5, integer(-5) + integer(0) + integer(10) + seq(varbind('1.3.6.1.2.1.2.2.1', tlv(0x05, b''))))
    f.append(udp(CLIENT, SERVER, cport, 161, seq(integer(1), os_(b'private'), pdu)))
    # v1 trap: enterprise OID, NetworkAddress [APPLICATION 0] (tagged
    # type), TimeTicks [APPLICATION 3]
    trap = ctx(4, oid('1.3.6.1.4.1.32473') + app(0, bytes([192, 0, 2, 10]), False) + integer(6) +
               integer(17) + app(3, b'\x00\x10\x00', False) + seq(varbind('1.3.6.1.4.1.32473.1', integer(5))))
    f.append(udp(SERVER, CLIENT, 41162, 162, seq(integer(0), os_(b'public'), trap)))
    # v3 with a plaintext scoped PDU
    hdr = seq(integer(77), integer(65507), os_(b'\x04'), integer(3))
    usm = os_(seq(os_(b'\x80\x00\x7f\x99\x04bertest'), integer(1), integer(100),
                  os_(b'user'), os_(b''), os_(b'')))
    scoped = seq(os_(b'\x80\x00\x7f\x99\x04bertest'), os_(b''),
                 ctx(0, integer(2002) + integer(0) + integer(0) + seq(varbind('1.3.6.1.2.1.1.5.0', tlv(0x05, b'')))))
    f.append(udp(CLIENT, SERVER, cport, 161, seq(integer(3), hdr, usm, scoped)))
    return f


def snmp_warning_frames():
    """Returns (constraint warnings, malformed)."""
    f = []
    cport = 40161
    # v1 trap: agent-addr of 5 octets (FT_IPv4 field: bad length, size
    # constraint 4..4), then one with a wrong application tag
    for addr in (app(0, bytes([192, 0, 2, 10, 1]), False), app(1, bytes([192, 0, 2, 10]), False)):
        trap = ctx(4, oid('1.3.6.1.4.1.32473') + addr + integer(6) + integer(17) +
                   app(3, b'\x10', False) + seq())
        f.append(udp(SERVER, CLIENT, 41162, 162, seq(integer(0), os_(b'public'), trap)))
    mal, f = f, []
    # v3: msgMaxSize below 484, a user name longer than 32 octets
    hdr = seq(integer(78), integer(100), os_(b'\x04'), integer(3))
    usm = os_(seq(os_(b'\x80\x00\x7f\x99\x04bertest'), integer(1), integer(100),
                  os_(b'u' * 33), os_(b''), os_(b'')))
    scoped = seq(os_(b'\x80\x00\x7f\x99\x04bertest'), os_(b''),
                 ctx(0, integer(2003) + integer(0) + integer(0) + seq()))
    f.append(udp(CLIENT, SERVER, cport, 161, seq(integer(3), hdr, usm, scoped)))
    # v3: an empty user name (SIZE (1..32))
    hdr = seq(integer(79), integer(1500), os_(b'\x04'), integer(3))
    usm = os_(seq(os_(b'\x80\x00\x7f\x99\x04bertest'), integer(1), integer(100),
                  os_(b''), os_(b''), os_(b'')))
    f.append(udp(CLIENT, SERVER, cport, 161, seq(integer(3), hdr, usm, scoped)))
    return f, mal


def ldap_warning_frames():
    c = TcpConv(40390, 389)
    f = []
    # bindRequest with version 0 and with version 200 (INTEGER (1..127))
    for v in (0, 200):
        f.append(c.seg(True, ldap_msg(7 + v, app(0, integer(v) + os_(b'') + ctx(0, b'', False)))))
    return f


# ---------------------------------------------------------------- GOOSE

def goose_frame(extra=b''):
    """IEC 61850 GOOSE (ethertype 0x88b8): implicitly tagged BOOLEAN,
    REAL, OBJECT IDENTIFIER and BIT STRING; add_ber_encoded_label()."""
    def c(n, body, constructed=False):
        return ctx(n, body, constructed)
    data = b''.join([
        c(3, b'\x01'),                                   # boolean
        c(4, b'\x03\xa8'),                               # bit-string
        c(5, b'\xff\x85'),                               # integer -123
        c(6, b'\x01\x00'),                               # unsigned 256
        c(8, b'\x80\x02\x03'),                           # real 12 (implicit REAL)
        c(8, b''),                                       # real 0
        c(9, b'\x0a\x0b'),                               # octet-string
        c(10, b'vis'),                                   # visible-string
        c(15, oid_body('1.0.61850.7.2')),                # objId (implicit OID)
        c(16, b'mms'),                                   # mMSString
        c(2, c(3, b'\x00') + c(5, b'\x07'), True),       # structure
    ]) + extra
    pdu = (c(0, b'IED1/LLN0$GO$gcb1') + c(1, b'\x07\xd0') + c(2, b'IED1/LLN0$ds1') +
           c(3, b'goid1') + c(4, b'\x68\x3b\x9c\x00\x00\x00\x00\x0a') + c(5, b'\x01') +
           c(6, b'\x02') + c(7, b'\x00') + c(8, b'\x01') + c(9, b'\x00') + c(10, b'\x0b') +
           c(11, data, True))
    apdu = app(1, pdu)
    body = struct.pack('!HHHH', 0x0001, 8 + len(apdu), 0, 0) + apdu
    return b'\x01\x0c\xcd\x01\x00\x01' + b'\x02\x00\x00\x00\x00\x03' + b'\x88\xb8' + body


# ---------------------------------------------------------------- Kerberos

def kstr(s):
    return tlv(0x1b, s)


def principal(ntype, *names):
    return seq(ctx(0, integer(ntype)), ctx(1, seq(*[kstr(n) for n in names])))


def kerberos_frames():
    """AS-REQ and AS-REP on UDP 88: KDCOptions (named bits),
    GeneralizedTime, GeneralString and the encrypted ticket data through
    dissect_ber_octet_string_wcb()."""
    body = seq(ctx(0, tlv(0x03, b'\x00\x50\x80\x00\x10')),
               ctx(1, principal(1, b'alice')),
               ctx(2, kstr(b'EXAMPLE.COM')),
               ctx(3, principal(2, b'krbtgt', b'EXAMPLE.COM')),
               ctx(5, tlv(0x18, b'20370913024805Z')),
               ctx(7, integer(12345)),
               ctx(8, seq(integer(18), integer(17))))
    asreq = app(10, seq(ctx(1, integer(5)), ctx(2, integer(10)), ctx(4, body)))
    encdata = lambda c: seq(ctx(0, integer(18)), ctx(1, integer(2)), ctx(2, tlv(0x04, c)))
    ticket = app(1, seq(ctx(0, integer(5)), ctx(1, kstr(b'EXAMPLE.COM')),
                        ctx(2, principal(2, b'krbtgt', b'EXAMPLE.COM')), ctx(3, encdata(bytes(range(48))))))
    asrep = app(11, seq(ctx(0, integer(5)), ctx(1, integer(11)), ctx(3, kstr(b'EXAMPLE.COM')),
                        ctx(4, principal(1, b'alice')), ctx(5, ticket), ctx(6, encdata(bytes(range(64, 112))))))
    return [udp(CLIENT, SERVER, 40088, 88, asreq), udp(SERVER, CLIENT, 88, 40088, asrep)]


# ---------------------------------------------------------------- malformed

def malformed_frames():
    """Paths that end in an exception, and the known two-pass issues."""
    f = []
    E = lambda name, b: exported_pdu(name, b)
    big = b'\x84\x7f\xff\xff\xff'          # length INT32_MAX
    # unknown BER nested deeper than BER_MAX_NESTING
    deep = integer(1)
    for _ in range(600):
        deep = tlv(0x30, deep)
    f.append(E('ber', deep))
    # indefinite lengths nested deeper than BER_MAX_NESTING (get_ber_length)
    deep = integer(1)
    for _ in range(600):
        deep = indef(0x30, deep)
    f.append(E('ber', deep))
    # an indefinite length whose element does not move forward
    f.append(E('ber', b'\x30\x80\x30\x84\xff\xff\xff\xf0' + b'\x00' * 4))
    # lengths that overflow the end offset: SEQUENCE, OCTET STRING,
    # SET, CHOICE, SEQUENCE OF, BIT STRING
    f.append(E('pkix-cert', b'\x30' + big + b'\x30\x00'))
    f.append(E('pkix-cert', certificate(tbs(1, name(), seq(), name(), [ext('2.5.29.14', b'\x04' + big)]))))
    f.append(E('pkix-cert', certificate(tbs(1, name(), seq(), name(), [ext('2.5.4.14', b'\x31' + big)]))))
    f.append(E('pkix-cert', certificate(tbs(1, name(), seq(), name(), [ext('2.5.4.3', b'\x0c' + big)]))))
    f.append(E('pkix-cert', certificate(tbs(1, name(), seq(), name(), [ext('2.5.29.32', b'\x30' + big)]))))
    f.append(E('pkix-cert', certificate(tbs(1, name(), seq(), name(), [ext('2.5.29.15', b'\x03' + big)]))))
    # constructed OCTET STRING whose second segment is an INTEGER, and
    # one with an empty first segment (LDAP AttributeValue)
    c = TcpConv(40400, 389, (192, 0, 2, 40))
    for val in (tlv(0x24, os_(b'ab') + integer(1)), tlv(0x24, os_(b'') + os_(b'cd'))):
        attr = seq(os_(b'cn'), set_(val))
        f.append(E('eth_withoutfcs', c.seg(True, ldap_msg(9, app(8, os_(b'cn=x') + seq(attr))))))
    # GOOSE implicit OCTET STRING and REAL longer than their CHOICE
    for item in (b'\x89\x05\x01', b'\x88\x05\x80'):
        f.append(E('eth_withoutfcs', goose_frame(item)))
    # an empty subjectPublicKey BIT STRING (X.509 then fails on the key)
    f.append(E('pkix-cert', certificate(tbs(10, name(), seq(), name(), None,
                                            key=seq(alg(RSA), tlv(0x03, b'\x00'))))))
    # constructed OCTET STRING nested deeper than BER_MAX_NESTING
    deep = os_(b'x')
    for _ in range(600):
        deep = tlv(0x24, deep)
    attr = seq(os_(b'cn'), set_(deep))
    f.append(E('eth_withoutfcs', TcpConv(40404, 389, (192, 0, 2, 44)).seg(True, ldap_msg(9, app(8, os_(b'') + seq(attr))))))
    # repro ber_reasm_twopass.py (known, not fixed): two constructed
    # OCTET STRINGs at the same nesting level in one frame share a
    # reassembly id; the second pass shows the first one's data twice
    c = TcpConv(40401, 389, (192, 0, 2, 41))
    dn = tlv(0x24, os_(b'dc=A') + os_(b'AAA'))
    typ = tlv(0x24, os_(b'BB') + os_(b'BB'))
    f.append(E('eth_withoutfcs', c.seg(True, ldap_msg(1, app(8, dn + seq(seq(typ, set_())))))))
    # repro ber_reasm_leftover.py (known, not fixed): a reassembly
    # aborted by an exception leaks its first segment into the next
    # frame's reassembly on the first pass only
    c = TcpConv(40402, 389, (192, 0, 2, 42))
    for i, dn in enumerate((tlv(0x24, os_(b'XXXX') + integer(1)), tlv(0x24, os_(b'dc=A') + os_(b'AAA')))):
        f.append(E('eth_withoutfcs', c.seg(True, ldap_msg(i + 1, app(8, dn + seq(seq(os_(b'cn'), set_())))))))
    # new: a constructed segment holding two segments; on the second
    # pass the inner reassembly returns after its first segment and the
    # outer one fails
    c = TcpConv(40403, 389, (192, 0, 2, 43))
    nested = tlv(0x24, tlv(0x24, os_(b'adm') + os_(b'in@example.com')))
    f.append(E('eth_withoutfcs', c.seg(False, ldap_msg(3, app(4, os_(b'cn=a') + seq(seq(os_(b'mail'), set_(nested))))))))
    return f


def truncated_frame():
    """A certificate cut by the snapshot length: SEQUENCE OF counts
    "unknown number of items"."""
    full = exported_pdu('pkix-cert', cert1())
    return full, 120


def write_pcap_trunc(fn, frames):
    """frames: list of bytes or (bytes, caplen)."""
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            if isinstance(fr, tuple):
                fr, cap = fr
            else:
                cap = len(fr)
            f.write(struct.pack('<IIII', 1748736000 + i, 0, cap, len(fr)))
            f.write(fr[:cap])


def ber_file():
    """A raw BER file with an indefinite length, so wiretap does not need
    the (compressed) file size to match."""
    return indef(0x30, integer(2025) + tlv(0x0c, b'BER file') +
                 indef(ident(2, True, 1), oid('1.3.6.1.4.1.32473.7') + tlv(0x05, b'')) +
                 set_(tlv(0x01, b'\xff'), tlv(0x18, b'20250601000000Z')))


# ---------------------------------------------------------------- main

def main_frames():
    """Returns [(section description, [frames])] for the main capture."""
    E = exported_pdu
    eth_ = lambda frames: [E('eth_withoutfcs', x) for x in frames]
    sections = []
    sections.append(('unknown BER ("ber")', [E('ber', x) for x in unknown_ber_frames()]))
    # repro ber_file_epdu_null.py: "ber_file" without file data
    sections.append(('"ber_file" without data (repro)',
                     [E('ber_file', seq(integer(1), tlv(0x0c, b'file')))]))
    sections.append(('X.509 certificates ("pkix-cert")',
                     [E('pkix-cert', x) for x in (cert1(), cert2(), cert3())]))
    sections.append(('CRL ("x509af")', [E('x509af', crl())]))
    sections.append(('Glow', [E('glow', x) for x in glow_frames()]))
    sections.append(('INAP', [E('inap', x) for x in inap_frames()]))
    sections.append(('LDAP on TCP 389', eth_(ldap_frames())))
    sections.append(('SNMP on UDP 161', eth_(snmp_frames())))
    sections.append(('GOOSE', eth_([goose_frame()])))
    sections.append(('Kerberos on UDP 88', eth_(kerberos_frames())))
    sections.append(('REAL overflow (repro), warning', [E('ber', real_overflow_frame())]))
    sections.append(('size constraint warnings: SNMP', eth_(snmp_warning_frames()[0])))
    sections.append(('size constraint warnings: LDAP', eth_(ldap_warning_frames())))
    return sections


def malformed_sections():
    E = exported_pdu
    return [
        ('BER Error warnings: unknown BER', [E('ber', x) for x in unknown_ber_warning_frames()]),
        ('BER Error warnings: Glow', [E('glow', x) for x in glow_warning_frames()]),
        ('BER Error warnings: X.509', [E('pkix-cert', warning_cert())]),
        ('BER Error warnings: SNMP', [E('eth_withoutfcs', x) for x in snmp_warning_frames()[1]]),
        ('exceptions and two-pass issues', malformed_frames()),
        ('truncated certificate', [truncated_frame()]),
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    for fn, sections in (('ber-coverage.pcap', main_frames()),
                         ('ber-coverage-malformed.pcap', malformed_sections())):
        print(fn)
        frames = []
        for title, fr in sections:
            print('  %4d-%-4d %s' % (len(frames) + 1, len(frames) + len(fr), title))
            frames += fr
        write_pcap_trunc(os.path.join(out, fn), frames)
    with open(os.path.join(out, 'ber-coverage.ber'), 'wb') as f:
        f.write(ber_file())
    with open(os.path.join(out, 'ber-coverage.cer'), 'wb') as f:
        f.write(cert1())


if __name__ == '__main__':
    main()
