#!/usr/bin/env python3
# Generates test/captures/acp133_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the ACP133 dissector (packet-acp133.c): mkacp133.py
<outdir>.  ACP133 registers the attribute syntaxes of the ACP 133 / SDN.701 /
X.402 directory attributes in the BER OID table; they are reached when a
directory Name carries an AttributeTypeAndValue whose type is one of the
OIDs.  The carrier is an X.509 CRL whose issuer has one RDN per attribute
(Exported PDU "x509af"), the BER helpers are in x500lib.py / x400lib.py.
Everything is synthetic."""
import os, random, sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
from x400lib import *  # noqa: F401,F403
from x500lib import *  # noqa: F401,F403

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
AT_CN_ = '2.5.4.3'


def name(*cns):
    return SEQ(*[SET(SEQ(OID(AT_CN_), PSTR(c))) for c in cns])


def ps_seq(*s):
    return SEQ(*[PSTR(x) for x in s])


# ---- GeneralNames
def gn_dir(*cns):
    return X(4, name(*cns))


GN1 = SEQ(gn_dir('List A'), IA5('list@example.org', 0x81), IA5('example.org', 0x82))
GN2 = SEQ(gn_dir('List B'))

ALGID = SEQ(OID('1.2.840.113549.1.1.11'), NULL())
ALGID_PARAM = SEQ(OID('1.2.840.113549.3.7'), OCTS(b'12345678'))

# CertificateAssertion body [n] IMPLICIT SEQUENCE
CERT_ASSERT_BODY = (INT(5, 0x80) + X(1, name('Issuer CA')) + OID('1.2.840.113549.1.1.1', 0x86) +
                    BITS(5, b'\xa0', 0x87) + X(10, name('Path')) + X(11, name('Subject')))


def alg_info(full=True, alt=False):
    body = X(0, *([OID('1.2.840.113549.3.7'), OCTS(b'12345678')] if alt else [OID('1.2.840.113549.1.1.11'), NULL()]))
    if full:
        body += tlv(0xa1, CERT_ASSERT_BODY) + tlv(0xa2, INT(7, 0x80))
    return SEQ(body)


# ---- values per syntax ----------------------------------------------------
def dl_submit_permissions():
    orn = orname()
    return [
        retag(0xa0, orn),                       # individual
        retag(0xa1, orname(ous=(), personal=False, ddas=())),   # member-of-dl
        retag(0xa2, orname(org='Pattern', ous=('A', 'B'))),     # pattern-match
        X(3, name('Group One', 'Group Two')),   # member-of-group
    ]


def dl_policy():
    full = SET(INT(2, 0x80), INT(1, 0x81), INT(4, 0x82), INT(3, 0x83), ENUM(2, 0x84),
               INT(3, 0x85), ENUM(2, 0x86), ENUM(2, 0x87), ENUM(2, 0x88), BOOL(False, 0x89),
               BOOL(False, 0x8a), INT(2, 0x8b),
               X(12, SEQ(INT(1), INT(2), INT(9))),
               tlv(0xad, alg_info(True), alg_info(False, alt=True)),
               tlv(0xae, alg_info(True)))
    out = [full, SET()]
    for m in (NULL(0x80), NULL(0x81)):
        out.append(SET(X(12, m)))
    for i, v in enumerate((0, 1, 2)):
        out.append(SET(INT(v, 0x80), INT(v % 2, 0x81), INT(v + 2 if v else 0, 0x82), INT(v, 0x83),
                       ENUM(v, 0x84), INT(v, 0x85), ENUM(v, 0x86), ENUM(v, 0x87), ENUM(v, 0x88),
                       BOOL(True, 0x89), BOOL(True, 0x8a), INT(v, 0x8b)))
    return out


def capability(full=True):
    body = b''
    if full:
        body += tlv(0xa0, OID('2.6.3.4.1'), OID('2.6.3.4.2'), OID('1.2.3.50'))
        body += INT(5000, 0x81)
        body += tlv(0xa2, tlv(0xa0, OID('1.2.3.70')), tlv(0xa1, OID('1.2.3.71')))
        body += tlv(0xa3, sec_label(), sec_label(cats=True))
    return SET(body)


def address_capabilities():
    return [SEQ(GSTR('Mail gateway'), or_address(), SET(capability(), capability(False))),
            SEQ(or_address(ous=(), personal=False, ddas=()), SET())]


def monthly_ukms():
    pt = SEQ(OCTS(b'KMID0001'), INT(3), UTCT('261101000000Z'))
    pt2 = SEQ(OCTS(b'KMID0002'), INT(1))
    return [SEQ(SEQ(SEQ(pt, OCTS(b'\x01' * 16)), SEQ(pt2, OCTS(b'\x02' * 8))), ALGID, BITS(0, b'\xa5' * 8)),
            SEQ(SEQ(), ALGID_PARAM, BITS(0, b'\x00'))]


def ri_parameters():
    return [PSTR('RI-PARAMS'), UTF8('ri parameters utf8'),
            SET(PSTR('RI1', 0x80), ENUM(0, 0x81), BOOL(False, 0x82), PSTR('SHD', 0x83), ENUM(3, 0x84)),
            SET(PSTR('RI2', 0x80), ENUM(1, 0x81), BOOL(True, 0x82), PSTR('SHD2', 0x83), ENUM(5, 0x84)),
            SET(PSTR('RI3', 0x80), ENUM(2, 0x81), BOOL(True, 0x82), PSTR('', 0x83), ENUM(0, 0x84))]


def ml_receipt_policy():
    return [NULL(0x80), tlv(0xa1, GN1, GN2), tlv(0xa2, GN2), tlv(0xa1)]


SYN = [
    # X.402
    ('2.6.5.2.4', dl_submit_permissions()),
    ('2.6.5.2.13', dl_policy()),
    ('2.6.5.2.16', address_capabilities()),
    ('2.6.5.2.19', [capability(), capability(False)]),
    # SDN.701
    ('2.16.840.1.101.2.1.5.14', [OCTS(b'\x00\x01\x02\x03\x04\x05\x06\x07'), OCTS(b'')]),
] + [('2.16.840.1.101.2.1.5.%d' % n, monthly_ukms()[:1 if n % 2 else 2]) for n in range(20, 32)] + [
    # ACP133
    ('2.16.840.1.101.2.2.1.46', [ps_seq('ACTION ONE', 'ACTION TWO'), ps_seq()]),
    ('2.16.840.1.101.2.2.1.47', [ps_seq('ADDITIONAL')]),
    ('2.16.840.1.101.2.2.1.48', [ps_seq('SECOND PARTY')]),
    ('2.16.840.1.101.2.2.1.50', [ps_seq('ORIGINATOR')]),
    ('2.16.840.1.101.2.2.1.52', [ENUM(v) for v in (0, 1, 2)]),
    ('2.16.840.1.101.2.2.1.56', [ENUM(v) for v in range(6)]),
    ('2.16.840.1.101.2.2.1.59', [ps_seq('INFO ONE', 'INFO TWO')]),
    ('2.16.840.1.101.2.2.1.67', [ENUM(v) for v in (0, 3, 5)]),
    ('2.16.840.1.101.2.2.1.71', [ps_seq('PLA ONE')]),
    ('2.16.840.1.101.2.2.1.76', [ps_seq('first remark', 'second remark'), ps_seq()]),
    ('2.16.840.1.101.2.2.1.78', [ENUM(v) for v in (1, 2, 4)]),
    ('2.16.840.1.101.2.2.1.79', ri_parameters()),
    ('2.16.840.1.101.2.2.1.80', [ps_seq('SECOND ONE')]),
    ('2.16.840.1.101.2.2.1.104', [PSTR('DIST-ACTION-1'), PSTR('')]),
    ('2.16.840.1.101.2.2.1.105', [PSTR('DIST-INFO-1')]),
    ('2.16.840.1.101.2.2.1.108', [ENUM(v) for v in (0, 1, 2)]),
    ('2.16.840.1.101.2.2.1.112', [INT(v) for v in range(5)]),
    ('2.16.840.1.101.2.2.1.123', [BITS(5, b'\xe0'), BITS(7, b'\x80'), BITS(0, b'')]),
    ('2.16.840.1.101.2.2.1.135', ml_receipt_policy()),
    ('2.16.840.1.101.2.2.1.142', [INT(v) for v in (0, 1, 4, 8, 17, 18, 32, 36)]),
    ('2.16.840.1.101.2.2.1.146', [OCTS(b'\xff\xd8\xff\xe0' + b'JFIF\0' + b'\x00' * 8 + b'\xff\xd9')]),
    ('2.16.840.1.101.2.2.1.147', [OCTS(b'\xff\xd8\xff\xe0' + b'JFIF\0' + b'\x01' * 4 + b'\xff\xd9')]),
    ('2.16.840.1.101.2.2.1.162', [INT(0), INT(1048576), INT(2 ** 31 - 1), INT(2 ** 40), INT(-5)]),
    ('2.16.840.1.101.2.2.1.163', [ENUM(0), ENUM(1)]),
    ('2.16.840.1.101.2.2.1.164', [BOOL(True), BOOL(False)]),
    ('2.16.840.1.101.2.2.1.165', [BOOL(True), BOOL(False)]),
    ('2.16.840.1.101.2.2.1.166', [ENUM(v) for v in range(4)]),
    ('2.16.840.1.101.2.2.1.167', [BOOL(True), BOOL(False)]),
    ('2.16.840.1.101.2.2.1.168', [PSTR('EXEMPT-ACTION')]),
    ('2.16.840.1.101.2.2.1.169', [PSTR('EXEMPT-INFO')]),
    ('2.16.840.1.101.2.2.1.170', [PSTR('KEYWORD-ACTION')]),
    ('2.16.840.1.101.2.2.1.171', [PSTR('KEYWORD-INFO')]),
    ('2.16.840.1.101.2.2.1.189', [BOOL(True), BOOL(False)]),
]


def crl(pairs):
    """CRL with the values in the issuer Name (x509if also formats every
    value as a string, which warns for non-string syntaxes)."""
    return crl_with_issuer(*pairs)


def crl_attrs(*attrs):
    """CRL whose subjectDirectoryAttributes extension (2.5.29.9) carries
    Attributes {type, SET OF values}; the values are dissected through the
    BER OID table without any string formatting."""
    return crl_with_exts(('2.5.29.9', SEQ(*[SEQ(OID(o), SET(*vals)) for o, vals in attrs])))


def main():
    pc = Pcapng()
    # one frame per attribute syntax, every value in its own RDN
    for oid_, vals in SYN:
        pc.exp('x509af', crl_attrs((oid_, vals)))
    # one frame with a value of every syntax at once
    pc.exp('x509af', crl_attrs(*[(o, vals[:1]) for o, vals in SYN]))
    pc.write(os.path.join(OUT, 'acp133-coverage.pcapng'))

    # ---- malformed: random BER values for every OID (seeded), truncated
    # and wrong-typed values
    r = random.Random(1330)
    tags = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0a, 0x13, 0x14, 0x16, 0x17, 0x18, 0x1e, 0x0c,
            0x30, 0x31, 0x80, 0x81, 0x82, 0x83, 0x84, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0x60, 0x61]

    def rval(depth=0):
        t = r.choice(tags)
        if t & 0x20 and depth < 5:
            return tlv(t, b''.join(rval(depth + 1) for _ in range(r.randint(0, 4))))
        n = r.choice([0, 1, 2, 3, 4, 8, 9, 20])
        return tlv(t & ~0x20 & 0xff if t & 0x20 else t, bytes(r.randrange(256) for _ in range(n)))
    bad = Pcapng()
    # MaxMessageSize is INTEGER but the field is a signed 32 bit one: larger values do not fit (malformed capture)
    bad.exp('x509af', crl_attrs(('2.16.840.1.101.2.2.1.162', [INT(2 ** 70)])))
    # the values in the issuer Name (x509if re-reads each value as an
    # OCTET STRING: warnings for the other syntaxes)
    for oid_, vals in SYN:
        bad.exp('x509af', crl([(oid_, v) for v in vals]))
    oids = [o for o, _ in SYN]
    for _ in range(40):
        bad.exp('x509af', crl([(o, rval()) for o in oids]))
        bad.exp('x509af', crl_attrs(*[(o, [rval(), rval()]) for o in oids]))
    for oid_, vals in SYN:
        v = vals[0]
        bad.exp('x509af', crl_attrs((oid_, [v[:len(v) // 2], v + b'\x00', NULL(), b''])))
        bad.exp('x509af', crl([(oid_, v[:len(v) // 2]), (oid_, v + b'\x00'), (oid_, NULL()), (oid_, b'')]))
    bad.write(os.path.join(OUT, 'acp133-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
