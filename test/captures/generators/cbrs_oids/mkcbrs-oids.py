#!/usr/bin/env python3
# Generates test/captures/cbrs_oids_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CBRS object identifier
dissector (packet-cbrs-oids.c, generated from asn1/cbrs-oids).

The dissector only registers seven BER OID dissectors (each a
UTF8String) and names the CBRS role and policy OIDs. They are reached
from X.509 certificates: an AttributeTypeAndValue in a Name whose type is
one of the CBRS OIDs, or an Extension whose extnID is one. The frames
are Exported PDUs (DLT 252) naming the "pkix-cert" dissector (the
application/pkix-cert media type), each holding one DER certificate in
the shape of the WInnForum CBRS PKI: one per role, with the role OID in
certificatePolicies. The keys and signatures are filler octets. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkcbrs-oids.py <output directory>

Writes:
  cbrs-oids-coverage.pcap            CBRS certificates for every role with
                                     every CBRS attribute
  cbrs-oids-coverage-malformed.pcap  CBRS attributes that are not a
                                     UTF8String or are cut short
"""

import hashlib
import os
import struct
import sys


def L(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(t, v):
    return bytes([t]) + L(len(v)) + v


def seq(*items):
    return tlv(0x30, b''.join(items))


def oid(s):
    a = [int(x) for x in s.split('.')]
    out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, out)


def utf8(s):
    return tlv(0x0c, s.encode())


def printable(s):
    return tlv(0x13, s.encode())


def integer(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big')
    return tlv(0x02, b)


CBRS = '1.3.6.1.4.1.46609'
ZONE = CBRS + '.1.2'
FREQUENCY = CBRS + '.1.3'
FCCID = CBRS + '.1.4'
SERIAL = CBRS + '.1.5'
FRN = CBRS + '.1.6'
CPIRID = CBRS + '.1.7'
TEST = CBRS + '.1.8'
ROLE = {'SAS': CBRS + '.1.1.1', 'INSTALLER': CBRS + '.1.1.2', 'CBSD': CBRS + '.1.1.3',
        'OPERATOR': CBRS + '.1.1.4', 'CA': CBRS + '.1.1.5', 'PAL': CBRS + '.1.1.6',
        'ESC': CBRS + '.1.1.7'}
CPS = CBRS + '.2.1'

CN, O, C = '2.5.4.3', '2.5.4.10', '2.5.4.6'


def rdn(t, value):
    return tlv(0x31, seq(oid(t), value))


def name(*rdns):
    return seq(*rdns)


def ext(extn_id, value, critical=False):
    return seq(oid(extn_id), *([tlv(0x01, b'\xff')] if critical else []), tlv(0x04, value))


def filler(tag, n):
    return hashlib.sha256(tag.encode()).digest() * (n // 32) + hashlib.sha256(tag.encode()).digest()[:n % 32]


SHA256_RSA = seq(oid('1.2.840.113549.1.1.11'), tlv(0x05, b''))
EC_P256 = seq(oid('1.2.840.10045.2.1'), oid('1.2.840.10045.3.1.7'))

ISSUER = name(rdn(C, printable('US')), rdn(O, utf8('Example CBRS PKI')),
              rdn(CN, utf8('Example CBRS Root CA')))


def certificate(serial, subject, roles, extra_ext=()):
    policies = seq(*[seq(oid(p)) for p in [CPS] + [ROLE[r] for r in roles]])
    exts = [ext('2.5.29.19', seq(), True),             # basicConstraints
            ext('2.5.29.15', tlv(0x03, b'\x07\x80'), True),  # keyUsage digitalSignature
            ext('2.5.29.32', policies)]                 # certificatePolicies
    exts += list(extra_ext)
    tbs = seq(tlv(0xa0, integer(2)), integer(serial), SHA256_RSA, ISSUER,
              seq(tlv(0x17, b'260101000000Z'), tlv(0x17, b'310101000000Z')),
              subject,
              seq(EC_P256, tlv(0x03, b'\x00\x04' + filler('key%d' % serial, 64))),
              tlv(0xa3, seq(*exts)))
    return seq(tbs, SHA256_RSA, tlv(0x03, b'\x00' + filler('sig%d' % serial, 256)))


def exp_pdu(name_, payload):
    n = name_.encode()
    pad = (-len(n)) % 4
    return (struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
            + struct.pack('>HH', 0, 0) + payload)


def write_pcap(path, payloads):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, p in enumerate(payloads):
            fr = exp_pdu('pkix-cert', p)
            f.write(struct.pack('<IIII', 1790000000 + i, 0, len(fr), len(fr)) + fr)


def main_certs():
    c = []
    # 1 CBSD: FCC ID and serial number in the subject
    c.append(certificate(1, name(rdn(C, printable('US')), rdn(O, utf8('Example Radio Co')),
                                 rdn(FCCID, utf8('ABC-CBSD100')),
                                 rdn(SERIAL, utf8('SN-000123456')),
                                 rdn(CN, utf8('CBSD SN-000123456'))), ['CBSD']))
    # 2 Professional installer: CPI registration ID
    c.append(certificate(2, name(rdn(C, printable('US')), rdn(CPIRID, utf8('CPIR-0042')),
                                 rdn(CN, utf8('Jane Installer'))), ['INSTALLER']))
    # 3 SAS administrator and 4 Domain Proxy operator: FCC registration number
    c.append(certificate(3, name(rdn(C, printable('US')), rdn(O, utf8('Example SAS Inc')),
                                 rdn(FRN, utf8('0012345678')),
                                 rdn(CN, utf8('sas.example'))), ['SAS']))
    c.append(certificate(4, name(rdn(O, utf8('Example DP Operator')),
                                 rdn(FRN, utf8('0087654321')),
                                 rdn(CN, utf8('dp.example'))), ['OPERATOR']))
    # 5 PAL holder: license zone and frequency
    c.append(certificate(5, name(rdn(O, utf8('Example PAL Holder')),
                                 rdn(ZONE, utf8('PAL-ZONE-06037')),
                                 rdn(FREQUENCY, utf8('3550-3560 MHz')),
                                 rdn(CN, utf8('PAL 06037'))), ['PAL']))
    # 6 ESC sensor with an empty FCC ID, and 7 a CA certificate
    c.append(certificate(6, name(rdn(O, utf8('Example ESC')), rdn(FCCID, utf8('')),
                                 rdn(CN, utf8('ESC sensor 7'))), ['ESC']))
    c.append(certificate(7, name(rdn(O, utf8('Example CBRS PKI')),
                                 rdn(CN, utf8('Example CBRS CBSD CA'))), ['CA']))
    # 8 a test certificate: the TEST attribute, UTF-8 text, all CBRS
    #   attributes in one subject, and the CBRS OIDs as extensions
    c.append(certificate(8, name(rdn(TEST, utf8('test certificate – not for use')),
                                 rdn(FCCID, utf8('XYZ-TEST')), rdn(SERIAL, utf8('T1')),
                                 rdn(FRN, utf8('0000000001')), rdn(CPIRID, utf8('CPIR-T')),
                                 rdn(ZONE, utf8('Z-T')), rdn(FREQUENCY, utf8('3700 MHz')),
                                 rdn(CN, utf8('CBRS test'))),
                         ['SAS', 'INSTALLER', 'CBSD', 'OPERATOR', 'CA', 'PAL', 'ESC'],
                         [ext(FCCID, utf8('EXT-FCCID')), ext(SERIAL, utf8('EXT-SERIAL')),
                          ext(TEST, utf8('EXT-TEST'))]))
    return c


def malformed_certs():
    c = []
    # 1 FCC ID as a PrintableString, 2 serial as an INTEGER
    c.append(certificate(101, name(rdn(FCCID, printable('ABC-CBSD100')),
                                   rdn(CN, utf8('wrong string type'))), ['CBSD']))
    c.append(certificate(102, name(rdn(SERIAL, integer(123456)),
                                   rdn(CN, utf8('serial as integer'))), ['CBSD']))
    # 3 ZONE value as a constructed UTF8String
    c.append(certificate(103, name(rdn(ZONE, tlv(0x2c, utf8('PAL') + utf8('-ZONE'))),
                                   rdn(CN, utf8('constructed'))), ['PAL']))
    # 3 is valid BER (DER requires a primitive string) and decodes without
    #   an error.
    # 4 FRN extension with an empty extnValue, 5 TEST extension with a
    #   length past the end of the extnValue
    c.append(certificate(104, name(rdn(CN, utf8('empty extension'))), ['SAS'],
                         [ext(FRN, b'')]))
    c.append(certificate(105, name(rdn(CN, utf8('long extension'))), ['SAS'],
                         [ext(TEST, b'\x0c\x20short')]))
    # 6 a certificate cut short inside the CPIRID attribute value
    full = certificate(106, name(rdn(CPIRID, utf8('CPIR-CUT-SHORT-0001')),
                                 rdn(CN, utf8('cut'))), ['INSTALLER'])
    i = full.find(b'CPIR-CUT')
    c.append(full[:i + 4])
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cbrs-oids-coverage.pcap'), main_certs())
    write_pcap(os.path.join(out, 'cbrs-oids-coverage-malformed.pcap'), malformed_certs())


if __name__ == '__main__':
    main()
