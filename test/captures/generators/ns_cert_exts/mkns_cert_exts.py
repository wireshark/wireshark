#!/usr/bin/env python3
# Generates test/captures/ns_cert_exts_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Netscape certificate extension coverage captures.

Usage: mkns_cert_exts.py <outdir>
Exported PDU "pkix-cert" frames with DER certificates (placeholder key and
signature bytes, no crypto) carrying the Netscape extensions."""
import struct
import sys


# ------------------------------------------------------------ DER helpers
def tlv(tag, content=b''):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    elif n < 0x10000:
        ln = bytes([0x82]) + struct.pack('>H', n)
    else:
        ln = bytes([0x83]) + n.to_bytes(3, 'big')
    return bytes([tag]) + ln + content


def seq(*parts):
    return tlv(0x30, b''.join(parts))


def sset(*parts):
    return tlv(0x31, b''.join(parts))


def ctx(n, content, constructed=True):
    return tlv((0xa0 if constructed else 0x80) | n, content)


def oid(dotted):
    p = [int(x) for x in dotted.split('.')]
    out = bytearray([40 * p[0] + p[1]])
    for v in p[2:]:
        chunk = [v & 0x7f]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def integer(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(0x02, v.to_bytes(n, 'big', signed=True))


def boolean(v):
    return tlv(0x01, b'\xff' if v else b'\x00')


def octets(b):
    return tlv(0x04, b)


def bitstr(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


def ia5(s):
    return tlv(0x16, s.encode())


def utf8(s):
    return tlv(0x0c, s.encode())


def printable(s):
    return tlv(0x13, s.encode())


def gtime(s):
    return tlv(0x18, s.encode())


def null():
    return tlv(0x05)


SHA256_RSA = '1.2.840.113549.1.1.11'
SHA1 = '1.3.14.3.2.26'


def algid(o, params=True):
    return seq(oid(o), null()) if params else seq(oid(o))


def name(cn):
    return seq(sset(seq(oid('2.5.4.3'), utf8(cn))))


def extension(o, value, critical=False):
    return seq(oid(o), *( [boolean(True)] if critical else [] ), octets(value))


def certificate(exts, cn='Synthetic Test CA', serial=0x1234):
    """X.509 v3 certificate with placeholder key and signature bytes."""
    tbs = seq(ctx(0, integer(2)), integer(serial), algid(SHA256_RSA), name(cn),
              seq(tlv(0x17, b'200101000000Z'), tlv(0x17, b'400101000000Z')),
              name('Subject ' + cn),
              seq(algid('1.2.840.113549.1.1.1'), bitstr(seq(integer(0xc5a3 << 112 | 0x1b), integer(65537)))),
              ctx(3, seq(*exts)))
    return seq(tbs, algid(SHA256_RSA), bitstr(b'\x00' * 16))


def exp_pdu(name_, payload):
    n = name_.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + \
        struct.pack('>HH', 0, 0) + payload


def pcap(path, frames, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

NS = '2.16.840.1.113730.1.'


def ns_exts(certtype=b'\xa0', unused=5):
    return [
        extension(NS + '1', bitstr(certtype, unused)),
        extension(NS + '2', ia5('https://base.example.test/')),
        extension(NS + '3', ia5('https://ca.example.test/revoke?')),
        extension(NS + '4', ia5('https://ca.example.test/ca-revoke?')),
        extension(NS + '7', ia5('https://ca.example.test/renew?')),
        extension(NS + '8', ia5('https://ca.example.test/policy.html')),
        extension(NS + '12', ia5('www.example.test')),
        extension(NS + '13', ia5('Synthetic certificate, test only')),
    ]


def main(out):
    ok = []
    # Netscape extensions in an X.509 certificate (pkix-cert)
    ok.append(exp_pdu('pkix-cert', certificate(ns_exts())))
    # every cert-type bit
    ok.append(exp_pdu('pkix-cert', certificate(
        [extension(NS + '1', bitstr(b'\xff', 0))], 'All Types')))
    ok.append(exp_pdu('pkix-cert', certificate(
        [extension(NS + '1', bitstr(b'\x00', 0)), extension(NS + '13', ia5(''))], 'No Types')))
    # critical extension, single extension, long strings
    ok.append(exp_pdu('pkix-cert', certificate(
        [extension(NS + '12', ia5('*.' + 'a' * 200 + '.example.test'), True)], 'Wildcard')))
    # a certificate list inside a CMS-free container: second certificate
    ok.append(exp_pdu('pkix-cert', certificate(ns_exts(b'\x06', 1), 'CA', 77)))
    mal = [
        exp_pdu('pkix-cert', certificate([extension(NS + '1', octets(b'\x00'))])),   # wrong type for CertType
        exp_pdu('pkix-cert', certificate([extension(NS + '2', bitstr(b'\x00'))])),   # wrong type for BaseUrl
        exp_pdu('pkix-cert', certificate([extension(NS + '13', b'\x16\x05ab')])),    # truncated string
        exp_pdu('pkix-cert', certificate([extension(NS + '1', b'')])),               # empty value
        exp_pdu('pkix-cert', certificate([extension(NS + '1', bitstr(b'', 0))])),    # empty bit string
    ]
    pcap(out + '/ns_cert_exts-coverage.pcap', ok)
    pcap(out + '/ns_cert_exts-coverage-malformed.pcap', mal)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
