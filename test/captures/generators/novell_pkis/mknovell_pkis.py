#!/usr/bin/env python3
# Generates test/captures/novell_pkis_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Novell PKIS certificate extension coverage captures.

Usage: mknovell_pkis.py <outdir>
Exported PDU "pkix-cert" frames with DER certificates (placeholder key and
signature bytes, no crypto) carrying the Novell security attribute and
reliance limit extensions."""
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

PA = '2.16.840.1.113719.1.9.4.'


def quality(enforce=True, comp=((1, 2),), crypto=((3, 4),), storage=5, tag=None):
    parts = [boolean(enforce),
             seq(*[seq(integer(a), integer(b)) for a, b in comp]),
             seq(*[seq(integer(a), integer(b)) for a, b in crypto]),
             integer(storage)]
    return tlv(tag, b''.join(parts)) if tag else seq(*parts)


def label(singles=(7,), isingles=(9,), tag=None, cats=b'\x01' * 12, icats=b'\x02' * 8):
    def single(x):
        if isinstance(x, tuple):
            return seq(integer(x[0]), integer(x[1]), boolean(x[2]))
        return integer(x)
    parts = [integer(1), integer(2), integer(3), bitstr(cats), bitstr(icats),
             seq(*[single(x) for x in singles]), seq(*[single(x) for x in isingles])]
    return tlv(tag, b''.join(parts)) if tag else seq(*parts)


def security_attributes(version=b'\x00\x01', nsi=True, tm='Novell Security Attribute(tm)',
                        uri='http://www.example.test/pa', singles=(7,)):
    glb = seq(
        quality(tag=0xa0),
        quality(False, ((200, 255), ), ((0, 0), ), 255, tag=0xa1),
        tlv(0xa2, integer(3) + boolean(True)),
        tlv(0xa3, label(singles, (11, (1, 100, False)), tag=0xa0) +
            label((1,), (2,), tag=0xa1) +
            tlv(0xa2, label((2 ** 62, (0, 2 ** 63 - 1, True)), (5,)))))
    return seq(octets(version), boolean(nsi), printable(tm), ia5(uri), glb)


def reliance(cur=(840, 1000, 2), cur2=(978, 25000, 0)):
    mv = lambda c: seq(integer(c[0]), integer(c[1]), integer(c[2]))
    return seq(mv(cur), mv(cur2))


def main(out):
    ok = []
    ok.append(exp_pdu('pkix-cert', certificate([
        extension(PA + '1', security_attributes()),
        extension(PA + '2', reliance())], 'Novell CA')))
    ok.append(exp_pdu('pkix-cert', certificate([
        extension(PA + '1', security_attributes(singles=(0, 1, 2, 3, (5, 9, True)))),
        ], 'Novell Singletons')))
    ok.append(exp_pdu('pkix-cert', certificate([
        extension(PA + '2', reliance((1, -5, -3), (999, 2 ** 40, 12)), True)], 'Novell Limits')))
    mal = [
        exp_pdu('pkix-cert', certificate([extension(PA + '1', seq(octets(b'\x00')))])),          # truncated
        exp_pdu('pkix-cert', certificate([extension(PA + '1', security_attributes(version=b'\x01'))])),
        exp_pdu('pkix-cert', certificate([extension(PA + '1', security_attributes(nsi=False))])),
        exp_pdu('pkix-cert', certificate([extension(PA + '1', security_attributes(tm='Other'))])),
        exp_pdu('pkix-cert', certificate([extension(PA + '2', seq(seq(integer(0), integer(1), integer(2))))])),
        exp_pdu('pkix-cert', certificate([extension(PA + '2', reliance((1000, 1, 1)))])),         # currency out of range
        exp_pdu('pkix-cert', certificate([extension(PA + '1', integer(5))])),
    ]
    pcap(out + '/novell_pkis-coverage.pcap', ok)
    pcap(out + '/novell_pkis-coverage-malformed.pcap', mal)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
