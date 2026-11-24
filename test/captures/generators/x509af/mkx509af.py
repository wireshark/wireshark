#!/usr/bin/env python3
# Generates test/captures/x509af_coverage.pcap.gz, x509af_coverage.pem
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-x509af.c (X.509 Authentication Framework).
# usage: mkx509af.py <outdir>
# Writes x509af-coverage.pcap (valid data), x509af-coverage-malformed.pcap
# and x509af-coverage.pem (RFC 7468 text file: PUBLIC KEY, ATTRIBUTE CERTIFICATE).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from x509lib import (
    algid, bits, bitstr, boolean, Cap, certificate, cms_certs, crl, ctx, ctxp, enum, extension,
    gentime, gn_dir, gn_dns, gn_email, gn_ip, gns, integer, name, null, octets, oid, pem,
    printable, rdn, rdn_multi, revoked, seq, setof, SIG, spki_dh, spki_dsa, spki_ec, spki_rsa,
    std_name, tlv, utctime, utf8, validity,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
os.makedirs(out, exist_ok=True)

def implicit(n, der):
    """replace the tag of a constructed DER value by [n] IMPLICIT"""
    return bytes([0xa0 | n]) + der[1:]

CA = std_name('Example CA', ou='Certification')
SUBJ = std_name('www.example.com')

bc = extension('2.5.29.19', seq(boolean(True), integer(2)), True)
ku = extension('2.5.29.15', bits(0b100101, 9), True)
eku = extension('2.5.29.37', seq(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.2')))
san = extension('2.5.29.17', gns(gn_dns('www.example.com'), gn_dns('example.com'),
                                 gn_ip(bytes([192, 0, 2, 7]))))
ski = extension('2.5.29.14', octets(bytes(range(20))))
aki = extension('2.5.29.35', seq(ctxp(0, bytes(range(20)))))
unknown_ext = extension('1.3.6.1.4.1.32473.1.1', octets(b'opaque'), False)
empty_ext = extension('1.3.6.1.4.1.32473.1.2', b'')

# ---------------------------------------------------------------- Capture
cap = Cap()

# 1-4: TLS Certificate messages, a three certificate chain, v3 RSA
leaf = certificate(SUBJ, CA, [bc, ku, eku, san, ski, aki, unknown_ext], serial=0x1234567890)
inter = certificate(CA, std_name('Example Root'), [bc, ku, ski], serial=2)
root = certificate(std_name('Example Root'), std_name('Example Root'), [bc, ku], serial=3)
cap.tls_certs([leaf, inter, root])

# v1 certificate (no version, no extensions), GeneralizedTime validity
v1 = certificate(std_name('v1.example.com'), CA, version=None, serial=7,
                 valid=validity('20230101000000Z', '20330101000000Z', gen=True))
# v2 certificate with unique identifiers
v2 = certificate(std_name('v2.example.com'), CA, version=1, serial=8,
                 uid_issuer=b'\xa5\x5a', uid_subject=b'\x5a\xa5\x5a')
cap.tls_certs([v1, v2], dport=50010)

# Other public key / signature algorithm identifiers
dsa = certificate(std_name('dsa.example.com'), CA, [ski], spki=spki_dsa(), serial=9,
                  sigalg=algid('1.2.840.10040.4.3', None))
dh = certificate(std_name('dh.example.com'), CA, spki=spki_dh(), serial=10,
                 sigalg=algid('1.3.14.3.2.29', b'\x05\x00'))
ec = certificate(std_name('ec.example.com'), CA, spki=spki_ec(), serial=11,
                 sigalg=algid('1.2.840.10045.4.3.2', None))
oiw = [certificate(std_name('oiw%d.example.com' % i), CA, serial=20 + i, sigalg=algid('1.3.14.3.2.%d' % i, b'\x05\x00'))
       for i in (2, 3, 4, 6, 11, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28)]
cap.tls_certs([dsa, dh, ec])
cap.tls_certs(oiw[:10], dport=4433)
cap.tls_certs(oiw[10:], dport=4434)

# Algorithm with explicit parameter OID, unknown algorithm with parameters
weird = certificate(std_name('weird.example.com'), CA, serial=12,
                    sigalg=algid('1.3.6.1.4.1.32473.2.1', seq(integer(1), octets(b'x'))),
                    spki=seq(algid('1.3.6.1.4.1.32473.2.2', None), bitstr(b'\x01\x02\x03')))
cap.tls_certs([weird], dport=4435)

# Validity quirks: notBefore after notAfter, and a certificate that is not
# yet valid at the frame time (expert warnings, not errors)
cap.tls_certs([certificate(std_name('backwards.example.com'), CA, serial=13,
                           valid=validity('330101000000Z', '230101000000Z'))], dport=4436)
cap.tls_certs([certificate(std_name('future.example.com'), CA, serial=14,
                           valid=validity('300101000000Z', '350101000000Z'))], dport=4437)
# UTCTime years below and above 50, GeneralizedTime notBefore only
cap.tls_certs([certificate(std_name('years.example.com'), CA, serial=15,
                           valid=seq(utctime('990101000000Z'), gentime('20500101000000Z')))], dport=4438)
# a certificate with a critical unknown extension and an empty extension
cap.tls_certs([certificate(std_name('ext.example.com'), CA, [unknown_ext,
               extension('2.5.29.19', seq(), True),
               extension('2.5.29.70', seq(CA, integer(5)))], serial=16)], dport=4439)

# Subject name for Export Objects (commonName = hostname); reproducer for
# "X509AF: Copy the subject name for export objects": a later bare RDN
# (CRLDistributionPoints nameRelativeToCRLIssuer) in the same certificate
rdn_impl = ctx(1, seq(oid('2.5.4.3'), utf8('crl.example.org' * 4)))
crldp = seq(seq(ctx(0, rdn_impl)))
cap.tls_certs([certificate(std_name('eo.example.com'), CA, [extension('2.5.29.31', crldp)], serial=17)],
              dport=4440)

# ----------------------------------------------------------- CRLs
rev_exts = [extension('2.5.29.21', enum(1)),
            extension('2.5.29.24', gentime('20230401000000Z')),
            extension('2.5.29.29', gns(gn_dir(CA)), True)]
crl_exts = [extension('2.5.29.20', integer(12)), extension('2.5.29.35', seq(ctxp(0, bytes(range(20)))))]
crl_v2 = crl(CA, 1, [revoked(1001, exts=rev_exts), revoked(1002), revoked(1003, gen=True, date='20230502000000Z')],
             crl_exts, next_='230701000000Z')
crl_v1 = crl(CA, None, None)
crl_empty = crl(CA, 1, [], None, next_='230701000000Z', gen=True, this='20230601000000Z')
cap.http_resp('application/pkix-crl', crl_v2)
cap.http_resp('application/pkix-crl', crl_v1, sport=8080)
cap.http_resp('application/pkix-crl', crl_empty, sport=8081)
delta = crl(CA, 1, [revoked(1004, exts=[extension('2.5.29.21', enum(6)), extension('2.5.29.23', oid('1.2.840.10040.2.1'))])],
            [extension('2.5.29.27', integer(11)), extension('2.5.29.20', integer(13))])
cap.http_resp('application/pkix-crl', delta, sport=8082)

# ---------------------------------------------------------- LDAP
cap.ldap_entry('cn=Example CA,o=Example', [('cACertificate;binary', [root, inter])], msgid=3)
cap.ldap_entry('cn=User,o=Example', [('userCertificate;binary', [leaf])], msgid=4)
cap.ldap_entry('cn=Example CA,o=Example', [('certificateRevocationList;binary', [crl_v2]),
                                           ('authorityRevocationList;binary', [crl_v1]),
                                           ('crl;binary', [delta]), ('arl;binary', [crl_empty])], msgid=5)
pair = seq(ctx(0, inter), ctx(1, root))
cap.ldap_entry('cn=Pair,o=Example', [('crossCertificatePair;binary', [pair])], msgid=6)
cap.ldap_entry('cn=Pair2,o=Example', [('crossCertificatePair;binary', [seq(ctx(0, inter))]),
                                      ('crossCertificatePair;binary', [seq(ctx(1, root))])], msgid=7)

# ------------------------------------------- CMS (PKCS#7) certs-only
alg = algid('1.2.840.113549.1.1.11')
attr_c = seq(oid('2.5.4.3'), setof(utf8('Operator'), printable('Ops')))
attr_o = seq(oid('2.5.4.10'), setof(utf8('Example Org')))
holder_ser = seq(gns(gn_dir(CA)), integer(0x1234567890), bitstr(b'\x01'))
def attr_cert(subject, attrs, exts=None, serial=77, uid=None, version=1):
    info = [integer(version), subject, gns(gn_dir(CA)), alg, integer(serial),
            seq(gentime('20230101000000Z'), gentime('20330101000000Z')), seq(*attrs)]
    if uid is not None:
        info.append(bitstr(uid))
    if exts:
        info.append(seq(*exts))
    return seq(seq(*info), alg, SIG)
ac1 = attr_cert(ctx(0, holder_ser), [attr_c, attr_o], [aki], uid=b'\x5a')
ac2 = attr_cert(ctx(1, gns(gn_dir(SUBJ), gn_email('user@example.com'))), [attr_c], None, serial=78)
ac3 = attr_cert(ctx(0, seq(gns(gn_dns('ca.example.com')), integer(5))), [attr_o], None, serial=79, version=1)
cap.http_resp('application/pkcs7-mime',
              cms_certs([leaf, implicit(2, ac1), implicit(2, ac2), implicit(2, ac3)], [crl_v2, crl_v1]), sport=8083)

# Certification paths with the ACPathData structures are not part of any
# registered dissector; AttributeCertificateAssertion likewise.

# ------------------------------------------------------ Userid, DSS params
ava_userid = rdn_multi(('0.9.2342.19200300.100.1.1', utf8('jdoe')), ('2.5.4.3', utf8('John Doe')))
cap.tls_certs([certificate(name(rdn('2.5.4.6', 'XX', printable), ava_userid, rdn('2.5.4.3', 'x')), CA, serial=18)],
              dport=4441)

# CMS SignedData with content, a SHA-256 digest algorithm and a messageDigest
# signed attribute: the CMS dissector asks x509af for the last algorithm OID
# (hashing only, the signature is filler)
import hashlib
content = b'synthetic signed content'
sha = algid('2.16.840.1.101.3.4.2.1', None)
sattrs = [seq(oid('1.2.840.113549.1.9.3'), setof(oid('1.2.840.113549.1.7.1'))),
          seq(oid('1.2.840.113549.1.9.4'), setof(octets(hashlib.sha256(content).digest()))),
          seq(oid('1.2.840.113549.1.9.5'), setof(utctime('230601120000Z')))]
signer = seq(integer(1), seq(CA, integer(0x1234567890)), sha, ctx(0, *sattrs),
             algid('1.2.840.113549.1.1.11'), octets(b'\x22' * 32))
signed = seq(oid('1.2.840.113549.1.7.2'), ctx(0, seq(
    integer(1), setof(sha), seq(oid('1.2.840.113549.1.7.1'), ctx(0, octets(content))),
    tlv(0xa0, leaf), setof(signer))))
cap.http_resp('application/pkcs7-signature', signed, sport=8084)

cap.write(os.path.join(out, 'x509af-coverage.pcap'))

# --------------------------------------------------------- malformed
mal = Cap(1700100000)
good = certificate(SUBJ, CA, [bc, ku, san], serial=100)
# Truncated certificate (length covers more than present)
mal.tls_certs([good[:len(good) // 2]], dport=4501)
# Wrong tags: SEQUENCE replaced by SET inside the certificate
bad = bytearray(good); bad[4] = 0x31
mal.tls_certs([bytes(bad)], dport=4502)
# Truncated CRL
mal.http_resp('application/pkix-crl', crl_v2[:len(crl_v2) - 40], sport=8091)
mal.http_resp('application/pkix-crl', b'\x30\x84\xff\xff\xff\xff' + b'\x00' * 8, sport=8092)
# Invalid UTCTime value, bad Time type tag
mal.tls_certs([certificate(SUBJ, CA, serial=101, valid=seq(utctime('notatime'), utctime('330101000000Z')))], dport=4503)
mal.tls_certs([certificate(SUBJ, CA, serial=102, valid=seq(tlv(0x13, b'230101000000Z'), tlv(0x13, b'330101000000Z')))], dport=4504)
# SubjectPublicKeyInfo with an RSA key that is not an RSAPublicKey; DSA key not an INTEGER
mal.tls_certs([certificate(SUBJ, CA, serial=103, spki=seq(algid('1.2.840.113549.1.1.1'), bitstr(b'\x01\x02')))], dport=4505)
mal.tls_certs([certificate(SUBJ, CA, serial=104, spki=seq(seq(oid('1.2.840.10040.4.1'), null()), bitstr(b'\x01\x02')))], dport=4506)
# Extension with an empty extnValue and a value with a wrong tag
mal.tls_certs([certificate(SUBJ, CA, [seq(oid('2.5.29.19'), octets(b''))], serial=105)], dport=4507)
mal.tls_certs([certificate(SUBJ, CA, [seq(oid('2.5.29.15'), octets(b'\x04\x02\x01\x02'))], serial=106)], dport=4508)
# Attribute certificate / CMS with a damaged v2AttrCert
mal.http_resp('application/pkcs7-mime', cms_certs([implicit(2, ac1)[:-30]]), sport=8093)
mal.ldap_entry('cn=Pair,o=Example', [('crossCertificatePair;binary', [pair[:50]])], msgid=9)
mal.write(os.path.join(out, 'x509af-coverage-malformed.pcap'))

# --------------------------------------------------------- PEM file
with open(os.path.join(out, 'x509af-coverage.pem'), 'w') as f:
    f.write(pem('PUBLIC KEY', spki_rsa()))
    f.write(pem('PUBLIC KEY', spki_dsa()))
    f.write(pem('PUBLIC KEY', spki_dh()))
    f.write(pem('ATTRIBUTE CERTIFICATE', ac1))
    f.write(pem('ATTRIBUTE CERTIFICATE', ac2))
    f.write(pem('X509 CRL', crl_v2))
    f.write(pem('CERTIFICATE', leaf))
