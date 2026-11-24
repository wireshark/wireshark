#!/usr/bin/env python3
# Generates test/captures/tcg_cp_oids_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the tcg-cp-oids coverage captures.  Usage: mktcg_cp_oids.py <outdir>
X.509 certificates with the TCG attributes and extensions are carried in
TLS Certificate messages (TCP port 443).  The certificates are synthetic:
the key and the signature are filler octets, not real cryptographic
values.  All packets are synthetic."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from berlib import (
    bitstr, boolean, gz, ia5, integer, null, octets, oid, seq, TcpStream, tlv, utf8, write_pcap,
)

SHA256 = seq(oid('2.16.840.1.101.3.4.2.1'), null())
RSA = seq(oid('1.2.840.113549.1.1.1'), null())
SHA256RSA = seq(oid('1.2.840.113549.1.1.11'), null())

def name(cn):
    return seq(seq(tlv(0x31, seq(oid('2.5.4.6'), tlv(0x13, b'XX')))),
               seq(tlv(0x31, seq(oid('2.5.4.3'), utf8(cn)))))

def name_rdn(cn):
    return seq(tlv(0x31, seq(oid('2.5.4.6'), tlv(0x13, b'XX'))),
               tlv(0x31, seq(oid('2.5.4.3'), utf8(cn))))

def attr(o, *vals):
    return seq(oid(o), tlv(0x31, b''.join(vals)))

def ext(o, value, critical=False):
    return seq(oid(o), *( [boolean(True)] if critical else []), octets(value))

def cert(cn, attrs=(), exts=(), serial=1):
    """A syntactically valid certificate; key and signature are filler."""
    allext = list(exts)
    if attrs:
        allext.insert(0, ext('2.5.29.9', seq(*attrs)))
    tbs = seq(
        tlv(0xa0, integer(2)),
        integer(serial),
        SHA256RSA,
        name_rdn('Test CA'),
        seq(tlv(0x17, b'250101000000Z'), tlv(0x17, b'350101000000Z')),
        name_rdn(cn),
        seq(RSA, bitstr(seq(integer(int.from_bytes(bytes(range(1, 65)), 'big')), integer(65537)))),
        tlv(0xa3, seq(*allext)) if allext else b'')
    return seq(tbs, SHA256RSA, bitstr(bytes((i * 7) & 0xff for i in range(64))))

# --- TCG structures ---
def tpm_spec(family='2.0', level=0, rev=164):
    return seq(utf8(family), integer(level), integer(rev))

def tcg_platform(maj=1, minr=0, rev=43, cls=b'\0\0\0\1'):
    return seq(seq(integer(maj), integer(minr), integer(rev)), octets(cls))

def uri_ref(uri, alg=True, hashv=True):
    b = ia5(uri)
    if alg: b += SHA256
    if hashv: b += bitstr(bytes(range(32)))
    return b

def cc_info(ver='3.1', eal=4, status=2, plus=None, sof=None, poid=None, puri=None, toid=None, turi=None):
    b = ia5(ver) + tlv(0x0a, bytes([eal])) + tlv(0x0a, bytes([status]))
    if plus is not None: b += boolean(plus)
    if sof is not None: b += tlv(0x80, bytes([sof]))
    if poid: b += oid(poid, tag=0x81)
    if puri: b += seq(uri_ref(*puri), tag=0xa2)
    if toid: b += oid(toid, tag=0x83)
    if turi: b += seq(uri_ref(*turi), tag=0xa4)
    return b

def fips(ver='140-2', level=2, plus=None):
    b = ia5(ver) + tlv(0x0a, bytes([level]))
    if plus is not None: b += boolean(plus)
    return b

def tpm_assert(version=None, upg=None, ekt=None, ekl=None, ekc=None, cc=None, fi=None, iso=None, uri=None):
    b = b''
    if version is not None: b += integer(version)
    if upg is not None: b += boolean(upg)
    if ekt is not None: b += tlv(0x80, bytes([ekt]))
    if ekl is not None: b += tlv(0x81, bytes([ekl]))
    if ekc is not None: b += tlv(0x82, bytes([ekc]))
    if cc is not None: b += tlv(0xa3, cc)
    if fi is not None: b += tlv(0xa4, fi)
    if iso is not None: b += boolean(iso, tag=0x85)
    if uri is not None: b += ia5(uri)
    return seq(b)

def tbb_assert(version=None, cc=None, fi=None, rtm=None, iso=None, uri=None):
    b = b''
    if version is not None: b += integer(version)
    if cc is not None: b += tlv(0xa0, cc)
    if fi is not None: b += tlv(0xa1, fi)
    if rtm is not None: b += tlv(0x82, bytes([rtm]))
    if iso is not None: b += boolean(iso)
    if uri is not None: b += ia5(uri)
    return seq(b)

def subj_info(uri, access=None, hashinfo=True):
    b = ia5(uri)
    if access: b += oid(access)
    if hashinfo: b += seq(SHA256, octets(bytes(range(32))))
    return seq(b)

def tls_conn(sport, certs, f, split=False):
    s = TcpStream(sport, 443)
    f.extend(s.handshake())
    rnd = bytes(range(32))
    ch = struct.pack('!H', 0x0303) + rnd + b'\0' + struct.pack('!HH', 2, 0xc02f) + b'\x01\0'
    ch = b'\x01' + struct.pack('!I', len(ch))[1:] + ch
    def rec(v, d): return b'\x16' + struct.pack('!H', v) + struct.pack('!H', len(d)) + d
    if split:   # the ClientHello over two records
        f.append(s.c2s(rec(0x0301, ch[:20]) + rec(0x0301, ch[20:])))
    else:
        f.append(s.c2s(rec(0x0301, ch)))
    sh = struct.pack('!H', 0x0303) + rnd + b'\0' + struct.pack('!H', 0xc02f) + b'\0'
    sh = b'\x02' + struct.pack('!I', len(sh))[1:] + sh
    cl = b''.join(struct.pack('!I', len(c))[1:] + c for c in certs)
    cm = struct.pack('!I', len(cl))[1:] + cl
    cm = b'\x0b' + struct.pack('!I', len(cm))[1:] + cm
    shd = b'\x0e\0\0\0'
    msgs = sh + cm + shd
    if split:   # the handshake messages over several records and TCP segments
        cuts = [0, 10, 300, len(msgs) - 3, len(msgs)]
        chunks = [rec(0x0303, msgs[a:b]) for a, b in zip(cuts, cuts[1:])]
        f.append(s.s2c(chunks[0]))
        f.append(s.s2c(chunks[1] + chunks[2][:7]))
        f.append(s.s2c(chunks[2][7:] + chunks[3]))
    else:
        f.append(s.s2c(rec(0x0303, msgs)))
    f.append(s.c2s(b'', 0x10))

def main(out):
    f = []
    # 1: an EK certificate with every TCG attribute and every optional field
    ek = cert('Test EK', attrs=[
        attr('2.23.133.2.16', tpm_spec()),
        attr('2.23.133.2.17', tcg_platform()),
        attr('2.23.133.2.18', tpm_assert(1, True, 3, 1, 2,
             cc_info('3.1', 7, 2, True, 2, '1.3.6.1.4.1.99999.1', ('http://example.invalid/pp', True, True),
                     '1.3.6.1.4.1.99999.2', ('http://example.invalid/st', False, False)),
             fips('140-2', 3, True), True, 'http://example.invalid/iso')),
        attr('2.23.133.2.19', tbb_assert(1, cc_info('2.2', 1, 0), fips('140-1', 1), 5, True, 'http://example.invalid/iso2')),
        attr('2.23.133.2.11', oid('1.3.6.1.4.1.99999.3')),
        attr('2.23.133.2.12', oid('1.3.6.1.4.1.99999.4')),
        attr('2.23.133.2.13', oid('1.3.6.1.4.1.99999.5')),
        attr('2.23.133.2.14', oid('1.3.6.1.4.1.99999.6')),
        attr('2.23.133.1', seq(integer(1), integer(2))),
    ], serial=2)
    # 2: only defaults and the first value of every enumeration
    plain = cert('Test Plain', attrs=[
        attr('2.23.133.2.16', tpm_spec('1.2', 2, 116)),
        attr('2.23.133.2.18', tpm_assert()),
        attr('2.23.133.2.19', tbb_assert()),
        attr('2.23.133.2.17', tcg_platform(2, 1, 1, b'\xde\xad\xbe\xef')),
    ], serial=3)
    # 3: assertions with the other enumeration values
    enums = []
    for i in range(4):
        enums.append(attr('2.23.133.2.18', tpm_assert(0, False, i, i % 3, (i + 1) % 3, None,
                                                       fips('140-2', i + 1), False)))
    for i in range(6):
        enums.append(attr('2.23.133.2.19', tbb_assert(0, cc_info('3.1', i + 1, i % 3, False, i % 3), fips('140-2', 4, False), i, False)))
    ecert = cert('Test Enums', attrs=enums, serial=4)
    # 4: the TCG certificate extensions (platform certificate style)
    creds = seq(subj_info('http://example.invalid/ek.crt', '1.3.6.1.5.5.7.48.1', True),
                subj_info('http://example.invalid/cred2.crt', None, False),
                subj_info('http://example.invalid/cred3.crt', '1.3.6.1.5.5.7.48.2', False))
    mans = seq(subj_info('http://example.invalid/manifest', None, True))
    pcert = cert('Test Platform', exts=[
        ext('2.23.133.6.2', creds),
        ext('2.23.133.6.3', mans),
        ext('2.23.133.6.4', ia5('https://example.invalid/attest')),
        ext('2.23.133.6.5', ia5('https://example.invalid/migrate-attest')),
        ext('2.23.133.6.6', ia5('https://example.invalid/migrate-reg')),
        ext('2.23.133.6.7', seq(boolean(True), ia5('https://example.invalid/backup'))),
        ext('2.5.29.19', seq(boolean(True))),
    ], serial=5)
    pcert2 = cert('Test Platform 2', exts=[
        ext('2.23.133.6.7', seq(ia5('https://example.invalid/backup2'))),
        ext('2.23.133.6.2', seq()),
    ], serial=6)
    # one certificate without extensions
    bare = cert('Test Bare', serial=7)
    tls_conn(40001, [ek], f)
    tls_conn(40002, [plain, bare], f, split=True)
    tls_conn(40003, [ecert, pcert, pcert2], f)
    write_pcap(os.path.join(out, 'tcg-cp-oids-coverage.pcap'), f, t0=1750000000.0)
    gz(os.path.join(out, 'tcg-cp-oids-coverage.pcap'), os.path.join(out, 'tcg_cp_oids_coverage.pcap.gz'))

    # malformed
    m = []
    def bad(sport, certs):
        tls_conn(sport, certs, m)
    # wrong types inside the TCG values
    bad(40101, [cert('Bad 1', attrs=[
        attr('2.23.133.2.16', seq(integer(1), integer(2))),            # family is not a string
        attr('2.23.133.2.17', seq(octets(b'x'))),
        attr('2.23.133.2.18', seq(boolean(True), boolean(True), tlv(0x80, b'\x09'), tlv(0xa3, b''))),
        attr('2.23.133.2.19', seq(tlv(0xa0, seq(integer(3))), tlv(0xa1, b'\x01'))),
        attr('2.23.133.2.11', integer(1)),
        attr('2.23.133.1', seq(integer(1))),
    ])])
    bad(40102, [cert('Bad 2', exts=[
        ext('2.23.133.6.2', seq(seq())),
        ext('2.23.133.6.3', integer(5)),
        ext('2.23.133.6.4', integer(5)),
        ext('2.23.133.6.7', ia5('x')),
    ])])
    # truncated extension values
    bad(40103, [cert('Bad 3', exts=[
        ext('2.23.133.6.2', seq(subj_info('http://x', '1.2.3', True))[:12]),
        ext('2.23.133.6.7', b'\x30\x84\xff\xff\xff\xff'),
    ], attrs=[attr('2.23.133.2.18', tpm_assert(1, True, 1, 1, 1, cc_info('3.1', 1, 1, True, 1, '1.2.3', ('u', True, True)))[:20])])])
    write_pcap(os.path.join(out, 'tcg-cp-oids-coverage-malformed.pcap'), m, t0=1750000000.0)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
