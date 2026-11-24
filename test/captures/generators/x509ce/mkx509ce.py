#!/usr/bin/env python3
# Generates test/captures/x509ce_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-x509ce.c (X.509 Certificate Extensions).
# usage: mkx509ce.py <outdir>
# Writes x509ce-coverage.pcapng (valid data, Ethernet and DVB-CI interfaces) and x509ce-coverage-malformed.pcap.
# The extensions travel in certificates (TLS Certificate, TCP 443) and in a
# CRL over HTTP; the matching rule assertions are carried as values of the
# 2.5.13.x OIDs in extensions of a certificate.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from x509lib import (
    algid, bits, bitstr, bmp, boolean, Cap, certificate, crl, ctx, ctxp, enum, extension, general,
    gentime, gn_dir, gn_dns, gn_edi, gn_email, gn_ip, gn_other, gn_rid, gn_uri, gn_x400, gns, ia5,
    inner, integer, name, octets, oid, oid_content, printable, rdn, revoked, seq, setof, std_name,
    tlv, utctime, utf8, validity,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
os.makedirs(out, exist_ok=True)

CA = std_name('Example CA')
SUBJ = std_name('www.example.com')
DN_A = name(rdn('2.5.4.6', 'XX', printable), rdn('2.5.4.10', 'Example Org'), rdn('2.5.4.3', 'Entry A'))
GT = '20230601120000Z'

def int_i(n, v):            # [n] IMPLICIT INTEGER
    c = integer(v)[2:]
    return ctxp(n, c)
def gt_i(n, s=GT):          # [n] IMPLICIT GeneralizedTime
    return ctxp(n, s.encode())
def oid_i(n, o):
    return ctxp(n, oid_content(o))
def ks(*oids):
    return seq(*[oid(o) for o in oids])

ALL_GN = [
    gn_other('1.3.6.1.4.1.311.20.2.3', utf8('user@example.com')),        # id-ms-san-upn
    gn_other('1.3.6.1.4.1.32473.9', octets(b'x')),
    gn_email('user@example.com'),
    gn_dns('www.example.com'),
    gn_x400(seq(tlv(0x61, printable('AU')), tlv(0x42, printable('ADMD')))),
    gn_dir(DN_A),
    gn_edi(utf8('Assigner'), printable('Party')),
    gn_edi(None, bmp('Party')),
    gn_uri('http://www.example.com/'),
    gn_ip(bytes([192, 0, 2, 1])),
    gn_ip(bytes([192, 0, 2, 0, 255, 255, 255, 0])),
    gn_ip(bytes(range(16))),
    gn_ip(bytes(range(16)) + bytes([255] * 8 + [0] * 8)),
    gn_ip(b'\x01\x02\x03'),
    gn_rid('1.3.6.1.4.1.32473.1'),
]
GN1 = gns(gn_dns('crl.example.com'), gn_uri('http://crl.example.com/ca.crl'))
GN_ONE = gn_uri('http://one.example.com/')
DPN_FULL = ctx(0, gn_uri('http://crl.example.com/ca.crl'), gn_dns('crl.example.com'))
DPN_REL = ctx(1, seq(oid('2.5.4.3'), utf8('crl')))

def reasons(v):
    return ctxp(1, bits(v, 10)[2:])
def reason_i(n, v):
    return ctxp(n, bits(v, 10)[2:])

aki_full = seq(ctxp(0, bytes(range(20))), ctx(1, gn_dir(DN_A)), int_i(2, 0x1234567890))
ski = octets(bytes(range(20)))

cap = Cap()
_port = [50200]
def tls(certs):
    _port[0] += 1
    cap.tls_certs(certs, dport=_port[0])

def cert(exts, serial=1, subject=None):
    return certificate(subject or SUBJ, CA, list(exts), serial=serial)

def E(o, v, crit=None):
    return extension(o, v, crit)

# ---- certificate policies (with CPS and user notice qualifiers) and relatives
cps = seq(oid('1.3.6.1.5.5.7.2.1'), ia5('http://example.com/cps'))
unotice = seq(oid('1.3.6.1.5.5.7.2.2'), seq(seq(utf8('Example Org'), seq(integer(1), integer(2))), utf8('Explicit text')))
unknown_q = seq(oid('1.3.6.1.4.1.32473.3'), octets(b'q'))
policies = seq(seq(oid('2.5.29.32.0'), seq(cps, unotice, unknown_q)),
               seq(oid('1.3.6.1.4.1.32473.2.1')),
               seq(oid('2.23.140.1.2.1'), seq(seq(oid('1.3.6.1.5.5.7.2.1')))))
tls([cert([E('2.5.29.32', policies), E('2.5.29.3', policies),
           E('1.3.6.1.4.1.311.21.10', seq(seq(oid('1.3.6.1.5.5.7.3.2')))),
           E('2.5.29.33', seq(seq(oid('1.3.6.1.4.1.32473.2.1'), oid('2.23.140.1.2.1')),
                              seq(oid('2.5.29.32.0'), oid('1.3.6.1.4.1.32473.2.2')))),
           E('2.5.29.36', seq(int_i(0, 2), int_i(1, 3))), E('2.5.29.36', seq(int_i(1, 0))),
           E('2.5.29.54', integer(4))], serial=2)])

# ---- key identifiers, key usage, extended key usage, constraints
tls([cert([E('2.5.29.14', ski), E('2.5.29.35', aki_full), E('2.5.29.35', seq(ctxp(0, b'\x01\x02'))),
           E('2.5.29.15', bits(0b111111111, 9), True),
           E('2.5.29.37', ks('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.3', '1.3.6.1.5.5.7.3.4',
                             '1.3.6.1.5.5.7.3.8', '1.3.6.1.5.5.7.3.9', '1.3.6.1.4.1.311.10.3.4')),
           E('2.5.29.19', seq(boolean(True), integer(5)), True)], serial=3),
     cert([E('2.5.29.19', seq()), E('2.5.29.15', bits(0, 9)), E('2.5.29.16', seq(gt_i(0), gt_i(1, '20250601120000Z')))],
          serial=4),
     cert([E('2.5.29.16', seq(gt_i(0))), E('2.5.29.19', seq(boolean(False)))], serial=5),
     cert([E('2.5.29.16', seq(gt_i(1)))], serial=6)])

# ---- subject / issuer alternative names with every GeneralName form
tls([cert([E('2.5.29.17', gns(*ALL_GN)), E('2.5.29.18', gns(*ALL_GN[:5])),
           E('2.5.29.29', gns(gn_dir(DN_A)))], serial=7)])

# ---- name constraints
perm = b''.join([seq(gn_dns('example.com')), seq(gn_dns('.example.org'), int_i(0, 0), int_i(1, 3)),
                 seq(gn_dir(DN_A), int_i(0, 1))])
excl = b''.join([seq(gn_ip(bytes([10, 0, 0, 0, 255, 0, 0, 0]))), seq(gn_email('example.com')),
                 seq(gn_uri('.example.com'))])
tls([cert([E('2.5.29.30', seq(tlv(0xa0, perm), tlv(0xa1, excl)), True)], serial=8),
     cert([E('2.5.29.30', seq(tlv(0xa0, seq(gn_dns('only.example.com')))))], serial=9),
     cert([E('2.5.29.30', seq(tlv(0xa1, seq(gn_dns('excl.example.com')))))], serial=10)])

# ---- CRL distribution points (full name, relative name, reasons, CRL issuer), freshest CRL
dp1 = seq(ctx(0, DPN_FULL), ctxp(1, bits(0b101010, 10)[2:]), ctx(2, gn_dir(DN_A), gn_dns('ci.example.com')))
dp2 = seq(ctx(0, DPN_REL))
dp3 = seq(ctx(0, ctx(0, gn_uri('http://crl3.example.com/'))))
dp4 = seq(ctxp(1, bits(0b1111111111, 10)[2:]), ctx(2, gn_dns('only.issuer.example.com')))
dp5 = seq()
tls([cert([E('2.5.29.31', seq(dp1, dp2, dp3, dp4, dp5)), E('2.5.29.46', seq(dp3, dp2))], serial=11)])

# ---- the remaining certificate extensions
tls([cert([E('1.3.6.1.5.5.7.1.34', seq(ia5('typeA'), ia5('typeB'))),
           E('2.5.29.70', seq(CA, integer(7))), E('2.5.29.70', seq(CA)),
           E('2.5.29.71', ks('1.3.6.1.4.1.32473.4', '1.3.6.1.4.1.32473.5')),
           E('2.5.29.72', seq(algid('1.2.840.113549.1.1.1'), bitstr(b'\x01\x02\x03'))),
           E('2.5.29.73', algid('1.2.840.113549.1.1.11')), E('2.5.29.74', bitstr(b'\x11' * 16)),
           E('2.5.29.75', seq(seq(oid('2.5.4.3'), setof(utf8('assoc'))))),
           E('1.3.6.1.4.1.311.21.7', seq(oid('1.3.6.1.4.1.311.21.8.1'), integer(100), integer(3))),
           E('1.3.6.1.4.1.311.21.7', seq(oid('1.3.6.1.4.1.311.21.8.1'), integer(100))),
           E('1.3.6.1.4.1.311.25.2', seq(tlv(0xa0, oid('1.3.6.1.4.1.311.25.2.1') + ctxp(0, b'S-1-5-21-1-2-3-500')))),
           E('1.3.6.1.4.1.311.25.2.1', tlv(0xa0, oid('1.3.6.1.4.1.311.25.2.1') + ctxp(0, b'S-1-5-21-1-2-3-501'))),
           E('1.3.6.1.4.1.9.21.2.5', octets(b'cisco template')),
           E('1.2.840.113533.7.65.0', seq(general('7.0'), bits(0b110101, 6))),
           E('1.2.840.113533.7.65.0', seq(general('6.0')))], serial=12)])

# ---- CRL extensions: reason, hold, invalidity date, certificate issuer, number, scope, delta, ...
idp_full = seq(ctx(0, DPN_FULL), ctxp(1, b'\xff'), ctxp(2, b'\xff'), ctxp(3, bits(0b1100, 10)[2:]),
               ctxp(4, b'\xff'), ctxp(5, b'\x00'))
idp_rel = seq(ctx(0, DPN_REL), ctxp(1, b'\x00'))
aaidp = seq(ctx(0, DPN_FULL), ctxp(1, bits(0b110, 10)[2:]), ctxp(2, b'\xff'), ctxp(3, b'\x00'), ctxp(4, b'\x00'), ctxp(5, b'\xff'))
nr = lambda: seq(int_i(0, 100), int_i(1, 200), integer(7))
ncrl = seq(int_i(0, 100))
scope = seq(seq(ctx(0, gn_dns('ca.example.com')), ctx(1, DPN_FULL), ctxp(2, bits(0b101, 3)[2:]),
                ctxp(4, bits(0b110, 10)[2:]), ctx(5, int_i(0, 1), int_i(1, 10), integer(2)),
                ctx(6, int_i(0, 11)), ctx(7, gn_dns('sub.example.com')),
                ctx(9, int_i(0, 3), int_i(1, 12), gt_i(2))),
            seq(ctx(0, gn_uri('http://x.example.com/'))))
crl_ref = tlv(0xa0, ctx(0, gn_dns('issuer.example.com')) + ctx(1, gn_uri('http://loc.example.com/')) +
              ctx(2, gn_uri('http://delta.example.com/'), gentime(GT)) + scope +
              gt_i(3) + gt_i(4, '20230601130000Z'))
crl_ref2 = tlv(0xa0, ctx(2, gn_dns('delta.example.com')) + scope)
other_ref = tlv(0xa1, oid('1.3.6.1.4.1.32473.6') + ctx(0, utf8('other')))
tbr = seq(seq(ctx(0, gn_dns('ca.example.com')), ctx(1, enum(1), oid('1.2.840.10040.2.1')), gentime(GT),
              tlv(0xa0, integer(1) + integer(2))),
          seq(gentime(GT), tlv(0xa1, int_i(0, 5) + int_i(1, 10))),
          seq(ctx(1, enum(6)), gentime(GT), tlv(0xa2, gn_dns('grp.example.com'))))
rvg = seq(seq(ctx(0, gn_dns('ca.example.com')), ctx(1, enum(5), oid('1.2.840.10040.2.2')), gt_i(2),
              ctx(3, nr())),
          seq(ctx(3, gn_dns('grp.example.com'))), seq(ctx(3, seq(integer(1)))))
ext_values = [
    E('2.5.29.20', integer(300)), E('2.5.29.27', integer(299)), E('2.5.29.28', idp_full, True),
    E('2.5.29.28', idp_rel), E('2.5.29.28', seq()), E('2.5.29.61', aaidp), E('2.5.29.63', seq(ctx(0, DPN_REL))),
    E('2.5.29.40', integer(5)), E('2.5.29.44', scope), E('2.5.29.45', seq(crl_ref, crl_ref2, other_ref)),
    E('2.5.29.47', enum(0)), E('2.5.29.47', enum(1)), E('2.5.29.53', seq(gn_dns('delta.example.com'), gentime(GT))),
    E('2.5.29.53', seq(gn_dns('delta.example.com'))), E('2.5.29.58', tbr), E('2.5.29.59', rvg),
    E('2.5.29.60', gentime(GT)),
    E('2.5.29.51', gentime(GT)), E('2.5.29.24', gentime(GT)),
]
for i, k in enumerate(range(0, len(ext_values), 7)):
    tls([cert(ext_values[k:k + 7], serial=20 + i)])

# CRLs (HTTP): entry extensions with every reason code, hold instruction, invalidity date and
# certificate issuer; CRL extensions
rev = [revoked(100 + code, exts=[E('2.5.29.21', enum(code)), E('2.5.29.24', gentime('20230401000000Z'))]) for code in
       (0, 1, 2, 3, 4, 5, 8, 9, 10, 11)]
rev.append(revoked(200, exts=[E('2.5.29.21', enum(6)), E('2.5.29.23', oid('1.2.840.10040.2.1')),
                              E('2.5.29.29', gns(gn_dir(DN_A)), True)]))
rev.append(revoked(201, exts=[E('2.5.29.23', oid('1.2.840.10040.2.2')), E('2.5.29.23', oid('1.2.840.10040.2.3')),
                              E('2.5.29.23', oid('1.3.6.1.4.1.32473.7'))]))
cap.http_resp('application/pkix-crl', crl(CA, 1, rev, [E('2.5.29.20', integer(300)), E('2.5.29.35', aki_full),
              E('2.5.29.28', idp_full, True), E('2.5.29.46', seq(dp3)), E('2.5.29.51', gentime(GT))],
              next_='240101000000Z'))

# ---- Matching rule assertions (2.5.13.x)
def cert_assertion(implicit_tags=True, enhanced=False):
    return seq(int_i(0, 0x1234567890), ctx(1, DN_A), ctxp(2, bytes(range(20))), ctx(3, inner(aki_full)),
               ctx(4, utctime('230601120000Z')), gt_i(5), oid_i(6, '1.2.840.113549.1.1.1'),
               ctxp(7, bits(0b101, 9)[2:]),
               (tlv(0xa8, enum(2) + gn_dns('a.example.com')) if enhanced else ctx(8, enum(4))),
               tlv(0xa9, oid('2.5.29.32.0') + oid('1.3.6.1.4.1.32473.2.1')),
               (tlv(0xaa, gn_dns('p.example.com') + gn_dir(DN_A)) if enhanced else ctx(10, DN_A)),
               ctx(11, DN_A),
               tlv(0xac, tlv(0xa0, seq(gn_dns('example.com')))))
ca1 = cert_assertion()
ca2 = seq(int_i(0, 5), ctx(4, gentime(GT)), ctx(8, oid('1.3.6.1.4.1.32473.8')))
cea = seq(integer(0x1234567890), DN_A)
ca_list = seq(DN_A, int_i(0, 1), int_i(1, 9), bits(0b101, 10), utctime('230601120000Z'),
              ctx(2, DPN_FULL), ctx(3, inner(aki_full)))
cl_exact = seq(DN_A, utctime('230601120000Z'), ctx(0, gn_uri('http://crl.example.com/')))
cl_exact2 = seq(DN_A, gentime(GT))
assertions = [
    E('2.5.13.35', ca1), E('2.5.13.35', ca2), E('2.5.13.35', seq()),
    E('2.5.13.36', seq(tlv(0xa0, inner(cea)), tlv(0xa1, inner(cea)))), E('2.5.13.36', seq(tlv(0xa0, inner(cea)))),
    E('2.5.13.37', seq(tlv(0xa0, inner(ca1)), tlv(0xa1, inner(ca2)))), E('2.5.13.37', seq(tlv(0xa1, inner(ca2)))),
    E('2.5.13.38', cl_exact), E('2.5.13.38', cl_exact2), E('2.5.13.39', ca_list), E('2.5.13.39', seq()),
    E('2.5.13.62', seq(DN_A, DN_A)),
    E('2.5.13.65', cert_assertion(enhanced=True)), E('2.5.13.65', seq(tlv(0xa8, enum(1)))),
    E('2.5.13.65', seq(tlv(0xa8, oid('1.3.6.1.4.1.32473.8')))),
]
tls([cert(assertions[:8], serial=30)])
tls([cert(assertions[8:], serial=31)])

# ---- CI+ extensions (ScramblerCapabilities, CiplusInfo, CicamBrandId, SecurityLevel):
# OIDs without an official assignment, dissected only inside the DVB-CI Content Control
# resource (second interface, LINKTYPE_DVB_CI 235): a CC data request with a certificate
def ber_len(n):
    return bytes([n]) if n < 0x80 else (bytes([0x81, n]) if n < 0x100 else bytes([0x82]) + struct.pack('>H', n))
def ci_pseudo(event, payload):
    return struct.pack('>BBH', 0, event, len(payload)) + payload
def ci_tpdu(tag, tcid, body):
    return bytes([tag]) + ber_len(len(body) + 1) + bytes([tcid]) + body
def ci_sb(tcid):
    return bytes([0x80, 0x02, tcid, 0x00])
def ci_apdu(tag, body=b''):
    return struct.pack('>I', tag)[1:] + ber_len(len(body)) + body
def ci_host(spdu):
    return ci_pseudo(0xFE, bytes([1, 0]) + ci_tpdu(0xA0, 1, spdu))
def ci_cam(spdu):
    return ci_pseudo(0xFF, bytes([1, 0]) + ci_tpdu(0xA0, 1, spdu) + ci_sb(1))
CC_RES = 0x00 << 24 | (0x8C << 16) | (1 << 6) | 1
def ci_plus_cert(cn, ci_exts):
    return certificate(name(rdn('2.5.4.3', cn)), name(rdn('2.5.4.3', 'Synthetic CI Plus Root')), ci_exts,
                       valid=validity('230101000000Z', '330101000000Z'))
cap.add(struct.pack('>BBH', 0, 0xFB, 1) + b'\x01', 1)
cap.add(bytes([0, 0xFF, 0, 2, 4, 0]), 1)
cap.add(bytes([0, 0xFE, 0, 2, 4, 0]), 1)
cap.add(ci_pseudo(0xFE, bytes([1, 0]) + ci_tpdu(0x82, 1, b'')), 1)
cap.add(ci_pseudo(0xFF, bytes([1, 0]) + ci_tpdu(0x83, 1, b'') + ci_sb(1)), 1)
cap.add(ci_cam(bytes([0x91, 0x04]) + struct.pack('>I', CC_RES)), 1)
cap.add(ci_host(bytes([0x92, 0x07, 0x00]) + struct.pack('>IH', CC_RES, 6)), 1)
cixt = [E('1.3.6.1.5.5.7.1.25', seq(integer(1), integer(2))), E('1.3.6.1.5.5.7.1.26', bitstr(b'\x80', 7)),
        E('1.3.6.1.5.5.7.1.27', integer(0x1234)), E('1.3.6.1.5.5.7.1.50', integer(1))]
cixt2 = [E('1.3.6.1.5.5.7.1.25', seq(integer(0), integer(3))), E('1.3.6.1.5.5.7.1.50', integer(0))]
def cc_item(i, d=b''):
    return bytes([i]) + struct.pack('>H', len(d)) + d
def cc_data(items):
    return b'\x01' + bytes([len(items)]) + b''.join(items) + b'\x00'
for exts, cn in ((cixt, 'Synthetic CICAM'), (cixt2, 'Synthetic Host')):
    cap.add(ci_cam(bytes([0x90, 0x02]) + struct.pack('>H', 6) +
                   ci_apdu(0x9F9003, cc_data([cc_item(0x08, ci_plus_cert(cn, exts)), cc_item(0x10, ci_plus_cert(cn, exts))]))), 1)

cap.write_pcapng(os.path.join(out, 'x509ce-coverage.pcapng'), (1, 235))

# ---------------------------------------------------------------- malformed
mal = Cap(1700100000)
_port[0] = 50400
def mtls(exts, serial=100):
    _port[0] += 1
    mal.tls_certs([cert(exts, serial=serial)], dport=_port[0])
# wrong types / truncated values for most extensions
bad = [('2.5.29.15', seq()), ('2.5.29.15', b''), ('2.5.29.19', integer(1)), ('2.5.29.19', seq(integer(1), integer(2), integer(3))),
       ('2.5.29.17', gns(gn_ip(b''), tlv(0x89, b'x'))), ('2.5.29.17', seq()), ('2.5.29.17', integer(5)),
       ('2.5.29.35', integer(1)), ('2.5.29.37', seq(integer(1))), ('2.5.29.37', seq()),
       ('2.5.29.31', seq(seq(ctx(0, ctx(5, b''))))), ('2.5.29.31', seq()), ('2.5.29.30', seq()),
       ('2.5.29.32', seq(seq(integer(1)))), ('2.5.29.32', seq(seq(oid('2.5.29.32.0'), seq(seq(oid('1.3.6.1.5.5.7.2.2'), integer(3)))))),
       ('2.5.29.20', seq()), ('2.5.29.21', integer(1)), ('2.5.29.21', enum(99)), ('2.5.29.24', utctime('230101000000Z')),
       ('2.5.29.24', gentime('notatime')), ('2.5.29.51', integer(1)), ('2.5.29.28', integer(1)),
       ('2.5.29.44', seq(seq(ctxp(2, b'')))), ('2.5.29.45', seq(tlv(0xa5, b''))), ('2.5.29.58', seq(seq(gentime(GT)))),
       ('2.5.29.59', seq(seq(ctx(3, integer(1))))), ('2.5.29.70', seq(integer(1))), ('2.5.29.72', seq(integer(1))),
       ('2.5.13.35', seq(tlv(0xad, b''))), ('2.5.13.65', integer(1)),
       ('1.3.6.1.5.5.7.1.34', seq(integer(1))), ('1.3.6.1.4.1.311.21.7', seq(integer(1))),
       ('1.2.840.113533.7.65.0', seq(integer(1)))]
for i, (o, v) in enumerate(bad):
    mtls([E(o, v)], serial=100 + i)
# GeneralName forms cut short, a name with a bad tag
mtls([E('2.5.29.17', gns(tlv(0x84, b'\x30\x00')))], serial=200)
mtls([E('2.5.29.17', gns(tlv(0xa5, b'')))], serial=201)
mtls([E('2.5.29.17', gns(tlv(0xa0, oid('1.2.3.4'))))], serial=202)
mal.write(os.path.join(out, 'x509ce-coverage-malformed.pcap'))
