#!/usr/bin/env python3
# Generates test/captures/x509if_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-x509if.c (X.509 Information Framework).
# usage: mkx509if.py <outdir> [limit]
# Writes x509if-coverage.pcap (valid data), x509if-coverage-malformed.pcap.
# x509if is reached through X.509 certificates (TLS Certificate, TCP 443),
# CRLs over HTTP and LDAP: Distinguished Names, Attributes, the
# SubtreeSpecification / HierarchyLevel / HierarchyBelow / DistinguishedName
# extension OIDs registered by x509if.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from x509lib import (
    bmp, boolean, Cap, certificate, crl, ctx, extension, gn_dir, gns, integer, name, octets, oid,
    printable, rdn, rdn_multi, revoked, seq, setof, std_name, teletex, tlv, universal, utf8,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
# Refinement nesting that is still accepted / refused (measured, see README)
OK_DEPTH = int(sys.argv[2]) if len(sys.argv) > 2 else 200
BAD_DEPTH = int(sys.argv[3]) if len(sys.argv) > 3 else 241
os.makedirs(out, exist_ok=True)

CA = std_name('Example CA')
SUBJ = std_name('www.example.com')
_port = [50100]
def tls(cap, certs):
    _port[0] += 1
    cap.tls_certs(certs, dport=_port[0])

def cert(subject=None, exts=(), serial=1, issuer=None):
    return certificate(subject or SUBJ, issuer or CA, list(exts), serial=serial)

# Refinement / SubtreeSpecification builders (EXPLICIT tags)
def r_item(o):
    return ctx(0, oid(o))
def r_and(*r):
    return ctx(1, setof(*r))
def r_or(*r):
    return ctx(2, setof(*r))
def r_not(r):
    return ctx(3, r)
def subtree(base=None, excl=None, minimum=None, maximum=None, filt=None):
    items = []
    if base is not None:
        items.append(ctx(0, base))
    if excl is not None:
        items.append(ctx(1, setof(*excl)))
    if minimum is not None:
        items.append(ctx(2, integer(minimum)))
    if maximum is not None:
        items.append(ctx(3, integer(maximum)))
    if filt is not None:
        items.append(ctx(4, filt))
    return seq(*items)

def deep_not(depth, leaf='2.5.6.0'):
    r = r_item(leaf)
    for _ in range(depth):
        r = r_not(r)
    return r

DN_A = name(rdn('2.5.4.6', 'XX', printable), rdn('2.5.4.10', 'Example Org'), rdn('2.5.4.3', 'Entry A'))
DN_B = name(rdn('2.5.4.6', 'YY', printable), rdn('2.5.4.3', 'Entry B'))
DN_EMPTY = seq()

cap = Cap()

# --- 1. Names: multi-valued RDN, every DirectoryString flavour, context lists
ctx_list = [seq(oid('2.5.4.3'), setof(utf8('en')), boolean(True)),
            seq(oid('2.5.4.10'), setof(utf8('fr'), printable('FR')))]
ava_ctx = seq(oid('2.5.4.3'), utf8('Ctx Entry'), boolean(False),
              setof(seq(ctx(0, utf8('Ctx Entry')), setof(*ctx_list)),
                    seq(setof(seq(oid('2.5.4.3'), setof(utf8('de')))))))
ava_ctx2 = seq(oid('2.5.4.10'), utf8('Org'), boolean(True))
subj1 = name(rdn('2.5.4.6', 'XX', printable),
             rdn_multi(('2.5.4.10', utf8('Example Org')), ('2.5.4.11', printable('Unit')),
                       ('2.5.4.5', printable('0042'))),
             setof(ava_ctx), setof(ava_ctx2),
             rdn('2.5.4.7', 'Sydney', teletex), rdn('2.5.4.8', 'NSW', bmp), rdn('2.5.4.3', 'ctx.example.com', universal))
tls(cap, [cert(subj1, serial=2)])

# --- 2. Attributes (subjectDirectoryAttributes 2.5.29.9, associatedInformation 2.5.29.75)
def attribute(t, vals, with_ctx=None):
    items = [oid(t), setof(*vals)]
    if with_ctx is not None:
        items.append(setof(*with_ctx))
    return seq(*items)
attrs = seq(attribute('2.5.4.3', [utf8('Operator'), printable('Ops')]),
            attribute('2.5.4.10', []),
            attribute('2.5.4.4', [utf8('Surname')],
                      [seq(utf8('Surname'), setof(*ctx_list)), seq(printable('Other'), setof(ctx_list[0]))]),
            attribute('1.3.6.1.4.1.32473.5', [octets(b'opaque')]),
            attribute('2.5.4.1', [DN_A, DN_B]))
tls(cap, [cert(exts=[extension('2.5.29.9', attrs), extension('2.5.29.75', seq(attribute('2.5.4.3', [utf8('x')])))], serial=3)])

# --- 3. SubtreeSpecification (2.5.18.6)
subtrees = [
    seq(),
    subtree(DN_A),
    subtree(DN_EMPTY, minimum=1, maximum=5),
    subtree(DN_A, [ctx(0, DN_B), ctx(1, DN_EMPTY)], 0, 10),
    subtree(None, None, None, None, r_item('2.5.6.6')),
    subtree(DN_B, None, 2, None, r_and(r_item('2.5.6.6'), r_or(r_item('2.5.6.7'), r_not(r_item('2.5.6.8'))))),
    subtree(None, None, None, None, r_and(r_or(r_item('2.5.6.0'), r_item('2.5.6.2')),
                                          r_not(r_and(r_item('2.5.6.9'))))),
]
tls(cap, [cert(exts=[extension('2.5.18.6', s)], serial=10 + i) for i, s in enumerate(subtrees)])

# --- 4. HierarchyLevel (INTEGER), HierarchyBelow (BOOLEAN)
tls(cap, [cert(exts=[extension('2.5.18.17', integer(3)), extension('2.5.18.18', boolean(True))], serial=20),
          cert(exts=[extension('2.5.18.17', integer(0)), extension('2.5.18.18', boolean(False))], serial=21)])

# --- 5. Every OID that carries a DistinguishedName
dn_oids = ["2.5.4.1", "2.5.4.31", "2.5.4.32", "2.5.4.33", "2.5.4.34", "2.5.4.49", "2.5.18.3", "2.5.18.4",
           "2.5.18.10", "2.5.18.11", "2.5.18.12", "2.5.18.13", "2.6.5.2.5", "2.6.5.2.14"]
dn_oids += ["2.16.840.1.101.2.2.1.%d" % i for i in (3, 4, 6, 49, 61, 110, 111, 113, 114, 117, 121, 138, 139, 140, 184, 188)]
for k in range(0, len(dn_oids), 10):
    tls(cap, [cert(exts=[extension(o, DN_A if i % 2 else DN_B) for i, o in enumerate(dn_oids[k:k + 10])],
                   serial=30 + k)])
# --- 6. Long DN strings: the DN text kept for the display is limited to 1024 bytes
def long_dn(n, width):
    return name(*[rdn('2.5.4.3', '%s%03d' % ('x' * (width - 3), i)) for i in range(n)])
tls(cap, [cert(long_dn(18, 40), serial=61)])      # 18 RDNs, 1044 bytes of text: all of them kept
tls(cap, [cert(long_dn(19, 40), serial=62)])      # the 19th RDN is not added (text already over 1024)
tls(cap, [cert(long_dn(200, 12), serial=63)])     # many RDNs: the text stops growing at 1024+

# --- 7. Refinement nesting just under the limit (and the same as a Criteria in x509sat)
tls(cap, [cert(exts=[extension('2.5.18.6', seq(ctx(4, deep_not(OK_DEPTH))))], serial=64)])

# --- 8. DNs in CRLs (HTTP), a DN with a very large number of RDNs in a CRL issuer
cap.http_resp('application/pkix-crl', crl(subj1, 1, [revoked(5, exts=[extension('2.5.29.29', gns(gn_dir(DN_A)), True)])],
                                          [extension('2.5.29.20', integer(2))], next_='240101000000Z'))
cap.write(os.path.join(out, 'x509if-coverage.pcap'))

# ------------------------------------------------------------ malformed / limits
mal = Cap(1700100000)
_port[0] = 50400
def mtls(certs):
    _port[0] += 1
    mal.tls_certs(certs, dport=_port[0])

# Reproducers of the fixes: Refinement nested one level past the limit (241) and
# far past it (300, the review's reproducer)
mtls([cert(exts=[extension('2.5.18.6', seq(ctx(4, deep_not(BAD_DEPTH))))], serial=100)])
mtls([cert(exts=[extension('2.5.18.6', seq(ctx(4, deep_not(300))))], serial=101)])
# RDNSequence with 20000 RDNs (CRL issuer over HTTP): was quadratic
r = rdn('1.2.3.4', 'A')
mal.http_resp('application/pkix-crl', crl(seq(r * 20000)), sport=8099)
# a handful of malformed forms
mtls([cert(exts=[extension('2.5.18.6', seq(ctx(0, seq(setof()))))], serial=102)])           # empty RDN
mtls([cert(exts=[extension('2.5.18.6', seq(ctx(1, setof(ctx(2, DN_A)))))], serial=103)])    # bad chop alternative
mtls([cert(exts=[extension('2.5.18.6', seq(ctx(4, ctx(5, oid('2.5.6.0')))))], serial=104)])  # bad Refinement tag
mtls([cert(exts=[extension('2.5.18.17', boolean(True))], serial=105)])
mtls([cert(exts=[extension('2.5.18.18', integer(5))], serial=106)])
mtls([cert(exts=[extension('2.5.4.1', seq(setof(seq(oid('2.5.4.3')))))], serial=107)])      # AVA without value
mtls([cert(name(setof(seq(oid('2.5.4.3'), utf8('a'), tlv(0x04, b'x'), setof()))), serial=108)])
mtls([cert(name(setof(seq(oid('2.5.4.3'), utf8('a'), boolean(True), setof(seq(setof()))))), serial=109)])
mtls([cert(exts=[extension('2.5.29.9', seq(seq(oid('2.5.4.3'), setof(utf8('a')),
                                          setof(seq(utf8('v'), setof(seq(oid('2.5.4.3'), setof())))))))], serial=110)])
# a DN as the value of a DN-syntax attribute inside the subject RDN: the AVA
# code also tries the value as an OCTET STRING (BER Error warning)
mtls([cert(name(rdn('2.5.4.6', 'XX', printable), rdn_multi(('2.5.4.1', DN_A), ('2.5.4.3', utf8('alias'))),
                rdn('2.5.4.31', DN_B, None)), serial=111)])
# 1000 AVAs in one DN: "Maximum protocol layer depth 500 exceeded" (x509sat per value)
mtls([cert(long_dn(1000, 12), serial=112)])
mal.write(os.path.join(out, 'x509if-coverage-malformed.pcap'))
