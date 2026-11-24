#!/usr/bin/env python3
# Generates test/captures/x509sat_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-x509sat.c (X.509 Selected Attribute Types).
# usage: mkx509sat.py <outdir>
# Writes x509sat-coverage.pcap (valid data) and x509sat-coverage-malformed.pcap.
# x509sat is reached through the attribute type OID of an AVA in a certificate's
# issuer/subject Name (TLS Certificate, TCP 443), in Attributes (subjectDirectoryAttributes),
# and through extension OIDs; every OID the dissector registers is used once.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from x509lib import (
    bitstr, bmp, boolean, Cap, certificate, ctx, extension, gentime, gn_edi, graphic, ia5,
    integer, name, numeric, octets, oid, printable, rdn, rdn_multi, seq, setof, std_name, teletex,
    tlv, universal, utctime, utf8,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
OK_DEPTH = int(sys.argv[2]) if len(sys.argv) > 2 else 200
BAD_DEPTH = int(sys.argv[3]) if len(sys.argv) > 3 else 241
os.makedirs(out, exist_ok=True)

# registered OIDs by syntax (from packet-x509sat.c)
OIDS = {
    "BitString": ("2.5.13.16", ),
    "Boolean": ("2.5.18.9", "2.16.840.1.101.2.2.1.54", "2.16.840.1.101.2.2.1.64", "2.16.840.1.101.2.2.1.65", "2.16.840.1.101.2.2.1.69", "2.16.840.1.101.2.2.1.72", "2.16.840.1.101.2.2.1.74", "2.16.840.1.101.2.2.1.81", "2.16.840.1.101.2.2.1.87", "2.6.1.6.3", ),
    "CaseIgnoreListMatch": ("2.5.13.11", ),
    "CountryName": ("2.5.4.6", "1.3.6.1.4.1.311.60.2.1.3", ),
    "DestinationIndicator": ("2.5.4.27", ),
    "DirectoryString": ("2.5.4.2", "2.5.4.3", "2.5.4.4", "2.5.4.7", "2.5.4.7.1", "2.5.4.8", "2.5.4.8.1", "2.5.4.9", "2.5.4.9.1", "2.5.4.10.1", "2.5.4.10", "2.5.4.11", "2.5.4.11.1", "2.5.4.12", "2.5.4.13", "2.5.4.15", "2.5.4.17", "2.5.4.17.1", "2.5.4.18", "2.5.4.18.1", "2.5.4.19", "2.5.4.19.1", "2.5.4.41", "2.5.4.42", "2.5.4.43", "2.5.4.44", "2.5.4.51", "2.5.4.54", "2.5.4.65", "2.5.4.97", "2.16.840.1.101.2.2.1.45", "2.16.840.1.101.2.2.1.118", "2.16.840.1.101.2.2.1.124", "2.16.840.1.101.2.2.1.125", "2.16.840.1.101.2.2.1.126", "2.16.840.1.101.2.2.1.129", "2.16.840.1.101.2.2.1.133", "2.16.840.1.101.2.2.1.143", "2.16.840.1.101.2.2.1.145", "2.16.840.1.101.2.2.1.158", "2.16.840.1.101.2.2.1.159", "1.2.840.113549.1.9.7", "1.2.840.113549.1.9.8", "1.2.840.113549.1.9.13", "1.3.6.1.5.5.7.9.2", "2.16.840.1.113730.3.1.1", "2.16.840.1.113730.3.1.2", "2.16.840.1.113730.3.1.3", "2.16.840.1.113730.3.1.4", "2.16.840.1.113730.3.1.39", "2.16.840.1.113730.3.1.241", "1.3.6.1.4.1.311.60.2.1.1", "1.3.6.1.4.1.311.60.2.1.2", ),
    "EnhancedGuide": ("2.5.4.47", ),
    "FacsimileTelephoneNumber": ("2.5.4.23", "2.5.4.23.1", ),
    "GUID": ("1.3.6.1.1.16.4", ),
    "Guide": ("2.5.4.14", ),
    "Integer": ("1.2.840.113549.1.9.25.4", "1.3.6.1.4.1.311.21.1", "1.3.6.1.4.1.311.21.3", "1.2.826.0.1063.7.0.0.0", ),
    "InternationalISDNNumber": ("2.5.4.25", "2.5.4.25.1", ),
    "NameAndOptionalUID": ("2.5.4.50", ),
    "ObjectIdentifier": ("2.5.4.0", "2.5.4.30", "2.5.4.52", "2.5.4.56", "2.5.4.66", "2.5.4.67", "2.5.18.5", "2.5.18.7", "2.5.24.1", "2.6.5.2.8", "2.6.5.2.10", "2.6.5.2.11", "2.16.840.1.101.2.2.1.115", "2.16.840.1.101.2.2.1.116", "2.16.840.1.101.2.2.1.161", "2.16.840.1.101.2.2.1.176", ),
    "OctetString": ("2.5.4.35", "1.2.840.113549.1.9.21", "1.2.840.113549.1.9.25.3", "1.3.6.1.4.1.311.21.2", ),
    "PostalAddress": ("2.5.4.16", "2.5.4.26", ),
    "PreferredDeliveryMethod": ("2.5.4.28", ),
    "PresentationAddress": ("2.5.4.29", ),
    "ProtocolInformation": ("2.5.4.48", ),
    "SyntaxBMPString": ("1.2.840.113549.1.9.20", "1.3.6.1.4.1.311.20.2", "1.3.6.1.4.1.311.17.1", ),
    "SyntaxGeneralizedTime": ("2.5.18.1", "2.5.18.2", "2.5.18.8", "2.16.840.1.101.2.2.1.55", "2.16.840.1.101.2.2.1.57", "2.16.840.1.101.2.2.1.60", "2.16.840.1.101.2.2.1.75", "2.16.840.1.101.2.2.1.174", "2.16.840.1.101.2.2.1.175", "1.3.6.1.5.5.7.9.1", ),
    "SyntaxGraphicString": ("2.16.840.1.101.2.2.1.107", "2.16.840.1.101.2.2.1.122", ),
    "SyntaxIA5String": ("1.2.840.113549.1.9.1", "0.9.2342.19200300.100.1.25", "1.2.826.0.1004.10.1.1", ),
    "SyntaxNumericString": ("2.5.13.8", ),
    "SyntaxPrintableString": ("2.5.4.5", "2.5.4.46", "2.16.840.1.101.2.2.1.51", "2.16.840.1.101.2.2.1.53", "2.16.840.1.101.2.2.1.58", "2.16.840.1.101.2.2.1.62", "2.16.840.1.101.2.2.1.63", "2.16.840.1.101.2.2.1.68", "2.16.840.1.101.2.2.1.68.1", "2.16.840.1.101.2.2.1.70", "2.16.840.1.101.2.2.1.73", "2.16.840.1.101.2.2.1.77", "2.16.840.1.101.2.2.1.82", "2.16.840.1.101.2.2.1.83", "2.16.840.1.101.2.2.1.84", "2.16.840.1.101.2.2.1.85", "2.16.840.1.101.2.2.1.86", "2.16.840.1.101.2.2.1.96", "2.16.840.1.101.2.2.1.97", "2.16.840.1.101.2.2.1.106", "2.16.840.1.101.2.2.1.144", "2.16.840.1.101.2.2.1.172", "2.16.840.1.101.2.2.1.173", "2.16.840.1.101.2.2.1.177", "2.16.840.1.101.2.2.1.178", "2.16.840.1.101.2.2.1.179", "2.16.840.1.101.2.2.1.180", "2.16.840.1.101.2.2.1.181", "2.16.840.1.101.2.2.1.182", "2.16.840.1.101.2.2.1.183", "2.16.840.1.101.2.2.1.185", "2.16.840.1.101.2.2.1.186", "2.16.840.1.101.2.2.1.187", "1.3.6.1.5.5.7.9.3", "1.3.6.1.5.5.7.9.4", "1.3.6.1.5.5.7.9.5", ),
    "SyntaxUTCTime": ("2.5.13.26", "1.3.6.1.4.1.311.21.4", ),
    "SyntaxUTF8String": ("1.3.6.1.4.1.311.20.2.3", "1.3.6.1.5.5.7.25.1", ),
    "TelephoneNumber": ("2.5.4.20", "2.5.4.20.1", "2.16.840.1.101.2.2.1.94", "2.16.840.1.101.2.2.1.95", "2.16.840.1.101.2.2.1.109", "2.16.840.1.101.2.2.1.119", "2.16.840.1.101.2.2.1.119.1", "2.16.840.1.101.2.2.1.120", "2.16.840.1.101.2.2.1.120.1", "2.16.840.1.101.2.2.1.127", "2.16.840.1.101.2.2.1.127.1", "2.16.840.1.101.2.2.1.128", "2.16.840.1.101.2.2.1.128.1", "2.16.840.1.101.2.2.1.160", ),
    "TelexNumber": ("2.5.4.21", "2.5.4.21.1", ),
    "UniqueIdentifier": ("2.5.4.45", ),
    "X121Address": ("2.5.4.24", ),
}

CA = std_name('Example CA')
DN_A = name(rdn('2.5.4.6', 'XX', printable), rdn('2.5.4.10', 'Example Org'), rdn('2.5.4.3', 'Entry A'))
DS_ENC = [utf8, printable, teletex, bmp, universal]      # DirectoryString alternatives

# --- Criteria (EXPLICIT tags): type [0] CriteriaItem, and [1], or [2], not [3]
def c_item(kind, o='2.5.4.3'):
    return ctx(0, ctx(kind, oid(o)))
def c_and(*c):
    return ctx(1, setof(*c))
def c_or(*c):
    return ctx(2, setof(*c))
def c_not(c):
    return ctx(3, c)
def guide(objclass, crit):
    items = []
    if objclass:
        items.append(ctx(0, oid(objclass)))
    items.append(ctx(1, crit))
    return setof(*items)
def enhanced_guide(objclass, crit, subset=None):
    items = [ctx(0, oid(objclass)), ctx(1, crit)]
    if subset is not None:
        items.append(ctx(2, integer(subset)))
    return seq(*items)
def deep_not(depth):
    c = c_item(0)
    for _ in range(depth):
        c = c_not(c)
    return c

CRITERIA = [c_item(0), c_item(1, '2.5.4.10'), c_item(2, '2.5.4.4'), c_item(3, '2.5.4.7'), c_item(4, '2.5.4.8'),
            c_and(c_item(0), c_or(c_item(1), c_item(2)), c_not(c_item(3))),
            c_or(c_and(c_item(0, '2.5.4.5'), c_item(4)), c_not(c_not(c_item(2))))]

def value_for(syntax, i):
    """a valid value of the given syntax; i varies the form"""
    s = 'value %d' % i
    if syntax == 'DirectoryString':
        return DS_ENC[i % 5](s)
    if syntax == 'Boolean':
        return boolean(i % 2 == 0)
    if syntax == 'BitString':
        return bitstr(b'\xa5\x58', 3)
    if syntax == 'CaseIgnoreListMatch':
        return seq(utf8('line one'), printable('line two'), bmp('line three'))
    if syntax == 'CountryName':
        return printable('AU')
    if syntax == 'DestinationIndicator':
        return printable('dest')
    if syntax == 'EnhancedGuide':
        return enhanced_guide('2.5.6.6', CRITERIA[i % len(CRITERIA)], [None, 0, 1, 2][i % 4])
    if syntax == 'FacsimileTelephoneNumber':
        return seq(printable('+61 2 5550 1234'), bitstr(b'\x01\x08', 3)) if i % 2 else seq(printable('+61 2 5550 1235'))
    if syntax == 'GUID':
        return octets(bytes(range(0x30, 0x40)))
    if syntax == 'Guide':
        return guide('2.5.6.6' if i % 2 else None, CRITERIA[i % len(CRITERIA)])
    if syntax == 'Integer':
        return integer(1000 + i)
    if syntax == 'InternationalISDNNumber':
        return numeric('61255501234')
    if syntax == 'NameAndOptionalUID':
        return seq(DN_A, bitstr(b'\x5a', 0)) if i % 2 else seq(DN_A)
    if syntax == 'ObjectIdentifier':
        return oid('1.3.6.1.4.1.32473.%d' % i)
    if syntax == 'OctetString':
        return octets(bytes([i, 1, 2, 3]))
    if syntax == 'PostalAddress':
        return seq(*[DS_ENC[(i + k) % 5]('address line %d' % k) for k in range(4)])
    if syntax == 'PreferredDeliveryMethod':
        return seq(integer(1), integer(2), integer(9))
    if syntax == 'PresentationAddress':
        return seq(ctx(0, octets(b'p')), ctx(1, octets(b's')), ctx(2, octets(b't')),
                   ctx(3, setof(octets(b'\x01\x02\x03'), octets(b'\x04\x05')))) if i % 2 else \
               seq(ctx(3, setof(octets(b'\x01'))))
    if syntax == 'ProtocolInformation':
        return seq(octets(b'\x01\x02'), setof(oid('1.3.6.1.4.1.32473.1'), oid('1.3.6.1.4.1.32473.2')))
    if syntax == 'SyntaxBMPString':
        return bmp(s)
    if syntax == 'SyntaxGeneralizedTime':
        return gentime('20230601120000Z')
    if syntax == 'SyntaxGraphicString':
        return graphic(s)
    if syntax == 'SyntaxIA5String':
        return ia5('user%d@example.com' % i)
    if syntax == 'SyntaxNumericString':
        return numeric('1234 567')
    if syntax == 'SyntaxPrintableString':
        return printable('PS %d' % i)
    if syntax == 'SyntaxUTCTime':
        return utctime('230601120000Z')
    if syntax == 'SyntaxUTF8String':
        return utf8('utf8 äö %d' % i)
    if syntax == 'TelephoneNumber':
        return printable('+61 2 5550 %04d' % i)
    if syntax == 'TelexNumber':
        return seq(printable('812345'), printable('AU'), printable('answer'))
    if syntax == 'UniqueIdentifier':
        return bitstr(b'\xa5\x5a\xa5', 0)
    if syntax == 'X121Address':
        return numeric('234212345678')
    raise KeyError(syntax)

# every registered OID once, in as many certificates as needed (each frame must stay
# below the protocol layer limit of 500, and the DN text below a size where it is cut)
pairs = []
for syn, oids in OIDS.items():
    for k, o in enumerate(oids):
        pairs.append((o, syn, len(pairs)))
cap = Cap()
_port = [50300]
def tls(certs):
    _port[0] += 1
    cap.tls_certs(certs, dport=_port[0])
def cert(subject=None, exts=(), serial=1):
    return certificate(subject or std_name('www.example.com'), CA, list(exts), serial=serial)

# Values that the AVA code can also read as an OCTET STRING go into the names; the other
# syntaxes are Attribute values (subjectDirectoryAttributes), where x509if only dispatches on the OID.
DN_SYN = {'DirectoryString', 'CountryName', 'DestinationIndicator', 'InternationalISDNNumber', 'SyntaxBMPString',
          'SyntaxGraphicString', 'SyntaxIA5String', 'SyntaxNumericString', 'SyntaxPrintableString',
          'SyntaxUTF8String', 'TelephoneNumber', 'X121Address', 'OctetString', 'GUID'}
per_cert = 11
certs = []
dn_pairs = [p for p in pairs if p[1] in DN_SYN]
attr_pairs = [p for p in pairs if p[1] not in DN_SYN]
for k in range(0, len(dn_pairs), per_cert):
    rdns = [rdn(o, value_for(syn, i)) for o, syn, i in dn_pairs[k:k + per_cert]]
    certs.append(cert(name(*rdns), serial=100 + k))
for k in range(0, len(attr_pairs), 12):
    attrs = [seq(oid(o), setof(value_for(syn, i), value_for(syn, i + 1))) for o, syn, i in attr_pairs[k:k + 12]]
    certs.append(cert(exts=[extension('2.5.29.9', seq(*attrs))], serial=200 + k))
for k in range(0, len(certs), 4):
    tls(certs[k:k + 4])

# --- every DirectoryString alternative for one attribute, multi-valued RDNs
tls([cert(name(rdn('2.5.4.3', 'utf8', utf8), rdn('2.5.4.3', 'printable', printable), rdn('2.5.4.3', 'teletex', teletex),
               rdn('2.5.4.3', 'bmp', bmp), rdn('2.5.4.3', 'universal', universal),
               rdn_multi(('2.5.4.10', utf8('Org')), ('2.5.4.11', bmp('Unit')))), serial=300)])

# --- the DN syntaxes as Attributes too
attrs = [seq(oid(o), setof(value_for(syn, i), value_for(syn, i + 1))) for o, syn, i in dn_pairs[::5]]
tls([cert(exts=[extension('2.5.29.9', seq(*attrs[:14]))], serial=301),
     cert(exts=[extension('2.5.29.9', seq(*attrs[14:]))], serial=302)])

# --- UnboundedDirectoryString: the five alternatives in the EDIPartyName of a subjectAltName
tls([cert(exts=[extension('2.5.29.17', seq(*[gn_edi(e('assigner %d' % i), e('party %d' % i))
                                              for i, e in enumerate(DS_ENC)]))], serial=299)])

# --- Guide / EnhancedGuide as extension values, every Criteria shape and nesting
ext_g = [extension('2.5.4.14', guide('2.5.6.6', c)) for c in CRITERIA] + \
        [extension('2.5.4.47', enhanced_guide('2.5.6.6', c, 2)) for c in CRITERIA[:3]]
tls([cert(exts=ext_g[:5], serial=303), cert(exts=ext_g[5:], serial=304)])

# --- UTCTime/GeneralizedTime values: years on both sides of 1950..2049
tls([cert(exts=[extension('2.5.29.9', seq(seq(oid('2.5.13.26'), setof(utctime('491231235959Z'), utctime('500101000000Z'))),
                                          seq(oid('2.5.18.1'), setof(gentime('20491231235959Z')))))], serial=305)])

# --- reproducers of the fixes: GUID after the 16 octets (1.3.6.1.1.16.4, entryUUID)
guid_rdn = setof(seq(oid('1.3.6.1.1.16.4'), octets(bytes(range(0x30, 0x40)))))
tls([cert(name(rdn('2.5.4.3', 'subject.example'), guid_rdn), serial=306),
     cert(name(rdn('2.5.4.3', 'entry'), setof(seq(oid('1.3.6.1.1.16.4'), octets(bytes(range(16)))))), serial=307)])

# --- Criteria nested to the limit (the Criteria of the review reproducer: depth 200 decodes)
tls([cert(exts=[extension('2.5.4.14', setof(ctx(1, deep_not(OK_DEPTH))))], serial=308)])
cap.write(os.path.join(out, 'x509sat-coverage.pcap'))

# ------------------------------------------------------------- malformed / limits
mal = Cap(1700100000)
_port[0] = 50500
def mtls(certs):
    _port[0] += 1
    mal.tls_certs(certs, dport=_port[0])
# Criteria one level past the limit and the review reproducer (300 levels)
mtls([cert(exts=[extension('2.5.4.14', setof(ctx(1, deep_not(BAD_DEPTH))))], serial=400)])
mtls([cert(exts=[extension('2.5.4.14', setof(ctx(1, deep_not(300))))], serial=401)])
mtls([cert(exts=[extension('2.5.4.47', enhanced_guide('2.5.6.6', deep_not(BAD_DEPTH)))], serial=402)])
# GUID with fewer than 16 octets, with more than 16, empty
for n in (0, 5, 15, 17, 40):
    mtls([cert(name(rdn('2.5.4.3', 'g%d' % n), setof(seq(oid('1.3.6.1.1.16.4'), octets(bytes(range(n)))))), serial=410 + n)])
# damaged values for each shape
bad = {'2.5.4.14': [seq(), setof(), setof(ctx(1, ctx(7, b''))), setof(ctx(0, oid('2.5.4.3')))],
       '2.5.4.47': [seq(), seq(ctx(0, oid('2.5.6.6')))],
       '2.5.4.16': [seq(integer(1)), integer(5)],
       '2.5.4.29': [seq(ctx(3, integer(1))), seq()],
       '2.5.4.48': [seq(octets(b'x'), setof(integer(1)))],
       '2.5.4.50': [seq(integer(1)), seq(DN_A, integer(2))],
       '2.5.4.21': [seq(printable('1'))],
       '2.5.4.23': [seq(integer(1)), seq(printable('1'), integer(2))],
       '2.5.4.28': [seq(printable('x'))],
       '2.5.13.11': [seq(integer(1))],
       '2.5.13.26': [utctime('abc'), printable('230601120000Z')],
       '2.5.18.1': [gentime('abc'), utctime('230601120000Z')],
       '2.5.4.3': [integer(1), seq(), tlv(0x1e, b'\x00'), tlv(0x1c, b'\x00\x00')],
       '2.5.4.6': [integer(1), printable('')],
       '1.3.6.1.1.16.4': [integer(1)]}
k = 0
for o, vals in bad.items():
    for v in vals:
        k += 1
        mtls([cert(name(setof(seq(oid(o), v))), serial=500 + k)])
mal.write(os.path.join(out, 'x509sat-coverage-malformed.pcap'))
