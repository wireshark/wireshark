# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""An X.509 certificate (the reduced PKIX1Explicit88 stand-in encodes
the same DER as the real module) whose extensions carry the SGP.22
object identifiers the dissector registers in the BER OID table."""
import datetime

EXTS = (('2.23.146.1.2.0.1', 'ExpirationDate'),
        ('2.23.146.1.2.0.2', 'TotalPartialCrlNumber'),
        ('2.23.146.1.2.0.3', 'PartialCrlNumber'),
        ('2.23.146.1.3.1.1', 'ActivationCodeRetrievalInfo'))


def name(cn):
    return ('rdnSequence', [[{'type': '2.5.4.3', 'value': cn}]])


def cert_value(S, module, variant, names=EXTS):
    exts = []
    for oid, tn in names:
        v = S.encode(tn, module, variant)
        exts.append({'extnID': oid, 'extnValue': v})
    return {
        'tbsCertificate': {
            'version': 2, 'serialNumber': 1 + variant,
            'signature': {'algorithm': '1.2.840.113549.1.1.11', 'parameters': None},
            'issuer': name('Test CI'),
            'validity': {'notBefore': ('utcTime', datetime.datetime(2026, 1, 1)),
                         'notAfter': ('generalTime', datetime.datetime(2036, 1, 1))},
            'subject': name('Test EUM'),
            'subjectPublicKeyInfo': {'algorithm': {'algorithm': '1.2.840.10045.2.1', 'parameters': None},
                                     'subjectPublicKey': (b'\x04' + bytes(range(64)), 8 * 65)},
            'extensions': exts},
        'signatureAlgorithm': {'algorithm': '1.2.840.113549.1.1.11', 'parameters': None},
        'signature': (bytes(32), 256)}


def cert_with_extensions(S, module, variant, names=EXTS):
    return S.comp.modules['PKIX1Explicit88']['Certificate'].encode(cert_value(S, module, variant, names))


def crl_value(S, module, variant, names=EXTS):
    exts = [{'extnID': oid, 'extnValue': S.encode(tn, module, variant)} for oid, tn in names]
    return {
        'tbsCertList': {
            'version': 1,
            'signature': {'algorithm': '1.2.840.113549.1.1.11', 'parameters': None},
            'issuer': name('Test CI'),
            'thisUpdate': ('utcTime', datetime.datetime(2026, 11, 1)),
            'nextUpdate': ('generalTime', datetime.datetime(2026, 12, 1)),
            'revokedCertificates': [{'userCertificate': 7, 'revocationDate': ('utcTime', datetime.datetime(2026, 10, 1))}],
            'crlExtensions': exts},
        'signatureAlgorithm': {'algorithm': '1.2.840.113549.1.1.11', 'parameters': None},
        'signature': (bytes(32), 256)}


def crl_with_extensions(S, module, variant, names=EXTS):
    return S.comp.modules['PKIX1Explicit88']['CertificateList'].encode(crl_value(S, module, variant, names))
