#!/usr/bin/env python3
# Generates test/captures/sgp32_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the SGP.32 dissector
(packet-sgp32.c, GSMA SGP.32 eSIM IoT remote provisioning, ESipa and
ES10; generated from epan/dissectors/asn1/sgp32).

The PDUs are encoded with asn1tools from the ASN.1 modules of the
dissector (asn/; the PKIX modules are reduced stand-ins) and sample
values built by asnsample.py, which varies every CHOICE alternative and
every OPTIONAL member from variant to variant. All values are made up
(zero keys, no certificates, no signatures).

SGP.32 is reached by default through
  - HTTP with the media type application/x-gsma-rsp-asn1 (a tag other
    than 'A2'): the ESipa messages EsipaMessageFromIpaToEim and
    EsipaMessageFromEimToIpa, every alternative several times; the
    ES9+ BoundProfilePackage that the ESipa response carries is handed to
    the SGP.22 dissector,
  - CoAP on the URI path /gsma/rsp2/asn1 (UDP 5683),
  - Exported PDU frames naming the registered dissectors "sgp32.request"
    and "sgp32.response": every PDU of the two tag tables.

The malformed capture holds the BoundProfilePackage nesting reproducer
(depth 6 and 600) through an ESipa response and truncated PDUs.

Usage: mksgp32.py <output directory> [-v]
Writes sgp32-coverage.pcapng and sgp32-coverage-malformed.pcapng.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















HERE = os.path.dirname(os.path.abspath(__file__))
from asnsample import Sampler  # noqa: E402
from rsplib import (Tcp, Pcapng, http_post, http_ok, udp_frame, coap)  # noqa: E402
import certs

MAC = b'\xa5' * 8          # placeholder for the C-MAC of a segment
RSP = 'RSPDefinitions'
SGP = 'SGP32Definitions'

# the "sgp32.request" and "sgp32.response" tables: (type, kind)
TABLE = [('PrepareDownloadResponse', 'response'), ('EUICCInfo2', 'response'),
         ('StoreMetadataRequest', 'request'), ('UpdateMetadataRequest', 'request'),
         ('RetrieveNotificationsListRequest', 'request'),
         ('RetrieveNotificationsListResponse', 'response'),
         ('ProfileInstallationResult', 'response'), ('AuthenticateServerResponse', 'response'),
         ('IpaeActivationRequest', 'request'), ('IpaeActivationResponse', 'response'),
         ('EuiccPackageRequest', 'request'), ('EuiccPackageResult', 'response'),
         ('IpaEuiccDataRequest', 'request'), ('IpaEuiccDataResponse', 'response'),
         ('EimAcknowledgements', 'request'), ('ProfileDownloadTriggerRequest', 'request'),
         ('ProfileDownloadTriggerResult', 'response'),
         ('GetEimConfigurationDataRequest', 'request'), ('GetEimConfigurationDataResponse', 'response'),
         ('GetCertsRequest', 'request'), ('GetCertsResponse', 'response'),
         ('AddInitialEimRequest', 'request'), ('AddInitialEimResponse', 'response'),
         ('ProfileRollbackRequest', 'request'), ('ProfileRollbackResponse', 'response'),
         ('ConfigureImmediateProfileEnablingRequest', 'request'),
         ('ConfigureImmediateProfileEnablingResponse', 'response'),
         ('ImmediateEnableRequest', 'request'), ('ImmediateEnableResponse', 'response'),
         ('EnableEmergencyProfileRequest', 'request'), ('EnableEmergencyProfileResponse', 'response'),
         ('DisableEmergencyProfileRequest', 'request'), ('DisableEmergencyProfileResponse', 'response'),
         ('ExecuteFallbackMechanismRequest', 'request'), ('ExecuteFallbackMechanismResponse', 'response'),
         ('ReturnFromFallbackRequest', 'request'), ('ReturnFromFallbackResponse', 'response'),
         ('GetConnectivityParametersRequest', 'request'), ('GetConnectivityParametersResponse', 'response'),
         ('EuiccMemoryResetRequest', 'request'), ('EuiccMemoryResetResponse', 'response'),
         ('SetDefaultDpAddressRequest', 'request'), ('SetDefaultDpAddressResponse', 'response')]

S = Sampler()


def enc(name, v, module=SGP):
    return S.encode(name, module, v)


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        ln = bytes([0x80 | len(b)]) + b
    return tag + ln + content


def esipa(kind, v):
    """EsipaMessageFromIpaToEim / EsipaMessageFromEimToIpa: the alternative
    number v (rotating); the inner PDU carries its own tag."""
    t = S.spec[SGP]['types']['EsipaMessageFrom' + ('IpaToEim' if kind == 'Request' else 'EimToIpa')]
    alts = [a for a in t['members'] if isinstance(a, dict)]
    a = alts[v % len(alts)]
    return enc(a['type'], v // len(alts))


def bpp_seg(v, path, n=12):
    return [bytes((v + i * 3 + len(path)) & 0xff for i in range(n)) + MAC]


# members of explicit tag [N] whose CHOICE type has the tag [N] too (the
# dissector does not accept the double tag)
S.skip_members.add('eUICCPackageResult')
S.overrides['Certificate'] = lambda v, path: certs.cert_value(S, RSP, v)
S.overrides['CertificateList'] = lambda v, path: certs.crl_value(S, RSP, v)
S.member_overrides['firstSequenceOf87'] = lambda v, path: bpp_seg(v, path)
S.member_overrides['sequenceOf88'] = lambda v, path: bpp_seg(v, path)
S.member_overrides['secondSequenceOf87'] = lambda v, path: bpp_seg(v, path, 9)
S.member_overrides['sequenceOf86'] = lambda v, path: bpp_seg(v, path, 20)
# MCC/MNC as coded in 3GPP TS 24.008: 310/410 and 262/01
S.member_overrides['mccMnc'] = lambda v, path: [b'\x13\x00\x14', b'\x62\xf2\x10'][v % 2]
S.member_overrides['rPLMN'] = S.member_overrides['mccMnc']
# tag lists: one and two octet tags (5A, 4F, 9F70, BF22)
S.member_overrides['tagList'] = lambda v, path: [b'\x5a', b'\x4f\x9f\x70', b'\xbf\x22\x5a'][v % 3]
S.member_overrides['vendorOid'] = lambda v, path: '2.23.146.1.3.1.1'
# the open type of the registered OID is an ActivationCodeRetrievalInfo
S.member_overrides['vendorSpecificData'] = lambda v, path: S.value(
    {'type': 'ActivationCodeRetrievalInfo'}, RSP, v, path)


def bpp_value(segments88, v=0):
    bpp = S.sample('BoundProfilePackage', RSP, v)
    bpp['sequenceOf88'] = [s + MAC for s in segments88]
    return bpp


def esipa_bpp_response(bpp):
    """GetBoundProfilePackageResponseEsipa with a BoundProfilePackage."""
    t = S.spec[SGP]['types']['GetBoundProfilePackageOkEsipa']
    ok = S.sample('GetBoundProfilePackageOkEsipa', SGP, 0)
    ok['boundProfilePackage'] = bpp
    val = ('getBoundProfilePackageOkEsipa', ok)
    return S.comp.modules[SGP]['GetBoundProfilePackageResponseEsipa'].encode(val)


def nested_bpp(depth, inner=b''):
    pdu = inner
    for _ in range(depth):
        bpp = S.sample('BoundProfilePackage', RSP, 0)
        bpp['sequenceOf88'] = [pdu + MAC if pdu else b'\x08' * 9 + MAC]
        bpp.pop('secondSequenceOf87', None)
        pdu = S.comp.modules[RSP]['BoundProfilePackage'].encode(bpp)
    return pdu


def main_frames(p):
    F = []
    # ---- HTTP: every alternative of the ESipa messages, several times
    c = Tcp(F, 41000, 80)
    c.handshake()
    for v in range(48):
        c.send(True, http_post(b'/gsma/rsp2/esipa/message%d' % v, esipa('Request', v)))
        c.send(False, http_ok(esipa('Response', v)))
    # a BoundProfilePackage in an ESipa response goes to the SGP.22 dissector;
    # BoundProfilePackages nest within the limit of 4
    for depth in (1, 2, 3):
        c.send(True, http_post(b'/gsma/rsp2/esipa/getBoundProfilePackage', esipa('Request', 2)))
        pdu = nested_bpp(depth, enc('StoreMetadataRequest', 0, RSP))
        c.send(False, http_ok(esipa_bpp_response(bpp_value([pdu]))))
    c.send(True, http_post(b'/gsma/rsp2/esipa/getBoundProfilePackage', esipa('Request', 2)))
    pdu = enc('StoreMetadataRequest', 1, RSP)
    c.send(False, http_ok(esipa_bpp_response(bpp_value([pdu[:len(pdu) // 2], pdu[len(pdu) // 2:]], 1))))
    # the reproducer of "SGP.22: Bound nested BoundProfilePackage dissection" (600
    # levels, through the ESipa response) is the only frame with an error expert
    # info: the fifth level
    c.send(True, http_post(b'/gsma/rsp2/esipa/getBoundProfilePackage', esipa('Request', 2)))
    c.send(False, http_ok(esipa_bpp_response(bpp_value([nested_bpp(600)]))), seg=20000)
    c.close()

    # ---- CoAP, URI path /gsma/rsp2/asn1
    mid = 1
    for v in range(6):
        F.append(udp_frame(50000 + v, 5683, coap(0, 2, mid, b'tk', ('gsma', 'rsp2', 'asn1'),
                                                 esipa('Request', v))))
        F.append(udp_frame(50000 + v, 5683, coap(2, 0x45, mid, b'tk', (), esipa('Response', v)), False))
        mid += 1
    p.eth(F)

    # ---- Exported PDU: the "sgp32.request" and "sgp32.response" tables
    # the PDUs with deeply nested CHOICEs get more variants
    big = ('EuiccPackageRequest', 'EuiccPackageResult', 'IpaEuiccDataResponse',
           'GetEimConfigurationDataResponse', 'ProfileDownloadTriggerResult')
    for t, kind in TABLE:
        for v in range(40 if t in big else 8):
            p.exp('sgp32.' + kind, enc(t, v))


def malformed_frames(p):
    F = []
    c = Tcp(F, 42000, 80)
    c.handshake()
    for depth in (5, 6, 600):
        c.send(True, http_post(b'/gsma/rsp2/esipa/getBoundProfilePackage', esipa('Request', 2)))
        c.send(False, http_ok(esipa_bpp_response(bpp_value([nested_bpp(depth)]))))
    good = esipa('Response', 0)
    for body in (good[:len(good) // 2], good[:3], b'\xbf\x39\x05\x01', tlv(b'\xbf\x3a', b'\xa0\x80')):
        c.send(True, http_post(b'/x', esipa('Request', 0)))
        c.send(False, http_ok(body))
    good = esipa('Request', 1)
    for body in (good[:len(good) // 2], good[:2]):
        c.send(True, http_post(b'/x', body))
        c.send(False, http_ok(b''))
    c.close()
    p.eth(F)
    # truncated PDUs of the tables
    for t, kind in TABLE[:12]:
        b = enc(t, 0)
        p.exp('sgp32.' + kind, b[:max(3, len(b) // 2)])
    p.exp('sgp32.request', b'\xbf')
    p.exp('sgp32.response', b'\xbf\x21')
    p.exp('sgp32.response', b'')
    # unknown tags
    p.exp('sgp32.request', b'\xbf\x7f\x00')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    p = Pcapng()
    main_frames(p)
    p.write(os.path.join(out, 'sgp32-coverage.pcapng'))
    if '-v' in sys.argv:
        print('main', p.n, 'frames')
    p = Pcapng()
    malformed_frames(p)
    p.write(os.path.join(out, 'sgp32-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        print('malformed', p.n, 'frames')


if __name__ == '__main__':
    main()
