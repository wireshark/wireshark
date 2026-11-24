#!/usr/bin/env python3
# Generates test/captures/sgp22_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the SGP.22 dissector
(packet-sgp22.c, GSMA Remote SIM Provisioning; generated from
epan/dissectors/asn1/sgp22).

The PDUs are encoded with asn1tools from the ASN.1 modules of the
dissector (asn/; the PKIX modules are reduced stand-ins) and sample
values built by asnsample.py, which varies every CHOICE alternative and
every OPTIONAL member from variant to variant. The values are made up
(zero keys, no real certificates, no cryptographic values: the 8 octet
C-MAC of a BoundProfilePackage segment is a constant placeholder).

SGP.22 is reached by default through
  - HTTP (media type application/x-gsma-rsp-asn1, tag 'A2'): ES9+/ES11
    RemoteProfileProvisioningRequest and Response, every alternative,
  - CoAP on the URI path /gsma/rsp2/asn1 (UDP 5683), the same PDUs,
  - the BoundProfilePackage of GetBoundProfilePackageResponse, whose '88'
    segments (MACed, not encrypted) are reassembled and handed back to
    the "sgp22.request" table: every request PDU of the table is sent
    inside a BoundProfilePackage, in one and in two segments, and
    BoundProfilePackages nest (the fix "SGP.22: Bound nested
    BoundProfilePackage dissection" limits this to 4 levels),
  - the BER object identifier table: the SGP.22 certificate extensions
    in an X.509 certificate (Exported PDU "x509af").

The malformed capture holds the nesting reproducer (depth 6 and 600),
segments too short to hold the C-MAC and truncated PDUs.

The main capture also holds the nesting reproducer (600 levels), the only
frame with an error expert info; the malformed capture nests 5 and 6 levels.

Usage: mksgp22.py <output directory> [-v]
Writes sgp22-coverage.pcapng and sgp22-coverage-malformed.pcapng.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















HERE = os.path.dirname(os.path.abspath(__file__))
from asnsample import Sampler  # noqa: E402
from rsplib import (Tcp, Pcapng, http_post, http_ok, udp_frame, coap)  # noqa: E402

MAC = b'\xa5' * 8          # placeholder for the C-MAC of a segment

# (type, kind, tag) of the "sgp22.request" and "sgp22.response" tables
REQUESTS = ['GetEuiccInfo1Request', 'PrepareDownloadRequest', 'GetEuiccInfo2Request',
            'InitialiseSecureChannelRequest', 'ConfigureISDPRequest', 'StoreMetadataRequest',
            'ReplaceSessionKeysRequest', 'ListNotificationRequest', 'SetNicknameRequest',
            'UpdateMetadataRequest', 'RetrieveNotificationsListRequest', 'ProfileInfoListRequest',
            'GetEuiccChallengeRequest', 'NotificationMetadata', 'NotificationSentRequest',
            'EnableProfileRequest', 'DisableProfileRequest', 'DeleteProfileRequest',
            'EuiccMemoryResetRequest', 'LoadCRLRequest', 'BoundProfilePackage',
            'AuthenticateServerRequest', 'InitiateAuthenticationRequest',
            'GetBoundProfilePackageRequest', 'AuthenticateClientRequest',
            'EuiccConfiguredAddressesRequest', 'HandleNotification', 'GetEuiccDataRequest',
            'SetDefaultDpAddressRequest', 'CancelSessionRequest', 'LpaeActivationRequest',
            'GetRatRequest']

RSP = 'RSPDefinitions'
S = Sampler()
import certs
S.overrides['Certificate'] = lambda v, path: certs.cert_value(S, RSP, v)
S.overrides['CertificateList'] = lambda v, path: certs.crl_value(S, RSP, v)
def bpp_seg(v, path, n=12):
    return [bytes((v + i * 3 + len(path)) & 0xff for i in range(n)) + MAC]


S.member_overrides['firstSequenceOf87'] = lambda v, path: bpp_seg(v, path)
S.member_overrides['sequenceOf88'] = lambda v, path: bpp_seg(v, path)
S.member_overrides['secondSequenceOf87'] = lambda v, path: bpp_seg(v, path, 9)
S.member_overrides['sequenceOf86'] = lambda v, path: bpp_seg(v, path, 20)
# MCC/MNC as coded in 3GPP TS 24.008: 310/410 and 262/01
S.member_overrides['mccMnc'] = lambda v, path: [b'\x13\x00\x14', b'\x62\xf2\x10'][v % 2]
# tag lists: one and two octet tags (5A, 4F, 9F70, BF22)
S.member_overrides['tagList'] = lambda v, path: (
    b'\x5a' if 'GetEuiccDataRequest' in path else [b'\x5a', b'\x4f\x9f\x70', b'\xbf\x22\x5a'][v % 3])
S.member_overrides['vendorOid'] = lambda v, path: '2.23.146.1.3.1.1'
# the open type of the registered OID is an ActivationCodeRetrievalInfo
S.member_overrides['vendorSpecificData'] = lambda v, path: S.value({'type': 'ActivationCodeRetrievalInfo'}, RSP, v, path)


def enc(name, v):
    return S.encode(name, RSP, v)


def rpp(kind, v):
    """RemoteProfileProvisioningRequest/Response [2] (tag 'A2') holding the
    alternative number v (rotating) of the CHOICE; the inner PDU carries
    its own tag, so the CHOICE is built by hand (asn1tools would add a
    second tag)."""
    t = S.spec[RSP]['types']['RemoteProfileProvisioning' + kind]
    alts = [a for a in t['members'] if isinstance(a, dict)]
    a = alts[v % len(alts)]
    return tlv(b'\xa2', enc(a['type'], v // len(alts)))


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        ln = bytes([0x80 | len(b)]) + b
    return tag + ln + content


def bpp_response(segments88, first87=(), second87=None, seq86=(b'\x01' * 12,), txid=b'\x11' * 4, v=0):
    """RemoteProfileProvisioningResponse holding a BoundProfilePackage whose
    segments are given (each a payload to which the placeholder C-MAC is added)."""
    bpp = S.sample('BoundProfilePackage', RSP, v)
    bpp['firstSequenceOf87'] = [s + MAC for s in first87] or [b'\x07' * 9 + MAC]
    bpp['sequenceOf88'] = [s + MAC for s in segments88]
    if second87 is None:
        bpp.pop('secondSequenceOf87', None)
    else:
        bpp['secondSequenceOf87'] = [s + MAC for s in second87]
    bpp['sequenceOf86'] = [s + MAC for s in seq86]
    val = ('getBoundProfilePackageOk', {'transactionId': txid, 'boundProfilePackage': bpp})
    return tlv(b'\xa2', S.comp.modules[RSP]['GetBoundProfilePackageResponse'].encode(val))


def nested_bpp(depth, inner=b''):
    """A BoundProfilePackage PDU whose '88' segment holds another one,
    depth levels deep (the innermost holds `inner`)."""
    pdu = inner
    for _ in range(depth):
        bpp = S.sample('BoundProfilePackage', RSP, 0)
        bpp['firstSequenceOf87'] = [b'\x07' * 9 + MAC]
        bpp['sequenceOf88'] = [pdu + MAC if pdu else b'\x08' * 9 + MAC]
        bpp.pop('secondSequenceOf87', None)
        bpp['sequenceOf86'] = [b'\x06' * 9 + MAC]
        pdu = S.comp.modules[RSP]['BoundProfilePackage'].encode(bpp)
    return pdu


def main_frames(p):
    F = []
    # ---- HTTP: every alternative of the ES9+/ES11 requests and responses
    c = Tcp(F, 41000, 80)
    c.handshake()
    for v in range(12):
        req = rpp('Request', v)
        resp = rpp('Response', v)
        c.send(True, http_post(b'/gsma/rsp2/es9plus/request%d' % v, req))
        c.send(False, http_ok(resp))
    c.close()

    # ---- HTTP: BoundProfilePackage with every sgp22.request PDU in its
    # '88' segments, in one and in two segments
    c = Tcp(F, 41001, 80)
    c.handshake()
    for i, t in enumerate(REQUESTS):
        for v in (0, 1):
            pdu = enc(t, v)
            if v == 0:
                segs = [pdu]
            else:
                cut = max(1, len(pdu) // 2)
                segs = [pdu[:cut], pdu[cut:]]
            c.send(True, http_post(b'/gsma/rsp2/es9plus/getBoundProfilePackage',
                                   rpp('Request', 2)))
            c.send(False, http_ok(bpp_response(
                segs, first87=[b'\x87' * (9 + i), b'\x87' * 11] if v else (),
                second87=[b'\x88' * 10, b'\x88' * 12] if v else None,
                seq86=[b'\x86' * 10, b'\x86' * 20] if v else (b'\x86' * 10,), v=v)))
    # nested BoundProfilePackages, within the limit of the dissector
    for depth in (1, 2, 3):
        c.send(True, http_post(b'/gsma/rsp2/es9plus/getBoundProfilePackage',
                               rpp('Request', 2)))
        c.send(False, http_ok(bpp_response([nested_bpp(depth, enc('StoreMetadataRequest', 0))])))
    # the reproducer of "SGP.22: Bound nested BoundProfilePackage dissection": 600
    # levels, which hit the layer limit assertion before the fix. With the fix
    # the fifth level has an error expert info (the only one of this capture)
    c.send(True, http_post(b'/gsma/rsp2/es9plus/getBoundProfilePackage', rpp('Request', 2)))
    c.send(False, http_ok(bpp_response([nested_bpp(600)])), seg=20000)
    c.close()

    # ---- CoAP, URI path /gsma/rsp2/asn1
    mid = 1
    for v in range(5):
        F.append(udp_frame(50000 + v, 5683, coap(0, 2, mid, b'tk', ('gsma', 'rsp2', 'asn1'),
                                                 rpp('Request', v))))
        F.append(udp_frame(50000 + v, 5683, coap(2, 0x45, mid, b'tk', (),
                                                 rpp('Response', v)), False))
        mid += 1
    p.eth(F)

    # ---- BER object identifier table: the SGP.22 certificate extensions
    from certs import crl_with_extensions
    p.exp('x509af', crl_with_extensions(S, RSP, 0))
    p.exp('x509af', crl_with_extensions(S, RSP, 1))


def malformed_frames(p):
    F = []
    # nesting past the limit of 4: depth 6 (an error expert info on the
    # fifth level) and the reproducer of the report with 600 levels
    c = Tcp(F, 42000, 80)
    c.handshake()
    for depth in (5, 6, 600):
        c.send(True, http_post(b'/gsma/rsp2/es9plus/getBoundProfilePackage',
                               rpp('Request', 2)))
        c.send(False, http_ok(bpp_response([nested_bpp(depth)])))
    # segments too short to hold the 8 octet C-MAC
    for segs in ([b''], [b'\x01\x02\x03']):
        bpp = S.sample('BoundProfilePackage', RSP, 0)
        bpp['firstSequenceOf87'] = [s for s in segs]
        bpp['sequenceOf88'] = [s for s in segs]
        bpp['sequenceOf86'] = [s for s in segs]
        bpp.pop('secondSequenceOf87', None)
        val = ('getBoundProfilePackageOk', {'transactionId': b'\x11', 'boundProfilePackage': bpp})
        c.send(True, http_post(b'/gsma/rsp2/es9plus/getBoundProfilePackage',
                               rpp('Request', 2)))
        c.send(False, http_ok(tlv(b'\xa2', S.comp.modules[RSP]['GetBoundProfilePackageResponse'].encode(val))))
    # a '88' segment with a BoundProfilePackage that is too short for a tag
    c.send(True, http_post(b'/x', rpp('Request', 2)))
    c.send(False, http_ok(bpp_response([b'\xbf'])))
    # truncated and garbled PDUs
    good = rpp('Response', 0)
    for body in (good[:len(good) // 2], good[:3], tlv(b'\xa2', b'\xbf\x39\x05\x01'),
                 tlv(b'\xa2', tlv(b'\xbf\x3a', tlv(b'\xa0', b'\x80\x01'))),
                 tlv(b'\xa2', tlv(b'\xbf\x39', b'\x30\x80'))):
        c.send(True, http_post(b'/x', rpp('Request', 0)))
        c.send(False, http_ok(body))
    c.close()
    # the request side too
    c = Tcp(F, 42001, 80)
    c.handshake()
    good = rpp('Request', 0)
    for body in (good[:len(good) // 2], good[:3], tlv(b'\xa2', b'\xbf\x39\x05\x01')):
        c.send(True, http_post(b'/x', body))
        c.send(False, http_ok(b''))
    c.close()
    p.eth(F)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    p = Pcapng()
    main_frames(p)
    p.write(os.path.join(out, 'sgp22-coverage.pcapng'))
    if '-v' in sys.argv:
        print('main', p.n, 'frames')
    p = Pcapng()
    malformed_frames(p)
    p.write(os.path.join(out, 'sgp22-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        print('malformed', p.n, 'frames')


if __name__ == '__main__':
    main()
