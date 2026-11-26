#!/usr/bin/env python3
# application/pkix-cert coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""application/pkix-cert (packet-app-pkix-cert.c): a client downloads
certificates over HTTP; the bodies of the 200 responses are handed to the
"media_type" table. The DER is built here with placeholder key and
signature bytes: no real certificate, key or signature is involved.

Usage: mkapp-pkix-cert.py [<output directory>]
writes app-pkix-cert-coverage.pcap and app-pkix-cert-coverage-malformed.pcap
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
import capgen  # noqa: E402
import pkixlib as pk  # noqa: E402


def http_get(path, host='pki.example'):
    return ('GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/pkix-cert\r\n\r\n'
            % (path, host)).encode()


def http_ok(body, ctype='application/pkix-cert', extra=''):
    return ('HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s\r\n'
            % (ctype, len(body), extra)).encode() + body


def exts():
    return [
        pk.ext('2.5.29.19', pk.SEQ(pk.BOOL(True), pk.INT(0)), critical=True),   # basicConstraints
        pk.ext('2.5.29.15', pk.BIT(b'\x06', 1), critical=True),                 # keyUsage
        pk.ext('2.5.29.17', pk.SEQ(pk.gn_dns('www.example.com'), pk.gn_email('ca@example.com'),
                                   pk.gn_uri('http://pki.example/'),
                                   pk.gn_ip(bytes([192, 0, 2, 7])))),            # subjectAltName
        pk.ext_eku(pk.OID_KP[:3]),
        pk.ext_aia(),
    ]


# Placeholder certificates (all signature and key bytes are filler)
CERTS = [
    ('/ca.cer', pk.cert_with(exts(), cn='Example Root CA', issuer='Example Root CA', serial=1)),
    ('/v1.cer', pk.cert_with(cn='Example v1 host', issuer='Example Root CA', serial=2, version=0)),
    ('/host.cer', pk.cert_with([pk.ext_eku(pk.OID_KP)], cn='host.example', serial=3)),
    ('/ec.cer', pk.cert_with(cn='ec.example', serial=4,
                             sigalg=pk.alg(pk.ECDSA_SHA256),
                             spki=pk.SEQ(pk.alg(pk.EC_PUBKEY, pk.OID('1.2.840.10045.3.1.7')),
                                         pk.BIT(b'\x04' + bytes(range(64)))))),
]

outdir = sys.argv[1] if len(sys.argv) > 1 else '.'


def conversation(items, sport, v6=False, isn=1000):
    """items: (request, response body bytes or list of segments)"""
    src, dst = (capgen.IP6_A, capgen.IP6_B) if v6 else (capgen.IP4_A, capgen.IP4_B)
    fl = capgen.TcpFlow(sport, 80, src=src, dst=dst, v6=v6, isn_c=isn, isn_s=isn + 5000)
    out = []   # captured mid-connection: no handshake (a SYN without options is flagged)
    for req, resp in items:
        out.append(fl.send(req))
        for seg in (resp if isinstance(resp, list) else [resp]):
            out.append(fl.recv(seg))
    out += fl.close()
    return out


frames = []
# One connection with the four certificates (frames 1-3 handshake, then
# request and response each), the second as a response to a request with
# a Content-Type parameter
frames += conversation([
    (http_get('/ca.cer'), http_ok(CERTS[0][1])),
    (http_get('/v1.cer'), http_ok(CERTS[1][1], 'application/pkix-cert; charset=binary')),
    (http_get('/host.cer'), http_ok(CERTS[2][1])),
    (http_get('/ec.cer'), http_ok(CERTS[3][1])),
], 41000)
# A certificate split over several TCP segments (reassembled by HTTP)
body = http_ok(CERTS[0][1])
frames += conversation([(http_get('/ca-split.cer'), [body[:150], body[150:300], body[300:]])],
                       41001, isn=2000)
# The same over IPv6
frames += conversation([(http_get('/host6.cer'), http_ok(CERTS[2][1]))], 41002, v6=True, isn=3000)
n = len(frames)
# Timestamps inside the validity of the certificates (2026-2036)
TS = lambda i: (1800000000 + i, 0)  # noqa: E731
capgen.write_pcap(os.path.join(outdir, 'app-pkix-cert-coverage.pcap'), frames, ts=TS)

# Malformed capture: damaged bodies
good = CERTS[0][1]
bad = [
    good[:60],                                 # cut inside the TBSCertificate
    good[:-10],                                # cut inside the signature
    good + b'\x00\x01trailing',                # data after the certificate
    b'\x30\x03\x02\x01\x01',                   # too small to be a certificate
    b'\x30\x80' + good[2:] + b'\x00\x00',      # indefinite length
    b'\x04\x10' + bytes(16),                   # an OCTET STRING, not a SEQUENCE
    b'\xff' * 40,                              # not BER at all
    b'\x30\x84\xff\xff\xff\xff' + good[4:40],  # length far beyond the data
    pk.cert_with(cn='x', serial=9, version=7),                 # version out of range
    pk.SEQ(pk.SEQ(pk.INT(1)), pk.alg(pk.SHA256_RSA, pk.NULL), pk.BIT(b'\x5a' * 4)),  # empty TBS
]
items = [(http_get('/bad%d.cer' % i), http_ok(b)) for i, b in enumerate(bad)]
capgen.write_pcap(os.path.join(outdir, 'app-pkix-cert-coverage-malformed.pcap'),
                  conversation(items, 41003, isn=4000), ts=TS)
print('app-pkix-cert-coverage.pcap: %d frames' % n)
