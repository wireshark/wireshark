#!/usr/bin/env python3
# Generates test/captures/wlancertextn_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the WLANCERTEXTN dissector
(packet-wlancertextn.c, generated from asn1/wlancertextn: RFC 3770 SSIDList
for the id-pe-wlanSSID certificate extension and the id-aca-wlanSSID
attribute certificate attribute, plus the names of the EAP over PPP and
EAP over LAN extended key usages).

The extension is reached as a real capture would: an X.509 certificate in
a TLS Certificate handshake message on TCP port 443 (cleartext TLS 1.2
server flight: ServerHello, Certificate, ServerHelloDone; nothing is
encrypted). The attribute is inside an attribute certificate in a CMS
SignedData certificate set, carried through Exported PDU (dissector name
cms, which is what e.g. an S/MIME file reaches). pkixlib.py (DER builders)
and rpcgen.py (TCP connections) are helpers copied from other generators;
everything is built with struct: made-up RSA keys, filler signatures, no
key material and no ciphertext.

Usage: mkwlancertextn.py <output directory>

Writes:
  wlancertextn-coverage.pcapng            TLS certificates with SSID lists (1,
                                          several, 1 and 32 octet SSIDs,
                                          critical or not, with the EKU names),
                                          attribute certificates in CMS
  wlancertextn-coverage-malformed.pcapng  SSIDs of 0 and 33 octets, an empty
                                          list, a list that is not a SEQUENCE,
                                          truncated lists
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from pkixlib import (SEQ, OCT, ext, ext_eku, cert_with, attr, attr_cert, cms_signed,  # noqa: E402
                     exp_pdu, ac_attrs, tlv)
from rpcgen import TCP  # noqa: E402

P = struct.pack
OID_PE = '1.3.6.1.5.5.7.1.13'
OID_ACA = '1.3.6.1.5.5.7.10.6'
EKU_PPP, EKU_LAN = '1.3.6.1.5.5.7.3.13', '1.3.6.1.5.5.7.3.14'
DLT_ETH, DLT_EXPDU = 1, 252


def pcapng(path, blocks):
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return P('<II', t, len(body) + 12) + body + P('<I', len(body) + 12)
    o = blk(0x0a0d0d0a, P('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    lts = []
    for lt, _ in blocks:
        if lt not in lts:
            lts.append(lt)
            o += blk(1, P('<HHI', lt, 0, 65535))
    ts = 1793491200 * 1000000
    for lt, d in blocks:
        ts += 1000
        o += blk(6, P('<IIIII', lts.index(lt), ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
    open(path, 'wb').write(o)


def ssid_list(*ssids):
    return SEQ(*[OCT(s) for s in ssids])


def tls_record(typ, body):
    return bytes([typ]) + P('>HH', 0x0303, len(body)) + body


def hs(typ, body):
    return bytes([typ]) + P('>I', len(body))[1:] + body


def client_hello():
    body = P('>H', 0x0303) + bytes(range(32)) + b'\x00' + P('>HH', 2, 0x009c) + b'\x01\x00'
    return tls_record(22, hs(1, body))


def server_flight(*certs):
    sh = hs(2, P('>H', 0x0303) + bytes(range(32, 64)) + b'\x00' + P('>H', 0x009c) + b'\x00')
    cs = b''.join(P('>I', len(c))[1:] + c for c in certs)
    cert = hs(11, P('>I', len(cs))[1:] + cs)
    return tls_record(22, sh + cert + hs(14, b''))


def tls_conn(F, port, *certs_lists):
    t = TCP(F, port, sport=443)
    t.seg(True, client_hello())
    for certs in certs_lists:
        t.seg(False, server_flight(*certs))
    t.fin()


def wlan_cert(*ssids, critical=False, ekus=False, serial=7, raw=None):
    exts = [ext(OID_PE, raw if raw is not None else ssid_list(*ssids), critical)]
    if ekus:
        exts.append(ext_eku([EKU_PPP, EKU_LAN]))
    return cert_with(extensions=exts, serial=serial)


def ac_with(value, **kw):
    return attr_cert([attr(OID_ACA, value)] + kw.get('more', []))


def main_frames():
    frames = []
    eth = []
    tls_conn(eth, 50443,
             [wlan_cert(b'corp-wifi')],
             [wlan_cert(b'guest', b'corp-wifi', b'lab-5G', serial=8, critical=True)],
             [wlan_cert(b'A', serial=9), wlan_cert(b'S' * 32, b'Z', serial=10, ekus=True)])
    tls_conn(eth, 50444,
             [wlan_cert(*[('ssid-%02d' % i).encode() for i in range(20)], serial=11, ekus=True)],
             [wlan_cert(bytes(range(1, 33)), serial=12)])
    frames += [(DLT_ETH, f) for f in eth]
    ac = [
        [ac_with(ssid_list(b'corp-wifi'))],
        [ac_with(ssid_list(b'a', b'b', b'c', b'D' * 32), more=ac_attrs()[:2])],
        [ac_with(ssid_list(b'x' * 5)), ac_with(ssid_list(b'y' * 8))],
    ]
    for acs in ac:
        frames.append((DLT_EXPDU, exp_pdu(cms_signed(attrcerts=acs))))
    return frames


def malformed_frames():
    eth = []
    tls_conn(eth, 50453,
             [wlan_cert(b'', serial=21)],                         # SSID of 0 octets (size 1..32)
             [wlan_cert(b'x' * 33, serial=22)],                   # 33 octets
             [wlan_cert(serial=23)],                              # empty list (SIZE 1..MAX)
             [wlan_cert(raw=OCT(b'notasequence'), serial=24)],    # not a SEQUENCE OF
             [wlan_cert(raw=tlv(0x30, b'\x04\x05abc'), serial=25)],        # SSID longer than the list
             [wlan_cert(raw=SEQ(OCT(b'ok'), tlv(0x02, b'\x01')), serial=26)])   # an INTEGER in the list
    frames = [(DLT_ETH, f) for f in eth]
    for v in (ssid_list(b''), ssid_list(b'x' * 40), SEQ(), OCT(b'x'), tlv(0x30, b'\x04\x09ab')):
        frames.append((DLT_EXPDU, exp_pdu(cms_signed(attrcerts=[ac_with(v)]))))
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(out, 'wlancertextn-coverage.pcapng'), main_frames())
    pcapng(os.path.join(out, 'wlancertextn-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
