#!/usr/bin/env python3
# Generates test/captures/ftam_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the FTAM dissector
(packet-ftam.c, generated from epan/dissectors/asn1/ftam/ISO8571-FTAM.asn).

FTAM (ISO 8571) runs over the OSI upper layers on TCP port 102 (TPKT,
COTP, session, presentation, ACSE), all registered by default. The
association uses the application context iso-ftam (1.0.8571.1.1) and the
abstract syntax ftam-pci (1.0.8571.2.1); F-INITIALIZE is carried in the
ACSE AARQ/AARE user information, everything else in P-DATA.

The FTAM PDUs are not typed by hand: asn1enc.py reads ISO8571-FTAM.asn
and generates BER for every alternative of PDU (all 73 request and
response PDUs), filling the optional components, rotating through the
CHOICE alternatives and nesting the recursive types to a limited depth.

Usage: mkftam.py <output directory>

Writes:
  ftam-coverage.pcap            the associations
  ftam-coverage-malformed.pcap  truncated and bogus PDUs
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from asn1enc import Gen
from x500lib import (Assoc, INT, tlv, write_pcap)

HERE = os.path.dirname(os.path.abspath(__file__))
# The ASN.1 module(s) of the tree.
ASN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..', 'epan', 'dissectors', 'asn1', 'ftam')
AC_FTAM = '1.0.8571.1.1'
AS_FTAM = '1.0.8571.2.1'
AS_TEXT = '1.0.8571.5.1'
AS_BINARY = '1.0.8571.5.3'
CTX_FTAM = 3
CTX_TEXT = 5
CTX_BINARY = 7


def user_info(pci, pdu):
    """ACSE user-information [30]: an EXTERNAL with the presentation
    context id and the PDU."""
    return tlv(0xbe, tlv(0x28, INT(pci), tlv(0xa0, pdu)))


class FtamAssoc(Assoc):
    def __init__(self, frames, cport, init_req, init_resp):
        super().__init__(frames, cport, AC_FTAM,
                         [(CTX_FTAM, AS_FTAM), (CTX_TEXT, AS_TEXT), (CTX_BINARY, AS_BINARY)])
        self.init_req = init_req
        self.init_resp = init_resp

    def open(self):
        super().open(user_info(CTX_FTAM, self.init_req), user_info(CTX_FTAM, self.init_resp))


def main(out):
    g = Gen(open(os.path.join(ASN_DIR, 'ISO8571-FTAM.asn')).read(), seed=7)
    alts = dict(g.pdu_alternatives())
    frames = []
    # association 1: F-INITIALIZE in the AARQ/AARE (full), then every other PDU
    g.mode = 'full'
    a = FtamAssoc(frames, 40001, g.enc(alts['f-initialize-request']), g.enc(alts['f-initialize-response']))
    a.open()
    names = [n for n in alts if not n.startswith('f-initialize')]
    for variant in ('full', 'min', 'mix', 'mix'):
        g.mode = variant
        for i, n in enumerate(names):
            a.pdata(i % 2 == 0, g.enc(alts[n]))
    # file content in the text and binary document types
    a.pdata(True, b'FTAM unstructured text\r\nsecond line', ctx=CTX_TEXT)
    a.pdata(True, bytes(range(40)), ctx=CTX_BINARY)
    a.pdata(False, b'plain text without BER encoding', ctx=CTX_TEXT)
    # two PDUs in one P-DATA
    g.mode = 'min'
    a.pdata(True, g.enc(alts['f-read-request']) + g.enc(alts['f-data-end-request']))
    a.close()
    # association 2: minimal F-INITIALIZE
    g.mode = 'min'
    b = FtamAssoc(frames, 40002, g.enc(alts['f-initialize-request']), g.enc(alts['f-initialize-response']))
    b.open()
    g.mode = 'mix'
    for n in ('f-select-request', 'f-select-response', 'f-open-request', 'f-open-response',
              'f-terminate-request', 'f-terminate-response'):
        b.pdata(n.endswith('request'), g.enc(alts[n]))
    b.close()
    write_pcap(os.path.join(out, 'ftam-coverage.pcap'), frames)

    # malformed
    bad = []
    g.mode = 'full'
    m = FtamAssoc(bad, 40003, g.enc(alts['f-initialize-request']), g.enc(alts['f-initialize-response']))
    m.open()
    pdu = g.enc(alts['f-open-request'])
    m.pdata(True, pdu[:len(pdu) // 2])                 # truncated
    m.pdata(True, b'\x00\x00')                         # zero tag, zero length
    m.pdata(True, tlv(0x5f, b'\x01\x02'))              # tag not in PDU
    m.pdata(True, tlv(0xa0, b'\xff\xff\xff'))          # bogus initialize request
    m.pdata(True, tlv(0xa6, b''))                      # empty select request
    m.pdata(True, tlv(0xbf, b'\x20\x00'))              # indefinite-ish tag
    # nesting through Contents-Type-Attribute/document-type/parameter with
    # document-type-name 1.0.8571.1.1, which dissects an FTAM PDU again
    def blen(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(b)]) + b

    def tl(tag, c):
        return tag + blen(len(c)) + c
    oid = bytes([0x4E, 5, 0x28, 0xC2, 0x7B, 1, 1])

    def level(inner):
        doc = tl(b'\xa0', oid + (tl(b'\xa0', inner) if inner is not None else b''))
        return tl(b'\xaf', tl(b'\x7f\x12', tl(b'\xa2', doc)))
    p = None
    for _ in range(60):
        p = level(p)
    m.pdata(False, p)
    m.close()
    write_pcap(os.path.join(out, 'ftam-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1])
