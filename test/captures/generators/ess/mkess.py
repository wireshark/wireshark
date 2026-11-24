#!/usr/bin/env python3
# Generates test/captures/ess_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic ESS (RFC 2634/5035 Extended Security Services)
coverage captures.

Usage: mkess.py <outdir>

ESS attributes are carried as signed attributes of CMS SignedData,
posted over HTTP with Content-Type application/pkcs7-mime, which is how
Wireshark reaches CMS and ESS by default. Every structure is built with
struct-style BER helpers; nothing comes from a real network. The
signatures are fixed filler octets, not computed.
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


# ---- BER ----

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82, n >> 8, n & 0xff])
    return bytes([tag]) + ln + body


def oid_body(s):
    a = [int(x) for x in s.split('.')]
    out = bytearray([a[0] * 40 + a[1]])
    for v in a[2:]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.insert(0, 0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(enc)
    return bytes(out)


def oid(s):
    return tlv(0x06, oid_body(s))


def integer(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return tlv(0x02, (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big'))


def seq(*items):
    return tlv(0x30, b''.join(items))


def set_(*items):
    return tlv(0x31, b''.join(items))


def octets(b):
    return tlv(0x04, b)


def bits(data, unused=0):
    return tlv(0x03, bytes([unused]) + data)


def utf8(s):
    return tlv(0x0c, s.encode())


def printable(s):
    return tlv(0x13, s.encode())


def gentime(s):
    return tlv(0x18, s.encode())


# ---- OIDs ----

ID_DATA = '1.2.840.113549.1.7.1'
ID_SIGNED = '1.2.840.113549.1.7.2'
ID_CT_RECEIPT = '1.2.840.113549.1.9.16.1.1'
AA = '1.2.840.113549.1.9.16.2.'
AA_RECEIPT_REQUEST = AA + '1'
AA_SECURITY_LABEL = AA + '2'
AA_ML_EXPAND = AA + '3'
AA_CONTENT_HINT = AA + '4'
AA_MSG_SIG_DIGEST = AA + '5'
AA_CONTENT_ID = AA + '7'
AA_EQUIV_LABELS = AA + '9'
AA_CONTENT_REF = AA + '10'
AA_SIGNING_CERT = AA + '12'
AA_SIGNING_CERT_V2 = AA + '47'
PKCS9_CONTENT_TYPE = '1.2.840.113549.1.9.3'
PKCS9_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
SHA256 = '2.16.840.1.101.3.4.2.1'
SHA1 = '1.3.14.3.2.26'
RSA = '1.2.840.113549.1.1.1'
TAG = '2.16.840.1.101.2.1.8.3.'
RESTRICTIVE, ENUM_PERMISSIVE, PERMISSIVE, INFORMATIVE, ENUM_RESTRICTIVE = (
    TAG + '0', TAG + '1', TAG + '2', TAG + '3', TAG + '4')
POLICY = '1.3.6.1.4.1.53148.99.1'      # a security policy without a name


# ---- X.509 / CMS pieces ----

def name(cn):
    return seq(set_(seq(oid('2.5.4.3'), utf8(cn))))


def general_names(*gns):
    return seq(*gns)


def rfc822(s):
    return tlv(0x81, s.encode())


def dns(s):
    return tlv(0x82, s.encode())


def dirname(cn):
    return tlv(0xa4, name(cn))


def alg(o, params=b'\x05\x00'):
    return seq(oid(o), params)


def attribute(o, *values):
    return seq(oid(o), set_(*values))


def signed_data(attrs, econtent_type=ID_DATA, econtent=None):
    # a detached signature unless econtent is given
    encap = seq(oid(econtent_type), tlv(0xa0, octets(econtent)) if econtent else b'')
    signer = seq(
        integer(3),
        tlv(0x80, bytes(range(1, 21))),                  # sid: subjectKeyIdentifier
        alg(SHA256),
        tlv(0xa0, b''.join(attrs)),                      # signedAttrs [0] IMPLICIT SET OF
        alg(RSA),
        octets(b'\x5a' * 32))                             # filler, not a signature
    sd = seq(integer(3), set_(alg(SHA256)), encap, set_(signer))
    return seq(oid(ID_SIGNED), tlv(0xa0, sd))


def base_attrs():
    return [attribute(PKCS9_CONTENT_TYPE, oid(ID_DATA)),
            attribute(PKCS9_MESSAGE_DIGEST, octets(bytes(range(32))))]


# ---- ESS structures ----

def receipt_request(first_tier=True):
    if first_tier:
        frm = tlv(0x80, b'\x01')                         # allOrFirstTier [0] firstTierRecipients
    else:
        frm = tlv(0xa1, general_names(rfc822('alice@example.com')) +
                  general_names(dns('mail.example.org')))
    return seq(octets(b'msg-0001'), frm,
               seq(general_names(rfc822('receipts@example.com'), dirname('Receipt Box'))))


def security_category(type_oid, value):
    return seq(tlv(0x80, oid_body(type_oid)), tlv(0xa1, value))


def restrictive(flags):
    return seq(oid(RESTRICTIVE), bits(flags))


def enumerated(tag_oid, *vals):
    return seq(oid(tag_oid), set_(*[integer(v) for v in vals]))


def permissive(flags):
    return seq(oid(PERMISSIVE), bits(flags, 4))


def informative_bits(flags):
    return seq(oid(INFORMATIVE), bits(flags))


def informative_set(*vals):
    return seq(oid(INFORMATIVE), set_(*[integer(v) for v in vals]))


def security_label(classification=None, privacy=None, categories=None, policy=POLICY):
    items = [oid(policy)]
    if classification is not None:
        items.append(integer(classification))
    if privacy is not None:
        items.append(privacy)
    if categories:
        items.append(set_(*categories))
    return set_(*items)


ALL_CATEGORIES = [
    security_category(RESTRICTIVE, restrictive(b'\xa0\x01')),
    security_category(ENUM_PERMISSIVE, enumerated(ENUM_PERMISSIVE, 1, 5, 300)),
    security_category(PERMISSIVE, permissive(b'\x5a\x30')),
    security_category(INFORMATIVE, informative_bits(b'\x81')),
    security_category(INFORMATIVE, informative_set(2, 7)),
    security_category(ENUM_RESTRICTIVE, enumerated(ENUM_RESTRICTIVE, 3)),
    # a category type without a dissector: shown as unknown BER
    security_category('1.3.6.1.4.1.53148.99.2', octets(b'\x01\x02')),
]


def ml_data(entity, policy=None):
    items = [entity, gentime('20261103120000Z')]
    if policy is not None:
        items.append(policy)
    return seq(*items)


def issuer_serial():
    return seq(general_names(dirname('Synthetic CA')), integer(0x1234))


def ess_cert_id(with_issuer=True):
    items = [octets(bytes(range(20)))]
    if with_issuer:
        items.append(issuer_serial())
    return seq(*items)


def ess_cert_id_v2(with_alg=True, with_issuer=True):
    items = []
    if with_alg:
        items.append(alg(SHA256, b''))
    items.append(octets(bytes(range(32))))
    if with_issuer:
        items.append(issuer_serial())
    return seq(*items)


def policy_info():
    return seq(oid('2.5.29.32.0'))     # anyPolicy


def receipt():
    return seq(integer(1), oid(ID_DATA), octets(b'msg-0001'), octets(b'\x5a' * 32))


# ---- the reproducer of "ESS: Reset the security category OID for each
# category" (from ess_stale_oid.py): a SecurityCategory with a type,
# then one without its [0] type in the next packet ----

def stale_oid_frames():
    enum_tag = enumerated(ENUM_PERMISSIVE, 5)
    value = tlv(0xa1, enum_tag)
    cat1 = seq(tlv(0x80, oid_body(ENUM_PERMISSIVE)) + value)
    cat2 = seq(value + value)
    return [signed_data(base_attrs() + [attribute(AA_SECURITY_LABEL,
                                                  security_label(categories=[c]))])
            for c in (cat1, cat2)]


# ---- HTTP framing ----

def ipv4(src, dst, proto, payload):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                      bytes(src), bytes(dst))
    s = 0
    for i in range(0, 20, 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return hdr[:10] + struct.pack('>H', ~s & 0xffff) + hdr[12:] + payload


class Http:
    """One TCP connection to port 80 carrying HTTP POSTs of CMS
    messages, each answered with an empty 204."""

    def __init__(self, cport=40100):
        self.cport = cport
        self.cseq = 1000
        self.sseq = 50000
        self.frames = []

    def _tcp(self, payload, rev, flags=0x18):
        if rev:
            sp_, dp, seq_, ack = 80, self.cport, self.sseq, self.cseq
            src, dst = [192, 0, 2, 81], [192, 0, 2, 80]
            self.sseq += len(payload) + (1 if flags & 0x02 else 0)
        else:
            sp_, dp, seq_, ack = self.cport, 80, self.cseq, self.sseq
            src, dst = [192, 0, 2, 80], [192, 0, 2, 81]
            self.cseq += len(payload) + (1 if flags & 0x02 else 0)
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS 1460 on SYNs
        tcp = struct.pack('>HHIIBBHHH', sp_, dp, seq_, ack if flags != 0x02 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        a, b = bytes.fromhex('020000000050'), bytes.fromhex('020000000051')
        if rev:
            a, b = b, a
        self.frames.append(b + a + b'\x08\x00' + ipv4(src, dst, 6, tcp))

    def handshake(self):
        self._tcp(b'', False, 0x02)
        self._tcp(b'', True, 0x12)
        self._tcp(b'', False, 0x10)

    def post(self, body, path='/ess'):
        hdr = ('POST %s HTTP/1.1\r\nHost: cms.example.com\r\n'
               'Content-Type: application/pkcs7-mime\r\n'
               'Content-Length: %d\r\n\r\n' % (path, len(body))).encode()
        self._tcp(hdr + body, False)
        self._tcp(b'HTTP/1.1 204 No Content\r\n\r\n', True)


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    h = Http()
    h.handshake()
    # 1: receipt request (first tier), content identifier and hints,
    #    message signature digest, content reference, signing certificates
    h.post(signed_data(base_attrs() + [
        attribute(AA_RECEIPT_REQUEST, receipt_request(True)),
        attribute(AA_CONTENT_ID, octets(b'msg-0001')),
        attribute(AA_CONTENT_HINT, seq(utf8('Synthetic report'), oid(ID_DATA))),
        attribute(AA_MSG_SIG_DIGEST, octets(bytes(range(32, 64)))),
        attribute(AA_CONTENT_REF, seq(oid(ID_DATA), octets(b'msg-0000'), octets(b'\x5a' * 16))),
        attribute(AA_SIGNING_CERT, seq(seq(ess_cert_id(True), ess_cert_id(False)),
                                       seq(policy_info()))),
        attribute(AA_SIGNING_CERT_V2, seq(seq(ess_cert_id_v2(True, True),
                                              ess_cert_id_v2(False, False)),
                                          seq(policy_info()))),
    ]))
    # 2: receipt request with a receipt list, hints without a description,
    #    mailing list expansion history, equivalent labels, certificates
    #    without policies
    h.post(signed_data(base_attrs() + [
        attribute(AA_RECEIPT_REQUEST, receipt_request(False)),
        attribute(AA_CONTENT_HINT, seq(oid(ID_DATA))),
        attribute(AA_ML_EXPAND, seq(
            ml_data(seq(name('List Server'), integer(77))),
            ml_data(octets(b'\x01\x02\x03\x04'), tlv(0x80, b'')),
            ml_data(octets(b'\x05\x06'), tlv(0xa1, general_names(rfc822('a@example.com')))),
            ml_data(octets(b'\x07'), tlv(0xa2, general_names(rfc822('b@example.com')))))),
        attribute(AA_EQUIV_LABELS, seq(security_label(1), security_label(2, printable('R')))),
        attribute(AA_SIGNING_CERT, seq(seq(ess_cert_id(False)))),
        attribute(AA_SIGNING_CERT_V2, seq(seq(ess_cert_id_v2(True, False)))),
    ]))
    # 3: a security label with a classification, a printable privacy mark
    #    and every kind of security category
    h.post(signed_data(base_attrs() + [
        attribute(AA_SECURITY_LABEL, security_label(3, printable('CONFIDENTIAL'),
                                                    ALL_CATEGORIES)),
    ]))
    # 4: a security label with a UTF-8 privacy mark; a minimal one
    h.post(signed_data(base_attrs() + [
        attribute(AA_SECURITY_LABEL, security_label(5, utf8('Vertraulich ä'))),
        attribute(AA_SECURITY_LABEL, security_label(policy='1.2.3.4.5')),
    ]))
    # 5: a signed receipt (content type id-ct-receipt)
    h.post(signed_data(base_attrs()[1:] + [
        attribute(PKCS9_CONTENT_TYPE, oid(ID_CT_RECEIPT)),
        attribute(AA_MSG_SIG_DIGEST, octets(bytes(range(32)))),
    ], ID_CT_RECEIPT, receipt()), '/receipt')
    write_pcap(os.path.join(OUT, 'ess-coverage.pcap'), h.frames)

    # Malformed capture: tag sets without their tag name (for the "ESS
    # Category Attributes" table lookups without an OID), and truncated
    # attributes.
    m = Http(40101)
    m.handshake()
    # The reproducer: its second category has BER errors (no type), so it
    # is here rather than in the main capture.
    for body in stale_oid_frames():
        m.post(body)
    no_name = [
        security_category(ENUM_PERMISSIVE, seq(set_(integer(5)))),
        # empty tag names
        security_category(ENUM_PERMISSIVE, seq(tlv(0x06, b''), set_(integer(5)))),
        security_category(RESTRICTIVE, seq(tlv(0x06, b''), bits(b'\xff'))),
        security_category(INFORMATIVE, seq(tlv(0x06, b''), bits(b'\xff'))),
        security_category(RESTRICTIVE, seq(bits(b'\xff'))),
        security_category(INFORMATIVE, seq(bits(b'\xff'))),
    ]
    m.post(signed_data(base_attrs() + [
        attribute(AA_SECURITY_LABEL, security_label(4, categories=no_name))]))
    full = attribute(AA_SECURITY_LABEL, security_label(3, printable('X'), ALL_CATEGORIES))
    for cut in (10, 25, 40, 60, 90):
        bad = full[:2] + full[2:cut]
        m.post(signed_data(base_attrs() + [bad]))
    rr = attribute(AA_RECEIPT_REQUEST, receipt_request(False))
    m.post(signed_data(base_attrs() + [rr[:len(rr) - 7]]))
    write_pcap(os.path.join(OUT, 'ess-coverage-malformed.pcap'), m.frames)
    print(len(h.frames), len(m.frames))


if __name__ == '__main__':
    main()
