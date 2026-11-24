#!/usr/bin/env python3
# Generates test/captures/cms_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CMS dissector
(packet-cms.c, Cryptographic Message Syntax, generated from
epan/dissectors/asn1/cms/).

All packets are built from scratch with struct (BER encoded by hand,
hashlib for the message digests and the PKCS#12 key, RC2 written out
below); no captured traffic is used. Nothing is really signed or
encrypted: signatures, keys and ciphertext are filler octets, except one
EncryptedData that is RC2 encrypted with a PKCS#12 key from the password
"cms" (see runcov.sh).

CMS has no port of its own. Most frames are Exported PDU records
(LINKTYPE_WIRESHARK_UPPER_PDU, 252) naming the "cms" dissector, which
reads one ContentInfo after another; this needs no preference or Decode
As. Two frames carry a ContentInfo the usual way, as the body of an HTTP
message with the media types application/pkcs7-mime and
application/pkcs7-signature, which are registered by default.

Usage: mkcms.py <output directory>

Writes:
  cms-coverage.pcap            every content type, recipient info,
                               certificate and revocation choice, the
                               registered attributes and algorithm
                               parameters, the firmware package types,
                               nested content, the two reproducers
  cms-coverage-malformed.pcap  paths that only malformed input reaches
  cms-coverage.p12             a PKCS#12 PFX with a MAC (DigestInfo), read
                               as a BER file by runcov.sh
  cms-coverage.p7s             a ContentInfo read as a BER file (syntax
                               by file extension) by runcov.sh
"""

import hashlib
import os
import struct
import sys


# --------------------------------------------------------------------------
# BER

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    elif n < 0x10000:
        ln = bytes([0x82]) + struct.pack('>H', n)
    else:
        ln = bytes([0x83]) + struct.pack('>I', n)[1:]
    return bytes([tag]) + ln + body


def body_of(der):
    """The contents octets of a TLV (to re-tag it IMPLICIT)."""
    n = der[1]
    if n < 0x80:
        return der[2:]
    k = n & 0x7f
    return der[2 + k:]


def implicit(tag, der):
    return tlv(tag, body_of(der))


def SEQ(*items):
    return tlv(0x30, b''.join(items))


def SET(*items):
    return tlv(0x31, b''.join(items))


def INT(v):
    n = 1
    while True:
        try:
            return tlv(0x02, v.to_bytes(n, 'big', signed=True))
        except OverflowError:
            n += 1


def ENUM(v):
    return tlv(0x0a, INT(v)[2:])


def OID(s):
    p = [int(x) for x in s.split('.')]
    out = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.insert(0, 0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(enc)
    return tlv(0x06, out)


def OCT(b):
    return tlv(0x04, b)


def BIT(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


NULL = b'\x05\x00'


def BOOL(v):
    return tlv(0x01, b'\xff' if v else b'\x00')


def UTC(s):
    return tlv(0x17, s.encode())


def GT(s):
    return tlv(0x18, s.encode())


def UTF8(s):
    return tlv(0x0c, s.encode())


def PRINTABLE(s):
    return tlv(0x13, s.encode())


def IA5(s):
    return tlv(0x16, s.encode())


def EXPL(n, der):
    """[n] EXPLICIT"""
    return tlv(0xa0 | n, der)


# --------------------------------------------------------------------------
# OIDs

ID_DATA = '1.2.840.113549.1.7.1'
ID_SIGNED = '1.2.840.113549.1.7.2'
ID_ENVELOPED = '1.2.840.113549.1.7.3'
ID_DIGESTED = '1.2.840.113549.1.7.5'
ID_ENCRYPTED = '1.2.840.113549.1.7.6'
ID_AUTHDATA = '1.2.840.113549.1.9.16.1.2'
ID_COMPRESSED = '1.2.840.113549.1.9.16.1.9'
ID_AUTHENVELOPED = '1.2.840.113549.1.9.16.1.23'
ID_CT_CONTENTINFO = '1.2.840.113549.1.9.16.1.6'
ID_ET_PKCS7 = '2.6.1.4.18'
ID_FW_PACKAGE = '1.2.840.113549.1.9.16.1.16'
ID_FW_RECEIPT = '1.2.840.113549.1.9.16.1.17'
ID_FW_ERROR = '1.2.840.113549.1.9.16.1.18'

ATTR_CONTENTTYPE = '1.2.840.113549.1.9.3'
ATTR_DIGEST = '1.2.840.113549.1.9.4'
ATTR_SIGNINGTIME = '1.2.840.113549.1.9.5'
ATTR_COUNTERSIG = '1.2.840.113549.1.9.6'
ATTR_SMIMECAPS = '1.2.840.113549.1.9.15'
ATTR_ENCKEYPREF = '1.2.840.113549.1.9.16.2.11'
ATTR_MS_ENCKEYPREF = '1.3.6.1.4.1.311.16.4'
ATTR_ALGPROTECT = '1.2.840.113549.1.9.52'
ATTR_USERSMIMECERT = '2.16.840.1.113730.3.1.40'
ATTR_FW_ID = '1.2.840.113549.1.9.16.2.35'
ATTR_FW_TARGETHW = '1.2.840.113549.1.9.16.2.36'
ATTR_FW_DECRYPTKEY = '1.2.840.113549.1.9.16.2.37'
ATTR_FW_IMPLCRYPTO = '1.2.840.113549.1.9.16.2.38'
ATTR_FW_WRAPPEDKEY = '1.2.840.113549.1.9.16.2.39'
ATTR_FW_COMMUNITY = '1.2.840.113549.1.9.16.2.40'
ATTR_FW_DIGEST = '1.2.840.113549.1.9.16.2.41'
ATTR_FW_INFO = '1.2.840.113549.1.9.16.2.42'
ATTR_FW_IMPLCOMPRESS = '1.2.840.113549.1.9.16.2.43'
ON_HWMODULENAME = '1.3.6.1.5.5.7.8.4'

SHA1 = '1.3.14.3.2.26'
MD5 = '1.2.840.113549.2.5'
SHA256 = '2.16.840.1.101.3.4.2.1'
RSA = '1.2.840.113549.1.1.1'
SHA256_RSA = '1.2.840.113549.1.1.11'
ECDSA_SHA256 = '1.2.840.10045.4.3.2'
EC_PUBKEY = '1.2.840.10045.2.1'
HMAC_SHA256 = '1.2.840.113549.2.9'
DES_EDE3_CBC = '1.2.840.113549.3.7'
RC2_CBC = '1.2.840.113549.3.2'
ID_ALG_RC4 = '1.2.840.113549.3.4'
CMS3DESWRAP = '1.2.840.113549.1.9.16.3.6'
CMSRC2WRAP = '1.2.840.113549.1.9.16.3.7'
AES128_WRAP = '2.16.840.1.101.3.4.1.5'
AES192_WRAP = '2.16.840.1.101.3.4.1.25'
AES256_WRAP = '2.16.840.1.101.3.4.1.45'
AES128_GCM = '2.16.840.1.101.3.4.1.6'
AES192_GCM = '2.16.840.1.101.3.4.1.26'
AES256_GCM = '2.16.840.1.101.3.4.1.46'
AES128_CCM = '2.16.840.1.101.3.4.1.7'
AES192_CCM = '2.16.840.1.101.3.4.1.27'
AES256_CCM = '2.16.840.1.101.3.4.1.44'
AES128_CBC = '2.16.840.1.101.3.4.1.2'
ECKA_SHA256 = '0.4.0.127.0.7.1.1.5.1.1.3'
DH_STD_SHA256 = '1.3.132.1.11.1'
DH_COFACTOR_SHA1 = '1.3.133.16.840.63.0.3'
MQV_SHA1 = '1.3.133.16.840.63.0.16'
PBKDF2 = '1.2.840.113549.1.5.12'
PBE_SHA_RC2_40 = '1.2.840.113549.1.12.1.6'
ZLIB = '1.2.840.113549.1.9.16.3.8'
PWRI_KEK = '1.2.840.113549.1.9.16.3.9'


# --------------------------------------------------------------------------
# X.509 building blocks

def name(cn, org=None):
    rdns = []
    if org:
        rdns.append(SET(SEQ(OID('2.5.4.10'), PRINTABLE(org))))
    rdns.append(SET(SEQ(OID('2.5.4.3'), UTF8(cn))))
    return SEQ(*rdns)


def alg(oid, params=None):
    return SEQ(OID(oid), params if params is not None else b'')


def iasn(cn, serial):
    """IssuerAndSerialNumber"""
    return SEQ(name(cn), INT(serial))


RSA_KEY = BIT(SEQ(INT(0x00c0ffee12345679), INT(65537)))


def certificate(cn, issuer, serial, extensions=b''):
    tbs = EXPL(0, INT(2)) + INT(serial) + alg(SHA256_RSA, NULL) + name(issuer, 'Example') + \
        SEQ(UTC('260101000000Z'), UTC('361231235959Z')) + name(cn, 'Example') + \
        SEQ(alg(RSA, NULL), RSA_KEY)
    if extensions:
        tbs += EXPL(3, SEQ(extensions))
    return SEQ(SEQ(tbs), alg(SHA256_RSA, NULL), BIT(b'\x5a' * 16))


def crl(issuer, revoked=()):
    tbs = INT(1) + alg(SHA256_RSA, NULL) + name(issuer, 'Example') + UTC('261101000000Z') + \
        UTC('261201000000Z')
    if revoked:
        tbs += SEQ(*[SEQ(INT(s), UTC('261015120000Z')) for s in revoked])
    return SEQ(SEQ(tbs), alg(SHA256_RSA, NULL), BIT(b'\xa5' * 16))


def general_names(*cns):
    return SEQ(*[EXPL(4, name(cn)) for cn in cns])


# --------------------------------------------------------------------------
# CMS building blocks

def attr(oid, *values):
    return SEQ(OID(oid), SET(*values))


def content_info(oid, content):
    return SEQ(OID(oid), EXPL(0, content))


def encap(oid, content=None):
    return SEQ(OID(oid), EXPL(0, OCT(content)) if content is not None else b'')


def signer_info(version, sid, digest_alg, signed=None, sig_alg=None, sig=b'\x00' * 16,
                unsigned=None):
    b = INT(version) + sid + digest_alg
    if signed is not None:
        b += tlv(0xa0, b''.join(signed))
    b += sig_alg if sig_alg is not None else alg(RSA, NULL)
    b += OCT(sig)
    if unsigned is not None:
        b += tlv(0xa1, b''.join(unsigned))
    return SEQ(b)


def signed_data(version, digest_algs, encap_ci, signers, certs=None, crls=None):
    b = INT(version) + SET(*digest_algs) + encap_ci
    if certs is not None:
        b += tlv(0xa0, b''.join(certs))
    if crls is not None:
        b += tlv(0xa1, b''.join(crls))
    b += SET(*signers)
    return SEQ(b)


def originator_info(certs=None, crls=None):
    b = b''
    if certs is not None:
        b += tlv(0xa0, b''.join(certs))
    if crls is not None:
        b += tlv(0xa1, b''.join(crls))
    return tlv(0xa0, b)


def eci(ctype, calg, content=None):
    """EncryptedContentInfo"""
    return SEQ(OID(ctype), calg, tlv(0x80, content) if content is not None else b'')


def ktri(version, rid, kalg, key):
    return SEQ(INT(version), rid, kalg, OCT(key))


def ski(b):
    """[0] SubjectKeyIdentifier"""
    return tlv(0x80, b)


def other_key_attr(oid, value=None):
    return SEQ(OID(oid), value if value is not None else b'')


def kari(originator, kalg, reks, ukm=None):
    b = INT(3) + EXPL(0, originator)
    if ukm is not None:
        b += EXPL(1, OCT(ukm))
    b += kalg + SEQ(*reks)
    return tlv(0xa1, b)


def kekri(kekid, kalg, key):
    return tlv(0xa2, INT(4) + kekid + kalg + OCT(key))


def pwri(kdf, kalg, key):
    return tlv(0xa3, INT(0) + (implicit(0xa0, kdf) if kdf is not None else b'') + kalg +
               OCT(key))


def ori(oid, value):
    return tlv(0xa4, OID(oid) + value)


def enveloped_data(version, ris, enc_ci, orig=None, unprot=None):
    b = INT(version) + (orig or b'') + SET(*ris) + enc_ci
    if unprot is not None:
        b += tlv(0xa1, b''.join(unprot))
    return SEQ(b)


def preferred(oid, ver):
    return SEQ(OID(oid), INT(ver))


# --------------------------------------------------------------------------
# RC2 and the PKCS#12 key derivation (RFC 7292 appendix B) for the one
# EncryptedData that the pkcs12 password preference decrypts

def pkcs12_key(password, salt, iterations, idbyte, length):
    d = bytes([idbyte]) * 64
    s = (salt * (64 // len(salt) + 1))[:64]
    p = (password.encode('utf-16-be') + b'\0\0')
    p = (p * (64 // len(p) + 1))[:64]
    a = d + s + p
    for _ in range(iterations):
        a = hashlib.sha1(a).digest()
    assert length <= 20
    return a[:length]


# RC2 (RFC 2268)

PITABLE = bytes.fromhex(
    'd978f9c419ddb5ed28e9fd794aa0d89d' 'c67e37832b76538e624c6488448bfba2'
    '179a59f587b34f1361456d8d09817d32' 'bd8f40eb86b77b0bf09521225c6b4e82'
    '54d66593ce60b21c7356c014a78cf1dc' '1275ca1f3bbee4d1423dd430a33cb626'
    '6fbf0eda4669075727f21d9bbc944303' 'f811c7f690ef3ee706c3d52fc8661ed7'
    '08e8eade8052eef784aa72ac354d6a2a' '961ad2715a1549744b9fd05e0418a4ec'
    'c2e0416e0f51cbcc2491af50a1f47039' '997c3a8523b8b47afc02365b25559731'
    '2d5dfa98e38a92ae05df2910676cbac9' 'd300e6cfe19ea82c6316013f58e289a9'
    '0d38341bab33ffb0bb480c5fb9b1cd2e' 'c5f3db47e5a59c770aa62068fe7fc1ad')
assert len(set(PITABLE)) == 256


def rc2_key(key, bits):
    T = len(key)
    L = list(key) + [0] * (128 - T)
    for i in range(T, 128):
        L[i] = PITABLE[(L[i - 1] + L[i - T]) & 0xff]
    T8 = (bits + 7) // 8
    TM = 0xff % (1 << (8 + bits - 8 * T8))
    L[128 - T8] = PITABLE[L[128 - T8] & TM]
    for i in range(127 - T8, -1, -1):
        L[i] = PITABLE[L[i + 1] ^ L[i + T8]]
    return [L[2 * i] | (L[2 * i + 1] << 8) for i in range(64)]

def rc2_block(K, blk):
    R = [blk[2 * i] | (blk[2 * i + 1] << 8) for i in range(4)]
    s = (1, 2, 3, 5)
    j = 0
    def mix():
        nonlocal j
        for i in range(4):
            R[i] = (R[i] + K[j] + (R[i - 1] & R[i - 2]) + ((~R[i - 1]) & R[i - 3])) & 0xffff
            j += 1
            R[i] = ((R[i] << s[i]) | (R[i] >> (16 - s[i]))) & 0xffff
    def mash():
        for i in range(4):
            R[i] = (R[i] + K[R[i - 1] & 63]) & 0xffff
    for _ in range(5): mix()
    mash()
    for _ in range(6): mix()
    mash()
    for _ in range(5): mix()
    return b''.join(bytes([r & 0xff, r >> 8]) for r in R)

def rc2_40_cbc(key, iv, data):
    """RC2 with 40 effective key bits in CBC mode, PKCS#5 padded."""
    pad = 8 - len(data) % 8
    data += bytes([pad]) * pad
    K = rc2_key(key, 40)
    out, prev = b'', iv
    for i in range(0, len(data), 8):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 8], prev))
        prev = rc2_block(K, blk)
        out += prev
    return out


PBE_PASSWORD = 'cms'
PBE_SALT = b'\x01\x02\x03\x04\x05\x06\x07\x08'


# --------------------------------------------------------------------------
# Carriers

def exp_pdu(payload, dissector='cms'):
    n = dissector.encode()
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def tcp_frame(src, dst, sport, dport, seq, ack, payload):
    """Ethernet/IPv4/TCP, raw (no Ethernet: carried as an Exported PDU
    record for the "eth_withoutfcs" dissector so the file has one link
    type)."""
    hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack('>H', ip_checksum(pseudo + hdr + payload)) + hdr[18:]
    l4 = hdr + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0x4000, 64, 6, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
    eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
    return eth + ip + l4


def write_pcap(path, records):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, r in enumerate(records):
            f.write(struct.pack('<IIII', 1793534400 + i, 0, len(r), len(r)))
            f.write(r)


# --------------------------------------------------------------------------
# The messages

CONTENT = b'Hello, CMS world.\r\n'


def certs_all():
    """One of each CertificateChoices."""
    san = SEQ(OID('2.5.29.17'), OCT(SEQ(
        tlv(0xa0, OID(ON_HWMODULENAME) + EXPL(0, SEQ(OID('1.3.6.1.4.1.99999.1'),
                                                     OCT(b'SN-0001')))))))
    cert = certificate('Alice', 'Example CA', 0x1001, san)
    ext_cert = implicit(0xa0, SEQ(
        SEQ(INT(0), certificate('Bob', 'Example CA', 0x1002),
            SET(attr(ATTR_SIGNINGTIME, UTC('261101120000Z')))),
        alg(SHA256_RSA, NULL), BIT(b'\x11' * 8)))
    v1_ac = implicit(0xa1, SEQ(
        SEQ(INT(0),
            implicit(0xa0, SEQ(general_names('Example CA'), INT(0x1001))),
            general_names('Example AA'),
            alg(SHA256_RSA, NULL), INT(77),
            SEQ(GT('20261101000000Z'), GT('20271101000000Z')),
            SEQ(attr(ATTR_CONTENTTYPE, OID(ID_DATA))),
            BIT(b'\x01\x02'),
            SEQ(SEQ(OID('2.5.29.56'), NULL and b'' or OCT(NULL)))),
        alg(SHA256_RSA, NULL), BIT(b'\x22' * 8)))
    v1_ac_name = implicit(0xa1, SEQ(
        SEQ(implicit(0xa1, general_names('Carol')),
            general_names('Example AA'),
            alg(SHA256_RSA, NULL), INT(78),
            SEQ(GT('20261101000000Z'), GT('20271101000000Z')),
            SEQ()),
        alg(SHA256_RSA, NULL), BIT(b'\x23' * 8)))
    v2_ac = implicit(0xa2, SEQ(
        SEQ(INT(1),
            EXPL(0, SEQ(general_names('Example CA'), INT(0x1001))),
            general_names('Example AA'),
            alg(SHA256_RSA, NULL), INT(79),
            SEQ(GT('20261101000000Z'), GT('20271101000000Z')),
            SEQ(SEQ(OID('2.5.4.3'), SET(UTF8('admin'))))),
        alg(SHA256_RSA, NULL), BIT(b'\x33' * 8)))
    return [cert, ext_cert, v1_ac, v1_ac_name, v2_ac]


def crls_all():
    return [crl('Example CA', (0x0999, 0x0998)),
            implicit(0xa1, SEQ(OID(ATTR_SIGNINGTIME), UTC('261101000000Z')))]


def smime_caps():
    """SMIMECapabilities with every registered parameter type."""
    caps = [
        SEQ(OID(AES256_CBC := '2.16.840.1.101.3.4.1.42')),
        SEQ(OID(RC2_CBC), INT(128)),                       # RC2 wrap parameter: bits
        SEQ(OID(RC2_CBC), SEQ(INT(58), OCT(b'\x01' * 8))),  # RC2 CBC parameter
        SEQ(OID(ID_ALG_RC4), INT(40)),
        SEQ(OID(DES_EDE3_CBC), OCT(b'\x02' * 8)),
        SEQ(OID(CMS3DESWRAP), NULL),
        SEQ(OID(CMSRC2WRAP), INT(58)),
        SEQ(OID(AES128_WRAP), alg(AES128_CBC)),
        SEQ(OID(AES192_WRAP), alg(AES128_CBC)),
        SEQ(OID(AES256_WRAP), alg(AES128_CBC)),
        SEQ(OID(AES128_GCM), SEQ(OCT(b'\x03' * 12))),
        SEQ(OID(AES192_GCM), SEQ(OCT(b'\x03' * 12), INT(16))),
        SEQ(OID(AES256_GCM), SEQ(OCT(b'\x03' * 12), INT(12))),
        SEQ(OID(AES128_CCM), SEQ(OCT(b'\x04' * 7))),
        SEQ(OID(AES192_CCM), SEQ(OCT(b'\x04' * 13), INT(8))),
        # .44 is id-aes256-CFB in pkixalgs, which wins over CMS's CCM
        SEQ(OID(AES256_CCM), SEQ(OCT(b'\x04' * 16))),
        SEQ(OID(ECKA_SHA256), alg(AES128_WRAP)),
        SEQ(OID('0.4.0.127.0.7.1.1.5.1.1.4'), alg(AES192_WRAP)),
        SEQ(OID('0.4.0.127.0.7.1.1.5.1.1.5'), alg(AES256_WRAP)),
        SEQ(OID(DH_STD_SHA256), alg(AES128_WRAP)),
        SEQ(OID(DH_COFACTOR_SHA1), alg(AES128_WRAP)),
        SEQ(OID(MQV_SHA1), alg(AES128_WRAP)),
        SEQ(OID('1.3.6.1.4.1.99999.2')),                    # no parameters
    ]
    return SEQ(*caps)


def signed_full():
    """SignedData with every optional part, three signers and a
    countersignature."""
    sha1 = hashlib.sha1(CONTENT).digest()
    signer1 = signer_info(
        1, iasn('Example CA', 0x1001), alg(SHA1, NULL),
        signed=[
            attr(ATTR_DIGEST, OCT(sha1)),                       # [correct]
            attr(ATTR_CONTENTTYPE, OID(ID_DATA)),
            attr(ATTR_SIGNINGTIME, UTC('261101120000Z')),
            attr(ATTR_SMIMECAPS, smime_caps()),
            attr(ATTR_ENCKEYPREF, implicit(0xa0, iasn('Example CA', 0x1001))),
            attr(ATTR_ENCKEYPREF, implicit(0xa1, SEQ(OCT(b'\x0a' * 20),
                                                     GT('20261101000000Z'),
                                                     other_key_attr(ATTR_SIGNINGTIME,
                                                                    UTC('261101000000Z'))))),
            attr(ATTR_ENCKEYPREF, tlv(0x82, b'\x0b' * 20)),
            attr(ATTR_MS_ENCKEYPREF, iasn('Example CA', 0x1001)),
            attr(ATTR_ALGPROTECT, SEQ(alg(SHA1, NULL), implicit(0xa1, alg(RSA, NULL)))),
            attr(ON_HWMODULENAME, SEQ(OID('1.3.6.1.4.1.99999.1'), OCT(b'SN-0002'))),
        ],
        sig_alg=alg(RSA, NULL), sig=b'\x5a' * 32,
        unsigned=[
            attr(ATTR_COUNTERSIG, signer_info(
                3, ski(b'\x0c' * 20), alg(SHA256, NULL),
                signed=[attr(ATTR_SIGNINGTIME, GT('20261101120005Z'))],
                sig_alg=alg(ECDSA_SHA256), sig=b'\x5b' * 16)),
        ])
    signer2 = signer_info(
        3, ski(b'\x0d' * 20), alg(MD5, NULL),
        signed=[attr(ATTR_DIGEST, OCT(b'\x00' * 16)),              # [incorrect]
                attr(ATTR_ALGPROTECT, SEQ(alg(MD5, NULL), implicit(0xa2, alg(HMAC_SHA256))))],
        sig_alg=alg(SHA256_RSA, NULL))
    signer3 = signer_info(
        1, iasn('Example CA', 0x1003), alg(SHA256, NULL),
        signed=[attr(ATTR_DIGEST, OCT(hashlib.sha256(CONTENT).digest()))],  # [unable]
        sig_alg=alg(SHA256_RSA, NULL))
    signer4 = signer_info(1, iasn('Example CA', 0x1004), alg(SHA1, NULL))  # no attrs
    sd = signed_data(3, [alg(SHA1, NULL), alg(MD5, NULL), alg(SHA256)],
                     encap(ID_DATA, CONTENT), [signer1, signer2, signer3, signer4],
                     certs=certs_all(), crls=crls_all())
    return content_info(ID_SIGNED, sd)


def signed_detached():
    """A detached SignedData with no certificates (digest not checked)."""
    sd = signed_data(1, [alg(SHA1, NULL)], encap(ID_DATA), [
        signer_info(1, iasn('Example CA', 0x1001), alg(SHA1, NULL),
                    signed=[attr(ATTR_CONTENTTYPE, OID(ID_DATA)),
                            attr(ATTR_DIGEST, OCT(b'\x99' * 20))])])
    return content_info(ID_SIGNED, sd)


def signed_certs_only():
    """A degenerate SignedData (certs-only, .p7c style): no signers, an
    unknown eContent type without content, certificates and an empty CRL
    set."""
    sd = signed_data(1, [], encap('1.3.6.1.4.1.99999.43'),
                     [], certs=[certificate('Dave', 'Example CA', 0x1005)], crls=[])
    return content_info(ID_SIGNED, sd)


def enveloped_full():
    """EnvelopedData with an originator info and every recipient info."""
    ris = [
        ktri(0, iasn('Example CA', 0x1001), alg(RSA, NULL), b'\x41' * 32),
        ktri(2, ski(b'\x0e' * 20), alg('1.2.840.113549.1.1.7'), b'\x42' * 32),
        kari(iasn('Example CA', 0x1006), alg(DH_STD_SHA256, alg(AES128_WRAP)),
             [SEQ(iasn('Example CA', 0x1007), OCT(b'\x43' * 24)),
              SEQ(implicit(0xa0, SEQ(OCT(b'\x10' * 20))), OCT(b'\x44' * 24))],
             ukm=b'\x45' * 8),
        kari(ski(b'\x0f' * 20), alg(DH_COFACTOR_SHA1, alg(AES192_WRAP)),
             [SEQ(implicit(0xa0, SEQ(OCT(b'\x11' * 20), GT('20261101000000Z'),
                                     other_key_attr(ATTR_CONTENTTYPE, OID(ID_DATA)))),
                  OCT(b'\x46' * 24))]),
        kari(implicit(0xa1, SEQ(alg(EC_PUBKEY, OID('1.2.840.10045.3.1.7')),
                                BIT(b'\x04' + b'\x47' * 64))),
             alg(MQV_SHA1, alg(AES256_WRAP)),
             [SEQ(implicit(0xa0, SEQ(OCT(b'\x12' * 20), GT('20261101000000Z'))),
                  OCT(b'\x48' * 24))]),
        kekri(SEQ(OCT(b'KEK-1'), GT('20261101000000Z'),
                  other_key_attr('1.3.6.1.4.1.99999.3')),
              alg(AES128_WRAP), b'\x49' * 24),
        kekri(SEQ(OCT(b'KEK-2')), alg(CMS3DESWRAP, NULL), b'\x4a' * 40),
        pwri(alg(PBKDF2, SEQ(OCT(b'salt'), INT(2048))), alg(AES128_WRAP), b'\x4c' * 32),
        pwri(None, alg(CMS3DESWRAP, NULL), b'\x4e' * 32),
        ori(ATTR_SIGNINGTIME, UTC('261101000000Z')),
    ]
    ed = enveloped_data(
        2, ris,
        eci(ID_DATA, alg(DES_EDE3_CBC, OCT(b'\x4f' * 8)), b'\x50' * 32),
        orig=originator_info(certs=[certificate('Eve', 'Example CA', 0x1008)],
                             crls=[crl('Example CA')]),
        unprot=[attr(ATTR_SIGNINGTIME, UTC('261101000000Z'))])
    return content_info(ID_ENVELOPED, ed)


def enveloped_simple():
    """EnvelopedData version 0, RC2 with an RC2 CBC parameter, no
    encrypted content (it is detached)."""
    ed = enveloped_data(
        0, [ktri(0, iasn('Example CA', 0x1001), alg(RSA, NULL), b'\x51' * 16)],
        eci(ID_DATA, alg(RC2_CBC, SEQ(INT(58), OCT(b'\x52' * 8)))),
        orig=originator_info())
    return content_info(ID_ENVELOPED, ed)


def digested():
    dd = SEQ(INT(0), alg(SHA1, NULL), encap(ID_DATA, CONTENT),
             OCT(hashlib.sha1(CONTENT).digest()))
    return content_info(ID_DIGESTED, dd)


def encrypted():
    ed = SEQ(INT(2), eci('1.3.6.1.4.1.99999.41', alg(AES128_CBC, OCT(b'\x53' * 16)),
                         b'\x54' * 32),
             tlv(0xa1, attr(ATTR_CONTENTTYPE, OID('1.3.6.1.4.1.99999.41')) +
                 attr('1.3.6.1.4.1.99999.42')))
    return content_info(ID_ENCRYPTED, ed)


def encrypted_pbe():
    """EncryptedData with pbeWithSHAAnd40BitRC2-CBC: with -o
    pkcs12.password:cms it decrypts to a DigestedData."""
    clear = SEQ(INT(0), alg(SHA1, NULL), encap(ID_DATA, b'secret'),
                OCT(hashlib.sha1(b'secret').digest()))
    key = pkcs12_key(PBE_PASSWORD, PBE_SALT, 1, 1, 5)
    iv = pkcs12_key(PBE_PASSWORD, PBE_SALT, 1, 2, 8)
    ct = rc2_40_cbc(key, iv, clear)
    ed = SEQ(INT(0), eci(ID_DIGESTED, alg(PBE_SHA_RC2_40, SEQ(OCT(PBE_SALT), INT(1))), ct))
    return content_info(ID_ENCRYPTED, ed)


def authenticated():
    ad = SEQ(INT(0),
             originator_info(certs=[certificate('Frank', 'Example CA', 0x1009)]),
             SET(ktri(0, iasn('Example CA', 0x1009), alg(RSA, NULL), b'\x55' * 16)),
             alg(HMAC_SHA256),
             implicit(0xa1, alg(SHA1, NULL)),
             encap(ID_DATA, CONTENT),
             tlv(0xa2, attr(ATTR_CONTENTTYPE, OID(ID_DATA)) +
                 attr(ATTR_DIGEST, OCT(hashlib.sha1(CONTENT).digest()))),
             OCT(b'\x56' * 32),
             tlv(0xa3, attr(ATTR_SIGNINGTIME, UTC('261101000000Z'))))
    return content_info(ID_AUTHDATA, ad)


def compressed():
    """id-ct-compressedData is registered as EncryptedContentInfo."""
    return content_info(ID_COMPRESSED, eci(ID_DATA, alg(ZLIB), b'\x78\x9c\x03\x00\x00\x00\x00\x01'))


def auth_enveloped():
    ae = SEQ(INT(0),
             originator_info(crls=[crl('Example CA', (0x0997,))]),
             SET(kekri(SEQ(OCT(b'KEK-3')), alg(AES256_WRAP), b'\x57' * 40)),
             eci(ID_DATA, alg(AES128_GCM, SEQ(OCT(b'\x58' * 12), INT(16))), b'\x59' * 24),
             tlv(0xa1, attr(ATTR_CONTENTTYPE, OID(ID_DATA))),
             OCT(b'\x5c' * 16),
             tlv(0xa2, attr(ATTR_SIGNINGTIME, UTC('261101000000Z'))))
    return content_info(ID_AUTHENVELOPED, ae)


def nested():
    """ContentInfo in id-ct-contentInfo, and a SignedData whose eContent
    is another SignedData (dissected in the outer tree)."""
    inner_sd = signed_data(1, [alg(SHA1, NULL)], encap(ID_DATA, b'inner'), [])
    outer_sd = signed_data(1, [alg(SHA1, NULL)], encap(ID_SIGNED, inner_sd), [])
    return content_info(ID_CT_CONTENTINFO, content_info(ID_CT_CONTENTINFO,
                                                        content_info(ID_SIGNED, outer_sd)))


def et_pkcs7_and_user_cert():
    """id-et-pkcs7 and userSMIMECertificate as attribute values."""
    sd = signed_data(1, [], encap(ID_DATA), [],
                     certs=[certificate('Grace', 'Example CA', 0x100a)])
    signer = signer_info(1, iasn('Example CA', 0x100a), alg(SHA1, NULL), signed=[
        attr(ID_ET_PKCS7, content_info(ID_DATA, OCT(b'pkcs7'))),
        attr(ATTR_USERSMIMECERT, sd)])
    return content_info(ID_SIGNED, signed_data(1, [alg(SHA1, NULL)], encap(ID_DATA), [signer]))


def firmware_package():
    """A firmware package (RFC 4108) with every firmware attribute."""
    pkg = b'\x7fELF' + bytes(range(60))
    fw_ed = enveloped_data(0, [kekri(SEQ(OCT(b'FW-KEK')), alg(AES128_WRAP), b'\x60' * 24)],
                           eci(ID_DATA, alg(AES128_CBC, OCT(b'\x61' * 16))))
    signer = signer_info(3, ski(b'\x13' * 20), alg(SHA256, NULL), signed=[
        attr(ATTR_CONTENTTYPE, OID(ID_FW_PACKAGE)),
        attr(ATTR_DIGEST, OCT(hashlib.sha256(OCT(pkg)).digest())),
        attr(ATTR_FW_ID, SEQ(preferred('1.3.6.1.4.1.99999.10', 3), INT(2))),
        attr(ATTR_FW_ID, SEQ(OCT(b'legacy-pkg-1.0'), OCT(b'legacy-pkg-0.9'))),
        attr(ATTR_FW_ID, SEQ(OCT(b'legacy-pkg-1.1'))),
        attr(ATTR_FW_TARGETHW, SEQ(OID('1.3.6.1.4.1.99999.20'), OID('1.3.6.1.4.1.99999.21'))),
        attr(ATTR_FW_DECRYPTKEY, OCT(b'FW-KEK')),
        attr(ATTR_FW_IMPLCRYPTO, SEQ(OID(AES128_CBC), OID(SHA256))),
        attr(ATTR_FW_IMPLCOMPRESS, SEQ(OID(ZLIB))),
        attr(ATTR_FW_COMMUNITY, SEQ(
            OID('1.3.6.1.4.1.99999.30'),
            SEQ(OID('1.3.6.1.4.1.99999.20'),
                SEQ(NULL, OCT(b'SN-0003'), SEQ(OCT(b'SN-0100'), OCT(b'SN-0199')))))),
        attr(ATTR_FW_INFO, SEQ(INT(1), SEQ(preferred('1.3.6.1.4.1.99999.11', 1),
                                           OCT(b'bootloader-2')))),
        attr(ATTR_FW_INFO, SEQ()),
        attr(ATTR_FW_WRAPPEDKEY, fw_ed),
        attr(ATTR_FW_DIGEST, SEQ(alg(SHA256), OCT(hashlib.sha256(pkg).digest()))),
    ], sig_alg=alg(ECDSA_SHA256))
    sd = signed_data(3, [alg(SHA256)], encap(ID_FW_PACKAGE, OCT(pkg)), [signer])
    return content_info(ID_SIGNED, sd)


def firmware_receipt():
    r1 = SEQ(INT(1), OID('1.3.6.1.4.1.99999.20'), OCT(b'SN-0003'),
             preferred('1.3.6.1.4.1.99999.10', 3), OCT(b'\x14' * 20), tlv(0x81, b'FW-KEK'))
    r2 = SEQ(OID('1.3.6.1.4.1.99999.20'), OCT(b'SN-0004'), OCT(b'legacy-pkg-1.0'))
    sd1 = signed_data(3, [alg(SHA256)], encap(ID_FW_RECEIPT, r1), [])
    sd2 = signed_data(3, [alg(SHA256)], encap(ID_FW_RECEIPT, r2), [])
    return content_info(ID_SIGNED, sd1) + content_info(ID_SIGNED, sd2)


def firmware_errors():
    e1 = SEQ(INT(1), OID('1.3.6.1.4.1.99999.20'), OCT(b'SN-0003'), ENUM(28), INT(4711),
             preferred('1.3.6.1.4.1.99999.10', 3),
             tlv(0xa1, SEQ(INT(1), preferred('1.3.6.1.4.1.99999.10', 4)) +
                 SEQ(OCT(b'bootloader-2'))))
    e2 = SEQ(OID('1.3.6.1.4.1.99999.20'), OCT(b'SN-0004'), ENUM(99))
    out = b''
    for e in (e1, e2):
        out += content_info(ID_SIGNED, signed_data(3, [alg(SHA256)], encap(ID_FW_ERROR, e), []))
    return out


def firmware_pkg_data():
    """id-ct-firmwarePackage directly as the content of a ContentInfo."""
    return content_info(ID_FW_PACKAGE, OCT(b'\x7fELF' + b'\0' * 12))


def http_post(media_type, body):
    """An HTTP request carrying the body with a CMS media type."""
    hdr = ('POST /smime HTTP/1.1\r\nHost: cms.example\r\nContent-Type: %s\r\n'
           'Content-Length: %d\r\n\r\n' % (media_type, len(body))).encode()
    return hdr + body


# --------------------------------------------------------------------------
# The reproducers of "CMS: Stop nested content before the layer limit,
# keep digests apart" (cms_recursion.py and
# cms_stale_content.py), built the same way.

def repro_recursion(depth):
    inner = SEQ(OID(ID_DATA), EXPL(0, OCT(b'x')))
    for _ in range(depth):
        inner = SEQ(OID(ID_CT_CONTENTINFO), EXPL(0, inner))
    return inner


def repro_stale_content():
    sha1alg = SEQ(OID(SHA1), NULL)
    rsaalg = SEQ(OID(RSA), NULL)

    def sd(econtent, digest):
        enc = OID(ID_DATA) + (EXPL(0, OCT(econtent)) if econtent is not None else b'')
        a = SEQ(OID(ATTR_DIGEST), SET(OCT(digest)))
        si = SEQ(INT(3), tlv(0x80, b'\x01\x02\x03\x04'), sha1alg, tlv(0xa0, a), rsaalg,
                 OCT(b'\x00' * 8))
        s = SEQ(INT(3), SET(sha1alg), SEQ(enc), SET(si))
        return SEQ(OID(ID_SIGNED), EXPL(0, s))

    d = hashlib.sha1(b'hello').digest()
    return sd(b'hello', d) + sd(None, d)


def main_records():
    R = []
    R.append(exp_pdu(signed_full()))                     # 1
    R.append(exp_pdu(signed_detached()))                 # 2
    R.append(exp_pdu(signed_certs_only()))               # 3
    R.append(exp_pdu(enveloped_full()))                  # 4
    R.append(exp_pdu(enveloped_simple()))                # 5
    R.append(exp_pdu(digested()))                        # 6
    R.append(exp_pdu(encrypted()))                       # 7
    R.append(exp_pdu(encrypted_pbe()))                   # 8
    R.append(exp_pdu(authenticated()))                   # 9
    R.append(exp_pdu(compressed()))                      # 10
    R.append(exp_pdu(auth_enveloped()))                  # 11
    R.append(exp_pdu(nested()))                          # 12
    R.append(exp_pdu(et_pkcs7_and_user_cert()))          # 13
    R.append(exp_pdu(firmware_package()))                # 14
    R.append(exp_pdu(firmware_receipt()))                # 15
    R.append(exp_pdu(firmware_errors()))                 # 16
    R.append(exp_pdu(firmware_pkg_data()))               # 17
    # 18-19: the usual carriers, HTTP bodies with the S/MIME media types
    R.append(exp_pdu(http_post('application/pkcs7-mime; smime-type=enveloped-data',
                               enveloped_simple()), 'http'))
    R.append(exp_pdu(http_post('application/pkcs7-signature', signed_detached()), 'http'))
    # 20-21: the reproducers
    R.append(exp_pdu(repro_stale_content()))
    R.append(exp_pdu(repro_recursion(REPRO_DEPTH)))
    return R


REPRO_DEPTH = 600


def malformed_records():
    R = []
    # 1: a messageDigest after a digest algorithm without an OID (no
    #    algorithm to verify with)
    sd = signed_data(1, [alg(SHA1, NULL)], encap(ID_DATA, CONTENT), [
        signer_info(1, iasn('Example CA', 0x1001), SEQ(),
                    signed=[attr(ATTR_DIGEST, OCT(b'\x00' * 20))])])
    R.append(exp_pdu(content_info(ID_SIGNED, sd)))
    # 2: a firmware package whose eContent is not an OCTET STRING
    sd = signed_data(3, [alg(SHA256)], encap(ID_FW_PACKAGE, b'\x7fELF' + bytes(60)), [])
    R.append(exp_pdu(content_info(ID_SIGNED, sd)))
    # 3: SignedData cut short
    R.append(exp_pdu(signed_full()[:300]))
    # 4: EnvelopedData cut short
    R.append(exp_pdu(enveloped_full()[:500]))
    # 5: a ContentInfo with an unknown content type and garbage after it
    R.append(exp_pdu(content_info('1.3.6.1.4.1.99999.40', OCT(b'x')) + b'\x01\x02'))
    # 6-9: things that are not OIDs where OIDs belong
    R.append(exp_pdu(SEQ(INT(1), EXPL(0, OCT(b'x')))))
    sd = signed_data(1, [alg(SHA1, NULL)], encap(ID_DATA, CONTENT), [
        signer_info(1, iasn('Example CA', 0x1001), alg(SHA1, NULL),
                    signed=[SEQ(INT(4), SET(OCT(b'x'))),
                            attr(ATTR_SMIMECAPS, SEQ(SEQ(INT(5), INT(6))))])])
    R.append(exp_pdu(content_info(ID_SIGNED, sd)))
    sd = signed_data(1, [alg(SHA1, NULL)], SEQ(OID(ID_DATA), EXPL(0, INT(7))), [])
    R.append(exp_pdu(content_info(ID_SIGNED, sd)))
    # 9: a messageDigest shorter than SHA-1 (shown as correct)
    sd = signed_data(1, [alg(SHA1, NULL)], encap(ID_DATA, CONTENT), [
        signer_info(1, iasn('Example CA', 0x1001), alg(SHA1, NULL),
                    signed=[attr(ATTR_DIGEST, OCT(b'\x00' * 4))])])
    R.append(exp_pdu(content_info(ID_SIGNED, sd)))
    # 10: the recursion reproducer at its original depth of 10000 (stops
    #    with the expert info; 177 kB)
    R.append(exp_pdu(repro_recursion(10000)))
    return R


def pfx():
    """A PKCS#12 PFX: its MacData holds the only DigestInfo, a CMS type
    that nothing in CMS itself uses."""
    safe = SEQ(content_info(ID_DATA, OCT(SEQ())))
    return SEQ(INT(3), content_info(ID_DATA, OCT(safe)),
               SEQ(SEQ(alg(SHA1, NULL), OCT(b'\x62' * 20)), OCT(b'\x63' * 8), INT(2048)))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cms-coverage.pcap'), main_records())
    write_pcap(os.path.join(out, 'cms-coverage-malformed.pcap'), malformed_records())
    # BER files, read through the file extension (runcov.sh only)
    with open(os.path.join(out, 'cms-coverage.p12'), 'wb') as f:
        f.write(pfx())
    with open(os.path.join(out, 'cms-coverage.p7s'), 'wb') as f:
        f.write(signed_full())


if __name__ == '__main__':
    main()
