# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""DER builders and PDU sets for the PKIX family dissectors (pkcs10, pkcs12,
pkinit, pkix1explicit, pkix1implicit, pkixac, pkixalgs, pkixproxy,
pkixqualified, pkixtsp). Everything is synthetic: made-up RSA keys, all
zero or filler signatures, no key material and no ciphertext. Builders
copied from the CMS coverage generator."""
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


def exp_pdu(payload, dissector='cms'):
    n = dissector.encode()
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def write_pcap(path, payloads, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(payloads):
            f.write(struct.pack('<IIII', 1793491200 + i, 1000 * i, len(p), len(p)) + p)


def read_pcap(path):
    d = open(path, 'rb').read()
    out = []
    off = 24
    while off < len(d):
        n = struct.unpack('<I', d[off + 8:off + 12])[0]
        out.append(d[off + 16:off + 16 + n])
        off += 16 + n
    return out


# --------------------------------------------------------------------------
# General building blocks

def BMP(s):
    return tlv(0x1e, s.encode('utf-16-be'))


def GENSTR(s):
    return tlv(0x1b, s.encode())


def ctx(n, der):
    """[n] IMPLICIT keeping the constructed bit of the original."""
    return tlv((0xa0 if der[0] & 0x20 else 0x80) | n, body_of(der))


def gn_uri(s):
    return tlv(0x86, s.encode())


def gn_dns(s):
    return tlv(0x82, s.encode())


def gn_email(s):
    return tlv(0x81, s.encode())


def gn_dir(cn):
    return EXPL(4, name(cn))


def gn_other(oid, value):
    return tlv(0xa0, OID(oid) + EXPL(0, value))


def gn_ip(b):
    return tlv(0x87, b)


def ext(oid, value, critical=False):
    return SEQ(OID(oid), BOOL(True) if critical else b'', OCT(value))


def exts(*items):
    return SEQ(*items)


def cert_with(extensions=(), spki=None, sigalg=None, serial=7, cn='host.example', issuer='Example CA',
              version=2):
    tbs = (EXPL(0, INT(version)) if version else b'') + INT(serial) + (sigalg or alg(SHA256_RSA, NULL)) + \
        name(issuer, 'Example') + SEQ(UTC('260101000000Z'), UTC('361231235959Z')) + name(cn, 'Example') + \
        (spki or SEQ(alg(RSA, NULL), RSA_KEY))
    if extensions:
        tbs += EXPL(3, SEQ(*extensions))
    return SEQ(SEQ(tbs), sigalg or alg(SHA256_RSA, NULL), BIT(b'\x5a' * 16))


def cms_signed(certs=(), crls=(), attrcerts=(), content=None, ctype=ID_DATA, signers=(), version=1):
    """ContentInfo(SignedData) with certificate-set entries (raw)."""
    c = list(certs) + [tlv(0xa2, body_of(a)) for a in attrcerts]
    return content_info(ID_SIGNED, signed_data(version, [alg(SHA256, NULL)], encap(ctype, content),
                                               list(signers), certs=c or None, crls=list(crls) or None))


def signer(unsigned=None, signed=None):
    return signer_info(1, SEQ(name('Example CA'), INT(7)), alg(SHA256, NULL), signed=signed,
                       sig_alg=alg(RSA, NULL), unsigned=unsigned)


def keyid(b):
    return b


# --------------------------------------------------------------------------
# Extension values

OID_KP = ['1.3.6.1.5.5.7.3.%d' % i for i in range(1, 10)] + [
    '1.3.6.1.4.1.311.10.12.1', '1.3.6.1.4.1.311.10.3.1', '1.3.6.1.4.1.311.10.3.2', '1.3.6.1.4.1.311.10.3.4',
    '1.3.6.1.4.1.311.10.3.4.1', '1.3.6.1.4.1.311.10.3.5', '1.3.6.1.4.1.311.10.3.6', '1.3.6.1.4.1.311.10.3.7',
    '1.3.6.1.4.1.311.10.3.8', '1.3.6.1.4.1.311.10.3.9', '1.3.6.1.4.1.311.10.3.10']


def ext_eku(oids):
    return ext('2.5.29.37', SEQ(*[OID(o) for o in oids]))


def ext_aia():
    return ext('1.3.6.1.5.5.7.1.1', SEQ(
        SEQ(OID('1.3.6.1.5.5.7.48.1'), gn_uri('http://ocsp.example/')),
        SEQ(OID('1.3.6.1.5.5.7.48.2'), gn_uri('http://ca.example/ca.crt')),
        SEQ(OID('1.3.6.1.5.5.7.48.99'), gn_dns('x.example'))))


def prefix_bits(bits, n):
    nb = (n + 7) // 8
    data = (bytes(bits) + b'\0' * nb)[:nb]
    unused = (8 * nb - n) % 8
    if unused:
        data = data[:-1] + bytes([data[-1] & (0xff << unused) & 0xff])
    return BIT(data, unused)


def ext_ipblocks(safi=False):
    fam4 = OCT(b'\x00\x01' + (b'\x01' if safi else b''))
    fam6 = OCT(b'\x00\x02' + (b'\x02' if safi else b''))
    return ext('1.3.6.1.5.5.7.1.7', SEQ(
        SEQ(fam4, SEQ(prefix_bits([10, 1], 16), SEQ(prefix_bits([192, 0, 2], 24), prefix_bits([192, 0, 3, 255], 32)),
                      prefix_bits([], 0))),
        SEQ(fam6, SEQ(prefix_bits([0x20, 0x01, 0x0d, 0xb8], 32),
                      SEQ(prefix_bits([0x20, 0x01, 0x0d, 0xb9], 32), prefix_bits([0x20, 0x01, 0x0d, 0xb9, 0xff], 40)))),
        SEQ(OCT(b'\x00\x01'), NULL)), critical=True)


def ext_asids():
    return ext('1.3.6.1.5.5.7.1.8', SEQ(
        EXPL(0, SEQ(INT(64512), SEQ(INT(65000), INT(65100)), INT(4200000000))),
        EXPL(1, NULL)), critical=True)


def ext_asids_inherit():
    return ext('1.3.6.1.5.5.7.1.8', SEQ(EXPL(0, NULL)), critical=True)


def ext_tlsfeature():
    return ext('1.3.6.1.5.5.7.1.24', SEQ(INT(5), INT(17)))


def ext_policies():
    qual = SEQ(OID('1.3.6.1.5.5.7.2.1'), IA5('https://cps.example/'))
    unotice = SEQ(OID('1.3.6.1.5.5.7.2.2'), SEQ(SEQ(UTF8('Example'), SEQ(INT(1))), UTF8('Explicit text')))
    return ext('2.5.29.32', SEQ(SEQ(OID('1.2.3.4.5'), SEQ(qual, unotice)), SEQ(OID('2.5.29.32.0'))))


def ext_san(*names):
    return ext('2.5.29.17', SEQ(*names))


def ext_ac_targets():
    return ext('2.5.29.55', SEQ(EXPL(0, gn_dns('a.example')), EXPL(1, gn_dns('g.example')),
                                tlv(0xa2, SEQ(SEQ(gn_dns('i')), INT(1)) + gn_dns('t'))))


def ext_qcstatements():
    return ext('1.3.6.1.5.5.7.1.3', SEQ(
        SEQ(OID('0.4.0.1862.1.1')),
        SEQ(OID('1.3.6.1.5.5.7.11.1'), SEQ(OID('1.2.3'), SEQ(gn_dns('reg.example')))),
        SEQ(OID('1.3.6.1.5.5.7.11.2'), SEQ(SEQ(gn_uri('http://reg.example/')))),
        SEQ(OID('1.3.6.1.5.5.7.11.2'), SEQ()),
        SEQ(OID('0.4.0.1862.1.2'))))


def ext_biometric():
    return ext('1.3.6.1.5.5.7.1.2', SEQ(
        SEQ(INT(0), alg(SHA1, NULL), OCT(b'\x01' * 20), IA5('http://example/b1')),
        SEQ(OID('1.2.3.4.5'), alg(SHA256, NULL), OCT(b'\x02' * 32)),
        SEQ(INT(1), alg(SHA1, NULL), OCT(b'\x03' * 20))))


def ext_subjdirattrs():
    return ext('2.5.29.9', SEQ(
        attr('1.3.6.1.5.5.7.9.1', GT('19700101000000Z')),
        attr('1.3.6.1.5.5.7.9.2', UTF8('Springfield')),
        attr('1.3.6.1.5.5.7.9.2', PRINTABLE('Shelbyville')),
        attr('1.3.6.1.5.5.7.9.3', PRINTABLE('M')),
        attr('1.3.6.1.5.5.7.9.4', PRINTABLE('DE')),
        attr('1.3.6.1.5.5.7.9.5', PRINTABLE('SE'))))


def ext_proxy(pathlen=None, lang='1.3.6.1.5.5.7.21.1', policy=b'policy text'):
    return ext('1.3.6.1.5.5.7.1.14', SEQ(INT(pathlen) if pathlen is not None else b'',
                                          SEQ(OID(lang), OCT(policy) if policy is not None else b'')), critical=True)


def ext_aacontrols(variant=0):
    if variant == 0:
        v = SEQ(INT(3), tlv(0xa0, OID('1.2.3.4') + OID('1.2.3.5')), tlv(0xa1, OID('1.2.3.6')), BOOL(False))
    else:
        v = SEQ()
    return ext('1.3.6.1.5.5.7.1.6', v)


def ext_proxying():
    return ext('1.3.6.1.5.5.7.1.10', SEQ(SEQ(EXPL(0, gn_dns('a.example')), EXPL(1, gn_dns('b.example'))),
                                        SEQ(EXPL(0, gn_dns('c.example')))))


# --------------------------------------------------------------------------
# Algorithm parameters (pkixalgs)

P = INT(0xfffffffffffffffffffffffffffffffeffffffffffffffff)


def ec_specified():
    return SEQ(INT(1), SEQ(OID('1.2.840.10045.1.1'), P),
               SEQ(OCT(b'\xff' * 24), OCT(b'\x64' * 24), BIT(b'\x30' * 20)),
               OCT(b'\x04' + b'\x01' * 48), INT(0xffffffffffffffffffffff99def836146bc9b1b4d22831), INT(1))


def spki_ec(params):
    return SEQ(alg(EC_PUBKEY, params), BIT(b'\x04' + b'\x01' * 64))


def pss_params(variant=0):
    if variant == 0:
        return SEQ(tlv(0xa0, alg(SHA256, NULL)), tlv(0xa1, alg('1.2.840.113549.1.1.8', alg(SHA256, NULL))),
                   tlv(0xa2, INT(32)), tlv(0xa3, INT(1)))
    return SEQ()


def dsa_params():
    return SEQ(INT(0xc0ffee0001), INT(0xc0ffee0003), INT(2))


def dh_params(full=True):
    if full:
        return SEQ(INT(0xc0ffee0001), INT(2), INT(0xc0ffee0003), INT(4),
                   SEQ(BIT(b'\x01\x02\x03\x04'), INT(1024)))
    return SEQ(INT(0xc0ffee0001), INT(2))


def sigalg_certs():
    """Certificates whose signature algorithm OIDs have BER callbacks."""
    oids = [('1.2.840.113549.2.2', None), ('1.2.840.113549.1.1.1', NULL), ('1.2.840.113549.1.1.2', NULL),
            ('1.2.840.113549.1.1.4', NULL), ('1.2.840.113549.1.1.5', NULL), ('1.2.840.113549.1.1.6', NULL),
            ('1.2.840.113549.1.1.11', NULL), ('1.2.840.113549.1.1.12', NULL), ('1.2.840.113549.1.1.13', NULL),
            ('1.2.840.113549.1.1.14', NULL), ('1.2.840.10045.4.1', None), ('1.2.156.10197.1.501', None),
            ('1.2.840.10045.4.3.1', None), ('1.2.840.10045.4.3.2', None), ('1.2.840.10045.4.3.3', None),
            ('1.2.840.10045.4.3.4', None), ('2.16.840.1.101.3.4.3.1', None), ('2.16.840.1.101.3.4.3.2', None),
            ('1.3.101.110', None), ('1.3.101.111', None), ('1.3.101.112', None), ('1.3.101.113', None),
            ('1.3.6.1.5.5.7.6.36', None), ('1.2.840.113549.2.4', NULL), ('1.2.840.113549.2.5', NULL),
            ('1.2.840.113549.1.1.3', NULL)]
    return [cert_with(sigalg=alg(o, p), serial=i + 1) for i, (o, p) in enumerate(oids)]


# --------------------------------------------------------------------------
# Attribute certificates (pkixac)

def attr_cert(attrs, holder=None, issuer=None, extensions=None):
    holder = holder or tlv(0xa1, general_names('Holder'))
    issuer = issuer or general_names('AA')
    info = INT(1) + holder + issuer + alg(SHA256_RSA, NULL) + INT(99) + SEQ(GT('20260101000000Z'), GT('20270101000000Z')) \
        + SEQ(*attrs)
    if extensions:
        info += SEQ(*extensions)
    return SEQ(SEQ(info), alg(SHA256_RSA, NULL), BIT(b'\x5a' * 16))


def ac_attrs():
    ietf = SEQ(tlv(0xa0, body_of(general_names('Authority'))), SEQ(OCT(b'octets'), OID('1.2.3.4'), UTF8('text')))
    svc = SEQ(gn_uri('http://svc.example/'), gn_uri('ident'), OCT(b'password'))
    return [
        attr('1.3.6.1.5.5.7.10.1', svc),
        attr('1.3.6.1.5.5.7.10.2', SEQ(gn_uri('http://svc.example/'), gn_uri('ident'))),
        attr('1.3.6.1.5.5.7.10.3', ietf),
        attr('1.3.6.1.5.5.7.10.4', ietf),
        attr('2.5.4.72', SEQ(tlv(0xa0, body_of(general_names('RA'))), tlv(0xa1, gn_uri('urn:role:admin')))),
        attr('2.5.4.55', SEQ(OID('1.2.3.4'), BIT(b'\xc0', 6),
                             SET(SEQ(tlv(0x80, OID('1.2.3.5')[2:]), tlv(0xa1, UTF8('cat')))))),
        attr('2.5.1.5.55', SEQ(OID('1.2.3.4'))),
    ]


# --------------------------------------------------------------------------
# PKCS#12 (no key material, no ciphertext: filler bytes)

def pbe_params(salt=b'\x11' * 8, it=2048):
    return SEQ(OCT(salt), INT(it))


def safe_bag(oid, value, attrs=None):
    return SEQ(OID(oid), EXPL(0, value), SET(*attrs) if attrs else b'')


def bag_attrs():
    return [SEQ(OID('1.2.840.113549.1.9.20'), SET(BMP('friendly'))),
            SEQ(OID('1.2.840.113549.1.9.21'), SET(OCT(b'\x01\x02\x03\x04'))),
            SEQ(OID('1.3.6.1.4.1.311.17.1'), SET(BMP('provider')))]


def safe_contents(*bags):
    return SEQ(*bags)


def pkcs12_pfx(auth_safe_items, mac=True):
    safe = SEQ(*auth_safe_items)
    pfx = INT(3) + content_info(ID_DATA, OCT(safe))
    if mac:
        pfx += SEQ(SEQ(alg(SHA1, NULL), OCT(b'\x07' * 20)), OCT(b'\x09' * 8), INT(2048))
    return SEQ(pfx)


def pkcs12_sets():
    x509 = cert_with()
    crl_ = crl('Example CA', (1, 2))
    kb = safe_bag('1.2.840.113549.1.12.10.1.1', SEQ(INT(0), alg(RSA, NULL), OCT(b'\xaa' * 16)), bag_attrs())
    skb = safe_bag('1.2.840.113549.1.12.10.1.2', SEQ(alg('1.2.840.113549.1.12.1.3', pbe_params()), OCT(b'\xbb' * 16)),
                   bag_attrs()[:1])
    cb = safe_bag('1.2.840.113549.1.12.10.1.3', SEQ(OID('1.2.840.113549.1.9.22.1'), EXPL(0, OCT(x509))), bag_attrs())
    cb2 = safe_bag('1.2.840.113549.1.12.10.1.3', SEQ(OID('1.2.840.113549.1.9.22.2'), EXPL(0, IA5('sdsi'))))
    crb = safe_bag('1.2.840.113549.1.12.10.1.5', SEQ(OID('1.2.840.113549.1.9.23.1'), EXPL(0, OCT(crl_))))
    sb = safe_bag('1.2.840.113549.1.12.10.1.4', SEQ(OID('1.2.3.4.5'), EXPL(0, OCT(b'secret'))))
    nested = safe_bag('1.2.840.113549.1.12.10.1.6', safe_contents(cb))
    return kb, skb, cb, cb2, crb, sb, nested


def enc_data(calg, content=b'\xcc' * 24):
    """EncryptedData with filler bytes (not real ciphertext)."""
    return content_info(ID_ENCRYPTED, SEQ(INT(0), SEQ(OID(ID_DATA), calg, tlv(0x80, content))))


def pbes2(kdf_salt=None, prf=None, keylen=None):
    salt = OCT(kdf_salt or b'\x22' * 8) if kdf_salt != 'alg' else SEQ(OID('1.2.3.4'))
    kdf = alg(PBKDF2, SEQ(salt, INT(1000), INT(keylen) if keylen else b'', prf or b''))
    return alg('1.2.840.113549.1.5.13', SEQ(kdf, alg(AES128_CBC, OCT(b'\x33' * 16))))


# --------------------------------------------------------------------------
# PKCS#10

def csr(attrs=(), subject=None, spki=None, sigalg=None):
    cri = INT(0) + (subject or name('csr.example', 'Example')) + (spki or SEQ(alg(RSA, NULL), RSA_KEY)) + \
        tlv(0xa0, b''.join(attrs))
    return SEQ(SEQ(cri), sigalg or alg(SHA256_RSA, NULL), BIT(b'\x5a' * 16)), SEQ(cri)


# --------------------------------------------------------------------------
# TSP

def msg_imprint(a=SHA256, n=32):
    return SEQ(alg(a, NULL), OCT(b'\x42' * n))


def tsq(full=True):
    if not full:
        return SEQ(INT(1), msg_imprint())
    return SEQ(INT(1), msg_imprint(), OID('1.2.3.4.1'), INT(0x1122334455667788), BOOL(True),
               tlv(0xa0, ext('1.2.3.4.9', b'\x05\x00')))


def tstinfo(full=True):
    if not full:
        return SEQ(INT(1), OID('1.2.3.4.1'), msg_imprint(), INT(5), GT('20261101120000Z'))
    return SEQ(INT(1), OID('1.2.3.4.1'), msg_imprint(), INT(6), GT('20261101120000.123Z'),
               SEQ(INT(1), tlv(0x80, b'\x01\xf4'), tlv(0x81, b'\x03\xe7')), BOOL(True),
               INT(0x1122334455667788), tlv(0xa0, gn_dir('TSA')), tlv(0xa1, ext('1.2.3.4.9', b'\x05\x00')))


def tsr(status=0, token=None, text=True, fail=None):
    st = INT(status)
    if text:
        st += SEQ(UTF8('granted'), UTF8('second'))
    if fail is not None:
        st += BIT(fail, 0)
    return SEQ(SEQ(st), token or b'')


def tst_token(info=None, unsigned=None):
    return cms_signed(content=info or tstinfo(), ctype='1.2.840.113549.1.9.16.1.4',
                      signers=[signer(unsigned=unsigned)], certs=[cert_with()])


# --------------------------------------------------------------------------
# PKINIT

def kerberos_time(s='20261101120000Z'):
    return GT(s)


def authpack(full=True):
    pa = SEQ(tlv(0xa0, INT(123456)), tlv(0xa1, kerberos_time()), tlv(0xa2, INT(0x1234)),
             tlv(0xa3, OCT(b'\x44' * 20)) if full else b'')
    if not full:
        return SEQ(tlv(0xa0, pa))
    return SEQ(tlv(0xa0, pa),
               tlv(0xa1, SEQ(alg('1.2.840.10046.2.1', dh_params()), BIT(b'\x00' + b'\x05' * 8))),
               tlv(0xa2, SEQ(alg(SHA256_RSA, NULL), alg(RSA, NULL))),
               tlv(0xa3, OCT(b'\x55' * 32)))


def kdc_dh_key_info(full=True):
    return SEQ(tlv(0xa0, BIT(b'\x00\x06' * 4)), tlv(0xa1, INT(0x1234)),
               tlv(0xa2, kerberos_time()) if full else b'')


def krb5_principal(realm='EXAMPLE.COM', names=('user',)):
    return SEQ(tlv(0xa0, GENSTR(realm)), tlv(0xa1, SEQ(tlv(0xa0, INT(1)), tlv(0xa1, SEQ(*[GENSTR(n) for n in names])))))
