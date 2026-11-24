# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers for the X.400 coverage generators (P1, P22, P7, P772):
OR names and addresses (X.411), a pcapng writer with an Ethernet and an
Exported PDU interface, and the Exported PDU / CRL carriers. The BER and
OSI upper layer helpers are in x500lib.py. Everything is built with
struct; no captured traffic is used."""

import struct

from x500lib import (  # noqa: F401,
    aare, aarq, Assoc, certificate, CTX_ACSE, DN_ADMIN, external, fully_encoded, OID_ACSE,
    oid_enc, pdv, pres_cp, pres_cpa, presentation_address, ros_invoke, ros_result, rtoac, rtorq,
    ses_ac, ses_cn, ses_param_userdata, spdu, user_info,
)
from x500lib import (tlv, INT, OID, SEQ, SET, X, PSTR, OCTS, BITS, BOOL, NULL, ENUM,
                     UTCT, GENT, tpkt, cotp_cr, cotp_cc, cotp_dt)


# ------------------------------------------------------------ strings

def NSTR(s, tag=0x12):
    return tlv(tag, s.encode())


def TSTR(s, tag=0x14):          # TeletexString
    return tlv(tag, s.encode())


def IA5(s, tag=0x16):
    return tlv(tag, s.encode())


def BMP(s, tag=0x1e):
    return tlv(tag, s.encode('utf-16-be'))


def UNIV(s, tag=0x1c):
    return tlv(tag, s.encode('utf-32-be'))


def VSTR(s, tag=0x15):          # VideotexString
    return tlv(tag, s.encode())


def GSTR(s, tag=0x1b):          # GeneralString
    return tlv(tag, s.encode())


def retag(tag, enc):
    """Replace the outer tag of a BER encoding (IMPLICIT tagging)."""
    return bytes([tag]) + enc[1:]


def imp(n, enc, constructed=None):
    """IMPLICIT context tag [n] over an encoding."""
    if constructed is None:
        constructed = bool(enc[0] & 0x20)
    return retag(0x80 | n | (0x20 if constructed else 0), enc)


def app(n, enc):
    """IMPLICIT [APPLICATION n] over an encoding."""
    return retag(0x40 | n | (enc[0] & 0x20), enc)


# --------------------------------------------------------- X.411 names

def universal(s, lang=None, four=False):
    """UniversalOrBMPString (SET)."""
    body = UNIV(s) if four else BMP(s)
    if lang:
        body += PSTR(lang)
    return SET(body)


def pdsparam(printable=None, teletex=None):
    body = b''
    if printable is not None:
        body += PSTR(printable)
    if teletex is not None:
        body += TSTR(teletex)
    return SET(body)


def ext_attr(n, value):
    """ExtensionAttribute: [0] type, [1] EXPLICIT (open type) value."""
    return SEQ(INT(n, 0x80), X(1, value))


def personal_name(surname='Smith', given='Alice', initials='AS', gen='Jr', tag=0xa5,
                  string=lambda s, t: PSTR(s, t)):
    body = string(surname, 0x80)
    if given:
        body += string(given, 0x81)
    if initials:
        body += string(initials, 0x82)
    if gen:
        body += string(gen, 0x83)
    return tlv(tag, body)


def country(s='AU'):
    return tlv(0x61, NSTR(s) if s.isdigit() else PSTR(s))


def admd(s=' ', numeric=False):
    return tlv(0x62, NSTR(s) if numeric else PSTR(s))


def prmd(s='Example', numeric=False):
    return tlv(0xa2, NSTR(s) if numeric else PSTR(s))


def orname(country_name='AU', admd_name=' ', prmd_name='Example', org='Org', ous=('Sales',),
           personal=True, ddas=(('type', 'value'),), ext=(), dn=None, numeric_user=None,
           network=None, terminal=None, cn_numeric=False, admd_numeric=False,
           prmd_numeric=False):
    """ORName [APPLICATION 0]."""
    bis = b''
    if country_name is not None:
        bis += country(country_name)
    if admd_name is not None:
        bis += admd(admd_name, admd_numeric)
    if network is not None:
        bis += NSTR(network, 0x80)
    if terminal is not None:
        bis += PSTR(terminal, 0x81)
    if prmd_name is not None:
        bis += prmd(prmd_name, prmd_numeric)
    if org is not None:
        bis += PSTR(org, 0x83)
    if numeric_user is not None:
        bis += NSTR(numeric_user, 0x84)
    if personal:
        bis += personal_name()
    if ous:
        bis += tlv(0xa6, *[PSTR(o) for o in ous])
    body = SEQ(bis)
    if ddas:
        body += SEQ(*[SEQ(PSTR(t), PSTR(v)) for t, v in ddas])
    if ext:
        body += SET(*ext)
    if dn is not None:
        body += X(0, dn)
    return tlv(0x60, body)


def or_address(**kw):
    """ORAddress (an ORName without the application tag and directory name)."""
    kw.pop('dn', None)
    n = orname(**kw)
    return retag(0x30, n)


def name_only(dn_enc):
    """ORName with only a directory-name."""
    return tlv(0x60, SEQ(b''), X(0, dn_enc))


# All 40 extension attributes (the type number and a valid value)
def all_ext_attrs(alt=False):
    pds = pdsparam('printable', 'teletex')
    upds = universal('universal pds', 'en')
    out = [
        ext_attr(1, PSTR('common')),
        ext_attr(2, TSTR('teletex common')),
        ext_attr(3, TSTR('teletex org')),
        ext_attr(4, personal_name(string=lambda s, t: TSTR(s, t), tag=0x31)),
        ext_attr(5, SEQ(TSTR('tou1'), TSTR('tou2'))),
        ext_attr(6, SEQ(SEQ(TSTR('tt'), TSTR('tv')))),
        ext_attr(7, PSTR('pds name')),
        ext_attr(8, NSTR('036') if alt else PSTR('AU')),
        ext_attr(9, PSTR('2000-A') if alt else NSTR('2000')),
        ext_attr(10, pds),
        ext_attr(11, pds),
        ext_attr(12, pds),
        ext_attr(13, pds),
        ext_attr(14, pds),
        ext_attr(15, pds),
        ext_attr(16, SET(SEQ(PSTR('line 1'), PSTR('line 2')), TSTR('teletex address'))),
        ext_attr(17, pds),
        ext_attr(18, pds),
        ext_attr(19, pds),
        ext_attr(20, pds),
        ext_attr(21, pds),
        ext_attr(22, SEQ(NSTR('61299999999', 0x80), NSTR('12', 0x81))),
        ext_attr(23, INT(5)),
        ext_attr(24, universal('universal common', 'en')),
        ext_attr(25, universal('universal org', None, True)),
        ext_attr(26, SET(tlv(0xa0, BMP('Smith')), tlv(0xa1, UNIV('Alice')),
                         tlv(0xa2, BMP('A'), PSTR('en')), tlv(0xa3, BMP('Jr')))),
        ext_attr(27, SEQ(universal('unit1'), universal('unit2', 'en-US'))),
        ext_attr(28, SEQ(SEQ(universal('t'), universal('v')))),
        ext_attr(29, upds),
        ext_attr(30, upds),
        ext_attr(31, upds),
        ext_attr(32, upds),
        ext_attr(33, upds),
        ext_attr(34, upds),
        ext_attr(35, upds),
        ext_attr(36, upds),
        ext_attr(37, upds),
        ext_attr(38, upds),
        ext_attr(39, upds),
        ext_attr(40, upds),
    ]
    return out


# --------------------------------------------------------- X.501 names

def attr_value_dn(*attrs):
    """A Name (RDNSequence) from (oid, value) pairs, one RDN each."""
    return SEQ(*[SET(SEQ(OID(t), v)) for t, v in attrs])


# ------------------------------------------------------------- pcapng

def _block(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)


class Pcapng:
    """pcapng with interface 0 = Ethernet, interface 1 = Exported PDU
    (linktype 252). add(frame, iface) keeps the frame order."""

    def __init__(self, t0=1793491200):
        self.t = t0
        self.out = _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in (1, 252):
            self.out += _block(1, struct.pack('<HHI', lt, 0, 262144))
        self.n = 0

    def add(self, frame, iface=0):
        ts = (self.t + self.n) * 1000000
        self.out += _block(6, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff,
                                          len(frame), len(frame)) + frame)
        self.n += 1

    def eth(self, frames):
        for f in frames:
            self.add(f, 0)

    def exp(self, name, payload):
        self.add(exp_pdu(name, payload), 1)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(self.out)


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + \
        struct.pack('!HH', 0, 0) + payload


# -------------------------------------------------- X.509 CRL carrier

SHA256RSA = '1.2.840.113549.1.1.11'


def crl_with_issuer(*attrs):
    """A CRL whose issuer Name has one RDN per (attribute OID, value):
    the attribute value is dissected through the BER OID table, so any
    dissector that registered the OID in ber.oid is reached
    (Exported PDU "x509af")."""
    alg = SEQ(OID(SHA256RSA), NULL())
    issuer = attr_value_dn(*attrs)
    tbs = SEQ(INT(1), alg, issuer, UTCT('260101000000Z'))
    return SEQ(tbs, alg, BITS(0, b'\x00'))


def GRAPH(s, tag=0x19):         # GraphicString
    return tlv(tag, s.encode())


def global_domain_id(c='AU', a=' ', p='Example', numeric=False):
    """GlobalDomainIdentifier [APPLICATION 3]."""
    body = country(c) + admd(a)
    if p is not None:
        body += NSTR(p) if numeric else PSTR(p)
    return app(3, SEQ(body))


def message_id(local='msg-0001', **kw):
    """MessageIdentifier / MTSIdentifier-like SEQUENCE."""
    return SEQ(global_domain_id(**kw), IA5(local))


def eits(bits=b'\x05\x60', ext=('1.2.3.9',)):
    """EncodedInformationTypes [APPLICATION 5]."""
    body = BITS(bits[0], bits[1:], 0x80)
    if ext:
        body += tlv(0xa4, *[OID(o) for o in ext])
    return app(5, SET(body))


def crl_with_exts(*exts):
    """A CRL whose crlExtensions carry (OID, DER value) pairs: the
    extnValue OCTET STRING is dissected through the BER OID table
    without x509if's string formatting (Exported PDU "x509af")."""
    alg = SEQ(OID(SHA256RSA), NULL())
    issuer = attr_value_dn(('2.5.4.3', PSTR('Test CA')))
    ex = SEQ(*[SEQ(OID(o), OCTS(v)) for o, v in exts])
    tbs = SEQ(INT(1), alg, issuer, UTCT('260101000000Z'), X(0, ex))
    return SEQ(tbs, alg, BITS(0, b'\x00'))


# ------------------------------------------------- security building blocks

ALG_RSA = '1.2.840.113549.1.1.5'


def alg_id(oid=ALG_RSA, params=None):
    return SEQ(OID(oid), NULL() if params is None else params)


def signature(oid=ALG_RSA):
    """Signature ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }."""
    return SEQ(alg_id(oid), BITS(0, b'\x5a' * 8))


def sec_label(cats=False):
    body = OID('1.2.3.10') + INT(3) + PSTR('mark')
    if cats:
        body += SET(SEQ(OID('2.6.4.3.6', 0x80), X(1, INT(2))))
    return SET(body)


def token_signed_data():
    return SEQ(imp(0, alg_id('1.2.840.113549.3.7', OCTS(b'12345678'))),
               imp(1, signature()), imp(2, sec_label()), ENUM(1, 0x83), INT(7, 0x84))


def token_encrypted_data():
    return SEQ(BITS(0, b'\x01\x02', 0x80), imp(1, signature()), imp(2, sec_label()),
               BITS(0, b'\x03', 0x83), INT(8, 0x84))


def asymmetric_token(name='recipient', data_type=2, enc=False):
    """MessageToken ::= Token (SEQUENCE { [0] type OID, [1] AsymmetricToken })
    holding an AsymmetricToken whose data is a TokenData of the given
    type (1 BindTokenSignedData, 2 MessageTokenSignedData, 3 and 4
    the encrypted ones)."""
    if data_type == 1:
        val = BITS(0, b'\x01\x02\x03')
    elif data_type == 2:
        val = token_signed_data()
    elif data_type == 3:
        val = token_encrypted_data()
    else:
        val = tlv(0x28, INT(1), OCTS(b'bind token data', 0x81))
    tdata = SEQ(INT(data_type, 0x80), X(1, val))
    nm = orname() if name == 'recipient' else tlv(0xa3, global_domain_id(), IA5('mta.example'))
    body = alg_id() + nm + UTCT() + imp(0, tdata)
    if enc:
        body += imp(1, alg_id()) + BITS(0, b'\x09', 0x82)
    atd = SEQ(body)
    return SEQ(atd, alg_id(), BITS(0, b'\x01\x02'))


def asym_token(name='recipient', data_type=2, enc=False):
    """Token: SEQUENCE { [0] type OID, [1] EXPLICIT AsymmetricToken }."""
    return SEQ(OID('2.6.3.6.0', 0x80), X(1, asymmetric_token(name, data_type, enc)))


# =================================================================== P1 / P3

def mts_id(local='msg-0001', **kw):
    """MTSIdentifier [APPLICATION 4]."""
    return app(4, SEQ(global_domain_id(**kw), IA5(local)))


def content_id(s='cid-1'):
    return app(10, PSTR(s))


def priority(p=0):
    return app(7, ENUM(p))


def per_message_indicators(bits=b'\x00\xa0'):
    return app(8, BITS(bits[0], bits[1:]))


def content_type(v=2):
    """ContentType: built-in [APPLICATION 6] INTEGER or an OID."""
    if isinstance(v, str):
        return OID(v)
    return app(6, INT(v))


def delivered_content_type(v=2):
    if isinstance(v, str):
        return OID(v)
    return imp(0, app(6, INT(v)), False)


def ext_field(ext, value=None, crit=None):
    """ExtensionField: standard-extension [0] INTEGER or private [3] OID,
    optional criticality [1], value [2] EXPLICIT."""
    body = OID(ext, 0x83) if isinstance(ext, str) else INT(ext, 0x80)
    if crit is not None:
        body += BITS(crit[0], crit[1:], 0x81)
    if value is not None:
        body += X(2, value)
    return SEQ(body)


def certificates():
    return SEQ(certificate())


def domain_supplied(attempted=False, additional=False, action=0):
    body = UTCT(tag=0x80) + ENUM(action, 0x82)
    if attempted:
        body += global_domain_id(p='Attempted')
    if additional:
        body += UTCT(tag=0x81) + eits() + BITS(6, b'\xc0', 0x83)
    return SET(body)


def trace_element(attempted=False, additional=False, action=0):
    return SEQ(global_domain_id(), domain_supplied(attempted, additional, action))


def trace_info(n=2):
    """TraceInformation [APPLICATION 9]."""
    return app(9, SEQ(*[trace_element(i % 2 == 1, i % 2 == 0, i % 2) for i in range(n)],
                      SEQ(global_domain_id('036', '0', '123', True), domain_supplied())))


def internal_trace_element(attempt='mta'):
    body = UTCT(tag=0x80) + ENUM(0, 0x82)
    if attempt == 'mta':
        body += IA5('attempted.example')
    elif attempt == 'domain':
        body += global_domain_id(p='Other')
    return SEQ(global_domain_id(), IA5('mta1.example'), SET(body))


def ext_values():
    """standard-extension number -> value (the extensions P1 registers)."""
    cert = certificates()
    sig = signature()
    return {
        1: ENUM(1), 2: orname(), 3: ENUM(1), 4: ENUM(1), 5: UTCT(),
        6: SEQ(INT(1), INT(4), INT(9)), 7: ENUM(1), 8: ENUM(1),
        9: BITS(0, b'\xa0'), 10: INT(1), 11: TSTR('advice-1'),
        12: OID('1.2.3.20'), 13: or_address(), 14: INT(2),
        15: cert, 16: asym_token(), 17: alg_id('1.2.840.113549.3.7', OCTS(b'12345678')),
        18: sig, 19: sig, 20: sec_label(True), 21: ENUM(1), 22: ENUM(1),
        23: IA5('correlator'), 24: sig,
        25: SEQ(SEQ(SEQ(orname(), UTCT()), ENUM(3))),
        26: SEQ(SEQ(orname(), UTCT()), SEQ(orname(prmd_name='Second'), UTCT())),
        27: orname(), 28: cert, 29: sig,
        30: SEQ(SEQ(orname(), UTCT()), SEQ(orname(prmd_name='Second'), UTCT())),
        31: orname(), 32: cert, 33: sig, 34: cert, 35: sig,
        37: trace_info(2),
        38: SEQ(internal_trace_element('mta'), internal_trace_element('domain'),
                internal_trace_element(None)),
        39: SEQ(global_domain_id(), IA5('rep-mta'), tlv(0xa0, DN_ADMIN)),
        40: SET(tlv(0xa0, DN_ADMIN), imp(1, cert)),
        42: SET(orname(), orname(prmd_name='Second')),
        45: SET(imp(0, SEQ(INT(5, 0x80))), imp(1, SEQ(INT(6, 0x80))),
                imp(2, SEQ(INT(7, 0x80))), imp(3, SEQ(INT(8, 0x80))),
                imp(4, SEQ(INT(9, 0x80)))),
    }


def all_ext_fields(numbers=None):
    vals = ext_values()
    return [ext_field(n, v, crit=b'\x05\xa0' if n % 3 == 0 else None)
            for n, v in vals.items() if numbers is None or n in numbers]


def recipient_submission(name=None, report=b'\x03\x10', conv=None, ext=()):
    body = (name if name is not None else orname()) + BITS(report[0], report[1:], 0x80)
    if conv is not None:
        body += INT(conv, 0x81)
    if ext:
        body += tlv(0xa2, *ext)
    return SET(body)


def submission_envelope(ctype=2, cid=True, ext=(), rext=(), nrecip=2, deferred=True, eit=True,
                        orig=None, rnames=None):
    body = orig if orig is not None else orname()
    if eit:
        body += eits()
    body += content_type(ctype)
    if cid:
        body += content_id()
    body += priority(1) + per_message_indicators()
    if deferred:
        body += UTCT(tag=0x80)
    if ext:
        body += tlv(0xa2, *ext)
    recips = [recipient_submission(rnames[i] if rnames else orname(prmd_name='Dest%d' % i),
                                    ext=rext if i == 0 else (), conv=11 if i else None)
              for i in range(nrecip)]
    body += tlv(0xa1, *recips)
    return SET(body)


def submission_arg(env=None, content=b'content data'):
    return SEQ(env if env is not None else submission_envelope(), OCTS(content))


def probe_envelope(ctype=2, ext=(), rext=()):
    body = orname() + eits() + content_type(ctype) + content_id()
    body += INT(1000, 0x80)
    body += per_message_indicators()
    if ext:
        body += tlv(0xa2, *ext)
    body += tlv(0xa3, recipient_submission(ext=rext), recipient_submission(orname(prmd_name='D2')))
    return SET(body)


# ---------------------------------------------------- P1 transfer (MTA)

def bilateral_info():
    """PerDomainBilateralInformation (the bilateral-information is an ANY)."""
    return SEQ(country(), admd(), OCTS(b'bilateral'))


def bilateral_info_private():
    return SEQ(country(), SEQ(imp(0, admd('PD')), tlv(0xa1, PSTR('Prmd'))), OCTS(b'bilateral2'))


def per_recipient_transfer(name=None, num=1, ind=b'\x00\x90', conv=None, ext=()):
    body = (name if name is not None else orname()) + INT(num, 0x80) + BITS(ind[0], ind[1:], 0x81)
    if conv is not None:
        body += INT(conv, 0x82)
    if ext:
        body += tlv(0xa3, *ext)
    return SET(body)


def message_transfer_envelope(ctype=22, ext=(), rext=(), nrecip=2, bilateral=True, cid=True):
    body = mts_id() + orname() + eits() + content_type(ctype)
    if cid:
        body += content_id()
    body += priority(2) + per_message_indicators() + UTCT(tag=0x80)
    if bilateral:
        body += tlv(0xa1, bilateral_info(), bilateral_info_private())
    body += trace_info(2)
    if ext:
        body += tlv(0xa3, *ext)
    body += tlv(0xa2, *[per_recipient_transfer(orname(prmd_name='Dest%d' % i), i + 1,
                                               conv=11 if i else None, ext=rext if i == 0 else ())
                        for i in range(nrecip)])
    return SET(body)


def message_apdu(content=b'content', ctype=22, **kw):
    """MTS-APDU message [0]."""
    return tlv(0xa0, message_transfer_envelope(ctype, **kw), OCTS(content))


def probe_transfer_envelope(ctype=2, ext=(), rext=()):
    body = mts_id() + orname() + eits() + content_type(ctype) + content_id()
    body += INT(2000, 0x80) + per_message_indicators()
    body += tlv(0xa1, bilateral_info())
    body += trace_info(1)
    if ext:
        body += tlv(0xa3, *ext)
    body += tlv(0xa2, per_recipient_transfer(ext=rext), per_recipient_transfer(orname(prmd_name='D2'), 2))
    return body


def probe_apdu(**kw):
    return tlv(0xa2, probe_transfer_envelope(**kw))


def report_type(delivery=True):
    if delivery:
        return tlv(0xa1, tlv(0xa0, UTCT(tag=0x80), INT(2, 0x81)))
    return tlv(0xa1, tlv(0xa1, INT(1, 0x80), INT(3, 0x81)))


def last_trace_information(delivery=True, with_eit=True):
    body = UTCT(tag=0x80)
    if with_eit:
        body += eits()
    body += report_type(delivery)
    return tlv(0xa3, body)


def per_recipient_report_transfer(delivery=True, ext=(), n=1):
    body = imp(0, orname()) + INT(n, 0x81) + BITS(0, b'\xb0', 0x82) + last_trace_information(delivery)
    body += imp(4, orname(prmd_name='Intended')) + PSTR('suppl info', 0x85)
    if ext:
        body += tlv(0xa6, *ext)
    return SET(body)


def report_apdu(ext=(), cext=(), rext=(), returned=True, ctype=22, content=b'returned'):
    env = SET(mts_id(), orname(), trace_info(1), *([tlv(0xa1, *ext)] if ext else []))
    c = mts_id() + trace_info(1) + eits() + content_type(ctype) + content_id()
    if returned:
        c += OCTS(content, 0x81)
    c += tlv(0xa2, SET(INT(1, 0x80)))     # additional-information (ANY)
    if cext:
        c += tlv(0xa3, *cext)
    c += tlv(0xa0, per_recipient_report_transfer(True, rext, 1), per_recipient_report_transfer(False, (), 2))
    return tlv(0xa1, env, SET(c))
