#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the P22 dissector
(packet-p22.c, X.420 Interpersonal Messaging, generated from
epan/dissectors/asn1/p22).

P22 has no port of its own. Real traffic reaches it through P1/P3/P7
(content type 2.6.1.10.0/2.6.1.10.1 in the BER OID table) and through
X.509 attribute values. The captures are pcapng with two interfaces,
Ethernet and Exported PDU (linktype 252):
  - Exported PDU "p22": InformationObject (IPM and IPN) with every
    heading field, heading extension and basic and extended body part;
  - Exported PDU "x509af": a CRL whose issuer attributes have the OIDs
    registered by P22 (heading, body, message store, correlation,
    security attributes), so that every OID dissector is reached;
  - OSI upper layers on TCP port 102: a P3 message submission and a P7
    message submission whose content is an IPM (content type 2.6.1.10.1).

Usage: mkp22.py <output directory>
Writes p22-coverage.pcapng and p22-coverage-malformed.pcapng.
"""

import os
import sys

from x400lib import (  # noqa: E402,
    app, asym_token, BITS, BOOL, certificates, crl_with_exts, eits, ENUM, GENT, GRAPH, GSTR, IA5,
    imp, INT, message_id, NULL, OCTS, OID, oid_enc, orname, Pcapng, PSTR, retag, SEQ, SET,
    signature, submission_envelope, tlv, TSTR, universal, UTCT, VSTR, X,
)

# ------------------------------------------------------------ building blocks

T_UTC = '261101120000Z'


def ipm_id(user=True, rel='id-1'):
    """IPMIdentifier [APPLICATION 11] SET."""
    body = (orname() if user else b'') + PSTR(rel)
    return app(11, SET(body))


def or_desc(formal=True, free='Free Form', tel='+61 2 5550 1234'):
    body = b''
    if formal:
        body += orname()
    if free:
        body += TSTR(free, 0x80)
    if tel:
        body += PSTR(tel, 0x81)
    return SET(body)


def recip(nr=b'\x05\x80', reply=True, ext=None, free='Bob'):
    body = imp(0, or_desc(free=free))
    if nr is not None:
        body += BITS(nr[0], nr[1:], 0x81)
    if reply:
        body += BOOL(True, 0x82)
    if ext:
        body += tlv(0xa3, *ext)
    return SET(body)


def ipms_ext(oid, value=None):
    return SEQ(OID(oid), value if value is not None else b'')


def ia5_bp(text='Hello, world', rep=None):
    params = SET(ENUM(rep, 0x80) if rep is not None else b'')
    return tlv(0xa0, params, IA5(text))


def g3_bp(pages=2, nbp=True):
    body = b''
    if pages is not None:
        body += INT(pages, 0x80)
    if nbp:
        body += BITS(0, b'\x01\x02\x03', 0x81)
    return tlv(0xa3, SET(body), SEQ(BITS(0, b'\x00\xff'), BITS(1, b'\xaa\x80')))


def teletex_bp():
    params = SET(INT(3, 0x80), BOOL(True, 0x81), tlv(0xa2, BITS(0, b'\x10', 0x83)))
    return tlv(0xa5, params, SEQ(TSTR('line one'), TSTR('line two')))


def videotex_bp(syntax=1):
    return tlv(0xa6, SET(INT(syntax, 0x80)), VSTR('page'))


def enc_bp():
    alg = SEQ(OID('1.2.840.113549.3.7'), OCTS(b'12345678'))
    return tlv(0xa8, SET(alg), BITS(0, b'\x01\x02\x03\x04'))


def msg_bp(inner):
    params = SET(UTCT(T_UTC, 0x80))
    return tlv(0xa9, params, inner)


def mixed_bp():
    return tlv(0xab, OCTS(b'\x01\x02'), OCTS(b'\x03'))


def g4_bp():
    return tlv(0xa4, OCTS(b'\x01\x02'), OCTS(b'\x03'))


def bilat_bp():
    return OCTS(b'bilateral data', 0x8e)


def national_bp():
    return tlv(0xa7, OCTS(b'national'))


def ext_bp(oid_data, data, oid_param=None, param=None):
    """ExtendedBodyPart: [0] parameters EXTERNAL-style, data EXTERNAL-style."""
    body = b''
    if param is not None:
        body += tlv(0xa0, OID(oid_param), X(0, param))
    body += tlv(0x28, OID(oid_data), X(0, data))
    return tlv(0xaf, body)


def body(*parts):
    return SEQ(*parts)


def heading(full=True, subject='Test subject', ext=None, rcpt=None, copies=True):
    h = ipm_id()
    if full:
        h += imp(0, or_desc())
        h += tlv(0xa1, or_desc(), or_desc(free=None, tel=None))
    h += tlv(0xa2, *(rcpt or [recip(ext=[ipms_ext('2.6.1.20.1', INT(3)), ipms_ext('2.6.1.20.0', NULL()),
                                         ipms_ext('2.6.1.18.0', BITS(4, b'\x50'))]),
                              recip(nr=None, reply=False, free=None)]))
    if full:
        if copies:
            h += tlv(0xa3, recip())
        h += tlv(0xa4, recip(free='Blind'))
        h += imp(5, ipm_id(rel='replied'))
        h += tlv(0xa6, ipm_id(rel='obs-1'), ipm_id(user=False, rel='obs-2'))
        h += tlv(0xa7, ipm_id(rel='rel-1'))
    if subject is not None:
        h += tlv(0xa8, TSTR(subject))
    if full:
        h += UTCT(T_UTC, 0x89) + UTCT(T_UTC, 0x8a)
        h += tlv(0xab, or_desc(), or_desc(free=None))
        h += ENUM(2, 0x8c) + ENUM(3, 0x8d) + BOOL(True, 0x8e)
    if ext:
        h += tlv(0xaf, *ext)
    return SET(h)


# heading extension values, by OID
def heading_exts():
    return [
        ipms_ext('2.6.1.5.0', NULL()),                                        # incomplete copy
        ipms_ext('2.6.1.5.1', SET(PSTR('en'), PSTR('en-AU'))),                # languages
        ipms_ext('2.6.1.5.2', ENUM(1)),                                       # auto submitted
        ipms_ext('2.6.1.5.5', GENT('20261101120000Z')),                       # authorization time
        ipms_ext('2.6.1.5.6', SEQ(SET(recip(free=None)),
                                  SET(recip(free=None), NULL()))),            # circulation list
        ipms_ext('2.6.1.5.7', SEQ(SEQ(OID('1.2.3.4'), universal('code'), imp(0, or_desc())))),
        ipms_ext('2.6.1.5.8', universal('Extended subject', 'en')),
        ipms_ext('2.6.1.5.9', SEQ(SEQ(OID('1.2.3.5', 0x80), imp(1, universal('descr'))))),
        ipms_ext('2.6.1.5.10', SEQ(universal('Handle with care'))),
        ipms_ext('2.6.1.5.11', universal('ref-1')),
        ipms_ext('2.6.1.5.12', OID('1.2.3.6')),
    ]


def ipm(h=None, b=None):
    return tlv(0xa0, h if h is not None else heading(), b if b is not None else body(ia5_bp()))


def ipm_plain(h=None, b=None):
    """An IPM as the data of a message body part (untagged SEQUENCE)."""
    return SEQ(h if h is not None else heading(False), b if b is not None else body(ia5_bp()))


def ipn_non_receipt(reason=0, discard=0, comment='auto forwarded', returned=False, ext=False):
    f = ENUM(reason, 0x80)
    if discard is not None:
        f += ENUM(discard, 0x81)
    if comment is not None:
        f += PSTR(comment, 0x82)
    if returned:
        f += tlv(0xa3, heading(False), body(ia5_bp('returned')))
    if ext:
        f += tlv(0xa4, ipms_ext('2.6.1.20.1', INT(3)))
    return tlv(0xa0, tlv(0xa0, f))


def ipn_receipt(auto=1, suppl=True, ext=False):
    f = UTCT(T_UTC, 0x80) + ENUM(auto, 0x81)
    if suppl:
        f += PSTR('suppl', 0x82)
    if ext:
        f += tlv(0xa3, ipms_ext('2.6.1.20.1', INT(3)))
    return tlv(0xa0, tlv(0xa1, f))


def ipn_other(*exts):
    return tlv(0xa0, tlv(0xa2, *exts))


def absence_advice():
    return ipms_ext('2.6.1.19.0', SEQ(ia5_bp('I am away'), UTCT(T_UTC)))


def change_of_address():
    return ipms_ext('2.6.1.19.1', SEQ(imp(0, or_desc()), UTCT(T_UTC, 0x81)))


# --------------------------------------------------------- the frames

def extended_parts():
    gt = ext_bp('2.6.1.4.11', GSTR('general text'), '2.6.1.11.11', SET(INT(1), INT(6), INT(77)))
    voice = ext_bp('2.6.1.4.16', OCTS(b'voice'), '2.6.1.11.16',
                   SEQ(INT(12, 0x80), OID('1.2.3.7', 0x81), IA5('supp', 0x82)))
    ftp = ext_bp('2.6.1.4.12', SEQ(tlv(0x28, INT(1), OCTS(b'file data', 0x81))), '2.6.1.11.12',
                 ft_params())
    ftp2 = ext_bp('2.6.1.4.12', SEQ(tlv(0x28, INT(1), OCTS(b'file data', 0x81))), '2.6.1.11.12',
                  SEQ(tlv(0xa1, tlv(0xa1, OID('1.0.8571.2.1'), OID('1.0.8571.2.2'))),
                      tlv(0xa4, tlv(0xaf, NULL(0x80)))))

    content = ext_bp('2.6.1.4.17.2.6.1.10.1', ipm(heading(False), body(ia5_bp('fwd'))),
                     '2.6.1.11.17.2.6.1.10.1',
                     SET(UTCT(T_UTC, 0x80), imp(2, message_id()),
                         tlv(0xa3, imp(0, signature()), imp(1, certificates()),
                             submission_envelope(22, True, (), (), 1))))
    ia5e = ext_bp('2.6.1.4.0', IA5('extended ia5'), '2.6.1.11.0', SET(ENUM(5, 0x80)))
    g3e = ext_bp('2.6.1.4.2', SEQ(BITS(0, b'\x01')), '2.6.1.11.2', SET(INT(1, 0x80)))
    return [gt, voice, ftp, ftp2, content, ia5e, g3e]


def ft_params():
    """FileTransferParameters with every field the template reaches."""
    pn = tlv(0xa0, GRAPH('dir'), GRAPH('file'))                      # incomplete-pathname
    pn_complete = tlv(0xb7, GRAPH('c'), GRAPH('d'))                  # complete-pathname [23]
    related = tlv(0xa0,
                  SEQ(tlv(0xa0, tlv(0xa0, pn), GRAPH('v1', 0x81)), tlv(0x80, b'\x02')),
                  SEQ(tlv(0xa0, tlv(0xa0, pn_complete)), tlv(0x81, GRAPH('descriptive')[2:])),
                  SEQ(tlv(0xa1, OCTS(b'xref', 0x80),
                          tlv(0xa1, imp(0, orname()), PSTR('mref', 0x81)), INT(2, 0x82)),
                      tlv(0x80, b'\x01')))
    ctype = tlv(0xa1, tlv(0xa0, OID('1.0.8571.5.1')))
    ctype2 = tlv(0xa1, tlv(0xa1, OID('1.0.8571.2.1'), OID('1.0.8571.2.2')))
    env = tlv(0xa2, tlv(0xa0, tlv(0x80, oid_enc('1.2.3.4'))),
              tlv(0xa1, tlv(0xa1, GRAPH('machine'))), tlv(0x82, oid_enc('1.2.3.5')),
              tlv(0xa3, GRAPH('user')))
    comp = tlv(0xa3, OID('1.2.3.6', 0x80), tlv(0xa1, NULL()))
    pw = tlv(0xa3, *[tlv(0xa0 + i, GRAPH('pw%d' % i) if i % 2 == 0 else OCTS(b'p')) for i in range(8)],
             tlv(0xa8, OCTS(b'x'), GRAPH('y')), tlv(0xa9, GRAPH('link')))
    loc = tlv(0xa4, OID('1.2.3.12'), INT(5))
    attrs = tlv(0xa4, pn,
                BITS(0, b'\xe0', 0x81),
                tlv(0xa3, GRAPH('account')), tlv(0xa4, GENT(tag=0x81)), tlv(0xa5, GENT(tag=0x81)),
                tlv(0xa6, NULL(0x80)), tlv(0xa7, GENT(tag=0x81)),
                tlv(0xa8, GRAPH('creator')), tlv(0xa9, NULL(0x80)), tlv(0xaa, GRAPH('reader')),
                tlv(0xab, GRAPH('modifier')),
                tlv(0xaf, tlv(0xa1, SEQ(BITS(0, b'\xc0', 0x80), GRAPH('who', 0x82), pw, loc))),
                b'')
    return SEQ(related, ctype, env, comp, attrs)


def ipm_frames():
    """(description, InformationObject) for the Exported PDU "p22"."""
    out = []
    out.append(('IPM, full heading with extensions, every basic body part',
                ipm(heading(True, ext=heading_exts()),
                    body(ia5_bp(), ia5_bp('ita2', 2), g3_bp(), g3_bp(None, False), g4_bp(),
                         teletex_bp(), videotex_bp(), enc_bp(), bilat_bp(), national_bp(),
                         mixed_bp()))))
    out.append(('IPM, minimal heading, empty body', ipm(heading(False, subject=None), body())))
    out.append(('IPM, message body part with a forwarded IPM',
                ipm(heading(False), body(msg_bp(ipm_plain())))))
    out.append(('IPM, extended body parts', ipm(heading(False), body(*extended_parts()))))
    out.append(('IPN, non-receipt', ipn_obj(ipn_non_receipt(1, 2, 'x', True, True))))
    out.append(('IPN, non-receipt minimal', ipn_obj(ipn_non_receipt(0, None, None), False)))
    out.append(('IPN, receipt', ipn_obj(ipn_receipt(1, True, True))))
    out.append(('IPN, receipt, manual', ipn_obj(ipn_receipt(0, False), False)))
    out.append(('IPN, other notification (advice)', ipn_obj(ipn_other(absence_advice(), change_of_address()))))
    return out


def ipn_obj(choice, full=True):
    """InformationObject ipn [1]: common fields and the choice."""
    body = ipm_id()
    if full:
        body += imp(1, or_desc()) + imp(2, or_desc(free=None))
        body += eits()
        body += tlv(0xa3, ipms_ext('2.6.1.20.1', INT(2)))
    return tlv(0xa1, body, choice)


# ----------------------------------------- attribute values by OID (CRL)

def ipm_synopsis(depth=2):
    non = tlv(0xa1, OID('2.6.1.4.0', 0x80), INT(100, 0x82), BOOL(True, 0x83))
    inner = SEQ(non, tlv(0xa1, OID('2.6.1.4.5', 0x80), INT(10, 0x82)))
    return SEQ(non, tlv(0xa0, INT(3, 0x80), imp(1, inner)))


def body_part_signatures():
    sig = SEQ(SEQ(OID('1.2.840.113549.1.1.5'), NULL()), BITS(0, b'\x01\x02'))
    return SET(SET(INT(1), sig))


def ipm_security_label():
    lab = SET(OID('1.2.3.10'), INT(3), PSTR('mark'))
    return SEQ(imp(0, lab), imp(1, lab), tlv(0xa2, NULL(0x80), imp(1, lab)))


def body_part_tokens():
    alg = SEQ(OID('1.2.840.113549.3.7'), OCTS(b'12345678'))
    enc = SET(alg, BITS(0, b'\x01\x02'))
    return SET(SET(INT(1), enc), SET(INT(2), tlv(0xa0, SET(INT(1), enc))))


def p22_oid_values():
    """(oid, value) for the OIDs P22 registers in the BER OID table."""
    h = heading(False)
    pair = ipm_id()
    synopsis = ipm_synopsis()
    vals = [
        ('2.6.1.19.0', SEQ(ia5_bp('away'), UTCT(T_UTC))),
        ('2.6.1.19.1', SEQ(imp(0, or_desc()), UTCT(T_UTC, 0x81))),
        ('2.6.1.17.2', SET(tlv(0xa0, tlv(0x80, b'\x02'), tlv(0x81, b'\x03'), INT(5, 0x82),
                              tlv(0xa3, INT(7), INT(2))))),
    ]
    vals += [
        ('2.6.1.5.0', NULL()), ('2.6.1.5.1', SET(PSTR('en'), PSTR('de'))), ('2.6.1.5.2', ENUM(2)),
        ('2.6.1.5.3', body_part_signatures()), ('2.6.1.5.4', ipm_security_label()),
        ('2.6.1.5.5', GENT()),
        ('2.6.1.5.6', SEQ(SET(recip(free=None)), SET(recip(free=None), GENT()),
                          SET(recip(free=None), SEQ(SEQ(SEQ(OID('1.2.840.113549.1.1.5'), NULL()), ipm_id(), GENT()), SEQ(OID('1.2.840.113549.1.1.5'), NULL()), BITS(0, b'\x01'))))),
        ('2.6.1.20.0', NULL()),
        ('2.6.1.5.7', SEQ(SEQ(OID('1.2.3.4'), universal('c'), imp(0, or_desc())), SEQ(universal('d')))),
        ('2.6.1.5.8', universal('subject')),
        ('2.6.1.5.9', SEQ(SEQ(OID('1.2.3.5', 0x80), imp(1, universal('d'))), SEQ())),
        ('2.6.1.5.10', SEQ(universal('h'))), ('2.6.1.5.11', universal('r')),
        ('2.6.1.5.12', OID('1.2.3.6')), ('2.6.1.20.1', INT(4)),
        ('2.6.1.4.0', IA5('text')), ('2.6.1.11.0', SET(ENUM(2, 0x80))),
        ('2.6.1.4.2', SEQ(BITS(0, b'\x01'))),
        ('2.6.1.11.2', SET(INT(2, 0x80), BITS(0, b'\x01', 0x81))),
        ('2.6.1.4.3', SEQ(OCTS(b'\x01'), OCTS(b'\x02'))),
        ('2.6.1.4.4', SEQ(TSTR('a'), TSTR('b'))),
        ('2.6.1.11.4', SET(INT(1, 0x80), BOOL(False, 0x81))),
        ('2.6.1.4.5', VSTR('v')), ('2.6.1.11.5', SET(INT(2, 0x80))),
        ('2.6.1.4.6', BITS(0, b'\x01\x02')),
        ('2.6.1.11.6', SET(SEQ(OID('1.2.840.113549.3.7'), OCTS(b'12345678')))),
        ('2.6.1.4.7', ipm_plain()),
        ('2.6.1.11.7', SET(UTCT(T_UTC, 0x80))),
        ('2.6.1.4.8', SEQ(OCTS(b'\x01'))),
        ('2.6.1.4.9', OCTS(b'bilateral')),
        ('2.6.1.11.11', SET(INT(1), INT(2))), ('2.6.1.4.11', GSTR('general')),
        ('2.6.1.11.12', SEQ(tlv(0xa4, tlv(0xa0, GRAPH('/x'))))),
        ('2.6.1.4.12', SEQ(tlv(0x28, INT(1), OCTS(b'f', 0x81)))),
        ('2.6.1.11.15', SET(UTCT(T_UTC, 0x80))),
        ('2.6.1.4.15', retag(0x31, ipn_obj(ipn_non_receipt(), False))), ('2.6.1.4.15', retag(0x31, ipn_obj(ipn_receipt(), True))),
        ('2.6.1.11.16', SEQ(INT(3, 0x80), OID('1.2.3.7', 0x81))), ('2.6.1.4.16', OCTS(b'voice')),
        ('2.6.1.11.17.2.6.1.10.1', SET(UTCT(T_UTC, 0x80))),
        ('2.6.1.4.17.2.6.1.10.1', ipm(h, body(ia5_bp()))),
        ('2.6.1.11.17.2.6.1.10.0', SET(imp(2, message_id()))),
        ('2.6.1.4.17.2.6.1.10.0', ipm(h, body(ia5_bp()))),
        ('2.6.1.11.17.1.3.26.0.4406.0.4.1', SET(UTCT(T_UTC, 0x80))),
        ('2.6.1.6.0', ENUM(2)), ('2.6.1.6.1', synopsis),
        ('2.6.1.6.2', SEQ(OID('2.6.1.4.0', 0x80), OID('2.6.1.11.0', 0x81), INT(3, 0x82),
                          INT(1, 0x83), INT(100, 0x84), BOOL(True, 0x85))),
        ('2.6.1.7.0', h), ('2.6.1.7.1', pair), ('2.6.1.7.2', or_desc()),
        ('2.6.1.7.3', pair), ('2.6.1.7.4', TSTR('subject')),
        ('2.6.1.7.5', UTCT()), ('2.6.1.7.6', UTCT()), ('2.6.1.7.7', ENUM(0)),
        ('2.6.1.7.8', ENUM(1)), ('2.6.1.7.9', BOOL(True)),
        ('2.6.1.7.10', or_desc()), ('2.6.1.7.11', recip()), ('2.6.1.7.12', recip()),
        ('2.6.1.7.13', recip()), ('2.6.1.7.14', pair), ('2.6.1.7.15', pair),
        ('2.6.1.7.16', or_desc()), ('2.6.1.7.17', NULL()), ('2.6.1.7.18', PSTR('en')),
        ('2.6.1.7.19', or_desc()), ('2.6.1.7.20', or_desc()), ('2.6.1.7.21', or_desc()),
        ('2.6.1.7.22', ENUM(1)), ('2.6.1.7.23', body_part_signatures()),
        ('2.6.1.7.24', ipm_security_label()), ('2.6.1.7.25', NULL(0x80)), ('2.6.1.7.25', imp(1, SET(OID('1.2.3.10'), INT(1)))),
        ('2.6.1.7.26', body_part_tokens()), ('2.6.1.7.27', GENT()),
        ('2.6.1.7.28', SET(recip(free=None), NULL())),
        ('2.6.1.7.29', SEQ(OID('1.2.3.4'))), ('2.6.1.7.30', universal('x')),
        ('2.6.1.7.31', SEQ(OID('1.2.3.5', 0x80))), ('2.6.1.7.32', universal('x')),
        ('2.6.1.7.33', universal('x')), ('2.6.1.7.34', OID('1.2.3.6')),
        ('2.6.1.7.35', SET(SET(INT(1), SET()))), ('2.6.1.7.37', INT(3)),
        ('2.6.1.7.38', SET(SET(INT(1, 0x80), INT(2, 0x81)))),
        ('2.6.1.8.0', body(ia5_bp(), g4_bp())),
        ('2.6.1.13.0', tlv(0xa1, INT(2), INT(3))), ('2.6.1.13.0', NULL(0x80)),
        ('2.6.1.13.1', tlv(0xa1, INT(1))), ('2.6.1.13.1', NULL(0x80)),
        ('2.6.1.13.2', INT(10)), ('2.6.1.13.3', INT(1)),
        ('2.6.1.13.7', SET(INT(1), INT(2))), ('2.6.1.13.7', NULL()),
        ('2.6.1.13.14', INT(25)), ('2.6.1.13.16', INT(2)), ('2.6.1.13.18', INT(1)),
        ('2.6.1.18.0', BITS(4, b'\x50')),
        ('2.6.1.18.1', SET(OCTS(b'orig'), INT(3))),
        ('2.6.1.18.1', SET(SET(imp(0, signature()), imp(1, signature()), imp(2, asym_token())), INT(5))),
        ('2.6.1.10.0', ipm(h, body(ia5_bp()))), ('2.6.1.10.1', ipm(h, body(ia5_bp()))),
    ]
    return [(o, v) for o, v in vals if v]


def ipm_empty_subject():
    h = ipm_id() + tlv(0xa8, tlv(0x34, b''))
    return ipm(SET(h), body(ia5_bp('empty subject')))


def nested_message(depth):
    inner = ipm_plain(heading(False), body(ia5_bp('leaf')))
    for _ in range(depth):
        inner = ipm_plain(heading(False), body(msg_bp(inner)))
    return ipm(heading(False), body(msg_bp(inner)))


def malformed_frames():
    f = []
    good = ipm(heading(False), body(ia5_bp()))
    f.append(('x', good[:len(good) // 2]))                                   # truncated
    f.append(('x', tlv(0xa0, SET(b''), body())))                              # no this-IPM
    f.append(('x', tlv(0xa5, SET(b''))))                                      # unknown choice
    f.append(('x', ipm(heading(False, ext=[ipms_ext('1.2.3.4.5', NULL())]), body())))   # unknown extension
    f.append(('x', ipm(heading(False), body(ext_bp('1.2.3.4.6', OCTS(b'x'))))))          # unknown body part
    f.append(('x', ipm(heading(False), body(ext_bp('1.2.3.4.6', OCTS(b'x'), '1.2.3.4.7', OCTS(b'y'))))))
    f.append(('x', ipm(heading(False), body(tlv(0xa0, SET(ENUM(5, 0x80)), INT(5))))))   # wrong data tag
    f.append(('x', good + b'\x00\x01'))
    f.append(('x', ipn_obj(ipn_non_receipt(9, 9), False)))                    # enumerations out of range
    f.append(('x', nested_message(60)))                                        # deeper than any real message
    f.append(('x', ipm(heading(False), body(ext_bp('2.6.1.4.17.2.6.1.10.1', ipm(heading(False), body()),
                                                  '2.6.1.11.17.2.6.1.10.1', SET(UTCT(T_UTC, 0x80)))))))
    f.append(('x', ipm(heading(False), body(ext_bp('2.6.1.4.12', SEQ(tlv(0x28, INT(1), OCTS(b'f', 0x81))), '2.6.1.11.12',
                                                  SEQ(tlv(0xa1, tlv(0xa0, OID('1.0.8571.5.1'), tlv(0xa0, NULL())))))))))
    f.append(('x', b''))
    f.append(('x', b'\x30\x80'))
    p = Pcapng()
    for _, obj in f:
        p.exp('p22', obj)
    p.exp('x509af', crl_with_exts(('2.6.1.7.0', b'\x31\x03\x02\x01'), ('2.6.1.5.1', b'\x13\x05\x01')))
    p.exp('x509af', crl_with_exts(('2.6.1.4.15', retag(0x31, ipn_obj(ipn_non_receipt(), False))[:-3])))
    p.exp('x509af', crl_with_exts(('2.6.1.6.1', SEQ(tlv(0xa2, b'')))))
    return p


def main_pcapng():
    p = Pcapng()
    for desc, obj in ipm_frames():
        p.exp('p22', obj)
    p.exp('p22', ipm_empty_subject())
    vals = p22_oid_values()
    n = int(os.environ.get('CHUNK', '6'))
    for i in range(0, len(vals), n):
        p.exp('x509af', crl_with_exts(*vals[i:i + n]))
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_pcapng().write(os.path.join(out, 'p22-coverage.pcapng'))
    malformed_frames().write(os.path.join(out, 'p22-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
