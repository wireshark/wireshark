#!/usr/bin/env python3
# Generates test/captures/p1_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the P1 dissector
(packet-p1.c, X.411 Message Transfer Service and, in the same file, the
P3 message access protocol; generated from epan/dissectors/asn1/p1).

P1 reaches the wire three ways, all used here:
  - P1 proper: the MTA transfer service over RTSE (application context
    id-ac-mts-transfer, abstract syntax id-as-mta-rtse) on the OSI upper
    layers on TCP port 102 (TPKT, COTP, session, presentation, ACSE):
    bind (RTORQ/RTOAC), message, probe and report transfers in RTSE data
    transfer segments and a major synchronisation point;
  - P3: the MTS access protocol over ROS (application context
    id-ac-mts-access-94, abstract syntax id-as-mts): binds, every
    operation with its argument, result and errors;
  - the BER OID table, through an X.509 CRL carried in Exported PDU
    (linktype 252, "x509af"): attribute OIDs (2.6.4.3.x, 2.6.5.x) in the
    crlExtensions, and the OR name attributes of the review reproducer
    (2.6.5.6.0 and 2.6.4.3.54 in the issuer name).

The messages carry an interpersonal message (content type 22) as content,
which P1 hands to the P22 dissector.

Usage: mkp1.py <output directory>
Writes p1-coverage.pcapng and p1-coverage-malformed.pcapng.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from x400lib import (  # noqa: E402,
    alg_id, all_ext_attrs, Assoc, asym_token, asymmetric_token, attr_value_dn, BITS, BOOL,
    certificates, content_id, content_type, crl_with_exts, crl_with_issuer,
    delivered_content_type, eits, ENUM, ext_attr, ext_field, ext_values, external,
    global_domain_id, IA5, imp, INT, internal_trace_element, message_apdu, mts_id, NSTR, NULL,
    OCTS, OID, or_address, orname, Pcapng, per_message_indicators, presentation_address, priority,
    probe_apdu, probe_envelope, PSTR, recipient_submission, report_apdu, ros_invoke, ros_result,
    rtoac, rtorq, sec_label, SEQ, SET, signature, spdu, submission_arg, submission_envelope, tlv,
    trace_element, user_info, UTCT, X,
)
import ipmlib

AC_MTS_ACCESS_94 = '2.6.0.1.7'
AS_MTS = '2.6.0.2.11'
AC_MTA_TRANSFER = '2.6.0.1.6'
AS_MTA_RTSE = '2.6.0.2.12'
CTX = 3

# P3 operation and error codes (packet-p1.h)
OP_REGISTER, OP_SUBMISSION_CONTROL, OP_MESSAGE_SUBMISSION, OP_PROBE_SUBMISSION = 1, 2, 3, 4
OP_MESSAGE_DELIVERY, OP_REPORT_DELIVERY, OP_DELIVERY_CONTROL = 5, 6, 2
OP_CANCEL_DEFERRED, OP_CHANGE_CREDENTIALS = 7, 8


class RtseAssoc(Assoc):
    def transfer(self, from_client, apdu, nseg=2, ctx=None):
        """An RTSE transfer: the EXTERNAL holding the ROS invoke of the APDU
        in nseg data transfer segments, then a major synchronisation point."""
        ext = external(self.ctx if ctx is None else ctx, ros_invoke(1, 1, apdu))
        n = max(1, len(ext) // nseg + 1)
        for i in range(0, len(ext), n):
            self.pdata(from_client, OCTS(ext[i:i + n]))
        self.osi(from_client, spdu(41, bytes([42, 1]) + b'1'))


def ext_n(*numbers):
    ex = ext_values()
    return [ext_field(n, ex[n], crit=b'\x05\xa0' if n % 4 == 0 else None) for n in numbers]


# ------------------------------------------------------------- bind types

def msgs_waiting():
    q = SET(INT(5, 0x80), INT(1000, 0x81))
    q2 = SET(INT(0, 0x80))
    return X(1, SET(imp(0, q), imp(1, q2), imp(2, q)))


def creds_simple(ia5=True):
    return X(2, IA5('secret') if ia5 else OCTS(b'secret'))


def creds_strong():
    return X(2, tlv(0xa0, imp(0, asym_token(data_type=1)), imp(1, certificates()),
                    imp(2, SEQ(INT(7, 0x80)))))


def creds_protected():
    return X(2, tlv(0xa1, signature(), UTCT(tag=0x80), UTCT(tag=0x81),
                    BITS(0, b'\x01', 0x82), BITS(0, b'\x02', 0x83)))


def mts_bind_arg(name='ua', creds=None, waiting=True, context=True, ext=False):
    if name == 'ua':
        n = orname()
    elif name == 'mta':
        n = IA5('mta.example', 0x80)
    else:
        n = imp(4, orname(prmd_name='Store'))
    body = n
    if waiting:
        body += msgs_waiting()
    body += creds if creds is not None else creds_simple()
    if context:
        body += tlv(0xa3, sec_label(), sec_label())
    if ext:
        body += tlv(0xa5, ext_field('2.6.4.3.6', INT(1)))
    return SET(body)


def mta_bind_result(authenticated=True):
    if not authenticated:
        return NULL()
    return tlv(0xa1, IA5('mta.example', 0x80), X(1, IA5('pw')))


def mta_bind_arg(authenticated=True, creds='simple'):
    if not authenticated:
        return NULL()
    if creds == 'simple':
        c = X(1, IA5('pw'))
    else:
        c = X(1, tlv(0xa0, imp(0, asym_token(data_type=2)), imp(1, certificates())))
    return tlv(0xa1, IA5('mta.example', 0x80), c, tlv(0xa2, sec_label()))


# ------------------------------------------------------------ P3 operations

def eit_constraints():
    return SEQ(tlv(0xa0, OID('1.2.3.70')), tlv(0xa1, OID('1.2.3.71')), tlv(0xa2, OID('1.2.3.72')))


def controls(full=True):
    body = BOOL(False, 0x80)
    if full:
        body += BITS(6, b'\xc0', 0x81) + INT(1000, 0x82) + priority(0)
        body += tlv(0xa4, content_type(2), content_type(22), content_type('1.2.3.50'))
        body += eit_constraints()
        body += tlv(0xa5, sec_label(), sec_label())
    return SET(body)


def restriction(exact=True, name=None):
    body = BOOL(False) + BITS(5, b'\xa0')
    body += imp(0 if exact else 1, orname(prmd_name='Source')) if name is None else b''
    return SET(body)


def message_class():
    return SET(tlv(0xa0, content_type(2), content_type('1.2.3.50')), INT(5000, 0x81),
               imp(2, eit_constraints()), tlv(0xa3, sec_label()),
               tlv(0xa4, priority(0), priority(2)), ENUM(1, 0x85),
               tlv(0xa6, restriction(True), restriction(False)),
               tlv(0xa7, ext_field('2.6.4.3.6', INT(1))))


def waiting():
    return SET(BITS(6, b'\xc0', 0x80), BITS(5, b'\xe0', 0x81), tlv(0xa2, content_type(2)), eits())


def other_fields(ctype=22, ext=(), full=True):
    body = delivered_content_type(ctype) + orname()
    if full:
        body += imp(1, eits()) + priority(1) + BITS(6, b'\x40', 0x82)
        body += tlv(0xa3, orname(), orname(prmd_name='Other'))
    body += imp(4, orname(prmd_name='This'))
    if full:
        body += imp(5, orname(prmd_name='Intended')) + imp(6, eits())
    body += UTCT(tag=0x87)
    if full:
        body += PSTR('cid', 0x88)
    if ext:
        body += tlv(0xa9, *ext)
    return SET(body)


def delivery_arg(content, ext=(), ctype=22, full=True):
    return SEQ(mts_id('del-1'), UTCT(), other_fields(ctype, ext, full), OCTS(content))


def register_arg(full=True, address='x121'):
    body = orname(prmd_name='User')
    if full:
        body += X(0, tlv(0xa0, NSTR('61234567'), PSTR('tsap')) if address == 'x121'
                  else imp(1, presentation_address()))
        body += SET(message_class(), SET())
        body += X(2, controls(True))
        body += tlv(0xa3, SET(tlv(0xa0, message_class()), imp(1, orname(prmd_name='Alt'))))
        body += tlv(0xa4, restriction(True), restriction(False))
        body += tlv(0xa5, BITS(2, b'\xfc', 0x80), tlv(0xa1, OID('2.6.4.3.6')))
        body += tlv(0xa6, ext_field('2.6.4.3.6', INT(1)))
    return SET(body)


def probe_result():
    return SET(mts_id('probe-1'), UTCT(tag=0x80), content_id(), tlv(0xa1, ext_field('2.6.4.3.6', INT(1))))


def submission_result(ext=True):
    body = mts_id('sub-1') + UTCT(tag=0x80) + content_id()
    if ext:
        body += tlv(0xa1, ext_field(34, certificates()), ext_field(35, signature()))
    return SET(body)


def report_delivery_arg(ext=(), rext=(), returned=True):
    per = []
    for i in range(2):
        body = imp(0, orname())
        body += (tlv(0xa1, tlv(0xa0, UTCT(tag=0x80), INT(1, 0x81))) if i == 0 else
                 tlv(0xa1, tlv(0xa1, INT(2, 0x80), INT(4, 0x81))))
        body += eits() + imp(2, orname(prmd_name='Intended')) + PSTR('suppl', 0x83)
        if rext and i == 0:
            body += tlv(0xa4, *rext)
        per.append(SET(body))
    body = mts_id('subject-1') + content_id() + content_type(22) + eits()
    if ext:
        body += tlv(0xa1, *ext)
    body += SEQ(*per)
    if returned:
        body += OCTS(b'returned content', 0x80)
    return SET(body)


def p3_ops(a, ipm_content):
    """Every operation (argument, result and errors) on association a."""
    sub_ext = ext_n(1, 3, 4, 5, 13, 15, 17, 19, 20, 21, 23, 25, 27, 31, 34, 37, 38, 39, 40, 42, 45)
    rcp_ext = ext_n(2, 6, 7, 8, 9, 10, 11, 12, 14, 16, 18, 22, 24, 28, 29, 32, 35)
    a.op(OP_MESSAGE_SUBMISSION,
         submission_arg(submission_envelope(22, True, sub_ext[:12], rcp_ext[:9]), ipm_content),
         submission_result(True))
    a.op(OP_MESSAGE_SUBMISSION,
         submission_arg(submission_envelope(2, False, sub_ext[12:], rcp_ext[9:], 1, False, False), ipm_content),
         submission_result(False))
    a.op(OP_MESSAGE_SUBMISSION, submission_arg(submission_envelope('2.6.1.10.0'), ipm_content),
         submission_result(False))
    names = [orname(ext=all_ext_attrs()), orname(ext=all_ext_attrs(True)),
             orname(country_name='036', admd_name='0', prmd_name='123', org=None, ous=(), personal=False,
                    numeric_user='5551234', network='61299998888', terminal='TERM1', ddas=(),
                    admd_numeric=True, prmd_numeric=True),
             orname(country_name='GB', admd_name='Mail', prmd_name=None, org='Org2', ous=('A', 'B', 'C'),
                    ddas=(('t1', 'v1'), ('t2', 'v2')), dn=attr_value_dn(('2.5.4.3', PSTR('cn'))))]
    a.op(OP_MESSAGE_SUBMISSION,
         submission_arg(submission_envelope(22, True, (), (), 4, orig=names[0], rnames=names), ipm_content),
         submission_result(False))
    a.op(OP_PROBE_SUBMISSION, probe_envelope(2, sub_ext[:6], rcp_ext[:4]), probe_result())
    a.op(OP_CANCEL_DEFERRED, mts_id('sub-1'), NULL())
    a.op(OP_CANCEL_DEFERRED, mts_id('sub-2'), error=(8, NULL()))
    a.op(OP_SUBMISSION_CONTROL, controls(True), waiting())
    a.op(OP_SUBMISSION_CONTROL, controls(False), waiting())
    for code, param in ((1, NULL()), (4, NULL()), (2, NULL()), (3, SEQ(orname(), orname(prmd_name='B'))),
                        (7, NULL()), (11, NULL()), (12, INT(9)), (13, NULL()), (15, NULL())):
        a.op(OP_MESSAGE_SUBMISSION, submission_arg(submission_envelope(22, True, (), (), 1), ipm_content),
             error=(code, param))
    # delivery: the MTS to the user agent
    dext = ext_n(4, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 22, 25, 26, 28, 37, 38, 40, 42, 45)
    a.op(OP_MESSAGE_DELIVERY, delivery_arg(ipm_content, dext[:12]),
         SET(imp(0, certificates()), imp(1, signature()), tlv(0xa2, ext_field('2.6.4.3.6', INT(1)))),
         from_client=False)
    a.op(OP_MESSAGE_DELIVERY, delivery_arg(ipm_content, dext[12:], 2, False), SET(), from_client=False)
    a.op(OP_REPORT_DELIVERY, report_delivery_arg(ext_n(20, 23, 25, 30, 31, 32, 33, 37, 38, 39),
                                                 ext_n(25, 27, 28, 29)), NULL(), from_client=False)
    a.op(OP_REPORT_DELIVERY, report_delivery_arg(returned=False), SET(ext_field('2.6.4.3.6', INT(1))),
         from_client=False)
    # delivery-control has the same operation code as submission-control, so
    # P3 dissects it as that; its errors are distinct
    for code, param in ((1, NULL()), (14, NULL()), (16, SET(imp(1, INT(3)), INT(1, 0x82)))):
        a.op(OP_SUBMISSION_CONTROL, controls(False), error=(code, param), from_client=False)
    a.op(OP_REGISTER, register_arg(False), NULL())
    a.op(OP_REGISTER, register_arg(True), SET(imp(0, register_arg(True, 'psap')),
                                              tlv(0xa1, ext_field('2.6.4.3.6', INT(1)))))
    a.op(OP_REGISTER, register_arg(True, 'psap'), NULL())
    a.op(OP_REGISTER, register_arg(False), error=(10, NULL()))
    a.op(OP_CHANGE_CREDENTIALS, SET(X(0, IA5('old')), X(1, IA5('new'))), NULL())
    for code in (5, 6):
        a.op(OP_CHANGE_CREDENTIALS, SET(X(0, IA5('old')), X(1, IA5('new'))), error=(code, NULL()))


# -------------------------------------------------------- transfer (RTSE)

def mta_transfers(r, ipm_content):
    msg_ext = ext_n(1, 3, 4, 5, 13, 15, 17, 19, 20, 23, 27, 31, 40, 42, 38, 26, 45)
    rcp_ext = ext_n(2, 6, 7, 8, 9, 10, 11, 12, 14, 16, 18, 22, 24, 28, 25)
    r.transfer(True, message_apdu(ipm_content, 22, ext=msg_ext, rext=rcp_ext))
    r.transfer(True, message_apdu(ipm_content, 2, nrecip=1, bilateral=False, cid=False), nseg=3)
    r.transfer(True, message_apdu(ipm_content, '2.6.1.10.1', nrecip=1))
    r.transfer(True, probe_apdu(ext=msg_ext[:6], rext=rcp_ext[:4]))
    r.transfer(False, report_apdu(ext_n(20, 25, 30, 31, 32, 33, 38, 39), ext_n(23), ext_n(25, 27, 28, 29)))
    r.transfer(False, report_apdu(returned=False, ctype=22))
    r.transfer(False, report_apdu(ctype=2, content=ipm_content))


# ------------------------------------------------------- BER OID carriers

def crl_oid_values(ipm):
    sig = signature()
    certs = certificates()
    ex = ext_values()
    env = submission_envelope(22, True, ext_n(1, 3, 4, 5), ext_n(2, 6, 7))
    penv = probe_envelope(2, ext_n(1, 3), ext_n(2))
    rdel_env = report_delivery_arg(ext_n(20, 23), ext_n(25), returned=False)
    delivery_fields = other_fields(22, ext_n(4, 6, 7))
    vals = [
        ('2.6.3.6.0', asymmetric_token('recipient', 1)), ('2.6.3.6.0', asymmetric_token('mta', 2, True)),
        ('2.6.3.6.0', asymmetric_token('recipient', 3)), ('2.6.3.6.0', asymmetric_token('mta', 4, True)),
        ('2.6.5.6.0', SEQ(IA5('mta.example'))), ('2.6.5.6.0', SEQ(global_domain_id(), IA5('mta.example'))),
        ('2.6.5.2.0', INT(100000)), ('2.6.5.2.1', OID('1.2.3.60')), ('2.6.5.2.2', OID('1.2.3.61')),
        ('2.6.5.2.3', orname()), ('2.6.5.2.6', or_address()), ('2.6.5.2.9', OID('1.2.3.62')),
        ('2.6.5.2.12', orname()), ('2.6.5.2.15', orname()), ('2.6.5.2.17', OID('1.2.3.63')),
        ('2.6.5.2.18', OID('1.2.3.64')),
        ('2.16.840.1.101.2.1.5.47', orname()), ('2.16.840.1.101.2.2.1.134.1', or_address()),
        ('2.6.4.3.80', ex[45]), ('2.6.4.3.1', OCTS(ipm)), ('2.6.4.3.3', IA5('correlator')),
        ('2.6.4.3.3', OCTS(b'octets')), ('2.6.4.3.4', content_id()), ('2.6.4.3.5', sig),
        ('2.6.4.3.6', INT(1000)), ('2.6.4.3.8', OID('1.2.3.60')), ('2.6.4.3.9', ENUM(1)),
        ('2.6.4.3.51', UTCT()), ('2.6.4.3.13', BITS(6, b'\x40')), ('2.6.4.3.78', orname()),
        ('2.6.4.3.14', SEQ(orname(), UTCT())), ('2.6.4.3.53', ENUM(1)),
        ('2.6.4.3.54', internal_trace_element('mta')), ('2.6.4.3.54', internal_trace_element('domain')),
        ('2.6.4.3.54', internal_trace_element(None)),
        ('2.6.4.3.55', UTCT()), ('2.6.4.3.18', SEQ(mts_id('del-1'), UTCT(), delivery_fields)),
        ('2.6.4.3.20', UTCT()), ('2.6.4.3.19', mts_id('id-1')), ('2.6.4.3.21', sig),
        ('2.6.4.3.22', sec_label()), ('2.6.4.3.59', env), ('2.6.4.3.23', UTCT()),
        ('2.6.4.3.24', asym_token()), ('2.6.4.3.81', ex[40]), ('2.6.4.3.17', orname()),
        ('2.6.4.3.62', certs), ('2.6.4.3.26', certs), ('2.6.4.3.27', orname()),
        ('2.6.4.3.63', BITS(3, b'\x10')), ('2.6.4.3.64', or_address()),
        ('2.6.4.3.28', orname()), ('2.6.4.3.65', per_message_indicators()),
        ('2.6.4.3.66', recipient_submission(ext=ext_n(2, 6))),
        ('2.6.4.3.67', recipient_submission(conv=3)),
        ('2.6.4.3.30', SET(imp(0, orname()), tlv(0xa1, tlv(0xa0, UTCT(tag=0x80))),
                           tlv(0xa4, ext_field(28, certs)))),
        ('2.6.4.3.30', SET(imp(0, orname()), tlv(0xa1, tlv(0xa1, INT(2, 0x80))))),
        ('2.6.4.3.31', priority(1)), ('2.6.4.3.68', sig), ('2.6.4.3.69', penv),
        ('2.6.4.3.32', ENUM(1)), ('2.6.4.3.70', sig), ('2.6.4.3.82', ex[40]),
        ('2.6.4.3.71', orname()), ('2.6.4.3.72', ENUM(1)), ('2.6.4.3.33', SEQ(SEQ(orname(), UTCT()), ENUM(2))),
        ('2.6.4.3.34', rdel_env), ('2.6.4.3.35', orname()), ('2.6.4.3.36', certs), ('2.6.4.3.37', sig),
        ('2.6.4.3.38', INT(3)), ('2.6.4.3.40', mts_id('subject')), ('2.6.4.3.41', orname()),
        ('2.6.4.3.75', trace_element(True, True)), ('2.6.4.3.75', trace_element(False, False, 1)),
        ('2.6.1.7.36', asym_token()),
    ]
    return vals


def ipm_content_ipm():
    return ipmlib.ipm(ipmlib.heading(False), ipmlib.body(ipmlib.ia5_bp('hello'), ipmlib.g3_bp(),
                                                          ipmlib.teletex_bp()))


def main_pcapng():
    p = Pcapng()
    ipm = ipm_content_ipm()
    F = []
    r = RtseAssoc(F, 42001, AC_MTA_TRANSFER, [(CTX, AS_MTA_RTSE)])
    r.open(user_info(CTX, rtorq(tlv(0xb0, mta_bind_arg(True)))),
           user_info(CTX, rtoac(tlv(0xb1, mta_bind_result(True)))))
    mta_transfers(r, ipm)
    r.close()
    r = RtseAssoc(F, 42002, AC_MTA_TRANSFER, [(CTX, AS_MTA_RTSE)])
    r.open(user_info(CTX, rtorq(tlv(0xb0, mta_bind_arg(False)))),
           user_info(CTX, rtoac(tlv(0xb1, NULL()))))
    r.close()
    r = RtseAssoc(F, 42003, AC_MTA_TRANSFER, [(CTX, AS_MTA_RTSE)])
    r.open(user_info(CTX, rtorq(tlv(0xb0, mta_bind_arg(True, 'strong')))),
           user_info(CTX, rtoac(tlv(0xb2, INT(2)))))
    r.close()
    a = Assoc(F, 43001, AC_MTS_ACCESS_94, [(CTX, AS_MTS)])
    a.open()
    a.bind(mts_bind_arg('ua', creds_simple(True), True, True, True))
    a.bind_result(mts_bind_arg('mta', creds_simple(False), True, False))
    p3_ops(a, ipm)
    a.close()
    for i, (n, c) in enumerate((('mta', creds_strong()), ('store', creds_protected()))):
        b = Assoc(F, 43002 + i, AC_MTS_ACCESS_94, [(CTX, AS_MTS)])
        b.open()
        b.bind(mts_bind_arg(n, c, False, False))
        b.bind_result(mts_bind_arg('ua', c, False, False))
        b.close()
    for i, code in enumerate((0, 2, 3, 4, 5)):
        b = Assoc(F, 43010 + i, AC_MTS_ACCESS_94, [(CTX, AS_MTS)])
        b.open()
        b.bind(mts_bind_arg())
        b.bind_error(INT(code))
        b.close()
    p.eth(F)
    vals = crl_oid_values(ipm)
    n = int(os.environ.get('CHUNK', '6'))
    for i in range(0, len(vals), n):
        p.exp('x509af', crl_with_exts(*vals[i:i + n]))
    # The review reproducers (an empty constructed mta-name 36 00 made
    # P1 call tvb_reported_length(NULL)): in an issuer name attribute
    gdi = global_domain_id(c='GB', a='A', p=None)
    p.exp('x509af', crl_with_exts(('2.6.5.6.0', SEQ(b'\x36\x00')),
                                  ('2.6.4.3.54', SEQ(gdi, b'\x36\x00', SET(UTCT(tag=0x80), ENUM(0, 0x82))))))
    return p


def malformed_frames():
    p = Pcapng()
    ipm = ipm_content_ipm()
    F = []
    gdi = global_domain_id(c='GB', a='A', p=None)
    # the review reproducers as the issuer name attributes of a CRL (x509if
    # formats every attribute value as a string, which gives its warnings)
    p.exp('x509af', crl_with_issuer(('2.6.5.6.0', SEQ(b'\x36\x00'))))
    p.exp('x509af', crl_with_issuer(('2.6.4.3.54', SEQ(gdi, b'\x36\x00',
                                                       SET(UTCT(tag=0x80), ENUM(0, 0x82))))))
    # contents P1 cannot identify: edi, unidentified, unknown OIDs
    r = RtseAssoc(F, 45001, AC_MTA_TRANSFER, [(CTX, AS_MTA_RTSE)])
    r.open(user_info(CTX, rtorq(tlv(0xb0, mta_bind_arg(True)))),
           user_info(CTX, rtoac(tlv(0xb1, mta_bind_result(True)))))
    r.transfer(True, message_apdu(b'edi content', 35, nrecip=1))
    r.transfer(True, message_apdu(b'unidentified content', 0, nrecip=1))
    r.transfer(True, message_apdu(b'voice', '1.2.3.61', nrecip=1))
    # a report with an unknown content type whose returned content is followed by
    # more fields: the expert item used the length of the parent tvb ("P1: Check for
    # a missing MTAName before using it" also fixed that)
    r.transfer(False, report_apdu(ctype=35, content=b'\x30\x03\x02\x01\x01'))
    r.transfer(True, message_apdu(ipm, 22, nrecip=1, ext=[ext_field(99, INT(1)),
                                                          ext_field('1.2.3.40', INT(1)),
                                                          ext_field('2.6.4.3.6', INT(1))]))
    r.transfer(True, message_apdu(ipm, 22, nrecip=1, rext=[ext_field(0, NULL())]))
    # a ROS result and a reject are not P1 PDUs
    ext = external(CTX, ros_result(1, 1, NULL()))
    r.pdata(True, OCTS(ext))
    r.osi(True, spdu(41, bytes([42, 1]) + b'2'))
    ext = external(CTX, ros_invoke(5, 1, b''))
    r.pdata(True, OCTS(ext))
    r.osi(True, spdu(41, bytes([42, 1]) + b'3'))
    r.close()
    # extension attributes and token data of unknown types, a bad security category
    names = [orname(ext=[ext_attr(99, NULL())]),
             orname(ext=[ext_attr(1, PSTR('x')), ext_attr(0, NULL())])]
    a = Assoc(F, 45002, AC_MTS_ACCESS_94, [(CTX, AS_MTS)])
    a.open()
    a.bind(mts_bind_arg())
    a.bind_result(mts_bind_arg('mta', None, False, False))
    a.op(OP_MESSAGE_SUBMISSION,
         submission_arg(submission_envelope(22, True, (), (), 2, orig=names[0], rnames=names), ipm),
         submission_result(False))
    unknown_token = SEQ(OID('2.6.3.6.0', 0x80), X(1, SEQ(
        SEQ(alg_id(), orname(), UTCT(), imp(0, SEQ(INT(9, 0x80), X(1, NULL())))), alg_id(), BITS(0, b'\x01'))))
    a.op(OP_MESSAGE_SUBMISSION,
         submission_arg(submission_envelope(22, True, [ext_field(16, unknown_token),
                                                       ext_field(20, SET(OID('1.2.3.10'), INT(1),
                                                                         SET(SEQ(OID('1.2.3.99', 0x80),
                                                                                 X(1, INT(2))))))],
                                            (), 1), ipm),
         submission_result(False))
    a.op(OP_SUBMISSION_CONTROL, controls(False),
         error=(16, SET(OID('1.2.3.40'), INT(2, 0x82))), from_client=False)
    a.op(OP_MESSAGE_SUBMISSION, submission_arg(), error=(99, NULL()))
    a.op(99, NULL(), NULL())
    a.close()
    p.eth(F)
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_pcapng().write(os.path.join(out, 'p1-coverage.pcapng'))
    malformed_frames().write(os.path.join(out, 'p1-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
