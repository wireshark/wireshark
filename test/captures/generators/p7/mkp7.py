#!/usr/bin/env python3
# Generates test/captures/p7_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the P7 dissector
(packet-p7.c, X.413 Message Store access, generated from
epan/dissectors/asn1/p7).

P7 runs over ROS on the OSI upper layers on TCP port 102 (TPKT, COTP,
session, presentation, ACSE): application context id-ac-ms-access-88
(2.6.0.1.4) with the abstract syntax id-as-ms-88 (2.6.0.2.9). The main
capture has:
  - binds (every credential type, restrictions, bind extensions) and
    bind errors;
  - every operation with argument and result, and every error (summarize,
    list, fetch, delete, register-MS, alert, modify, MS message
    submission, MS probe submission, cancel deferred delivery and
    submission control, which P7 shares with P3);
  - the attribute types of the message store (attribute values are
    dissected through the BER OID table), also as X.509 CRL extensions in
    Exported PDU (linktype 252, "x509af").

Usage: mkp7.py <output directory>
Writes p7-coverage.pcapng and p7-coverage-malformed.pcapng.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from x400lib import (  # noqa: E402,
    Assoc, asym_token, BITS, BOOL, certificates, content_id, content_type, crl_with_exts, eits,
    ENUM, ext_field, ext_values, GSTR, IA5, imp, INT, mts_id, NULL, OCTS, OID, orname, Pcapng,
    per_message_indicators, priority, PSTR, recipient_submission, sec_label, SEQ, SET, signature,
    submission_envelope, tlv, UTCT, X,
)
import ipmlib

AC_MS_ACCESS_88 = '2.6.0.1.4'
AS_MS_88 = '2.6.0.2.9'
CTX = 3

(OP_SUBMISSION_CONTROL, OP_MS_MESSAGE_SUBMISSION, OP_MS_PROBE_SUBMISSION, OP_CANCEL_DEFERRED,
 OP_SUMMARIZE, OP_LIST, OP_FETCH, OP_DELETE, OP_REGISTER_MS, OP_ALERT, OP_MODIFY) = (
    2, 3, 4, 7, 20, 21, 22, 23, 24, 25, 26)

# attribute types (OIDs registered in the BER OID table) and a value each
AT_CREATION_TIME = '2.6.4.3.11'
AT_ENTRY_TYPE = '2.6.4.3.16'
AT_SEQUENCE_NUMBER = '2.6.4.3.39'
AT_RETRIEVAL_STATUS = '2.6.4.3.15'
AT_GROUP_NAME = '2.6.4.3.57'
AT_ORIG_NAME = '2.6.4.3.27'
AT_PRIORITY = '2.6.4.3.31'
AT_CONTENT_LENGTH = '2.6.4.3.6'


def attribute_value(oid):
    return {AT_CREATION_TIME: UTCT(), AT_ENTRY_TYPE: INT(0), AT_SEQUENCE_NUMBER: INT(5),
            AT_RETRIEVAL_STATUS: INT(1), AT_GROUP_NAME: SEQ(GSTR('group'), GSTR('sub')),
            AT_ORIG_NAME: orname(), AT_PRIORITY: priority(1), AT_CONTENT_LENGTH: INT(1234)}[oid]


def attribute(oid, values=1):
    return SEQ(OID(oid), SEQ(*[attribute_value(oid)] * values))


def ms_extension_item(oid, value):
    """MSExtensionItem ::= INSTANCE OF MS-EXTENSION (EXTERNAL-like)."""
    return tlv(0x28, OID(oid), X(0, value))


def ms_extensions(*items):
    """MSExtensions (SEQUENCE SIZE (1..n)): one item at least."""
    return SEQ(*(items or (ms_extension_item('2.6.4.9.5', SET(OID('1.2.840.113549.1.1.5'))),)))


def ava(oid):
    """AttributeValueAssertion contents (type OID, value)."""
    return OID(oid) + attribute_value(oid)


def filters():
    """Filter alternatives. This module has EXPLICIT TAGS: every context tag
    wraps the complete encoding. Filter: item [0], and [1], or [2], not [3]."""
    item = lambda alt: X(0, alt)                                    # noqa: E731
    eq = lambda n, oid: X(n, SEQ(ava(oid)))                         # noqa: E731
    return [
        item(eq(0, AT_ENTRY_TYPE)),
        item(X(1, SEQ(OID(AT_ORIG_NAME), SEQ(X(0, attribute_value(AT_ORIG_NAME)),
                                              X(1, attribute_value(AT_ORIG_NAME)),
                                              X(2, attribute_value(AT_ORIG_NAME)))))),
        item(eq(2, AT_SEQUENCE_NUMBER)),
        item(eq(3, AT_CONTENT_LENGTH)),
        item(X(4, OID(AT_ORIG_NAME))),
        item(eq(5, AT_CREATION_TIME)),
        item(X(6, SEQ(X(0, OID('2.5.13.1')), X(1, OID(AT_ORIG_NAME)), X(2, attribute_value(AT_ORIG_NAME))))),
        X(1, SET(item(eq(0, AT_ENTRY_TYPE)), item(X(4, OID(AT_ORIG_NAME))))),
        X(2, SET(item(eq(0, AT_ENTRY_TYPE)), item(eq(2, AT_SEQUENCE_NUMBER)))),
        X(3, item(eq(0, AT_ENTRY_TYPE))),
    ]


def selector(full=True):
    body = X(0, BOOL(True))
    body += X(1, X(0, SEQ(X(0, INT(1)), X(1, INT(10)))))
    if full:
        body += X(2, filters()[0])
        body += X(3, INT(10)) + X(4, BITS(5, b'\xe0'))
    return SET(body)


def selector_time():
    return SET(X(1, X(1, SEQ(X(0, UTCT()), X(1, UTCT())))))


def selector_filter(f):
    return SET(X(2, f))


def entry_information(n=1, values=True, exceeded=True):
    body = INT(n)
    if values:
        body += SET(attribute(AT_SEQUENCE_NUMBER), attribute(AT_CREATION_TIME), attribute(AT_GROUP_NAME),
                    attribute(AT_ORIG_NAME, 2))
    if exceeded:
        body += X(0, SET(SEQ(X(0, OID(AT_ORIG_NAME)), X(1, INT(5)))))
    return SEQ(body)


def selection():
    return SET(SET(OID(AT_SEQUENCE_NUMBER), X(0, INT(1)), X(1, INT(3))), SET(OID(AT_CREATION_TIME)))


def summarize_arg(ext=False):
    body = X(0, INT(0)) + X(1, selector(True)) + X(2, SEQ(OID(AT_ENTRY_TYPE), OID(AT_CREATION_TIME)))
    if ext:
        body += X(3, ms_extensions())
    return SET(body)


def summarize_result():
    return SET(X(0, INT(7)), X(1, INT(12)), X(2, SEQ(X(0, INT(1)), X(1, INT(20)))),
               X(3, SEQ(SET(X(0, INT(2)), X(1, SET(SEQ(OID(AT_ENTRY_TYPE), attribute_value(AT_ENTRY_TYPE),
                                                       INT(3))))),
                        SET(X(1, SET(SEQ(OID(AT_CREATION_TIME), UTCT(), INT(2))))))),
               X(4, ms_extensions()))


def list_arg():
    return SET(X(0, INT(3)), X(1, selector(True)), X(3, selection()), X(4, ms_extensions()))


def list_result():
    return SET(X(0, INT(9)), X(1, SEQ(entry_information(1), entry_information(2, True, False),
                                      entry_information(3, False, False))), X(2, ms_extensions()))


def fetch_arg(precise=True):
    body = X(0, INT(0))
    body += X(2, INT(5)) if precise else X(1, selector(False))
    body += X(3, selection()) + X(4, ms_extensions())
    return SET(body)


def fetch_result(full=True):
    body = X(0, entry_information(1))
    if full:
        body += X(1, SEQ(INT(2), INT(3))) + X(2, INT(4)) + X(3, ms_extensions())
    return SET(body)


def delete_arg(sel=True):
    body = X(0, INT(2))
    body += X(1, selector(False)) if sel else X(2, SET(INT(1), INT(2)))
    body += X(3, ms_extensions())
    return SET(body)


def delete_result():
    return SET(X(0, SEQ(INT(1), INT(2))), X(1, ms_extensions()))


def ms_submission_options():
    return SET(X(0, INT(2)), X(1, BOOL(True)), X(2, SET(SEQ(GSTR('drafts')))), X(3, ms_extensions()))


def message_group_name_descriptor():
    return SET(X(0, SEQ(GSTR('g1'))), X(1, GSTR('descr')))


def registration_types(extended=False):
    """RegistrationTypes. The extended-registrations (an OID list) make the
    dissector assert (see the README): only the malformed capture has them."""
    return SET(X(0, BITS(2, b'\xfc')), *([X(1, SET(OID('2.6.4.9.5')))] if extended else []),
               X(2, SET(X(0, SEQ(GSTR('p'))), X(1, BOOL(False)), X(2, BOOL(False)))))


def ua_registration():
    token_ext = ms_extension_item('2.6.4.9.5', SET(OID('1.2.840.113549.1.1.5')))
    return SET(X(0, PSTR('ua-1')), X(1, SET(OID(AT_SEQUENCE_NUMBER))), X(2, SET(OID(AT_ENTRY_TYPE))),
               X(3, ms_submission_options()), X(4, ms_extensions(token_ext)))


def auto_action_registration(param=False):
    """The registration-parameter is an optional ANY that the dissector does
    not consume: it makes every such PDU a BER error (malformed capture only)."""
    return SEQ(OID('2.6.4.3.6'), X(0, INT(2)), *([X(1, INT(5))] if param else []))


def register_arg(full=True):
    token_ext = ms_extension_item('2.6.4.9.5', SET(OID('1.2.840.113549.1.1.5')))
    body = X(0, SET(auto_action_registration(), SEQ(OID('2.6.4.3.6'))))
    body += X(1, SET(SEQ(OID('2.6.4.3.6'), X(0, INT(2))), SEQ(OID('2.6.4.3.6'))))
    body += X(2, SET(OID(AT_SEQUENCE_NUMBER), OID(AT_CREATION_TIME))) + X(3, SET(OID(AT_ENTRY_TYPE)))
    body += X(4, SEQ(X(0, IA5('old')), X(1, IA5('new'))))
    body += X(5, SET(sec_label()))
    body += X(6, SET(ua_registration()))
    body += X(7, ms_submission_options())
    body += X(8, SEQ(X(0, message_group_name_descriptor()), X(1, SEQ(GSTR('g2'))),
                     X(2, message_group_name_descriptor())))
    body += X(9, registration_types())
    body += X(10, ms_extensions(token_ext))
    return SET(body)


def register_result():
    return SET(X(0, SET(auto_action_registration())), X(1, SET(OID(AT_SEQUENCE_NUMBER))),
               X(2, SET(OID(AT_ENTRY_TYPE))), X(3, SET(ua_registration())),
               X(4, ms_submission_options()), X(5, SET(message_group_name_descriptor())),
               X(6, ms_extensions()))


def modify_arg():
    mods = X(3, SEQ(
        SET(X(0, BOOL(True)), X(1, attribute(AT_RETRIEVAL_STATUS))),
        SET(X(2, OID(AT_RETRIEVAL_STATUS))),
        SET(X(3, SEQ(OID(AT_RETRIEVAL_STATUS), SEQ(SEQ(X(1, INT(1))))))),
        SET(X(4, SEQ(OID(AT_RETRIEVAL_STATUS), SEQ(SEQ(X(1, INT(2)))))))))
    return SET(X(0, INT(3)), X(2, SEQ(INT(1), INT(2))), mods, X(4, ms_extensions()))


def modify_arg_selector():
    return SET(X(1, selector(False)), X(3, SEQ(SET(X(2, OID(AT_RETRIEVAL_STATUS))))))


def alert_arg(entry=True):
    body = X(0, INT(2))
    if entry:
        body += X(2, entry_information(4))
    return SET(body)


def ms_bind_arg(creds=None, full=True):
    body = orname()
    body += creds if creds is not None else X(2, IA5('secret'))
    if full:
        body += tlv(0xa3, sec_label(), sec_label())
        body += X(4, SET(X(0, SET(OID('2.6.1.10.1'), OID('2.6.1.10.0'))), X(1, SET(OID('1.2.3.80'))),
                         X(2, INT(5000))))
        body += X(5, BOOL(True)) + X(6, PSTR('ua-1'))
        body += X(7, ms_extensions(ms_extension_item('2.6.4.9.5', SET(OID('1.2.840.113549.1.1.5')))))
    return SET(body)


def ms_bind_result(full=True):
    body = X(2, IA5('secret'))
    if full:
        body += X(3, SET(OID('2.6.4.3.6'))) + X(4, SET(OID(AT_ENTRY_TYPE), OID(AT_CREATION_TIME)))
        body += X(5, BOOL(True)) + X(6, SET(OID('2.6.1.10.1'))) + X(7, SET(INT(0), INT(3)))
        body += X(8, SET(OID('2.5.13.1'))) + X(9, ms_extensions(ms_extension_item('2.6.4.9.5', SET())))
        body += X(10, INT(2)) + X(11, X(0, NULL()))
        body += X(12, SET(OID('1.2.3.81'))) + X(13, BOOL(True)) + X(14, GSTR('service info'))
    return SET(body)


def bind_error(kind=0):
    if kind == 0:
        return ENUM(0)
    if kind == 1:
        return SET(X(0, ENUM(3)), X(1, GSTR('supplementary')), X(2, SET(OID('1.2.3.82'))))
    return SET(X(0, ENUM(4)))


def ms_message_submission_arg(ipm_content):
    return SEQ(submission_envelope(22, True, ext_n(1, 3, 4, 5), ext_n(2, 6), 2), OCTS(ipm_content),
               X(4, ms_submission_options()))


def ext_n(*numbers):
    ex = ext_values()
    return [ext_field(n, ex[n]) for n in numbers]


def common_submission_results(variant=0):
    return SET(X(0, INT(8)), X(1, X(0, NULL()) if variant == 0 else X(1, INT(3))),
               X(2, ms_extensions()))


def ms_message_submission_result(variant=0):
    if variant == 0:
        return SET(mts_id('sub-1'), UTCT(tag=0x80), content_id(), X(1, SET(ext_field(35, signature()))),
                   X(4, common_submission_results(0)))
    return X(4, common_submission_results(1))


def ms_probe_submission_arg():
    body = orname() + eits() + content_type(22) + content_id() + X(0, INT(100))
    body += per_message_indicators() + X(2, SET(ext_field(1, ENUM(1))))
    body += X(3, SEQ(recipient_submission(), recipient_submission(orname(prmd_name='Two'))))
    body += X(4, ms_submission_options())
    return SET(body)


def ms_probe_submission_result():
    return SET(mts_id('probe-1'), X(0, UTCT()), content_id(), X(1, SET(ext_field(35, signature()))),
               X(4, common_submission_results(0)))


def error_params():
    """(error code, parameter) for the message store errors."""
    return [
        (21, SET(X(0, SET(SET(X(0, INT(2)), X(1, OID(AT_SEQUENCE_NUMBER))),
                          SET(X(0, INT(0)), X(1, OID(AT_ENTRY_TYPE))))))),
        (22, SET(X(0, SET(SET(X(0, INT(1)), X(1, OID(AT_ENTRY_TYPE))))))),
        (23, SET(X(0, SET(SET(X(0, INT(1)), X(1, INT(3))))), X(1, SET(INT(4))))),
        (24, SET(X(0, SET(SET(X(3, INT(1)), X(0, OID('2.6.1.10.1'))))))),
        (24, SET(X(0, SET(SET(X(3, INT(2)), X(1, SET(OID('1.2.3.80')))))))),
        (24, SET(X(0, SET(SET(X(3, INT(3)), X(2, INT(100))))))),
        (25, SET(X(0, INT(0)))),
        (28, SET(X(1, SET(SET(X(0, INT(0)), X(1, INT(7))))))),
        (27, SET(X(0, INT(1)), X(1, GSTR('service info')))),
        (29, NULL()),
        (30, SET(X(0, INT(1)), X(1, SEQ(GSTR('group'))))),
        (31, X(0, ms_extension_item('2.6.4.9.5', SET()))),
        (31, X(1, OID('1.2.3.83'))),
        (32, SET(X(0, ENUM(2)), X(1, registration_types()))),
        (33, SET(X(0, SEQ(INT(1), INT(2))), X(1, INT(3)), X(2, INT(1)), X(3, INT(4)))),
        (34, SET(X(0, INT(1)), X(1, BITS(5, b'\x40')))),
    ]


def ms_ops(a, ipm_content):
    a.op(OP_SUMMARIZE, summarize_arg(True), summarize_result())
    a.op(OP_SUMMARIZE, SET(X(1, selector_time())), SET(X(1, INT(3))))
    a.op(OP_SUMMARIZE, SET(X(1, selector_filter(filters()[0]))), SET(X(1, INT(0))))
    for f in filters()[1:]:
        a.op(OP_LIST, SET(X(1, selector_filter(f))), SET())
    a.op(OP_LIST, list_arg(), list_result())
    a.op(OP_LIST, SET(X(1, selector_time())), SET(X(0, INT(2))))
    a.op(OP_FETCH, fetch_arg(True), fetch_result(True))
    a.op(OP_FETCH, fetch_arg(False), fetch_result(False))
    a.op(OP_DELETE, delete_arg(True), NULL())
    a.op(OP_DELETE, delete_arg(False), delete_result())
    a.op(OP_REGISTER_MS, register_arg(), NULL())
    a.op(OP_REGISTER_MS, SET(), register_result())
    a.op(OP_ALERT, alert_arg(True), NULL(), from_client=False)
    a.op(OP_ALERT, alert_arg(False), NULL(), from_client=False)
    a.op(OP_MODIFY, modify_arg(), SET(X(0, SEQ(INT(1), INT(2))), X(1, ms_extensions())))
    a.op(OP_MODIFY, modify_arg_selector(), SET())
    a.op(OP_MS_MESSAGE_SUBMISSION, ms_message_submission_arg(ipm_content), ms_message_submission_result(0))
    a.op(OP_MS_MESSAGE_SUBMISSION, ms_message_submission_arg(ipm_content), ms_message_submission_result(1))
    a.op(OP_MS_PROBE_SUBMISSION, ms_probe_submission_arg(), ms_probe_submission_result())
    for code, param in error_params():
        a.op(OP_LIST, list_arg(), error=(code, param))


def p7_oid_values(ipm):
    return [
        ('2.6.4.3.42', X(1, SEQ(SEQ(X(0, INT(2)), X(1, INT(2))), SEQ(X(0, INT(3)))))),
        ('2.6.4.3.42', X(0, NULL())),
        ('2.6.4.3.76', INT(5)), ('2.6.4.3.43', ENUM(4)),
        ('2.6.4.3.44', SEQ(X(0, INT(2)), X(1, INT(1)))),
        ('2.6.4.3.48', INT(6)), ('2.6.4.3.49', OID('2.6.4.3.6')),
        ('2.6.4.3.0', INT(7)), ('2.6.4.3.10', OID('1.2.3.90')), ('2.6.4.3.11', UTCT()),
        ('2.6.4.3.50', UTCT()), ('2.6.4.3.52', UTCT()), ('2.6.4.3.12', OID('1.2.3.91')),
        ('2.6.4.3.16', INT(3)), ('2.6.4.3.57', SEQ(GSTR('a'), GSTR('b'))),
        ('2.6.4.3.61', X(1, NULL())), ('2.6.4.3.61', X(2, NULL())), ('2.6.4.3.61', X(3, SEQ(orname()))),
        ('2.6.4.3.61', X(4, NULL())), ('2.6.4.3.61', X(11, NULL())), ('2.6.4.3.61', X(12, INT(5))),
        ('2.6.4.3.61', X(13, NULL())), ('2.6.4.3.61', X(15, NULL())),
        ('2.6.4.3.61', X(27, SET(X(0, INT(1)), X(1, GSTR('info'))))),
        ('2.6.4.3.61', X(30, SET(X(0, INT(1)), X(1, SEQ(GSTR('g')))))),
        ('2.6.4.3.61', tlv(b'\xbf\x1f', X(1, OID('1.2.3.84')))),
        ('2.6.4.3.61', tlv(b'\xbf\x22', SET(X(0, INT(0)), X(1, BITS(5, b'\x40'))))),
        ('2.6.4.3.25', OID('1.2.3.92')), ('2.6.4.3.29', INT(8)), ('2.6.4.3.15', INT(2)),
        ('2.6.4.3.39', INT(9)),
        ('2.6.4.3.79', SET(X(0, INT(2)), X(1, INT(8)), X(2, INT(0)), X(3, INT(3)), X(4, INT(1)), X(5, INT(7)))),
        ('2.6.4.3.73', INT(86400)), ('2.6.4.3.74', UTCT()),
        ('2.6.0.2.10', tlv(0xb2, INT(0, 0x80))),
        ('2.6.0.2.10', INT(3)), ('2.6.0.2.10', OCTS(b'transfer')),
        ('2.6.0.2.10', tlv(0xb6, INT(0, 0x80), BITS(0, b'\x01', 0x81), X(2, NULL()))),
        ('2.6.4.9.5', SET(OID('1.2.840.113549.1.1.5'))),
        ('2.6.4.9.3', asym_token()),
        ('2.6.4.9.4', SEQ(OID('1.2.840.113549.1.1.5', 0x80), X(2, IA5('old')), BITS(0, b'\x01', 0x82))),
    ]


def main_pcapng():
    p = Pcapng()
    ipm = ipmlib.ipm(ipmlib.heading(False), ipmlib.body(ipmlib.ia5_bp('stored')))
    F = []
    a = Assoc(F, 46001, AC_MS_ACCESS_88, [(CTX, AS_MS_88)])
    a.open()
    a.bind(ms_bind_arg())
    a.bind_result(ms_bind_result())
    ms_ops(a, ipm)
    a.close()
    for i, cr in enumerate((X(2, OCTS(b'secret')), creds_strong(), creds_protected())):
        b = Assoc(F, 46002 + i, AC_MS_ACCESS_88, [(CTX, AS_MS_88)])
        b.open()
        b.bind(ms_bind_arg(cr, False))
        b.bind_result(ms_bind_result(False))
        b.close()
    for i, k in enumerate((0, 1)):
        b = Assoc(F, 46010 + i, AC_MS_ACCESS_88, [(CTX, AS_MS_88)])
        b.open()
        b.bind(ms_bind_arg(None, False))
        b.bind_error(bind_error(k))
        b.close()
    p.eth(F)
    vals = p7_oid_values(ipm)
    n = int(os.environ.get('CHUNK', '6'))
    for i in range(0, len(vals), n):
        p.exp('x509af', crl_with_exts(*vals[i:i + n]))
    return p


def creds_strong():
    return X(2, tlv(0xa0, imp(0, asym_token(data_type=1)), imp(1, certificates()),
                    imp(2, SEQ(INT(7, 0x80)))))


def creds_protected():
    return X(2, tlv(0xa1, signature(), UTCT(tag=0x80), UTCT(tag=0x81),
                    BITS(0, b'\x01', 0x82), BITS(0, b'\x02', 0x83)))


def malformed_frames():
    p = Pcapng()
    ipm = ipmlib.ipm(ipmlib.heading(False), ipmlib.body(ipmlib.ia5_bp('stored')))
    F = []
    a = Assoc(F, 47001, AC_MS_ACCESS_88, [(CTX, AS_MS_88)])
    a.open()
    a.bind(ms_bind_arg())
    a.bind_result(ms_bind_result())
    # Register-MS with registration-status-request holding extended-registrations
    # (an OID list): DISSECTOR_ASSERT_NOT_REACHED in packet-ber.c, the hf of the
    # item is FT_NONE (p7.cnf RegistrationTypes/extended-registrations/_item)
    a.op(OP_REGISTER_MS, SET(X(9, registration_types(True))), NULL())
    a.op(OP_LIST, list_arg(), error=(32, SET(X(0, ENUM(2)), X(1, registration_types(True)))))
    # optional ANY values the dissector does not consume (BER errors)
    a.op(OP_REGISTER_MS, SET(X(0, SET(auto_action_registration(True)))), NULL())
    ordered_a = SEQ(OID(AT_RETRIEVAL_STATUS), SEQ(SEQ(X(0, INT(2)), X(1, INT(1)))))
    ordered_b = SEQ(OID(AT_RETRIEVAL_STATUS), SEQ(SEQ(X(0, INT(1)))))
    a.op(OP_MODIFY, SET(X(0, INT(3)), X(2, SEQ(INT(1))),
                        X(3, SEQ(SET(X(3, ordered_a)), SET(X(4, ordered_b))))), SET())
    a.op(OP_LIST, list_arg(), error=(21, SET(X(0, SET(SET(X(0, INT(2)), X(1, OID(AT_SEQUENCE_NUMBER)),
                                                         X(2, INT(5))))))))
    # operations and errors the P7 tables do not have, an unknown operation and error
    a.op(OP_CANCEL_DEFERRED, mts_id('sub-1'), NULL())
    a.op(OP_LIST, list_arg(), error=(12, INT(5)))
    a.op(OP_LIST, list_arg(), error=(26, NULL()))
    a.op(OP_LIST, list_arg(), error=(99, NULL()))
    a.op(99, NULL(), NULL())
    # a filter that names an attribute type without a dissector, an unknown auto action
    a.op(OP_SUMMARIZE, SET(X(1, SET(X(2, X(0, X(0, SEQ(OID('1.2.3.99'), INT(1)))))))), SET(X(1, INT(0))))
    a.op(OP_REGISTER_MS, SET(X(0, SET(SEQ(OID('1.2.3.98'))))), SET())
    a.close()
    # a bind with a bad credential type and a bind error that is not a bind error
    b = Assoc(F, 47002, AC_MS_ACCESS_88, [(CTX, AS_MS_88)])
    b.open()
    b.bind(ms_bind_arg(X(2, tlv(0xa2, NULL()))))
    b.bind_error(NULL())
    b.close()
    p.eth(F)
    # auto-action-error attributes: the error code is dissected with an hf that is
    # not an integer type (an expert info from dissect_ber_choice)
    p.exp('x509af', crl_with_exts(('2.6.4.3.46', SET(X(0, INT(4)), X(1, NULL()))),
                                  ('2.6.4.3.46', SET(X(0, OID('2.6.4.3.6')), X(1, INT(5))))))
    # a P7 attribute value with the wrong type, and a truncated one
    p.exp('x509af', crl_with_exts(('2.6.4.3.11', INT(5)), ('2.6.4.3.16', UTCT()), ('2.6.4.3.61', NULL(0x70))))
    p.exp('x509af', crl_with_exts(('2.6.4.3.79', SET(X(0, INT(2)), b'\x81\x05\x02')),))
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_pcapng().write(os.path.join(out, 'p7-coverage.pcapng'))
    malformed_frames().write(os.path.join(out, 'p7-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
