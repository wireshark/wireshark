#!/usr/bin/env python3
# Generates test/captures/disp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DISP dissector
(packet-disp.c, X.525/X.519 Directory Information Shadowing Protocol,
generated from epan/dissectors/asn1/disp).

DISP runs over ROSE or RTSE. The main capture carries it over the OSI
upper layers on TCP port 102 (TPKT, COTP, session, presentation, ACSE):
  - ROS associations with the application contexts
    shadow-consumer-initiated (2.5.3.4) and shadow-supplier-initiated
    (2.5.3.5) and the abstract syntax id-as-directory-shadow (2.5.9.3):
    binds, bind errors, every operation with every argument and result
    choice, and shadowError;
  - RTSE associations with the reliable shadow application contexts
    (2.5.3.6, 2.5.3.7) and abstract syntaxes (2.5.9.5, 2.5.9.6): the
    bind argument in the RTORQ and the bind result in the RTOAC of the
    A-ASSOCIATE;
  - a DOP association (2.5.3.3, 2.5.9.4) whose establish and modify
    operations use the shadow operational binding (2.5.19.1), which hands
    the agreement and the role parameters to DISP;
  - an IDMP connection (TCP port 1102) with the review reproducer for
    "DISP: Close the parenthesis of an unknown standard update strategy".

Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkdisp.py <output directory>

Writes:
  disp-coverage.pcap            see above
  disp-coverage-malformed.pcap  unknown opcodes and error codes, an
                                unbind, RTSE transfers (always decoded
                                as opcode 0), truncated and wrongly
                                tagged PDUs
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from x500lib import (  # noqa: E402,
    access_point, alg, Assoc, AT_CN, AT_GN, AT_OC, AT_SN, AT_TEL, attribute, bind_arg,
    bind_error_data, BITS, BOOL, context_selection, dn, DN_ADMIN, DN_BOB, DN_DSA, DN_ORG, ENUM,
    GENT, Idmp, INT, NULL, OC_PERSON, OCTS, OID, presentation_address, PSTR, R_CN, R_CN2, R_O,
    R_OU, rtoac, rtorq, rttr, security_parameters, SEQ, SET, simple_creds, tlv, user_info, UTF8,
    write_pcap, X,
)

AC_CONSUMER = '2.5.3.4'
AC_SUPPLIER = '2.5.3.5'
AC_REL_CONSUMER = '2.5.3.6'
AC_REL_SUPPLIER = '2.5.3.7'
AC_DOP = '2.5.3.3'
AS_SHADOW = '2.5.9.3'
AS_REL_SHADOW = '2.5.9.5'
AS_REL_BINDING = '2.5.9.6'
AS_DOP = '2.5.9.4'
IDMP_DISP = '2.5.9.3'
SHADOW_AGREEMENT = '2.5.19.1'
CTX = 3

REQUEST, UPDATE, COORDINATE = 1, 2, 3
SHADOW_ERROR = 1
DOP_ESTABLISH, DOP_TERMINATE, DOP_MODIFY = 100, 101, 102


def retag(tag, enc):
    """Replace the outer tag of a BER encoding (IMPLICIT tagging)."""
    return bytes([tag]) + enc[1:]


def agreement_id(i=1, v=1):
    return SEQ(INT(i), INT(v))


def time(s='20261101120000Z'):
    return GENT(s)


def update_window():
    if not TIMES:           # dates only (BER warnings), see usa_data()
        return SEQ(GENT('20261101'), GENT('20261102'))
    return SEQ(time('20261101000000Z'), time('20261102000000Z'))


def attrs_seq():
    return SEQ(attribute(AT_CN, PSTR('note')))


def common_results(variant=0):
    """securityParameters [30], performer [29], aliasDereferenced [28],
    notification [27] (IMPLICIT)."""
    return (retag(0xbe, security_parameters(variant)) + retag(0xbd, DN_ADMIN)
            + BOOL(True, 0x9c) + retag(0xbb, attrs_seq()))


def signed_data(tag, data):
    return SEQ(retag(tag, data), alg(), BITS(0, b'\x5a' * 16))


# ------------------------------------------------------- operations

# TIMES says whether to add the optional Time fields (lastUpdate,
# beginTime, update windows) and a valid mandatory updateTime. Both
# captures have them; they were a dissector bug (Time had the field type
# FT_STRING in disp.cnf) until "DISP: Close the parenthesis of an unknown
# standard update strategy" (see the README). Without TIMES the
# updateTime is a date without the time of day (a BER warning).
TIMES = False


def rsu_data(strategy, full=False):
    body = agreement_id()
    if full and TIMES:
        body += time()
    body += strategy
    if full:
        body += security_parameters(0)
    return SEQ(body)


def csu_data(strategy, full=False):
    return rsu_data(strategy, full)


def ext_strategy():
    # EXTERNAL with direct-reference and octet-aligned encoding
    return SEQ(OID('1.3.6.1.4.1.32473.2'), OCTS(b'strategy', 0x81), tag=0x28)


def information(full=True, signed=False, variant=0):
    body = agreement_id(1, 2)
    if full:
        body += (time() if TIMES else b'') + common_results(variant)
    data = SEQ(body)
    if signed:
        return signed_data(0xa0, data)
    return retag(0xa0, data)


def sdse(full=True):
    body = BITS(0, b'\x81\x40\x00')            # root, entry, shadow
    if full:
        body += BOOL(True, 0x80) + BOOL(False, 0x81)
    body += SET(attribute(AT_CN, PSTR('Alice Smith')), attribute(AT_OC, OID(OC_PERSON)))
    if full:
        body += SET(OID(AT_TEL))
    return SEQ(body)


def subtree(rdn_, sub=None, full=True):
    body = rdn_
    if full:
        body += sdse(False)
    if sub is not None:
        body += SET(*sub)
    return SEQ(body)


def total_refresh(full=True):
    if not full:
        return tlv(0xa0, b'')
    leaf = subtree(R_CN)
    mid = subtree(R_OU, [leaf, subtree(R_CN2, full=False)])
    return tlv(0xa0, sdse(), SET(subtree(R_O, [mid])))


def entry_modifications():
    return SEQ(X(0, attribute(AT_TEL, PSTR('+61 2 9999 0000'))),
               X(1, OID(AT_GN)),
               X(2, attribute(AT_CN, PSTR('Ali'))),
               X(3, attribute(AT_CN, PSTR('Al'))),
               X(4, SEQ(OID(AT_SN), UTF8('x'))),
               X(5, OID(AT_CN)),
               X(6, attribute(AT_SN, UTF8('Smith'))))


def content_change(variant):
    if variant == 0:
        body = R_CN2 + retag(0xa0, SET(attribute(AT_CN, PSTR('Bob Jones'))))
        body += BITS(0, b'\x40') + BOOL(True, 0x82) + BOOL(True, 0x83) + SET(OID(AT_TEL))
    else:
        body = DN_BOB + retag(0xa1, entry_modifications()) + BITS(0, b'\x40')
    return tlv(0xa1, body)


def step(change=None, subs=None):
    body = b''
    if change is not None:
        body += change
    if subs is not None:
        body += SEQ(*subs)
    return SEQ(body)


def incremental_refresh():
    sub_change = SEQ(R_CN, step(NULL()))
    nested = SEQ(R_OU, step(subs=[SEQ(R_CN2, step(retag(0xa0, sdse(False))))]))
    return tlv(0xa1,
               step(retag(0xa0, sdse())),                  # add
               step(NULL()),                               # remove
               step(content_change(0)),                    # modify, newRDN, replace
               step(content_change(1), [sub_change]),      # modify, newDN, changes
               step(subs=[nested]),                        # only subordinate updates
               step())                                     # empty


def usa_data(info, full=False):
    # without TIMES the mandatory updateTime is a date without the time
    # of day, which BER rejects (a warning) before it adds the field
    body = agreement_id() + (time() if TIMES else GENT('20261101'))
    if full:
        body += update_window()
    body += info
    if full:
        body += security_parameters(1)
    return SEQ(body)


def shadow_error_data(problem, full=False):
    body = INT(problem)
    if full:
        if TIMES:
            body += time() + update_window()
        body += common_results(1)
    return SEQ(body)


# ------------------------------------------------------- X.500 binds

def dsa_bind_arg():
    return bind_arg(simple_creds())


def dsa_bind_result():
    return bind_arg(simple_creds(DN_DSA, validity=False, password=None))


def update_ops(a):
    unsigned = lambda d: retag(0xa0, d)            # noqa: E731
    a.op(UPDATE, unsigned(usa_data(NULL(), True)), NULL(), from_client=False)
    a.op(UPDATE, unsigned(usa_data(total_refresh())), information(True), from_client=False)
    a.op(UPDATE, unsigned(usa_data(total_refresh(False))), NULL(), from_client=False)
    a.op(UPDATE, unsigned(usa_data(incremental_refresh())), information(False), from_client=False)
    a.op(UPDATE, unsigned(usa_data(ext_strategy())), information(True, signed=True), from_client=False)
    a.op(UPDATE, signed_data(0xa0, usa_data(total_refresh(), True)), NULL(), from_client=False)


def shadow_ops(a):
    """Every DISP operation over ROS, with every argument and result."""
    unsigned = lambda d: retag(0xa0, d)            # noqa: E731
    # requestShadowUpdate
    a.op(REQUEST, unsigned(rsu_data(ENUM(1), True)), NULL())
    a.op(REQUEST, unsigned(rsu_data(ENUM(2))), information(True))
    a.op(REQUEST, unsigned(rsu_data(ENUM(9))), information(False))
    a.op(REQUEST, unsigned(rsu_data(ext_strategy())), information(True, signed=True))
    a.op(REQUEST, signed_data(0xa0, rsu_data(ENUM(1), True)), information(True, variant=1))
    # coordinateShadowUpdate
    a.op(COORDINATE, unsigned(csu_data(ENUM(0), True)), NULL(), from_client=False)
    a.op(COORDINATE, unsigned(csu_data(ENUM(1))), information(True), from_client=False)
    a.op(COORDINATE, unsigned(csu_data(ENUM(2))), information(False, signed=True), from_client=False)
    a.op(COORDINATE, unsigned(csu_data(ENUM(9))), NULL(), from_client=False)
    a.op(COORDINATE, unsigned(csu_data(ext_strategy())), NULL(), from_client=False)
    a.op(COORDINATE, signed_data(0xa0, csu_data(ENUM(1), True)), NULL(), from_client=False)
    # updateShadow (updateTime is mandatory)
    update_ops(a)
    # shadowError: every problem, with and without every field, signed
    for p in range(1, 12):
        a.op(REQUEST, unsigned(rsu_data(ENUM(1))),
             error=(SHADOW_ERROR, shadow_error_data(p, p == 3)))
    a.op(REQUEST, unsigned(rsu_data(ENUM(1))), error=(SHADOW_ERROR, shadow_error_data(99)))
    a.op(REQUEST, unsigned(rsu_data(ENUM(1))),
         error=(SHADOW_ERROR, tlv(0xa0, shadow_error_data(6, True), alg(), BITS(0, b'\x5a' * 16))))


# ------------------------------------------------------- DOP: shadow binding

def access_point_dsp():
    return SET(X(0, DN_DSA), X(1, presentation_address()),
               X(2, SET(SEQ(OCTS(b'\x00\x01\x02\x03'), SET(OID('2.5.33.0'))))))


def subtree_spec(variant=0):
    if variant == 0:
        return SEQ(X(0, dn(R_OU)),
                   X(1, SET(X(0, dn(R_CN)), X(1, dn(R_CN2)))),
                   X(2, INT(0)), X(3, INT(4)),
                   X(4, X(1, SET(X(0, OID(OC_PERSON)),
                                 X(3, X(0, OID('2.5.6.7'))),
                                 X(2, SET(X(0, OID('2.5.6.5'))))))))
    return SEQ()


def unit_of_replication(full=True):
    area = SEQ(DN_ORG, subtree_spec(0 if full else 1))
    sel = SET(SEQ(OID(OC_PERSON), retag(0xa0, SET(OID(AT_CN), OID(AT_SN)))),
              SEQ(OID('2.5.6.5'), retag(0xa1, SET(OID(AT_TEL)))),
              SEQ(NULL()),
              SEQ())
    body = area + sel
    if full:
        body += SEQ(ENUM(2), BOOL(True)) + BOOL(True) + context_selection(True, True)
        body += tlv(0xa0, SET(OID(AT_CN)))
    else:
        body += SEQ(ENUM(0)) + tlv(0xa0, NULL())
    return SEQ(body)


def shadowing_agreement(variant):
    if variant == 0:      # supplier initiated on change, a master, secondary shadows
        return SEQ(unit_of_replication(), tlv(0xa0, BOOL(True)),
                   access_point_dsp(), BOOL(True, 0x82))
    if variant == 1:      # supplier initiated, scheduled
        sched = SEQ(SEQ((time() if TIMES else b'') + INT(3600) + INT(600)), BOOL(False))
        return SEQ(unit_of_replication(False), tlv(0xa0, sched))
    if variant == 2:      # consumer initiated
        return SEQ(unit_of_replication(False), tlv(0xa1, SEQ(INT(60), INT(30))))
    return SEQ(unit_of_replication(False), tlv(0xa1, BOOL(True)))


def modification_parameter():
    sac = SET(X(0, DN_DSA), X(1, presentation_address()),
              X(2, SET(SEQ(OCTS(b'\x00\x01'), SET(OID('2.5.33.0'))))),
              X(3, SET(access_point(), access_point())))
    return SEQ(SET(sac, SET(X(0, DN_ADMIN), X(1, presentation_address()), X(3, SET()))))


def dop_ops(d):
    """establish, modify and terminate a shadow operational binding;
    DOP hands the agreement and the role parameters to DISP."""
    bt = X(0, OID(SHADOW_AGREEMENT))
    for i, (role, agr) in enumerate(((4, 0), (5, 1), (4, 2), (5, 3))):
        arg = SEQ(bt, X(1, agreement_id(i + 1, 1)), X(2, access_point()),
                  X(role, NULL()), X(6, shadowing_agreement(agr)))
        res = SEQ(bt, X(1, agreement_id(i + 1, 1)), X(2, access_point()),
                  X(role, NULL()))
        d.op(DOP_ESTABLISH, arg, res)
    for role in (4, 5):
        arg = SEQ(bt, X(1, agreement_id(1, 1)), X(role, modification_parameter()),
                  X(6, agreement_id(1, 2)), X(7, shadowing_agreement(0)))
        d.op(DOP_MODIFY, arg, X(0, NULL()))


# ------------------------------------------------------- the captures

def main_frames():
    global TIMES
    TIMES = True
    F = []
    # ROS, consumer initiated: bind, every operation, unbind-less release
    a = Assoc(F, 40001, AC_CONSUMER, [(CTX, AS_SHADOW)])
    a.open()
    a.bind(dsa_bind_arg())
    a.bind_result(dsa_bind_result())
    shadow_ops(a)
    a.close()
    # ROS, supplier initiated: bind errors
    for i, err in enumerate((bind_error_data('service', 2),
                             bind_error_data('security', 7, secp=True))):
        b = Assoc(F, 40002 + i, AC_SUPPLIER, [(CTX, AS_SHADOW)])
        b.open()
        b.bind(dsa_bind_arg())
        b.bind_error(err)
        b.close()
    # RTSE: the bind in the A-ASSOCIATE
    for i, (ac, asx) in enumerate(((AC_REL_CONSUMER, AS_REL_SHADOW),
                                   (AC_REL_SUPPLIER, AS_REL_BINDING))):
        r = Assoc(F, 40004 + i, ac, [(CTX, asx)])
        r.open(user_info(CTX, rtorq(dsa_bind_arg())),
               user_info(CTX, rtoac(dsa_bind_result())))
        r.close()
    # DOP with the shadow operational binding
    d = Assoc(F, 40006, AC_DOP, [(CTX, AS_DOP)])
    d.open()
    d.bind(dsa_bind_arg())
    d.bind_result(dsa_bind_result())
    dop_ops(d)
    d.close()
    # IDMP: the review reproducer (bind, requestShadowUpdate with
    # standard strategy 1 and the unknown 7)
    agreement = SEQ(INT(1), INT(1))
    i = Idmp(F, 40007, IDMP_DISP)
    i.bind(SET())
    i.request(1, REQUEST, tlv(0xa0, agreement + ENUM(1)))
    i.request(2, REQUEST, tlv(0xa0, agreement + ENUM(7)))
    TIMES = False
    return F


def malformed_frames():
    global TIMES
    F = []
    a = Assoc(F, 41001, AC_CONSUMER, [(CTX, AS_SHADOW)])
    a.open()
    a.bind(dsa_bind_arg())
    a.bind_result(dsa_bind_result())
    # every operation again with the Time fields (a dissector bug before
    # the fix; now the same as in the main capture)
    TIMES = True
    shadow_ops(a)
    d = Assoc(F, 41003, AC_DOP, [(CTX, AS_DOP)])
    d.open()
    dop_ops(d)
    d.close()
    TIMES = False
    a.op(9, NULL(), NULL())                                   # unknown opcode
    a.op(REQUEST, retag(0xa0, rsu_data(ENUM(1))), error=(9, NULL()))   # unknown error
    a.unbind()                                                # not a DISP PDU
    a.op(REQUEST, bytes([0xa0, 0x10, 0x30, 0x06]))            # truncated
    a.op(REQUEST, INT(5))                                     # wrong tag
    a.op(UPDATE, retag(0xa0, usa_data(tlv(0xa5, NULL()))))    # unknown refresh choice
    a.op(COORDINATE, retag(0xa0, csu_data(ENUM(1))), tlv(0x82, b''))   # bad result
    a.op(REQUEST, retag(0xa0, rsu_data(ENUM(1))), error=(SHADOW_ERROR, OCTS(b'x')))
    a.close()
    # RTSE transfers: DISP always sees opcode 0
    r = Assoc(F, 41002, AC_REL_SUPPLIER, [(CTX, AS_REL_SHADOW)])
    r.open(user_info(CTX, rtorq(dsa_bind_arg())), user_info(CTX, rtoac(dsa_bind_result())))
    r.pdata(False, rttr(CTX, retag(0xa0, usa_data(NULL()))))
    r.close()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'disp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'disp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
