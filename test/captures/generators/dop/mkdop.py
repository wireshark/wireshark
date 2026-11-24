#!/usr/bin/env python3
# Generates test/captures/dop_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DOP dissector
(packet-dop.c, X.501/X.519 Directory Operational Binding Management
Protocol, generated from epan/dissectors/asn1/dop).

DOP runs over ROSE. The main capture carries it over the OSI upper
layers on TCP port 102 (TPKT, COTP, session, presentation, ACSE): an
A-ASSOCIATE with the application context
id-ac-directory-operational-binding-management (2.5.3.3) sets up the
abstract syntax id-as-directory-operational-binding-management
(2.5.9.4), and every DOP PDU is a ROS bind or invoke/result/error on
it. The hierarchical (2.5.19.2) and non-specific hierarchical
(2.5.19.3) operational bindings have their role parameters and
agreements registered by DOP itself; the DSA operational attributes
(2.5.12.0, 2.5.12.5-7) and the ACI attributes (2.5.24.4-6) are carried
in the entry information of those parameters.

Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkdop.py <output directory>

Writes:
  dop-coverage.pcap            binds, bind errors, establish, modify and
                               terminate with every parameter, unsigned
                               and signed, their results and every
                               operational binding error, parameters of
                               unknown binding types, and the reproducers
                               of "DOP: Reset the binding type for each
                               PDU" (an error without binding type after
                               an establish with one, and an agreement,
                               whose callback has no Info column text)
  dop-coverage-malformed.pcap  unknown opcodes and error codes, an
                               unbind, truncated and wrongly tagged PDUs,
                               and the two review reproducers over IDMP
                               (their access points are SEQUENCEs, not
                               SETs)
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from x500lib import (  # noqa: E402,
    access_point, alg, Assoc, AT_CN, AT_MEMBER, AT_OC, AT_SN, AT_TEL, attribute, bind_arg,
    bind_error_data, BITS, BOOL, ctx_assertion, dn, DN_ADMIN, DN_ALICE, DN_BOB, DN_DSA, DN_ORG,
    ENUM, f_item, fi_present, GENT, Idmp, INT, NULL, OC_PERSON, OCTS, OID, presentation_address,
    PSTR, R_C, R_CN, R_CN2, R_O, R_OU, rdn, security_parameters, SEQ, SET, simple_creds, tlv,
    UTCT, UTF8, write_pcap, X,
)

AC_DOP = '2.5.3.3'
AS_DOP = '2.5.9.4'
IDMP_DOP = '2.5.9.4'
CTX = 3

SHADOW = '2.5.19.1'
HOB = '2.5.19.2'
NHOB = '2.5.19.3'
UNKNOWN_BT = '1.3.6.1.4.1.32473.19'

ESTABLISH, TERMINATE, MODIFY = 100, 101, 102
OP_BINDING_ERROR = 100

AT_DSETYPE = '2.5.12.0'
AT_SUPPLIER = '2.5.12.5'
AT_CONSUMER = '2.5.12.6'
AT_SECONDARY = '2.5.12.7'
AT_PRESCRIPTIVE_ACI = '2.5.24.4'
AT_ENTRY_ACI = '2.5.24.5'
AT_SUBENTRY_ACI = '2.5.24.6'


def binding_id(i=1, v=1):
    return SEQ(INT(i), INT(v))


def bt(oid):
    return X(0, OID(oid))


def protocol_information():
    return SET(SEQ(OCTS(b'\x00\x01\x02\x03'), SET(OID('2.5.33.0'))))


def access_point_full():
    return SET(X(0, DN_DSA), X(1, presentation_address()), X(2, protocol_information()),
               X(6, UTF8('ldap://dsa-1.example.org/ dsa-1')))


def masap():
    """MasterAndShadowAccessPoints with every field."""
    return SET(SET(X(0, DN_DSA), X(1, presentation_address()), X(2, protocol_information()),
                   X(3, ENUM(0)), X(5, BOOL(True))),
               SET(X(0, DN_ADMIN), X(1, presentation_address()), X(3, ENUM(1))))


def validity(variant=0):
    if variant == 0:
        return SEQ(X(0, X(0, NULL())), X(1, X(0, NULL())))
    if variant == 1:
        return SEQ(X(0, X(1, UTCT())), X(1, X(1, GENT('20271101120000Z'))))
    return SEQ()


def subtree_spec():
    return SEQ(X(0, dn(R_OU)), X(1, SET(X(0, dn(R_CN)), X(1, dn(R_CN2)))),
               X(2, INT(0)), X(3, INT(2)), X(4, X(0, OID(OC_PERSON))))


# ------------------------------------------------------- ACI (X.501 basic access control)

def protected_items():
    return SEQ(X(0, NULL()), X(1, NULL()), X(2, SET(OID(AT_CN))), X(3, SET(OID(AT_SN))),
               X(4, NULL()), X(5, SET(SEQ(OID(AT_CN), PSTR('Alice Smith')))),
               X(6, SET(OID(AT_MEMBER))), X(7, f_item(fi_present(AT_TEL))),
               X(8, SET(SEQ(OID(AT_TEL), INT(3)))), X(9, INT(100)),
               X(10, SET(SEQ(OID(AT_MEMBER), OID(AT_CN)))),
               X(11, SET(ctx_assertion())), X(12, X(0, OID(OC_PERSON))))


def user_classes():
    return SEQ(X(0, NULL()), X(1, NULL()),
               X(2, SET(SEQ(DN_ALICE, BITS(0, b'\x01')), SEQ(DN_BOB))),
               X(3, SET(SEQ(DN_ADMIN))), X(4, SET(subtree_spec())))


GRANTS_ALL = BITS(6, b'\xff\xff\xff\xc0')       # all 26 grants and denials


def aci_item(variant):
    if variant == 0:      # item first, basic levels with every field
        perms = SET(SEQ(INT(3), user_classes(), GRANTS_ALL),
                    SEQ(SEQ(X(0, NULL())), BITS(7, b'\x80')))
        return SEQ(PSTR('aci-item-first'), INT(10), SEQ(ENUM(2), INT(1), BOOL(True)),
                   X(0, SEQ(protected_items(), perms)))
    if variant == 1:      # user first, other authentication level
        perms = SET(SEQ(INT(2), protected_items(), GRANTS_ALL),
                    SEQ(SEQ(X(0, NULL())), BITS(6, b'\x40')))
        other = SEQ(OID('1.3.6.1.4.1.32473.24'), OCTS(b'level', 0x81), tag=0x28)
        return SEQ(UTF8('aci-user-first'), INT(5), other, X(1, SEQ(user_classes(), perms)))
    return SEQ(UTF8('aci-min'), INT(0), SEQ(ENUM(0)), X(0, SEQ(SEQ(), SET())))


# ------------------------------------------------------- DSA operational attributes

def supplier_information():
    return SET(X(0, DN_DSA), X(1, presentation_address()), X(2, protocol_information()),
               X(3, binding_id(7, 1)), X(4, BOOL(False)), X(5, access_point_full()))


def consumer_information():
    return SET(X(0, DN_ADMIN), X(1, presentation_address()), X(2, protocol_information()),
               X(3, binding_id(8, 1)))


def supplier_and_consumers():
    return SET(X(0, DN_DSA), X(1, presentation_address()), X(2, protocol_information()),
               X(3, SET(access_point(), access_point_full())))


def entry_info(full=True):
    if not full:
        return SET(attribute(AT_OC, OID(OC_PERSON)))
    return SET(attribute(AT_DSETYPE, BITS(0, b'\x81\x40\x00')),
               attribute(AT_SUPPLIER, supplier_information()),
               attribute(AT_CONSUMER, consumer_information()),
               attribute(AT_SECONDARY, supplier_and_consumers()),
               attribute(AT_ENTRY_ACI, aci_item(0)),
               attribute(AT_OC, OID(OC_PERSON)))


def subentries():
    return SET(SEQ(X(0, rdn((AT_CN, PSTR('aci subentry')))),
                   X(1, SET(attribute(AT_SUBENTRY_ACI, aci_item(1)),
                            attribute(AT_PRESCRIPTIVE_ACI, aci_item(2))))))


def dit_context(full=True):
    if not full:
        return SEQ(SEQ(X(0, R_C)))
    return SEQ(SEQ(X(0, R_C), X(1, SET(attribute(AT_PRESCRIPTIVE_ACI, aci_item(0)))),
                   X(2, subentries()), X(3, masap())),
               SEQ(X(0, R_O)),
               SEQ(X(0, R_OU), X(3, masap())))


# role parameters and agreements of the hierarchical bindings

def sup_to_sub(full=True):
    if not full:
        return SEQ(X(0, dit_context(False)))
    return SEQ(X(0, dit_context()), X(1, entry_info()), X(2, entry_info(False)))


def sub_to_sup(full=True):
    if not full:
        return SEQ()
    return SEQ(X(0, masap()), X(1, BOOL(False)), X(2, entry_info()), X(3, subentries()))


def sup_to_sub_mod():
    return SEQ(X(0, dit_context()), X(2, entry_info(False)))


def hob_agreement():
    return SEQ(X(0, R_CN), X(1, DN_ORG))


def nhob_agreement():
    return SEQ(X(1, DN_ORG))


def nhob_sup_to_sub(full=True):
    if not full:
        return SEQ(X(0, dit_context(False)))
    return SEQ(X(0, dit_context()), X(2, entry_info(False)))


def nhob_sub_to_sup(full=True):
    if not full:
        return SEQ()
    return SEQ(X(0, masap()), X(3, subentries()))


ROLE_PARAMS = {
    (HOB, 4): sup_to_sub, (HOB, 5): sub_to_sup,
    (NHOB, 4): nhob_sup_to_sub, (NHOB, 5): nhob_sub_to_sup,
}
AGREEMENT = {HOB: hob_agreement, NHOB: nhob_agreement}


def common_results(variant=0):
    return (X(30, security_parameters(variant)) + X(29, DN_ADMIN) + X(28, BOOL(True))
            + X(27, SEQ(attribute(AT_CN, PSTR('notice')))))


def signed(data):
    return SEQ(data, alg(), BITS(0, b'\x5a' * 16))


# ------------------------------------------------------- operations

def establish_arg(btype, role, i, full=True):
    body = bt(btype) + X(1, binding_id(i, 1)) + X(2, access_point_full() if full else access_point())
    body += X(role, ROLE_PARAMS[(btype, role)]())
    body += X(6, AGREEMENT[btype]())
    if full:
        body += X(7, validity(i % 2)) + X(8, security_parameters(i % 2))
    return SEQ(body)


def establish_res(btype, role, i, full=True):
    body = bt(btype) + X(1, binding_id(i, 1)) + X(2, access_point())
    if role is not None:
        # roleA initiates -> roleB replies with its parameter and vice versa
        reply = 5 if role == 4 else 4
        body += X(reply, ROLE_PARAMS[(btype, reply)](False))
    if full:
        body += common_results(i % 2)
    return SEQ(body)


def modify_arg(btype, role, i, full=True):
    body = bt(btype) + X(1, binding_id(i, 1))
    if full:
        body += X(2, access_point())
    if role is not None:
        body += X(role, sup_to_sub_mod() if (btype, role) == (HOB, 4) else ROLE_PARAMS[(btype, role)]())
    body += X(6, binding_id(i, 2))
    if full:
        body += X(7, AGREEMENT[btype]()) + X(8, validity(1)) + X(9, security_parameters(0))
    return SEQ(body)


def modify_res(btype, i, full=True):
    body = binding_id(i, 2) + OID(btype) + AGREEMENT[btype]()
    if full:
        body += validity(0) + common_results(1)
    return X(1, signed(SEQ(body)))


def terminate_arg(btype, i, initiator=None, at=None, full=False):
    body = bt(btype) + X(1, binding_id(i, 2))
    if initiator is not None:
        body += X(initiator, NULL())
    if at is not None:
        body += X(5, at)
    if full:
        body += X(6, security_parameters(1))
    return SEQ(body)


def terminate_res(btype, i, full=True):
    body = binding_id(i, 2) + OID(btype)
    if full:
        body += GENT('20261231235959Z') + common_results(0)
    return X(1, signed(SEQ(body)))


def op_binding_error(problem, btype=None, agreement=None, retry=None, full=False):
    body = X(0, INT(problem))
    if btype is not None:
        body += X(1, OID(btype))
    if agreement is not None:
        body += X(2, agreement)
    if retry is not None:
        body += X(3, retry)
    if full:
        body += common_results(1)
    return SEQ(body)


def dop_ops(d):
    # establish: every binding type and role (the signed arguments cannot
    # be decoded, see the README; they are in the malformed capture)
    i = 0
    for btype in (HOB, NHOB):
        for role in (4, 5):
            i += 1
            d.op(ESTABLISH, establish_arg(btype, role, i), establish_res(btype, role, i))
    # modify: every binding type and role, without initiator, signed
    i = 0
    for btype in (HOB, NHOB):
        for role in (4, 5):
            i += 1
            d.op(MODIFY, modify_arg(btype, role, i), modify_res(btype, i))
    d.op(MODIFY, modify_arg(HOB, None, 5, False), X(0, NULL()))
    d.op(MODIFY, modify_arg(NHOB, 4, 6), modify_res(NHOB, 6, False))
    # terminate: with both times, signed; results null and protected
    d.op(TERMINATE, terminate_arg(HOB, 1, at=UTCT(), full=True), X(0, NULL()))
    d.op(TERMINATE, terminate_arg(NHOB, 2, at=GENT()), terminate_res(NHOB, 2))
    d.op(TERMINATE, terminate_arg(HOB, 3), terminate_res(HOB, 3, False))
    # operational binding errors: every problem, the first with every field
    for p in range(0, 11):
        if p == 0:
            err = op_binding_error(p, HOB, hob_agreement(), UTCT(), True)
        elif p == 1:
            err = op_binding_error(p, NHOB, nhob_agreement(), GENT())
        else:
            err = op_binding_error(p, HOB)
        d.op(ESTABLISH, establish_arg(HOB, 4, 10 + p, False), error=(OP_BINDING_ERROR, err))
    d.op(ESTABLISH, establish_arg(HOB, 4, 30, False), error=(OP_BINDING_ERROR, op_binding_error(99)))


def stale_binding_type(d):
    """The reproducer of "DOP: Reset the binding type for each PDU": an
    establish with the hierarchical binding type, answered by an
    operational binding error without a binding type but with an
    agreement proposal. The binding type of the error must not be the
    one of the establish (a string freed with the earlier packet)."""
    d.op(ESTABLISH, establish_arg(HOB, 4, 40, False),
         error=(OP_BINDING_ERROR, op_binding_error(8, agreement=hob_agreement())))


def unknown_parameters(d):
    """Parameters that DOP has no dissector for: the symmetric initiator
    (no binding type has one), terminate initiators, an unknown binding
    type, and the shadow binding type whose parameters DISP has."""
    d.op(ESTABLISH, SEQ(bt(HOB), X(2, access_point()), X(3, NULL()), X(6, hob_agreement())),
         SEQ(bt(HOB), X(2, access_point()), X(3, NULL())))
    d.op(ESTABLISH, SEQ(bt(UNKNOWN_BT), X(2, access_point()), X(4, INT(1)), X(6, SEQ(INT(2)))))
    d.op(MODIFY, SEQ(bt(HOB), X(1, binding_id(1, 1)), X(3, NULL()), X(6, binding_id(1, 2))),
         X(0, NULL()))
    for init in (2, 3, 4):
        d.op(TERMINATE, terminate_arg(NHOB, 1, initiator=init), X(0, NULL()))
    d.op(ESTABLISH, SEQ(bt(SHADOW), X(2, access_point()), X(4, NULL()),
                        X(6, SEQ(SEQ(SEQ(DN_ORG, SEQ()), SET())))),
         SEQ(bt(SHADOW), X(2, access_point()), X(5, NULL())))


# ------------------------------------------------------- the captures

def dsa_bind_arg():
    return bind_arg(simple_creds())


def dsa_bind_result():
    return bind_arg(simple_creds(DN_DSA, validity=False, password=None))


def main_frames():
    F = []
    d = Assoc(F, 40001, AC_DOP, [(CTX, AS_DOP)])
    d.open()
    d.bind(dsa_bind_arg())
    d.bind_result(dsa_bind_result())
    dop_ops(d)
    stale_binding_type(d)
    unknown_parameters(d)
    d.close()
    for i, err in enumerate((bind_error_data('service', 4),
                             bind_error_data('security', 2, secp=True))):
        b = Assoc(F, 40002 + i, AC_DOP, [(CTX, AS_DOP)])
        b.open()
        b.bind(dsa_bind_arg())
        b.bind_error(err)
        b.close()
    return F


def malformed_frames():
    F = []
    d = Assoc(F, 41001, AC_DOP, [(CTX, AS_DOP)])
    d.open()
    d.bind(dsa_bind_arg())
    d.bind_result(dsa_bind_result())
    d.op(9, NULL(), NULL())                                    # unknown opcode
    d.op(ESTABLISH, establish_arg(HOB, 4, 1, False), error=(9, NULL()))   # unknown error
    d.unbind()                                                 # not a DOP PDU
    # signed arguments: the unsigned choice (also a SEQUENCE) is taken
    d.op(ESTABLISH, signed(establish_arg(HOB, 4, 5, False)), establish_res(HOB, None, 5, False))
    d.op(MODIFY, signed(modify_arg(NHOB, 4, 6)), modify_res(NHOB, 6, False))
    d.op(TERMINATE, signed(terminate_arg(HOB, 3)), terminate_res(HOB, 3, False))
    d.op(ESTABLISH, bytes([0x30, 0x10, 0xa0, 0x05]))           # truncated
    d.op(MODIFY, INT(5))                                       # wrong tag
    d.op(TERMINATE, terminate_arg(HOB, 1), tlv(0xa5, b''))     # unknown result choice
    d.op(ESTABLISH, SEQ(bt(HOB), X(2, access_point()), X(4, SEQ(X(0, SEQ(SEQ(X(0, INT(1))))))),
                        X(6, hob_agreement())))                # bad DITcontext
    d.op(ESTABLISH, SEQ(X(0, BOOL(True)), X(2, access_point()), X(6, hob_agreement())))  # no OID
    d.close()
    # the review reproducers over IDMP (frames as in the review)
    i = Idmp(F, 41002, IDMP_DOP)
    i.bind(SET())
    # dop_stale_binding_type.py: bindingType with a long OID, then an
    # establish without binding type (junk elements in its place)
    bt_long = tlv(0xa0, tlv(0x06, bytes([0x55, 0x13, 0x01, 0x81, 0x80, 0x80, 0x01])))
    i.request(1, ESTABLISH, tlv(0x30, bt_long + tlv(0xa2, tlv(0x30, b'')) + tlv(0xa6, tlv(0x05, b''))))
    i.request(2, ESTABLISH, tlv(0x30, tlv(0xa9, b'') + tlv(0xa9, b'') + tlv(0xa4, tlv(0x05, b''))
                                + tlv(0xa6, tlv(0x05, b''))))
    # dop_agreement_null_colinfo.py: an establish with agreement [6]
    i.request(3, ESTABLISH, tlv(0x30, tlv(0xa0, tlv(0x06, bytes([0x55, 0x13, 0x02])))
                                + tlv(0xa2, tlv(0x30, b'')) + tlv(0xa6, tlv(0x30, b''))))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dop-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dop-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
