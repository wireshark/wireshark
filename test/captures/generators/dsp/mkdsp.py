#!/usr/bin/env python3
# Generates test/captures/dsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DSP dissector
(packet-dsp.c, X.518/X.519 Directory System Protocol, generated from
epan/dissectors/asn1/dsp).

DSP runs over ROSE. The main capture carries it over the OSI upper
layers on TCP port 102 (TPKT, COTP, session, presentation, ACSE): an
A-ASSOCIATE with the application context id-ac-directory-system
(2.5.3.2) sets up the abstract syntax id-as-directory-system (2.5.9.2),
and every DSP PDU is a ROS bind or invoke/result/error on it. The
chained operations carry the DAP arguments and results: every DAP
operation and error of dap-coverage (dapops.py) is sent again wrapped
in ChainingArguments and ChainingResults, unsigned and signed. The DSA
knowledge attributes DSP registers (2.5.12.1-4, 2.5.12.8) are carried
in the notification of a DSA referral. An IDMP connection (TCP port
1102) has a bind and a chained abandon.

Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkdsp.py <output directory>

Writes:
  dsp-coverage.pcap            see above
  dsp-coverage-malformed.pcap  securityError (its SPKM info is not
                               implemented in DAP), unknown opcodes and
                               error codes, an unbind, truncated and
                               wrongly tagged PDUs, and the review
                               reproducer dsp_col_protocol.py over IDMP
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from x500lib import (  # noqa: E402,
    access_point, access_point_information, alg, Assoc, AT_CN, attribute, ava, bind_arg,
    bind_error_data, BITS, BOOL, continuation_reference, dn, DN_ADMIN, DN_ALICE, DN_BOB, DN_DSA,
    DN_ORG, entry_information, ENUM, GENT, Idmp, INT, MR_CASEIGNORE, MR_NUMERIC, NULL, OCTS, OID,
    operation_progress, presentation_address, PSTR, R_C, R_CN2, R_O, R_OU, security_parameters,
    SEQ, SET, simple_creds, tlv, UTCT, UTF8, write_pcap, X,
)
import dapops
from dapops import ABANDON, READ  # noqa: E402

AC_DSP = '2.5.3.2'
AS_DSP = '2.5.9.2'
IDMP_DSP = '2.5.9.2'
CTX = 3
E_DSAREFERRAL = 9
E_SECURITY = 6

AT_MYAP = '2.5.12.1'
AT_SUPERIOR = '2.5.12.2'
AT_SPECIFIC = '2.5.12.3'
AT_NONSPECIFIC = '2.5.12.4'
AT_DITBRIDGE = '2.5.12.8'


def protocol_information():
    return SET(SEQ(OCTS(b'\x00\x01\x02\x03'), SET(OID('2.5.33.0'))))


def access_point_full():
    return SET(X(0, DN_DSA), X(1, presentation_address()), X(2, protocol_information()),
               X(6, UTF8('ldap://dsa-1.example.org/ dsa-1')))


def masap():
    return SET(SET(X(0, DN_DSA), X(1, presentation_address()), X(2, protocol_information()),
                   X(3, ENUM(0)), X(5, BOOL(True))),
               SET(X(0, DN_ADMIN), X(1, presentation_address()), X(3, ENUM(1))))


def ap_information_full():
    return SET(X(0, DN_DSA), X(1, presentation_address()), X(2, protocol_information()),
               X(3, ENUM(1)), X(5, BOOL(False)), X(4, masap()))


def trace_information():
    return SEQ(SET(X(0, DN_DSA), X(1, DN_ALICE), X(2, operation_progress(2, 3))),
               SET(X(0, DN_ADMIN), X(2, operation_progress(1, None))))


def chaining_arguments(variant):
    if variant == 0:      # every field
        return SET(X(0, DN_ADMIN), X(1, DN_ALICE), X(2, operation_progress(3, None)),
                   X(3, trace_information()), X(4, BOOL(True)), X(5, INT(1)),
                   X(6, BOOL(True)), X(7, ENUM(2)), X(8, OID('1.3.6.1.4.1.32473.8')),
                   X(9, UTCT()), X(10, security_parameters(0)), X(11, BOOL(False)),
                   X(12, BITS(0, b'\x12\x34')), X(13, SEQ(ENUM(2), INT(7), BOOL(True))),
                   X(14, SET(dn(R_C, R_O, R_OU), dn(R_C))), X(15, BOOL(True)),
                   X(16, BOOL(True)), X(17, INT(4242)),
                   X(18, SEQ(INT(3), X(0, OID('1.3.6.1.4.1.32473.18')))),
                   X(19, SEQ(X(0, SEQ(SEQ(OID('1.3.6.1.4.1.32473.19'), INT(1)))),
                             X(1, SEQ(SEQ(OID(AT_CN), X(0, OID(MR_CASEIGNORE)),
                                          X(1, OID(MR_NUMERIC))))))),
                   X(20, INT(2)), X(21, BOOL(True)), X(22, ENUM(0)), X(23, INT(10)),
                   X(24, BOOL(False)))
    if variant == 1:      # GeneralizedTime, other authentication level
        other = SEQ(OID('1.3.6.1.4.1.32473.13'), OCTS(b'level', 0x81), tag=0x28)
        return SET(X(3, SEQ()), X(9, GENT()), X(10, security_parameters(1)), X(13, other))
    return SET(X(3, trace_information()))


def chaining_results(variant):
    if variant == 0:
        return SET(X(0, OID('1.3.6.1.4.1.32473.8')),
                   X(1, SEQ(SET(X(0, DN_ORG), X(1, ap_information_full())),
                            SET(X(0, dn(R_C)), X(1, access_point())))),
                   X(2, security_parameters(0)), X(3, SET(dn(R_C, R_O))))
    return SET()


class ChainedAssoc(Assoc):
    """A DSP association: op() wraps a DAP argument and result in the
    chained form, alternating the ChainingArguments/Results variants and
    unsigned and signed chained PDUs (abandon is not chained)."""

    def __init__(self, *args):
        super().__init__(*args)
        self.n = 0

    def op(self, opcode, arg, result=None, error=None, from_client=True, variant=None):
        if opcode != ABANDON:
            v = self.n % 4 if variant is None else variant
            self.n += 1
            arg = SET(chaining_arguments(v % 3), X(0, arg))
            if v == 3:
                arg = SEQ(arg, alg(), BITS(0, b'\x5a' * 16))
            if result is not None:
                result = SET(chaining_results(v % 2), X(0, result))
                if v == 3:
                    result = SEQ(result, alg(), BITS(0, b'\x5a' * 16))
        super().op(opcode, arg, result, error, from_client)


def signed_ops(d):
    """One signed chained argument and result of every chained operation
    (the rotation in ChainedAssoc does not reach all of them)."""
    from dapops import COMPARE, LIST, SEARCH, ADD, REMOVE, MODIFY, MODIFYDN
    pairs = {
        READ: (SET(X(0, DN_ALICE)), SET(X(0, entry_information(DN_ALICE, False)))),
        COMPARE: (SET(X(0, DN_ALICE), X(1, ava(AT_CN, PSTR('Alice Smith')))), SET(X(0, BOOL(True)))),
        LIST: (SET(X(0, DN_ORG)), SET(X(1, SET()))),
        SEARCH: (SET(X(0, DN_ORG)), SET(X(0, SET()))),
        ADD: (SET(X(0, DN_BOB), X(1, SET(attribute(AT_CN, PSTR('Bob'))))), NULL()),
        REMOVE: (SET(X(0, DN_BOB)), NULL()),
        MODIFY: (SET(X(0, DN_ALICE), X(1, SEQ())), NULL()),
        MODIFYDN: (SET(X(0, DN_BOB), X(1, R_CN2)), NULL()),
    }
    for opcode, (arg, res) in pairs.items():
        d.op(opcode, arg, res, variant=3)


def continuation_reference_min():
    return SET(X(0, DN_ALICE), X(2, operation_progress(1, None)), X(4, ENUM(9)),
               X(5, SET(access_point_information())))


def knowledge_attributes():
    """The DSA knowledge attributes that DSP registers."""
    return SEQ(attribute(AT_MYAP, access_point_full()),
               attribute(AT_SUPERIOR, access_point()),
               attribute(AT_SPECIFIC, masap()),
               attribute(AT_NONSPECIFIC, masap()),
               attribute(AT_DITBRIDGE, SEQ(UTF8('bridge-1'), masap())),
               attribute(AT_DITBRIDGE, SEQ(masap())))


def dsa_referral(full=True):
    if not full:
        return SET(X(0, continuation_reference_min()))
    return SET(X(0, continuation_reference()), X(1, DN_ORG), X(30, security_parameters(1)),
               X(29, DN_ADMIN), X(28, BOOL(True)), X(27, knowledge_attributes()))


def dsp_errors(d):
    """DSA referrals (the DAP errors are in dapops.errors())."""
    arg = SET(X(0, DN_ALICE))
    d.op(READ, arg, None, (E_DSAREFERRAL, dsa_referral()))
    d.op(READ, arg, None, (E_DSAREFERRAL, dsa_referral(False)))
    d.op(READ, arg, None, (E_DSAREFERRAL, SEQ(dsa_referral(False), alg(), BITS(0, b'\x5a' * 16))))
    # every reference type and name resolution phase
    for rt in range(1, 10):
        cr = SET(X(0, DN_ALICE), X(2, operation_progress(1 + rt % 3, None)), X(4, ENUM(rt)),
                 X(5, SET(access_point_information())))
        d.op(READ, arg, None, (E_DSAREFERRAL, SET(X(0, cr))))


def dsa_bind_arg():
    return bind_arg(simple_creds())


def dsa_bind_result():
    return bind_arg(simple_creds(DN_DSA, validity=False, password=None))


def main_frames():
    F = []
    d = ChainedAssoc(F, 40001, AC_DSP, [(CTX, AS_DSP)])
    d.open()
    d.bind(dsa_bind_arg())
    d.bind_result(dsa_bind_result())
    dapops.ops(d)
    signed_ops(d)
    dapops.errors(d)
    dsp_errors(d)
    d.close()
    for i, err in enumerate((bind_error_data('service', 3),
                             bind_error_data('security', 1, secp=True))):
        b = Assoc(F, 40002 + i, AC_DSP, [(CTX, AS_DSP)])
        b.open()
        b.bind(dsa_bind_arg())
        b.bind_error(err)
        b.close()
    # IDMP: bind and a chained abandon
    i = Idmp(F, 40004, IDMP_DSP)
    i.bind(SET())
    i.request(1, ABANDON, SEQ(X(0, INT(1))))
    i.result(1, ABANDON, NULL())
    return F


def malformed_frames():
    F = []
    d = ChainedAssoc(F, 41001, AC_DSP, [(CTX, AS_DSP)])
    d.open()
    d.bind(dsa_bind_arg())
    d.bind_result(dsa_bind_result())
    # securityError: the SPKM info of the DAP SecurityErrorData is not
    # implemented (observation 1 of dap-coverage)
    d.op(READ, SET(X(0, DN_ALICE)), None, (E_SECURITY, SET(X(0, INT(2)), X(1, NULL()))))
    Assoc.op(d, 10, NULL(), NULL())                            # unknown opcode
    Assoc.op(d, READ, SET(), error=(10, NULL()))               # unknown error
    d.unbind()                                                 # not a DSP PDU
    Assoc.op(d, READ, bytes([0x31, 0x10, 0x31, 0x05]))         # truncated
    Assoc.op(d, READ, INT(5))                                  # wrong tag
    Assoc.op(d, READ, SET(SET(), X(0, SET(X(0, DN_ALICE)))), tlv(0xa5, b''))   # bad result
    Assoc.op(d, READ, SET(X(0, DN_ALICE)), error=(E_DSAREFERRAL, OCTS(b'x')))
    d.close()
    # the review reproducer dsp_col_protocol.py over IDMP: bind, then an
    # abandon (SET + [0]: not an AbandonArgument) and a truncated one
    i = Idmp(F, 41002, IDMP_DSP)
    i.bind(SET())
    i.request(1, ABANDON, tlv(0x30, tlv(0x31, b'') + tlv(0xa0, tlv(0x30, b''))))
    i.request(2, ABANDON, bytes([0x30, 0x05, 0x31, 0x7f]))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dsp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dsp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
