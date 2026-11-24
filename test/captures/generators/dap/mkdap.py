#!/usr/bin/env python3
# Generates test/captures/dap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DAP dissector
(packet-dap.c, generated from epan/dissectors/asn1/dap).

DAP (X.511/X.519 Directory Access Protocol) runs over ROSE. Here it is
carried over the OSI upper layers on TCP port 102 (TPKT, COTP, session,
presentation): an A-ASSOCIATE (AARQ/AARE with application context
id-ac-directory-access 2.5.3.1) sets up presentation context 3 for the
abstract syntax id-as-directory-access (2.5.9.1), and every DAP PDU is
a ROS bind-invoke/result/error or invoke/returnResult/returnError in a
P-DATA on that context. The malformed capture also has a connection
on TCP port 1102 with IDMP (dap-ip, 2.5.33.0), which hands the bind
result and the operation arguments and results to DAP the same way
(but not the bind argument, see the README).

Every packet is built from scratch with struct; no captured traffic is
used. Names use registered X.520 attribute types (cn, ou, o, c, sn) so
the attribute values decode with a known syntax.

Usage: mkdap.py <output directory>

Writes:
  dap-coverage.pcap            bind with every kind of credentials,
                               bind results and errors, every operation
                               with its unsigned and signed argument and
                               result, every error, every common argument
                               and result, every filter item, the simple
                               credentials without a name (the reproducer
                               of "DAP: Do not pass a NULL DN to "%s" for
                               simple credentials")
  dap-coverage-malformed.pcap  securityError (its SPKM info is not
                               implemented), truncated and wrongly
                               tagged PDUs, unknown codes, the IDMP
                               bind (its argument is never handed to
                               DAP) and the reproducer over IDMP
"""

import os
import sys

from osilib import (  # noqa: E402,
    aare, aarq, BITS, BOOL, Conn, cotp_cc, cotp_cr, cotp_dt, CTX_ACSE, ENUM, fully_encoded, GENT,
    INT, NULL, OCTS, OID, OID_ACSE, pdv, pres_cp, pres_cpa, PSTR, rlre, rlrq, ros_error,
    ros_invoke, ros_result, SEQ, ses_ac, ses_cn, ses_dn, ses_dt, ses_fn, SET, struct, tlv, tpkt,
    UTCT, UTF8, write_pcap, X,
)

OID_DAP_AS = '2.5.9.1'       # id-as-directory-access
OID_DAP_AC = '2.5.3.1'       # id-ac-directory-access
OID_DAP_IP = '2.5.33.0'      # IDMP dap-ip
CTX_DAP = 3

AT_OC = '2.5.4.0'            # objectClass (OBJECT IDENTIFIER)
AT_CN = '2.5.4.3'            # commonName (DirectoryString)
AT_SN = '2.5.4.4'            # surname
AT_C = '2.5.4.6'             # countryName (PrintableString)
AT_O = '2.5.4.10'            # organizationName
AT_OU = '2.5.4.11'           # organizationalUnitName
AT_TEL = '2.5.4.20'          # telephoneNumber
AT_GN = '2.5.4.42'           # givenName
AT_MEMBER = '2.5.4.31'       # member (DistinguishedName)
OC_PERSON = '2.5.6.6'
MR_CASEIGNORE = '2.5.13.2'
MR_NUMERIC = '2.5.13.8'
ALG_SHA256RSA = '1.2.840.113549.1.1.11'
ALG_ECPUB = '1.2.840.10045.2.1'
CURVE_P256 = '1.2.840.10045.3.1.7'


# ------------------------------------------------------- X.501 types

def rdn(*pairs):
    return SET(*[SEQ(OID(t), v) for t, v in pairs])


def dn(*rdns):
    """RDNSequence (also Name and DistinguishedName)."""
    return SEQ(*rdns)


R_C = rdn((AT_C, PSTR('AU')))
R_O = rdn((AT_O, UTF8('Example Org')))
R_OU = rdn((AT_OU, UTF8('People')))
R_CN = rdn((AT_CN, PSTR('Alice Smith')))
R_CN2 = rdn((AT_CN, PSTR('Bob Jones')))
# a multi-valued RDN
R_MULTI = rdn((AT_CN, PSTR('Carol')), (AT_SN, UTF8('Brown')))

DN_ORG = dn(R_C, R_O)
DN_ALICE = dn(R_C, R_O, R_OU, R_CN)
DN_BOB = dn(R_C, R_O, R_OU, R_CN2)
DN_ADMIN = dn(R_C, R_O, rdn((AT_CN, PSTR('admin'))))
DN_DSA = dn(R_C, R_O, rdn((AT_CN, PSTR('dsa-1'))))
DN_ROOT = dn()


def context(ctype=AT_CN, vals=(PSTR('en'),), fallback=None):
    """Context: no context syntax is registered, so the context type is
    an attribute type whose syntax is known."""
    body = OID(ctype) + SET(*vals)
    if fallback is not None:
        body += BOOL(fallback)
    return SEQ(body)


def ctx_assertion(ctype=AT_CN, vals=(PSTR('en'),)):
    return SEQ(OID(ctype), SET(*vals))


def attribute(t, *vals, with_ctx=False):
    body = OID(t) + SET(*vals)
    if with_ctx:
        body += SET(SEQ(vals[0], SET(context(fallback=True))))
    return SEQ(body)


def ava(t, v, asserted=None):
    body = OID(t) + v
    if asserted == 'all':
        body += X(0, NULL())
    elif asserted == 'selected':
        body += X(1, SET(ctx_assertion()))
    return SEQ(body)


def ata(t, with_ctx=True):
    """AttributeTypeAssertion."""
    body = OID(t)
    if with_ctx:
        body += SEQ(ctx_assertion())
    return SEQ(body)


def alg(oid=ALG_SHA256RSA, params=None):
    return SEQ(OID(oid), NULL() if params is None else params)


def certificate(serial=1):
    tbs = SEQ(X(0, INT(2)), INT(serial), alg(), DN_ORG,
              SEQ(UTCT('260101000000Z'), UTCT('361231235959Z')), DN_ALICE,
              SEQ(alg(ALG_ECPUB, OID(CURVE_P256)), BITS(0, b'\x04' + bytes(range(64)))))
    return SEQ(tbs, alg(), BITS(0, bytes(range(32))))


def cert_path():
    return SEQ(certificate())


def code_local(v):
    return INT(v)


def code_global(oid):
    return OID(oid)


def security_parameters(variant=0):
    """SecurityParameters; variant 0 has every field with a UTCTime and
    a local code, variant 1 a GeneralizedTime and a global code."""
    if variant == 0:
        return SET(X(0, cert_path()), X(1, DN_ALICE), X(2, UTCT()),
                   X(3, BITS(0, b'\x11\x22\x33\x44')), X(4, INT(1)),
                   X(5, BITS(0, b'\x55\x66')), X(6, code_local(1)),
                   X(8, INT(3)), X(9, code_local(2)))
    return SET(X(1, DN_BOB), X(2, GENT()), X(4, INT(2)),
               X(6, code_global('2.5.33.0')), X(8, INT(0)),
               X(9, code_global('2.5.33.0')))


def operation_progress(phase=2, nxt=1):
    body = X(0, ENUM(phase))
    if nxt is not None:
        body += X(1, INT(nxt))
    return SET(body)


def service_controls():
    return SET(X(0, BITS(2, b'\xff\xfc')),          # every option bit
               X(1, INT(2)), X(2, INT(30)), X(3, INT(100)), X(4, INT(1)),
               X(5, INT(4096)),
               X(6, SEQ(DN_DSA, SEQ(INT(7), INT(1)))),
               X(7, OID('2.5.9.1')), X(8, INT(3)))


def context_selection(selected=True, preference=True):
    if not selected:
        return NULL()
    if preference:
        ca = SEQ(ctx_assertion(), ctx_assertion(AT_CN, (PSTR('de'),)))
    else:
        ca = SET(ctx_assertion())
    return SET(SEQ(OID(AT_CN), ca))


def common_args(full=False, alt=False):
    if not full:
        return b''
    return (X(30, service_controls()) + X(29, security_parameters(1 if alt else 0))
            + X(28, DN_ADMIN) + X(27, operation_progress())
            + X(26, INT(1)) + X(25, BITS(5, b'\xe0')) + X(24, ENUM(2))
            + X(23, BOOL(False)) + X(22, SET(dn(R_C, R_O, R_OU)))
            + X(21, BOOL(True))
            + X(20, context_selection(True, alt))
            + X(19, ENUM(3 if alt else 2)))


def common_results(full=False, alt=False):
    if not full:
        return b''
    return (X(30, security_parameters(1 if alt else 0)) + X(29, DN_DSA)
            + X(28, BOOL(True))
            + X(27, SEQ(attribute(AT_CN, PSTR('notice')))))


def eis(variant=0):
    """EntryInformationSelection."""
    if variant == 0:
        return SET(X(1, SET(OID(AT_CN), OID(AT_SN))), X(2, INT(0)),
                   X(4, SET(OID(AT_OC))), context_selection(True, False),
                   BOOL(True),
                   SEQ(ENUM(3), SEQ(OID(OC_PERSON))))
    if variant == 1:
        return SET(X(0, NULL()), X(2, INT(1)), X(3, NULL()),
                   context_selection(False), BOOL(False), SEQ(ENUM(2)))
    return SET()


def entry_information(name=DN_ALICE, full=True):
    if not full:
        return SEQ(name)
    info = SET(OID(AT_TEL),
               attribute(AT_CN, PSTR('Alice Smith')),
               attribute(AT_OC, OID(OC_PERSON)))
    return SEQ(name, BOOL(False), info, X(3, BOOL(True)), X(4, BOOL(True)),
               X(5, BOOL(True)))


def presentation_address():
    return SEQ(X(0, OCTS(b'\x00\x01')), X(1, OCTS(b'\x00\x01')),
               X(2, OCTS(b'\x00\x01')), X(3, SET(OCTS(b'\x54\x00\x72\x87\x22\x03\xc0\x00\x02\x02'))))


def access_point_information():
    return SET(X(0, DN_DSA), X(1, presentation_address()), X(3, ENUM(1)),
               X(5, BOOL(True)))


def access_point():
    return SET(X(0, DN_DSA), X(1, presentation_address()))


def continuation_reference():
    return SET(X(0, DN_ALICE), X(1, INT(0)), X(2, operation_progress(3, None)),
               X(3, INT(2)), X(4, ENUM(2)), X(5, SET(access_point_information())),
               X(6, BOOL(True)), X(7, SET(dn(R_C))), X(8, BOOL(True)),
               X(9, BOOL(True)))


# ------------------------------------------------------- filters

def f_item(fi):
    return X(0, fi)


def f_and(*f):
    return X(1, SET(*f))


def f_or(*f):
    return X(2, SET(*f))


def f_not(f):
    return X(3, f)


def fi_equality(asserted='all'):
    return X(0, ava(AT_CN, PSTR('Alice'), asserted))


def fi_substrings(*strings):
    return X(1, SEQ(OID(AT_CN), SEQ(*strings)))


def fi_ge():
    return X(2, ava(AT_SN, UTF8('A')))


def fi_le():
    return X(3, ava(AT_SN, UTF8('M')))


def fi_present(t=AT_TEL):
    return X(4, OID(t))


def fi_approx():
    return X(5, ava(AT_GN, UTF8('Alys'), 'selected'))


def fi_extensible(match_value=False):
    # matchValue [3] is mandatory, but its body is not implemented
    body = X(1, SET(OID(MR_CASEIGNORE))) + X(2, OID(AT_CN)) + X(3, PSTR('alice'))
    body += X(4, BOOL(True))
    return X(6, SEQ(body))


def fi_context_present():
    return X(7, ata(AT_CN))


# the substrings item: the initial [0] value is shown as "not yet
# implemented"; any [1] and final [2] are skipped
SUBSTR_CLEAN = fi_substrings(X(0, PSTR('Al')), attribute(AT_CN, PSTR('control')))

FILTER_BIG = f_and(
    f_item(fi_equality('all')),
    f_or(f_item(SUBSTR_CLEAN), f_item(fi_ge()), f_item(fi_le())),
    f_not(f_item(fi_present())),
    f_item(fi_approx()),
    f_item(fi_extensible()),
    f_item(fi_context_present()))


def paged_new():
    return SEQ(INT(25), SEQ(SEQ(OID(AT_SN), OID(MR_CASEIGNORE)), SEQ(OID(AT_CN))),
               X(1, BOOL(True)), X(2, BOOL(True)))


def paged_ref(ref):
    return OCTS(ref)


def poq(entry_count=7):
    return SET(X(0, INT(1)), X(1, SET(continuation_reference())),
               X(2, BOOL(True)), X(3, SET(OID('2.5.9.2'))),
               X(4, OCTS(b'page-2')), X(5, f_item(fi_present(AT_CN))),
               X(6, SEQ(attribute(AT_CN, PSTR('partial')))),
               X(entry_count, INT(42)), X(10, BOOL(True)))


def relaxation():
    return SEQ(X(0, SEQ()), X(3, INT(2)), X(4, INT(1)))


def join_argument():
    return SEQ(X(0, DN_ORG), X(1, UTF8('local-1')), X(2, ENUM(1)),
               X(3, f_item(fi_present(AT_CN))),
               X(4, SEQ(SEQ(OID(AT_CN), OID(AT_SN), SEQ(OID(AT_CN))))),
               X(5, eis(1)))


def signed(data, tag=None):
    body = data + alg() + BITS(0, b'\x5a' * 16)
    return X(0, SEQ(body)) if tag == 0 else SEQ(body)


# ------------------------------------------------------- bind

def bind_arg(creds=None, versions=True):
    body = b''
    if creds is not None:
        body += X(0, creds)
    if versions:
        body += X(1, BITS(6, b'\xc0'))
    return SET(body)


def simple_creds(name=DN_ALICE, validity=True, password='plain'):
    body = b''
    if name is not None:
        body += X(0, name)
    if validity:
        body += X(1, SET(X(0, UTCT()), X(1, GENT('20261101130000Z')),
                         X(2, BITS(0, b'\x01\x02\x03\x04')), X(3, BITS(0, b'\x05\x06\x07\x08'))))
    if password == 'plain':
        body += X(2, OCTS(b'secret'))
    elif password == 'protected':
        body += X(2, SEQ(OCTS(b'\x9f' * 20), alg('1.3.14.3.2.26'), BITS(0, b'\x77' * 8)))
    elif password == 'gt':
        pass
    return X(0, SEQ(body))


def token():
    td = SEQ(X(0, alg()), X(1, DN_ALICE), X(2, UTCT()),
             X(3, BITS(0, b'\x01' * 8)), X(4, BITS(0, b'\x02' * 8)),
             X(5, SEQ(alg())), X(6, BITS(0, b'\x03' * 8)),
             X(7, SEQ(alg('2.16.840.1.101.3.4.1.42', OCTS(bytes(16))))), X(8, BITS(0, b'\x04' * 8)))
    return SEQ(td, alg(), BITS(0, b'\x99' * 16))


def strong_creds():
    return X(1, SET(X(0, cert_path()), X(1, token()), X(2, DN_ALICE)))


def external_creds():
    # EXTERNAL with direct-reference and octet-aligned encoding
    return X(2, SEQ(OID('1.3.6.1.4.1.32473.1'), OCTS(b'token', 0x81), tag=0x28))


def sasl_creds(full=True):
    body = X(0, UTF8('PLAIN'))
    if full:
        body += X(1, OCTS(b'\x00alice\x00secret')) + X(2, BOOL(False))
    return X(4, SEQ(body))


def bind_error_data(kind='service', problem=1, secp=False):
    body = X(0, BITS(6, b'\xc0'))
    body += X(1, INT(problem)) if kind == 'service' else X(2, INT(problem))
    if secp:
        body += X(30, security_parameters(1))
    return SET(body)


# ------------------------------------------------------- the captures

class Dap:
    """The DAP association on TCP port 102."""

    def __init__(self, frames, cport=40001):
        self.F = frames
        self.c = Conn(frames, cport, 102)
        self.iid = 0

    def osi(self, from_client, s):
        self.c.send(from_client, tpkt(cotp_dt(s)))

    def pdata(self, from_client, ros):
        self.osi(from_client, ses_dt(fully_encoded(pdv(CTX_DAP, ros))))

    def open(self):
        self.c.handshake()
        self.c.send(True, tpkt(cotp_cr()))
        self.c.send(False, tpkt(cotp_cc()))
        ctxs = [(CTX_ACSE, OID_ACSE), (CTX_DAP, OID_DAP_AS)]
        self.osi(True, ses_cn(pres_cp(ctxs, fully_encoded(pdv(CTX_ACSE, aarq(OID_DAP_AC))))))
        self.osi(False, ses_ac(pres_cpa(2, fully_encoded(pdv(CTX_ACSE, aare(OID_DAP_AC))))))

    def close(self):
        self.osi(True, ses_fn(fully_encoded(pdv(CTX_ACSE, rlrq()))))
        self.osi(False, ses_dn(fully_encoded(pdv(CTX_ACSE, rlre()))))
        self.c.close()

    def bind(self, arg):
        self.pdata(True, tlv(0xb0, arg))

    def bind_result(self, res):
        self.pdata(False, tlv(0xb1, res))

    def bind_error(self, err):
        self.pdata(False, tlv(0xb2, err))

    def op(self, opcode, arg, result=None, error=None):
        """An invoke and its result or error (code, parameter)."""
        self.iid += 1
        self.pdata(True, ros_invoke(self.iid, opcode, arg))
        if result is not None:
            self.pdata(False, ros_result(self.iid, opcode, result))
        if error is not None:
            self.pdata(False, ros_error(self.iid, error[0], error[1]))


class Idmp:
    """A DAP connection over IDMP (TCP port 1102)."""

    def __init__(self, frames, cport=40002):
        self.c = Conn(frames, cport, 1102)

    def send(self, from_client, pdu, final=True):
        self.c.send(from_client, struct.pack('!BBI', 2, 1 if final else 0, len(pdu)) + pdu)

    def bind(self, arg):
        self.send(True, X(0, SEQ(OID(OID_DAP_IP), X(2, arg))))

    def bind_result(self, res):
        self.send(False, X(1, SEQ(OID(OID_DAP_IP), X(1, res))))

    def request(self, iid, opcode, arg):
        self.send(True, X(3, SEQ(INT(iid), INT(opcode), arg)))

    def result(self, iid, opcode, res):
        self.send(False, X(4, SEQ(INT(iid), INT(opcode), res)))


READ, COMPARE, ABANDON, LIST, SEARCH, ADD, REMOVE, MODIFY, MODIFYDN = range(1, 10)
E_ATTR, E_NAME, E_SERVICE, E_REFERRAL, E_ABANDONED, E_SECURITY, E_ABANDONFAILED, E_UPDATE = range(1, 9)


def ops(d):
    """Every operation with its unsigned and signed argument and result."""
    # read: every field of the argument and of the result
    read_full = SET(X(0, DN_ALICE), X(1, eis(0)), X(2, BOOL(True)), common_args(True))
    modify_rights = SET(SEQ(X(0, NULL()), X(3, BITS(4, b'\xf0'))),
                        SEQ(X(1, OID(AT_CN)), X(3, BITS(6, b'\xc0'))),
                        SEQ(X(2, ava(AT_CN, PSTR('Alice Smith'))), X(3, BITS(7, b'\x80'))))
    read_res = SET(X(0, entry_information()), X(1, modify_rights), common_results(True))
    d.op(READ, read_full, read_res)
    # alternate common arguments / results; the root name
    d.op(READ, SET(X(0, DN_ROOT), X(1, eis(1)), common_args(True, alt=True)),
         SET(X(0, entry_information(DN_ROOT, False)), common_results(True, alt=True)))
    # signed argument and result
    d.op(READ, signed(SET(X(0, DN_BOB), X(1, eis(2)))),
         signed(SET(X(0, entry_information(DN_BOB, False)))))

    # compare
    cmp_arg = SET(X(0, DN_ALICE), X(1, ava(AT_CN, PSTR('Alice Smith'), 'all')), common_args(True))
    cmp_res = SET(DN_ALICE, X(0, BOOL(True)), X(1, BOOL(False)), X(2, OID(AT_CN)), common_results(True))
    d.op(COMPARE, cmp_arg, cmp_res)
    d.op(COMPARE, signed(SET(X(0, DN_BOB), X(1, ava(AT_SN, UTF8('Jones'))))),
         signed(SET(X(0, BOOL(False)))))

    # abandon: result NULL, unsigned and signed information
    d.op(ABANDON, SEQ(X(0, INT(1))), NULL())
    d.op(ABANDON, signed(SEQ(X(0, INT(2))), tag=0),
         SEQ(INT(2), common_results(True)))
    d.op(ABANDON, SEQ(X(0, INT(3))), signed(SEQ(INT(3)), tag=0))

    # list: new paged request, printable and binary query references,
    # listInfo with every field, uncorrelated, signed
    list_res = SET(DN_ORG,
                   X(1, SET(SEQ(R_OU, X(0, BOOL(True)), X(1, BOOL(False))),
                            SEQ(R_MULTI))),
                   X(2, poq(7)), common_results(True))
    d.op(LIST, SET(X(0, DN_ORG), X(1, paged_new()), X(2, BOOL(True)), common_args(True)), list_res)
    d.op(LIST, SET(X(0, DN_ORG), X(1, paged_ref(b'cookie-1'))),
         X(0, SET(SET(X(1, SET(SEQ(R_OU)))), signed(SET(X(1, SET()))))))
    d.op(LIST, signed(SET(X(0, DN_ORG), X(1, paged_ref(b'\x00\x01\xfe\xff')))),
         signed(SET(DN_ORG, X(1, SET()), X(2, SET(X(8, INT(3)))))))

    # a constructed query reference without segments (no value tvb)
    d.op(LIST, SET(X(0, DN_ORG), X(1, tlv(0x24, b''))), SET(X(1, SET())))

    # search: every field, each subset, every filter item, joins
    s_full = SET(X(0, DN_ORG), X(1, INT(2)), X(2, FILTER_BIG), X(3, BOOL(False)),
                 X(4, eis(0)), X(5, paged_new()), X(6, BOOL(True)),
                 X(7, f_item(fi_present(AT_CN))), X(8, BOOL(True)),
                 X(9, relaxation()), X(10, INT(3)), X(11, BITS(6, b'\xff\xc0')),
                 X(12, BITS(4, b'\xff\xf0')), X(13, SEQ(join_argument())),
                 X(14, ENUM(2)), common_args(True))
    s_res = SET(DN_ORG, X(0, SET(entry_information(), entry_information(DN_BOB, False))),
                X(2, poq(9)), X(3, BOOL(True)), common_results(True))
    d.op(SEARCH, s_full, s_res)
    d.op(SEARCH, SET(X(0, DN_ORG), X(1, INT(1)), X(2, f_item(fi_equality(None)))),
         X(0, SET(SET(X(0, SET())), signed(SET(X(0, SET(entry_information(DN_BOB, False))))))))
    d.op(SEARCH, SET(X(0, DN_ORG), X(1, INT(0))),
         signed(SET(X(0, SET()), X(2, SET(X(0, INT(0)))))))
    d.op(SEARCH, SET(X(0, DN_ORG), X(1, INT(7))), SET(X(0, SET())))
    # substrings any [1] and final [2] (bodies not implemented)
    d.op(SEARCH, SET(X(0, DN_ORG), X(2, f_item(fi_substrings(X(1, PSTR('li')), X(2, PSTR('ce')))))),
         SET(X(0, SET())))
    d.op(SEARCH, signed(SET(X(0, DN_ORG), X(2, f_not(f_or()))), ), None,
         (E_SERVICE, SET(X(0, INT(3)))))

    # addEntry
    add_arg = SET(X(0, DN_BOB),
                  X(1, SET(attribute(AT_OC, OID(OC_PERSON)),
                           attribute(AT_CN, PSTR('Bob Jones')),
                           attribute(AT_SN, UTF8('Jones')))),
                  X(2, access_point()), common_args(True))
    d.op(ADD, add_arg, NULL())
    d.op(ADD, signed(SET(X(0, DN_BOB), X(1, SET(attribute(AT_CN, PSTR('Bob')))))),
         SEQ(common_results(True)))
    d.op(ADD, SET(X(0, DN_BOB), X(1, SET())), signed(SEQ(), tag=0))

    # removeEntry
    d.op(REMOVE, SET(X(0, DN_BOB), common_args(True)), NULL())
    d.op(REMOVE, signed(SET(X(0, DN_BOB))), SEQ(common_results(True)))
    d.op(REMOVE, SET(X(0, DN_BOB)), signed(SEQ(), tag=0))

    # modifyEntry: every kind of modification
    changes = SEQ(X(0, attribute(AT_TEL, PSTR('+61 7 5555 0100'))),
                  X(1, OID(AT_GN)),
                  X(2, attribute(AT_CN, PSTR('Ally'))),
                  X(3, attribute(AT_CN, PSTR('Alice Smith'))),
                  X(4, SEQ(OID(AT_SN), UTF8('Smyth'))),
                  X(5, OID(AT_CN)))
    d.op(MODIFY, SET(X(0, DN_ALICE), X(1, changes), X(2, eis(1)), common_args(True)),
         NULL())
    d.op(MODIFY, signed(SET(X(0, DN_ALICE), X(1, SEQ()))),
         SEQ(X(0, entry_information()), common_results(True)))
    d.op(MODIFY, SET(X(0, DN_ALICE), X(1, SEQ())), signed(SEQ(), tag=0))

    # modifyDN
    d.op(MODIFYDN, SET(X(0, DN_BOB), X(1, rdn((AT_CN, PSTR('Robert Jones')))),
                       X(2, BOOL(True)), X(3, DN_ORG), common_args(True)), NULL())
    d.op(MODIFYDN, SET(X(0, DN_BOB), X(1, R_CN2)),
         SEQ(R_CN2, common_results(True)))
    d.op(MODIFYDN, SET(X(0, DN_BOB), X(1, R_CN2)), signed(SEQ(R_CN2), tag=0))


def errors(d):
    """Every error, unsigned (with the common results) and signed."""
    cr = common_results(True)
    errs = [
        (READ, E_ABANDONED, SET(cr)),
        (READ, E_ABANDONED, signed(SET())),
        (ABANDON, E_ABANDONFAILED, SET(X(0, INT(2)), X(1, INT(9)), cr)),
        (ABANDON, E_ABANDONFAILED, signed(SET(X(0, INT(1)), X(1, INT(9))))),
        (READ, E_ATTR, SET(X(0, DN_ALICE),
                           X(1, SET(SEQ(X(0, INT(1)), X(1, OID(AT_TEL))),
                                    SEQ(X(0, INT(2)), X(1, OID(AT_CN)), X(2, PSTR('bad'))))),
                           cr)),
        (READ, E_ATTR, signed(SET(X(0, DN_ALICE), X(1, SET())))),
        (READ, E_NAME, SET(X(0, INT(1)), X(1, DN_ORG), cr)),
        (READ, E_NAME, signed(SET(X(0, INT(5)), X(1, DN_ROOT)))),
        (READ, E_REFERRAL, SET(X(0, continuation_reference()), cr)),
        (READ, E_REFERRAL, signed(SET(X(0, continuation_reference())))),
        (READ, E_SERVICE, SET(X(0, INT(1)), cr)),
        (READ, E_SERVICE, SET(X(0, INT(17)))),
        (READ, E_SERVICE, SET(X(0, INT(99)))),
        (READ, E_SERVICE, signed(SET(X(0, INT(7))))),
        (ADD, E_UPDATE, SET(X(0, INT(5)), X(1, SET(OID(AT_CN), attribute(AT_SN, UTF8('x')))), cr)),
        (ADD, E_UPDATE, SET(X(0, INT(12)))),
        (ADD, E_UPDATE, SET(X(0, INT(99)))),
        (ADD, E_UPDATE, signed(SET(X(0, INT(1))))),
    ]
    args = {READ: SET(X(0, DN_ALICE)), ABANDON: SEQ(X(0, INT(1))),
            ADD: SET(X(0, DN_ALICE), X(1, SET(attribute(AT_SN, UTF8('x')))))}
    for opcode, code, param in errs:
        d.op(opcode, args[opcode], None, (code, param))


def binds(d):
    """Bind arguments with every kind of credentials, results, errors."""
    d.bind(bind_arg(simple_creds()))
    d.bind_result(bind_arg(strong_creds()))
    d.bind(bind_arg(simple_creds(DN_BOB, False, 'protected')))
    d.bind_result(bind_arg(None, versions=False))          # anonymous (empty SET)
    d.bind(bind_arg(external_creds()))
    d.bind_result(bind_arg(sasl_creds()))
    d.bind(bind_arg(sasl_creds(False), versions=False))
    d.bind_error(bind_error_data('service', 1))
    d.bind(bind_arg(simple_creds(DN_ROOT, False, None)))
    d.bind_error(bind_error_data('security', 2, secp=True))
    d.bind(bind_arg(None, versions=False))                 # anonymous
    d.bind_error(bind_error_data('service', 99))
    d.bind(bind_arg(simple_creds(DN_ADMIN, False, 'plain')))
    d.bind_error(bind_error_data('security', 99))
    d.bind(bind_arg(simple_creds(DN_ADMIN, False, 'plain')))
    d.bind_error(signed(bind_error_data('security', 7, secp=True)))
    # SPKM credentials, req [0] and rep [1] (bodies not implemented)
    d.bind(bind_arg(X(3, X(0, SEQ(INT(1))))))
    d.bind_result(bind_arg(X(3, X(1, SEQ(INT(2))))))
    # The reproducer: SimpleCredentials without the mandatory name, so
    # there is no last DN (NULL was passed to "%s")
    d.bind(bind_arg(simple_creds(None, False, 'plain')))
    d.bind_result(bind_arg(simple_creds(DN_DSA, False, None)))


def main_frames():
    F = []
    d = Dap(F)
    d.open()
    binds(d)
    ops(d)
    errors(d)
    d.close()
    return F


def malformed_frames():
    F = []
    d = Dap(F, 40003)
    d.open()
    # securityError: spkmInfo [1] is mandatory but its body is not
    # implemented, so the SET reports it as unknown and missing
    d.op(READ, SET(X(0, DN_ALICE)), None, (E_SECURITY, SET(X(0, INT(9)), X(1, SEQ(INT(1))))))
    d.op(READ, SET(X(0, DN_ALICE)), None, (E_SECURITY, signed(SET(X(0, INT(99)), X(1, NULL())))))
    # truncated: a read argument cut in the middle of the name
    d.pdata(True, ros_invoke(50, READ, SET(X(0, DN_ALICE))[:-6]))
    # wrong tags: a SEQUENCE where the read argument SET is expected
    # inside a signed argument, a bind error with an unknown choice
    d.op(READ, SEQ(SEQ(X(0, DN_ALICE)), alg(), BITS(0, b'\x00')))
    d.bind_error(SET(X(0, BITS(6, b'\xc0')), X(5, INT(1))))
    d.op(READ, SET(X(0, DN_ALICE)), SET(X(0, SEQ(INT(1)))))
    # unknown operation and error codes
    d.op(42, SET(), SET())
    d.op(READ, SET(X(0, DN_ALICE)), None, (42, SET()))
    d.close()
    # IDMP: the bind argument is dissected before the protocol ID is
    # saved, so it is not handed to DAP; the bind result is
    i = Idmp(F)
    i.c.handshake()
    i.bind(bind_arg(simple_creds(None, False, 'plain')))
    i.bind_result(bind_arg(simple_creds(None, False, 'plain')))
    i.request(1, READ, SET(X(0, DN_ALICE)))
    i.result(1, READ, SET(X(0, entry_information())))
    i.c.close()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dap-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dap-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
