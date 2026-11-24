#!/usr/bin/env python3
# Generates test/captures/cmip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CMIP dissector
(packet-cmip.c, generated from epan/dissectors/asn1/cmip).

CMIP (X.711) runs over ROSE on the OSI upper layers. Every frame is an
Exported PDU record that hands an OSI session SPDU to the "ses"
dissector; session hands the user data to presentation, which calls
CMIP (abstract syntax 2.9.0.0.2, presentation context 3) or ACSE
(2.2.1.0.1, context 1), and ACSE calls CMIP for the CMIPUserInfo /
CMIPAbortInfo in its user-information EXTERNAL (2.9.1.1.4).

Every packet is built from scratch with struct; no captured traffic is
used. The OIDs used for action, event, error and extension types are
registered X.721 attribute OIDs, so the "information" parts that CMIP
hands to the OID table decode with a known syntax.

Usage: mkcmip.py <output directory>

Writes:
  cmip-coverage.pcap            association, every operation with its
                                arguments and results, linked replies,
                                errors without parameters, rejects,
                                every X.721 attribute, release, abort,
                                refuse, the stale OID reproducer
  cmip-coverage-malformed.pcap  ReturnError with every error parameter
                                (not consumed, see README), truncated
                                and wrongly tagged PDUs
"""

import os
import struct
import sys

# ---------------------------------------------------------------- BER


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, val=b''):
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + ber_len(len(val)) + val


def ber_int(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def oid_enc(s):
    p = [int(x) for x in s.split('.')]
    out = bytearray()
    for a in [p[0] * 40 + p[1]] + p[2:]:
        enc = [a & 0x7f]
        a >>= 7
        while a:
            enc.insert(0, 0x80 | (a & 0x7f))
            a >>= 7
        out += bytes(enc)
    return bytes(out)


def INT(v, tag=0x02):
    return tlv(tag, ber_int(v))


def ENUM(v, tag=0x0a):
    return tlv(tag, ber_int(v))


def OID(s, tag=0x06):
    return tlv(tag, oid_enc(s))


def NULL(tag=0x05):
    return tlv(tag, b'')


def BOOL(v, tag=0x01):
    return tlv(tag, b'\xff' if v else b'\x00')


def GSTR(s, tag=0x19):          # GraphicString
    return tlv(tag, s.encode())


def OCTS(b, tag=0x04):
    return tlv(tag, b)


def GTIME(s='20261030120000Z', tag=0x18):
    return tlv(tag, s.encode())


def BITS(unused, data, tag=0x03):
    return tlv(tag, bytes([unused]) + data)


def SEQ(*items, tag=0x30):
    return tlv(tag, b''.join(items))


def SET(*items, tag=0x31):
    return tlv(tag, b''.join(items))


def REAL_dec(s):
    # ISO 6093 NR3 decimal encoding
    return tlv(0x09, b'\x03' + s.encode())


# ------------------------------------------------------- X.721 OIDs

def X721(n):
    return '2.9.3.2.7.%d' % n


OID_CMIP_AS = '2.9.0.0.2'          # CMIP abstract syntax
OID_CMIP_PCI = '2.9.1.1.4'         # CMIP-PCI (user information)
OID_ACSE = '2.2.1.0.1'
OID_BER = '2.1.1'
OID_CN = '2.5.4.3'                 # X.520 commonName
OID_OU = '2.5.4.11'                # X.520 organizationalUnitName

# Registered OIDs whose syntax is known, used as action / event / error
# / extension / feature types: additionalText (GraphicString),
# operationalState (ENUMERATED), maxLogSize (INTEGER)
OID_TXT = X721(7)
OID_OPSTATE = X721(35)
OID_MAXLOG = X721(62)

# ------------------------------------------------------- CMIP types


def oc_global(oid='2.9.3.2.3.13'):
    return OID(oid, 0x80)            # ObjectClass globalForm [0]


def oc_local(v=5):
    return INT(v, 0x81)              # ObjectClass localForm [1]


def rdn(oid, value):
    return SET(SEQ(OID(oid), value))


def utf8(s):
    return tlv(0x0c, s.encode())


def dn(*rdns):
    return b''.join(rdns)


DN1 = dn(rdn(OID_OU, utf8('network')), rdn(OID_CN, utf8('switch-1')))


def oi_dn(d=DN1):
    return tlv(0xa2, d)              # distinguishedName [2]


def oi_nonspecific(b=b'\x01\x02\x03'):
    return OCTS(b, 0x83)             # nonSpecificForm [3]


def oi_local(d=None):
    return tlv(0xa4, d if d is not None else rdn(OID_CN, utf8('port-7')))


def attr_id_global(oid):
    return OID(oid, 0x80)            # AttributeId globalForm [0]


def attr_id_local(v):
    return INT(v, 0x81)              # AttributeId localForm [1]


def attribute(aid, value):
    return SEQ(aid, value)


def external(oid, value):
    """EXTERNAL: direct-reference and single-ASN1-type [0]."""
    return SEQ(OID(oid), tlv(0xa0, value), tag=0x28)


def external_body(oid, value):
    """The EXTERNAL fields without the UNIVERSAL 8 header."""
    return OID(oid) + tlv(0xa0, value)


def access_control():
    # accessControl [5] AccessControl (EXTERNAL); the generated code
    # takes the [5] as implicit
    return tlv(0xa5, external_body(OID_TXT, GSTR('access token')))


def sync(v):
    return ENUM(v, 0x86)


def scope_named(v):
    return tlv(0xa7, INT(v))


def scope_individual(v):
    return tlv(0xa7, INT(v, 0x81))


def scope_nth(v):
    return tlv(0xa7, INT(v, 0x82))


def filt_item(fi):
    return tlv(0xa8, fi)             # item [8] FilterItem (explicit)


def filt_and(*f):
    return tlv(0xa9, b''.join(f))


def filt_or(*f):
    return tlv(0xaa, b''.join(f))


def filt_not(f):
    return tlv(0xab, f)


def fi_attr(tag, aid, value):
    return tlv(0xa0 | tag, aid + value)


def fi_substrings(*items):
    return tlv(0xa1, b''.join(items))


def fi_present(aid):
    return tlv(0xa4, aid)


# ------------------------------------------------------- ROSE


def invoke_id(v):
    return NULL() if v is None else INT(v)


def invoke(iid, opcode, arg=None, linked=None, global_code=None):
    body = invoke_id(iid)
    if linked is not None:
        body += INT(linked, 0x80)
    body += OID(global_code) if global_code else INT(opcode)
    if arg is not None:
        body += arg
    return tlv(0xa1, body)


def return_result(iid, opcode=None, result=None, global_code=None):
    body = invoke_id(iid)
    if opcode is not None or global_code:
        r = OID(global_code) if global_code else INT(opcode)
        if result is not None:
            r += result
        body += SEQ(r)
    return tlv(0xa2, body)


def return_error(iid, code, param=None, global_code=None):
    body = invoke_id(iid) + (OID(global_code) if global_code else INT(code))
    if param is not None:
        body += param
    return tlv(0xa3, body)


def reject(iid, ptag, problem):
    return tlv(0xa4, invoke_id(iid) + INT(problem, 0x80 | ptag))


# ------------------------------------------------- session / presentation

CTX_ACSE = 1
CTX_CMIP = 3


def ses_param_userdata(data):
    if len(data) < 255:
        return bytes([193, len(data)]) + data
    return bytes([194, 0xff]) + struct.pack('>H', len(data)) + data


def spdu(si, params):
    if len(params) < 255:
        return bytes([si, len(params)]) + params
    return bytes([si, 0xff]) + struct.pack('>H', len(params)) + params


def ctx_item(ctx, oid):
    return SEQ(INT(ctx), OID(oid), SEQ(OID(OID_BER)))


def pdv(ctx, value, octet_aligned=False):
    if octet_aligned:
        return SEQ(INT(ctx), tlv(0x81, value))
    return SEQ(INT(ctx), tlv(0xa0, value))


def fully_encoded(*pdvs):
    return tlv(0x61, b''.join(pdvs))


def pres_cp(user_data):
    nmp = (OCTS(b'\x00\x01', 0x81) + OCTS(b'\x00\x02', 0x82)
           + tlv(0xa4, ctx_item(CTX_ACSE, OID_ACSE) + ctx_item(CTX_CMIP, OID_CMIP_AS))
           + user_data)
    return SET(tlv(0xa0, INT(1, 0x80)), tlv(0xa2, nmp))


def pres_cpa(user_data):
    res = SEQ(INT(0, 0x80), OID(OID_BER, 0x81))
    nmp = OCTS(b'\x00\x02', 0x83) + tlv(0xa5, res + res) + user_data
    return SET(tlv(0xa0, INT(1, 0x80)), tlv(0xa2, nmp))


def pres_cpr(user_data):
    # CPR-PPDU normal-mode-parameters (SEQUENCE)
    return SEQ(OCTS(b'\x00\x02', 0x83) + user_data)


def pres_aru(user_data):
    # ARU-PPDU normal-mode-parameters [0] IMPLICIT SEQUENCE
    return tlv(0xa0, tlv(0xa0, SEQ(INT(CTX_ACSE), OID(OID_BER))) + user_data)


def ses_cn(pres):
    return spdu(13, ses_param_userdata(pres))


def ses_ac(pres):
    return spdu(14, ses_param_userdata(pres))


def ses_rf(pres):
    # Refuse: reason code 2 (rejection by the called SS-user, user data follows)
    p = b'\x02' + pres
    return spdu(12, bytes([50, len(p)]) + p)


def ses_fn(pres):
    return spdu(9, ses_param_userdata(pres))


def ses_dn(pres):
    return spdu(10, ses_param_userdata(pres))


def ses_ab(pres):
    # Transport disconnect parameter (17) then user data
    return spdu(25, b'\x11\x01\x0b' + ses_param_userdata(pres))


def ses_dt(pres):
    # Give Tokens (empty) + Data Transfer (empty params) + user information
    return b'\x01\x00\x01\x00' + pres


def ses_td(pres):
    # Typed Data (33)
    return b'\x21\x00' + pres


def p_data(ros, ctx=CTX_CMIP, octet_aligned=False):
    return fully_encoded(pdv(ctx, ros, octet_aligned))


def cmip(ros):
    """A ROSE APDU in a session DT / presentation P-DATA."""
    return ses_dt(p_data(ros))


# ----------------------------------------------------------- ACSE

def user_info_ext(value, oid=OID_CMIP_PCI):
    return tlv(0xbe, external(oid, value))


def aarq(user):
    return tlv(0x60, BITS(7, b'\x80', 0x80) + tlv(0xa1, OID(OID_CMIP_AS))
               + tlv(0xa2, OID('1.3.6.1.4.1.32473.2')) + user)


def aare(user, result=0):
    return tlv(0x61, BITS(7, b'\x80', 0x80) + tlv(0xa1, OID(OID_CMIP_AS))
               + tlv(0xa2, INT(result)) + tlv(0xa3, tlv(0xa1, INT(0))) + user)


def rlrq(user):
    return tlv(0x62, INT(0, 0x80) + user)


def rlre(user):
    return tlv(0x63, INT(0, 0x80) + user)


def abrt(user, src=0):
    return tlv(0x64, INT(src, 0x80) + user)


def cmip_user_info(full=True):
    if not full:
        return SEQ()
    return SEQ(BITS(6, b'\xc0', 0x80),               # version1, version2
               BITS(3, b'\xf8', 0x81),               # every functional unit
               tlv(0xa2, external_body(OID_TXT, GSTR('acl'))),
               tlv(0xa3, external_body(OID_OPSTATE, ENUM(1))))


def cmip_abort_info(src, user=True):
    body = ENUM(src, 0x80)
    if user:
        body += tlv(0xa1, external_body(OID_TXT, GSTR('abort reason')))
    return SEQ(body)


# ----------------------------------------------------- X.721 attributes

def ae_title_form2(oid='1.3.6.1.4.1.32473.9'):
    return OID(oid)


def ae_title_form1():
    return SEQ(rdn(OID_CN, utf8('manager')))


def x721_values():
    """(attribute number, value) for every attribute type registered in
    cmip.cnf, some more than once to reach every CHOICE alternative."""
    T = GTIME()
    ext = SEQ(OID(OID_TXT), BOOL(True, 0x81), tlv(0xa2, GSTR('extension')))
    ext2 = SEQ(OID(OID_MAXLOG), tlv(0xa2, INT(1000)))
    tm = lambda h, m: SEQ(INT(h), INT(m))
    v = [
        (1, INT(17)),                                   # discriminatorId number
        (2, GSTR('log-a')),                             # logId string
        (3, INT(99)),                                   # logRecordId
        (4, GSTR('system-a')),                          # systemId name
        (4, INT(4)),                                    # systemId number
        (4, NULL()),                                    # systemId nothing
        (5, SEQ(DN1)),                                  # systemTitle DN
        (5, OID('1.3.6.1.4.1.32473.5')),                # systemTitle oid
        (5, NULL()),                                    # systemTitle nothing
        (6, SET(ext, ext2)),                            # additionalInformation
        (7, GSTR('free text')),                         # additionalText
        (8, SET(attr_id_global(X721(31)), attr_id_local(3))),  # attributeIdentifierList
        (9, SET(attribute(attr_id_global(X721(35)), ENUM(1)))),  # attributeList
        (10, SET(SEQ(attr_id_global(OID_OPSTATE), tlv(0xa1, ENUM(0)), tlv(0xa2, ENUM(1))),
                 SEQ(attr_id_local(9), tlv(0xa2, ENUM(1))))),  # attributeValueChangeDefinition
        (11, BOOL(True)),                               # backedUpStatus
        (12, SET(SEQ(SET(INT(1), INT(2)), oi_dn()), SEQ(SET(INT(3))))),  # correlatedNotifications
        (13, T),                                        # eventTime
        (14, OID(OID_OPSTATE, 0x86)),                   # eventType globalForm
        (14, INT(4, 0x87)),                             # eventType localForm
        (15, SET(attribute(attr_id_global(X721(52)), SET(INT(80))))),  # monitoredAttributes
        (16, INT(1234)),                                # notificationIdentifier
        (17, ENUM(3)),                                  # perceivedSeverity
        (18, OID('2.9.3.2.0.0.1')),                     # probableCause global
        (18, INT(5)),                                   # probableCause local
        (19, SET(OID('2.9.3.2.0.1.1'), INT(2))),        # proposedRepairActions
        (20, SET(SEQ(attr_id_local(1), tlv(0xa2, ENUM(0))))),  # relationshipChangeDefinition
        (21, OID('2.9.3.2.0.2.1')),                     # securityAlarmCause
        (22, OID('1.3.6.1.4.1.32473.22', 0x80)),        # securityAlarmDetector mechanism
        (22, tlv(0xa1, oi_nonspecific())),              # securityAlarmDetector object
        (22, tlv(0xa2, ae_title_form2())),              # securityAlarmDetector application
        (23, ENUM(2)),                                  # securityAlarmSeverity
        (24, SEQ(OID(OID_TXT), GSTR('provider'))),      # serviceProvider
        (25, SEQ(OID(OID_MAXLOG), INT(7))),             # serviceUser
        (26, ENUM(1)),                                  # sourceIndicator
        (27, SET(OID('2.9.3.2.0.3.1'), INT(8))),        # specificProblems
        (28, SET(SEQ(attr_id_global(X721(31)), tlv(0xa2, ENUM(0))))),  # stateChangeDefinition
        (29, SEQ(attr_id_global(X721(52)), INT(95),
                 tlv(0xa1, tlv(0xa1, INT(90) + INT(70))), tlv(0x82, b'20261030120000Z'))),  # thresholdInfo up
        (29, SEQ(attr_id_local(3), REAL_dec('25.E0'),
                 tlv(0xa1, tlv(0xa2, REAL_dec('30.E0') + INT(10))))),  # thresholdInfo down, real
        (30, ENUM(2)),                                  # trendIndication
        (31, ENUM(1)),                                  # administrativeState
        (32, SET(INT(0), INT(4))),                      # alarmStatus
        (33, SET(INT(1), INT(8))),                      # availabilityStatus
        (34, SET(INT(0), INT(3))),                      # controlStatus
        (35, ENUM(1)),                                  # operationalState
        (36, SET(INT(0), INT(3))),                      # proceduralStatus
        (37, ENUM(0)),                                  # standbyStatus
        (38, BOOL(False)),                              # unknownStatus
        (39, ENUM(2)),                                  # usageState
        (40, oi_dn()),                                  # backUpObject objectName
        (41, NULL()),                                   # backedUpObject noObject
        (42, SET(oi_dn(), oi_local())),                 # member
        (43, SET(oi_nonspecific())),                    # owner
        (44, oi_local()),                               # peer
        (45, SET(SEQ(oi_dn(), INT(0)), SEQ(oi_local(), INT(127)))),  # primary
        (46, SET(SEQ(oi_nonspecific(), INT(5)))),       # providerObject
        (47, SET()),                                    # secondary
        (48, SET(SEQ(oi_dn(), INT(64)))),               # userObject
        (49, ae_title_form2()),                         # activeDestination single
        (50, SET(oc_global(), oc_local())),             # allomorphs
        (51, SEQ(ae_title_form2(), ae_title_form1())),  # backUpDestinationList
        (52, SET(INT(80), INT(100))),                   # capacityAlarmThreshold
        (53, BOOL(True)),                               # confirmedMode
        (54, INT(4096)),                                # currentLogSize
        (55, SET(ae_title_form2(), ae_title_form1())),  # destination multiple
        (55, ae_title_form1()),                         # destination single
        (56, filt_item(fi_present(attr_id_global(X721(35))))),  # discriminatorConstruct
        (57, SET(SEQ(tm(8, 0), tm(17, 30)))),           # intervalsOfDay
        (58, ENUM(0)),                                  # logFullAction
        (59, T),                                        # loggingTime
        (62, INT(0)),                                   # maxLogSize unlimited
        (63, OID('2.9.3.2.6.1')),                       # nameBinding
        (64, INT(12)),                                  # numberOfRecords
        (65, oc_global('2.9.3.2.3.4')),                 # objectClass
        (66, SET(OID('2.9.3.2.4.14'))),                 # packages
        (68, T),                                        # startTime
        (69, T),                                        # stopTime specific
        (69, NULL()),                                   # stopTime continual
        (70, SET(SEQ(OID(OID_TXT), GSTR('feature')))),  # supportedFeatures
        (71, SET(SEQ(BITS(1, b'\x7e'), SET(SEQ(tm(0, 0), tm(23, 59)))))),  # weekMask
        (115, ENUM(1)),                                 # lifecycleState
        ('2.9.2.21.7.13', SEQ(oc_global(), oi_nonspecific())),  # BaseManagedObjectId
    ]
    return v


def attr_list(pairs):
    return b''.join(attribute(attr_id_global(n if isinstance(n, str) else X721(n)), val)
                    for n, val in pairs)


def base_obj(oc=None, oi=None):
    return (oc if oc is not None else oc_global()) + (oi if oi is not None else oi_dn())


# ------------------------------------------------------- the PDUs

def event_report_arg(local=False, info=True, time=True):
    body = oc_global() + oi_dn()
    if time:
        body += GTIME(tag=0x85)
    if local:
        body += INT(9, 0x87)
    else:
        body += OID(OID_TXT, 0x86)
        if info:
            body += tlv(0xa8, GSTR('link down'))
    return SEQ(body)


def get_arg():
    filt = filt_and(
        filt_item(fi_attr(0, attr_id_global(X721(35)), ENUM(1))),
        filt_item(fi_substrings(
            tlv(0xa0, attr_id_global(OID_TXT) + GSTR('ab')),
            tlv(0xa1, attr_id_global(OID_TXT) + GSTR('cd')),
            tlv(0xa2, attr_id_global(OID_TXT) + GSTR('ef')))),
        filt_item(fi_attr(2, attr_id_global(X721(54)), INT(10))),
        filt_item(fi_attr(3, attr_id_global(X721(54)), INT(10000))),
        filt_or(filt_item(fi_present(attr_id_local(7))),
                filt_item(fi_attr(5, attr_id_global(X721(33)), SET(INT(1)))),
                filt_item(fi_attr(6, attr_id_global(X721(33)), SET(INT(1), INT(2)))),
                filt_item(fi_attr(7, attr_id_global(X721(33)), SET(INT(3))))),
        filt_not(filt_item(fi_present(attr_id_global(X721(31))))))
    return SEQ(base_obj(), access_control(), sync(1), scope_named(2), filt,
               tlv(0xac, attr_id_global(X721(35)) + attr_id_local(12)))


def get_arg_min(scope):
    return SEQ(base_obj(oc_local(), oi_nonspecific()), scope)


def get_result(pairs, time=True):
    body = oc_global() + oi_dn()
    if time:
        body += GTIME(tag=0x85)
    body += tlv(0xa6, attr_list(pairs))
    return SEQ(body)


def set_arg():
    mods = (SEQ(INT(0, 0x82), attr_id_global(X721(31)), ENUM(0))
            + SEQ(INT(1, 0x82), attr_id_global(X721(52)), SET(INT(90)))
            + SEQ(INT(3, 0x82), attr_id_global(X721(54)))
            + SEQ(attr_id_local(4), INT(77)))
    return SEQ(base_obj(), access_control(), sync(0), scope_individual(1),
               filt_item(fi_present(attr_id_global(X721(35)))), tlv(0xac, mods))


def set_result():
    return SEQ(oc_global(), oi_dn(), GTIME(tag=0x85),
               tlv(0xa6, attr_list([(31, ENUM(0)), (52, SET(INT(90)))])))


def action_info(global_type=True, arg=True, oid=OID_TXT):
    body = OID(oid, 0x82) if global_type else INT(3, 0x83)
    if arg:
        body += tlv(0xa4, GSTR('reset'))
    return body


def action_arg(global_type=True, arg=True, extra=True):
    body = base_obj()
    if extra:
        body += access_control() + sync(1) + scope_nth(3) + filt_and()
    return SEQ(body + tlv(0xac, action_info(global_type, arg)))


def action_result(reply=True, oid=OID_TXT):
    body = oc_global() + oi_dn() + GTIME(tag=0x85)
    if reply:
        body += tlv(0xa6, OID(oid, 0x82) + tlv(0xa4, GSTR('done')))
    return SEQ(body)


def create_arg(variant):
    if variant == 0:
        return SEQ(oc_global(), oi_dn(), access_control(), tlv(0xa6, oi_local()),
                   tlv(0xa7, attr_list([(31, ENUM(1)), (35, ENUM(1)), (7, GSTR('new'))])))
    if variant == 1:
        # a local form attribute is decoded with the last OID seen in the
        # PDU (even an object class), so there is no global OID before it
        return SEQ(oc_local(), tlv(0xa8, oi_nonspecific()), tlv(0xa7, attribute(attr_id_local(2), INT(5))))
    return SEQ(oc_local())


def create_result():
    return SEQ(oc_global(), oi_dn(), GTIME(tag=0x85),
               tlv(0xa6, attr_list([(31, ENUM(1)), (66, SET(OID('2.9.3.2.4.14')))])))


def delete_arg():
    return SEQ(base_obj(), access_control(), sync(1), scope_named(1),
               filt_or(filt_item(fi_present(attr_id_local(1)))))


def delete_result():
    return SEQ(oc_global(), oi_dn(), GTIME(tag=0x85))


def event_report_result():
    return SEQ(oc_global(), oi_dn(), GTIME(tag=0x85),
               SEQ(OID(OID_TXT, 0x86), tlv(0xa8, GSTR('ack'))))


def specific_error_info(oid=OID_MAXLOG):
    return OID(oid) + INT(3)


def processing_failure_body():
    return oc_global() + oi_dn() + tlv(0xa5, specific_error_info())


def get_list_error_body():
    return (oc_global() + oi_dn() + GTIME(tag=0x85)
            + tlv(0xa6, tlv(0xa0, ENUM(5) + attr_id_global(X721(99)))
                  + tlv(0xa1, attr_id_global(X721(35)) + ENUM(1))))


def set_list_error_body(value=False):
    # AttributeError's attributeValue is decoded with object_identifier_id
    # (no OID here), not with its attributeId
    return (oc_global() + oi_dn() + GTIME(tag=0x85)
            + tlv(0xa6, tlv(0xa0, ENUM(25) + INT(2, 0x82) + attr_id_global(OID_TXT)
                            + (GSTR('bad') if value else b''))
                  + tlv(0xa0, ENUM(2) + attr_id_local(5))
                  + tlv(0xa1, attr_id_global(X721(31)) + ENUM(0))))


def action_error_body(variant):
    if variant == 0:
        info = OID(OID_TXT, 0x82)                       # actionType
    elif variant == 1:
        info = tlv(0xa0, tlv(0xa0, oc_global() + OID(OID_TXT, 0x82)))   # noSuchArgument actionId
    elif variant == 2:
        info = tlv(0xa0, tlv(0xa1, oc_local() + INT(1, 0x87)))          # noSuchArgument eventId
    elif variant == 3:
        info = tlv(0xa1, tlv(0xa0, OID(OID_TXT, 0x82) + tlv(0xa4, GSTR('bad arg'))))  # invalidArgumentValue action
    else:
        info = tlv(0xa1, tlv(0xa1, OID(OID_TXT, 0x86) + tlv(0xa8, GSTR('bad event'))))  # invalidArgumentValue event
    status = [9, 14, 14, 15, 15][variant]
    return oc_global() + oi_dn() + GTIME(tag=0x85) + tlv(0xa6, ENUM(status) + info)


def linked_replies():
    return [
        tlv(0xa0, oc_global() + oi_dn() + tlv(0xa6, attr_list([(35, ENUM(1))]))),   # getResult
        tlv(0xa1, get_list_error_body()),                                         # getListError
        tlv(0xa2, oc_global() + oi_dn()),                                         # setResult
        tlv(0xa3, set_list_error_body()),                                         # setListError
        tlv(0xa4, oc_global() + oi_dn() + tlv(0xa6, OID(OID_TXT, 0x82) + tlv(0xa4, GSTR('ok')))),  # actionResult
        tlv(0xa5, processing_failure_body()),                                     # processingFailure
        tlv(0xa6, oc_global() + oi_dn() + GTIME(tag=0x85)),                       # deleteResult
        tlv(0xa7, action_error_body(0)),                                          # actionError
        tlv(0xa7, action_error_body(1)),
        tlv(0xa7, action_error_body(2)),
        tlv(0xa7, action_error_body(3)),
        tlv(0xa7, action_error_body(4)),
        tlv(0xa8, oc_global() + oi_dn() + ENUM(2, 0x86)),                         # deleteError
    ]


def error_params():
    """(error code, parameter) for every error that has a parameter."""
    return [
        (0, oc_global()),                                       # noSuchObjectClass
        (1, oi_dn()),                                           # noSuchObjectInstance
        (3, ENUM(1)),                                           # syncNotSupported
        (4, filt_item(fi_present(attr_id_local(1)))),           # invalidFilter
        (5, attr_id_global(X721(99))),                          # noSuchAttribute
        (6, attribute(attr_id_global(X721(31)), ENUM(7))),      # invalidAttributeValue
        (7, SEQ(get_list_error_body())),                        # getListError
        (8, SEQ(set_list_error_body(True))),                        # setListError
        (9, SEQ(oc_global() + OID(OID_TXT, 0x82))),             # noSuchAction
        (10, SEQ(processing_failure_body())),                   # processingFailure
        (11, oi_dn()),                                          # duplicateManagedObjectInstance
        (12, oi_local()),                                       # noSuchReferenceObject
        (13, SEQ(oc_global() + INT(2, 0x87))),                  # noSuchEventType
        (14, tlv(0xa0, OID(OID_TXT, 0x82))),                    # noSuchArgument
        (15, tlv(0xa0, OID(OID_TXT, 0x82) + tlv(0xa4, GSTR('x')))),  # invalidArgumentValue
        (16, INT(2)),                                           # invalidScope
        (17, oi_nonspecific()),                                 # invalidObjectInstance
        (18, SET(attr_id_global(X721(31)), attr_id_local(2))),  # missingAttributeValue
        (19, SEQ(oc_global() + oi_dn())),                       # classInstanceConflict
        (20, SET(tlv(0xa0, INT(1)), tlv(0xa1, filt_and()), INT(0, 0x82))),  # complexityLimitation
        (22, INT(5)),                                           # noSuchInvokeId
    ]


# ----------------------------------------------------------- frames


def main_frames():
    F = []
    # 1-2: association: AARQ / AARE carrying CMIPUserInfo
    F.append(ses_cn(pres_cp(fully_encoded(pdv(CTX_ACSE, aarq(user_info_ext(cmip_user_info())))))))
    F.append(ses_ac(pres_cpa(fully_encoded(pdv(CTX_ACSE, aare(user_info_ext(cmip_user_info(False))))))))
    # 3-5: event reports
    F.append(cmip(invoke(1, 0, event_report_arg())))
    F.append(cmip(invoke(2, 1, event_report_arg(local=True, time=False))))
    F.append(cmip(return_result(2, 1, event_report_result())))
    # 6-9: get
    F.append(cmip(invoke(3, 3, get_arg())))
    F.append(cmip(invoke(4, 3, get_arg_min(scope_individual(2)))))
    F.append(cmip(invoke(5, 3, get_arg_min(scope_nth(1)))))
    F.append(cmip(return_result(3, 3, get_result([(35, ENUM(1)), (31, ENUM(1))]))))
    # 10-12: every X.721 attribute in get results
    vals = x721_values()
    third = (len(vals) + 2) // 3
    for i in range(3):
        # AttributeValueChangeDefinition values are decoded with the OID
        # of the last event type (object_identifier_id), so each frame
        # starts with an eventType attribute naming operationalState
        chunk = [(14, OID(OID_OPSTATE, 0x86))] + vals[i * third:(i + 1) * third]
        F.append(cmip(return_result(10 + i, 3, get_result(chunk, time=(i == 0)))))
    # 13-16: set (15: local form attribute ids only)
    F.append(cmip(invoke(6, 4, set_arg())))
    F.append(cmip(invoke(7, 5, set_arg())))
    # local form attribute ids only, no OID anywhere before them
    F.append(cmip(invoke(70, 4, SEQ(oc_local(), oi_nonspecific(),
                                    tlv(0xac, SEQ(attr_id_local(4), INT(77)) + SEQ(attr_id_local(5)))))))
    F.append(cmip(return_result(7, 5, set_result())))
    # 17-20: action
    F.append(cmip(invoke(8, 6, action_arg())))
    F.append(cmip(invoke(9, 7, action_arg(global_type=True, arg=False, extra=False))))
    F.append(cmip(return_result(9, 7, action_result())))
    F.append(cmip(return_result(9, 7, action_result(reply=False))))
    # 21-27: create and delete
    for v in range(3):
        F.append(cmip(invoke(20 + v, 8, create_arg(v))))
    F.append(cmip(return_result(20, 8, create_result())))
    F.append(cmip(return_result(21, 8, SEQ())))
    F.append(cmip(invoke(30, 9, delete_arg())))
    F.append(cmip(return_result(30, 9, delete_result())))
    # 28-29: cancel get
    F.append(cmip(invoke(31, 10, INT(3))))
    F.append(cmip(return_result(31)))
    # 30-42: linked replies to the get (invoke 3)
    for i, lr in enumerate(linked_replies()):
        F.append(cmip(invoke(40 + i, 2, lr, linked=3)))
    # 43-46: results without data, an invoke without invoke id
    F.append(cmip(return_result(1)))
    F.append(cmip(return_result(6)))
    F.append(cmip(return_result(8)))
    F.append(cmip(invoke(None, 0, event_report_arg(info=False))))   # invoke id absent
    # 47-50: errors without a parameter, local and global code
    F.append(cmip(return_error(5, 2)))                                # accessDenied
    F.append(cmip(return_error(4, 21)))                               # mistypedOperation
    F.append(cmip(return_error(31, 23)))                              # operationCancelled
    F.append(cmip(return_error(9, 0, global_code='2.9.1.1.9')))       # global error code
    # 51-58: rejects
    for ptag, prob in ((0, 0), (0, 2), (1, 1), (1, 7), (2, 0), (2, 2), (3, 2), (3, 4)):
        F.append(cmip(reject(50 + len(F), ptag, prob)))
    # 59-60: unknown local opcode, global opcode
    F.append(cmip(invoke(60, 42)))
    F.append(cmip(invoke(61, 0, global_code='2.9.1.1.99')))
    # 61: event report in typed data (SPDU 33, not dissected by CMIP)
    F.append(ses_td(p_data(invoke(62, 0, event_report_arg()))))
    # 62: event report in an octet-aligned PDV
    F.append(ses_dt(p_data(invoke(63, 0, event_report_arg()), octet_aligned=True)))
    # 63-64: reproducer cmip_stale_oid.py: M-ACTION with a
    # global action type (sets the OID), then M-ACTION with a local form
    # and an actionInfoArg (no OID: must not reuse the earlier one)
    F.append(cmip(invoke(1, 6, SEQ(oc_local(5), oi_nonspecific(b'\x00'),
                                   tlv(0xac, action_info(True, True))))))
    F.append(cmip(invoke(1, 6, SEQ(oc_local(5), oi_nonspecific(b'\x00'),
                                   tlv(0xac, INT(7, 0x83) + tlv(0xa4, OCTS(b'AB')))))))
    # 65-66: release (RLRQ / RLRE with CMIPUserInfo)
    F.append(ses_fn(fully_encoded(pdv(CTX_ACSE, rlrq(user_info_ext(cmip_user_info(False)))))))
    F.append(ses_dn(fully_encoded(pdv(CTX_ACSE, rlre(user_info_ext(cmip_user_info(False)))))))
    # 67: abort (ABRT with CMIPAbortInfo)
    F.append(ses_ab(pres_aru(fully_encoded(pdv(CTX_ACSE, abrt(user_info_ext(cmip_abort_info(0))))))))
    # 68: abort by the provider without user info
    F.append(ses_ab(pres_aru(fully_encoded(pdv(CTX_ACSE, abrt(user_info_ext(cmip_abort_info(1, False)), 1))))))
    # 69: refuse (CPR with a rejected AARE carrying CMIPUserInfo)
    F.append(ses_rf(pres_cpr(fully_encoded(pdv(CTX_ACSE, aare(user_info_ext(cmip_user_info()), result=1))))))
    # 70: a get result whose attribute (id: the CMIP abstract syntax OID)
    # holds another CMIP APDU (CMIP called again with the session data)
    F.append(cmip(nested_cmip(1)))
    return F


def nested_cmip(n):
    ros = invoke(1, 0, event_report_arg(info=False))
    for _ in range(n):
        ros = return_result(2, 3, SEQ(tlv(0xa6, attribute(attr_id_global(OID_CMIP_AS), ros))))
    return ros


def malformed_frames():
    F = []
    # ReturnError with a parameter: T_parameter does not assign the
    # offset, so each one ends with a BER error
    for code, param in error_params():
        F.append(cmip(return_error(70 + code, code, param)))
    # unknown error code with a parameter
    F.append(cmip(return_error(99, 77, INT(1))))
    # truncated invoke
    F.append(cmip(invoke(1, 3, get_arg())[:20]))
    # wrong ROS tag
    F.append(cmip(tlv(0xa7, INT(1))))
    # attribute with an unregistered OID
    F.append(cmip(return_result(3, 3, get_result([(200, INT(1))]))))
    # event report with an unregistered event type
    F.append(cmip(invoke(1, 0, SEQ(oc_global(), oi_dn(), OID('1.3.6.1.4.1.32473.1', 0x86),
                                   tlv(0xa8, INT(1))))))
    # results with data for operations that have no result data
    for op in (0, 2, 4, 6, 10):
        F.append(cmip(return_result(1, op, INT(5))))
    # CMIP nested in CMIP 300 times through attribute values: ends at the
    # dissection depth assertion (no tree) or the tree depth limit
    F.append(cmip(nested_cmip(300)))
    # the CMIP OID inside a management extension (X.721 PDU dissector,
    # no session data): CMIP returns 0
    F.append(cmip(return_result(3, 3, get_result(
        [(6, SET(SEQ(OID(OID_CMIP_AS), tlv(0xa2, invoke(1, 0, event_report_arg(info=False))))))]))))
    # stale object_identifier_id: an event report with a global event type
    # cut short (the exception skips the restore at the end of
    # dissect_cmip), then an AARQ whose user-information EXTERNAL is an
    # attributeValueChangeDefinition (2.9.3.2.7.10); its newAttributeValue
    # is decoded with the OID from the previous packet (freed memory)
    er = invoke(1, 0, SEQ(oc_local(1), oi_nonspecific(),
                          OID('1.3.6.1.4.1.32473.77.1.2.3.4.5.6.7.8.9.10', 0x86), tlv(0xa8, INT(1))))
    F.append(cmip(er[:-1]))
    avc = SET(SEQ(attr_id_local(1), tlv(0xa2, INT(5))))
    F.append(ses_cn(pres_cp(fully_encoded(pdv(CTX_ACSE, aarq(user_info_ext(avc, oid=X721(10))))))))
    return F


def write_exported_pdu(path, frames, proto='ses'):
    name = proto.encode()
    pad = name + b'\x00' * (-len(name) % 4)
    if len(pad) == len(name):
        pad += b'\x00' * 4
    hdr = struct.pack('>HH', 12, len(pad)) + pad + struct.pack('>HH', 0, 0)
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            data = hdr + fr
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(data), len(data)))
            f.write(data)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_f = main_frames()
    # the malformed capture starts with the association so that the
    # presentation contexts are known
    write_exported_pdu(os.path.join(out, 'cmip-coverage.pcap'), main_f)
    write_exported_pdu(os.path.join(out, 'cmip-coverage-malformed.pcap'),
                       main_f[:1] + malformed_frames())


if __name__ == '__main__':
    main()
