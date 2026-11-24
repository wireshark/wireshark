#!/usr/bin/env python3
# Generates test/captures/p772_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the P772 dissector
(packet-p772.c, STANAG 4406 Military Message Handling System, generated
from epan/dissectors/asn1/p772).

P772 has no port of its own. It is reached
  - as the content of a P1/P3 message whose content type is the object
    identifier 1.3.26.0.4406.0.4.1 (the BER OID table), here in a P3
    message submission on the OSI upper layers on TCP port 102;
  - through Exported PDU (linktype 252): "p772" (InformationObject) and
    "x509af" (a CRL whose extensions carry the OIDs P772 registers: the
    military heading extensions, the extended body parts and the
    priority level qualifier).
The P22 dissector hands the heading extensions of an interpersonal message
to P772 (IPMSExtension OIDs 1.3.26.0.4406.0.2.x).

Usage: mkp772.py <output directory>
Writes p772-coverage.pcapng and p772-coverage-malformed.pcapng.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from x400lib import (  # noqa: E402,
    Assoc, BITS, crl_with_exts, delivered_content_type, eits, ENUM, IA5, imp, INT, mts_id, NULL,
    OCTS, OID, orname, Pcapng, priority, PSTR, sec_label, SEQ, SET, submission_envelope, tlv,
    UTCT, X,
)
import ipmlib
from ipmlib import ipms_ext, or_desc, ext_bp  # noqa: E402

AC_MTS_ACCESS_94 = '2.6.0.1.7'
AS_MTS = '2.6.0.2.11'
CTX = 3
OP_MESSAGE_SUBMISSION = 3
CT_P772 = '1.3.26.0.4406.0.4.1'
MMHS = '1.3.26.0.4406.0'


def other_fields(ctype=22, ext=(), full=True):
    body = delivered_content_type(ctype) + orname()
    if full:
        body += imp(1, eits()) + priority(1)
    body += imp(4, orname(prmd_name='This')) + UTCT(tag=0x87)
    return SET(body)


def address_list(n=2):
    return SEQ(*[SET(INT(i % 2, 0x80), imp(1, or_desc()), INT(i % 3, 0x82), INT((i + 1) % 3, 0x83))
                 for i in range(n)])


def heading_values():
    """(OID suffix, value) of the military heading extensions."""
    lab = sec_label()
    return [
        ('2.0', INT(4)), ('2.1', INT(17)), ('2.2', SET(INT(1, 0x80), PSTR('MSG0001', 0x81))),
        ('2.2', SET(INT(3, 0x80))),
        ('2.3', address_list(3)), ('2.4', SEQ(or_desc(), or_desc(free=None))),
        ('2.5', UTCT()),
        ('2.6', SET(tlv(0xa0, PSTR('SIC1'), PSTR('SIC2')),
                    tlv(0xa1, SEQ(OID('1.2.3.4'), NULL()), SEQ(OID('1.2.3.5'), INT(5))))),
        ('2.6', SET(tlv(0xa0, PSTR('SIC3')))),
        ('2.7', SEQ(PSTR('HANDLE'), PSTR('CAREFULLY'))), ('2.8', SEQ(PSTR('INSTRUCTION'))),
        ('2.9', INT(1234)), ('2.10', PSTR('ORIGINATOR REF')),
        ('2.11', SEQ(SET(INT(0, 0x80), PSTR('DESIGNATOR', 0x81)), SET(INT(1, 0x80), PSTR('D2', 0x81)))),
        ('2.12', SEQ(SEQ(INT(2, 0x80), tlv(0xa1, or_desc()), imp(2, lab), tlv(0xa3, PSTR('HAND'))),
                     SEQ(INT(18, 0x80)))),
        ('2.13', PSTR('ACP127 ID')), ('2.14', PSTR('PLAD')), ('2.15', BITS(5, b'\xe0')),
        ('2.16', SET(BITS(5, b'\x80', 0x80), UTCT(tag=0x81), imp(2, address_list(1)),
                     PSTR('recipient', 0x83), PSTR('supp info', 0x84))),
        ('2.17', SEQ(imp(0, lab), imp(1, lab), tlv(0xa2, SET(imp(0, lab), INT(2, 0x81)), SET(imp(0, lab))))),
        ('8.0', ENUM(1)),
    ]


def ext_list():
    out = []
    for suffix, val in heading_values():
        if suffix.startswith('2.'):
            out.append(ipms_ext('%s.%s' % (MMHS, suffix), val))
    return out


def body_part_values():
    return [
        ('7.0', tlv(0x80, b'line oriented data')), ('7.0', tlv(0xa1, IA5('set'), IA5('oriented'))),
        ('7.2', INT(3)), ('7.1', IA5('corrections')), ('7.3', INT(2)),
        ('7.6', BITS(0, b'\x12\x34')),
        ('7.7', SET(UTCT(tag=0x80), imp(1, other_fields()))),
        ('7.9', ipmlib.ipm_plain()), ('7.10', SET(UTCT(tag=0x80), imp(1, other_fields()))),
        ('7.12', IA5('acp127 data')), ('7.13', INT(4)),
    ]


def mm_message(h=None, b=None):
    return ipmlib.ipm(h if h is not None else ipmlib.heading(False), b if b is not None else ipmlib.body())


def info_objects():
    out = []
    ext = ext_list()
    parts = [ext_bp('%s.%s' % (MMHS, s), v) for s, v in body_part_values() if s in ('7.0', '7.1', '7.12', '7.6')]
    parts.append(ext_bp('%s.7.9' % MMHS, ipmlib.ipm_plain(), '%s.7.10' % MMHS,
                        SET(UTCT(tag=0x80), imp(1, other_fields()))))
    parts.append(ext_bp('%s.7.0' % MMHS, tlv(0x80, b'adatp3'), '%s.7.2' % MMHS, INT(3)))
    parts.append(ext_bp('%s.7.12' % MMHS, IA5('acp127'), '%s.7.13' % MMHS, INT(2)))
    parts.append(ext_bp('%s.7.1' % MMHS, IA5('corr'), '%s.7.3' % MMHS, INT(1)))
    parts.append(ext_bp('%s.7.6' % MMHS, BITS(0, b'\x01'), '%s.7.7' % MMHS,
                        SET(UTCT(tag=0x80), imp(1, other_fields()))))
    out.append(mm_message(ipmlib.heading(True, ext=ext), ipmlib.body(*parts)))
    out.append(mm_message(ipmlib.heading(False, ext=ext[:6])))
    out.append(ipmlib.ipn_obj(ipmlib.ipn_other(ipms_ext('%s.2.16' % MMHS, dict((k, v) for k, v in heading_values() if k == '2.16')['2.16'])), True))
    out.append(ipmlib.ipn_obj(ipmlib.ipn_non_receipt(0, 1, 'fwd', True), False))
    out.append(ipmlib.ipn_obj(ipmlib.ipn_receipt(1, True), True))
    return out


def crl_values():
    vals = [('%s.%s' % (MMHS, s), v) for s, v in heading_values()]
    vals += [('%s.%s' % (MMHS, s), v) for s, v in body_part_values()]
    vals.append(('2.6.1.4.17.1.3.26.0.4406.0.4.1', mm_message()))
    vals.append((CT_P772, mm_message(ipmlib.heading(False, ext=ext_list()[:4]))))
    return vals


def main_pcapng():
    p = Pcapng()
    F = []
    a = Assoc(F, 48001, AC_MTS_ACCESS_94, [(CTX, AS_MTS)])
    a.open()
    a.bind(SET(orname(), X(2, IA5('secret'))))
    a.bind_result(SET(IA5('mta.example', 0x80), X(2, IA5('secret'))))
    for obj in info_objects()[:3]:
        a.op(OP_MESSAGE_SUBMISSION, SEQ(submission_envelope(CT_P772, True, (), (), 1), OCTS(obj)),
             SET(mts_id('sub-1'), UTCT(tag=0x80)))
    a.close()
    p.eth(F)
    for obj in info_objects():
        p.exp('p772', obj)
    vals = crl_values()
    n = int(os.environ.get('CHUNK', '6'))
    for i in range(0, len(vals), n):
        p.exp('x509af', crl_with_exts(*vals[i:i + n]))
    return p


def malformed_frames():
    p = Pcapng()
    good = info_objects()[0]
    p.exp('p772', good[:len(good) // 2])
    p.exp('p772', tlv(0xa5, SET()))
    p.exp('p772', mm_message(ipmlib.heading(False, ext=[ipms_ext('%s.2.99' % MMHS, NULL())])))
    p.exp('p772', mm_message(ipmlib.heading(False, ext=[ipms_ext('%s.2.0' % MMHS, UTCT())])))
    p.exp('p772', mm_message(ipmlib.heading(False), ipmlib.body(ext_bp('%s.7.99' % MMHS, OCTS(b'x')))))
    p.exp('p772', b'')
    p.exp('x509af', crl_with_exts(('%s.2.2' % MMHS, SET(INT(9))), ('%s.7.0' % MMHS, NULL()),
                                  ('%s.2.6' % MMHS, SET(tlv(0xa1, SEQ(INT(1)))))))
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_pcapng().write(os.path.join(out, 'p772-coverage.pcapng'))
    malformed_frames().write(os.path.join(out, 'p772-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
