#!/usr/bin/env python3
# Generates test/captures/h248_3gpp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-h248_3gpp.c (3GPP TS 29.232 packages: 3G
User Plane 0x002f, Circuit Switched Data 0x0030, TFO Control 0x0031, IP
transport 0x0083 and Interface Type 0x00e3).  Usage: mkh248_3gpp.py <outdir>
Writes h248_3gpp-coverage.pcapng and h248_3gpp-coverage-malformed.pcapng."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from h248common import (
    A, action, b4, ber_int, CODEC_LIST, command, evt_msg, megaco, pkg_main, prop_msg, prop_parm,
    sig_msg, term_id, term_list, tlv, trx_req,
)

PK = [0x002f, 0x0030, 0x0031, 0x0083, 0x00e3]
T = term_id(b'\x01\x02')
I = lambda v: tlv(2, ber_int(v))


def pm(pkg, item, v):
    return prop_parm(pkg, item, [v])


def event(pkg, eid, pars):
    ps = [tlv(0x30, tlv(0x80, pid), tlv(0xA1, tlv(4, v))) for pid, v in pars]
    return tlv(0x30, tlv(0x80, b4(pkg, eid)), tlv(0xA2, *ps))


def specific(g, sw):
    F = []
    # 3G User Plane properties: mode, UP versions, delivery of erroneous SDUs, interface, initialisation direction
    for k in range(4):
        F.append(prop_msg(T, [pm(0x2f, 1, I(1 + k % 2)), pm(0x2f, 2, I(1 << k)), pm(0x2f, 3, I(1 + k % 3)),
                              pm(0x2f, 4, I(1 + k % 2)), pm(0x2f, 5, I(2 - k % 2))], 2 + k % 2, 10 + k))
    F.append(prop_msg(T, [pm(0x2f, 9, I(1)), pm(0x2f, 1, I(70000))], 2, 14))
    # IP transport and interface type
    F.append(prop_msg(T, [pm(0x83, 1, tlv(4, b'\xc0\x00\x02\x01')), pm(0x83, 2, tlv(4, bytes(range(1, 17))))], 2, 15))
    F.append(prop_msg(T, [pm(0x83, 3, I(49170)), pm(0xe3, 1, I(1)), pm(0xe3, 1, I(2)), pm(0xe3, 9, I(2))], 3, 16))
    # circuit switched data: bearer capability of several lengths (a short one used to wrap), channel codings
    for k, bc in enumerate((b'\x60', b'\x60\x04\x02\x01\x00', b'\x60\x04', b'', b'\x60\x04\x02\x01\x00\x00\x00\x00\x00',
                            b'\xa0\x84\x00', b'\x04\x06\x60\x04\x02\x01\x00\x00')):
        F.append(prop_msg(T, [pm(0x30, 1, tlv(4, bc)), pm(0x30, 2, tlv(4, bytes([k, 2, 3])))], 2 + k % 2, 20 + k))
    # events protres (result, cause), ratechg and the signal actprot
    for k in range(3):
        F.append(evt_msg(T, [event(0x30, 1, [(b'\x00\x01', I(k % 2)), (b'\x00\x02', I(1 + k % 2))]),
                             event(0x30, 2, [(b'\x00\x01', I(64000 + k))]), event(0x30, 3, [])], 2 + k % 2, 31 + k))
    F.append(sig_msg(T, [tlv(0xA0, tlv(0x80, b4(0x30, 0x10)), tlv(0xA6, tlv(0x30, tlv(0x80, b'\x00\x01'),
                                                                          tlv(0xA1, tlv(4, I(1))))))], 2, 36))
    F.append(sig_msg(T, [tlv(0xA0, tlv(0x80, b4(0x30, 0x11)))], 2, 37))
    # TFO: enable, codec list, optimal codec (a short codec: the length of the outer value was used), distant list, status
    F.append(prop_msg(T, [pm(0x31, 1, I(1)), pm(0x31, 1, I(2)), pm(0x31, 2, tlv(4, CODEC_LIST)),
                          pm(0x31, 2, tlv(4, CODEC_LIST[:2])), pm(0x31, 2, b'\x30\x01\x00')], 2, 38))
    for k, codec in enumerate((b'\x02\x04', b'\x01\x08', b'\x02\x01\x81', b'\x01\x01', b'\x02\x03\x81\x82', b'\x01\x0a\x01')):
        F.append(evt_msg(T, [event(0x31, 0x10, [(b'\x00\x11', tlv(4, codec))])], 2 + k % 2, 40 + k))
    F.append(evt_msg(T, [event(0x31, 0x10, [(b'\x00\x11', b'\x30\x00')])], 2, 46))
    F.append(evt_msg(T, [event(0x31, 0x12, [(b'\x00\x13', tlv(4, CODEC_LIST)), (b'\x00\x13', tlv(4, CODEC_LIST[:4]))]),
                         event(0x31, 0x12, [(b'\x00\x13', b'\x30\x00')]), event(0x31, 0x14, [(b'\x00\x01', tlv(1, b'\xff'))]),
                         event(0x31, 0x14, [(b'\x00\x01', tlv(1, b'\x00'))]), event(0x31, 0x15, [])], 3, 47))
    return F


def bad():
    M = []
    ev = lambda pkg, eid, pid, v: megaco([trx_req(1, [action(1, [command(6, term_list(T), A(1, tlv(0x80, b'\x09'),
                                                                                        A(1, event(pkg, eid, [(pid, v)]))))])])])
    # a codec that is longer than its octet string, an ETSI codec of one octet, an unknown organisation
    M.append(ev(0x31, 0x10, b'\x00\x11', tlv(4, b'\x02')))
    M.append(ev(0x31, 0x10, b'\x00\x11', tlv(4, b'')))
    M.append(ev(0x31, 0x12, b'\x00\x13', tlv(4, b'\x01\x01\x02')))
    M.append(ev(0x31, 0x12, b'\x00\x13', tlv(4, b'\x05\x01\x01')))
    M.append(ev(0x31, 0x14, b'\x00\x01', tlv(2, b'\x01')))
    M.append(ev(0x30, 2, b'\x00\x01', tlv(4, b'x')))
    M.append(megaco([trx_req(2, [action(1, [command(2, term_list(T), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, prop_parm(0x30, 1, [b'\x30\x00']))))))])])]))
    M.append(megaco([trx_req(2, [action(1, [command(2, term_list(T), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0,
             prop_parm(0x30, 1, [b'\x04\x09\x60']))))))])])]))
    return M


if __name__ == '__main__':
    pkg_main(sys.argv[1] if len(sys.argv) > 1 else '.', 'h248_3gpp', PK, specific, bad, 51)
