#!/usr/bin/env python3
# Generates test/captures/h248_q1950_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-h248_q1950.c (ITU-T Q.1950 Annex A
packages: bcp 0x001e, bnc cut-through 0x001f, reuse idle 0x0020, generic
bearer connection 0x0021, bearer control tunnelling 0x0022 and the basic
call progress tones generator 0x0023).  The tunnelling package carries BCTP
(Q.1990), which the bctp dissector shows.
Usage: mkh248_q1950.py <outdir>
Writes h248_q1950-coverage.pcapng and h248_q1950-coverage-malformed.pcapng."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from h248common import (
    A, action, b4, BCTP_IPBCP, ber_int, command, evt_msg, megaco, pkg_main, prop_msg, prop_parm,
    sig_msg, struct, term_id, term_list, tlv, trx_req,
)

PK = [0x001e, 0x001f, 0x0020, 0x0021, 0x0022, 0x0023]
T = term_id(b'\x01\x02')
I = lambda v: tlv(2, ber_int(v))


def event(pkg, eid, pars):
    ps = [tlv(0x30, tlv(0x80, pid), tlv(0xA1, tlv(4, v))) for pid, v in pars]
    return tlv(0x30, tlv(0x80, b4(pkg, eid)), tlv(0xA2, *ps))


def signal(pkg, sid, pars):
    sp = [tlv(0x30, tlv(0x80, pid), tlv(0xA1, tlv(4, v))) for pid, v in pars]
    return tlv(0xA0, tlv(0x80, b4(pkg, sid)), tlv(0xA6, *sp))


def bctp(tpi, payload, bvi=1, bvei=0, tpei=0):
    return struct.pack('>BB', (bvei << 6) | (bvi & 0x1f), (tpei << 6) | (tpi & 0x3f)) + payload


def specific(g, sw):
    F = []
    # properties: bearer characteristics, cut-through, reuse idle, tunnelling option
    for k in range(4):
        F.append(prop_msg(T, [prop_parm(0x1e, 1, [I(k)]), prop_parm(0x1f, 1, [I(1 + k % 3)]), prop_parm(0x20, 1, [I(k % 2)]),
                              prop_parm(0x22, 1, [I(1 + k % 3)])], 2 + k % 2, 10 + k))
    F.append(prop_msg(T, [prop_parm(0x1e, 2, [I(1)]), prop_parm(0x22, 7, [I(1)])], 2, 14))
    # generic bearer: establish / modify / release (general cause, failure cause, reset), the BNC change event
    F.append(sig_msg(T, [signal(0x21, 1, []), signal(0x21, 2, [])], 2, 15))
    F.append(sig_msg(T, [signal(0x21, 3, [(b'\x00\x01', I(1 + k)) for k in range(6)] + [(b'\x00\x02', tlv(4, b'\x01\x02')),
                                                                                       (b'\x00\x03', tlv(1, b'\xff')),
                                                                                       (b'\x00\x03', tlv(1, b'\x00')),
                                                                                       (b'\x00\x09', I(1))])], 3, 16))
    F.append(evt_msg(T, [event(0x21, 1, [(b'\x00\x01', I(k))]) for k in range(1, 6)], 2, 17))
    # the tones with their direction
    F.append(sig_msg(T, [signal(0x23, 0x40 + k, [(b'\x00\x01', I(1 + k % 3))]) for k in range(10)] + [signal(0x23, 0x4a, [])], 2, 18))
    # bearer control tunnelling: BCTP in the tunnel indication event and in the Bearer Information Tunnel signal;
    # IPBCP (TPI 0x20) goes to SDP, other protocols to data
    for k, pdu in enumerate((bctp(0x20, BCTP_IPBCP[2:]), bctp(0x20, b'v=0\r\nc=IN IP4 192.0.2.5\r\nm=audio 4000 RTP/AVP 0\r\n'),
                             bctp(0x17, b'\x01\x02\x03'), bctp(0x23, b'text lines\r\n'), bctp(0x22, b''), bctp(0x20, b'', bvi=0x1f),
                             bctp(0x20, b'a=ipbcp:1 Accepted\r\n', bvei=1, tpei=1))):
        F.append(evt_msg(T, [event(0x22, 1, [(b'\x00\x01', tlv(4, pdu))])], 2 + k % 2, 20 + k))
        F.append(sig_msg(T, [signal(0x22, 1, [(b'\x00\x01', tlv(4, pdu))])], 2 + k % 2, 30 + k))
    # a tunnelled value that is not an octet string is shown as bytes
    F.append(evt_msg(T, [event(0x22, 1, [(b'\x00\x01', b'\x30\x02\x05\x00')])], 2, 40))
    F.append(sig_msg(T, [signal(0x22, 1, [(b'\x00\x01', b'\x02\x01\x07')])], 2, 41))
    # unknown ids of the packages
    F.append(sig_msg(T, [signal(0x22, 9, []), signal(0x21, 9, [(b'\x00\x01', I(1))])], 2, 42))
    F.append(evt_msg(T, [event(0x22, 9, []), event(0x21, 9, [(b'\x00\x05', I(1))])], 2, 43))
    return F


def bad():
    M = []
    ev = lambda v, eid=1: megaco([trx_req(1, [action(1, [command(6, term_list(T), A(1, tlv(0x80, b'\x09'),
                                  A(1, event(0x22, eid, [(b'\x00\x01', v)]))))])])])
    M.append(ev(tlv(4, b'')))                       # BCTP of no octets
    M.append(ev(tlv(4, b'\x01')))                   # BCTP of one octet
    M.append(ev(tlv(4, tlv(4, b'\x01\x20'))))
    M.append(ev(b''))
    M.append(megaco([trx_req(2, [action(1, [command(0, term_list(T), A(1, tlv(0xA5, signal(0x21, 3, [(b'\x00\x01', tlv(4, b'x'))]))))])])]))
    M.append(megaco([trx_req(3, [action(1, [command(0, term_list(T), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, prop_parm(0x1e, 1, [tlv(4, b'x')]))))))])])]))
    return M


if __name__ == '__main__':
    pkg_main(sys.argv[1] if len(sys.argv) > 1 else '.', 'h248_q1950', PK, specific, bad, 81, passes=3, nrand=60)
