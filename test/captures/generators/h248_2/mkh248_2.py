#!/usr/bin/env python3
# Generates test/captures/h248_2_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-h248_2.c (H.248.2, Facsimile, Text
Conversation and Call Discrimination packages; the dissector registers the
Call Type Discrimination package "ctyp", 0x0011, with the event dtone
(Discriminating Tone Detected, id 1) and its observed tone type parameter).
Usage: mkh248_2.py <outdir>
Writes h248_2-coverage.pcapng and h248_2-coverage-malformed.pcapng."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from h248common import (
    A, action, action_reply, b4, ber_int, command, evt_msg, megaco, pkg_main, prop_msg, prop_parm,
    reply_cmd, sig_msg, term_id, term_list, tlv, trx_reply, trx_req, udp,
)

PK = [0x0011]
T = term_id(b'\x01\x02')


def event(eid, pars):
    ps = [tlv(0x30, tlv(0x80, pid), tlv(0xA1, tlv(4, v))) for pid, v in pars]
    return tlv(0x30, tlv(0x80, b4(0x11, eid)), tlv(0xA2, *ps))


def specific(g, sw):
    F = []
    i = lambda v: tlv(2, ber_int(v))
    # the tone types of the value list (CNG, V21flag ... V8BIS) and values outside of it
    for k, v in enumerate((1, 2, 3, 0x0b, 0x12, 0x17, 0x1b, 0x1c, 0x00, 0x99, 70000)):
        F.append(evt_msg(T, [event(1, [((1).to_bytes(1 + k % 4, 'big'), i(v))])], 2 + k % 2, 10 + k))
    # two parameters, no parameter, an unknown parameter, the event that is not in the table
    F.append(evt_msg(T, [event(1, [(b'\x00\x01', i(1)), (b'\x00\x01', i(2))])], 2, 30))
    F.append(evt_msg(T, [event(1, [])], 3, 31))
    F.append(evt_msg(T, [event(1, [(b'\x00\x07', i(1))])], 2, 32))
    F.append(evt_msg(T, [event(2, [(b'\x00\x01', i(1))])], 2, 33))
    F.append(evt_msg(T, [event(1, [(b'\x00\x01', i(1))]), event(2, []), event(3, [(b'\x00\x01', i(1))])], 3, 34))
    # requested events, a notification of version 1, a signal and a property of the package (it has none)
    req = tlv(0x30, tlv(0x80, b4(0x11, 1)))
    F.append(udp(megaco([trx_req(35, [action(0, [command(2, term_list(T), A(1, tlv(0xA3, tlv(0x80, b'\x07'), tlv(0xA1, req))))])])])))
    F.append(evt_msg(T, [event(1, [(b'\x00\x01', i(1))])], 1, 36))
    F.append(sig_msg(T, [tlv(0xA0, tlv(0x80, b4(0x11, 1)))], 2, 37))
    F.append(prop_msg(T, [prop_parm(0x11, 1, [tlv(4, b'\x01')])], 2, 38))
    # replies of the gateway
    F.append(udp(megaco([trx_reply(10, [action_reply(0, [reply_cmd(6, term_list(T))])])]), '192.0.2.2', 2945, '192.0.2.1', 2945))
    return F


def bad():
    M = []
    # a tone type that is not an integer, an empty one and an octet string
    for v in (tlv(4, b'x'), b'', tlv(2, b''), tlv(2, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09')):
        M.append(megaco([trx_req(1, [action(1, [command(6, term_list(T), A(1, tlv(0x80, b'\x09'),
                                   A(1, event(1, [(b'\x00\x01', v)]))))])])]))
    return M


if __name__ == '__main__':
    pkg_main(sys.argv[1] if len(sys.argv) > 1 else '.', 'h248_2', PK, specific, bad, 41)
