#!/usr/bin/env python3
# Generates test/captures/h248_annex_e_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-h248_annex_e.c (H.248.1 Annex E, the
standard packages: generic 0x0001, tonegen 0x0003, tonedet 0x0004, dg
0x0005, cg 0x0007, cd 0x0008, al 0x0009, ct 0x000a, nt 0x000b, rtp 0x000c
and tdmc 0x000d; the root 0x0002 and dd 0x0006 packages are defined in the
file but not registered).  Usage: mkh248_annex_e.py <outdir>
Writes h248_annex_e-coverage.pcapng and h248_annex_e-coverage-malformed.pcapng."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from h248common import (
    A, action, b4, ber_int, command, evt_msg, megaco, pkg_main, prop_msg, prop_parm, sig_msg,
    struct, term_id, term_list, tlv, trx_req, udp, UNREGISTERED,
)

PK = [p for p in range(1, 14) if p not in UNREGISTERED]
T = term_id(b'\x01\x02')
I = lambda v: tlv(2, ber_int(v))


def event(pkg, eid, pars):
    ps = [tlv(0x30, tlv(0x80, pid), tlv(0xA1, tlv(4, v))) for pid, v in pars]
    return tlv(0x30, tlv(0x80, b4(pkg, eid)), tlv(0xA2, *ps))


def signal(pkg, sid, pars):
    sp = [tlv(0x30, tlv(0x80, pid), tlv(0xA1, tlv(4, v))) for pid, v in pars]
    return tlv(0xA0, tlv(0x80, b4(pkg, sid)), tlv(0xA6, *sp))


def specific(g, sw):
    F = []
    # generic package: the cause event and the service change event, with and without parameters
    F.append(evt_msg(T, [event(1, 1, [(b'\x00\x01', I(1)), (b'\x00\x02', tlv(4, b'text'))])], 2, 10))
    for k, (pk, mt) in enumerate(((1, 0), (3, 1), (5, 2), (0x7777, 3))):
        F.append(evt_msg(T, [event(1, 2, [(b'\x00\x01', tlv(4, struct.pack('>HH', pk, k))), (b'\x00\x02', I(mt)),
                                           (b'\x00\x03', I(900 + k)), (b'\x00\x04', I(10))])], 2 + k % 2, 11 + k))
    F.append(evt_msg(T, [event(1, 3, [(b'\x00\x01', I(1))]), event(1, 1, [])], 3, 15))
    # tone generation: play tone with several parameters, tone detection events
    F.append(sig_msg(T, [signal(3, 1, [(b'\x00\x01', I(5)), (b'\x00\x02', I(100)), (b'\x00\x03', I(1))])], 2, 16))
    F.append(evt_msg(T, [event(4, 1, [(b'\x00\x01', I(0)), (b'\x00\x02', I(3)), (b'\x00\x03', I(20))]),
                         event(4, 2, [(b'\x00\x01', I(7))]), event(4, 3, [(b'\x00\x01', I(7))])], 2, 17))
    # alerting line, call progress generation / detection, the root and dd packages that are not registered
    F.append(evt_msg(T, [event(9, 4, [(b'\x00\x01', I(1)), (b'\x00\x02', tlv(1, b'\xff'))]),
                         event(9, 5, [(b'\x00\x01', I(2)), (b'\x00\x02', tlv(1, b'\x00'))]), event(9, 6, [(b'\x00\x01', I(3))])], 2, 18))
    F.append(sig_msg(T, [signal(9, 2, [(b'\x00\x06', tlv(4, b'\x0a\x0b'))])], 2, 19))
    F.append(sig_msg(T, [signal(7, 1, [(b'\x00\x01', I(1)), (b'\x00\x02', I(1)), (b'\x00\x03', I(1))])], 3, 20))
    F.append(evt_msg(T, [event(8, 1, [(b'\x00\x01', I(1))])], 2, 21))
    F.append(prop_msg(T, [prop_parm(2, 1, [I(1)]), prop_parm(2, 7, [I(3)])], 2, 22))
    F.append(evt_msg(T, [event(6, 1, [(b'\x00\x01', I(1))])], 2, 23))
    F.append(prop_msg(T, [prop_parm(0x0d, 8, [tlv(1, b'\xff')]), prop_parm(0x0d, 0x0a, [I(2)]), prop_parm(0x0d, 9, [I(1)])], 2, 24))
    # statistics of rtp, the packages ct and nt (no entries), unknown ids of the packages
    st = [tlv(0x30, tlv(0x80, b4(0x0c, 4)), tlv(0xA1, tlv(4, b'\x01\x02'))), tlv(0x30, tlv(0x80, b4(0x0c, 9))),
          tlv(0x30, tlv(0x80, b4(0x0a, 1))), tlv(0x30, tlv(0x80, b4(0x0b, 1)))]
    F.append(udp(megaco([trx_req(25, [action(0, [command(1, term_list(T), A(1, tlv(0xA8, *st)))])])])))
    F.append(evt_msg(T, [event(0x0a, 1, [(b'\x00\x01', I(1))]), event(0x0b, 1, []), event(5, 9, [])], 2, 26))
    F.append(sig_msg(T, [signal(5, 0x7f, [(b'\x00\x01', I(1))]), signal(0x0a, 1, []), signal(3, 1, [(b'\x00\x09', I(1))])], 2, 27))
    return F


def bad():
    M = []
    bad_ev = lambda pkg, eid, v: megaco([trx_req(1, [action(1, [command(6, term_list(T), A(1, tlv(0x80, b'\x09'),
                                         A(1, event(pkg, eid, [(b'\x00\x01', v)]))))])])])
    M.append(bad_ev(1, 1, tlv(4, b'x')))                 # the cause is not an integer
    M.append(bad_ev(1, 2, tlv(4, b'\x00')))              # the package name is only one octet
    M.append(bad_ev(1, 2, tlv(2, b'\x01')))
    M.append(bad_ev(4, 1, tlv(1, b'\xff')))
    M.append(bad_ev(9, 4, b''))
    M.append(megaco([trx_req(2, [action(1, [command(0, term_list(T), A(1, tlv(0xA5, signal(7, 1, [(b'\x00\x02', tlv(2, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09'))]))))])])]))
    return M


if __name__ == '__main__':
    pkg_main(sys.argv[1] if len(sys.argv) > 1 else '.', 'h248_annex_e', PK, specific, bad, 71, passes=3, nrand=60)
