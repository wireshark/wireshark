#!/usr/bin/env python3
# Generates test/captures/h248_7_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-h248_7.c (H.248.7, Announcement package
"an", 0x001d: signals apf (Announcement Play Fixed, id 1) and apv
(Announcement Play Variable, id 2) with their parameters).
Usage: mkh248_7.py <outdir>
Writes h248_7-coverage.pcapng and h248_7-coverage-malformed.pcapng."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from h248common import (
    A, action, b4, ber_int, command, megaco, pkg_main, sig_msg, term_id, term_list, tlv, trx_req,
)

PK = [0x001d]
T = term_id(b'\x01\x02')


def signal(sid, pars):
    """A signal of the package with (parameter id, value TLV) pairs."""
    sp = [tlv(0x30, tlv(0x80, pid), tlv(0xA1, tlv(4, v))) for pid, v in pars]
    return tlv(0xA0, tlv(0x80, b4(0x1d, sid)), tlv(0xA6, *sp))


def specific(g, sw):
    F = []
    i = lambda v: tlv(2, ber_int(v))
    # apf: announcement name, cycles, variant, direction (ext, int, both and one that is not defined)
    for k, di in enumerate((1, 2, 3, 0)):
        F.append(sig_msg(T, [signal(1, [(b'\x00\x01', i(7 + k)), (b'\x00\x02', i(k)), (b'\x00\x03', tlv(4, b'variant%d' % k)),
                                         (b'\x00\x04', i(di))])], 2 + k % 2, 10 + k))
    # apv: all parameters, the specific parameters as an octet string (the fixed bug), the longer ids
    for k, (idl, sp) in enumerate(((2, b'abc'), (1, b''), (4, b'a,b;c=d'), (3, b'\x00\x01'))):
        n = lambda x: x.to_bytes(idl, 'big')
        F.append(sig_msg(T, [signal(2, [(n(1), i(100 + k)), (n(2), i(1)), (n(3), tlv(4, b'av')), (n(4), i(5)),
                                         (n(5), i(2)), (n(6), tlv(4, sp)), (n(7), i(1 + k % 3))])], 2 + k % 2, 20 + k))
    # a signal of the package that does not exist, an unknown parameter, a repeated parameter, no parameters
    F.append(sig_msg(T, [signal(3, [(b'\x00\x01', i(1))])], 2, 30))
    F.append(sig_msg(T, [signal(1, [(b'\x00\x09', i(1))])], 2, 31))
    F.append(sig_msg(T, [signal(2, [(b'\x00\x06', tlv(4, b'x')), (b'\x00\x06', tlv(4, b'y'))])], 2, 32))
    F.append(sig_msg(T, [signal(1, [])], 3, 33))
    # in a modify, in a second signal list, with a request id, in a version 1 message
    F.append(sig_msg(T, [signal(1, [(b'\x00\x01', i(3))]), signal(2, [(b'\x00\x01', i(4))])], 3, 34))
    F.append(sig_msg(T, [signal(2, [(b'\x00\x06', tlv(4, b'v1 sp'))])], 1, 35))
    return F


def bad():
    i = lambda v: tlv(2, ber_int(v))
    M = []
    # the integer specific parameters, which used to hit an assertion in the BER integer code
    M.append(megaco([trx_req(1, [action(1, [command(0, term_list(T), A(1, tlv(0xA5, signal(2, [(b'\x00\x06', i(5))]))))])])]))
    # announcement name and variant of the wrong type
    M.append(megaco([trx_req(2, [action(1, [command(0, term_list(T), A(1, tlv(0xA5, signal(1, [(b'\x00\x01', tlv(4, b'x')),
                                                                                              (b'\x00\x03', i(1)),
                                                                                              (b'\x00\x04', tlv(4, b'z'))]))))])])]))
    M.append(megaco([trx_req(3, [action(1, [command(0, term_list(T), A(1, tlv(0xA5, signal(1, [(b'\x00\x01', b'')]))))])])]))
    return M


if __name__ == '__main__':
    pkg_main(sys.argv[1] if len(sys.argv) > 1 else '.', 'h248_7', PK, specific, bad, 31)
