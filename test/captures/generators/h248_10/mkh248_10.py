#!/usr/bin/env python3
# Generates test/captures/h248_10_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-h248_10.c (H.248.10, Media Gateway
Resource Congestion Handling package "chp", 0x0029).  The package has one
event, MGCon (id 1), with the parameter "reduction" (id 1, an integer).
Usage: mkh248_10.py <outdir>

Writes h248_10-coverage.pcapng (binary H.248 on UDP 2945, registered by
default) and h248_10-coverage-malformed.pcapng.  The helpers are shared
with mkh248.py (h248common.py, h248lib.py)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from h248common import (
    A, action, action_reply, b4, ber_int, command, megaco, newgen, pcapng, pkg_sweep, prop_parm,
    reply_cmd, Sweep, term_id, term_list, tlv, trx_reply, trx_req, udp,
)

PK = [0x0029]


def main(out):
    frames = []
    marks = {}

    def add(name, fr):
        marks[name] = (len(frames) + 1, len(frames) + len(fr))
        frames.extend(fr)

    sw = Sweep(pkgs=PK)
    g = newgen(21, sw)
    g1 = newgen(22, sw, v1=True)
    t = term_id(b'\x01\x02')
    # MGCon notifications with the reduction parameter, versions 2 and 3,
    # parameter id lengths 1 to 4, several values, none and two parameters
    F = []
    for k, (ver, idl, red) in enumerate([(2, 2, 0), (3, 1, 10), (2, 4, 50), (3, 3, 100), (2, 2, 255), (3, 2, 70000)]):
        pid = (1).to_bytes(idl, 'big')
        par = tlv(0x30, tlv(0x80, pid), tlv(0xA1, tlv(4, tlv(2, ber_int(red)))))
        ev = tlv(0x30, tlv(0x80, b4(0x29, 1)), tlv(0xA2, par))
        obs = A(1, tlv(0x80, bytes([k + 1])), A(1, ev))
        F.append(udp(megaco([trx_req(10 + k, [action(0, [command(6, term_list(t), obs)])])], ver)))
    # reply to the notification, an event without parameters, an unknown parameter
    F.append(udp(megaco([trx_reply(10, [action_reply(0, [reply_cmd(6, term_list(t))])])]), '192.0.2.2', 2945, '192.0.2.1', 2945))
    ev = tlv(0x30, tlv(0x80, b4(0x29, 1)), tlv(0xA2))
    obs = A(1, tlv(0x80, b'\x07'), A(1, ev))
    F.append(udp(megaco([trx_req(20, [action(0, [command(6, term_list(t), obs)])])])))
    par = tlv(0x30, tlv(0x80, b'\x00\x09'), tlv(0xA1, tlv(4, tlv(2, b'\x01'))))
    ev = tlv(0x30, tlv(0x80, b4(0x29, 1)), tlv(0xA2, par))
    F.append(udp(megaco([trx_req(21, [action(0, [command(6, term_list(t), A(1, tlv(0x80, b'\x08'), A(1, ev)))])])])))
    # an unknown event of the package, and a property / signal name of the package (no entries)
    ev = tlv(0x30, tlv(0x80, b4(0x29, 9)), tlv(0xA2, par))
    F.append(udp(megaco([trx_req(22, [action(0, [command(6, term_list(t), A(1, tlv(0x80, b'\x08'), A(1, ev)))])])])))
    F.append(udp(megaco([trx_req(23, [action(0, [command(0, term_list(t), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, prop_parm(0x29, 0, [tlv(4, b'\x01')])))), tlv(0xA5, tlv(0xA0, tlv(0x80, b4(0x29, 1))))))])])])))
    # the events descriptor requesting MGCon
    req = tlv(0x30, tlv(0x80, b4(0x29, 1)))
    F.append(udp(megaco([trx_req(24, [action(0, [command(2, term_list(t), A(1, tlv(0xA3, tlv(0x80, b'\x07'), tlv(0xA1, req))))])])])))
    add('mgcon', F)
    add('sweep', pkg_sweep(PK, passes=2))
    sw.q = {k: [] for k in sw.q}
    # messages made from the ASN.1 module with this package in descriptors
    R = []
    for i in range(45):
        sw.version = [2, 3][i % 2]
        g.mode = ['full', 'mix', 'full', 'min'][i % 4]
        R.append(udp(megaco([g.make_alt('Transaction', i % 5)], sw.version)))
    for i in range(10):
        g1.mode = ['full', 'mix'][i % 2]
        R.append(udp(megaco([g1.make_alt('Transaction', [2, 0][i % 2])], 1)))
    add('random', R)
    for k, v in marks.items():
        print('%-8s frames %d-%d' % (k, v[0], v[1]))
    pcapng(os.path.join(out, 'h248_10-coverage.pcapng'), frames)
    # malformed: mutations of the main capture, a truncated event, a non-integer value
    base = [f[1][42:] for f in frames if f[0] == 0][::2]
    import random
    rnd = random.Random(10)
    M = []
    par = tlv(0x30, tlv(0x80, b'\x00\x01'), tlv(0xA1, tlv(4, b'\x30\x00')))
    ev = tlv(0x30, tlv(0x80, b4(0x29, 1)), tlv(0xA2, par))
    M.append(megaco([trx_req(30, [action(0, [command(6, term_list(t), A(1, tlv(0x80, b'\x08'), A(1, ev)))])])]))
    par = tlv(0x30, tlv(0x80, b'\x00\x01'), tlv(0xA1, tlv(4, b'')))
    ev = tlv(0x30, tlv(0x80, b4(0x29, 1)), tlv(0xA2, par))
    M.append(megaco([trx_req(31, [action(0, [command(6, term_list(t), A(1, tlv(0x80, b'\x08'), A(1, ev)))])])]))
    for i in range(60):
        p = bytearray(rnd.choice(base))
        if i % 3 == 0:
            p = p[:rnd.randrange(2, len(p))]
        elif i % 3 == 1:
            p[rnd.randrange(len(p))] = rnd.randrange(256)
        else:
            for _ in range(3):
                p[rnd.randrange(len(p))] = rnd.choice([0x00, 0x04, 0x30, 0x80, 0xa0, 0xff])
        M.append(bytes(p))
    pcapng(os.path.join(out, 'h248_10-coverage-malformed.pcapng'), [udp(p, '192.0.2.41', 2945, '192.0.2.42', 2945) for p in M])
    print('malformed frames', len(M))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
