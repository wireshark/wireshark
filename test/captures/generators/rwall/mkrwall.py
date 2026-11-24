#!/usr/bin/env python3
# Generates test/captures/rwall_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RWALL coverage captures. Usage: mkrwall.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from pcaplib import Pcap, TcpStream, udp_frame
from rpclib import call, flavor, rec, reply, u, xstr

PROG = 100008
UP = 32780          # UDP server port (found by the RPC heuristic)
TP = 32781          # TCP server port

def main(out):
    p = Pcap()
    xid = [0x3000]
    def nx():
        xid[0] += 1
        return xid[0]
    def uex(vers, proc, args=b'', res=b'', cred=u(0, 0)):
        x = nx()
        p.add(udp_frame(call(x, PROG, vers, proc, args, cred), 900, UP))
        p.add(udp_frame(reply(x, res), UP, 900, '10.0.0.2', '10.0.0.1', 2, 1))
    # 1-2: NULL procedure of version 1 (not in the table)
    uex(1, 0)
    # 3-12: WALL calls: empty, 1..5 octets, ordinary text, unprintable octets, long text
    for m in ('', 'x', 'xy', 'xyz', 'wxyz', 'vwxyz',
              'The system will go down for maintenance in 5 minutes.\n',
              'bell\x07 and \x01\xfe octets', 'A' * 400):
        uex(1, 2, xstr(m))
    # 21-22: AUTH_UNIX credentials with the call
    uex(1, 2, xstr('Broadcast from root'), cred=flavor(1, u(1) + xstr('host1') + u(0, 0, 0)))
    # 23-: unknown procedure and unknown version
    uex(1, 5, u(1, 2, 3))
    uex(2, 2, xstr('version 2'))
    # PROG_MISMATCH reply
    x = nx()
    p.add(udp_frame(call(x, PROG, 3, 2, xstr('v3')), 900, UP))
    p.add(udp_frame(reply(x, u(1, 1), accept=2), UP, 900, '10.0.0.2', '10.0.0.1', 2, 1))
    # TCP: two calls and replies with record marking
    t = TcpStream(p, 1023, TP)
    for m in ('over TCP', 'second message'):
        x = nx()
        t.c(rec(call(x, PROG, 1, 2, xstr(m))))
        t.s(rec(reply(x)))
    # two calls in one segment
    x1, x2 = nx(), nx()
    t.c(rec(call(x1, PROG, 1, 2, xstr('first in segment'))) + rec(call(x2, PROG, 1, 2, xstr('second in segment'))))
    t.s(rec(reply(x1)) + rec(reply(x2)))
    p.write(os.path.join(out, 'rwall-coverage.pcap'))

    m = Pcap()
    # message string longer than the data present
    x = nx()
    m.add(udp_frame(call(x, PROG, 1, 2, u(200) + b'short'), 900, UP))
    # call without arguments
    x = nx()
    m.add(udp_frame(call(x, PROG, 1, 2, b''), 900, UP))
    # call with a string length of 0xffffffff
    x = nx()
    m.add(udp_frame(call(x, PROG, 1, 2, u(0xffffffff) + b'abcd'), 900, UP))
    m.write(os.path.join(out, 'rwall-coverage-malformed.pcap'))

main(sys.argv[1])
