#!/usr/bin/env python3
# Generates test/captures/sadmind_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SADMIND coverage captures. Usage: mksadmind.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from pcaplib import Pcap, TcpStream, udp_frame
from rpclib import call, flavor, rec, reply, u, xstr

PROG = 100232
UP = 32790
TP = 32791

def main(out):
    p = Pcap()
    xid = [0x4000]
    def nx():
        xid[0] += 1
        return xid[0]
    def uex(vers, proc, args=b'', res=b'', cred=u(0, 0)):
        x = nx()
        p.add(udp_frame(call(x, PROG, vers, proc, args, cred), 901, UP))
        p.add(udp_frame(reply(x, res), UP, 901, '10.0.0.2', '10.0.0.1', 2, 1))
    # 1-6: NULL of versions 1, 2 and 3 over UDP
    for v in (1, 2, 3):
        uex(v, 0)
    # 7-8: AUTH_UNIX credentials
    uex(3, 0, cred=flavor(1, u(1) + xstr('host1') + u(0, 0, 0)))
    # 9-12: procedures that are not defined (shown as data), unknown version
    uex(1, 1, u(1, 2, 3, 4), u(0))
    uex(3, 7, xstr('some argument'), u(0))
    uex(4, 0)
    # 13-14: PROG_MISMATCH and PROC_UNAVAIL replies
    x = nx()
    p.add(udp_frame(call(x, PROG, 5, 0), 901, UP))
    p.add(udp_frame(reply(x, u(1, 3), accept=2), UP, 901, '10.0.0.2', '10.0.0.1', 2, 1))
    x = nx()
    p.add(udp_frame(call(x, PROG, 3, 9), 901, UP))
    p.add(udp_frame(reply(x, accept=3), UP, 901, '10.0.0.2', '10.0.0.1', 2, 1))
    # TCP
    t = TcpStream(p, 1022, TP)
    for v in (1, 2, 3):
        x = nx()
        t.c(rec(call(x, PROG, v, 0)))
        t.s(rec(reply(x)))
    t.fin()
    p.write(os.path.join(out, 'sadmind-coverage.pcap'))

    m = Pcap()
    # call truncated inside the credentials, and reply truncated
    x = nx()
    m.add(udp_frame(call(x, PROG, 3, 0)[:30], 901, UP))
    m.add(udp_frame(reply(x)[:10], UP, 901, '10.0.0.2', '10.0.0.1', 2, 1))
    m.write(os.path.join(out, 'sadmind-coverage-malformed.pcap'))

main(sys.argv[1])
