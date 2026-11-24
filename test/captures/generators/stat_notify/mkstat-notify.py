#!/usr/bin/env python3
# Generates test/captures/stat_notify_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the STAT-CB (NSM callback) coverage captures: mkstat-notify.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
from c17lib import Cap, udp, rpc_call, rpc_reply, xstr

PROG = 200048
U32 = lambda *a: struct.pack('>%dI' % len(a), *a)

def main(out, verbose):
    c = Cap(1)
    cl, sv = '192.0.2.20', '192.0.2.10'
    xid = [0]
    def rpc(proc, args=b'', port=32770, reply=True):
        xid[0] += 1
        c.add(udp(1019, port, rpc_call(xid[0], PROG, 1, proc, args), cl, sv))
        if reply:
            c.add(udp(port, 1019, rpc_reply(xid[0]), sv, cl))
    c.mark('NULL call and reply')
    rpc(0)
    c.mark('MON-CALLBACK calls (name, state, 16 octets of private data) with names of 0-9 octets, and replies')
    for n in (0, 1, 2, 3, 4, 5, 9):
        rpc(1, xstr(b'h' * n) + U32(100 + n) + bytes((n * 16 + i) & 255 for i in range(16)))
    rpc(1, xstr(b'client1.example.net') + U32(7) + b'\xff' * 16, port=870)
    m = Cap(1)
    def mrpc(args, reply=True):
        xid[0] += 1
        m.add(udp(1019, 32770, rpc_call(xid[0], PROG, 1, 1, args), cl, sv))
    m.mark('Name past the packet, missing state and private data cut short')
    mrpc(U32(500) + b'abc')
    mrpc(xstr(b'abc'))
    mrpc(xstr(b'abc') + U32(1) + b'\0' * 7)
    c.write(os.path.join(out, 'stat-notify-coverage.pcap'))
    m.write(os.path.join(out, 'stat-notify-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
