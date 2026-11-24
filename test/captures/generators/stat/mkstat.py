#!/usr/bin/env python3
# Generates test/captures/stat_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the STAT (NSM) coverage captures: mkstat.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
from c17lib import Cap, udp, rpc_call, rpc_reply, xstr

PROG = 100024
U32 = lambda *a: struct.pack('>%dI' % len(a), *a)

def my_id(host, prog=100021, vers=4, proc=16):
    return xstr(host) + U32(prog, vers, proc)

def mon_id(name, host):
    return xstr(name) + my_id(host)

def main(out, verbose):
    c = Cap(1)
    cl, sv = '192.0.2.10', '192.0.2.20'
    xid = [0]
    def rpc(proc, args=b'', res=None, reply=True, port=32765, cport=1019):
        xid[0] += 1
        c.add(udp(cport, port, rpc_call(xid[0], PROG, 1, proc, args), cl, sv))
        if reply:
            c.add(udp(port, cport, rpc_reply(xid[0], res if res is not None else b''), sv, cl))
    c.mark('NULL call and reply')
    rpc(0)
    c.mark('STAT calls with names of 1-8 octets and the results (success with state, failure)')
    for n in (1, 2, 3, 4, 5, 8):
        rpc(1, xstr(b'h' * n), U32(0, n))
    rpc(1, xstr(b''), U32(1, 0))
    c.mark('MON calls (name, my_id, 16 octets of private data) with the success and failure results')
    rpc(2, mon_id(b'client1.example.net', b'server.example.net') + bytes(range(16)), U32(0, 3))
    rpc(2, mon_id(b'a', b'b') + b'\xff' * 16, U32(1, 0))
    rpc(2, mon_id(b'', b'') + b'\0' * 16, U32(0, 5))
    c.mark('UNMON calls (mon_id) with the state reply')
    rpc(3, mon_id(b'client1.example.net', b'server.example.net'), U32(4))
    rpc(3, mon_id(b'abc', b'defgh'), U32(6))
    c.mark('UNMON_ALL calls (my_id) with the state reply')
    rpc(4, my_id(b'server.example.net'), U32(8))
    rpc(4, my_id(b'x', 7, 9, 11), U32(10))
    c.mark('SIMU_CRASH call and reply')
    rpc(5)
    c.mark('NOTIFY calls (name, state) and replies')
    rpc(6, xstr(b'client1.example.net') + U32(12))
    rpc(6, xstr(b'c') + U32(13))
    c.mark('Reproducer of the id length fix: names of 257 octets in MON and UNMON_ALL (the length rounding dropped the bits above 0xff)')
    rpc(2, mon_id(b'm' * 257, b'h' * 257) + bytes(range(16)), U32(0, 14))
    rpc(4, my_id(b'h' * 257), U32(15))
    rpc(3, mon_id(b'n' * 300, b'g' * 5), U32(16))
    c.mark('Calls on other UDP ports')
    rpc(1, xstr(b'second'), U32(0, 2), port=870, cport=1020)

    m = Cap(1)
    def mrpc(proc, args=b'', res=None):
        xid[0] += 1
        m.add(udp(1019, 32765, rpc_call(xid[0], PROG, 1, proc, args), cl, sv))
        if res is not None:
            m.add(udp(32765, 1019, rpc_reply(xid[0], res), sv, cl))
    m.mark('Truncated STAT, MON, UNMON, UNMON_ALL, NOTIFY and results; name lengths past the packet')
    mrpc(1, U32(100) + b'abc')
    mrpc(2, xstr(b'abc') + U32(1000) + b'x', b'\0\0\0\0')
    mrpc(2, mon_id(b'a', b'b') + b'\0' * 8)
    mrpc(3, U32(0xfffffff0))
    mrpc(3, xstr(b'abc') + xstr(b'abc') + U32(1, 2), b'')
    mrpc(4, U32(0x7ffffff0) + b'abcd')
    mrpc(6, xstr(b'abc'), b'')
    mrpc(1, xstr(b'abc'), U32(0))
    mrpc(1, xstr(b'abc'), U32(1))
    c.write(os.path.join(out, 'stat-coverage.pcap'))
    m.write(os.path.join(out, 'stat-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
