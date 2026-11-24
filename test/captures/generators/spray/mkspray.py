#!/usr/bin/env python3
# Generates test/captures/spray_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SPRAY coverage captures: mkspray.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
from c17lib import Cap, udp, rpc_call, rpc_reply

PROG = 100012

def main(out, verbose):
    c = Cap(1)
    cl, sv = '192.0.2.10', '192.0.2.20'
    def call(xid, proc, args=b'', sport=1021):
        c.add(udp(sport, 32767, rpc_call(xid, PROG, 1, proc, args), cl, sv))
    def reply(xid, res=b'', sport=1021):
        c.add(udp(32767, sport, rpc_reply(xid, res), sv, cl))
    c.mark('NULL call and reply')
    call(1, 0); reply(1)
    c.mark('SPRAY calls with 0, 1, 7 and 1400 octets of data, and the replies')
    for i, n in enumerate((0, 1, 7, 1400)):
        call(2 + i, 1, struct.pack('>I', n) + bytes((j * 7) & 255 for j in range(n)) + b'\0' * ((4 - n % 4) % 4))
        reply(2 + i)
    c.mark('GET call and reply with counter and clock')
    call(10, 2); reply(10, struct.pack('>III', 1000000, 1700000000, 123456))
    c.mark('CLEAR call and reply')
    call(11, 3); reply(11)
    c.mark('Second client, call without a reply and a reply with a different xid')
    call(12, 2, sport=1022)
    reply(99, struct.pack('>III', 1, 2, 3), sport=1022)
    m = Cap(1)
    def mcall(xid, proc, args=b''):
        m.add(udp(1021, 32767, rpc_call(xid, PROG, 1, proc, args), cl, sv))
    m.mark('SPRAY call whose data length runs past the packet, truncated GET reply')
    mcall(1, 1, struct.pack('>I', 500) + b'abc')
    m.add(udp(32767, 1021, rpc_reply(1, b'\0\0\0\1\0\0'), sv, cl))
    mcall(2, 2)
    m.add(udp(32767, 1021, rpc_reply(2, b'\0\0\0\1\0\0'), sv, cl))
    c.write(os.path.join(out, 'spray-coverage.pcap'))
    m.write(os.path.join(out, 'spray-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
