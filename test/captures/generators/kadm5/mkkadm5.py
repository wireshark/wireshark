#!/usr/bin/env python3
# Generates test/captures/kadm5_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the kadm5 coverage captures: mkkadm5.py <outdir>.

kadm5 (Kerberos administration, ONC RPC program 2112 version 2) is
reached through the RPC dissector: TCP (record marking) and UDP calls
and replies whose program number is 2112. The procedure arguments and
results are placeholder bytes; nothing is authenticated or encrypted.
Writes kadm5-coverage.pcap and kadm5-coverage-malformed.pcap.
"""
import os
import struct
import sys
from pylib import Pcap, Tcp, eth_udp

PROG = 2112
PORT = 749

def opaque(b):
    return struct.pack('>I', len(b)) + b + bytes((-len(b)) % 4)

def call(xid, proc, args=b'', vers=2, prog=PROG, cred=(0, b''), verf=(0, b'')):
    return (struct.pack('>IIIIII', xid, 0, 2, prog, vers, proc) +
            struct.pack('>I', cred[0]) + opaque(cred[1]) +
            struct.pack('>I', verf[0]) + opaque(verf[1]) + args)

def reply(xid, res=b'', accept=0, verf=(0, b'')):
    return (struct.pack('>III', xid, 1, 0) + struct.pack('>I', verf[0]) +
            opaque(verf[1]) + struct.pack('>I', accept) + res)

def rm(pdu):
    return struct.pack('>I', 0x80000000 | len(pdu)) + pdu

def args(n):
    return bytes(range(n))

def main(out):
    p = Pcap()
    t = Tcp(p, sport=51749, dport=PORT)
    t.seg(b'', True, 0x02)
    t.seg(b'', False, 0x12)
    t.seg(b'', True, 0x10)
    # 4-47: every procedure of the version 2 table, call and reply
    for proc in range(22):
        xid = 0x1000 + proc
        t.seg(rm(call(xid, proc, b'' if proc == 0 else opaque(args(8 + proc)))), True)
        t.seg(rm(reply(xid, b'' if proc == 0 else struct.pack('>I', 0) + opaque(args(4)))), False)
    # 48-51: a procedure number the table does not have, and a call
    # with AUTH_UNIX credentials (stamp, machine name, uid, gid, no gids)
    t.seg(rm(call(0x2000, 22, opaque(args(4)))), True)
    t.seg(rm(reply(0x2000, b'', accept=3)), False)             # PROC_UNAVAIL
    unix = struct.pack('>I', 1234) + opaque(b'client1') + struct.pack('>III', 0, 0, 0)
    t.seg(rm(call(0x2001, 5, opaque(args(12)), cred=(1, unix))), True)
    t.seg(rm(reply(0x2001, opaque(args(20)))), False)
    # 52-55: two calls in one segment, and a reply split in two segments
    t.seg(rm(call(0x2002, 14, opaque(b'*'))) + rm(call(0x2003, 15, opaque(b'*'))), True)
    r = rm(reply(0x2002, opaque(args(40))))
    t.seg(r[:24], False)
    t.seg(r[24:] + rm(reply(0x2003, opaque(args(8)))), False)
    # UDP calls and replies (RPC over UDP is recognised by its structure)
    def udp(data, rev=False):
        sp, dp = (PORT, 40749) if rev else (40749, PORT)
        p.add(eth_udp(sp, dp, data, rev=rev))
    udp(call(0x3000, 0))
    udp(reply(0x3000), rev=True)
    udp(call(0x3001, 13, opaque(args(16))))
    udp(reply(0x3001, opaque(args(16))), rev=True)
    udp(call(0x3002, 21, opaque(args(24))))
    udp(reply(0x3002, struct.pack('>I', 0), accept=0), rev=True)
    t.seg(b'', True, 0x11)
    p.write(os.path.join(out, 'kadm5-coverage.pcap'))

    m = Pcap()
    mt = Tcp(m, sport=51750, dport=PORT)
    mt.seg(b'', True, 0x02)
    mt.seg(b'', False, 0x12)
    mt.seg(b'', True, 0x10)
    c = call(0x4000, 3, opaque(args(8)))
    mt.seg(rm(c[:30]), True)                      # call cut in the credentials
    mt.seg(rm(call(0x4001, 9, args(3))), True)    # arguments not a multiple of 4
    mt.seg(rm(reply(0x4001, b'\x00\x00')), False)
    mt.seg(rm(call(0x4002, 1, vers=3)), True)     # version the program does not have
    mt.seg(rm(reply(0x4002, b'', accept=2)), False)
    m.write(os.path.join(out, 'kadm5-coverage-malformed.pcap'))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
