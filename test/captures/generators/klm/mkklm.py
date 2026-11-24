#!/usr/bin/env python3
# Generates test/captures/klm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the KLM (Kernel Lock Manager, RPC program 100020 v1) captures.
Usage: mkklm.py <outdir>.  Writes klm-coverage.pcap and klm-coverage-malformed.pcap."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from _lib import Pcap

C, S = '192.0.2.10', '192.0.2.20'
xid = [0x1000]

def u32(*v): return b''.join(struct.pack('!I', x & 0xffffffff) for x in v)
def xstr(s):
    s = s if isinstance(s, bytes) else s.encode()
    return u32(len(s)) + s + b'\0' * (-len(s) % 4)
def fh(n, fill=0xab):  return u32(n) + bytes([fill]) * n + b'\0' * (-n % 4)

def lock(name='client1', fhl=32, pid=1234, off=0, ln=4096):
    return xstr(name) + fh(fhl) + u32(pid, off, ln)

def call(proc, args, x, vers=1, prog=100020):
    return u32(x, 0, 2, prog, vers, proc, 0, 0, 0, 0) + args
def reply(x, res):
    return u32(x, 1, 0, 0, 0, 0) + res

def rm(b):  # TCP record marking
    return struct.pack('!I', 0x80000000 | len(b)) + b

def mk_main(path):
    p = Pcap()
    def udp_pair(proc, a, r, sport=900):
        xid[0] += 1
        p.udp(C, S, sport, 4045, call(proc, a, xid[0]))
        p.udp(S, C, 4045, sport, reply(xid[0], r))
    # TEST: granted; denied with holder; denied exclusive
    udp_pair(1, u32(1) + lock(), u32(0))
    udp_pair(1, u32(0) + lock('client2', 8, 77, 100, 0), u32(1, 1, 4321, 10, 20))
    udp_pair(1, u32(1) + lock('', 64), u32(1, 0, 1, 0, 0xffffffff))
    udp_pair(1, u32(0) + lock('host', 4, 1, 0xffffffff, 1), u32(2))
    # LOCK: block/exclusive combinations and every status
    for blk, ex, st in ((1, 1, 0), (0, 1, 1), (1, 0, 2), (0, 0, 3)):
        udp_pair(2, u32(blk, ex) + lock(pid=blk * 2 + ex), u32(st))
    # CANCEL
    udp_pair(3, u32(1, 1) + lock(), u32(0))
    udp_pair(3, u32(0, 0) + lock('long-client-name.example.net', 36), u32(1))
    # UNLOCK
    udp_pair(4, lock(), u32(0))
    udp_pair(4, lock('c3', 12, 5, 6, 7), u32(3))
    # Status value that is not defined
    udp_pair(2, u32(1, 1) + lock(), u32(9))
    # Same over TCP with record marking
    for proc, a, r, k in ((1, u32(1) + lock(), u32(1, 1, 5, 6, 7), 0),
                          (2, u32(1, 0) + lock(), u32(0), 1),
                          (3, u32(0, 1) + lock(), u32(1), 2),
                          (4, lock(), u32(0), 3)):
        xid[0] += 1
        sp = 41800 + 17 * k; xid[0] += 0x1234
        p.tcp(C, S, sp, 4045, rm(call(proc, a, xid[0])))
        p.tcp(S, C, 4045, sp, rm(reply(xid[0], r)))
    p.write(path)

def mk_mal(path):
    p = Pcap()
    # truncated calls and replies (exceptions in each field)
    full = u32(1) + lock()
    for n in (0, 4, 8, 12, 16, 24, 40, 48, len(full) - 4):
        xid[0] += 1
        p.udp(C, S, 1901, 4045, call(1, full[:n], xid[0]))
    xid[0] += 1
    p.udp(C, S, 1901, 4045, call(2, (u32(1, 1) + lock())[:20], xid[0]))
    xid[0] += 1
    p.udp(C, S, 1901, 4045, call(4, lock()[:30], xid[0]))
    # Huge file handle length and a huge server name length
    xid[0] += 1
    p.udp(C, S, 1901, 4045, call(1, u32(1) + xstr('x') + u32(0x7fffffff, 1, 2, 3), xid[0]))
    xid[0] += 1
    p.udp(C, S, 1901, 4045, call(1, u32(1) + u32(0x7ffffff0) + b'abcd', xid[0]))
    # replies: truncated holder
    for n in (0, 4, 8, 12, 16):
        xid[0] += 1
        p.udp(C, S, 1902, 4045, call(1, u32(1) + lock(), xid[0]))
        p.udp(S, C, 4045, 1902, reply(xid[0], u32(1, 1, 2, 3, 4)[:n]))
    xid[0] += 1
    p.udp(C, S, 1902, 4045, call(2, u32(1, 1) + lock(), xid[0]))
    p.udp(S, C, 4045, 1902, reply(xid[0], b''))
    # Version 2 / unknown procedure of the program
    xid[0] += 1
    p.udp(C, S, 1903, 4045, call(1, b'', xid[0], vers=2))
    xid[0] += 1
    p.udp(C, S, 1903, 4045, call(9, b'', xid[0]))
    p.write(path)

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    mk_main(os.path.join(out, 'klm-coverage.pcap'))
    mk_mal(os.path.join(out, 'klm-coverage-malformed.pcap'))
