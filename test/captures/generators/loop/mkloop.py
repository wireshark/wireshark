#!/usr/bin/env python3
# Generates test/captures/loop_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the LOOP coverage captures. Usage: mkloop.py <outdir>

LOOP (Configuration Test Protocol, "loopback") is Ethernet ethertype
0x9000, registered by default.
"""
import os
import struct
import sys

def pcap(path, pkts, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def eth(payload, dst='020000000002', src='020000000001'):
    return bytes.fromhex(dst) + bytes.fromhex(src) + b'\x90\x00' + payload

def reply(n):
    return struct.pack('<HH', 1, n)

def fwd(addr):
    return struct.pack('<H', 2) + bytes.fromhex(addr)

def loop(skip, *funcs, tail=b''):
    return struct.pack('<H', skip) + b''.join(funcs) + tail

A1, A2, A3 = '0200000000aa', '0200000000bb', 'ffffffffffff'

def main(out):
    P = []
    # Reply as the first function, with and without trailing data
    P.append(loop(0, reply(0x0102)))
    P.append(loop(0, reply(0), tail=b'payload after the reply'))
    # Forward Data first: the relevant function is the forward
    P.append(loop(0, fwd(A1), reply(7)))
    # skipCount 8: the relevant function is the one after the first forward
    P.append(loop(8, fwd(A1), reply(8)))
    P.append(loop(8, fwd(A1), fwd(A2), reply(9)))
    # skipCount 16: after two forwards
    P.append(loop(16, fwd(A1), fwd(A2), reply(10), tail=b'\xde\xad\xbe\xef'))
    # A chain of forwards (the relevant function is the last)
    P.append(loop(8 * 9, *([fwd(A1)] * 9), reply(11)))
    # Unknown functions: relevant or not
    P.append(loop(0, struct.pack('<H', 0x1234) + b'\x00\x01'))
    P.append(loop(8, fwd(A1), struct.pack('<HH', 99, 5)))
    P.append(loop(0, struct.pack('<H', 0)))
    # skipCount that never meets a function boundary
    P.append(loop(1, reply(1)))
    P.append(loop(3, fwd(A1), reply(1)))
    P.append(loop(0x7fff, reply(12)))
    P.append(loop(0xffff, fwd(A2), reply(13)))
    # Frames to a broadcast and a multicast address, padded to 60 octets
    R = [eth(loop(0, reply(14)) + bytes(40), dst='ffffffffffff'),
         eth(loop(0, reply(15)) + bytes(40), dst='cf0000000000')]
    # Back to back replies (only the first is followed)
    P.append(loop(0, reply(1), tail=reply(2)))
    pkts = [eth(p) for p in P] + R
    pcap(os.path.join(out, 'loop-coverage.pcap'), pkts)
    bad = []
    bad.append(eth(b'\x00'))                                 # skipCount cut off
    bad.append(eth(b'\x00\x00'))                             # no function
    bad.append(eth(b'\x00\x00\x01'))                         # function cut off
    bad.append(eth(b'\x00\x00\x01\x00\x07'))                 # receipt number cut off
    bad.append(eth(b'\x00\x00\x02\x00\x01\x02\x03'))         # forwarding address cut off
    bad.append(eth(loop(0, fwd(A1))))                        # forward at the end, no next function
    bad.append(eth(loop(0, fwd(A1), fwd(A2))))
    bad.append(eth(loop(0, fwd(A1), fwd(A2))[:-2]))
    bad.append(eth(loop(16, fwd(A1), fwd(A2), fwd(A3))))     # chain ends at a forward
    pcap(os.path.join(out, 'loop-coverage-malformed.pcap'), bad)
    print(len(pkts), len(bad))

main(sys.argv[1])
