#!/usr/bin/env python3
# Generates test/captures/icp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic ICP (Internet Cache Protocol) coverage captures
(UDP 3130). Usage: mkicp.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
from c9lib import pcap, udp_frame

C, S = '192.0.2.10', '192.0.2.20'
frames = []

def icp(op, payload, nr=1, opts=0, opt_data=0, ver=2, sender='192.0.2.10', length=None):
    n = 20 + len(payload) if length is None else length
    return (struct.pack('>BBHIII', op, ver, n, nr, opts, opt_data)
            + socket.inet_aton(sender) + payload)

def send(p, src=C, dst=S, sp=3130, dp=3130):
    frames.append(udp_frame(src, dst, sp, dp, p, len(frames) + 1))

URL = b'http://example.org/index.html\0'
REQ = socket.inet_aton('192.0.2.99')
# queries: plain, with HIT_OBJ, with SRC_RTT, with both
send(icp(1, REQ + URL, 1))
send(icp(1, REQ + URL, 2, opts=0x80000000))
send(icp(1, REQ + URL, 3, opts=0x40000000))
send(icp(1, REQ + URL, 4, opts=0xc0000000))
# replies without and with SRC_RTT (RTT field)
for nr, op in enumerate((2, 3, 4, 10, 11, 21, 22), 5):
    send(icp(op, URL, nr), src=S, dst=C, sp=3130, dp=3130)
send(icp(2, URL, 12, opts=0x40000000, opt_data=0x00000000), src=S, dst=C)
send(icp(3, URL, 13, opts=0x40000000, opt_data=0x0000002a), src=S, dst=C)
# opcodes without payload decoding
for nr, op in enumerate((0, 5, 6, 7, 8, 9, 99), 14):
    send(icp(op, b'opaque', nr), src=S, dst=C)
# HIT_OBJ: complete object, an empty one (an object longer than the packet
# throws before the 'fragmented packet' warning: malformed capture)
obj = bytes(range(32))
send(icp(23, URL + struct.pack('>H', len(obj)) + obj, 21), src=S, dst=C)
send(icp(23, URL + struct.pack('>H', 0), 23), src=S, dst=C)
# other source port (ICP is on 3130 on the cache side only)
send(icp(1, REQ + URL, 24), sp=40000)
# version 3, odd sender, length field shorter than the packet
send(icp(1, REQ + URL, 25, ver=3, sender='0.0.0.0'))
send(icp(2, URL, 26, length=32), src=S, dst=C)
pcap(os.path.join(sys.argv[1], 'icp-coverage.pcap'), frames)

frames = []
send(icp(1, REQ + URL, 1)[:12])                      # cut inside the header
send(icp(1, REQ + URL, 2)[:19])                      # cut before the sender address
send(icp(1, REQ + URL, 3)[:22])                      # cut inside the requester address
send(icp(1, REQ + b'no terminator', 4))              # URL without NUL
send(icp(2, b'no terminator', 5))
send(icp(23, URL, 6))                                # HIT_OBJ without object length
send(icp(23, URL + b'\x00', 7))
send(icp(23, b'no terminator', 8))
send(icp(2, URL, 9, length=10))                      # length shorter than the header
send(icp(2, URL, 10, length=0))
send(icp(23, URL + struct.pack('>H', 1000) + bytes(range(32)), 12), src=S, dst=C)
send(b'\x01')                                        # one octet
pcap(os.path.join(sys.argv[1], 'icp-coverage-malformed.pcap'), frames)
