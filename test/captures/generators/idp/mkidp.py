#!/usr/bin/env python3
# Generates test/captures/idp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic IDP (XNS Internetwork Datagram Protocol) coverage
captures: Ethernet type 0x0600 and Cisco HDLC protocol 0x0600.
Usage: mkidp.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from c9lib import pcapng, eth

DST = bytes.fromhex('aa0000000002')
SRC = bytes.fromhex('aa0000000001')

def idp(ptype, payload, dsock=0x0bbc, ssock=0x1234, dnet=2, snet=1, hops=0,
        csum=0xffff, length=None):
    n = 30 + len(payload) if length is None else length
    return (struct.pack('>HHBBI', csum, n, hops, ptype, dnet) + DST
            + struct.pack('>HI', dsock, snet) + SRC + struct.pack('>H', ssock) + payload)

def spp(cc=0x40, dst_id=0x0100, src_id=0x0200, seq=1, ack=1, alloc=5, data=b''):
    return struct.pack('>BBHHHHH', cc, 0, src_id, dst_id, seq, ack, alloc) + data

frames = []
def ether(p, n=None):
    frames.append((0, eth(DST, SRC, 0x0600, p)))

ether(idp(1, b'RIP request payload', dsock=1, ssock=1))          # RIP, RIP sockets
ether(idp(2, b'echo request', dsock=2, ssock=0x4000))            # Echo
ether(idp(3, b'error packet', dsock=3, ssock=3))                 # Error
ether(idp(4, b'PEP data', dsock=5, ssock=5, hops=3))             # PEP, Courier
ether(idp(5, spp(0x40, data=b'spp data'), dsock=8))             # SPP, Time
ether(idp(5, spp(0xc0, seq=2), dsock=8))
ether(idp(6, b'pup lookup', dsock=9, ssock=9))                   # PUPLookup
ether(idp(0, b'type zero'))                                      # unknown packet type
ether(idp(255, b'unknown type', csum=0x1234, hops=15))
ether(idp(4, b'', dsock=0x0bbc, ssock=0xffff, dnet=0xffffffff, snet=0))   # empty payload
# datagram with trailing padding beyond the IDP length (Ethernet padding)
ether(idp(4, b'padded') + bytes(20))
# CHDLC: address 0x0f, control 0, protocol 0x0600
frames.append((1, bytes([0x0f, 0x00, 0x06, 0x00]) + idp(4, b'over cisco hdlc')))
pcapng(os.path.join(sys.argv[1], 'idp-coverage.pcapng'), [1, 104], frames)

frames = []
ether(idp(4, b'short length', length=20) )          # length shorter than the header
ether(idp(4, b'long length', length=500))           # length beyond the data
ether(idp(4, b'x')[:20])                            # header cut short
ether(idp(4, b'x')[:29])
ether(b'\x00' * 5)
ether(idp(5, b'\x40\x00')) # SPP cut short
frames.append((1, bytes([0x0f, 0x00, 0x06, 0x00]) + b'\x00' * 10))
pcapng(os.path.join(sys.argv[1], 'idp-coverage-malformed.pcapng'), [1, 104], frames)
