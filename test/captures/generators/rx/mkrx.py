#!/usr/bin/env python3
# Generates test/captures/rx_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RX coverage captures. Usage: mkrx.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pcaplib import Pcap, udp_frame
from rpclib import u

CL, SV = '10.0.0.1', '10.0.0.2'
EPOCH = 0x5f000000

DATA, ACK, BUSY, ABORT, ACKALL, CHALLENGE, RESPONSE, DEBUG, PARAMS, VERSION = 1, 2, 3, 4, 5, 6, 7, 8, 9, 13
F_CLIENT, F_REQACK, F_LAST, F_MORE, F_FREE = 1, 2, 4, 8, 16   # flag bits as the dissector shows them

def hdr(typ, flags=0, cid=0x100, call=1, seq=1, serial=1, user=0, sec=0, spare=0, svc=1, epoch=EPOCH):
    return struct.pack('>IIIIIBBBBHH', epoch, cid, call, seq, serial, typ, flags, user, sec, spare, svc)

class Cap:
    def __init__(self):
        self.p = Pcap()
    def rx(self, payload, to_server=True, sport=7001, cport=7001):
        if to_server:
            self.p.add(udp_frame(payload, cport, sport, CL, SV, 1, 2))
        else:
            self.p.add(udp_frame(payload, sport, cport, SV, CL, 2, 1))

def acks(bufspace=64, skew=0, first=1, prev=1, serial=5, reason=1, types=(), extra=b''):
    return struct.pack('>HHIIIBB', bufspace, skew, first, prev, serial, reason, len(types)) + bytes(types) + extra

def main(out):
    c = Cap()
    # ---- DATA: AFS payloads (the AFS dissector gets them with the RX info)
    # fs service (1) FetchStatus (130) call and reply, vldb (52), bos(73)
    c.rx(hdr(DATA, F_CLIENT | F_REQACK | F_LAST, 0x104, 1, 1, 1, svc=1) + u(130, 1, 2, 3))
    c.rx(hdr(DATA, F_LAST, 0x104, 1, 1, 2, svc=1) + u(0, 1, 2, 3, 4, 5, 6, 7, 8), to_server=False)
    c.rx(hdr(DATA, F_CLIENT | F_MORE | F_FREE, 0x104, 2, 1, 3, svc=1) + u(131, 7, 8, 9))
    c.rx(hdr(DATA, F_CLIENT | F_LAST, 0x108, 1, 1, 4, svc=52) + u(510, 0, 0), sport=7003)
    c.rx(hdr(DATA, 0, 0x10c, 1, 2, 5, svc=73) + u(0, 1))
    c.rx(hdr(DATA, 0xff, 0x110, 3, 1, 6, user=7, sec=2, spare=0x1234, svc=7) + u(1, 2, 3))
    # ---- ACK: every reason, with and without acks and extra fields
    for i, r in enumerate((1, 2, 3, 4, 5, 6, 7, 8, 9, 10)):
        c.rx(hdr(ACK, 0, 0x104, 1, 0, 10 + i, svc=1) + acks(reason=r, types=(1,) * (i % 3) + (0,) * (i % 2)), to_server=(i % 2 == 0))
    # no acks, no extras
    c.rx(hdr(ACK, 0, 0x104, 1, 0, 30) + acks())
    # acks and exactly 3 octets of padding after them (no extra field is shown)
    c.rx(hdr(ACK, 0, 0x104, 1, 0, 31) + acks(types=(1, 1, 0, 1), extra=b'\0\0\0'))
    # padding and 1, 2, 3 and 4 extra words
    for n in range(0, 5):
        c.rx(hdr(ACK, 0, 0x104, 1, 0, 32 + n) + acks(types=(1,), extra=b'\0\0\0' + u(1444, 1500, 32, 4)[:4 * n]))
    # padding and a partial word
    c.rx(hdr(ACK, 0, 0x104, 1, 0, 37) + acks(extra=b'\0\0\0' + u(1444) + b'\x01\x02'))
    # four octets after the acks (3 skipped, 1 left over)
    c.rx(hdr(ACK, 0, 0x104, 1, 0, 38) + acks(extra=b'\0\0\0\0'))
    # ---- BUSY, ACKALL, VERSION request and NAT ping, DEBUG, PARAMS (no payload dissected)
    c.rx(hdr(BUSY, 0, 0x104, 1, 0, 40, svc=1), to_server=False)
    c.rx(hdr(ACKALL, 0, 0x104, 1, 0, 41, svc=1))
    c.rx(hdr(VERSION, F_CLIENT, 0x104, 0, 0, 42, svc=1))
    c.rx(hdr(VERSION, F_CLIENT, 0, 0, 0, 43, svc=1))
    c.rx(hdr(DEBUG, F_CLIENT, 0x104, 0, 0, 44, svc=1) + u(1, 2, 3))
    c.rx(hdr(PARAMS, 0, 0x104, 0, 0, 45, svc=1) + u(1, 2, 3))
    # ---- ABORT with a code
    c.rx(hdr(ABORT, F_CLIENT, 0x104, 3, 1, 46, svc=1) + u(0x2b2d3))
    c.rx(hdr(ABORT, 0, 0x104, 3, 1, 47, svc=1) + u(1), to_server=False)
    # ---- CHALLENGE: version 2 (nonce and minimum level) and version 1 (no more fields)
    c.rx(hdr(CHALLENGE, 0, 0x104, 0, 0, 48, sec=2) + u(2, 0x01020304, 1), to_server=False)
    c.rx(hdr(CHALLENGE, 0, 0x104, 0, 0, 49, sec=2) + u(1), to_server=False)
    # ---- RESPONSE: version 2, with the (arbitrary filler) fields of the "encrypted" part, a ticket;
    # and version 1 with nothing after the version
    enc = (u(EPOCH, 0x104, 0xdeadbeef) + bytes([2, 0, 0, 0]) + u(1, 2, 3, 4) + u(0x11223344, 2))
    assert len(enc) == 40
    for tl in (0, 1, 7, 32):
        c.rx(hdr(RESPONSE, F_CLIENT, 0x104, 0, 0, 50 + tl, sec=2) + u(2, 0) + enc + u(1, tl) + bytes(range(tl)))
    c.rx(hdr(RESPONSE, F_CLIENT, 0x104, 0, 0, 90, sec=2) + u(1))
    # ---- another port in the default range and port 7021
    c.rx(hdr(ACKALL, 0, 0x200, 1, 0, 91, svc=5), sport=7021, cport=7021)
    c.rx(hdr(ACKALL, 0, 0x200, 1, 0, 92, svc=5), sport=7009, cport=50000)
    # ---- reproducer-free: header only, exactly 28 octets of an ACKALL
    c.rx(hdr(ACKALL))
    # ---- not RX: shorter than the header, and an unknown packet type (shown as UDP data)
    c.rx(hdr(ACKALL)[:27])
    c.rx(hdr(99) + u(1, 2))
    c.p.write(os.path.join(out, 'rx-coverage.pcap'))

    m = Cap()
    # too short for the RX header (27 octets) and unknown packet type: not RX at all
    m.rx(hdr(ACKALL)[:27])
    m.rx(hdr(99) + u(1, 2))
    m.rx(hdr(0) + u(1, 2))
    # ACK with more NACK/ACK octets than present
    m.rx(hdr(ACK) + acks(types=(1,))[:17] + b'\x01\xff')
    # ACK truncated inside the fixed part
    m.rx(hdr(ACK) + b'\x00\x40\x00')
    # CHALLENGE v2 truncated after the nonce, and without the version
    m.rx(hdr(CHALLENGE) + u(2, 1))
    m.rx(hdr(CHALLENGE))
    # RESPONSE v2 truncated in the encrypted part, in the ticket length, ticket longer than data
    m.rx(hdr(RESPONSE) + u(2, 0) + enc[:20])
    m.rx(hdr(RESPONSE) + u(2, 0) + enc + u(1))
    m.rx(hdr(RESPONSE) + u(2, 0) + enc + u(1, 200) + b'abc')
    m.rx(hdr(RESPONSE) + u(2, 0) + enc + u(1, 0xffffffff) + b'abc')
    m.rx(hdr(RESPONSE))
    # ABORT without a code
    m.rx(hdr(ABORT))
    m.rx(hdr(ABORT) + b'\0\0')
    # DATA without payload: the AFS dissector gets nothing
    m.rx(hdr(DATA))
    m.p.write(os.path.join(out, 'rx-coverage-malformed.pcap'))

main(sys.argv[1])
