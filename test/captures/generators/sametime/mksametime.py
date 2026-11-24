#!/usr/bin/env python3
# Generates test/captures/sametime_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Sametime coverage captures. Usage: mksametime.py <outdir>"""
import sys
import os
import struct
from pcaplib import Pcap, TcpStream

PORT = 1533

def txt(s):
    b = s.encode() if isinstance(s, str) else s
    return struct.pack('>H', len(b)) + b

def msg(mtype, body=b'', opts=0, chan=0x11223344):
    rest = struct.pack('>HHI', mtype, opts, chan) + body
    return struct.pack('>I', len(rest)) + rest

Z = lambda n: bytes(n)
def u2(v): return struct.pack('>H', v)
def u4(v): return struct.pack('>I', v)

def send(stype, body, chan=0x11223344, opts=0):
    return msg(0x0004, u2(stype) + body, opts=opts, chan=chan)

def main(out):
    p = Pcap()
    t = TcpStream(p, 40200, PORT)
    # ---- handshake and login
    t.c(msg(0x0000, u2(0x1e) + u2(0x18) + Z(4) + u4(0x0a000001) + u2(0x1000) + u4(0x0a000002) + Z(6) + txt('client-host') + Z(8) + txt('Sametime Connect')))
    t.s(msg(0x8000, u2(0x1e) + u2(0x18) + u4(0x0a000002) + Z(4) + Z(4) + txt('server banner')))
    t.c(msg(0x0025))                                                    # handshake SYN
    t.c(msg(0x0001, Z(2) + txt('alice@example.com')))                   # login
    t.s(msg(0x0018, Z(2) + txt('redirect.example.com')))                # login redirect
    t.s(msg(0x8001, txt('alice') + u2(0x1000) + txt('Alice Example') + txt('token') + Z(3) + txt('community') +
                    u4(0x0a000003) + txt('host') + Z(21) + txt('desc') + txt('end')))        # login ack
    t.c(msg(0x0016, b'\x01\x02\x03\x04'))                               # login continue (no dissection)
    # ---- channels
    t.c(msg(0x0002, Z(4) + u4(0x100) + txt('channel-name') + u4(0x11) + Z(8) + txt('description')))        # create: service aware
    t.s(msg(0x0006, Z(34) + txt('accepted') + b'\x01' + txt('user') + u2(0x20) + u4(1700000000) + txt('Available')))   # accept, with status
    t.s(msg(0x0006, Z(34) + txt('accepted') + b'\x00'))
    t.s(msg(0x0006, Z(34) + b'\x00\x00\x00'))                           # accept: nothing after the 34 octets (zero length text)
    t.c(msg(0x0003, u4(0x80000022)))                                    # channel destroy
    # ---- channel send, every send type
    t.c(send(0x0068, Z(8) + u2(0x0002) + txt('buddy1')))                # aware add: user
    t.c(send(0x0068, Z(8) + u2(0x0003) + txt('group1')))                # group
    t.c(send(0x0068, Z(8) + u2(0x0008) + txt('server')))
    t.c(send(0x0068, Z(8) + u2(0x0077) + txt('other')))
    t.c(send(0x0069, Z(10)))                                            # aware remove (no dissection)
    t.c(send(0x00c9, Z(20) + u4(0x33) + txt('US') + txt('02134') + txt('MA') + txt('Boston') + txt('555-0100') + b'\x00' + txt('Office') + txt('-5')))   # location
    t.c(send(0x00c9, Z(20) + u4(0x01) + txt('plain option')))
    t.c(send(0x00cb, Z(10)))                                            # opt watch
    t.s(send(0x0259, Z(8) + u2(0x0002) + txt('first') + txt('second') + txt('third')))   # got set
    t.s(send(0x0259, Z(8) + u2(0x0003) + b'\x00\x00\x00' + txt('after a zero length item')))
    t.s(send(0x025d, Z(10)))                                            # did set
    t.s(send(0x01f4, Z(12) + u2(0x0002) + txt('snapshot-user')))
    t.s(send(0x01f5, Z(8) + u2(0x0002) + txt('upd-user') + Z(4) + b'\x01' + txt('name') + u2(0x60) + u4(1700000100) + txt('Away')))   # update with status
    t.s(send(0x01f5, Z(8) + u2(0x0003) + txt('upd-user') + Z(4) + b'\x00'))                                                           # update without
    t.c(send(0x0000, Z(14) + txt('send type zero')))
    t.c(send(0x0002, Z(8) + txt('first') + Z(3) + txt('second')))
    t.c(send(0x0005, Z(26) + txt('<xml>message</xml>')))                # XML
    t.c(send(0x0005, Z(10)))                                            # XML too short
    t.c(send(0x0007, Z(8) + txt('a') + txt('b') + Z(3) + txt('c') + txt('d')))
    t.c(send(0x0007, Z(4)))
    t.c(send(0x025a, Z(10) + txt('question mark')))
    t.c(send(0x1234, Z(10)))                                            # unknown send type
    # ---- user status
    for st_, name in ((0x20, 'Active'), (0x40, 'Idle'), (0x60, 'Away'), (0x80, 'Busy'), (0x08, 'In a meeting'), (0x1234, 'Odd')):
        t.c(msg(0x0009, u2(st_) + u4(1700000000) + txt(name)))
    # ---- sense service: every code
    for code in (0x11, 0x15, 0x18, 0x1a, 0x80000011, 0x80000015, 0x80000018, 0x80000022, 0x77):
        t.s(msg(0x0011, u4(code)))
    # ---- other message types, options (encrypted, attributes)
    t.c(msg(0x000b, Z(8)))                                             # set privacy list
    t.c(msg(0x0019, Z(8)))                                             # admin
    t.c(msg(0x0022, Z(8)))                                             # announce
    t.c(msg(0x7777, Z(8)))                                             # unknown type
    t.c(msg(0x0004, b'\x12\x34' + Z(10), opts=0x4000))                                # encrypted
    t.c(msg(0x0009, u2(0x20) + u4(5) + txt('x'), opts=0x8000))          # has attributes
    t.c(msg(0x0009, u2(0x20) + u4(5) + txt('x'), opts=0xc000))
    # ---- strings the heuristic rejects: a zero first character, a length beyond the packet
    t.c(msg(0x0001, Z(2) + b'\x00\x05\x00abcd'))
    t.c(msg(0x0001, Z(2) + b'\x00\x50abc'))
    # ---- two messages in a segment and a message split over segments
    t.c(msg(0x0011, u4(0x11)) + msg(0x0001, Z(2) + txt('second in segment')))
    m = msg(0x0001, Z(2) + txt('split into three segments'))
    t.c(m[:3]); t.c(m[3:12]); t.c(m[12:])
    t.fin()

    p.write(os.path.join(out, 'sametime-coverage.pcap'))

    # ===== malformed
    m = Pcap()
    t = TcpStream(m, 41200, PORT)
    # fixed parts cut: handshake, handshake ack, create, send types, accept, user status, sense service
    for mt, n in ((0x0000, 12), (0x8000, 6), (0x0001, 1), (0x0018, 1), (0x8001, 2), (0x0002, 6), (0x0004, 1), (0x0006, 20), (0x0009, 3), (0x0011, 2)):
        t.c(msg(mt, Z(n)))
    for st_, n in ((0x68, 5), (0xc9, 15), (0x259, 4), (0x1f4, 6), (0x1f5, 6), (0x0, 6), (0x2, 4), (0x5, 30), (0x7, 6), (0x25a, 4)):
        t.c(send(st_, Z(n)))
    t.c(send(0x00c9, Z(20) + u4(0x33) + txt('US')))                     # location cut
    t.c(send(0x01f5, Z(8) + u2(2) + txt('u') + Z(4) + b'\x01' + txt('n') + b'\x00'))   # status cut
    t.c(msg(0x0006, Z(34) + txt('x') + b'\x01'))
    # heartbeats: a one octet PDU cannot reach the dissector (tcp_dissect_pdus needs 4 octets), see README
    t.fin()
    t = TcpStream(m, 41202, PORT)
    t.c(b'\x80')
    t.s(b'\x80')
    t.c(b'\x80')
    t.c(struct.pack('>I', 0xfffffffd) + b'abcd')   # a length that wraps to a PDU of one octet
    t.fin()
    t = TcpStream(m, 41200, PORT)
    # a message with a length far beyond the data (never completes), and a length of 0 / 1 / 2
    t.c(struct.pack('>I', 100000) + struct.pack('>HHI', 4, 0, 0))
    t.fin()
    t = TcpStream(m, 41201, PORT)
    t.c(struct.pack('>I', 0) + b'abcd')
    t.c(struct.pack('>I', 2) + b'ab')
    t.c(b'\x00\x00')
    t.c(b'\xff\xff\xff\xf0abcdefgh')
    t.fin()
    m.write(os.path.join(out, 'sametime-coverage-malformed.pcap'))

main(sys.argv[1])
