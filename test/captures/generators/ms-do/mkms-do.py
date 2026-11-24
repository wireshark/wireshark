#!/usr/bin/env python3
# Generates test/captures/ms-do_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MS-DO coverage captures: mkms-do.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from k11lib import Conn, exp_port_tags, exported_pdu, pcap, pcapng_write

def msg(mid, body=b''):
    return struct.pack('!IB', len(body) + 1, mid) + body

def handshake(name=b'Swarm protocol', size=0x1000, h=0x11, pid=0x22, suf=0x1234):
    return (bytes([len(name)]) + name + struct.pack('!Q', size) + bytes([h]) * 32 +
            bytes([pid]) * 16 + struct.pack('!I', suf))

def build():
    main, notes = [], []
    def mark(t): notes.append((len(main) + 1, t))
    # 1: a connection with the handshake both ways and every message type
    c = Conn(50001, 7680)
    mark('handshake request/reply, keepalive, simple messages, have, bitfield, request, cancel, piece, heap spraying, with an unknown id in the malformed capture')
    main += c.syn()
    main.append(c.cs(handshake()))
    main.append(c.sc(handshake(size=0x2000, h=0x33, pid=0x44)))
    main.append(c.cs(struct.pack('!I', 0)))                       # KeepAlive
    for mid in (1, 0, 2, 3):
        main.append(c.cs(msg(mid)) if mid & 1 else c.sc(msg(mid)))
    main.append(c.cs(msg(4, struct.pack('!I', 7))))                # Have
    main.append(c.sc(msg(5, b'\xa5\x0f\xff')))                     # BitField 3 bytes
    main.append(c.sc(msg(5, b'')))                                 # BitField empty
    main.append(c.cs(msg(6, struct.pack('!III', 3, 0x4000, 0x8000))))   # Request
    main.append(c.cs(msg(8, struct.pack('!III', 3, 0x4000, 0x8000))))   # Cancel
    main.append(c.sc(msg(7, struct.pack('!II', 3, 0x4000) + b'piece data' * 5)))  # Piece
    main.append(c.sc(msg(20, b'spray' * 4)))                       # HeapSpraying
    main.append(c.cs(msg(1) + msg(0, ) + msg(4, struct.pack('!I', 9)) + struct.pack('!I', 0)))  # several in one
    # handshake after other data in the stream and a name of another length
    main.append(c.cs(handshake(name=b'Other', suf=0xdeadbeef)))
    main.append(c.cs(handshake(name=b'')))
    # 2: desegmentation: size header cut after 2 octets, body over two segments
    mark('desegmentation: header in two segments, body in three, message and next message')
    c2 = Conn(50002, 7680, isn_c=2000, isn_s=6000)
    main += c2.syn()
    m = msg(7, struct.pack('!II', 1, 0) + bytes(range(60)))
    main.append(c2.cs(m[:2]))
    main.append(c2.cs(m[2:20]))
    main.append(c2.cs(m[20:50]))
    main.append(c2.cs(m[50:] + msg(1)))
    # a full message followed by the first bytes of the next one
    m = msg(6, struct.pack('!III', 1, 2, 3))
    main.append(c2.sc(msg(0) + m[:3]))
    main.append(c2.sc(m[3:]))
    # 3: reproducer of the message size wrap: 0xFFFFFFFC
    mark('msdo_wrap reproducer (message_size 0xFFFFFFFC, was a wrapped size check)')
    for mid in (0x63, 0x14, 0x07, 0x05, 0x00, 0x04):
        cc = Conn(50100 + mid, 7680, isn_c=3000, isn_s=7000)
        main.append(cc.cs(struct.pack('!IB', 0xFFFFFFFC, mid) + b'\x00' * 20))
    # 4: Exported PDU: ports that match neither the match_uint (reproducer of the assertion)
    mark('Exported PDU msdo (reproducer: direction unknown), with and without a port match')
    name = b'Swarm protocol'
    exp = []
    exp.append(exported_pdu('msdo', handshake(), exp_port_tags(1111, 2222)))
    exp.append(exported_pdu('msdo', msg(1)))
    exp.append(exported_pdu('msdo', struct.pack('!I', 0)))
    # 5: Exported PDU with the DO port as destination of a handshake: port tags only, so match_uint 0 again
    exp.append(exported_pdu('msdo', msg(4, struct.pack('!I', 3)), exp_port_tags(7680, 50001)))
    # an empty payload
    exp.append(exported_pdu('msdo', b'', exp_port_tags(7680, 50001)))
    # 6: UDP/other: DO on TCP only
    mal = []
    c3 = Conn(50003, 7680, isn_c=4000, isn_s=8000)
    mal += c3.syn()
    mal.append(c3.cs(msg(0x63, b'abc')))   # unknown message id
    for mid, body in ((0, b'\x01'), (1, b'\x00\x00'), (2, b'x'), (3, b'xx'),
                      (4, b'\x00\x00\x00'), (4, b'\x00' * 6), (6, b'\x00' * 12),
                      (6, b'\x00' * 14), (8, b'\x00' * 4), (7, b'\x00' * 8), (7, b'')):
        mal.append(c3.cs(msg(mid, body)))
    mal.append(c3.cs(msg(7, b'\x00' * 8)))
    return main, exp, mal, notes

if __name__ == '__main__':
    out = sys.argv[1]
    main, exp, mal, notes = build()
    # the Exported PDU frames go to a second interface: pcapng is not needed, use a pcap
    # per link type; the main capture is pcapng with two interfaces.
    pass
    pcapng_write(os.path.join(out, 'ms-do-coverage.pcapng'), [(1, main), (252, exp)])
    pcap(os.path.join(out, 'ms-do-coverage-malformed.pcap'), mal)
    if '-v' in sys.argv:
        print('main', len(main), 'exp', len(exp), 'malformed', len(mal))
        for n, t in notes: print(n, t)
