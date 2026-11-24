#!/usr/bin/env python3
# Generates test/captures/soupbintcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic SoupBinTCP 3.0 captures. Usage: mksoupbintcp.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pcaplib_s9 import Stream, write_pcap

PORT = 20000


def pkt(t, body=b''):
    """A SoupBinTCP packet: 16 bit length (not counting itself), type, body."""
    return struct.pack('!HB', 1 + len(body), ord(t)) + body


def alpha(s, n):
    return s.encode().ljust(n)[:n]


def num(v, n=20):
    return str(v).rjust(n).encode()


def login_req(user='alice', pw='secret', sess='', seq=0):
    return pkt('L', alpha(user, 6) + alpha(pw, 10) + alpha(sess, 10) + num(seq))


def login_acc(sess='SESS000001', seq=1):
    return pkt('A', alpha(sess, 10) + num(seq))


def system_event(code=b'S'):
    # 10 octet OUCH system event, claimed by a heuristic dissector
    return b'S' + b'\x00' * 8 + code


def main(out):
    s1 = Stream('192.0.2.10', 40001, '192.0.2.20', PORT)
    s1.hs()
    s1.send(login_req('alice', 'secret', '', 0))
    s1.recv(login_acc('SESS000001', 100))
    s1.recv(pkt('S', b'\x01\x02\x03\x04unknown payload'))     # seq 100
    s1.recv(pkt('S', b'\xee' * 4))                            # seq 101
    s1.recv(pkt('H'))
    s1.send(pkt('R'))
    s1.send(pkt('U', b'client unsequenced data'))
    s1.recv(pkt('U', b'\x00'))
    s1.recv(pkt('+', b'Debug text from the server'))
    s1.recv(pkt('+', b''))                                    # empty debug text
    # PDU split over three TCP segments (reassembly) and three PDUs in one
    big = pkt('S', bytes(range(256)) * 2)                     # seq 102
    s1.recv(big[:100])
    s1.recv(big[100:300])
    s1.recv(big[300:])
    s1.recv(pkt('S', b'one') + pkt('S', b'two') + pkt('H'))   # 103, 104
    # a length field split over two segments
    p = pkt('S', b'split header')                             # seq 105
    s1.recv(p[:1])
    s1.recv(p[1:])
    # Unknown packet type, in the SoupBinTCP tree
    s1.recv(pkt('X', b'\x11\x22\x33 unknown type'))
    # a second Login Accepted in the same connection restarts the numbering
    s1.recv(login_acc('SESS000002', 5000))
    s1.recv(pkt('S', b'after relogin'))                       # seq 5000
    s1.recv(pkt('S', system_event()))                         # heuristic claims
    s1.send(pkt('O'))
    s1.recv(pkt('Z'))

    # second connection: login rejected, request with session and seq
    s2 = Stream('192.0.2.11', 40002, '192.0.2.20', PORT)
    s2.hs()
    s2.send(login_req('bob', 'pw', 'SESS000009', 12345))
    s2.recv(pkt('J', b'A'))
    s2.send(login_req('bob', 'pw2', 'SESS000009', 1))
    s2.recv(pkt('J', b'S'))
    s2.recv(pkt('J', b'Q'))                                   # unknown reject code

    # third connection: sequenced data without a Login Accepted
    s3 = Stream('192.0.2.12', 40003, '192.0.2.20', PORT)
    s3.hs()
    s3.recv(pkt('S', b'no login'))
    s3.recv(pkt('S', b'no login either'))

    # fourth connection: login accepted with a large and a zero next number
    s4 = Stream('192.0.2.13', 40004, '192.0.2.20', PORT)
    s4.hs()
    s4.recv(login_acc('SESS000004', 2147483647))
    s4.recv(pkt('S', b'last int'))
    s4.recv(login_acc('SESS000005', 0))
    s4.recv(pkt('S', b'zero'))

    pkts = []
    for s in (s1, s2, s3, s4):
        pkts += s.pkts
    write_pcap(os.path.join(out, 'soupbintcp-coverage.pcap'), pkts)

    # Malformed: invalid sequence number strings (expert errors) and
    # exceptions
    m = Stream('192.0.2.30', 40010, '192.0.2.20', PORT)
    m.hs()
    m.send(pkt('L', alpha('eve', 6) + alpha('pw', 10) + alpha('', 10) + b'not a number' + b' ' * 8))
    m.recv(pkt('A', alpha('SESS000007', 10) + b'xyz' + b' ' * 17))
    m.recv(pkt('S', b'after bad login'))
    m.recv(pkt('A', alpha('SESS000008', 10) + num(7)[:5]))     # truncated login accepted
    m.send(pkt('L', alpha('eve', 6)))                          # truncated login request
    m.recv(pkt('J'))                                           # reject without code
    m.recv(pkt('X'))                                           # unknown type without a body
    m.recv(struct.pack('!HB', 50, ord('+')) + b'short')        # length beyond the data
    m.recv(struct.pack('!H', 0))                               # zero length, no type
    write_pcap(os.path.join(out, 'soupbintcp-coverage-malformed.pcap'), m.pkts)


if __name__ == '__main__':
    main(sys.argv[1])
