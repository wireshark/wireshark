#!/usr/bin/env python3
# Generates test/captures/h1_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H1 (Sinec H1) coverage captures. Usage: mkh1.py <outdir> [-v]
Everything is built with struct; nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from _lib import Pcap

def blk(t, *data):
    d = bytes(data)
    return bytes([t, 2 + len(d)]) + d

def h1(*blocks, extra=b'', hlen=None):
    body = b''.join(blocks)
    n = 3 + len(body) if hlen is None else hlen
    return b'S5' + bytes([n]) + body + extra

def opcode(op): return blk(0x01, op)
def request(org, db, dw, ln): return blk(0x03, org, db, dw >> 8, dw & 255, ln >> 8, ln & 255)
def response(rc): return blk(0x0F, rc)
def empty(n=0): return bytes([0xFF, 2 + n]) + bytes(n)

def tpkt_dt(payload):
    cotp = bytes([0x02, 0xF0, 0x80])
    return struct.pack('!BBH', 3, 0, 4 + len(cotp) + len(payload)) + cotp + payload

def main(out, verbose=False):
    A, B = '192.0.2.10', '192.0.2.20'
    p = Pcap(); marks = []
    def tcp(payload, sp=41001, dp=41234, src=A, dst=B):
        p.tcp(src, dst, sp, dp, payload)
    def mark(name): marks.append((len(p.frames) + 1, name))

    mark('opcode blocks')
    # Heuristic over TCP on a port nobody registers. Request / response
    # pairs for read and write, every organisation, every return code.
    for org in (1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0A, 0x10, 0x11):
        tcp(h1(opcode(5), request(org, 3, 0x0100 + org, 20), empty()))
    mark('requests with unknown org')
    tcp(h1(opcode(3), request(0x77, 255, 65535, 1), empty()),)
    mark('responses')
    for op, rc in ((6, 0x00), (4, 0x00), (6, 0x02), (6, 0x03), (4, 0xFF)):
        tcp(h1(opcode(op), empty(), response(rc)), sp=41234, dp=41001, src=B, dst=A)
    mark('unknown opcode, unknown return code')
    tcp(h1(opcode(0x77), empty(), response(0x55)), sp=41234, dp=41001, src=B, dst=A)
    mark('reproducer h1.dlen > 32767 (shown negative before)')
    tcp(h1(opcode(5), request(1, 7, 100, 40000), empty()))
    tcp(h1(opcode(3), request(2, 7, 0, 65535), empty()))
    mark('empty block with longer length, data after the H1 header')
    tcp(h1(opcode(5), request(1, 1, 0, 4), empty(3), extra=b'\x00\x11\x22\x33\x44\x55\x66\x77'))
    mark('block_len 0 stops the block loop')
    tcp(h1(opcode(5), bytes([0xFF, 0]), hlen=8, extra=b'tail'))
    mark('header length covers only the first block')
    tcp(h1(opcode(5), request(1, 1, 0, 4), hlen=6, extra=b'payload'))
    mark('over COTP (TPKT on 102)')
    for op in (5, 6, 3, 4):
        pl = h1(opcode(op), request(1, 5, 10, 8), empty()) if op in (5, 3) else h1(opcode(op), empty(), response(0))
        if op == 3: pl += b'\xde\xad\xbe\xef' * 4
        tcp(tpkt_dt(pl), sp=40002, dp=102, src=A, dst=B)
    mark('end')
    p.write(os.path.join(out, 'h1-coverage.pcap'))

    # Malformed: exceptions (block header beyond the packet), unknown block
    # type (heuristic returns false after the items were added), 1 byte.
    m = Pcap()
    def mt(payload, sp=41001, dp=41234):
        m.tcp(A, B, sp, dp, payload)
    mt(b'S5\x20' + opcode(5))                      # H1 length beyond the packet
    mt(b'S5\x07' + opcode(5) + b'\x03')            # block length byte missing
    mt(h1(opcode(5), bytes([0x03, 0x08, 1, 2])))   # request block truncated
    mt(h1(opcode(5), bytes([0x0F, 0x03])))         # response block without value
    mt(h1(opcode(5), bytes([0x42, 4, 0, 0]), empty()))  # unknown block type
    mt(b'S')
    mt(b'S5')
    mt(b'S5\x03')
    mt(b'S5\x04\x01')
    mt(b'S5\x02' + b'abcd')
    mt(b'S5\x05\x01\x03')
    m.tcp(A, B, 41002, 102, tpkt_dt(b'S'))
    m.write(os.path.join(out, 'h1-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
