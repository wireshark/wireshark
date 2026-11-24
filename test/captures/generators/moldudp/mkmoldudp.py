#!/usr/bin/env python3
# Generates test/captures/moldudp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MoldUDP coverage captures.  Usage: mkmoldudp.py <outdir> [-v]
MoldUDP has no default UDP port, so the frames are Exported PDUs
(linktype 252) that name the "moldudp" dissector; the same is reached over
UDP with Decode As (done in runcov.sh).
Writes moldudp-coverage.pcap and moldudp-coverage-malformed.pcap."""
import struct
import sys
import os

def epdu(payload):
    n = b'moldudp'
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload

def pcap(name, pkts):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, p in enumerate(pkts):
            wire = None
            if isinstance(p, tuple):
                p, wire = p
            p = epdu(p)
            wire = len(p) if wire is None else len(p) + wire
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), wire))
            f.write(p)

def hdr(session, seq, count):
    return session.ljust(10) + struct.pack('<IH', seq, count)

def blocks(*datas):
    return b''.join(struct.pack('<H', len(d)) + d for d in datas)

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    S = b'SESSION001'
    pk, marks = [], []
    def add(p, label):
        pk.append(p)
        marks.append((len(pk), label))
    add(hdr(S, 1, 0), 'Heartbeat')
    add(hdr(S, 1, 3) + blocks(b'hello', b'', bytes(range(40))), 'Messages: 3 blocks (5, 0 and 40 octets)')
    add(hdr(S, 9, 1) + blocks(b''), 'Message of length 0 (End Of Session)')
    add(hdr(b'SESSION002', 1000, 1) + blocks(b'x' * 300), 'Messages: one 300 octet block, other session')
    add(hdr(S, 10, 10) + blocks(*[bytes([i]) * (i + 1) for i in range(10)]), 'Messages: 10 blocks')
    add(hdr(S, 20, 1) + struct.pack('<H', 0xFFFF) + b'\xff' * 0xFFFF,
        'REPRODUCER (length wrap): one block of 65535 octets (message length 0xFFFF)')
    add(hdr(S, 50, 1) + blocks(b'z'), 'single octet message')
    add(hdr(S, 60, 0), 'second heartbeat, other sequence')
    pcap(os.path.join(out, 'moldudp-coverage.pcap'), pk)
    if verbose:
        for n, l in marks:
            print(n, l)
        print(len(pk), 'frames')

    pk, marks = [], []
    add(hdr(S, 1, 2) + blocks(b'only one'), 'Count claims 2, one block found')
    add(hdr(S, 1, 1) + blocks(b'a', b'b'), 'Count claims 1, two blocks found')
    add(hdr(S, 1, 1) + struct.pack('<H', 100) + b'short', 'Message length 100, 5 octets left')
    add(hdr(S, 1, 0) + blocks(b'abc'), 'Heartbeat with a message block')
    add(hdr(S, 20, 1) + struct.pack('<H', 0xFFFF) + b'\xff' * 66000,
        'Message length 0xFFFF with 66000 octets (the length-wrap reproducer: claims 65535, then 461 left)')
    add(b'short', 'frame shorter than the header (not dissected)')
    add(hdr(S, 1, 1) + struct.pack('<H', 0xFFFF), 'message length 0xFFFF with no data')
    add(hdr(S, 1, 2) + blocks(b'ab') + b'\x00', 'one block and a lone octet (incomplete length field)')
    pcap(os.path.join(out, 'moldudp-coverage-malformed.pcap'), pk)
    if verbose:
        for n, l in marks:
            print('M', n, l)
        print(len(pk), 'malformed frames')

main()
