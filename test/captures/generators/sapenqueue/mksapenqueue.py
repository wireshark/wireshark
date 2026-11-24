#!/usr/bin/env python3
# Generates test/captures/sapenqueue_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP Enqueue Server coverage captures.
# Usage: mksapenqueue.py <outdir>
# The Enqueue Server uses the same TCP port as the Diag dispatcher (3200), so
# SAP NI offers every message to a heuristic dissector first: the first
# message of a conversation with the magic bytes 0xabcde123 and at least 24
# bytes sets the conversation dissector, later messages go straight to it.
# Nothing is captured from a network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from sapcov_lib import Cap, Flow, ni

CLI, SRV = '192.0.2.1', '192.0.2.2'
n = [51000]
MAGIC = b'\xab\xcd\xe1\x23'


def flow(c, port=3200):
    n[0] += 1
    f = Flow(c, CLI, SRV, n[0], port)
    f.syn()
    return f


def eh(dest, opcode=0, type_=0, more=0, id_=1, length=0, frag=0):
    '''20 byte header after the NI length: magic, id, length, fragment length,
    destination, opcode, more fragments, type.  The dissector reads the fields
    from the TCP payload including the 4 byte NI length (a message that is
    found through the conversation); the very first message of a conversation
    reaches it through the heuristic without the NI length (see first())'''
    return (MAGIC + struct.pack('!III', id_, length, frag) +
            bytes([dest, opcode, more, type_]))


def first():
    '''First message of a conversation: the heuristic hands the dissector the
    payload without the NI length, so every field is read 4 bytes too far.
    This is a connection admin keepalive for either reading.'''
    return eh(0) + bytes([6, 6, 0, 0, 0, 0, 0, 0])


def sadm(opcode, body=b'', ver=1, rc=0, flags=0):
    '''Server admin header (27 bytes) and body.'''
    return (b'ADM1' + bytes([ver]) + b'\0\0\0' + b'ADM2' + b'\x01' + struct.pack('!I', 27 + len(body)) +
            bytes([opcode, flags]) + struct.pack('!I', rc) + b'ADM3' + body)


def trace(patterns, action=1, limit=0, thread=0, level=2, nopat=None, eye=True):
    b = bytes([1, action, limit, thread]) + b'\0' * 4 + struct.pack('!I', level) + b'\0' * 4
    b += b'\x01' + struct.pack('!I', 1000000) + struct.pack('!I', len(patterns) if nopat is None else nopat)
    b += b'\0' * 8 + b'TRC1'
    for p in patterns:
        b += bytes([len(p)]) + p + b'\0'
    if eye:
        b += b'TRC2'
    return b


def params(opcode, items):
    '''items: list of (id, value bytes) -> count + parameters.'''
    return struct.pack('!I', len(items)) + b''.join(struct.pack('!I', i) + v for i, v in items)


def build_main(out):
    c = Cap()
    f = flow(c)
    f.send(ni(first()))
    # --- connection admin: keepalive, shutdowns, loopback -------------------
    for op in (0, 6, 3, 4, 5, 9):
        f.send(ni(eh(6, op, 0, id_=op + 1) + b'\0\0\0\0'))
    # --- parameter request / response -------------------------------------
    f.send(ni(eh(6, 1, 0) + params(1, [(0, struct.pack('!I', 65536)), (1, struct.pack('!I', 65536)),
                                      (2, struct.pack('!I', 7)), (3, b'ENQ_CLIENT\0'),
                                      (4, b''), (5, struct.pack('!I', 2)),
                                      (6, struct.pack('!I', 4) + b'\0\0\0\x01'), (9, struct.pack('!I', 9))])))
    f.send(ni(eh(6, 2, 2) + params(2, [(4, struct.pack('!I', 1)), (3, b'ENQ_SERVER\0'),
                                      (6, struct.pack('!I', 1) + b'U'), (0, struct.pack('!I', 4096))])), False)
    # Unicode support value of 8 bytes (fixed: it is FT_BYTES now; a length
    # other than 1-4 made the packet malformed)
    f.send(ni(eh(6, 2, 2) + params(2, [(6, struct.pack('!I', 8) + b'\x01\x02\x03\x04\x05\x06\x07\x08')])), False)
    f.send(ni(eh(6, 2, 2) + params(2, [(6, struct.pack('!I', 0))])), False)
    f.send(ni(eh(6, 1, 0) + params(1, []) + b'\0'))                  # no parameters
    # --- enqueue and other destinations -----------------------------------
    for dest, t in ((1, 0), (2, 1), (5, 0), (7, 0), (8, 2), (9, 0)):
        f.send(ni(eh(dest, 0, t, 0, id_=dest) + b'\x01\x02\x03\x04' * 4))
    f.send(ni(eh(1, 0, 0, 1, length=100, frag=24)), False)           # more fragments
    # --- server admin ------------------------------------------------------
    f.send(ni(eh(3, 0, 0) + sadm(1)))                                  # dummy, no value
    f.send(ni(eh(3, 0, 0) + sadm(2, b'\x01')))                         # shutdown, value
    f.send(ni(eh(3, 0, 2) + sadm(4, b'REPLINFO' * 3, rc=0)), False)    # replication info
    f.send(ni(eh(3, 0, 0) + sadm(6, trace([b'*', b'ENQ*', b'x' * 10]))))
    # a pattern of 255 characters: its length byte (255) plus the terminating NUL
    # wrapped to a length of zero (fixed: the length is unsigned now)
    f.send(ni(eh(3, 0, 0) + sadm(6, trace([b'p' * 255, b'tail']))))
    f.send(ni(eh(3, 0, 0) + sadm(6, trace([], action=5, limit=4, thread=6))))
    for a, l, t in ((2, 1, 1), (3, 2, 2), (4, 3, 3), (5, 4, 4)):
        f.send(ni(eh(3, 0, 0) + sadm(6, trace([b'pat'], action=a, limit=l, thread=t))))
    # --- heuristic fix: 20 bytes with the magic is not an Enqueue message -----
    g = flow(c, 40000)
    g.send(ni(MAGIC + b'\0' * 16))   # 20 bytes
    # a second flow where the heuristic claims the first message
    h = flow(c, 40000)
    h.send(ni(first()))
    h.send(ni(eh(6, 6, 0) + b'\0\0\0\0'))
    h.send(ni(eh(6, 6, 2) + b'\0\0\0\0'), False)
    # a payload of 24 bytes or more without the magic bytes: not an Enqueue message
    k = flow(c, 40000)
    k.send(ni(b'ADM:PING'.ljust(40, b'\0')))
    c.write(os.path.join(out, 'sapenqueue-coverage.pcap'))


def build_malformed(out):
    c = Cap()
    f = flow(c)
    f.send(ni(first()))                                           # starts the conversation
    f.send(ni(eh(3, 0, 0) + b'ADM1'))                             # server admin header cut short
    f.send(ni(eh(3, 0, 0) + sadm(6, b'\x01\x02')))                # trace request cut short
    f.send(ni(eh(3, 0, 0) + sadm(6, trace([b'abc', b'def'], nopat=2)[:-12])))   # pattern cut short
    f.send(ni(eh(3, 0, 0) + sadm(6, trace([b'abc'], eye=False))))              # no final eyecatcher
    f.send(ni(eh(3, 0, 0) + sadm(6, trace([b'a' * 255, b'tail'])[:-30])))     # long pattern cut short
    f.send(ni(eh(3, 0, 0) + sadm(6, trace([b'abc'], nopat=500))))             # more patterns than data
    f.send(ni(eh(6, 6, 0)))                                        # nothing after the header: exception
    f.send(ni(eh(6, 1, 0) + params(1, [])))                        # no parameter after the count: exception
    f.send(ni(eh(6, 1, 0) + b'\0'))                               # parameter request, count cut short
    f.send(ni(eh(6, 1, 0) + b'\0\0\0'))                           # count cut short
    f.send(ni(eh(6, 1, 0) + struct.pack('!I', 2) + b'\0\0'))      # parameter id cut short
    f.send(ni(eh(6, 1, 0) + params(1, [(0, b'\0\0')])))          # parameter value cut short
    f.send(ni(eh(6, 2, 2) + params(2, [(4, b'\0')])))            # no support value cut short
    f.send(ni(eh(6, 2, 2) + struct.pack('!II', 1, 6) + b'\0\0'))  # unicode length cut short
    f.send(ni(eh(6, 2, 2) + params(2, [(6, struct.pack('!I', 99) + b'abc')])))  # unicode length too large
    f.send(ni(eh(6, 2, 2) + struct.pack('!II', 1, 3) + b'unterminated'))      # name without NUL
    f.send(ni(eh(6, 2, 2) + struct.pack('!II', 1, 3)))                          # name, nothing there
    f.send(ni(eh(6, 2, 2) + struct.pack('!II', 3, 9) + struct.pack('!I', 5)))  # count > parameters
    # a message of fewer than 24 bytes on a conversation set to the Enqueue dissector
    f.send(ni(MAGIC + b'\0' * 10))
    c.write(os.path.join(out, 'sapenqueue-coverage-malformed.pcap'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)
