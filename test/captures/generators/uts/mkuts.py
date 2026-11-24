#!/usr/bin/env python3
# Generates test/captures/uts_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Unisys Transmittal System (UTS) coverage captures (packet-uts.c).

usage: mkuts.py <outdir> [-v]
Writes uts-coverage.pcap and uts-coverage-malformed.pcap (DLT_SITA, link type 196).
Every frame starts with the 5 octet SITA header (flags, signals, errors 1,
errors 2, protocol 6 = UTS); flags bit 0 is the direction (0 transmitted by the
IOP, 1 received from the remote).
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []

SOH, STX, ETX, EOT, ENQ, BEL, NAK, DLE = 1, 2, 3, 4, 5, 7, 0x15, 0x10
GRID, GSID, GDID = 0x20, 0x50, 0x70
TXED, RXED = 0, 1


class Pcap:
    def __init__(self, lt=196):
        self.b = bytearray(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, lt))
        self.n = 0
        self.t = 1700000000

    def pkt(self, data):
        self.t += 1
        self.b += struct.pack('<IIII', self.t, 0, len(data), len(data)) + data
        self.n += 1

    def write(self, fn):
        open(fn, 'wb').write(self.b)


def mark(p, name, start):
    RANGES.append((name, start + 1, p.n))


def sita(msg, flags=RXED, proto=6, signals=0x1c, e1=0, e2=0):
    return bytes([flags, signals, e1, e2, proto]) + bytes(msg)


def hdr(rid=0x41, sid=0x42, did=0x43):
    return [SOH, rid, sid, did]


def main_capture():
    p = Pcap()
    s0 = p.n
    # no traffic, with and without padding
    p.pkt(sita([EOT, EOT, ETX]))
    p.pkt(sita([EOT, EOT, ETX, 0, 0, 0, 0]))
    p.pkt(sita([EOT, EOT, ETX], flags=TXED))
    # general poll, with the general RID (0x20)
    p.pkt(sita(hdr() + [ETX], flags=TXED))
    p.pkt(sita(hdr(rid=GRID, sid=GSID, did=GDID) + [ETX], flags=TXED))
    mark(p, 'no traffic, general poll', s0)

    s0 = p.n
    # acknowledgements: DLE '1' ETX, by the SID/DID combination
    p.pkt(sita(hdr(GRID, GSID, GDID) + [DLE, ord('1'), ETX], flags=TXED))      # General Poll + ACK
    p.pkt(sita(hdr(0x41, 0x42, GDID) + [DLE, ord('1'), ETX], flags=TXED))      # Specific Poll + ACK
    p.pkt(sita(hdr(0x41, 0x42, 0x43) + [DLE, ord('1'), ETX], flags=RXED))      # No Traffic + ACK
    p.pkt(sita(hdr(0x41, GSID, 0x43) + [DLE, ord('1'), ETX], flags=TXED))      # SID general, DID not: unknown format (sent)
    p.pkt(sita(hdr(0x41, GSID, 0x43) + [DLE, ord('1'), ETX], flags=RXED))      # (received)
    p.pkt(sita(hdr(0x41, 0x42, GDID) + [DLE, NAK, ETX], flags=TXED))           # Retransmit Request
    p.pkt(sita(hdr(0x41, GSID, GDID) + [DLE, NAK, ETX], flags=TXED))           # NAK with general SID: not a retransmit request
    mark(p, 'acknowledgements and retransmit request', s0)

    s0 = p.n
    p.pkt(sita(hdr() + [BEL, STX, ETX], flags=TXED))                           # Message Waiting
    p.pkt(sita(hdr() + [DLE, ord('1'), STX] + list(b'TEXT AND ACK') + [ETX, 0x55], flags=RXED))   # Text + ACK, with BCC
    p.pkt(sita(hdr() + [STX] + list(b'HELLO FROM THE TERMINAL') + [ETX, 0x31, 0, 0], flags=RXED))   # Text received, BCC and padding
    p.pkt(sita(hdr() + [STX] + list(b'HELLO TERMINAL') + [ETX, 0x32], flags=TXED))               # Text sent
    p.pkt(sita(hdr() + [STX] + list(b'NO END OF TEXT'), flags=RXED))           # no ETX
    p.pkt(sita(hdr() + [STX, ETX], flags=RXED))                                # empty text
    p.pkt(sita(hdr() + [STX] + list(b'X' * 200) + [ETX, 0x30], flags=TXED))    # long text
    mark(p, 'message waiting and text messages', s0)

    s0 = p.n
    p.pkt(sita(hdr() + [DLE, ENQ, ETX], flags=RXED))                           # Reply Request
    p.pkt(sita(hdr() + [DLE, ord('?'), ETX], flags=RXED))                      # Busy
    p.pkt(sita(hdr() + [DLE, ord(';'), ETX], flags=RXED))                      # Not Busy
    p.pkt(sita(hdr() + [DLE, ord('1'), DLE, ord(';'), ETX], flags=RXED))       # Not Busy + ACK
    p.pkt(sita(hdr() + [DLE, ord('1'), ord('A'), ETX], flags=RXED))            # Function Message 41 + ACK
    p.pkt(sita(hdr() + [ord('B'), ETX], flags=RXED))                           # Function Message 42
    p.pkt(sita(hdr() + [0x00, ETX], flags=RXED))                               # function code 00 (control character, the fix prints it as hex)
    p.pkt(sita(hdr() + [0x7f, ETX], flags=RXED))                               # function code 7f
    p.pkt(sita(hdr() + [0xc1, ETX], flags=RXED))                               # high bit set: masked to 41
    p.pkt(sita(hdr() + [DLE, ord('1'), 0x0a, ETX], flags=RXED))                # Function Message 0A + ACK
    mark(p, 'reply request, busy, not busy, function messages', s0)

    s0 = p.n
    # messages that fit no pattern: found ETX only, or no ETX at all
    p.pkt(sita(hdr() + [DLE, ord('2'), 0x20, 0x21, ETX], flags=RXED))
    p.pkt(sita(hdr() + [0x20, 0x21, 0x22], flags=RXED))                         # no ETX and not a function message
    p.pkt(sita(hdr() + [ETX, 0x00, 0x00, 0x00], flags=TXED))                    # general poll with trailing bytes
    p.pkt(sita(hdr() + [DLE, ord('1'), ETX, 0x17, 0x00], flags=TXED))           # ACK with trailing bytes
    p.pkt(sita([SOH, 0x41, 0x42], flags=RXED))                                  # cut inside the address: "Unknown Message Format"
    p.pkt(sita([SOH], flags=RXED))
    p.pkt(sita([0x41, 0x42, 0x43, 0x44, 0x45], flags=RXED))                     # does not start with SOH
    p.pkt(sita([EOT, EOT], flags=RXED))                                         # truncated no traffic
    p.pkt(sita([], flags=RXED))                                                 # empty
    mark(p, 'messages that match no pattern, cut messages', s0)

    s0 = p.n
    # SITA header fields around the UTS payload: direction, signals, error bits
    p.pkt(sita(hdr() + [ETX], flags=TXED, signals=0x1f, e1=0x00, e2=0x0f))
    p.pkt(sita(hdr() + [ETX], flags=RXED, signals=0x00, e1=0x1f, e2=0xff))
    mark(p, 'SITA header flags, signals and error bits', s0)
    return p


def malformed_capture():
    p = Pcap()
    p.pkt(sita(hdr() + [STX] + list(b'TEXT'), flags=RXED)[:9])                  # header only up to the STX
    p.pkt(sita(hdr() + [DLE, ord('1')], flags=RXED))                            # ACK without ETX
    p.pkt(sita(hdr() + [BEL, STX], flags=RXED))                                 # message waiting without ETX
    return p


if __name__ == '__main__':
    p = main_capture()
    p.write(os.path.join(OUT, 'uts-coverage.pcap'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'uts-coverage-malformed.pcap'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-60s frames %d-%d' % (n, a, b))
        print('main', p.n, 'malformed', m.n)
