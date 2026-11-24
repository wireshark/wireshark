#!/usr/bin/env python3
# Generates test/captures/nasdaq_soup_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic Nasdaq-SoupTCP 2.0 coverage captures.

Usage: mknasdaq-soup.py <outdir>

SoupTCP has no registered port (the tcp.port range preference is empty), so
tshark needs Decode As:  -d tcp.port==6000,nasdaq_soup
nasdaq-soup-coverage.pcap: a SoupTCP session on TCP 6000: login request,
accepted and rejected logins, sequenced data (ITCH messages), unsequenced
data, heartbeats, debug packets, logout, unknown packet types, several
lines in one segment, lines split over TCP segments, and the empty line of
"Nasdaq-SOUP: Skip empty lines".
nasdaq-soup-coverage-malformed.pcap: packets cut short or with a missing
line end (not added to the tree).  User names, passwords and session names
are made up.
"""
import struct
import sys
import os


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Pcap:
    def __init__(self):
        self.pkts = []
        self.ipid = 1

    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)


class Flow:
    def __init__(self, pcap, cport, sport=6000, cip='192.0.2.1', sip='192.0.2.2'):
        self.pcap = pcap
        self.c = (bytes(map(int, cip.split('.'))), cport, b'\x02\x00\x00\x00\x00\x01')
        self.s = (bytes(map(int, sip.split('.'))), sport, b'\x02\x00\x00\x00\x00\x02')
        self.seq = {True: 1000, False: 5000}

    def seg(self, from_client, payload):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        pseudo = src[0] + dst[0] + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.pcap.ipid, 0, 64, 6, 0, src[0], dst[0])
        self.pcap.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pcap.pkts.append(dst[2] + src[2] + b'\x08\x00' + ip + tcp + payload)
        self.seq[from_client] = (seq + len(payload)) & 0xffffffff

    def s2c(self, *b):
        self.seg(False, b''.join(b))

    def c2s(self, *b):
        self.seg(True, b''.join(b))


def line(kind, body=b''):
    return kind + body + b'\n'


def build_main(pc):
    f = Flow(pc, 50001)
    f.c2s(line(b'L', b'user01' + b'secret    ' + b'SESSION001' + b'0000000001'))
    f.s2c(line(b'J', b'A'))                                       # rejected: not authorized
    f.c2s(line(b'L', b'user02' + b'pw        ' + b'          ' + b'          '))
    f.s2c(line(b'J', b'S'))                                       # rejected: session not available
    f.s2c(line(b'J', b'Z'))                                       # unknown reject code
    f.c2s(line(b'L', b'user01' + b'secret    ' + b'SESSION001' + b'0000000001'))
    f.s2c(line(b'A', b'SESSION001' + b'0000000001'))
    f.s2c(line(b'+', b'Server debug text'))
    f.c2s(line(b'+', b'client debug text'))
    f.s2c(line(b'H'))
    f.c2s(line(b'R'))
    # sequenced data carrying ITCH messages; several lines in one segment
    f.s2c(line(b'S', b'T' + b'37800'))
    f.s2c(line(b'S', b'S' + b'O') + line(b'S', b'M' + b'123') + line(b'H') + line(b'S', b'D' + b'000000001'))
    f.s2c(line(b'S', b'A' + b'000000002' + b'B' + b'000500' + b'ABCD  ' + b'0001234500'))
    f.c2s(line(b'U', b'D' + b'000000002'))                       # unsequenced data
    f.s2c(line(b'S'))                                             # sequenced data without a message
    f.s2c(line(b'U', b''))
    # unknown packet types
    f.s2c(line(b'Z', b'some unknown payload'))
    f.s2c(line(b'q'))
    # a line split over three segments (reassembly) and a segment holding the end of
    # one line and a whole second line
    ln = line(b'+', b'a debug line that is delivered in three pieces')
    f.seg(False, ln[:10])
    f.seg(False, ln[10:30])
    f.seg(False, ln[30:] + line(b'H'))
    # empty lines: skipped (reproducer of "Nasdaq-SOUP: Skip empty lines")
    f.s2c(b'H\n\nS' + b'S' + b'O\n')
    f.s2c(b'\n\n')
    f.s2c(line(b'H') + b'\n' + line(b'H'))
    f.c2s(line(b'O'))                                             # logout request
    f.s2c(line(b'H'))


def build_malformed(pc):
    f = Flow(pc, 50101)
    f.c2s(line(b'L', b'user'))                                    # login request cut short
    f.s2c(line(b'A', b'SESSION'))                                 # login accepted cut short
    f.s2c(b'J\n')                                                 # login reject without a code
    f.s2c(line(b'+'))                                             # debug packet without text
    f.s2c(b'H')                                                   # no line end: waits for more data
    f = Flow(pc, 50102)
    f.s2c(b'+text without end of line')                           # never ends
    f.s2c(b'more text without end of line')
    f = Flow(pc, 50103)
    f.s2c(line(b'S', b'A' + b'0000000'))                          # ITCH message cut short
    f.s2c(line(b'U', b'Z'))
    f.c2s(line(b'U', b'x'))                                       # one octet of unknown ITCH
    f.s2c(line(b'S', b'Q'))                                       # one octet of a cross trade


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    pc = Pcap()
    build_main(pc)
    pc.write(os.path.join(out, 'nasdaq-soup-coverage.pcap'))
    n = len(pc.pkts)
    pc = Pcap()
    build_malformed(pc)
    pc.write(os.path.join(out, 'nasdaq-soup-coverage-malformed.pcap'))
    print('main frames:', n, 'malformed frames:', len(pc.pkts))


if __name__ == '__main__':
    main()
