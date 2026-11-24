#!/usr/bin/env python3
# Generates test/captures/ipars_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ipars.c (IPARS, reached through the SITA
WAN link layer, pcap link type 196, protocol 5 = ALC).
Usage: mkipars.py <outdir> [-v]
Writes ipars-coverage.pcap (main) and ipars-coverage-malformed.pcap."""
import struct
import sys
import os

DLT_SITA = 196
S1, S2, GA = 0x00, 0x20, 0x03
EOMpb, EOMc, EOMu, EOMi = 0x10, 0x11, 0x12, 0x13


class Cap:
    def __init__(self):
        self.frames = []
        self.marks = []

    def mark(self, name):
        self.marks.append((len(self.frames) + 1, name))

    def add(self, payload, rx=True, signals=0, e1=0, e2=0, proto=5):
        """SITA pseudo header: flags, signals, errors1, errors2, proto."""
        self.frames.append(bytes([1 if rx else 0, signals, e1, e2, proto]) + bytes(payload))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, DLT_SITA))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
                f.write(d)


def main_cap():
    c = Cap()
    c.mark('go_ahead_polls')
    c.add([GA])                                     # "GoAhead"
    c.add([GA, 0x41])                               # S1/S2 absent, 2 octets: GoAhead NextIA
    c.add([0x83])                                   # FPGA go ahead, 1 octet
    c.add([0x83, 0x25])                             # FPGA: GoAhead NextIA (0x25)
    c.add([0x43, 0x25, 0x01, 0x02])                 # long: poll
    c.add([0x83, 0x26, 0x00])
    c.add([GA, 0x07, 0x01])
    c.mark('data_messages')
    c.add([S1, S2, 0x05, 0x11, 0x22, 0x33])         # data
    c.add([S1, S2, 0x05, 0x11, 0x1f, 0x38])         # please resend
    c.add([S1, S2, 0x05, 0x11, 0x2a, 0x05])         # unsolicited message indicator
    c.add([0x05, 0x11, 0x1f, 0x38])                 # the same without the S1/S2 prefix
    c.add([0x05, 0x11, 0x2a, 0x05, 0x01])
    c.add([S1, S2, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e])   # other data
    c.add([S1, S2, 0x0a])                           # data cut after the command
    c.add([S1, S2, 0x01])
    c.add([0x00, 0x21, 0x22, 0x23])                 # S1, then not S2 (ia & 0x3f == 0, ta not 0x20)
    c.add([0x40, 0x60, 0x1f, 0x38])                 # high bits set: masked to S1 S2
    c.add([0x05, 0x0d, 0x0e])                       # not S1 and not a go ahead: unknown format
    c.add([0x31, 0x20, 0x21, 0x22])                 # TA = 0x20: reset IA
    c.add([0x31, 0x20])
    c.add([0x31])
    c.mark('eom')
    for eom in (EOMc, EOMi, EOMu, EOMpb, 0x14, 0x2a, 0x3f, 0x51):
        c.add([S1, S2, GA, 0x07, eom, 0x00])
    c.add([S1, S2, GA, 0x07, 0x00, 0x00])
    c.add([S1, S2, GA, 0xc7, 0x12, 0x00])
    c.mark('sita_header')
    c.add([S1, S2, 0x05, 0x11, 0x22], rx=False, signals=0x1f)
    c.add([GA], rx=False, signals=0x00, e2=0x0f)
    c.add([GA], rx=True, signals=0x15, e1=0x1f, e2=0xff)
    c.add([S1, S2, GA, 0x07, 0x2a, 0x00], rx=False, signals=0xe0)
    c.add([S1, S2, GA, 0x07, EOMc, 0x00], e1=0x00, e2=0x00, proto=5)
    c.mark('reproducers')
    # reproducers of "IPARS: Fix unknown EOM type text and data length":
    # the unknown EOM text shows the EOM type (0x2A), the Data item the
    # length of the data after the first three octets
    c.add([S1, S2, 0x05, 0x11, 0x22, 0x33])
    c.add([S1, S2, GA, 0x07, 0x2a, 0x00])
    return c


def malformed_cap():
    c = Cap()
    c.add([])
    c.add([S1, S2])                                  # S1 S2 only: no third octet
    c.add([S1, S2, GA])                              # GoAhead without IA
    c.add([S1, S2, GA, 0x07])                        # no EOM type
    c.add([S1, S2, GA, 0x07, EOMc])                  # no BCC (reads one past)
    c.add([0x00])                                    # S1 only, second octet missing
    c.add([S1, S2, 0x05])
    c.add([0x83, 0x25], proto=9)                     # SITA protocol that is not ALC
    return c


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_cap()
    m.write(os.path.join(out, 'ipars-coverage.pcap'))
    x = malformed_cap()
    x.write(os.path.join(out, 'ipars-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, nm in m.marks:
            print(n, nm)
        print('main frames', len(m.frames), 'malformed', len(x.frames))


main()
