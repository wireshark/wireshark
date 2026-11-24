#!/usr/bin/env python3
# Generates test/captures/ua_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Generate the UA coverage captures (synthetic).

usage: mkua.py OUTDIR [-v]

The UA dissector (packet-ua.c) splits the UA/UDP data into UA messages and
hands each to UA3G or NOE by opcode. It has no port of its own: it is
reached through UAUDP on UDP port 32000, in both directions (a destination
port of 32000 is system to terminal, a source port of 32000 terminal to
system). Writes ua-coverage.pcap and ua-coverage-malformed.pcap.
'''
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from u9lib import Pcap, udp

SYS = [192, 0, 2, 10]
TERM = [192, 0, 2, 50]
PORT = 32000

sections = []


def ua(op, body=b''):
    m = bytes([op]) + bytes(body)
    return struct.pack('<H', len(m)) + m


def data(msgs, exp=1, snt=1):
    return bytes([7]) + struct.pack('!HH', exp, snt) + b''.join(msgs)


class Gen:
    def __init__(self):
        self.pc = Pcap(1)
        self.seq = 1

    def sec(self, name):
        sections.append([name, len(self.pc) + 1, None])

    def end(self):
        sections[-1][2] = len(self.pc)

    def s2t(self, *msgs):
        self.seq += 1
        return self.pc.add(udp(SYS, TERM, 40000, PORT, data(msgs, self.seq, self.seq)))

    def t2s(self, *msgs):
        self.seq += 1
        return self.pc.add(udp(TERM, SYS, PORT, 40000, data(msgs, self.seq, self.seq)))


# every opcode the UA dissector passes to UA3G, with a body UA3G accepts
S2T = {
    0x00: [], 0x01: [1], 0x02: [1, 0x20], 0x03: [0], 0x04: [1], 0x05: [], 0x06: [1], 0x07: [], 0x08: [],
    0x09: [], 0x0A: [], 0x0B: [1, 0xAA], 0x0C: [1, 5, 6], 0x0D: [], 0x0E: [], 0x0F: [], 0x11: [],
    0x12: [], 0x13: [0x0B, 5], 0x14: [], 0x17: [0, 1, 0xBB], 0x18: list(b'debug'), 0x1F: [],
    0x20: [], 0x21: [0, 1], 0x22: [], 0x23: [], 0x24: [], 0x25: [], 0x26: [], 0x27: [0, 3, 65],
    0x28: [0, 3, 66], 0x29: [0], 0x2A: [], 0x2B: [1], 0x2C: [1, 1], 0x2D: [], 0x2E: [],
    0x30: [20, 30, 0, 0], 0x31: [1, 1, 2, 3], 0x32: [7], 0x33: [0], 0x35: [1, 2],
    0x36: [0x41] + list(range(8)), 0x38: [1, 2, 3, 4], 0x39: [0, 0x20], 0x3A: [], 0x3B: [3], 0x3C: [],
    0x3D: [0], 0x3E: [6, 0x8A], 0x3F: [1], 0x40: [0], 0x41: [0], 0x42: [1], 0x43: [], 0x44: [1, 2],
    0x45: [1, 2, 3], 0x46: [], 0x47: [1, 2, 3], 0x48: [0], 0x49: [0, 0, 1], 0x4A: [1, 2], 0x4B: [],
    0x4C: [], 0x4D: [0], 0x4E: [0], 0x4F: [0], 0x50: [4],
}
T2S = dict(S2T)
T2S.update({
    0x03: [1], 0x04: [1, 2, 3], 0x13: [0, 5, 6], 0x1F: [0x07, 1], 0x20: [1], 0x21: [0, 1, 0x23, 0x20, 0, 5, 0x6B],
    0x22: [1], 0x23: [1, 1], 0x24: [0x21, 0x43, 0x65, 0x87], 0x26: [1], 0x27: [], 0x28: [], 0x29: [1],
    0x2A: [1], 0x2B: [1, 2], 0x2D: [1], 0x50: [0, 1, 2, 3, 4],
})
# NOE messages (opcodes 0x15 and 0x16): the bodies of messages from the NOE capture
NOE_S2T = ua(0x15, bytes([0x00, 0x01, 0x05, 0x01, 0x02]))
NOE_T2S = ua(0x16, bytes([0x80, 0x85, 0x00, 0x07, 0x37, 0x02, 0x4F, 0x4B]))
UNKNOWN = (0x10, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x2F, 0x34, 0x37, 0x51, 0x60, 0x7E)


def build_main(g):
    g.sec('System to terminal: every opcode UA hands to UA3G (one message per datagram)')
    for op, body in S2T.items():
        g.s2t(ua(op, body))
    g.end()
    g.sec('Terminal to system: the same opcodes')
    for op, body in T2S.items():
        g.t2s(ua(op, body))
    g.end()
    g.sec('The CP bit (0x80) is ignored when the opcode is chosen')
    g.s2t(ua(0x80 | 0x3F, [1]), ua(0x80 | 0x00))
    g.t2s(ua(0x80 | 0x03, [1]), ua(0x80 | 0x02))
    g.end()
    g.sec('NOE messages (opcodes 0x15 and 0x16) go to the NOE dissector')
    g.s2t(NOE_S2T)
    g.t2s(NOE_T2S)
    g.s2t(NOE_S2T, ua(0x00), NOE_S2T)
    g.end()
    g.sec('Opcodes UA does not pass on: "UA3G Message ERR", the body is shown as data')
    for op in UNKNOWN:
        g.s2t(ua(op, [1, 2, 3]))
    g.t2s(ua(0x19, [9]))
    g.t2s(ua(0xFF))
    g.end()
    g.sec('Several UA messages in one datagram, of mixed kinds')
    g.s2t(ua(0x00), ua(0x3F, [1]), ua(0x60, [1]), NOE_S2T, ua(0x21, [3, 1]), ua(0x13, [0x0B, 5]))
    g.t2s(ua(0x01), ua(0x02), ua(0x19), ua(0x03, [9]))
    g.end()


def build_malformed(g):
    g.sec('Truncated messages and framing errors')
    g.s2t(struct.pack('<H', 200) + b'\x3f\x01')            # message longer than the data
    g.s2t(b'\x01')                                          # one octet only
    g.s2t(struct.pack('<H', 0))                              # length 0, no opcode
    g.s2t(struct.pack('<H', 0) + b'\x00')                    # length 0 with an opcode octet after it
    g.s2t(ua(0x3F, [1]) + b'\x05')                           # trailing octet
    g.s2t(ua(0x00) + struct.pack('<H', 3))                   # second message without an opcode
    g.s2t(ua(0x15, [0x00]))                                  # NOE message too short
    g.s2t(ua(0x13, [0x01]))
    g.t2s(ua(0x13, [0x02, 0x00, 0x05, 1]))
    g.end()


def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    g = Gen()
    build_main(g)
    g.pc.write(os.path.join(out, 'ua-coverage.pcap'))
    if verbose:
        print('main: %d frames' % len(g.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))
    del sections[:]
    m = Gen()
    build_malformed(m)
    m.pc.write(os.path.join(out, 'ua-coverage-malformed.pcap'))
    if verbose:
        print('malformed: %d frames' % len(m.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))


if __name__ == '__main__':
    main()
