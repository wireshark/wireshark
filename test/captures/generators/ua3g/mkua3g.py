#!/usr/bin/env python3
# Generates test/captures/ua3g_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Generate the UA3G coverage captures (synthetic).

usage: mkua3g.py OUTDIR [-v]

UA3G messages are carried in UA/UDP data packets on UDP port 32000
(registered by default). The UDP destination port is 32000 for messages
from the system to the terminal, the source port for the other direction.
Writes ua3g-coverage.pcap and ua3g-coverage-malformed.pcap.
'''
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from u9lib import Pcap, Pcapng, udp, epdu

SYS = [192, 0, 2, 10]      # call server
TERM = [192, 0, 2, 50]     # terminal
RTPPEER = [192, 0, 2, 77]
PORT = 32000

sections = []


def ua(op, body=b''):
    m = bytes([op]) + bytes(body)
    return struct.pack('<H', len(m)) + m


def ua_raw(length, op, body=b''):
    return struct.pack('<H', length) + bytes([op]) + bytes(body)


def data(msgs, exp=1, snt=1):
    return bytes([7]) + struct.pack('!HH', exp, snt) + b''.join(msgs)


class Gen:
    def __init__(self, pc=None):
        self.pc = pc if pc is not None else Pcap(1)
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

    def raw(self, src, dst, sp, dp, payload):
        return self.pc.add(udp(src, dst, sp, dp, payload))


def tlv(i, v):
    if isinstance(v, int):
        v = bytes([v])
    return bytes([i, len(v)]) + bytes(v)


def be(n, size):
    return n.to_bytes(size, 'big')


IP4 = lambda a, b, c, d: bytes([a, b, c, d])


def build_main(g):
    # ------------------------------------------------------------------
    g.sec('UAUDP Connect / keepalive (carries the UA3G messages)')
    g.raw(TERM, SYS, PORT, 40000, bytes([0]) + tlv(0, be(0x01020304, 4)) + tlv(1, 8) + tlv(2, be(1500, 2)))
    g.raw(SYS, TERM, 40000, PORT, bytes([1]))
    g.end()

    # ------------------------------------------------------------------
    g.sec('System to terminal: messages with one parameter or none')
    for op in (0x00, 0x05, 0x07, 0x08, 0x09, 0x0D, 0x0E, 0x0F, 0x11, 0x12, 0x14, 0x22, 0x23,
               0x24, 0x25, 0x26, 0x2A, 0x2D, 0x2E, 0x3A, 0x43, 0x46, 0x4B, 0x4C):
        g.s2t(ua(op))
    # opcodes with one parameter, with and without the parameter, the CP bit
    for op in (0x01, 0x06, 0x2B, 0x3B, 0x42, 0x03, 0x04):
        g.s2t(ua(op, [0x01]), ua(op))
    g.s2t(ua(0x80 | 0x03, [0x00]), ua(0x80 | 0x04, [0x01]), ua(0x80 | 0x2B, [0x05]))
    g.s2t(ua(0x02, [0x01, 0x20]), ua(0x02, [0x02, 0x21, 1, 2, 3, 4]))
    g.end()

    # ------------------------------------------------------------------
    g.sec('Super message, segment message, debug in line (both directions)')
    g.s2t(ua(0x0B, [3, 1, 2, 3, 0, 2, 9, 9]))
    g.s2t(ua(0x17, [0, 3, 1, 2, 3, 0, 0, 0, 2, 9, 9]))
    g.t2s(ua(0x0B, [1, 0xAA]))
    g.t2s(ua(0x17, [0, 1, 0xBB]))
    g.s2t(ua(0x0C, [0x80 | 0x02] + list(be(300, 2)) + [1, 2, 3, 4]))
    g.s2t(ua(0x0C, [0x01, 5, 6, 7]))
    g.s2t(ua(0x0C, [0x00]))
    g.t2s(ua(0x0C, [0x80 | 0x01] + list(be(10, 2)) + [1, 2]))
    g.s2t(ua(0x18, b'debug text from the system'))
    g.t2s(ua(0x18, b'debug text from the terminal'))
    g.end()

    # ------------------------------------------------------------------
    g.sec('System to terminal: IP device routing (opcode 0x13)')
    ipd = lambda cmd, body=b'': ua(0x13, bytes([cmd]) + bytes(body))
    # Reset
    g.s2t(ipd(0x00))
    g.s2t(ipd(0x00, tlv(0x00, 0xFF)))                         # update mode: all flags
    g.s2t(ipd(0x00, tlv(0x00, 0x00)))                         # update mode: none
    g.s2t(ipd(0x00, tlv(0x00, 0x80)))                         # not the new format
    g.s2t(ipd(0x00, tlv(0x00, bytes([0x01, 0x02]))))          # longer value
    g.s2t(ipd(0x00, tlv(0x01, 0x01)))
    g.s2t(ipd(0x00, tlv(0x02, b'custom')))
    g.s2t(ipd(0x00, tlv(0x03, b'l10n')))
    g.s2t(ipd(0x00, tlv(0x04, 0x01)))
    g.s2t(ipd(0x00, tlv(0x05, b'sipname')))
    g.s2t(ipd(0x00, tlv(0x06, 0x01)))
    g.s2t(ipd(0x00, tlv(0x7E, b'\x01\x02\x03')))
    g.s2t(ipd(0x00, tlv(0x03, b'')))
    # Start RTP: parameters in one big message
    start_ids = [(0x00, be(20000, 2)), (0x02, be(30000, 2)), (0x03, 0xB8), (0x04, 0x00),
                 (0x05, 20), (0x06, 1), (0x07, 0), (0x08, 5), (0x09, 0), (0x0A, 1), (0x0B, 1),
                 (0x0C, be(0x01020304, 4)), (0x0D, 1), (0x0E, 7), (0x0F, 8), (0x10, be(30001, 2)),
                 (0x12, be(30003, 2)), (0x14, 3), (0x15, 1), (0x16, 96), (0x17, 101), (0x18, 1),
                 (0x31, 1), (0x32, bytes(range(16))), (0x33, bytes(range(14))),
                 (0x34, bytes(range(16))), (0x35, bytes(range(14))), (0x36, 1), (0x37, be(5, 4)),
                 (0x38, be(6, 4)), (0x39, 2), (0x50, bytes(range(16))), (0x7F, b'\x01\x02\x03')]
    ipids = [(0x01, IP4(192, 0, 2, 77)), (0x11, IP4(192, 0, 2, 78)), (0x13, IP4(192, 0, 2, 79))]
    for d in (0, 1, 2):
        g.s2t(ipd(0x01, bytes([d]) + tlv(0x04, 0x01)))
    g.s2t(ipd(0x01, bytes([2]) + b''.join(tlv(i, v) for i, v in ipids + start_ids[:12])))
    g.s2t(ipd(0x01, bytes([0]) + b''.join(tlv(i, v) for i, v in start_ids[12:])))
    # values longer than 8 octets for the ids that print them as numbers (bytes branch)
    long9 = bytes(range(1, 10))
    g.s2t(ipd(0x01, bytes([1]) + b''.join(tlv(i, long9) for i in (0x04, 0x06, 0x07, 0x0A, 0x0B, 0x0D,
                                                                   0x0E, 0x0F, 0x15, 0x18, 0x31, 0x00))))
    # RTP: only IP, no port (no conversation); IP and port (conversation); port first
    g.s2t(ipd(0x01, bytes([1]) + tlv(0x01, IP4(192, 0, 2, 80))))
    g.s2t(ipd(0x01, bytes([1]) + tlv(0x02, be(40000, 2)) + tlv(0x01, IP4(192, 0, 2, 77))))
    g.s2t(ipd(0x01, bytes([1]) + tlv(0x01, IP4(192, 0, 2, 77)) + tlv(0x02, be(0, 2))))
    # Stop RTP
    g.s2t(ipd(0x02, tlv(0x0E, 7) + tlv(0x0F, be(8, 4)) + tlv(0x14, bytes(range(9))) + tlv(0x01, 0)))
    g.s2t(ipd(0x02))
    # Redirect
    g.s2t(ipd(0x03, tlv(0x00, IP4(192, 0, 2, 11)) + tlv(0x01, be(2000, 2)) + tlv(0x02, IP4(192, 0, 2, 12))
              + tlv(0x05, bytes(range(9))) + tlv(0x06, be(1, 4))))
    # Tone definition and start/stop
    g.s2t(ipd(0x04, bytes([2]) + be(425, 2) + bytes([0xF6]) + be(0, 2) + bytes([0xEC])
              + be(440, 2) + bytes([0xF0]) + be(480, 2) + bytes([0xE8])))
    g.s2t(ipd(0x04, bytes([0])))
    g.s2t(ipd(0x05, bytes([1, 2]) + bytes([3]) + be(200, 2) + bytes([4]) + be(300, 2)))
    g.s2t(ipd(0x05, bytes([0, 0])))
    g.s2t(ipd(0x06))
    # Start / stop listen RTP
    g.s2t(ipd(0x07, tlv(0x00, IP4(192, 0, 2, 50)) + tlv(0x01, be(1, 2)) + tlv(0x02, be(2, 2))
              + tlv(0x03, IP4(192, 0, 2, 51)) + tlv(0x04, 3) + tlv(0x09, bytes(range(10)))))
    g.s2t(ipd(0x08, tlv(0x04, 3)))
    # Get / set parameters
    g.s2t(ipd(0x09, bytes([0x00, 0x01, 0x02, 0x03, 0x0A, 0x0B])))
    sp = [(0x00, 0xB8), (0x01, be(100, 2)), (0x02, 5), (0x03, b'contact'), (0x04, b'sysname'),
          (0x05, b'location'), (0x06, 0x01), (0x07, b'net down'), (0x08, b'cable'), (0x09, b'try'),
          (0x0A, b'connected'), (0x0B, b'reset'), (0x0C, b'duplicate'), (0x0D, b'community'),
          (0x0E, 1), (0x0F, IP4(192, 0, 2, 20)), (0x10, b'1234'), (0x11, 2), (0x12, 1), (0x13, 0xFF),
          (0x14, 1), (0x15, b'sess'), (0x16, 1), (0x17, 3), (0x18, 1), (0x19, 1), (0x1A, 1),
          (0x1B, 3), (0x1C, b'fr'), (0x1D, 1), (0x1E, 2), (0x1F, b'sshpw'), (0x20, 1), (0x21, 1),
          (0x22, 1), (0x23, 2), (0x24, 3), (0x25, 1), (0x26, 1), (0x30, bytes(range(16))),
          (0x7E, bytes(range(9))), (0x7D, 2)]
    for i in range(0, len(sp), 14):
        g.s2t(ipd(0x0A, b''.join(tlv(a, b) for a, b in sp[i:i + 14])))
    g.s2t(ipd(0x0A, tlv(0x14, b'')))
    g.s2t(ipd(0x0B, [0x05]))
    g.s2t(ipd(0x0C, tlv(0x14, 3) + tlv(0x7F, bytes(range(9)))))
    g.s2t(ipd(0x0D, tlv(0x14, 3)))
    # Start / stop record RTP
    rec = (tlv(0x00, 1) + tlv(0x01, IP4(192, 0, 2, 77)) + tlv(0x02, be(41000, 2)) + tlv(0x03, be(41002, 2))
           + tlv(0x04, IP4(192, 0, 2, 78)) + tlv(0x05, be(1, 2)) + tlv(0x06, be(2, 2)) + tlv(0x07, 0xB8)
           + tlv(0x08, bytes(range(16))) + tlv(0x09, bytes(range(14))) + tlv(0x10, 1) + tlv(0x11, 2)
           + tlv(0x30, bytes(range(16))) + tlv(0x7F, bytes(range(10))))
    g.s2t(ipd(0x0E, rec))
    g.s2t(ipd(0x0F, rec))
    g.s2t(ipd(0x0E, tlv(0x01, IP4(192, 0, 2, 81))))
    g.s2t(ipd(0x0F, tlv(0x00, 1)))
    g.s2t(ipd(0x10))
    # Free seating
    g.s2t(ipd(0x11, tlv(0x00, bytes([2, 0, 0, 0, 0, 1])) + tlv(0x01, IP4(192, 0, 2, 30))
              + tlv(0x02, bytes(range(1, 17))) + tlv(0x01, bytes(range(3))) + tlv(0x03, 1)
              + tlv(0x09, 5) + tlv(0x0A, bytes(range(12)))))
    # Application parameters
    g.s2t(ipd(0x14, tlv(0x00, b'app') + tlv(0x01, 1) + tlv(0x02, b'http://192.0.2.9/a')
              + tlv(0x05, 7) + tlv(0x06, bytes(range(12)))))
    g.s2t(ipd(0x12, [1, 2, 3]))
    g.end()

    # ------------------------------------------------------------------
    g.sec('System to terminal: display, LED and voice commands')
    for c in range(0, 9):
        g.s2t(ua(0x21, [c] + ([c + 1] if c < 7 else [])))
    for op in (0x27, 0x28):
        g.s2t(ua(op, [0x00, 0x03, ord('H'), ord('i')]))
        g.s2t(ua(op, [0xF1, 0x00] + list(b'Write')))
        g.s2t(ua(op, [0x02, 0x09] + list(b'Append')))
        g.s2t(ua(op, [0xFF, 0x00] + list(b'Timer')))
    g.s2t(ua(0x26))
    for m in (0x00, 0x01, 0x10, 0x11, 0x12, 0x13, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x7F):
        body = [m]
        if m == 0x06:
            body += [2, 3, 4, 5]
        elif m in (0x02, 0x03, 0x04, 0x05):
            body += [4, 5]
        elif m == 0x11 or m in (0x12, 0x13):
            body += [0x20, 0x41]
        g.s2t(ua(0x29, body))
    g.s2t(ua(0x29, [0x03, 4]))                       # no microphone volume
    g.s2t(ua(0x29, [0x06, 1, 7, 6]))
    g.s2t(ua(0x2C, [0x01, 0x01]))
    g.s2t(ua(0x2C, [0x02, 0x00]))
    g.s2t(ua(0x30, [20, 30, 0, 0]))
    g.s2t(ua(0x30, [20, 30, 1, 5]))
    g.s2t(ua(0x31, [0x00, 12, 30, 15, 1, 2, 3]))
    g.s2t(ua(0x31, [0x01, 23, 59, 59]))
    g.s2t(ua(0x31, [0x02, 0, 10, 5]))
    g.s2t(ua(0x31, [0x03]))
    g.s2t(ua(0x32, [0x07]))
    g.s2t(ua(0x32, [0x01, 0x02]))
    g.s2t(ua(0x32, [0x01, 0x02, 0x03, 0x04]))
    g.s2t(ua(0x32, [0x01, 0x02, 0x03]))
    for c in (0, 1, 2, 3):
        g.s2t(ua(0x33, [c]))
    g.s2t(ua(0x35, [1, 0x02]))
    g.s2t(ua(0x35, [2, 0x00]))
    g.s2t(ua(0x36, [0x41] + list(range(8))))
    g.s2t(ua(0x36, [0x41] + list(range(8)) + [0x42] + list(range(8, 16))))
    g.s2t(ua(0x38, [1, 2, 3, 4]))
    g.s2t(ua(0x39, [0x00, 0x20]))
    g.s2t(ua(0x39, [0x01, 0x10]))
    g.end()

    # ------------------------------------------------------------------
    g.sec('System to terminal: beep, tones, audio')
    g.s2t(ua(0x3C))
    g.s2t(ua(0x3C, [0x01, 0x03, 0x8A, 0x14, 0xFF]))
    g.s2t(ua(0x3C, [0x02, 0x01, 0xFF]))
    g.s2t(ua(0x3C, [0x03]))
    g.s2t(ua(0x3C, [0x04, 0xFF, 0x05]))
    g.s2t(ua(0x3C, [0x04, 0x00, 0x00]))
    g.s2t(ua(0x3C, [0x05, 0x10, 2] + [0x20, 0x30, 0x40, 0x21, 0x31, 0x41, 0xFE]))
    g.s2t(ua(0x3C, [0x05, 0x50, 1] + [0x20, 0x30, 0x40, 0xFD]))
    g.s2t(ua(0x3C, [0x05, 0x44, 1] + [0x20, 0x30, 0x40, 0xFF]))
    g.s2t(ua(0x3C, [0x09]))
    g.s2t(ua(0x3D, [0x00]))
    g.s2t(ua(0x3D, [0x01, 0x0A]))
    g.s2t(ua(0x3D, [0x01, 0xF6]))
    g.s2t(ua(0x3E, [0x06, 0x8A, 0x0A, 0x8A, 0x14]))
    g.s2t(ua(0x3E, [0x07, 0x7F]))
    g.s2t(ua(0x3F, [0x00]))
    g.s2t(ua(0x3F, [0x01]))
    g.s2t(ua(0x40, [0x00]))
    g.s2t(ua(0x40, [0x01, 0x10, 5]))
    g.s2t(ua(0x40, [0x01, 0xF0]))
    g.s2t(ua(0x44, [0x12, 0x34]))
    g.s2t(ua(0x45, [0x12, 0x34, 0x56]))
    g.s2t(ua(0x47, [3, 0xAA, 0x55]))
    g.s2t(ua(0x49, [0x00, 0x01, 0x00]))
    g.s2t(ua(0x49, [0x01, 1, 2, 3, 4, 5]))
    g.s2t(ua(0x49, [0x02, 1, 2, 3, 4, 5, 6, 7]))
    g.s2t(ua(0x49, [0x03] + list(range(10, 20))))
    g.s2t(ua(0x49, [0x04, 0x03]))
    g.s2t(ua(0x49, [0x04, 0x00]))
    g.s2t(ua(0x49, [0x05] + list(range(1, 12))))
    g.s2t(ua(0x49, [0x06, 0x00, 0x1F, 0x05, 0x15, 0x0A]))
    g.s2t(ua(0x49, [0x09, 1, 2]))
    g.s2t(ua(0x4A, [0xF6, 0x0A]))
    for op in (0x41, 0x48, 0x4D, 0x4E):
        g.s2t(ua(op, [0x00]))
        g.s2t(ua(op, [0x01, 0x05]))
        g.s2t(ua(op, [0x01]))
    g.s2t(ua(0x4F, [0x00]))
    g.s2t(ua(0x4F, [0x01, 3, 2, 5, 7, 0x81]))
    g.s2t(ua(0x4F, [0x01, 3, 2, 5, 7, 0x00]))
    g.end()

    # ------------------------------------------------------------------
    g.sec('UA download protocol (both directions)')
    g.t2s(ua(0x50, [0x00, 0x01, 0x12, 0x34, 0x05]))
    g.s2t(ua(0x50, [0x01, 0x01, 0x00, 0x01, 0x23, 0x0F, 0x07, 0x03, 0x23, 0x00, 0x10, 0x00]))   # request, not R1
    g.s2t(ua(0x50, [0x01, 0x00, 0x02, 0x01, 0x23, 0x05, 0xFF, 0x03, 0x1B, 0x00, 0x10, 0x00]))
    g.t2s(ua(0x50, [0x02, 0x00, 0x05, 0x00]))
    g.t2s(ua(0x50, [0x02, 0x00, 0x06, 0xFF]))
    g.s2t(ua(0x50, [0x03, 0x00, 0x05, 0x10, 0x11, 0x12]))
    g.s2t(ua(0x50, [0x04]))
    g.t2s(ua(0x50, [0x05, 0x00]))
    g.s2t(ua(0x50, [0x06, 0x12, 0x34, 0x56, 0x78]))
    g.t2s(ua(0x50, [0x07, 0x30]))
    g.s2t(ua(0x50, [0x09, 1, 2]))
    g.end()

    # ------------------------------------------------------------------
    g.sec('Terminal to system: simple messages, keys, status')
    for op in (0x00, 0x01, 0x02, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0D, 0x0E, 0x0F, 0x11, 0x12, 0x27, 0x28):
        g.t2s(ua(op))
    g.t2s(ua(0x03, [0x35]))
    g.t2s(ua(0x04, [0x01, 0x02, 0x03, 4, 5]))
    g.t2s(ua(0x04, [0x01, 0x02, 0x03]))
    for op in (0x20, 0x26, 0x2A, 0x2D):
        g.t2s(ua(op, [0x21]))
        g.t2s(ua(op))
    g.t2s(ua(0x22, [0x07]))
    g.t2s(ua(0x23, [0x81, 0xFF]))
    g.t2s(ua(0x23, [0x00, 0x00]))
    g.t2s(ua(0x29, [0xA5]))
    g.t2s(ua(0x24, [0x21, 0x43, 0x65, 0x87]))
    g.t2s(ua(0x2B, [0x12, 0x34]))
    g.t2s(ua(0x2B, [0x12, 0x34, 0x56]))
    g.end()

    # ------------------------------------------------------------------
    g.sec('Terminal to system: IP device routing (opcode 0x13)')
    ips = lambda cmd, body=b'': ua(0x13, bytes([cmd]) + bytes(body))
    g.t2s(ips(0x00, [0x21, 0x07]))
    g.t2s(ips(0x01, [0x05]))
    g.t2s(ips(0x01, [0x05, 0x06, 0x07]))
    g.t2s(ips(0x02, tlv(0x00, be(0x0102, 2)) + tlv(0x01, bytes([1, 2, 3])) + tlv(0x02, IP4(192, 0, 2, 50))
              + tlv(0x03, IP4(192, 0, 2, 51)) + tlv(0x04, IP4(255, 255, 255, 0)) + tlv(0x05, IP4(192, 0, 2, 1))
              + tlv(0x06, IP4(192, 0, 2, 2)) + tlv(0x07, IP4(192, 0, 2, 3)) + tlv(0x08, 0x00)
              + tlv(0x08, bytes(range(9))) + tlv(0x09, bytes([3, ord('F')])) + tlv(0x09, bytes([2, ord('H'), 3, ord('F')]))
              + tlv(0x09, bytes([1, 2, 3])) + tlv(0x0A, bytes(range(6))) + tlv(0x0B, bytes(range(6, 12)))
              + tlv(0x7E, 5) + tlv(0x7F, bytes(range(10)))))
    cs3 = [(0x01, be(0x1234, 4)), (0x02, be(5, 2)), (0x03, 1), (0x06, be(0x0102, 2)),
           (0x08, IP4(192, 0, 2, 50)), (0x09, IP4(192, 0, 2, 77)), (0x0A, b'local-id'), (0x0B, b'remote-id'),
           (0x0C, be(61, 4)), (0x0D, be(1, 4)), (0x0E, be(2, 4)), (0x0F, 1), (0x10, 1), (0x11, 0),
           (0x12, 0x51), (0x13, 20), (0x14, 30), (0x15, 2), (0x16, be(1000, 4)), (0x17, be(999, 4)),
           (0x18, be(1, 4)), (0x19, be(2, 4)), (0x1A, be(3, 4)),
           (0x1B, b''.join(be(i, 2) for i in range(5))), (0x1C, be(80, 2)), (0x1D, be(4, 2)),
           (0x1E, b''.join(be(i, 2) for i in range(10))), (0x1F, b''.join(be(i, 2) for i in range(5))),
           (0x20, b''.join(be(i, 4) for i in range(10))), (0x21, be(0, 2)), (0x26, be(0x0102, 2)),
           (0x29, 20), (0x2A, 1), (0x2D, be(10, 2)), (0x2E, 1), (0x2F, 5), (0x30, be(100, 2)),
           (0x31, 0xB8), (0x37, 1), (0x3D, b''.join(be(i, 2) for i in range(5))),
           (0x3E, b''.join(be(i, 2) for i in range(5))), (0x7F, b'\x01\x02')]

    def tlv3(i, v):
        if isinstance(v, int):
            v = bytes([v])
        return bytes([i]) + struct.pack('!H', len(v)) + v
    for i in range(0, len(cs3), 12):
        g.t2s(ips(0x03, b''.join(tlv3(a, b) for a, b in cs3[i:i + 12])))
    g.t2s(ips(0x03, tlv3(0x06, b'')))
    g.t2s(ips(0x04, [1, 2]))
    g.end()

    # ------------------------------------------------------------------
    g.sec('Terminal to system: unsolicited messages and version responses')
    for op in (0x9F, 0x1F):
        g.t2s(ua(op, [0x00, 0x00, 0x01, 0x23, 0x00, 0x03, 0x23, 0x00, 0x21, 0x01]))     # VTA type 3
        g.t2s(ua(op, [0x01, 0x00, 0x01, 0x23, 0x00, 0x04, 0x23, 0x00, 0x21, 0x00]))
    g.t2s(ua(0x9F, [0x00, 0x00, 0x01, 0x23, 0x00, 0x05, 0x23, 0x01, 0x21, 0x01]))
    # link TDM
    g.t2s(ua(0x9F, [0x00, 0x00, 0x01, 0x23, 0x00, 0x20, 0x00, 0x05, 0x6B, 0x01]))
    g.t2s(ua(0x9F, [0x00, 0x00, 0x01, 0x23, 0x00, 0x20, 0x00, 0x05, 0x6B, 0x01, 0x04, 0x56]))
    g.t2s(ua(0x9F, [0x00, 0x00, 0x01, 0x23, 0x00, 0x20, 0x00, 0x05, 0x6B, 0x01, 0x04, 0x56, 0x07, 0x89]))
    # link IP
    ipbase = [0x00, 0x00, 0x01, 0x23, 0x00, 0x20, 0x01, 0x01, 0xFF, 0x01]
    g.t2s(ua(0x9F, ipbase))
    g.t2s(ua(0x9F, ipbase + [0x12, 0x34, 0x56, 0x78]))
    g.t2s(ua(0x9F, ipbase + [0x12, 0x34, 0x56, 0x78, 0x31]))
    g.t2s(ua(0x9F, ipbase + [0x12, 0x34, 0x56, 0x78, 0x31, 0x01]))
    g.t2s(ua(0x9F, ipbase + [0x12, 0x34, 0x56, 0x78, 0x31, 0x01, 0x07]))
    g.t2s(ua(0x9F, ipbase + [0x12, 0x34, 0x56, 0x78, 0x31, 0x01, 0x07, 0x01]))
    g.t2s(ua(0x9F, ipbase + [0x12, 0x34, 0x56, 0x78, 0x31, 0x01, 0x07, 0x01, 0xEE, 0xDD]))
    g.t2s(ua(0x9F, [0x02, 0x44, 0x01, 0x02, 0x03]))
    g.t2s(ua(0x9F, [0x02, 0x44]))
    g.t2s(ua(0x9F, [0x05, 0x03]))
    g.t2s(ua(0x9F, [0x06, 0xF5, 0x12, 0x34]))
    g.t2s(ua(0x9F, [0x07, 0x02]))
    g.t2s(ua(0x9F, [0x03]))
    # version responses (opcode 0x21): no self test or hook status
    g.t2s(ua(0x21, [0x00, 0x01, 0x23, 0x03, 0x23, 0x00, 0x21]))
    g.t2s(ua(0x21, [0x00, 0x01, 0x23, 0x20, 0x00, 0x05, 0x6B]))
    g.t2s(ua(0x21, [0x00, 0x01, 0x23, 0x20, 0x01, 0x01, 0xFF]))
    g.t2s(ua(0x21, [0x00, 0x01, 0x23, 0x20, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00]))
    g.end()

    # ------------------------------------------------------------------
    g.sec('Several messages in one datagram, empty data and unknown opcodes')
    g.s2t(ua(0x00), ua(0x3F, [1]), ua(0x21, [0, 1]), ua(0x13, [0x0B, 9]))
    g.t2s(ua(0x01), ua(0x02), ua(0x03, [9]))
    g.raw(SYS, TERM, 40000, PORT, bytes([7]) + struct.pack('!HH', 5, 5))                   # Data ACK
    g.raw(TERM, SYS, PORT, 40000, bytes([7]) + struct.pack('!HH', 5, 6))
    g.s2t(ua(0x60, [1, 2, 3]))                  # UA layer: unknown opcode
    g.t2s(ua(0x19, [1]))
    g.s2t(ua(0x7F))
    g.end()



def build_malformed(g):
    g.sec('Truncated and inconsistent messages')
    # message shorter than its fields
    g.s2t(ua_raw(1, 0x13))                            # IP device routing with no command
    g.s2t(ua(0x13, [0x01]))                           # start RTP without direction
    g.s2t(ua(0x13, [0x01, 0x00, 0x00, 0x04, 1, 2]))   # parameter longer than the message
    g.s2t(ua(0x13, [0x01, 0x00, 0x01, 0x04, 1, 2]))   # IP address cut short
    g.s2t(ua(0x13, [0x00, 0x02, 0x09, 1]))            # reset parameter longer than the message
    g.s2t(ua(0x13, [0x0A, 0x1C, 0x02, 0x41]))         # language id cut short
    g.s2t(ua(0x13, [0x0A, 0x0F, 0x02, 1, 2]))         # TFTP backup IP cut short
    g.s2t(ua(0x13, [0x04, 0x03, 0x01]))               # tone definition truncated
    g.s2t(ua(0x13, [0x05, 0x00, 0x05, 0x01, 0x00]))   # start tone truncated
    g.s2t(ua(0x13, [0x03, 0x00, 0x02, 1, 2]))
    g.s2t(ua(0x13, [0x07, 0x00, 0x02, 1, 2]))
    g.s2t(ua(0x13, [0x11, 0x00, 0x03, 1, 2, 3]))      # pseudo MAC cut short
    g.s2t(ua(0x13, [0x09]))
    g.s2t(ua(0x13, [0x0B]))
    g.s2t(ua(0x0B, [5, 1]))                           # super message
    g.s2t(ua(0x17, [0, 9, 1]))
    g.s2t(ua(0x0C))                                   # segment message without a header
    g.s2t(ua(0x0C, [0x80, 0x01]))
    g.s2t(ua(0x50, [0x01, 0x80, 0x01, 0x02, 0x03]))
    g.s2t(ua(0x50, [0x01, 0x01]))
    # "R1" layout (item, version, binary info, length): the branch for it is
    # reached only for a body of at most 2 octets after the version and
    # then reads 4 octets
    g.s2t(ua(0x50, [0x01, 0x00, 0x01, 0x23, 0x80, 0x00, 0x20, 0x00]))
    g.s2t(ua(0x50, [0x01, 0x00, 0x01, 0x23, 0x80, 0x00]))
    g.s2t(ua(0x50, [0x01, 0x00, 0x01, 0x23, 0x01, 0x02, 0x03, 0x04, 0x05]))
    g.s2t(ua(0x30, [20, 30, 0]))                      # DTMF format: country octet read past the end
    g.t2s(ua(0x9F, [0x00, 0x00, 0x01, 0x23, 0x00, 0x20, 0x00]))
    g.t2s(ua(0x21, [0x00, 0x01, 0x23, 0x20, 0x00, 0x05]))
    g.t2s(ua(0x23, [0x81]))
    g.s2t(ua(0x3C, [0x05, 0x10, 2] + [0x20, 0x30, 0x40, 0xFE, 0x21, 0x31, 0x41, 0xFF]))
    g.s2t(ua(0x21))                                   # LED command without a command
    g.s2t(ua(0x27, [0x00]))
    g.s2t(ua(0x29, [0x11]))
    g.s2t(ua(0x29, [0x06, 1]))
    g.s2t(ua(0x2C, [0x01]))
    g.s2t(ua(0x30, [0x01]))
    g.s2t(ua(0x31, [0x00, 1]))
    g.s2t(ua(0x36, [0x41, 1, 2]))
    g.s2t(ua(0x38, [1, 2]))
    g.s2t(ua(0x3C, [0x01]))
    g.s2t(ua(0x3C, [0x05, 1, 3, 1]))
    g.s2t(ua(0x3C, [0x04, 1]))
    g.s2t(ua(0x3E, [0x01]))
    g.s2t(ua(0x47, [1]))
    g.s2t(ua(0x49, [0x03, 1]))
    g.s2t(ua(0x49, [0x01, 1]))
    g.s2t(ua(0x4F, [0x01, 1]))
    g.s2t(ua(0x50, [0x03]))
    g.s2t(ua(0x50, [0x01, 1, 0, 1, 2]))
    g.s2t(ua(0x50, [0x06]))
    g.s2t(ua(0x02, [0x01]))
    g.t2s(ua(0x04, [0x01]))
    g.t2s(ua(0x13, [0x02, 0x00, 0x05, 1]))
    g.t2s(ua(0x13, [0x02, 0x02, 0x02, 1, 2]))
    g.t2s(ua(0x13, [0x03, 0x06, 0x00, 0x05, 1]))
    g.t2s(ua(0x13, [0x03, 0x08, 0x00, 0x02, 1, 2]))
    g.t2s(ua(0x13, [0x00, 0x01]))
    g.t2s(ua(0x9F, [0x00, 0x00, 0x01]))
    g.t2s(ua(0x9F, [0x06, 0x01]))
    g.t2s(ua(0x9F, []))
    g.t2s(ua(0x2B, [0x12]))
    g.t2s(ua(0x24, [0x21]))
    g.end()
    # ------------------------------------------------------------------
    g.sec('RTP and RTCP to the address learned from Start RTP: only decoded when the tree was built in the first pass (one pass yes, -2 no)')
    ipd = lambda cmd, body=b'': ua(0x13, bytes([cmd]) + bytes(body))
    g.s2t(ipd(0x01, bytes([1]) + tlv(0x02, be(30000, 2)) + tlv(0x01, IP4(192, 0, 2, 77))))
    rtp = bytes([0x80, 0x00]) + struct.pack('!HII', 1, 160, 0x1234) + bytes(20)
    g.raw(SYS, RTPPEER, 20000, 30000, rtp)
    g.raw(SYS, RTPPEER, 20000, 30000, bytes([0x80, 0x00]) + struct.pack('!HII', 2, 320, 0x1234) + bytes(20))
    rtcp = bytes([0x80, 200, 0, 6]) + struct.pack('!I', 0x1234) + bytes(20)
    g.raw(SYS, RTPPEER, 20001, 30001, rtcp)
    g.end()
    g.sec('Exported PDU without the direction data (the UA3G dissector refuses it)')
    g.pc.add(epdu('ua3g', ua(0x3F, [1])), 1)
    g.end()
    g.sec('UA framing errors')
    g.s2t(ua_raw(200, 0x3F, [1]))                     # message length beyond the datagram
    g.s2t(b'\x01')                                    # a UA message of one octet
    g.raw(SYS, TERM, 40000, PORT, bytes([7, 0, 1, 0, 1, 0]))   # UA length field cut short
    g.raw(SYS, SYS, 40000, 40001, bytes([7, 0, 1, 0, 1]) + ua(0x3F, [1]))   # direction unknown
    g.end()


def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    g = Gen()
    build_main(g)
    g.pc.write(os.path.join(out, 'ua3g-coverage.pcap'))
    nmain = len(g.pc)
    if verbose:
        print('main: %d frames' % nmain)
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))
    del sections[:]
    m = Gen(Pcapng([1, 252]))
    build_malformed(m)
    m.pc.write(os.path.join(out, 'ua3g-coverage-malformed.pcapng'))
    if verbose:
        print('malformed: %d frames' % len(m.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))


if __name__ == '__main__':
    main()
