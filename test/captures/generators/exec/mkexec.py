#!/usr/bin/env python3
# Generates test/captures/exec_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EXEC (rexec) dissector
(packet-exec.c).

rexec runs over TCP port 512, registered by default. The client sends
NUL terminated strings: optional stderr port, user name, password and
command; everything after that is session data. The dissector decides
per packet which field it sees from a per conversation state machine.
Every packet is built from scratch with struct.

Usage: mkexec.py <output directory>

Writes:
  exec-coverage.pcap            conversations with all fields in one
                                packet, one field per packet, empty and
                                invalid fields (treated as data), data in
                                both directions
  exec-coverage-malformed.pcap  frames cut short inside a string
"""
import os
import struct
import sys


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (fr, orig) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), orig))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Conv:
    def __init__(self, cport, v6=False):
        self.cport = cport
        self.cseq = 1000
        self.sseq = 5000

    def pkt(self, to_server, payload, trunc=None):
        cmac, smac = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
        c, s = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
        if to_server:
            sp, dp, src, dst, seq, ack = self.cport, 512, c, s, self.cseq, self.sseq
            self.cseq += len(payload)
            em = smac + cmac
        else:
            sp, dp, src, dst, seq, ack = 512, self.cport, s, c, self.sseq, self.cseq
            self.sseq += len(payload)
            em = cmac + smac
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, 0x18, 65535, 0, 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        fr = em + b'\x08\x00' + ip + tcp
        if trunc is not None:
            return (fr[:trunc], len(fr))
        return (fr, len(fr))


C, S = True, False


def main_frames():
    F = []
    # C1: everything in one packet, then data both ways
    c = Conv(40001)
    F.append(c.pkt(C, b'\0root\0secret\0uptime\0'))
    F.append(c.pkt(S, b'up 1 day\n'))
    F.append(c.pkt(C, b'q'))
    F.append(c.pkt(S, b'\0'))          # ends with NUL, state stays data
    F.append(c.pkt(S, b'bye\n'))
    # C2: one field per packet, stderr port given
    c = Conv(40002)
    F.append(c.pkt(C, b'1234\0'))
    F.append(c.pkt(C, b'alice\0'))
    F.append(c.pkt(C, b'pw\0'))
    F.append(c.pkt(C, b'echo hi\0'))
    F.append(c.pkt(S, b'hi\n'))
    F.append(c.pkt(C, b'x\n'))
    # C3: empty stderr port, empty password (skipped)
    c = Conv(40003)
    F.append(c.pkt(C, b'\0'))
    F.append(c.pkt(C, b'bob\0'))
    F.append(c.pkt(C, b'\0'))
    F.append(c.pkt(C, b'ls -l\0'))
    F.append(c.pkt(S, b'total 0\n'))
    # C4: first string not numeric: all data
    c = Conv(40004)
    F.append(c.pkt(C, b'abc\0'))
    F.append(c.pkt(S, b'Login incorrect\n'))
    # C5: stderr port too long (6 octets with the NUL)
    c = Conv(40005)
    F.append(c.pkt(C, b'123456\0'))
    F.append(c.pkt(S, b'\1error\n'))
    # C6: user name too long
    c = Conv(40006)
    F.append(c.pkt(C, b'\0reallylongusername123\0'))
    F.append(c.pkt(S, b'\1bad\n'))
    # C7: user name not printable
    c = Conv(40007)
    F.append(c.pkt(C, b'\0\x01\x02\0pw\0cmd\0'))
    F.append(c.pkt(C, b'more'))
    # C8: password too long (not shown), command follows
    c = Conv(40008)
    F.append(c.pkt(C, b'\0u\0' + b'x' * 20 + b'\0cmd\0'))
    F.append(c.pkt(S, b'ok'))
    # C9: command too long
    c = Conv(40009)
    F.append(c.pkt(C, b'\0u\0p\0' + b'c' * 300 + b'\0'))
    F.append(c.pkt(S, b'ok'))
    # C10: command empty; password and command split from user
    c = Conv(40010)
    F.append(c.pkt(C, b'\0carol\0'))
    F.append(c.pkt(C, b'pw\0\0'))
    F.append(c.pkt(S, b'no\n'))
    # C11: user, password and command with port in packet 1; the fourth
    #      packet is data; a fifth and sixth follow
    c = Conv(40011)
    F.append(c.pkt(C, b'7\0'))
    F.append(c.pkt(C, b'dave\0pw\0'))
    F.append(c.pkt(C, b'who\0'))
    F.append(c.pkt(S, b'dave tty1\n'))
    F.append(c.pkt(C, b'\0'))
    F.append(c.pkt(S, b'\n'))
    # C12: the reproducer of "Exec: Build the Info column after parsing
    #      the packet": user learned in packet 1, command not printable
    #      (data); Info of packet 1 must not depend on the pass.
    c = Conv(40012)
    F.append(c.pkt(C, b'\0root\0pw\0\x01\x02\0'))
    F.append(c.pkt(S, b'output\n'))
    # C13: user name that is also the only field, not NUL terminated
    c = Conv(40013)
    F.append(c.pkt(C, b'\0erin'))
    F.append(c.pkt(S, b'ok'))
    return F


def malformed_frames():
    F = []
    c = Conv(41001)
    # reported length larger than captured, no NUL in what was captured
    F.append(c.pkt(C, b'\0root\0pw\0' + b'a' * 40, trunc=14 + 20 + 20 + 12))
    c = Conv(41002)
    F.append(c.pkt(C, b'\0root\0pw\0cmd', trunc=14 + 20 + 20 + 6))
    c = Conv(41003)
    F.append(c.pkt(C, b'12\0' + b'u' * 10 + b'\0', trunc=14 + 20 + 20 + 3))
    return F


def main():
    out = sys.argv[1]
    pcap(os.path.join(out, 'exec-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'exec-coverage-malformed.pcap'), malformed_frames())


main()
