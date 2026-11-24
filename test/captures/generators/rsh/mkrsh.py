#!/usr/bin/env python3
# Generates test/captures/rsh_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the RSH coverage captures: mkrsh.py <outdir>
# Every packet is built with struct; nothing comes from a real network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from pk import Cap, Tcp

def conv(cap, port):
    t = Tcp(cap, port, 514)
    t.handshake()
    return t

def main(out):
    cap = Cap()
    # A: the whole setup in one packet, then data in both directions
    t = conv(cap, 1021)
    t.c(b'1022\0alice\0bob\0uptime\0')
    t.s(b'\0')
    t.c(b'input line\n')
    t.s(b'up 3 days\n')
    t.s(b'no terminating null')
    t.fin()
    # B: setup split into one field per packet (also the empty stderr port)
    t = conv(cap, 1020)
    t.c(b'\0')
    t.c(b'carol\0')
    t.c(b'root\0')
    t.c(b'ls -l /tmp\0')
    t.s(b'\0')
    t.s(b'total 0\n')
    t.c(b'more\n')
    t.fin()
    # C: stderr port is not a number, so the packet is data
    t = conv(cap, 1019)
    t.c(b'abc\0def\0')
    t.s(b'reply\n')
    # D: client username longer than 16 -> data; then a conversation
    t = conv(cap, 1018)
    t.c(b'0\0' + b'x' * 17 + b'\0')
    t.c(b'0\0al\x01ce\0')          # (same conversation, already data)
    t = conv(cap, 1017)
    t.c(b'0\0al\x01ce\0')          # unprintable client username -> data
    # E: empty server username, command follows
    t = conv(cap, 1016)
    t.c(b'0\0dave\0\0whoami\0')
    # F: empty command -> data
    t = conv(cap, 1015)
    t.c(b'0\0erin\0frank\0\0')
    # G: six digit stderr port -> data
    t = conv(cap, 1014)
    t.c(b'123456\0')
    # H: unprintable server username is skipped, command follows
    t = conv(cap, 1013)
    t.c(b'0\0gina\0bo\x02b\0date\0')
    # I: command longer than 256 -> data
    t = conv(cap, 1012)
    t.c(b'0\0hank\0ivy\0' + b'y' * 300 + b'\0')
    # J: setup split across packets: port+client, server+command
    t = conv(cap, 1011)
    t.c(b'2000\0jane\0')
    t.c(b'kim\0echo hi\0')
    t.s(b'hi\n')
    # K: first packet comes from the server
    t = Tcp(cap, 1010, 514)
    t.handshake()
    t.s(b'banner\n')
    t.c(b'0\0lee\0max\0true\0')
    # L: setup stops after the client username; later packets are server username/command
    t = conv(cap, 1009)
    t.c(b'0\0ned\0')
    t.c(b'oz\0')
    t.c(b'pwd\0')
    t.c(b'data after\n')
    t.c(b'data after2\n')
    cap.write(os.path.join(out, 'rsh-coverage.pcap'))

    # Malformed: truncated frames (captured payload shorter than reported)
    cap = Cap()
    t = conv(cap, 1100)
    t.c(b'0\0alice\0bob\0ls\0', trunc=6)
    t = conv(cap, 1101)
    t.c(b'7777\0' + b'z' * 10, trunc=10)
    t.c(b'tail data\n', trunc=20)
    cap.write(os.path.join(out, 'rsh-coverage-malformed.pcap'))

main(sys.argv[1])
