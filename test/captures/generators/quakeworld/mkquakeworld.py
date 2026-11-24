#!/usr/bin/env python3
# Generates test/captures/quakeworld_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the QuakeWorld (UDP 27500) coverage captures.
Usage: mkquakeworld.py <outdir> [-v]"""
import struct
import sys
import os

class Pcap:
    def __init__(self, lt=1):
        self.lt = lt
        self.frames = []
    def add(self, data):
        self.frames.append(data)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.lt))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
                f.write(d)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def udp4(src, dst, sport, dport, payload):
    ulen = 8 + len(payload)
    udp = struct.pack('!HHHH', sport, dport, ulen, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + ulen, 1, 0, 64, 17, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = bytes.fromhex('020000000002020000000001') + b'\x08\x00'
    return eth + ip + udp

C, S = '192.0.2.10', '192.0.2.20'



CP, SP = 27001, 27500

def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    verbose = '-v' in sys.argv
    m = Pcap(); bad = Pcap()
    OOB = b'\xff\xff\xff\xff'
    def c2s(payload, p=m, sport=CP, dport=SP):
        p.add(udp4(C, S, sport, dport, payload))
    def s2c(payload, p=m, sport=SP, dport=CP):
        p.add(udp4(S, C, sport, dport, payload))
    def oc(text, p=m):          # connectionless, client to server, NUL terminated
        c2s(OOB + text + b'\0', p)
    def os_(text, p=m):         # connectionless, server to client
        s2c(OOB + text + b'\0', p)
    def game_c(seq, ack, data, qport=0x1234, p=m):
        c2s(struct.pack('<IIH', seq, ack, qport) + data, p)
    def game_s(seq, ack, data, p=m):
        s2c(struct.pack('<II', seq, ack) + data, p)

    # The reproducers of "QuakeWorld: Fix quadratic allocation in the command tokenizer"
    # (frames 1-6): the commands were never recognised, and one packet of
    # one-character tokens allocated about 1 GB
    oc(b'ping')                                                          # 1
    oc(b'status')                                                        # 2
    oc(b'connect 28 1234 5678 "\\name\\x\\team\\y"')                    # 3
    oc(b'"x"connect 28 1234 5678 "\\name\\x"')                          # 4 quoted token first, then connect (unknown command "x")
    oc(b'rcon pw status now')                                            # 5
    c2s(OOB + b'a ' * 32500 + b'\0')                                     # 6 about 64 kB of one-character tokens
    # Client to server commands
    oc(b'log')                                                           # 7
    oc(b'getchallenge')                                                  # 8
    oc(b'k')                                                             # 9 ping (single byte)
    oc(b'k\n')                                                           # 10
    oc(b'l')                                                             # 11 ack
    oc(b'l\n')                                                           # 12
    oc(b'kx')                                                            # 13 unknown (not a single byte)
    oc(b'unknown command here')                                          # 14
    oc(b'')                                                              # 15 empty text
    oc(b'\nping')                                                        # 16 newline first: no command
    oc(b'ping\nstatus')                                                  # 17 a newline ends the command
    oc(b'   \t  status  extra')                                          # 18 leading white space and control chars
    oc(b'//comment\nping')                                               # 19 comment then command
    oc(b'// only a comment')                                             # 20 comment to the end
    oc(b'"ping"')                                                        # 21 quoted
    oc(b'"ping')                                                         # 22 unterminated quote (also the report's quote reproducer)
    oc(b'"')                                                             # 23 a lone quote
    oc(b'"abc')                                                          # 24 the unterminated quoted token reproducer of the report
    # connect with its infostring in several shapes
    oc(b'connect 28 1234 5678 "\\name\\Player\\team\\red\\topcolor\\3\\bottomcolor\\4"')   # 25
    oc(b'connect 28 1234 5678 \\name\\Plain')                            # 26 unquoted infostring
    oc(b'connect 28 1234 5678 "name\\x\\skin\\base"')                    # 27 no leading backslash
    oc(b'connect 28 1234 5678 "\\onlykey"')                              # 28 key without value
    oc(b'connect 28 1234 5678 "\\name\\x\\"')                            # 29 trailing backslash
    oc(b'connect 28 1234 5678 ""')                                       # 30 empty infostring
    oc(b'connect 28 1234 5678')                                          # 31 no infostring
    oc(b'connect 28 1234 4294967295 "\\a\\b"')                           # 32 largest challenge (shown as -1)
    # rcon
    oc(b'rcon')                                                          # 33 no password
    oc(b'rcon secret')                                                   # 34 password only
    oc(b'rcon secret map e1m1')                                          # 35
    oc(b'rcon secret say "hello world" again')                           # 36 quoted argument
    oc(b'rcon secret ' + b' '.join([b'x' * 40] * 79))                     # 37 more than MAX_TEXT_SIZE of arguments
    oc(b'rcon' + b' a' * 100)                                            # 38 more tokens than MAX_ARGS
    # Server to client commands
    os_(b'j')                                                            # 39 connected
    os_(b'B' + b'say hi\0' + b'1\0')                                     # 40 client command (stringz, stringz)
    os_(b'n' + b'Server message\n')                                      # 41 print
    os_(b'k')                                                            # 42 ping
    os_(b'c')                                                            # 43 challenge
    os_(b'c' + b'12345678')                                              # 44 challenge with a value
    os_(b'x' + b'whatever')                                              # 45 unknown
    os_(b'')                                                             # 46 empty
    # Game packets
    game_c(1, 0, b'')                                                    # 47
    game_c(0x80000002, 1, b'\x01\x02\x03')                               # 48 reliable
    game_c(3, 0x80000002, b'abcdefgh')                                   # 49 acknowledges reliable
    game_s(1, 0, b'')                                                    # 50
    game_s(0x80000002, 1, b'xyz')                                        # 51
    game_s(0x7fffffff, 0xfffffffe, b'data')                              # 52
    n = len(m.frames)
    # Malformed
    # a connect with fields that are not numbers (error expert info)
    oc(b'connect x y z "\\a\\b"', bad)
    oc(b'connect 28 70000 5678 "\\a\\b"', bad)
    oc(b'connect', bad)
    oc(b'connect 28 1234 -5678 "\\a\\b"', bad)                          # negative challenge is not a uint32
    # real text without NUL: FT_STRINGZ is malformed without a terminator
    c2s(OOB + b'ping', bad)
    s2c(OOB + b'j', bad)
    c2s(OOB, bad)
    c2s(b'\xff\xff', bad)
    c2s(b'\x01', bad)
    c2s(b'\x01\x00\x00\x00\x01\x00\x00', bad)
    c2s(struct.pack('<II', 1, 1) + b'\x01', bad)
    s2c(struct.pack('<I', 1), bad)
    m.write(os.path.join(out, 'quakeworld-coverage.pcap'))
    bad.write(os.path.join(out, 'quakeworld-coverage-malformed.pcap'))
    if verbose:
        print('main frames', n, 'malformed frames', len(bad.frames))

main()
