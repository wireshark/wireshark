#!/usr/bin/env python3
# Generates test/captures/quake2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Quake II (UDP 27910) coverage captures.
Usage: mkquake2.py <outdir> [-v]"""
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
CP, SP = 27901, 27910

def z(s): return s.encode() + b'\0'

def move(bits, angles=(), mv=(), buttons=None, impulse=None, msec=16, light=128):
    b = bytes([bits])
    for a in angles: b += struct.pack('<H', a)
    for v in mv: b += struct.pack('<h', v)
    if buttons is not None: b += bytes([buttons])
    if impulse is not None: b += bytes([impulse])
    return b + bytes([msec, light])

def clc_move(m1, m2, m3, lastframe=7, chk=0x5a):
    return b'\x02' + bytes([chk]) + struct.pack('<I', lastframe) + m1 + m2 + m3

def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    verbose = '-v' in sys.argv
    m = Pcap(); bad = Pcap()
    def c2s(payload, p=m):
        p.add(udp4(C, S, CP, SP, payload))
    def s2c(payload, p=m):
        p.add(udp4(S, C, SP, CP, payload))
    def game_c(seq, ack, cmds, qport=0x1234, p=m):
        c2s(struct.pack('<IIH', seq, ack, qport) + cmds, p)
    def game_s(seq, ack, cmds, p=m):
        s2c(struct.pack('<II', seq, ack) + cmds, p)
    OOB = b'\xff\xff\xff\xff'

    # Connectionless: client queries, server answers
    c2s(OOB + b'getchallenge\n')                                        # 1
    s2c(OOB + b'challenge 123456789')                                   # 2
    c2s(OOB + b'connect 34 4242 123456789 "\\name\\Player\\skin\\male/grunt"\n')  # 3
    s2c(OOB + b'client_connect\n')                                      # 4
    c2s(OOB + b'ping\n')                                                # 5
    s2c(OOB + b'ack')                                                   # 6
    s2c(OOB)                                                            # 7 empty text
    # Game packets, client to server
    game_c(1, 0, b'')                                                   # 8 no data
    game_c(2, 1, b'\x01')                                               # 9 clc_nop only
    game_c(0x80000003, 2, b'\x00\x01')                                  # 10 reliable seq; clc_bad then nop
    game_c(4, 0x80000002, b'\x03' + z('\\name\\Player\\rate\\25000'))   # 11 userinfo
    game_c(5, 4, b'\x04' + z('begin 1'))                                # 12 stringcmd
    game_c(6, 5, b'\x04' + z('say hello') + b'\x01' + b'\x04' + z('cmd 2'))  # 13 stringcmd, nop, stringcmd
    game_c(7, 6, b'\x09')                                               # 14 unknown command, nothing after
    game_c(8, 7, b'\x09' + b'\x01' + b'\x01')                           # 15 unknown, nop, nop
    # moves
    n0 = move(0)
    game_c(10, 9, clc_move(n0, n0, n0))                                 # 16 no moves
    game_c(11, 10, clc_move(move(0x01, (0x4000,)), move(0x02, (0x8000,)), move(0x04, (0xc000,))))   # 17 angles one at a time
    game_c(12, 11, clc_move(move(0x08, mv=(200,)), move(0x10, mv=(-200,)), move(0x20, mv=(100,))))  # 18 fwd, side, up
    game_c(13, 12, clc_move(move(0x40, buttons=1), move(0x40, buttons=2), move(0x40, buttons=0x83)))  # 19 buttons attack, use, any
    game_c(14, 13, clc_move(move(0x80, impulse=5), move(0xff, (1, 2, 3), (4, -5, 6), 0xff, 9, 1, 2), move(0x7f, (100, 200, 300), (-1, -2, -3), 0, msec=255, light=0)))  # 20 impulse, all bits, all but impulse
    game_c(15, 14, clc_move(move(0x40, buttons=0), move(0x40, buttons=0x80), move(0x40, buttons=4)) + b'\x04' + z('after move'))  # 21 buttons none, any, other; then stringcmd
    game_c(16, 15, clc_move(n0, n0, n0, lastframe=0xffffffff, chk=0xff) + b'\x01')  # 22 move then nop
    # Server to client
    game_s(1, 0, b'')                                                   # 23 no data
    game_s(0x80000002, 1, b'')                                          # 24 reliable
    names = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]
    for i, c in enumerate(names):                                       # 25-46 every server command (with data)
        game_s(10 + i, 9 + i, bytes([c]) + b'payload' + bytes([c]))
    game_s(40, 39, b'\x06')                                             # 47 svc_nop without data
    game_s(41, 40, b'\x14')                                             # 48 svc_frame without data
    game_s(0x80000007, 0x80000006, b'\x0b' + z('echo hi\n'))            # 49 stufftext, both reliable
    n = len(m.frames)
    # malformed
    c2s(b'\xff\xff\xff', bad)                                           # truncated marker
    c2s(b'\x01\x00', bad)                                               # no marker word
    c2s(b'\x01\x00\x00\x00\x01\x00\x00', bad)                           # second sequence cut
    c2s(struct.pack('<II', 1, 1) + b'\x01', bad)                        # qport cut
    game_c(1, 1, b'\x02', p=bad)                                        # move with no body
    game_c(1, 1, b'\x02\x00' + struct.pack('<I', 1) + move(0xff)[:6], p=bad)  # move cut inside the first move
    game_c(1, 1, b'\x02\x00' + struct.pack('<I', 1) + move(0) * 2, p=bad)  # only two moves
    game_c(1, 1, b'\x03' + b'noterminator', p=bad)                        # userinfo without NUL
    game_c(1, 1, b'\x04' + b'noterminator', p=bad)                        # stringcmd without NUL
    s2c(struct.pack('<I', 1), bad)                                      # server packet, second sequence missing
    s2c(b'\x01\x00', bad)
    m.write(os.path.join(out, 'quake2-coverage.pcap'))
    bad.write(os.path.join(out, 'quake2-coverage-malformed.pcap'))
    if verbose:
        print('main frames', n, 'malformed frames', len(bad.frames))

main()
