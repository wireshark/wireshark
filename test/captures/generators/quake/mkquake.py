#!/usr/bin/env python3
# Generates test/captures/quake_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Quake (NetQuake, UDP 26000) coverage captures.
Usage: mkquake.py <outdir> [-v]"""
import struct
import sys
import os

class Pcap:
    def __init__(self, lt=1):
        self.lt = lt
        self.frames = []
    def add(self, data, ts=None):
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

def hdr(flags, total, seq=None):
    h = struct.pack('!HH', flags, total)
    if seq is not None:
        h += struct.pack('!I', seq)
    return h

def ctl(body):
    return hdr(0x8000, 4 + len(body)) + body

def z(s): return s.encode() + b'\0'

def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    verbose = '-v' in sys.argv
    m = Pcap(); bad = Pcap()
    marks = []
    def req(sport, dport, body, p=m, src=C, dst=S):
        p.add(udp4(src, dst, sport, dport, body))
    def rep(body, p=m):
        p.add(udp4(S, C, 26000, 27001, body))

    # Control requests
    req(27001, 26000, ctl(b'\x01' + z('QUAKE') + b'\x03'))              # 1 connect
    req(27001, 26000, ctl(b'\x02' + z('QUAKE') + b'\x03'))              # 2 server_info
    req(27001, 26000, ctl(b'\x03' + b'\x00'))                           # 3 player_info
    req(27001, 26000, ctl(b'\x04' + z('')))                             # 4 rule_info (first)
    req(27001, 26000, ctl(b'\x04' + z('sv_gravity')))                   # 5 rule_info
    # Replies
    rep(ctl(b'\x81' + struct.pack('<I', 26000)))                        # 6 accept
    rep(ctl(b'\x82' + z('Server is full.')))                            # 7 reject
    rep(ctl(b'\x83' + z('192.0.2.20:26000') + z('Example server') + z('e1m1') + bytes([3, 16, 3])))  # 8
    rep(ctl(b'\x84' + b'\x00' + z('Player One') + struct.pack('<III', 0x4d, 12, 345) + z('192.0.2.30:27500')))  # 9 colours 4,13
    rep(ctl(b'\x84' + b'\x01' + z('Two') + struct.pack('<III', 0x00, 0, 0) + z('')))  # 10 white
    rep(ctl(b'\x84' + b'\x02' + z('Three') + struct.pack('<III', 0xff, 1, 2) + z('x')))  # 11 brights
    rep(ctl(b'\x85' + z('sv_gravity') + z('800')))                      # 12 rule_info
    rep(ctl(b'\x85' + z('deathmatch') + z('1')))                        # 13
    rep(ctl(b'\x85'))                                                   # 14 empty rule info (no rule)
    rep(ctl(b'\x99' + b'abc'))                                          # 15 unknown reply command
    req(27001, 26000, ctl(b'\x55' + b'xyz'))                            # 16 unknown request command
    # Data frames
    req(27001, 26000, hdr(0x0001, 8 + 4, 0) + b'abcd')                  # 17 data
    req(27001, 26000, hdr(0x0009, 8 + 6, 1) + b'abcdef')                # 18 data + EOM
    rep(hdr(0x0002, 8, 1))                                              # 19 ack
    rep(hdr(0x0004, 8, 2))                                              # 20 nak
    req(27001, 26000, hdr(0x0010, 8 + 3, 0x01020304) + b'xyz')          # 21 unreliable
    req(27001, 26000, hdr(0x0019, 8 + 3, 0xfffffffe) + b'xyz')          # 22 data|eom|unreliable
    req(27001, 26000, hdr(0x8001, 8 + 2, 5) + b'ab')                    # 23 control bit plus data (not pure CTL)
    req(27001, 26000, hdr(0x0000, 8, 0))                                # 24 no flags, no payload
    # Frame sent in a non-default port pair: the accept conversation
    # (frames 6 and 25: the accept makes the 4-tuple a Quake conversation)
    m.add(udp4(S, C, 26000, 27002, ctl(b'\x81' + struct.pack('<I', 26001))))   # 25 accept to other client port
    m.add(udp4(C, S, 27002, 26000, hdr(0x0001, 8 + 2, 0) + b'zz'))     # 26 data on that conversation
    # a Quake packet from a port pair that is not 26000 (needs Decode As), not included
    n = len(m.frames)
    # Malformed
    req(27001, 26000, b'\x80', bad)                                     # truncated flags
    req(27001, 26000, b'\x80\x00\x00', bad)                             # truncated length
    req(27001, 26000, hdr(0x8000, 4), bad)                              # CTL without command
    req(27001, 26000, hdr(0x0001, 6), bad)                              # data header cut before seq
    req(27001, 26000, ctl(b'\x01' + b'QUAKE'), bad)                     # unterminated game string
    req(27001, 26000, ctl(b'\x01' + z('QUAKE')), bad)                   # missing version
    req(27001, 26000, ctl(b'\x02' + z('QUAKE')), bad)                   # missing version
    req(27001, 26000, ctl(b'\x03'), bad)                                # missing player
    rep(ctl(b'\x81' + b'\x01\x02'), bad)                                # accept cut short
    rep(ctl(b'\x81'), bad)                                              # accept no port
    rep(ctl(b'\x83' + z('a')), bad)                                     # server_info cut at server
    rep(ctl(b'\x83' + z('a') + z('b') + z('c')), bad)                   # cut at num_player
    rep(ctl(b'\x83' + z('a') + z('b') + z('c') + b'\x01\x02'), bad)     # cut at version
    rep(ctl(b'\x84' + b'\x00' + z('n') + b'\x01\x02'), bad)             # colors cut short
    rep(ctl(b'\x84' + b'\x00' + z('n') + struct.pack('<II', 1, 2)), bad)  # frags ok connect time cut
    rep(ctl(b'\x84' + b'\x00'), bad)                                    # no name
    rep(ctl(b'\x85' + z('rule')), bad)                                  # value missing
    rep(ctl(b'\x82'), bad)                                              # reject without reason
    m.write(os.path.join(out, 'quake-coverage.pcap'))
    bad.write(os.path.join(out, 'quake-coverage-malformed.pcap'))
    if verbose:
        print('main frames', n, 'malformed frames', len(bad.frames))

main()
