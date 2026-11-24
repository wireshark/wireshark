#!/usr/bin/env python3
# Generates test/captures/quake3_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Quake III Arena (UDP 27960, master 27950) coverage captures.
Usage: mkquake3.py <outdir> [-v]"""
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

C, S, M = '192.0.2.10', '192.0.2.20', '192.0.2.30'



CP, SP, MP = 27901, 27960, 27950

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
    def c2m(payload, p=m):
        p.add(udp4(C, M, CP, MP, payload))
    def m2c(payload, p=m):
        p.add(udp4(M, C, MP, CP, payload))
    def game_c(seq, ack, data, qport=0x1234, p=m, dport=SP):
        c2s(struct.pack('<HHH', seq, ack, qport) + data, p, dport=dport)
    def game_s(seq, ack, data, p=m, sport=SP):
        s2c(struct.pack('<HH', seq, ack) + data, p, sport=sport)

    # Server queries and replies (frames 1-14)
    c2s(OOB + b'getstatus xyz' + b'\0')                                       # 1
    s2c(OOB + b'statusResponse\n\\sv_hostname\\Example\\mapname\\q3dm1\n0 0 "Player"\n' + b'\0')  # 2
    c2s(OOB + b'getinfo xyz' + b'\0')                                         # 3
    s2c(OOB + b'infoResponse\n\\challenge\\xyz\\hostname\\Example' + b'\0')   # 4
    c2s(OOB + b'getchallenge' + b'\0')                                        # 5
    s2c(OOB + b'challengeResponse 1234567' + b'\0')                           # 6
    c2s(OOB + b'connect "\\challenge\\1234567\\name\\Player"' + b'\0')        # 7
    s2c(OOB + b'connectResponse' + b'\0')                                     # 8
    c2s(OOB + b'rcon secret status' + b'\0')                                  # 9
    s2c(OOB + b'rconResponse\nmap: q3dm1' + b'\0')                            # 10
    c2s(OOB + b'unknowncommand' + b'\0')                                      # 11 unknown
    s2c(OOB + b'\0')                                                 # 12 marker only
    c2s(OOB + b'getstatus' + b'\0', dport=27961)                              # 13 second server port
    s2c(OOB + b'statusResponse' + b'\0', sport=27963)                         # 14 last server port
    # Master server (15-26)
    c2m(OOB + b'getmotd' + b'\0')                                             # 15
    m2c(OOB + b'getmotdResponse\n\\challenge\\1\\motd\\Hello' + b'\0')         # 16
    c2m(OOB + b'getservers 68 empty full' + b'\0')                            # 17
    def srv(ip, port):
        return b'\\' + bytes(map(int, ip.split('.'))) + struct.pack('!H', port)
    m2c(OOB + b'getserversResponse' + srv('192.0.2.20', 27960) + srv('192.0.2.21', 27961) + srv('198.51.100.7', 27960) + b'\\EOT\0\0\0')  # 18 three servers, end marker
    m2c(OOB + b'getserversResponse' + b'\0')                                  # 19 no servers
    m2c(OOB + b'getserversResponse' + srv('192.0.2.22', 27962) + b'\\\\\\\0')  # 20 one server plus a short tail
    c2m(OOB + b'getKeyAuthorize 0 ABCD' + b'\0')                              # 21
    c2m(OOB + b'getIpAuthorize 1234 192.0.2.10' + b'\0')                      # 22
    m2c(OOB + b'ipAuthorize 1234 accept' + b'\0')                             # 23
    c2m(OOB + b'getservers 68\0')                                     # 24 (master port 27951 below)
    m.add(udp4(C, M, CP, 27951, OOB + b'getmotd\0'))                # 25 master port base + 1
    m.add(udp4(M, C, 27953, CP, OOB + b'ipAuthorize\0'))             # 26 master port base + 3
    # Game packets (27-40)
    game_c(1, 0, b'')                                                 # 27 no data
    game_c(0x8002, 1, b'\x01\x02\x03\x04')                            # 28 reliable, with data
    game_c(3, 0x8002, b'abcdefgh')                                    # 29 ack of reliable
    game_s(1, 0, b'')                                                 # 30 server no data
    game_s(0x8002, 1, b'\x05\x06\x07')                                # 31 server reliable, data
    game_s(0x7fff, 0x7fff, b'xyz')                                    # 32 maximum sequence numbers
    game_c(0xffff, 0xfffe, b'\0', dport=27962)                        # 33 on another server port
    game_s(2, 1, b'data', sport=27961)                                # 34 from another server port
    n = len(m.frames)
    # Malformed
    # Real Quake III traffic has no NUL after the text of a connectionless
    # packet, which the FT_STRINGZ text item turns into a malformed packet
    c2s(OOB + b'getstatus', bad)
    s2c(OOB + b'infoResponse\n\\hostname\\x', bad)
    m2c(OOB + b'getserversResponse', bad)
    c2s(OOB, bad)
    c2s(b'\xff\xff', bad)
    c2s(b'\x01', bad)
    c2s(b'\x01\x00\x01', bad)                                         # second sequence cut
    c2s(b'\x01\x00\x01\x00\x34', bad)                                 # qport cut
    s2c(b'\x01\x00\x01', bad)                                         # S2C second sequence cut
    s2c(b'', bad)
    m.write(os.path.join(out, 'quake3-coverage.pcap'))
    bad.write(os.path.join(out, 'quake3-coverage-malformed.pcap'))
    if verbose:
        print('main frames', n, 'malformed frames', len(bad.frames))

main()
