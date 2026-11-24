#!/usr/bin/env python3
# Generates test/captures/ddtp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DDTP dissector
(packet-ddtp.c, Dynamic DNS Tools Protocol).

All packets are built from scratch with struct; no captured traffic is
used. A dynamic DNS client (192.0.2.10) talks to its server
(192.0.2.20) on UDP port 1052, the port DDTP registers by default.

Usage: mkddtp.py <output directory>

Writes:
  ddtp-coverage.pcap            every version, encryption type, message
                                type, opcode and status, packets with an
                                unknown version or too short for DDTP
  ddtp-coverage-malformed.pcap  plain text messages cut short
"""

import os
import struct
import sys

CLIENT = '192.0.2.10'
SERVER = '192.0.2.20'
PORT = 1052


def ipcsum(h):
    s = sum(struct.unpack('!%dH' % (len(h) // 2), h))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def udp4(payload, src, dst, sport, dport, ipid):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    sa = bytes(int(x) for x in src.split('.'))
    da = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ipid & 0xffff, 0,
                    64, 17, 0, sa, da)
    h = h[:10] + struct.pack('!H', ipcsum(h)) + h[12:]
    macs = (b'\x02\x00\x00\x00\x00\x14\x02\x00\x00\x00\x00\x0a' if src == CLIENT
            else b'\x02\x00\x00\x00\x00\x0a\x02\x00\x00\x00\x00\x14')
    return macs + b'\x08\x00' + h + u


class Pcap:
    def __init__(self):
        self.frames = []

    def q(self, payload):
        """client to server"""
        self.frames.append(udp4(payload, CLIENT, SERVER, PORT, PORT, len(self.frames) + 1))

    def r(self, payload):
        """server to client"""
        self.frames.append(udp4(payload, SERVER, CLIENT, PORT, PORT, len(self.frames) + 1))

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)


# version: 0 protocol error, 1 = "4", 2 = "5"
# encryption: 0 error, 1 plain text, 2 blowfish
# message type: 0 error, 1 update query, 2 update reply, 3 alive query, 4 alive reply

def hdr(version, encrypt, hostid):
    return struct.pack('!III', version, encrypt, hostid)


def plain(msgtype, *words, version=2, hostid=4242):
    return hdr(version, 1, hostid) + struct.pack('!I', msgtype) + b''.join(words)


def u32(v):
    return struct.pack('!I', v)


def ip(a):
    return bytes(int(x) for x in a.split('.'))


def main(outdir):
    m = Pcap()
    m.q(plain(1, u32(0), ip('198.51.100.7')))       # 1: update query, mark online
    m.r(plain(2, u32(0)))                           # 2: update reply, succeeded
    m.q(plain(1, u32(1), ip('198.51.100.8')))       # 3: update query, mark offline
    m.r(plain(2, u32(1)))                           # 4: failed
    m.r(plain(2, u32(2)))                           # 5: invalid password
    m.r(plain(2, u32(3)))                           # 6: invalid account
    m.r(plain(2, u32(4)))                           # 7: invalid opcode
    m.q(plain(1, u32(7), ip('198.51.100.9')))       # 8: unknown opcode 7
    m.r(plain(2, u32(9)))                           # 9: unknown status 9
    m.q(plain(3, u32(0x1234)))                      # 10: alive query
    m.r(plain(4, u32(0x1234)))                      # 11: alive reply
    m.r(plain(0))                                   # 12: message error
    m.r(plain(9))                                   # 13: unknown message type (expert warning)
    m.q(hdr(2, 2, 4242) + bytes(range(0x30, 0x48)))  # 14: Blowfish encrypted payload
    m.q(hdr(2, 0, 4242))                            # 15: encryption error
    m.q(plain(3, u32(1), version=1, hostid=17))     # 16: version 4, alive query
    m.r(plain(4, u32(1), version=1, hostid=17))     # 17: version 4, alive reply
    m.r(plain(0, version=0, hostid=0))              # 18: version 0 (protocol error)
    m.q(hdr(3, 1, 4242) + u32(3) + u32(0))          # 19: unknown version 3: not DDTP
    m.q(b'\x00\x00\x02')                            # 20: 3 octets: not DDTP
    m.write(os.path.join(outdir, 'ddtp-coverage.pcap'))

    b = Pcap()
    b.q(plain(1, u32(0)))                           # 1: update query without the address
    b.r(plain(2))                                   # 2: update reply without the status
    b.q(plain(3))                                   # 3: alive query without the dummy word
    b.r(hdr(2, 1, 4242))                            # 4: plain text without a message type
    b.q(struct.pack('!II', 2, 1))                   # 5: no host id
    b.write(os.path.join(outdir, 'ddtp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
