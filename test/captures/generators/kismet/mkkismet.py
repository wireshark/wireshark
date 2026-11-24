#!/usr/bin/env python3
# Generates test/captures/kismet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Kismet client/server protocol coverage captures.

Usage: mkkismet.py <outdir>

  kismet-coverage.pcap            a TCP stream to port 2501: banner,
                                  requests, responses with several
                                  lines, continuation data
  kismet-coverage-malformed.pcap  invalid *TIME values, short *KISMET
                                  lines
Synthetic: built with struct only.
"""
import os
import struct
import sys

CMAC = bytes.fromhex('020000000002')
SMAC = bytes.fromhex('020000000001')
PORT = 2501
A, B = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])


def csum(b):
    if len(b) & 1:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Conn:
    def __init__(self, cport=41000):
        self.cport = cport
        self.cseq, self.sseq = 1000, 5000
        self.out = []

    def seg(self, to_server, data=b'', flags=0x18):
        if to_server:
            sp, dp, s, a, src, dst = self.cport, PORT, self.cseq, self.sseq, A, B
        else:
            sp, dp, s, a, src, dst = PORT, self.cport, self.sseq, self.cseq, B, A
        opts = struct.pack('!BBH', 2, 4, 1460) + b'\x04\x02\x01\x03\x03\x07\x01\x01' if flags & 2 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, s, a if flags & 0x10 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + data
        tcp = tcp[:16] + struct.pack('!H', csum(src + dst + struct.pack('!BBH', 0, 6, len(tcp)) + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), len(self.out) + 1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.out.append(((CMAC + SMAC) if to_server else (SMAC + CMAC)) + b'\x08\x00' + ip + tcp)
        adv = len(data) + (1 if flags & 3 else 0)
        if to_server:
            self.cseq += adv
        else:
            self.sseq += adv

    def handshake(self):
        self.seg(True, flags=0x02)
        self.seg(False, flags=0x12)
        self.seg(True, flags=0x10)

    def close(self):
        self.seg(True, flags=0x11)
        self.seg(False, flags=0x11)
        self.seg(True, flags=0x10)


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


BANNER = b'*KISMET: 0.0.0.0 1700000000 \x01kismet-server\x01 20110301 1 2011-03-R1\n'


def main(out):
    c = Conn()
    c.handshake()
    # Banner: the version, start time, server name, build revision, an
    # undocumented field and the extended version
    c.seg(False, BANNER)
    # The second and later lines are decoded too (before the fix a stale
    # pointer made them tokenize the first line again)
    c.seg(False, b'*PROTOCOLS: KISMET,ERROR,ACK,PROTOCOLS,CAPABILITY,TERMINATE,TIME\n'
                 b'*TIME: 1700000100\n'
                 + BANNER)
    # Requests
    c.seg(True, b'!0 REMOVE TIME\n')
    c.seg(True, b'!1 CAPABILITY NETWORK bssid,ssid,channel\n!2 ENABLE NETWORK bssid,ssid\n')
    # Responses
    c.seg(False, b'*ACK: 1\n')
    c.seg(False, b'*TIME: 1700000200\n')
    c.seg(False, b'*TIME: 1700000300\r\n*ACK: 2 \r\n')
    c.seg(False, b'*CAPABILITY: NETWORK bssid,ssid,channel\n*NETWORK: 00:11:22:33:44:55 "ssid"  6\n')
    # a blank line in the middle and no end of line at the end
    c.seg(False, b'*NETWORK: 00:11:22:33:44:66 x 1\n\n*NETWORK: 00:11:22:33:44:77 y 11')
    # a *TIME line with a time of a different size
    c.seg(False, b'*TIME: 0\n*TIME: 4102444800\n')
    # a status line starting with "!"
    c.seg(False, b'!1 ERROR: unknown command\n')
    # a continuation: data that starts with something else
    c.seg(False, b'00:11:22:33:44:88 more network data\n')
    # a request with a final line without an end of line
    c.seg(True, b'!3 PING 1')
    # not Kismet: too short a line, and unprintable bytes
    c.seg(True, b'!4 OK\n')
    c.seg(False, b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\n')
    c.close()
    pcap(os.path.join(out, 'kismet-coverage.pcap'), c.out)

    m = Conn(cport=41001)
    m.handshake()
    # *TIME that is not a number, and one that does not fit 64 bits
    m.seg(False, b'*TIME: notatime\n')
    m.seg(False, b'*TIME: 99999999999999999999\n')
    # *TIME with the time out of range for the time string
    m.seg(False, b'*TIME: 18446744073709551615\n')
    # *KISMET with fewer fields than expected
    m.seg(False, b'*KISMET: 0.0.0.0\n')
    m.seg(False, b'*KISMET: 0.0.0.0 1700000000 \x01s\x01\n')
    m.seg(False, b'*KISMET:\n')
    m.seg(False, b'*TIME:\n')
    pcap(os.path.join(out, 'kismet-coverage-malformed.pcap'), m.out)


if __name__ == '__main__':
    main(sys.argv[1])
