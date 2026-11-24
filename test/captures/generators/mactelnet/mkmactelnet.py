#!/usr/bin/env python3
# Generates test/captures/mactelnet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic MAC-Telnet captures.  Usage: mkmactelnet.py <outdir>
Writes mactelnet-coverage.pcap and mactelnet-coverage-malformed.pcap."""
import os
import struct
import sys

CLIENT = bytes.fromhex('020000000001')
SERVER = bytes.fromhex('020000000002')
MAGIC = 0x563412FF
T_MAC_TELNET, T_WINBOX = 0x0015, 0x0f90


def pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ip_udp(payload, src=CLIENT, dst=SERVER, sport=20561, dport=20561):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 255]))
    return dst + src + b'\x08\x00' + ip + udp


def ctl(ctype, data=b''):
    """A control packet: magic, type (1), length (4, big endian), data."""
    return struct.pack('>IBI', MAGIC, ctype, len(data)) + data


def pkt(ptype, ctype_off, session, counter, body=b'', client=True, ver=1):
    """MAC-Telnet packet.  Client -> server: session at 14, client type at 16;
    server -> client: client type at 14, session at 16."""
    src, dst = (CLIENT, SERVER) if client else (SERVER, CLIENT)
    if client:
        mid = struct.pack('>HH', session, ctype_off)
    else:
        mid = struct.pack('>HH', ctype_off, session)
    return bytes([ver, ptype]) + src + dst + mid + struct.pack('>I', counter) + body


def build():
    main, bad = [], []
    f = main.append

    def c2s(ptype, counter, body=b'', ct=T_MAC_TELNET, sess=0x1234):
        f(ip_udp(pkt(ptype, ct, sess, counter, body), CLIENT, SERVER))

    def s2c(ptype, counter, body=b'', ct=T_MAC_TELNET, sess=0x1234):
        f(ip_udp(pkt(ptype, ct, sess, counter, body, client=False), SERVER, CLIENT))

    # a MAC Telnet session
    c2s(0, 0)                                        # start session
    s2c(2, 0)                                        # acknowledge
    c2s(1, 0, ctl(0))                                # begin authentication
    s2c(2, 9)                                        # acknowledge
    s2c(1, 0, ctl(1, bytes(range(16))))              # encryption key
    c2s(2, 9)
    c2s(1, 9, ctl(2, b'\x00' + bytes(range(16))) + ctl(3, b'admin') + ctl(4, b'xterm')
        + ctl(5, struct.pack('<H', 132)) + ctl(6, struct.pack('<H', 43)))   # password, user, terminal, size
    s2c(2, 62)
    s2c(1, 9, ctl(9))                                # end authentication
    c2s(2, 71)
    s2c(1, 71, b'\r\nMikroTik v6.48\r\n')            # terminal data after control packets
    c2s(2, 88)
    c2s(1, 88, b'/system resource print\r\n')        # plain data
    s2c(1, 88, ctl(3, b'x' * 10) + b'tail data')     # control packet followed by data
    s2c(1, 100, ctl(7))                              # authentication failure (no decoding)
    s2c(1, 100, ctl(8))                              # server failure
    s2c(1, 100, ctl(0x7f))                           # unknown control type
    c2s(1, 100, ctl(2, b'\x11' * 17) + ctl(3, b'a'))
    # several control packets in one data packet
    c2s(1, 100, ctl(4, b'vt100') + ctl(9) + ctl(0))
    # data that starts with the magic number but is too short to be control
    c2s(1, 200, struct.pack('>I', MAGIC))
    # pings (the type decides, not the client type)
    f(ip_udp(pkt(4, 0, 0, 0)[:18] + b'ping-data'))            # ping request
    f(ip_udp(pkt(5, 0, 0, 0, client=False)[:18], SERVER, CLIENT))   # ping response, no data
    f(ip_udp(pkt(4, 0, 0, 0)[:18] + b'ping-data'))
    # winbox client type, both directions
    c2s(0, 0, ct=T_WINBOX, sess=0x4321)
    s2c(2, 0, ct=T_WINBOX, sess=0x4321)
    c2s(1, 5, b'winbox data', ct=T_WINBOX, sess=0x4321)
    # end session, an unknown packet type, protocol version 0
    c2s(255, 1000)
    s2c(255, 1000)
    c2s(3, 0)
    f(ip_udp(pkt(1, T_MAC_TELNET, 7, 5, b'ver0', ver=0)))
    # a control packet with a long username (length byte 200)
    c2s(1, 300, ctl(3, b'u' * 200))
    # reproducer of the control packet type fix: Username "admin"
    c2s(1, 400, ctl(3, b'admin'))

    # ---- malformed capture
    g = bad.append
    g(ip_udp(pkt(1, T_MAC_TELNET, 1, 1)[:17]))                       # too short: 17 bytes
    g(ip_udp(pkt(1, T_MAC_TELNET, 1, 1)[:20]))                       # counter cut short
    g(ip_udp(pkt(1, 0x1111, 1, 1, b'xxxx')))                           # no known client type
    g(ip_udp(pkt(1, T_MAC_TELNET, 1, 1, ctl(3, b'abc')[:-1])))         # username cut short
    g(ip_udp(pkt(1, T_MAC_TELNET, 1, 1, struct.pack('>IBI', MAGIC, 3, 250) + b'abc')))  # length past the end
    g(ip_udp(pkt(1, T_MAC_TELNET, 1, 1, ctl(5, b'\x84'))))             # width: one byte
    g(ip_udp(pkt(1, T_MAC_TELNET, 1, 1, ctl(6, b'\x2b'))))             # height: one byte
    g(ip_udp(pkt(1, T_MAC_TELNET, 1, 1, ctl(1, b'ab') + struct.pack('>I', MAGIC) + b'\x01')))
    g(ip_udp(pkt(1, T_MAC_TELNET, 1, 1, struct.pack('>IBI', MAGIC, 2, 300) + b'x' * 300)))  # length >= 256
    return main, bad


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m, b = build()
    pcap(os.path.join(out, 'mactelnet-coverage.pcap'), m)
    pcap(os.path.join(out, 'mactelnet-coverage-malformed.pcap'), b)
