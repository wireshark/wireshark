#!/usr/bin/env python3
# Generates test/captures/echo_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate a synthetic capture that exercises the Echo dissector
(packet-echo.c, RFC 862).

Echo runs on UDP and TCP port 7. A request goes to port 7, the echoed
response comes from it. Over UDP the dissector first tries Wake On LAN,
which also uses UDP port 7, and only then echo. Every packet is built
from scratch with struct; no captured traffic is used.

Usage: mkecho.py <output directory>

Writes:
  echo-coverage.pcap   UDP and TCP requests and responses, a
                       Wake On LAN magic packet to UDP port 7 (decoded as
                       WOL) and a UDP datagram that only starts like one
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, src, dst, payload, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000,
                      64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def eth(src, dst, payload):
    return dst + src + struct.pack('>H', 0x0800) + payload


def udp(fwd, sport, dport, data, ident):
    src, dst = (IP_A, IP_B) if fwd else (IP_B, IP_A)
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    ph = src + dst + struct.pack('>BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    m1, m2 = (MAC_A, MAC_B) if fwd else (MAC_B, MAC_A)
    return eth(m1, m2, ipv4(17, src, dst, u, ident))


def tcp(fwd, sport, dport, seq, ack, flags, data, ident):
    src, dst = (IP_A, IP_B) if fwd else (IP_B, IP_A)
    # SYN and SYN-ACK carry an MSS option
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                    65535, 0, 0) + opts + data
    ph = src + dst + struct.pack('>BBH', 0, 6, len(t))
    t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
    m1, m2 = (MAC_A, MAC_B) if fwd else (MAC_B, MAC_A)
    return eth(m1, m2, ipv4(6, src, dst, t, ident))


def main_frames():
    F = []
    # 1-2: UDP request to port 7 and its echo from port 7
    msg = b'Hello, echo server!\n'
    F.append(udp(True, 40000, 7, msg, 1))
    F.append(udp(False, 7, 40000, msg, 2))
    # 3: Wake On LAN magic packet to UDP port 7 (taken by WOL, not echo)
    target = bytes.fromhex('0200000000aa')
    F.append(udp(True, 40002, 7, b'\xff' * 6 + target * 16, 5))
    # 4: starts with the WOL synchronization stream, but no MAC repeated
    #    16 times: WOL rejects it, so it is an echo request
    F.append(udp(True, 40002, 7, b'\xff' * 6 + bytes(range(96)), 14))
    # 5-12: TCP connection to port 7: handshake, request, echo, close
    c, s = 1000, 5000
    F.append(tcp(True, 40003, 7, c, 0, 0x02, b'', 6))
    F.append(tcp(False, 7, 40003, s, c + 1, 0x12, b'', 7))
    F.append(tcp(True, 40003, 7, c + 1, s + 1, 0x10, b'', 8))
    data = bytes(range(256))
    F.append(tcp(True, 40003, 7, c + 1, s + 1, 0x18, data, 9))
    F.append(tcp(False, 7, 40003, s + 1, c + 1 + len(data), 0x18, data, 10))
    F.append(tcp(True, 40003, 7, c + 1 + len(data), s + 1 + len(data), 0x11, b'', 11))
    F.append(tcp(False, 7, 40003, s + 1 + len(data), c + 2 + len(data), 0x11, b'', 12))
    F.append(tcp(True, 40003, 7, c + 2 + len(data), s + 2 + len(data), 0x10, b'', 13))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'echo-coverage.pcap'), main_frames())


if __name__ == '__main__':
    main()
