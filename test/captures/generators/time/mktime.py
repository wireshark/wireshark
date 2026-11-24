#!/usr/bin/env python3
# Generates test/captures/time_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the TIME protocol dissector
(packet-time.c): requests and responses over UDP and TCP port 37.

Usage: mktime.py <output directory>

Writes:
  time-coverage.pcap            UDP and TCP requests and responses with
                                several time values
  time-coverage-malformed.pcap  responses shorter than 4 octets
"""

import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def eth(payload, ethertype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', ethertype) + payload


def udp(sport, dport, payload, rev=False):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if rev:
        return eth(ip4(17, u, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(17, u))


def tcp(sport, dport, seq, ack, payload, flags=0x18, rev=False):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + payload
    if rev:
        return eth(ip4(6, t, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(6, t))


def main_frames():
    F = []
    # 1-2: UDP request (empty) and response (1 Jan 1970 = 2208988800)
    F.append(udp(50000, 37, b''))
    F.append(udp(37, 50000, struct.pack('>I', 2208988800), rev=True))
    # 3-4: UDP request with a payload and a response in 2024
    F.append(udp(50001, 37, b'x'))
    F.append(udp(37, 50001, struct.pack('>I', 2208988800 + 1705314600), rev=True))
    # 5: response with 0 (1 Jan 1900, before the Unix epoch)
    F.append(udp(37, 50002, struct.pack('>I', 0), rev=True))
    # 6: response with the largest value (2036)
    F.append(udp(37, 50003, struct.pack('>I', 0xffffffff), rev=True))
    # 7-8: TCP request (1 octet) and response
    F.append(tcp(50010, 37, 1, 1, b'\n'))
    F.append(tcp(37, 50010, 1, 2, struct.pack('>I', 2208988800 + 1705314600), rev=True))
    # 9: TCP response with a longer payload (only the first 4 octets are used)
    F.append(tcp(37, 50011, 1, 1, struct.pack('>I', 2208988800 + 86400) + b'\0\0\0\0', rev=True))
    return F


def malformed_frames():
    F = []
    # 1: response with 3 octets
    F.append(udp(37, 50020, b'\x01\x02\x03', rev=True))
    # 2: response with 1 octet over TCP
    F.append(tcp(37, 50021, 1, 1, b'\x01', rev=True))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'time-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'time-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
