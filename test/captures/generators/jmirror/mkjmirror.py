#!/usr/bin/env python3
# Generates test/captures/jmirror_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Juniper Packet Mirror (jmirror) coverage captures.

Usage: mkjmirror.py <outdir>

  jmirror-coverage.pcap            mirrored IPv4, IPv6 and PPP/HDLC packets
                                   and payloads the heuristic does not
                                   recognise
  jmirror-coverage-malformed.pcap  mirrored packets cut short
Synthetic: built with struct only.
"""
import os
import struct
import sys

CMAC = bytes.fromhex('020000000002')
SMAC = bytes.fromhex('020000000001')
A4 = bytes([192, 0, 2, 1]); B4 = bytes([192, 0, 2, 2])
A6 = bytes.fromhex('20010db8000000000000000000000001')
B6 = bytes.fromhex('20010db8000000000000000000000002')


def csum(b):
    if len(b) & 1:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(l4, proto, src=A4, dst=B4, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + l4


def ipv6(l4, nh, src=A6, dst=B6, tc=0, flow=0):
    return struct.pack('!IHBB16s16s', (6 << 28) | (tc << 20) | flow, len(l4), nh, 64, src, dst) + l4


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def udp6(sport, dport, payload, src=A6, dst=B6):
    u = udp(sport, dport, payload)
    c = csum(src + dst + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]


def icmp_echo(payload=b'jmirror', typ=8):
    m = struct.pack('!BBHHH', typ, 0, 0, 1, 1) + payload
    return m[:2] + struct.pack('!H', csum(m)) + m[4:]


def eth_ip(ip4, proto=17):
    return CMAC + SMAC + b'\x08\x00' + ip4


def outer(mid, sid, inner, sport=40000, dport=30030):
    p = struct.pack('!II', mid, sid) + inner
    return eth_ip(ipv4(udp(sport, dport, p), 17))


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main(out):
    fr = []
    # 1: IPv4 / ICMP echo
    fr.append(outer(1, 100, ipv4(icmp_echo(), 1)))
    # 2: IPv4 / UDP
    fr.append(outer(1, 100, ipv4(udp(5000, 5001, b'mirrored udp'), 17, B4, A4)))
    # 3: IPv6 / UDP, with a traffic class and flow label
    fr.append(outer(2, 200, ipv6(udp6(6000, 6001, b'mirrored v6'), 17, tc=0xb8, flow=0x12345)))
    # 4: PPP in HDLC (address, control, protocol 0x0021) carrying IPv4
    fr.append(outer(3, 300, b'\xff\x03\x00\x21' + ipv4(udp(7001, 8001, b'ppp4'), 17)))
    # 5: PPP in HDLC carrying IPv6 (protocol 0x0057)
    fr.append(outer(3, 301, b'\xff\x03\x00\x57' + ipv6(udp6(1, 2, b'ppp6'), 17)))
    # 6: HDLC with the high nibble of the third byte set (still the IPv4 pattern)
    fr.append(outer(4, 400, b'\xff\x03\xf0\x21' + ipv4(udp(9, 10, b'ppp-f0'), 17)))
    # 7: IPv4 with options (0x46): not recognised, left to the UDP data dissector
    fr.append(outer(5, 500, b'\x46' + bytes(30)))
    # 8: Large MID and SID
    fr.append(outer(0xfffffff0, 0x80000001, ipv4(udp(11, 12, b'big'), 17)))
    # 9: only 11 bytes in all: too short for the heuristic
    fr.append(eth_ip(ipv4(udp(40000, 30030, bytes(11)), 17)))
    # 10: FF 03 not followed by the PPP IPv4/IPv6 protocol
    fr.append(outer(6, 600, b'\xff\x03\x00\x2b' + bytes(20)))
    # 11: source port 30030 (the mirror is the sender)
    fr.append(outer(7, 700, ipv4(icmp_echo(b'jmirror', 0), 1, B4, A4), sport=30030, dport=40001))
    pcap(os.path.join(out, 'jmirror-coverage.pcap'), fr)

    mal = []
    # IPv4 header cut after 10 bytes
    mal.append(outer(8, 800, ipv4(icmp_echo(), 1)[:10]))
    # mirrored IPv6 cut inside the header
    mal.append(outer(8, 801, ipv6(udp(1, 2, b'x'), 17)[:30]))
    # PPP/HDLC with only the 4 byte header
    mal.append(outer(8, 802, b'\xff\x03\x00\x21'))
    pcap(os.path.join(out, 'jmirror-coverage-malformed.pcap'), mal)


if __name__ == '__main__':
    main(sys.argv[1])
