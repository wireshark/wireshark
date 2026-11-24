#!/usr/bin/env python3
# Generates test/captures/wol_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Wake On LAN dissector (packet-wol.c).

WOL is reached by ethertype 0x0842 and by the UDP heuristic (any port,
here 7 and 9). A MagicPacket is 6 bytes of 0xff and 16 copies of the
target MAC, optionally followed by a 4 byte (IP style) or 6 byte (MAC
style) SecureOn password.

Usage: mkwol.py <output directory>
Writes wol-coverage.pcap and wol-coverage-malformed.pcap (not-WOL
traffic that the heuristic must reject).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from wlccp_common import udp_frame, eth_frame, write_pcap

SYNC = b'\xff' * 6
M1 = bytes.fromhex('020000000009')
M2 = bytes.fromhex('0a1b2c3d4e5f')

def magic(mac, extra=b''):
    return SYNC + mac * 16 + extra

def main(out):
    ok = [
        eth_frame(magic(M1), 0x0842),                                  # 1 plain, ethertype
        eth_frame(magic(M2, bytes([10, 1, 2, 3])), 0x0842),            # 2 4 byte password
        eth_frame(magic(M1, bytes([1, 2, 3, 4, 5, 6])), 0x0842),       # 3 6 byte password
        udp_frame(magic(M1), 40000, 9),                                # 4 UDP heuristic, no password
        udp_frame(magic(M2, bytes([192, 0, 2, 77])), 40000, 7),        # 5 UDP, IP style password
        udp_frame(magic(M1, bytes([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])), 40000, 9),  # 6 MAC style
        udp_frame(magic(M2, b'\x01\x02\x03\x04\x05'), 40001, 9),       # 7 5 bytes: 4 byte password, 1 trailing
        udp_frame(magic(M1, bytes(range(1, 10))), 40001, 9),           # 8 9 bytes: 6 byte password, 3 trailing
        udp_frame(magic(M1, b'\x00' * 4), 51000, 51001),               # 9 other ports, heuristic
        udp_frame(magic(b'\xff' * 6), 40000, 9),                       # 10 broadcast MAC
    ]
    bad = [
        udp_frame(SYNC + M1 * 15, 40000, 50000),               # 15 copies only, not WOL
        udp_frame(SYNC + M1 * 15 + M2, 40000, 50000),          # last copy differs
        udp_frame(b'\xff' * 5 + b'\x00' + M1 * 16, 40000, 50000),  # sync differs
        udp_frame(b'\xff' * 6, 40000, 50000),                  # too short
        eth_frame(SYNC + M1 * 8, 0x0842),                  # ethertype, truncated
        eth_frame(SYNC + M1 * 16 + b'\x01\x02', 0x0842),   # 2 trailing bytes
        eth_frame(b'\x00' * 20, 0x0842),                   # ethertype, not a MagicPacket
    ]
    write_pcap(os.path.join(out, 'wol-coverage.pcap'), ok)
    write_pcap(os.path.join(out, 'wol-coverage-malformed.pcap'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
