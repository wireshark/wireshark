#!/usr/bin/env python3
# Generates test/captures/bofl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BOFL dissector (packet-bofl.c).

Wellfleet Breath of Life, ethertype 0x8102. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkbofl.py <output directory>

Writes:
  bofl-coverage.pcap            both usual PDU values, an unusual one, a
                                sequence that counts up and wraps, padding
                                of several lengths and none, BOFL in an
                                802.1Q VLAN
  bofl-coverage-malformed.pcap  BOFL payloads shorter than 8 octets
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('0000a2000001')   # Wellfleet OUI 00:00:A2
MAC_B = bytes.fromhex('0000a2000002')
BCAST = b'\xff' * 6
ETH_BOFL = 0x8102


def eth(dst, src, etype, payload):
    return dst + src + struct.pack('>H', etype) + payload


def bofl(pdu, seq, padding=b''):
    return struct.pack('>II', pdu, seq) + padding


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main_frames():
    F = []
    # 1-3: PDU 0x01010000, sequence 1-3, padded to the 60 octet minimum
    for seq in (1, 2, 3):
        F.append(eth(BCAST, MAC_A, ETH_BOFL, bofl(0x01010000, seq, bytes(38))))
    # 4-5: PDU 0x01011111 from the other router, padding of a pattern
    F.append(eth(BCAST, MAC_B, ETH_BOFL, bofl(0x01011111, 100, bytes(range(38)))))
    F.append(eth(BCAST, MAC_B, ETH_BOFL, bofl(0x01011111, 101, b'\xaa' * 38)))
    # 6: exactly 8 octets of BOFL: no padding item
    F.append(eth(BCAST, MAC_A, ETH_BOFL, bofl(0x01010000, 4)))
    # 7: one octet of padding
    F.append(eth(BCAST, MAC_A, ETH_BOFL, bofl(0x01010000, 5, b'\x01')))
    # 8: an unusual PDU value and the largest sequence number
    F.append(eth(MAC_B, MAC_A, ETH_BOFL, bofl(0xdeadbeef, 0xffffffff, bytes(38))))
    # 9: sequence 0 after the wrap
    F.append(eth(MAC_B, MAC_A, ETH_BOFL, bofl(0xdeadbeef, 0, bytes(38))))
    # 10: BOFL in an 802.1Q VLAN (VLAN 42)
    F.append(eth(BCAST, MAC_A, 0x8100,
                 struct.pack('>HH', 42, ETH_BOFL) + bofl(0x01010000, 6, bytes(34))))
    return F


def malformed_frames():
    F = []
    # 1: no BOFL data at all
    F.append(eth(BCAST, MAC_A, ETH_BOFL, b''))
    # 2: PDU cut short
    F.append(eth(BCAST, MAC_A, ETH_BOFL, b'\x01\x01'))
    # 3: PDU only, no sequence
    F.append(eth(BCAST, MAC_A, ETH_BOFL, struct.pack('>I', 0x01010000)))
    # 4: sequence cut short
    F.append(eth(BCAST, MAC_A, ETH_BOFL, struct.pack('>IH', 0x01010000, 7)))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bofl-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'bofl-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
