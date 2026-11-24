#!/usr/bin/env python3
# Generates test/captures/brcm_tag_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Broadcom tag dissector
(packet-brcm-tag.c).

The Broadcom tag is ethertype 0x8874 (ETHERTYPE_BRCM_TYPE); it is the only
way the dissector is registered. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkbrcm_tag.py <output directory>

Writes:
  brcm_tag-coverage.pcap            every opcode (the four named and the four
                                    unnamed values), the mirror bits, the
                                    12-bit frame octet count with the upper
                                    bits set, a tag behind an 802.1Q VLAN
                                    tag, tags shorter than 4 octets and the
                                    5-octet frame of 
                                    brcm_tag_offset4.py
  brcm_tag-coverage-malformed.pcap  4-octet tags with nothing after them
                                    (the source device/port item is read at
                                    offset 4, past the tag: exception)
"""

import os
import struct
import sys

MAC_DST = bytes.fromhex('020000000001')
MAC_SRC = bytes.fromhex('020000000002')
ETH_BRCM = 0x8874
ETH_VLAN = 0x8100


def eth(payload, ethertype=ETH_BRCM, pad=True):
    frame = MAC_DST + MAC_SRC + struct.pack('>H', ethertype) + payload
    if pad and len(frame) < 60:
        frame += b'\0' * (60 - len(frame))
    return frame


def vlan(payload, vid=100, pcp=5):
    return struct.pack('>HH', (pcp << 13) | vid, ETH_BRCM) + payload


def tag(opcode, mr=0, mo=0, count=0, byte3=0, low=0):
    """Byte 0: opcode (bits 7-5), MR (bit 4), MO (bit 3), low bits 2-0.
    Bytes 1-2: frame octet count (12 bits, the upper 4 bits are not part of
    the field). Byte 3: destination device ID or reserved."""
    b0 = (opcode << 5) | (mr << 4) | (mo << 3) | (low & 7)
    return struct.pack('>BHB', b0, count, byte3)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(p), len(p)))
            f.write(p)


def main_frames():
    # Data after the tag: the dissector reads its source device/port item
    # from the first octet after the tag (see the README), so every frame
    # carries at least one octet there.
    data = bytes.fromhex('25') + b'BRCM-TAG'
    frames = [
        # 1-4: the four named opcodes, no mirror bits.
        eth(tag(0, count=64, byte3=0x01) + data),          # Unicast
        eth(tag(1, count=128, byte3=0x00) + data),         # Multicast
        eth(tag(2, count=256, byte3=0x02) + data),         # Egress directed
        eth(tag(3, count=512, byte3=0x00) + data),         # Ingress directed
        # 5-8: the four opcodes not in the value string.
        eth(tag(4, count=60, byte3=0x00) + data),
        eth(tag(5, count=61, byte3=0x00) + data),
        eth(tag(6, count=62, byte3=0x00) + data),
        eth(tag(7, count=63, byte3=0x00) + data),
        # 9-11: mirror bits, alone and together.
        eth(tag(0, mr=1, count=100, byte3=0x03) + data),
        eth(tag(2, mo=1, count=101, byte3=0x01) + data),
        eth(tag(1, mr=1, mo=1, count=102, byte3=0x00) + data),
        # 12: frame octet count with the upper 4 bits set (0xF123 -> 0x123
        # = 291), low bits of byte 0 set, and a destination device ID byte
        # with bits outside the 2-bit mask set (0xFE -> 2).
        eth(tag(0, count=0xF123, byte3=0xFE, low=7) + data),
        # 13: behind an 802.1Q VLAN tag.
        eth(vlan(tag(2, count=1500, byte3=0x03) + data), ethertype=ETH_VLAN),
        # 14: brcm_tag_offset4.py frame 2: a 4-octet tag and
        # one octet after it (not padded).
        eth(bytes([0x40, 0x00, 0x40, 0x13, 0x25]), pad=False),
        # 15-16: shorter than the 4-octet tag (3 and 1 octets, not
        # padded): only the protocol item.
        eth(bytes([0x00, 0x00, 0x40]), pad=False),
        eth(bytes([0x60]), pad=False),
    ]
    return frames


def malformed_frames():
    return [
        # brcm_tag_offset4.py frame 1: a 4-octet tag and
        # nothing after it, for each opcode branch.
        eth(bytes([0x40, 0x00, 0x40, 0x13]), pad=False),
        eth(tag(0, count=64, byte3=1), pad=False),
        eth(tag(2, count=64, byte3=1), pad=False),
        eth(tag(3, count=64), pad=False),
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'brcm_tag-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'brcm_tag-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
