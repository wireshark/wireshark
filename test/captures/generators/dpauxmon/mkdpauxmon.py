#!/usr/bin/env python3
# Generates test/captures/dpauxmon_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DPAUXMON dissector
(packet-dpauxmon.c, DisplayPort AUX channel monitor).

DPAUXMON is link-layer type 275 (LINKTYPE_DISPLAYPORT_AUX). Each packet
starts with a type octet: Data (0, an origin octet and an AUX
transaction for DPAUX), Data End (1), Event (2) and Start (3) with an
inputs octet (Hotplug Detect, IN0-IN2), Stop (4) and Timestamp Overflow
(0x84). Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkdpauxmon.py <output directory>

Writes:
  dpauxmon-coverage.pcap            every packet type, every input bit,
                                    data from the source and the sink
  dpauxmon-coverage-malformed.pcap  data and event packets cut short
"""

import os
import struct
import sys


def pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = [
        bytes([0x03, 0x00]),                        # 1: Start, no inputs
        bytes([0x02, 0x01]),                        # 2: Event, Hotplug Detect
        bytes([0x00, 0x01, 0x90, 0x00, 0x00, 0x00]),  # 3: Data from the source: native read of DPCD_REV
        bytes([0x00, 0x00, 0x00, 0x12]),            # 4: Data from the sink: ACK with 1 octet
        bytes([0x01]),                              # 5: Data End (no name, "Unknown")
        bytes([0x02, 0x0e]),                        # 6: Event, IN0, IN1, IN2
        bytes([0x84]),                              # 7: Timestamp Overflow
        bytes([0x00, 0x02, 0x90, 0x00, 0x01, 0x00]),  # 8: Data, origin 2 (no name, non-zero: from the source)
        bytes([0x00, 0x00, 0x10]),                  # 9: Data from the sink: AUX NACK
        bytes([0x10, 0xaa]),                        # 10: unknown packet type 0x10
        bytes([0x02, 0x0f]),                        # 11: Event, all inputs
        bytes([0x04]),                              # 12: Stop
    ]
    pcap(os.path.join(out, 'dpauxmon-coverage.pcap'), 275, frames)
    bad = [
        bytes([0x00]),   # Data without an origin
        bytes([0x02]),   # Event without inputs
        bytes([0x03]),   # Start without inputs
        b'',             # empty packet
    ]
    pcap(os.path.join(out, 'dpauxmon-coverage-malformed.pcap'), 275, bad)


if __name__ == '__main__':
    main()
