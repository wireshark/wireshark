#!/usr/bin/env python3
# AVSP postcard frames with many samples
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Arista Postcard Telemetry (GREENT, version 1) frames with 10, 30, 100
and 255 samples, each sample an Ethernet/IPv4/UDP frame. Every sample
adds layers to the packet, so many samples used to pass the layer limit
and end in a dissector bug ("AVSP: Stop the GREENT sample loop near the
layer limit"); the loop now stops with an expert info.

Usage: mkavsp_greent_layers.py [<output directory>]

Writes avsp-greent-layers.pcap. Every packet is built here; nothing comes
from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402

ETHERTYPE_AVSP = 0xd28b


def sample_frame():
    src, dst = '192.0.2.1', '198.51.100.1'
    return eth(ipv4(udp(b'', 40000, 40001, src=src, dst=dst), 17, src=src, dst=dst), 0x0800,
               dst='02:00:00:00:00:02', src='02:00:00:00:00:01')


def greent(count):
    s = sample_frame()
    pad = b'\0' * (-len(s) % 4)
    body = struct.pack('>HH', 0x0004, 0x0001) + struct.pack('>HBB', 1, 0, count)
    for _ in range(count):
        body += struct.pack('>HHIIIHH', len(s), 1, 2, 3, 4, 5, 0) + s + pad
    return eth(body, ETHERTYPE_AVSP, dst='02:00:00:00:00:02', src='02:00:00:00:00:01')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'avsp-greent-layers.pcap'),
               [greent(n) for n in (10, 30, 100, 255)])


if __name__ == '__main__':
    main()
