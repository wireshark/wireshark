#!/usr/bin/env python3
# Art-Net ArtDmx and ArtNzs with a DMX length that does not match the packet
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ArtDmx and ArtNzs packets (UDP port 6454) for "Art-Net: Restore Info
column state and fix subtrees":

 1. ArtDmx, length 8, 8 octets of DMX data
 2. ArtDmx, length 512, only 6 octets of DMX data
 3. ArtDmx, length 4, 10 octets of DMX data
 4. ArtNzs with start code 0x01, length 300, only 5 octets of data
 5. ArtNzs with start code 0x01, length 5, 5 octets of data

Usage: mkartnet_dmx_length.py [<output directory>]

Writes artnet-dmx-length.pcap. Every packet is built here; nothing comes
from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402

SRC = '192.0.2.1'
DST = '192.0.2.255'
HEAD = b'Art-Net\0'
PROTVER = struct.pack('>H', 14)


def art(opcode, body):
    return HEAD + struct.pack('<H', opcode) + PROTVER + body


def dmx(length, data, seq=1):
    return art(0x5000, bytes([seq, 0]) + struct.pack('<H', 1) + struct.pack('>H', length) + data)


def nzs(length, data, seq=1):
    return art(0x5100, bytes([seq, 0x01, 0, 0]) + struct.pack('>H', length) + data)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    payloads = [
        dmx(8, bytes(range(1, 9))),
        dmx(512, bytes(range(1, 7))),
        dmx(4, bytes(range(1, 11))),
        nzs(300, bytes(range(1, 6))),
        nzs(5, bytes(range(1, 6))),
    ]
    frames = [eth(ipv4(udp(p, 6454, 6454, src=SRC, dst=DST), 17, src=SRC, dst=DST, ident=i + 1),
                  0x0800, dst='ff:ff:ff:ff:ff:ff', src='02:00:00:00:00:01')
              for i, p in enumerate(payloads)]
    write_pcap(os.path.join(out, 'artnet-dmx-length.pcap'), frames)


if __name__ == '__main__':
    main()
