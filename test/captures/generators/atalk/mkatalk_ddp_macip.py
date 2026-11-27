#!/usr/bin/env python3
# AppleTalk DDP over LLAP with a MacIP error reply
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Two LocalTalk frames in Ethernet (ethertype 0x809b) with long DDP
headers, for "AppleTalk: Fix DDP addresses, MacIP errors and ASP
transaction lookup":

 1. an ATP response from socket 72 to node 258.5, whose payload is a
    MacIP error reply (function -1) with the text "no addresses"
 2. the same with a longer text, "no free address in the pool"

The hidden ddp.src and ddp.dst fields must show the DDP addresses
(772.6 and 258.5), and the error text is a string, not further IP
addresses.

Usage: mkatalk_ddp_macip.py [<output directory>]

Writes atalk-ddp-macip.pcap. Every packet is built here; nothing comes
from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, write_pcap  # noqa: E402

ETHERTYPE_LLAP = 0x809b


def frame(text, tid):
    macip = struct.pack('>HHi', 1, 0, -1) + bytes(20) + text + b'\x00'
    atp = bytes([0x90, 0x00]) + struct.pack('>H', tid) + macip
    ddp = struct.pack('>HHHHBBBBB', 13 + len(atp), 0, 0x0102, 0x0304, 5, 6, 72, 72, 3) + atp
    return eth(bytes([5, 6, 2]) + ddp, ETHERTYPE_LLAP, dst='02:00:00:00:00:02',
               src='02:00:00:00:00:01')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'atalk-ddp-macip.pcap'),
               [frame(b'no addresses', 7), frame(b'no free address in the pool', 8)])


if __name__ == '__main__':
    main()
