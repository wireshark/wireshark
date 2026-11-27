#!/usr/bin/env python3
# ARP duplicate address note and request storms
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Ethernet ARP frames for "ARP: Fix duplicate IP note and request storm
state":

 1. a reply from 192.0.2.1 (02:00:00:00:00:01) to 192.0.2.2
    (02:00:00:00:00:02)
 2. a reply from 192.0.2.1 with another MAC address (02:00:00:00:00:03)
    to the same target: the sender is a duplicate, the target is not,
    and the target check used to wipe the duplicate note from the Info
    column
 3. 9 requests from 192.0.2.10 for 192.0.2.99, 1 ms apart: with the
    storm limit set to 3 requests in 100 ms a storm is reported on every
    fourth request (frames 5 and 9), in one and in two passes

Usage: mkarp_dup_storm.py [<output directory>]

Writes arp-dup-storm.pcap. Every packet is built here; nothing comes
from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import TS_BASE, eth, ip4, mac, write_pcap  # noqa: E402

REQUEST, REPLY = 1, 2


def arp(op, sha, spa, tha, tpa):
    return struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, op, mac(sha), ip4(spa), mac(tha), ip4(tpa))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m1, m2, m3, m10 = ('02:00:00:00:00:%02x' % n for n in (1, 2, 3, 10))
    frames = [
        eth(arp(REPLY, m1, '192.0.2.1', m2, '192.0.2.2'), 0x0806, dst=m2, src=m1),
        eth(arp(REPLY, m3, '192.0.2.1', m2, '192.0.2.2'), 0x0806, dst=m2, src=m3),
    ]
    for _ in range(9):
        frames.append(eth(arp(REQUEST, m10, '192.0.2.10', '00:00:00:00:00:00', '192.0.2.99'),
                          0x0806, dst='ff:ff:ff:ff:ff:ff', src=m10))
    write_pcap(os.path.join(out, 'arp-dup-storm.pcap'), frames,
               ts=lambda i: (TS_BASE, i * 1000))


if __name__ == '__main__':
    main()
