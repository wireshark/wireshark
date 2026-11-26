#!/usr/bin/env python3
# AMT nested to the protocol layer depth limit
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""IPv4 packets nesting IP/UDP 2268/AMT Multicast Data/IP/UDP 2268/... so
deep that the innermost UDP packet (unknown ports, so the heuristic
dissectors are tried) is reached with exactly the default limit of 500
protocol layers. The heuristic dissector table must stop there with a
dissector error, not an assertion ("epan: Stop heuristic dissectors at the
layer depth limit without asserting"). Three layers are added per AMT level,
so one IP-in-IP header (a 4th) and 165 levels hit the limit exactly.

Usage: mkamt_layer_limit.py [<output directory>]

Writes amt-layer-limit.pcap (LINKTYPE_RAW) with two frames: the nesting at
the limit, and a control with 3 levels that dissects completely. Every
packet is built here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import LINKTYPE_RAW, ipv4, udp, write_pcap  # noqa: E402


def nested(extra_ipip, levels):
    p = ipv4(udp(b'\0' * 8, 40000, 40001), 17)
    for _ in range(levels):
        amt = bytes([0x06, 0x00]) + p      # AMT version 0, Multicast Data
        p = ipv4(udp(amt, 2268, 2268), 17)
    for _ in range(extra_ipip):
        p = ipv4(p, 4)
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'amt-layer-limit.pcap'),
               [nested(1, 165), nested(0, 3)], linktype=LINKTYPE_RAW)


if __name__ == '__main__':
    main()
