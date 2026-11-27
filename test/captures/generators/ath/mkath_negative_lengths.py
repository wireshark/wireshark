#!/usr/bin/env python3
# Apache Tribes Heartbeat with negative length fields
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Four ATH heartbeats (UDP port 45564) for "ATH: Treat negative lengths
as zero": one with valid lengths, one with a command length of -1 and a
domain "dom", one with a domain length of -1, one with a payload length
of -5. A negative length used to move the offset backwards.

Usage: mkath_negative_lengths.py [<output directory>]

Writes ath-negative-lengths.pcap. Every packet is built here; nothing
comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402

SRC = '192.0.2.1'
DST = '192.0.2.2'


def ath(clen, cmd, dlen, dom, plen, pay):
    b = b'TRIBES-B' + b'\x00\x01' + struct.pack('!I', 0) + struct.pack('!Q', 1)
    b += struct.pack('!iii', 4000, -1, 45564) + b'\x04' + bytes([10, 0, 0, 1])
    b += struct.pack('!i', clen) + cmd + struct.pack('!i', dlen) + dom
    b += b'\x00' * 16 + struct.pack('!i', plen) + pay + b'TRIBES-E' + b'\x01\x00'
    return b


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    payloads = [
        ath(4, b'ABCD', 0, b'', 0, b''),
        ath(-1, b'', 3, b'dom', 0, b''),
        ath(0, b'', -1, b'', 0, b''),
        ath(0, b'', 0, b'', -5, b''),
    ]
    frames = [eth(ipv4(udp(p, 45564, 45564, src=SRC, dst=DST), 17, src=SRC, dst=DST, ident=i + 1),
                  0x0800)
              for i, p in enumerate(payloads)]
    write_pcap(os.path.join(out, 'ath-negative-lengths.pcap'), frames)


if __name__ == '__main__':
    main()
