#!/usr/bin/env python3
# ASTERIX data blocks of short records valid in several UAPs
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ASTERIX category 1 has two UAPs (plot and track), so the dissector
probes every UAP at every record offset of a data block ("ASTERIX: Fix
exponential probing of possible record interpretations"). A record of
FSPEC 0x80 and I001/010 (SAC/SIC) is 3 octets long in both UAPs. UDP
datagrams to port 8600 (the default):

 1. one data block of 13 such records and a final octet that is no record
    (nothing to find, all the probing is dead ends)
 2. three of those data blocks in one datagram
 3. one data block of 13 valid records (many interpretations)
 4. one data block of 4 valid records, a bad octet and 4 more records

Usage: mkasterix_probe.py [<output directory>]

Writes asterix-probe.pcap (raw IPv4). Every packet is built here; nothing
comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import LINKTYPE_RAW, ipv4, udp, write_pcap  # noqa: E402

SRC = '192.0.2.1'
DST = '192.0.2.2'
REC = b'\x80\x01\x02'


def block(records, cat=1):
    return struct.pack('!BH', cat, 3 + len(records)) + records


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    payloads = [
        block(REC * 13 + b'\x80'),
        block(REC * 13 + b'\x80') * 3,
        block(REC * 13),
        block(REC * 4 + b'\x80' + REC * 4),
    ]
    frames = [ipv4(udp(p, 40000, 8600, src=SRC, dst=DST), 17, src=SRC, dst=DST, ident=i + 1)
              for i, p in enumerate(payloads)]
    write_pcap(os.path.join(out, 'asterix-probe.pcap'), frames, linktype=LINKTYPE_RAW)


if __name__ == '__main__':
    main()
