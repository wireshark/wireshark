#!/usr/bin/env python3
# BFCP padding inside grouped attributes and short ERROR-CODE attributes
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""BFCPv2 messages over UDP port 5070 (dissect them with
-d udp.port==5070,bfcp) for "BFCP: Count attribute padding and check the
ERROR-CODE length":

 1. a FloorRequestStatus (primitive 4) with a FLOOR-REQUEST-INFORMATION
    group (id 0x11) whose only attribute is a STATUS-INFO of 3 octets of
    text (length 5, 3 octets of padding, all 0xff), followed by a FLOOR-ID
    outside the group. The group loop used to go on into the FLOOR-ID.
 2. an Error (primitive 13) with an ERROR-CODE attribute of length 2,
    followed by a FLOOR-ID. The attribute used to step the offset back.
 3. an Error with a valid ERROR-CODE (code 5, length 3, 1 octet of
    padding) followed by a FLOOR-ID.

Usage: mkbfcp_padding.py [<output directory>]

Writes bfcp-padding.pcap. Every packet is built here; nothing comes from
a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402

SRC = '192.0.2.1'
DST = '192.0.2.2'


def attr(t, val, pad=b'\0'):
    """type << 1 | M, length without padding, value, padding to 4 octets."""
    a = bytes([(t << 1) | 1, 2 + len(val)]) + val
    return a + pad * (-len(a) % 4)


def floor_id(v):
    return attr(2, struct.pack('>H', v))


def bfcp(prim, attrs, tid):
    hdr = struct.pack('>BBHIHH', (2 << 5) | 0x10, prim, (len(attrs) + 3) // 4, 1001, tid, 1)
    return hdr + attrs


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    status = attr(9, b'abc', pad=b'\xff')
    group = bytes([(15 << 1) | 1, 4 + len(status)]) + struct.pack('>H', 0x11) + status
    payloads = [
        bfcp(4, group + floor_id(5), 1),
        bfcp(13, bytes([(6 << 1) | 1, 2, 0, 0]) + floor_id(5), 2),
        bfcp(13, attr(6, bytes([5])) + floor_id(5), 3),
    ]
    frames = [eth(ipv4(udp(p, 40000, 5070, src=SRC, dst=DST), 17, src=SRC, dst=DST, ident=i + 1),
                  0x0800)
              for i, p in enumerate(payloads)]
    write_pcap(os.path.join(out, 'bfcp-padding.pcap'), frames)


if __name__ == '__main__':
    main()
