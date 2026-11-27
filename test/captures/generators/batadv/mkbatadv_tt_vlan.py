#!/usr/bin/env python3
# B.A.T.M.A.N. Advanced TT TVLV with many interleaved VLANs
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""An OGM2 whose TT TVLV (version 1) is a full table response with 24
VLANs and the changes of 22 of them interleaved. The dissector computes
the CRC of every VLAN in one pass over the changes ("BATADV: Compute TT
VLAN checksums in one pass"). VLANs 7 and 21 carry a wrong CRC, VLAN 22 has
no changes and CRC 0 (empty VLAN), VLAN 23 has no changes and a wrong CRC,
and a few changes name a VLAN that is not listed. Frame 2 holds the same
TVLV as a non full response, for which no CRC is verified.

Usage: mkbatadv_tt_vlan.py [<output directory>]

Writes batadv-tt-vlan.pcap. Every packet is built here; nothing comes
from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, write_pcap  # noqa: E402

ETH_P_BATMAN = 0x4305
NUM_VLAN = 24


def crc32c_raw(data, crc):
    """crc32c_calculate_no_swap(): reflected CRC-32C, no pre/post inversion."""
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc


def change(flags, n, vid):
    return struct.pack('>B3s6sH', flags, b'\0\0\0', bytes([2, 0, 0, 0, 0, n]), vid)


def vlan_crc(changes, vid):
    crc = 0
    for c in changes:
        if struct.unpack('>H', c[10:12])[0] != vid:
            continue
        e = crc32c_raw(c[10:12], 0)
        e = crc32c_raw(c[0:1], e)
        e = crc32c_raw(c[4:10], e)
        crc ^= e
    return crc


def build_changes():
    """Round robin over the VLANs, VLAN v has 1 + v % 5 changes."""
    per_vlan = [[change(0x10 + (i & 3), v * 8 + i, v) for i in range(1 + v % 5)]
                for v in range(22)]
    changes = []
    for i in range(5):
        for v in range(22):
            if i < len(per_vlan[v]):
                changes.append(per_vlan[v][i])
        if i == 2:
            changes.append(change(0x10, 0xee, 0x00ff))     # VLAN not listed
    return changes


def tt_tvlv(flags, changes, bad):
    body = struct.pack('>BBH', flags, 5, NUM_VLAN)
    for v in range(NUM_VLAN):
        crc = vlan_crc(changes, v)
        if v in bad:
            crc ^= 0x00c0ffee
        body += struct.pack('>IHH', crc, v, 0)
    body += b''.join(changes)
    return struct.pack('>BBH', 4, 1, len(body)) + body     # type TT, version 1


def ogm2(tvlv, seq):
    hdr = struct.pack('>BBBBI6sHI', 0x04, 15, 1, 0, seq,
                      bytes([2, 0, 0, 0, 0, 2]), len(tvlv), 10)
    return hdr + tvlv


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    changes = build_changes()
    bad = {7, 21, 23}
    frames = [
        eth(ogm2(tt_tvlv(0x14, changes, bad), 1), ETH_P_BATMAN),
        eth(ogm2(tt_tvlv(0x04, changes, bad), 2), ETH_P_BATMAN),
    ]
    write_pcap(os.path.join(out, 'batadv-tt-vlan.pcap'), frames)


if __name__ == '__main__':
    main()
