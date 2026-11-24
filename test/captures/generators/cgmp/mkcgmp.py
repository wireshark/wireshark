#!/usr/bin/env python3
# Generates test/captures/cgmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco Group Management
Protocol dissector (packet-cgmp.c).

CGMP is carried in Ethernet II frames with ethertype 0x2001 and in
IEEE 802.3 frames with LLC/SNAP, Cisco OUI 00:00:0c and PID 0x2001. A
message is a version/type octet, two reserved octets, a count and
"count" pairs of Group Destination Address and Unicast Source Address.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcgmp.py <output directory>

Writes:
  cgmp-coverage.pcap            Join, Leave and unknown types, counts 0 to
                                several, both encapsulations
  cgmp-coverage-malformed.pcap  a count larger than the pairs present,
                                messages cut short
"""

import os
import struct
import sys

CGMP_DST = bytes.fromhex('01000cdddddd')
SRC = bytes.fromhex('02000000cafe')


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def eth2(payload):
    """Ethernet II, ethertype 0x2001."""
    return CGMP_DST + SRC + struct.pack('>H', 0x2001) + payload


def snap(payload):
    """IEEE 802.3 with LLC/SNAP, Cisco OUI and PID 0x2001."""
    llc = bytes.fromhex('aaaa03') + bytes.fromhex('00000c') + struct.pack('>H', 0x2001)
    body = llc + payload
    frame = CGMP_DST + SRC + struct.pack('>H', len(body)) + body
    # pad to the Ethernet minimum; the 802.3 length field marks the end
    return frame + b'\0' * max(0, 60 - len(frame))


def mac(i, mcast=True):
    if mcast:
        return bytes([0x01, 0x00, 0x5e, 0x00, 0x01, i & 0xff])
    return bytes([0x00, 0x11, 0x22, 0x33, 0x44, i & 0xff])


def cgmp(version, mtype, pairs, reserved=0, count=None):
    if count is None:
        count = len(pairs)
    return (bytes([(version << 4) | mtype]) + struct.pack('>HB', reserved, count)
            + b''.join(g + u for g, u in pairs))


def main_frames():
    f = []
    # 1: Join, one group, Ethernet II
    f.append(eth2(cgmp(1, 0, [(mac(1), mac(1, False))])))
    # 2: Leave, one group, Ethernet II
    f.append(eth2(cgmp(1, 1, [(mac(1), mac(1, False))])))
    # 3: Join, count 0 (no pairs)
    f.append(eth2(cgmp(1, 0, [])))
    # 4: Leave all: group 0, source 0 (count 1)
    f.append(eth2(cgmp(1, 1, [(bytes(6), bytes(6))])))
    # 5: Join, five groups, non-zero reserved field
    f.append(eth2(cgmp(1, 0, [(mac(i), mac(i, False)) for i in range(2, 7)], reserved=0xbeef)))
    # 6: unknown type 5, version 2
    f.append(eth2(cgmp(2, 5, [(mac(9), mac(9, False))])))
    # 7: Join over LLC/SNAP (802.3), two groups
    f.append(snap(cgmp(1, 0, [(mac(10), mac(10, False)), (mac(11), mac(11, False))])))
    # 8: Leave over LLC/SNAP, count 0
    f.append(snap(cgmp(1, 1, [])))
    # 9: Join with the largest count, 255 groups (3064 octets)
    f.append(eth2(cgmp(1, 0, [(mac(i), mac(i, False)) for i in range(255)])))
    # 10: version 15, type 15 (both nibbles at maximum)
    f.append(eth2(cgmp(15, 15, [(mac(0xff), mac(0xff, False))])))
    return f


def malformed_frames():
    f = []
    # 1: count 3 with one pair present
    f.append(eth2(cgmp(1, 0, [(mac(1), mac(1, False))], count=3)))
    # 2: count 1 with only a group address (no source)
    f.append(eth2(cgmp(1, 0, [], count=1) + mac(2)))
    # 3: only the first octet
    f.append(eth2(b'\x10'))
    # 4: empty payload (Ethernet II, no octets after the ethertype)
    f.append(eth2(b''))
    # 5: count 255 with nothing following, over LLC/SNAP
    f.append(snap(cgmp(1, 1, [], count=255)))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'cgmp-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'cgmp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
