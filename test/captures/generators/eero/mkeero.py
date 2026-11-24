#!/usr/bin/env python3
# Generates test/captures/eero_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EERO dissector
(packet-eero.c).

EERO mesh access points broadcast frames with ethertype 0x9104 (not
officially registered). The dissector shows a type octet, the sender
MAC address and the rest as data. Every packet is built from scratch
with struct; no captured traffic is used. The MAC addresses are locally
administered (02:...) made-up values.

Usage: mkeero.py <output directory>

Writes:
  eero-coverage.pcap            types 0, 1, 2, 0x7f and 0xff, with no
                                data, short data and 1400 octets of data
  eero-coverage-malformed.pcap  an empty payload, a payload cut short in
                                the sender MAC address
"""

import os
import struct
import sys

BCAST = b'\xff' * 6
ETHERTYPE = 0x9104


def mac(n):
    return bytes([0x02, 0x00, 0x5e, 0x10, 0x00, n])


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(src, payload, dst=BCAST):
    return dst + src + struct.pack('>H', ETHERTYPE) + payload


def eero(typ, sender, data=b''):
    return bytes([typ]) + sender + data


def main_frames():
    f = []
    # 1-3: three access points announce themselves (type 1) with a short
    # body; the sender MAC in the payload is the source address
    for n in (1, 2, 3):
        f.append(eth(mac(n), eero(1, mac(n), bytes([0x00, n, 0x10, 0x20]))))
    # 4: type 0, no data at all (the frame ends after the MAC address)
    f.append(eth(mac(1), eero(0, mac(1))))
    # 5: type 2 sent to a unicast address, sender differs from the source
    f.append(eth(mac(2), eero(2, mac(9), b'eero mesh'), dst=mac(3)))
    # 6: type 0x7f with a large body
    f.append(eth(mac(3), eero(0x7f, mac(3), bytes(range(256)) * 5 + bytes(120))))
    # 7: type 0xff (highest type value), one data octet
    f.append(eth(mac(1), eero(0xff, mac(1), b'\x01')))
    return f


def malformed_frames():
    return [
        # 1: no EERO octets at all
        eth(mac(1), b''),
        # 2: type and three octets of the MAC address
        eth(mac(1), b'\x01\x02\x00\x5e'),
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'eero-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'eero-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
