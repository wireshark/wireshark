#!/usr/bin/env python3
# Generates test/captures/marker_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the Marker (Link Aggregation Marker Protocol) coverage captures.
# Usage: mkmarker.py <outdir>
import struct
import sys
import os

def pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', i, 0, len(fr), len(fr)))
            f.write(fr)

DST = bytes.fromhex('0180c2000002')
SRC = bytes.fromhex('020000000001')

def marker(ver=1, t=1, l=16, port=1, sysid=bytes.fromhex('02aabbccddee'), tid=1,
           pad=0, tt=0, tl=0, reserved=b'\0' * 90, subtype=2):
    pdu = struct.pack('>BBBBH', subtype, ver, t, l, port) + sysid
    pdu += struct.pack('>IHBB', tid, pad, tt, tl) + reserved
    fr = DST + SRC + struct.pack('>H', 0x8809) + pdu
    return fr + b'\0' * max(0, 60 - len(fr))

main = [
    marker(t=1, port=3, tid=100),                          # information
    marker(t=2, port=3, tid=100, sysid=bytes.fromhex('0211223344 55'.replace(' ', ''))),  # response
    marker(t=1, port=65535, tid=0xffffffff, ver=2),         # other version, max values
    marker(t=2, port=7, tid=7, pad=0x1234),                 # non-zero pad (warning only)
    marker(t=1, port=9, tid=9, reserved=bytes(range(90))),  # reserved bytes not zero
]
mal = [
    marker(t=0, port=1),                       # unexpected TLV type 0 (info type error)
    marker(t=3, port=1),                       # unknown TLV type 3
    marker(t=1, l=15),                         # wrong TLV length
    marker(t=2, l=0),                          # wrong TLV length (zero)
    marker(t=1, tt=1, tl=0),                   # terminator with wrong type
    marker(t=1, tt=0, tl=5),                   # terminator with non-zero length
    marker(t=3, l=20, tt=2, tl=1, pad=1),      # everything wrong at once
    marker()[:14 + 1 + 20],                    # truncated before the pad
    marker()[:14 + 1 + 3],                     # truncated after the TLV header
    marker()[:14 + 1 + 100],                   # truncated in the reserved field (60 byte min is padding)
]
out = sys.argv[1]
pcap(os.path.join(out, 'marker-coverage.pcap'), main)
pcap(os.path.join(out, 'marker-coverage-malformed.pcap'), mal)
