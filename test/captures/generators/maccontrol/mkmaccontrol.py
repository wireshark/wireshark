#!/usr/bin/env python3
# Generates test/captures/maccontrol_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the MAC Control (macc) coverage captures.
# Usage: mkmaccontrol.py <outdir>
import struct
import sys
import os

def pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', i, 0, len(fr), len(fr)))
            f.write(fr)

PAUSE_DST = bytes.fromhex('0180c2000001')
SRC = bytes.fromhex('020000000001')

def mc(body, dst=PAUSE_DST, pad=True):
    fr = dst + SRC + struct.pack('>H', 0x8808) + body
    if pad:
        fr += b'\0' * max(0, 60 - len(fr))
    return fr

def pause(t, dst=PAUSE_DST):
    return mc(struct.pack('>HH', 1, t), dst)

def ts(op, stamp, rest=b''):
    return mc(struct.pack('>HI', op, stamp) + rest)

def cbfc(enbv, times, dst=PAUSE_DST):
    return mc(struct.pack('>HH8H', 0x0101, enbv, *times), dst)

main = [
    pause(0xffff),                                     # 1 pause, maximum
    pause(0),                                          # 2 pause, resume
    pause(512, dst=bytes.fromhex('010000000000')),     # 3 pause to a wrong destination (warning)
    ts(2, 0x01020304),                                 # 4 gate
    ts(3, 0x01020304, b'\x01\x02\x03'),                # 5 report
    ts(4, 100, struct.pack('>BB', 1, 3)),              # 6 register req (flags register, grants 3)
    ts(4, 100, struct.pack('>BB', 2, 0)),              # 7 register req (deregister)
    ts(5, 200, struct.pack('>HBHB', 0x1234, 1, 0x5678, 3)),   # 8 register
    ts(5, 200, struct.pack('>HBHB', 0x1234, 4, 0x5678, 3)),   # 9 register, nack
    ts(6, 300, struct.pack('>BHH', 3, 0x1234, 0x5678)),       # 10 register ack
    ts(6, 300, struct.pack('>BHH', 9, 0xffff, 0xffff)),       # 11 register ack, unknown flags
    cbfc(0x00ff, [1, 2, 3, 4, 5, 6, 7, 8]),            # 12 CBFC all classes
    cbfc(0x0005, [0, 0xffff, 0, 0, 0, 0, 0, 0xffff]),  # 13 CBFC classes 0 and 2
    cbfc(0x0000, [0] * 8),                             # 14 CBFC no class
    cbfc(0x0180, [9] * 8),                             # 15 CBFC, high byte of the vector set (warning)
    cbfc(0x0001, [100] * 8, dst=bytes.fromhex('ffffffffffff')),   # 16 CBFC to a wrong destination (warning)
    mc(struct.pack('>H', 0x0007) + b'\xaa' * 20),      # 17 unknown opcode (warning)
    mc(struct.pack('>H', 0xffff)),                     # 18 unknown opcode 0xffff
    mc(struct.pack('>H', 0x0000)),                     # 19 opcode 0
]
mal = [
    pause(1)[:14 + 1],                                  # opcode truncated
    pause(1)[:14 + 5],                                  # pause time missing, tree item longer than the data
    ts(4, 1)[:14 + 7],                                  # register req: flags missing
    ts(5, 1, struct.pack('>HBHB', 1, 1, 1, 1))[:14 + 13],  # register truncated
    ts(6, 1, struct.pack('>BHH', 1, 1, 1))[:14 + 11],      # register ack truncated
    cbfc(0x0001, [1] * 8)[:14 + 10],                    # CBFC enable vector then truncated times
    mc(struct.pack('>HH', 1, 1), pad=False),            # short but complete pause frame, no padding
    mc(struct.pack('>H', 2) + b'\0\0\0\0', pad=False),  # gate without padding
]
out = sys.argv[1]
pcap(os.path.join(out, 'maccontrol-coverage.pcap'), main)
pcap(os.path.join(out, 'maccontrol-coverage-malformed.pcap'), mal)
