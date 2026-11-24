#!/usr/bin/env python3
# Generates test/captures/mctp_smbus_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MCTP over SMBus/I2C coverage captures.
Usage: mkmctp-smbus.py <outdir>.  Writes mctp-smbus-coverage.pcap and
mctp-smbus-coverage-malformed.pcap (DLT 209, Linux I2C: a 5 byte pseudo
header (bus, flags) and the I2C message)."""
import struct
import sys
import os

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 209))
        for i, (p, cap) in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, cap, len(p)))
            f.write(p[:cap])

def pec(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xff if crc & 0x80 else (crc << 1) & 0xff
    return crc

def frame(mctp_msg, dst=0x40, cmd=0x0f, src=0x81, ver=1, d=0x20, s=0x40, flags=0xc8,
          bc=None, with_pec=False, bad_pec=False, trailing=b'', rw=0, cap=None):
    """SMBus block write: dst slave, command, byte count, src slave, MCTP header, message"""
    body = bytes([ver, d, s, flags]) + mctp_msg
    if bc is None:
        bc = len(body) + 1
    i2c = bytes([dst | rw, cmd, bc, src]) + body
    if with_pec:
        p = pec(i2c)
        if bad_pec:
            p ^= 0xff
        i2c += bytes([p])
    i2c += trailing
    pkt = bytes([0]) + struct.pack('>I', 0) + i2c
    return (pkt, len(pkt) if cap is None else 5 + cap)

GET_EID = bytes([0x00, 0x80, 0x02])
good = [
    frame(GET_EID),                                                # 1 no PEC
    frame(GET_EID, with_pec=True),                                 # 2 correct PEC
    frame(GET_EID, with_pec=True, bad_pec=True),                   # 3 bad PEC
    frame(GET_EID, with_pec=True, trailing=b'\xde\xad'),           # 4 two bytes after the PEC
    frame(bytes([0x01, 0x80, 0x00, 0x02]), flags=0xc9, with_pec=True),  # 5 PLDM
    frame(bytes([0x05]) + bytes(range(249)), flags=0xca, with_pec=True),   # 6 largest byte count (255)
    frame(bytes([0x00, 0x80]), flags=0x88, with_pec=True),         # 7 control message in two fragments (SOM)
    frame(bytes([0x02]), flags=0x58, with_pec=True),               # 8 (EOM)
    frame(bytes([0x42])),                                          # 9 smallest byte count (6), unknown type
    frame(GET_EID, dst=0x42, src=0x83, d=0x22, s=0x42, with_pec=True),   # 10 other addresses
    # rejected by the heuristic: raw I2C data
    frame(GET_EID, rw=1),                                          # 11 read bit set
    frame(GET_EID, cmd=0x0e),                                      # 12 other command code
    frame(GET_EID, bc=5),                                          # 13 byte count below the minimum
    frame(GET_EID, bc=12),                                         # 14 frame shorter than the byte count says
    frame(GET_EID, src=0x80),                                      # 15 source LSB 0 (IPMB)
    frame(GET_EID, ver=2),                                         # 16 MCTP header version 2
    frame(GET_EID, cap=2),                                         # 17 truncated by the snaplen
    (bytes([0]) + struct.pack('>I', 0) + bytes([0x40, 0x0f, 0x08]), 8),   # 18 shorter than 9 bytes
    (bytes([0x80]) + struct.pack('>I', 1), 5),                     # 19 I2C event, no data
]
# the same kind of frames, handed to the dissector with Decode As
bad = [
    frame(GET_EID, rw=1),                                          # 1 read bit set
    frame(GET_EID, cmd=0x0e),                                      # 2 other command code
    frame(GET_EID, src=0x80),                                      # 3 source LSB 0
    frame(GET_EID, bc=5),                                          # 4 byte count below the minimum
    frame(GET_EID, bc=12),                                         # 5 frame shorter than the byte count says
    frame(GET_EID, ver=2),                                         # 6 MCTP header version 2
    frame(GET_EID, cap=2),                                         # 7 truncated by the snaplen
    (bytes([0]) + struct.pack('>I', 0) + bytes([0x40, 0x0f, 0x08]), 8),   # 8 shorter than 9 bytes
    frame(GET_EID, with_pec=True, trailing=b'\xde\xad'),           # 9 trailing bytes after the PEC
    frame(GET_EID, with_pec=True, trailing=b'\xde\xad', cap=11),   # 10 trailing bytes cut by the snaplen
]
out = sys.argv[1]
pcap(os.path.join(out, 'mctp-smbus-coverage.pcap'), good)
pcap(os.path.join(out, 'mctp-smbus-coverage-malformed.pcap'), bad)
