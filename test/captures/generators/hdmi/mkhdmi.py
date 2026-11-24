#!/usr/bin/env python3
# Generates test/captures/hdmi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the HDMI coverage captures.  Usage: mkhdmi.py <outdir>

HDMI DDC traffic (EDID reads and HDCP register access) carried in I2C
messages: pcap link type 209 (I2C with the Linux pseudo-header).  HDMI
has no port or heuristic; it is reached through Decode As of the I2C
message table (-d i2c.message,hdmi).  The EDID blocks are made up (a
fictitious manufacturer, serial numbers and descriptors) and the HDCP
values are placeholders; nothing comes from a real network or monitor."""
import struct
import sys
import os

EDID_W, EDID_R, HDCP_W, HDCP_R = 0xA0, 0xA1, 0x74, 0x75
HDR = bytes.fromhex('00ffffffffffff00')


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000

    def i2c(self, payload, read, bus=1):
        flags = 1 if read else 0
        self.frames.append((self.t, struct.pack('>BI', bus, flags) + bytes(payload)))
        self.t += 1

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 209))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


def manf(letters):
    """Three letters packed into 15 bits, A = 1."""
    a, b, c = (ord(x) - 64 for x in letters)
    return struct.pack('>H', (a << 10) | (b << 5) | c)


def edid(letters='ZZX', product=0x1234, serial=0x00010203, week=10, year=20,
         version=(1, 3), size=128):
    blk = bytearray(HDR + manf(letters) + struct.pack('<HIBB', product, serial, week, year)
                    + bytes(version))
    blk += bytes(size - len(blk))
    if size == 128:
        blk[127] = (-sum(blk[:127])) & 0xff        # checksum
    return bytes(blk)


def main(out):
    c = Cap()
    c.i2c([EDID_W, 0x00], read=False)                         # 1 EDID request
    c.i2c(bytes([EDID_R]) + edid(), read=True)                # 2 EDID, week 10, year 2010
    c.i2c([EDID_W, 0x80], read=False)                         # 3 second block
    c.i2c(bytes([EDID_R]) + edid('ABC', 0xbeef, 0xdeadbeef, 255, 25, (1, 4)),
          read=True)                                          # 4 model year, EDID 1.4
    c.i2c(bytes([EDID_R]) + bytes(range(0x40, 0x60)), read=True)    # 5 not an EDID header (fragment)
    c.i2c([EDID_W, 0xff], read=False)                         # 6 offset 255
    c.i2c(bytes([EDID_R]) + edid('QRS', 0, 0, 1, 0, (2, 0), size=20), read=True)  # 7 only the first 20 octets
    c.i2c(bytes([EDID_R]) + edid('AAA', 1, 1, 52, 36, (1, 3)), read=True, bus=2)  # 8 bus 2
    # HDCP over the same DDC bus
    c.i2c([HDCP_W, 0x00], read=False)                         # 9 HDCP request B_ksv
    c.i2c(bytes([HDCP_R]) + struct.pack('<Q', 0x1122334455)[:5], read=True)  # 10 response
    c.i2c([HDCP_W, 0x40], read=False)                         # 11 B_caps request
    c.i2c([HDCP_R, 0x91], read=True)                          # 12 response
    # addresses that are not HDMI: not decoded by HDMI
    c.i2c([0x50, 0x00], read=False)                           # 13
    c.i2c([0x51, 0x01, 0x02], read=True)                      # 14
    c.i2c([0xA2, 0x00], read=False)                           # 15 (segment pointer, not decoded)
    c.write(os.path.join(out, 'hdmi-coverage.pcap'))

    m = Cap()
    m.i2c([EDID_W], read=False)                               # EDID request without offset
    m.i2c([EDID_R, 0x00, 0xff, 0xff], read=True)              # shorter than the EDID header
    m.i2c(bytes([EDID_R]) + HDR, read=True)                   # header only
    m.i2c(bytes([EDID_R]) + HDR + b'\x04\x43', read=True)     # ends in the manufacturer id
    m.i2c(bytes([EDID_R]) + HDR + manf('ZZX') + b'\x34\x12\x03', read=True)    # ends in the serial
    m.i2c(bytes([EDID_R]) + HDR + manf('ZZX') + struct.pack('<HIBB', 1, 2, 3, 4) + b'\x01',
          read=True)                                          # version cut after one octet
    m.i2c([EDID_R], read=True)                                # no data at all
    m.i2c([HDCP_W], read=False)                               # HDCP without register
    m.write(os.path.join(out, 'hdmi-coverage-malformed.pcap'))


main(sys.argv[1])
