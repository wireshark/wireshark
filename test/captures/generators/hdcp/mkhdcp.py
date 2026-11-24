#!/usr/bin/env python3
# Generates test/captures/hdcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the HDCP coverage captures.  Usage: mkhdcp.py <outdir>

HDCP 1.x register traffic on the DDC (I2C) bus of an HDMI link, carried
in pcap link type 209 (I2C with the Linux pseudo-header).  HDCP has no
port or heuristic of its own: it is reached through the HDMI dissector
(which needs Decode As "i2c.message" = HDMI) for the I2C addresses 0x74
(write) and 0x75 (read).  All key selection vectors and random numbers
are made-up placeholder values; nothing comes from a real network."""
import struct
import sys
import os

HDCP_W, HDCP_R = 0x74, 0x75

REG_BKSV, REG_AKSV, REG_AN, REG_BCAPS, REG_BSTATUS = 0x00, 0x10, 0x18, 0x40, 0x41


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000

    def i2c(self, payload, read, bus=1):
        """One I2C message: 5 octet pseudo-header (bus, flags) + payload."""
        flags = 1 if read else 0
        self.frames.append((self.t, struct.pack('>BI', bus, flags) + bytes(payload)))
        self.t += 1

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 209))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


def ksv(v):
    """5 octet little endian key selection vector (placeholder)."""
    return struct.pack('<Q', v)[:5]


def request(c, reg):
    c.i2c([HDCP_W, reg], read=False)


def response(c, data):
    c.i2c(bytes([HDCP_R]) + bytes(data), read=True)


def main(out):
    c = Cap()
    # 1 a read before any request: link verification without a transaction
    response(c, struct.pack('<H', 0x0a0b))
    # 2-3 the transmitter reads B_ksv of the receiver
    request(c, REG_BKSV)
    response(c, ksv(0x1122334455))
    # 3-4 B_caps: repeater, KSV fifo ready, 400 kHz, features, fast reauth
    request(c, REG_BCAPS)
    response(c, [0xf3])
    # 5-6 B_caps with no bits set
    request(c, REG_BCAPS)
    response(c, [0x00])
    # 7 A_ksv, 8 An
    c.i2c(bytes([HDCP_W, REG_AKSV]) + ksv(0xaabbccddee), read=False)
    c.i2c(bytes([HDCP_W, REG_AN]) + struct.pack('<Q', 0x0102030405060708), read=False)
    # 9-10 B_status: HDMI mode, depth 5, 12 downstream, both exceeded bits
    request(c, REG_BSTATUS)
    response(c, struct.pack('<H', 0x1000 | 0x0800 | (5 << 8) | 0x0080 | 12))
    # 11-12 B_status with all bits clear
    request(c, REG_BSTATUS)
    response(c, struct.pack('<H', 0))
    # 13 the transmitter writes another register (Aksv-like but not 0x10/0x18)
    c.i2c(bytes([HDCP_W, 0x20]) + b'\x00\x01\x02', read=False)
    # 14 a read of Ri' with no pending request: link verification
    response(c, struct.pack('<H', 0x3c4d))
    # 15-16 a request for a register that has no name, and its response
    request(c, 0x08)
    response(c, struct.pack('<H', 0x5e6f))
    # 17 link verification again (the request above is already answered)
    response(c, struct.pack('<H', 0x7081))
    # 18 a read of another length with no pending request: nothing decoded
    response(c, b'\x01\x02\x03')
    # 19 a request that is never answered, followed by another request
    request(c, REG_BKSV)
    request(c, REG_BCAPS)
    # 21 the response goes to the last request
    response(c, [0x40])
    # 22 request with a trailing write of B_ksv sized data (a write)
    c.i2c(bytes([HDCP_W, REG_BKSV]) + ksv(0x99), read=False)
    # 23 a response with the register of B_ksv, then 24 request B_ksv
    # again and a second response in the same exchange
    request(c, REG_BKSV)
    response(c, ksv(0x2233445566))
    response(c, struct.pack('<H', 0x9293))              # 25 link verification
    c.write(os.path.join(out, 'hdcp-coverage.pcap'))

    # malformed: short messages (exceptions in the register readers)
    m = Cap()
    request(m, REG_BKSV)
    response(m, [0x01, 0x02])                    # B_ksv of two octets
    request(m, REG_BSTATUS)
    response(m, [0x01])                          # B_status of one octet
    request(m, REG_BCAPS)
    response(m, [])                              # B_caps without data
    m.i2c([HDCP_W, REG_AKSV, 1, 2], read=False)  # A_ksv truncated
    m.i2c([HDCP_W, REG_AN, 1, 2, 3], read=False) # An truncated
    m.i2c([HDCP_W], read=False)                  # no register
    m.i2c([HDCP_R], read=True)                   # empty read
    m.write(os.path.join(out, 'hdcp-coverage-malformed.pcap'))


main(sys.argv[1])
