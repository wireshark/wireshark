#!/usr/bin/env python3
# Generates test/captures/mctp_control_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MCTP Control Protocol coverage captures.
Usage: mkmctp-control.py <outdir>.  Writes mctp-control-coverage.pcap and
mctp-control-coverage-malformed.pcap (Linux cooked capture, DLT 113,
protocol 0x00FA = MCTP, message type 0 = MCTP control)."""
import struct
import sys
import os

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

def msg(payload, dst=8, src=9, to=1, tag=0):
    hdr = bytes([1, dst, src, 0xc0 | (to << 3) | tag])
    return struct.pack('>HHH8sH', 0, 290, 0, b'', 0x00fa) + hdr + payload

def rq(cmd, data=b'', inst=1, d=0, ic=0):
    return msg(bytes([ic << 7, 0x80 | (d << 6) | inst, cmd]) + data)

def rsp(cmd, cc, data=b'', inst=1):
    return msg(bytes([0, inst, cmd, cc]) + data, dst=9, src=8, to=0)

UUID = bytes.fromhex('00112233445566778899aabbccddeeff')
def ver(*entries):
    return bytes([len(entries)]) + b''.join(struct.pack('>I', e) for e in entries)

good = [
    rq(0x01, bytes([0x00, 0x10])),                                    # 1 Set EID, set
    rsp(0x01, 0, bytes([0x01, 0x10, 0x20])),                          # 2 accepted, pool allocation required, pool 32
    rq(0x01, bytes([0x01, 0x11]), inst=2),                            # 3 Set EID, force
    rsp(0x01, 0, bytes([0x12, 0x00, 0x00]), inst=2),                  # 4 rejected, already received allocation
    rq(0x01, bytes([0x02, 0x00]), inst=3),                            # 5 reset EID
    rq(0x01, bytes([0x03, 0x00]), inst=4),                            # 6 set discovered flag
    rq(0x02, inst=5),                                                 # 7 Get EID
    rsp(0x02, 0, bytes([0x42, 0x11, 0x00]), inst=5),                  # 8 bus owner/bridge, static EID matches
    rsp(0x02, 0, bytes([0x00, 0x03, 0x05]), inst=5),                  # 9 simple endpoint, static EID differs
    rq(0x03, inst=6),                                                 # 10 Get UUID
    rsp(0x03, 0, UUID, inst=6),                                       # 11
    rq(0x04, bytes([0xff]), inst=7),                                  # 12 Get version support, base spec
    rq(0x04, bytes([0x00]), inst=8),                                  # 13 control protocol
    rq(0x04, bytes([0x05]), inst=9),                                  # 14 SPDM
    rq(0x04, bytes([0x7e]), inst=10),                                 # 15 unknown message type
    rsp(0x04, 0, ver(0xf1f0ff00, 0xf1f3f300, 0xf3f71061, 0x1011f700), inst=7),  # 16 valid versions
    rsp(0x04, 0, ver(0xf1f0ff01, 0xf2f1f2ff), inst=8),                # 17 non-letter alpha byte, 0xff alpha
    rsp(0x04, 0, ver(), inst=9),                                      # 18 no entries
    rsp(0x04, 0, ver(0xfff0ff00), inst=10),                           # 19 0xff major: invalid BCD
    rsp(0x04, 0, ver(0xf1fa1000), inst=11),                           # 20 invalid minor nibble
    rsp(0x04, 0, ver(0xf1f0a500), inst=12),                           # 21 invalid update nibble
    rq(0x05, inst=11),                                                # 22 Get message type support
    rsp(0x05, 0, bytes([4, 0x00, 0x04, 0x05, 0x7e]), inst=11),        # 23
    rsp(0x05, 0, bytes([0]), inst=12),                                # 24 no types
    rq(0x08, bytes([0x00, 8, 0x20]), inst=13),                        # 25 Allocate EIDs
    rsp(0x08, 0, bytes([0x00, 8, 0x20]), inst=13),                    # 26 accepted
    rq(0x08, bytes([0x02, 0, 0]), inst=14),                           # 27 get allocation information
    rsp(0x08, 0, bytes([0x01, 0, 0]), inst=14),                       # 28 rejected
    rq(0x08, bytes([0x01, 4, 0x30]), inst=15),                        # 29 force allocation
    rq(0x0a, bytes([0x00]), inst=16),                                 # 30 Get routing table entries: no decoding
    rsp(0x0a, 0, bytes([0xff, 0x00, 0x01, 0x02]), inst=16),           # 31
    rq(0x0c, inst=17),                                                # 32 Endpoint Discovery
    rq(0x0d, inst=18, d=1),                                           # 33 Discovery Notify, datagram
    rq(0x0b, bytes([1]), inst=19),                                    # 34 Prepare for Endpoint Discovery
    rq(0x7e, bytes([1, 2]), inst=20),                                 # 35 unknown command
    rq(0xf3, inst=21),                                                # 36 transport binding command range
    rq(0x00, inst=22),                                                # 37 command 0
    rq(0x14, inst=23),                                                # 38 Query Supported Interfaces
    rsp(0x02, 0x01, inst=5),                                          # 39 completion code Error
    rsp(0x02, 0x02, bytes([1, 2, 3]), inst=5),                        # 40 invalid data, stale payload not decoded
    rsp(0x02, 0x03, inst=5),                                          # 41 invalid length
    rsp(0x02, 0x04, inst=5),                                          # 42 not ready
    rsp(0x02, 0x05, bytes([1, 2, 3]), inst=5),                        # 43 unsupported command, stale payload
    rsp(0x02, 0x80, bytes([1, 2, 3]), inst=5),                        # 44 command specific
    rsp(0x02, 0x06, inst=5),                                          # 45 unknown completion code
    rsp(0x02, 0, bytes([0x42, 0x11, 0x00, 0xde, 0xad]), inst=5),      # 46 trailing bytes after a decoded payload
    rsp(0x01, 0x03, inst=2),                                          # 47 Set EID error
    msg(bytes([0x80, 0x80, 0x02])),                                   # 48 message type 0 with IC set
    # too short for MCTP control: the message is the type byte only, or two bytes
    msg(bytes([0x00])),                                               # 49 bogus length 1
    msg(bytes([0x00, 0x80])),                                         # 50 bogus length 2
    msg(bytes([0x00, 0x00, 0x02]), dst=9, src=8, to=0),               # 51 response without completion code
    msg(bytes([0x00, 0x00, 0x7e]), dst=9, src=8, to=0),               # 52 same, unknown command
]
bad = [
    rsp(0x01, 0, bytes([0x01])),                                      # 1 truncated Set EID response
    rsp(0x04, 0, bytes([10]) + struct.pack('>I', 0xf1f0ff00)),        # 2 version count too high
    rsp(0x05, 0, bytes([9, 0, 4])),                                   # 3 message type count too high
    rq(0x01, bytes([0x00])),                                          # 4 truncated Set EID request
    rq(0x04),                                                         # 5 version request without message type
    rsp(0x03, 0, UUID[:9]),                                           # 6 truncated UUID
    rq(0x08, bytes([0x00, 1])),                                       # 7 truncated Allocate EIDs request
    rsp(0x08, 0, bytes([0x00])),                                      # 8 truncated Allocate EIDs response
    rsp(0x02, 0, bytes([0x42])),                                      # 9 truncated Get EID response
    rsp(0x04, 0, b''),                                                # 10 version response without a count
]
out = sys.argv[1]
pcap(os.path.join(out, 'mctp-control-coverage.pcap'), good)
pcap(os.path.join(out, 'mctp-control-coverage-malformed.pcap'), bad)
