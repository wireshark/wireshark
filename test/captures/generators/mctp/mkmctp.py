#!/usr/bin/env python3
# Generates test/captures/mctp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MCTP coverage captures.
Usage: mkmctp.py <outdir>.  Writes mctp-coverage.pcap and
mctp-coverage-malformed.pcap (Linux cooked capture, DLT 113, protocol
0x00FA = MCTP)."""
import struct
import sys
import os

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

def sll(payload):
    # packet type host, ARPHRD_MCTP (290), no link layer address, protocol 0x00FA
    return struct.pack('>HHH8sH', 0, 290, 0, b'', 0x00fa) + payload

def mctp(dst, src, payload, som=1, eom=1, seq=0, to=1, tag=0, ver=1):
    flags = (som << 7) | (eom << 6) | ((seq & 3) << 4) | (to << 3) | (tag & 7)
    return sll(bytes([ver, dst, src, flags]) + payload)

CTRL_GET_EID_RQ = bytes([0x00, 0x80, 0x02])
CTRL_GET_EID_RSP = bytes([0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00])
# NC-SI Clear Initial State command (type 2 = NC-SI over MCTP, IC clear),
# 16 byte header and the 4 byte checksum
NCSI = bytes([0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
ETH = bytes.fromhex('aabbccddeeff102233445566') + b'\x88\xb5' + b'ethernet over mctp pad' + bytes(20)

good = [
    mctp(8, 9, CTRL_GET_EID_RQ, tag=1),                              # 1 control request, tag owner
    mctp(9, 8, CTRL_GET_EID_RSP, to=0, tag=1),                       # 2 control response
    mctp(8, 9, bytes([0x01, 0x80, 0x00, 0x02]), tag=2),              # 3 PLDM
    mctp(8, 9, bytes([0x85, 0x10, 0x84, 0x00]), tag=3),              # 4 SPDM with IC: no sub-dissection
    mctp(8, 9, bytes([0x05, 0x10, 0x84, 0x00]), tag=3),              # 5 SPDM, nothing registered, encap table has no entry
    mctp(8, 9, bytes([0x03]) + ETH, tag=4),                          # 6 Ethernet encapsulation
    mctp(8, 9, bytes([0x02]) + NCSI, tag=5),                         # 7 NC-SI encapsulation
    mctp(8, 9, bytes([0x7e, 0x01, 0x02]), tag=6),                    # 8 vendor defined PCI
    mctp(8, 9, bytes([0x7f, 0x00, 0x00, 0x11, 0x22]), tag=7),        # 9 vendor defined IANA
    mctp(8, 9, bytes([0x09, 1, 2, 3]), tag=0),                       # 10 PCIe MI type, no dissector
    mctp(8, 9, bytes([0x42, 1]), tag=0),                             # 11 unknown message type
    # a fragmented message, three packets (SOM, middle, EOM)
    mctp(8, 9, bytes([0x05, 0x01, 0x02, 0x03, 0x04]), som=1, eom=0, seq=0, to=1, tag=2),   # 12
    mctp(8, 9, bytes([0x11, 0x12, 0x13, 0x14]), som=0, eom=0, seq=1, to=1, tag=2),         # 13
    mctp(8, 9, bytes([0x21, 0x22]), som=0, eom=1, seq=2, to=1, tag=2),                     # 14
    # the response with the same tag value, TO clear, interleaved with another request
    mctp(9, 8, bytes([0x05, 0xa1, 0xa2]), som=1, eom=0, seq=0, to=0, tag=2),               # 15
    mctp(8, 9, bytes([0x05, 0xb1, 0xb2]), som=1, eom=0, seq=0, to=1, tag=2),               # 16
    mctp(9, 8, bytes([0xa3, 0xa4]), som=0, eom=1, seq=1, to=0, tag=2),                     # 17
    mctp(8, 9, bytes([0xb3, 0xb4, 0xb5]), som=0, eom=1, seq=1, to=1, tag=2),               # 18
    # a fragmented control message
    mctp(8, 9, bytes([0x00, 0x80]), som=1, eom=0, seq=0, to=1, tag=3),                     # 19
    mctp(8, 9, bytes([0x02]), som=0, eom=1, seq=1, to=1, tag=3),                           # 20
    # a start without an end, an end without a start, a middle fragment alone
    mctp(8, 9, bytes([0x05, 9, 9, 9]), som=1, eom=0, seq=0, to=1, tag=5),                  # 21
    mctp(8, 9, bytes([1, 2, 3]), som=0, eom=1, seq=1, to=1, tag=6),                        # 22
    mctp(8, 9, bytes([4, 5, 6]), som=0, eom=0, seq=2, to=0, tag=7),                        # 23
    # short and invalid packets
    sll(bytes([1, 8, 9, 0xc8])),                                      # 24 header only: bogus length
    sll(bytes([1, 8, 9])),                                            # 25 three bytes: bogus length
    mctp(8, 9, bytes([0x00, 0x80, 0x02]), ver=2),                     # 26 invalid version
    mctp(8, 9, bytes([0x00, 0x80, 0x02]), ver=0),                     # 27 version 0
    mctp(0xff, 9, bytes([0x00, 0x80, 0x02]), tag=1),                  # 28 broadcast destination
]
bad = [
    sll(bytes([1, 8])),                                               # 1 truncated header
    sll(bytes([1, 8, 9, 0xc8, 0x03]) ) ,                              # 2 Ethernet encapsulation without data
    mctp(8, 9, bytes([0x03, 1, 2, 3]), tag=1),                        # 3 truncated Ethernet frame
    mctp(8, 9, bytes([0x02, 1, 2, 3]), tag=1),                        # 4 truncated NC-SI
]
out = sys.argv[1]
pcap(os.path.join(out, 'mctp-coverage.pcap'), good)
pcap(os.path.join(out, 'mctp-coverage-malformed.pcap'), bad)
