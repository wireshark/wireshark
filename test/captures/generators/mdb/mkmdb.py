#!/usr/bin/env python3
# Generates test/captures/mdb_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MDB (Multi-Drop Bus) coverage captures.
Usage: mkmdb.py <outdir>.  Writes mdb-coverage.pcap and
mdb-coverage-malformed.pcap (link type 300, LINKTYPE_MDB)."""
import struct
import sys
import os

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 300))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 250000 * (i % 4), len(p), len(p)))
            f.write(p)

def mp(*data, bad=False):
    """master -> peripheral: version, event, address+command byte, data, checksum"""
    d = bytes(data)
    c = (sum(d) + (1 if bad else 0)) & 0xff
    return bytes([0, 0xff]) + d + bytes([c])

def pm(addr, *data, bad=False, chk=True):
    """peripheral -> master: version, event, address, data, checksum"""
    d = bytes(data)
    c = (sum(d) + (1 if bad else 0)) & 0xff
    return bytes([0, 0xfe, addr]) + d + (bytes([c]) if chk else b'')

def ident(n=29):
    # manufacturer code (3), serial number (12), model (12), version (2)
    return (b'ACM' + b'SN0000000001' + b'MODEL-0000001' [:12] + b'\x01\x02')[:n]

PRICE = struct.pack('>HH', 0x0064, 0x0007)

good = []
add = good.append
add(bytes([0, 0xfd, 0x00]))                                        # 1 bus reset
# Cashless #1 (0x10), master to peripheral
add(mp(0x10))                                                      # 2 Reset
add(mp(0x11, 0x00, 3, 16, 2, 0x05))                                # 3 Setup, config data
add(pm(0x10, 0x01, 3, 0x07, 0x78, 1, 2, 5))                        # 4 reader config data response
add(mp(0x11, 0x01, 0xff, 0xff, 0x00, 0x00))                        # 5 Setup, max/min prices unknown
add(mp(0x11, 0x01, 0x03, 0xe8, 0x00, 0x0a))                        # 6 Setup, max/min prices known
add(mp(0x11, 0x01, 0, 0, 0x27, 0x10, 0, 0, 0, 5, 0x07, 0x78))      # 7 Setup, expanded currency
add(mp(0x11, 0x01, 1, 2, 3))                                       # 8 Setup, max/min, other length
add(mp(0x12))                                                      # 9 Poll
add(pm(0x10, 0x00, chk=True))                                      # 10 just reset
add(mp(0x13, 0x00, 0x00, 0x64, 0x00, 0x07))                        # 11 vend request
add(mp(0x13, 0x00, 1, 2, 3))                                       # 12 vend request, other length
add(pm(0x10, 0x05, 0x00, 0x64))                                    # 13 vend approved
add(pm(0x10, 0x05, 0x00, 0x64, 0x00, 0x00))                        # 14 vend approved, expanded
add(mp(0x13, 0x02, 0x00, 0x07))                                    # 15 vend success
add(mp(0x13, 0x04))                                                # 16 session complete
add(mp(0x13, 0x03))                                                # 17 vend sub-command unknown
add(pm(0x10, 0x03, 0x00, 0x64))                                    # 18 begin session
add(pm(0x10, 0x06))                                                # 19 vend denied
add(pm(0x10, 0x07))                                                # 20 end session
add(mp(0x14, 0x01))                                                # 21 reader enable
add(mp(0x14, 0x00))                                                # 22 reader disable
add(mp(0x14, 0x55))                                                # 23 reader unknown sub-command
add(b"")                                                         # 24 replaced below
add(mp(0x17, 0x04, 0, 0, 0, 3))                                    # 25 expansion optional feature enabled
add(mp(0x17, 0x09, 1, 2))                                          # 26 expansion unknown sub-command
add(mp(0x15, 1, 2))                                                # 27 cashless unknown command
add(pm(0x10, 0x09, *ident(29), 0, 0, 0, 1))                        # 28 peripheral id response
add(pm(0x10, 0x0b))                                                # 29 command out of sequence
add(pm(0x10, 0x0d, 1, 2))                                          # 30 unknown response
add(bytes([0, 0xff, 0x00]))                                        # 32 ACK from the master
add(bytes([0, 0xfe, 0x10, 0xaa]))                                  # 33 RET from a peripheral
add(bytes([0, 0xfe, 0x10, 0xff]))                                  # 34 NAK
add(bytes([0, 0xff, 0x77]))                                        # 35 invalid ack byte
add(pm(0x10, 0xaa, chk=True))                                      # 37 data byte that looks like a reply: no checksum
# Communications Gateway (0x18)
add(mp(0x18))                                                      # 38 Reset
add(mp(0x19, 3, 1, 2))                                             # 39 Setup
add(pm(0x18, 0x01, 3, 0x00, 0x3c))                                 # 40 config response
add(mp(0x1a))                                                      # 41 Poll
add(mp(0x1b, 0x01, 1, 2, 3, 4))                                    # 42 Report, transaction
add(mp(0x1b, 0x02, *(b'DTSEVT0001'), 0x20, 0x26, 0x11, 0x07, 0x12, 0x34, 0, 0, 0x0e, 0x10, 1))  # 43 DTS event
add(mp(0x1b, 0x09))                                                # 44 unknown report sub-command
add(pm(0x18, 0x05))                                                # 45 DTS event acknowledge
add(mp(0x1f, 0x00))                                                # 46 expansion, identification
add(mp(0x1f, 0x01, 0, 0, 0, 1))                                    # 47 expansion, feature enable
add(mp(0x1f, 0x02))                                                # 48 expansion, time/date request
add(mp(0x1f, 0x7f))                                                # 49 unknown
add(pm(0x18, 0x06, *ident(29), 0, 0, 0, 2))                        # 50 peripheral id
add(pm(0x18, 0x0f, 9))                                             # 51 unknown response
add(mp(0x1c, 7))                                                   # 52 unknown command
# Bill Validator (0x30)
add(pm(0x30, 0x00, 0x00))                                          # 53 response before any request
add(mp(0x30))                                                      # 54 Reset
add(mp(0x31))                                                      # 55 Setup
add(pm(0x30, 1, 0x19, 0x99, 0x00, 0x01, 2, 0x00, 0x64, 0x00, 0xff, 0x01, *range(0, 16)))  # 56 setup response
add(mp(0x32, 0xff, 0xff))                                          # 57 Security
add(pm(0x30, 0xff, 0xff))                                          # 58 security response
add(mp(0x33))                                                      # 59 Poll
add(pm(0x30, 0x80 | 0x10 | 0x03))                                  # 60 poll: bill accepted (stacked)
add(mp(0x33))                                                      # 61 Poll
add(pm(0x30, 0x80 | 0x20 | 0x04))                                  # 62 poll: escrow position, type 4
add(mp(0x33))                                                      # 63
add(pm(0x30, 0x06))                                                # 64 poll: validator was reset
add(mp(0x33))                                                      # 65
add(pm(0x30, 0x1b))                                                # 66 poll: file transport layer
add(mp(0x33))                                                      # 67
add(pm(0x30, 0x0f))                                                # 68 poll: unknown state
add(mp(0x34, 0x00, 0x07, 0x00, 0x03))                              # 69 Bill type
add(pm(0x30, 0x00))                                                # 70 ACK (as data+chk 00)
add(mp(0x35, 0x01))                                                # 71 Escrow
add(pm(0x30, 0x00, 0x00))                                          # 72 escrow response
add(mp(0x36))                                                      # 73 Stacker
add(pm(0x30, 0x80, 0x05))                                          # 74 stacker response
# Bill Validator expansion: request, then the response where there is one
add(mp(0x37, 0x00)); add(pm(0x30, *ident(29)))                     # 75 76 level 1 identification
add(mp(0x37, 0x01, 0, 0, 0, 2))                                    # 77 level 2 feature enable (the fixed bug)
add(mp(0x37, 0x02)); add(pm(0x30, *ident(29), 0, 0, 0, 3))         # 78 79 id with option bits
add(mp(0x37, 0x03)); add(pm(0x30, 0x00, 0x03))                     # 80 81 recycler setup
add(mp(0x37, 0x04, 0x00, 0x03, *([3] * 16)))                       # 82 recycler enable
add(mp(0x37, 0x05)); add(pm(0x30, 0x00, 0x01, *range(32)))         # 83 84 bill dispense status
add(mp(0x37, 0x06, 2, 0, 5))                                       # 85 dispense bill
add(mp(0x37, 0x07, 0x00, 0x14))                                    # 86 dispense value
add(mp(0x37, 0x08)); add(pm(0x30, *([0, 3] * 16)))                 # 87 88 payout status
add(mp(0x37, 0x09)); add(pm(0x30, 0x00, 0x05))                     # 89 90 payout value poll
add(mp(0x37, 0x0a))                                                # 91 payout cancel
add(mp(0x37, 0x0b)); add(pm(0x30, 1, 2, 3))                        # 92 93 unknown sub-command
add(mp(0x33)); add(pm(0x30, 0x2a))                                 # 94 95 recycler "Bill Waiting"
# other peripherals: raw data
add(mp(0x08, 1, 2, 3))                                             # 96 Changer
add(pm(0x08, 4, 5, 6))                                             # 97
add(mp(0x60))                                                      # 98 Cashless #2, no data
add(pm(0x60, 0x00, 0x00))                                          # 99
# Cashless #1 expansion request id (a clean frame; frame 24 is built by hand above)
good[23] = mp(0x17, 0x00, *ident(29))

bad = [
    mp(0x11, 0x00, 3, 16),                                         # 1 truncated Setup config
    pm(0x10, 0x01, 3, 0x07),                                       # 2 truncated reader config data
    pm(0x10, 0x09, *ident(10)),                                    # 3 truncated peripheral id
    mp(0x17, 0x00, *ident(10)),                                    # 4 truncated expansion id
    mp(0x1b, 0x02, 1, 2, 3),                                       # 5 truncated DTS event
    pm(0x18, 0x06, *ident(10)),                                    # 6 truncated CGW id
    mp(0x30),                                                      # 7 Reset
    pm(0x30, 1, 0x19, 0x99),                                       # 8 reset response is not parsed
    mp(0x31),                                                      # 9
    pm(0x30, 1, 0x19, 0x99, 0, 1, 2),                              # 10 truncated setup response
    mp(0x34, 0, 7),                                                # 11 truncated bill type
    mp(0x37, 0x04, 0, 3, 3, 3),                                    # 12 truncated recycler enable
    mp(0x37), # 13 expansion without a sub-command
    mp(0x37, 0x08), pm(0x30, 0, 3),                                # 14 15 truncated payout status
    mp(0x37, 0x05), pm(0x30, 0, 1, 2, 3),                          # 16 17 truncated dispense status
    mp(0x33), pm(0x30),                                            # 18 19 empty poll response
    bytes([1, 0xff, 0x30, 0x31, 0x31]),                            # 20 version 1: not MDB
    bytes([0, 0x42, 0x30, 0x31, 0x31]),                            # 21 unknown event
    bytes([0, 0xff]),                                              # 22 too short
    mp(0x11, 0x01, 0xff, 0xff, 0x00, 0x00, bad=True),              # 23 bad checksum
    bytes([0, 0xfe, 0x10]),                                        # peripheral message without data (short packet)
    pm(0x30, 0x80, bad=True), pm(0x10, 0x03, 0x00, 0x64, bad=True), # 24 25
]
out = sys.argv[1]
pcap(os.path.join(out, 'mdb-coverage.pcap'), good)
pcap(os.path.join(out, 'mdb-coverage-malformed.pcap'), bad)
