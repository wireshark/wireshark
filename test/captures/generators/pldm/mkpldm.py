#!/usr/bin/env python3
# Generates test/captures/pldm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the PLDM coverage captures (PLDM over MCTP, Linux cooked capture
DLT 113, protocol 0x00FA = MCTP, MCTP message type 1).
Usage: mkpldm.py <outdir>.  Writes pldm-coverage.pcap and
pldm-coverage-malformed.pcap.  Every packet is built with struct; nothing
comes from a real network."""
import struct
import os
import sys

def pcap(fn, pkts, lt=113):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, lt))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

def sll(payload):
    # packet type host, ARPHRD_MCTP (290), no link layer address, protocol 0x00FA
    return struct.pack('>HHH8sH', 0, 290, 0, b'', 0x00fa) + payload

def mctp(payload, dst=8, src=9, tag=1, to=1):
    flags = (1 << 7) | (1 << 6) | (to << 3) | (tag & 7)
    return sll(bytes([1, dst, src, flags]) + payload)

REQ, RSP, ASYNC = 2, 0, 3
def pldm(direction, inst, ptype, cmd, body=b'', hver=0, tag=1, raw_type=None):
    b1 = (direction << 6) | (inst & 0x1f)
    b2 = (hver << 6) | (ptype if raw_type is None else raw_type)
    # the MCTP message type 1 octet is part of the MCTP payload
    return mctp(bytes([0x01, b1, b2, cmd]) + body, tag=tag, to=1 if direction != RSP else 0)

BASE, PLATFORM, BIOS, FRU, FWU = 0, 2, 3, 4, 5
def resp(inst, ptype, cmd, body=b'', cc=0):
    return pldm(RSP, inst, ptype, cmd, bytes([cc]) + body)

good = []
bad = []

# ---- base: messaging control and discovery ---------------------------------
good.append(pldm(REQ, 1, BASE, 0x01, b'\x42'))                                   # 1 SetTID
good.append(resp(1, BASE, 0x01))                                                 # 2 its response
good.append(pldm(REQ, 2, BASE, 0x02))                                            # 3 GetTID
good.append(resp(2, BASE, 0x02, b'\x42'))                                        # 4 its response
good.append(pldm(REQ, 3, BASE, 0x03, struct.pack('<IBB', 0, 1, 0)))              # 5 GetPLDMVersion
for i, ver in enumerate((bytes([0xf1, 0xf3, 0xf1, 0x00]),                        # 1.3.1
                         bytes([0x12, 0x34, 0x56, ord('a')]),                    # 12.34.56a
                         bytes([0xff, 0xff, 0xff, 0x00]),                        # every field unused
                         bytes([0xf0, 0x99, 0xf7, 0x01]))):                      # non-printable alpha byte (the fix)
    good.append(resp(3, BASE, 0x03, struct.pack('<IB', 0, 5) + ver))             # 6-9 GetPLDMVersion responses
good.append(resp(3, BASE, 0x03, b'', cc=1))                                      # 10 error completion code
good.append(pldm(REQ, 4, BASE, 0x04))                                            # 11 GetPLDMTypes
good.append(resp(4, BASE, 0x04, bytes([0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80])))   # 12 types 0,2,3,4,5 and 63
# GetPLDMCommands: the response is decoded by the type asked for in the request
VER = bytes([0xf1, 0xf0, 0xf0, 0x00])
good.append(pldm(REQ, 5, BASE, 0x05, bytes([0]) + VER))                          # 13 request for type 0
good.append(resp(5, BASE, 0x05, bytes([0x1f]) + bytes(31)))                      # 14 base commands 0-4
good.append(pldm(REQ, 5, BASE, 0x05, bytes([2]) + VER))                          # 15 the same instance asks for type 2
good.append(resp(5, BASE, 0x05, bytes([0x10, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08]) + bytes(20) +
                 bytes([0x02, 0x00, 0x00, 0x00])))                               # 16 platform commands
good.append(pldm(REQ, 6, BASE, 0x05, bytes([3]) + VER))                          # 17 type 3 (BIOS)
good.append(resp(6, BASE, 0x05, bytes([0x0f, 0x80])))                            # 18 BIOS commands
good.append(pldm(REQ, 7, BASE, 0x05, bytes([4]) + VER))                          # 19 type 4 (FRU)
good.append(resp(7, BASE, 0x05, bytes([0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80])))   # 20 FRU commands
good.append(pldm(REQ, 8, BASE, 0x05, bytes([5]) + VER))                          # 21 type 5: no decoding for the response
good.append(resp(8, BASE, 0x05, bytes(8)))                                       # 22
good.append(pldm(REQ, 9, BASE, 0x05, bytes([63]) + VER))                         # 23 OEM type (63 is stored as 7)
good.append(resp(9, BASE, 0x05, bytes(8)))                                       # 24
good.append(pldm(REQ, 10, BASE, 0x05, bytes([9]) + VER))                         # 25 invalid type
good.append(resp(11, BASE, 0x05, bytes(8)))                                      # 26 response without a request
good.append(pldm(REQ, 12, BASE, 0x20))                                           # 27 unknown base command
good.append(pldm(ASYNC, 13, BASE, 0x02))                                         # 28 asynchronous message
good.append(pldm(1, 14, BASE, 0x02))                                             # 29 reserved direction bits
good.append(pldm(REQ, 15, 1, 0x01))                                              # 30 PLDM for SMBIOS: no dissector for the type
good.append(pldm(REQ, 16, 63, 0x01, hver=1))                                     # 31 OEM type, header version 1
good.append(pldm(REQ, 17, 9, 0x01))                                              # 32 unknown type

# ---- platform monitoring and control -------------------------------------------
P = PLATFORM
good.append(pldm(REQ, 1, P, 0x04, bytes([3, 0, 8]) + struct.pack('<H', 100)))   # 33 SetEventReceiver, MCTP, heartbeat
good.append(pldm(REQ, 1, P, 0x04, bytes([1, 1, 0])))                             # 34 SetEventReceiver, other transport
good.append(pldm(REQ, 1, P, 0x04, bytes([0, 0, 8])))                             # 35 SetEventReceiver, MCTP, no heartbeat
good.append(resp(1, P, 0x04))                                                    # 36 response
good.append(resp(1, P, 0x04, cc=0x80))                                           # 37 platform completion code
def pem(cls, data):
    return bytes([1, 0x42, cls]) + data
good.append(pldm(REQ, 2, P, 0x0a, pem(0, struct.pack('<HB', 0x1234, 0) + bytes([1, 2]))))       # 38 sensor op state event
good.append(pldm(REQ, 2, P, 0x0a, pem(0, struct.pack('<HB', 0x1234, 1) + bytes([3, 4, 5]))))    # 39 state sensor state
for size, val in ((0, b'\x01'), (1, b'\xff'), (2, b'\x01\x02'), (3, b'\xff\xff'), (4, b'\x01\x02\x03\x04'),
                  (5, b'\xff\xff\xff\xff'), (6, b'')):
    good.append(pldm(REQ, 2, P, 0x0a, pem(0, struct.pack('<HB', 0x1234, 2) + bytes([1, 2, size]) + val)))   # 40-46 numeric sensor, every size
good.append(pldm(REQ, 2, P, 0x0a, pem(0, struct.pack('<HB', 0x1234, 7))))        # 47 unknown sensor event class
good.append(pldm(REQ, 2, P, 0x0a, pem(4, bytes([1, 2]) + bytes([0, 2]) + struct.pack('<II', 5, 6) + bytes([1, 1]) + struct.pack('<I', 7))))   # 48 PDR change, by type
good.append(pldm(REQ, 2, P, 0x0a, pem(4, bytes([2, 1]) + bytes([0, 2]) + struct.pack('<II', 5, 6))))     # 49 by record handle
good.append(pldm(REQ, 2, P, 0x0a, pem(4, bytes([0, 0]))))                         # 50 refresh the whole repository (no records)
good.append(pldm(REQ, 2, P, 0x0a, pem(4, bytes([0, 1, 0, 1]) + struct.pack('<I', 9))))                  # 51 data format 0 with a record
good.append(pldm(REQ, 2, P, 0x0a, pem(6, bytes([1, 77]))))                        # 52 heartbeat
good.append(pldm(REQ, 2, P, 0x0a, pem(5, b'')))                                   # 53 unknown event class
good.append(resp(2, P, 0x0a, b'\x01'))                                            # 54 response with status
good.append(pldm(REQ, 3, P, 0x21, struct.pack('<H', 5) + bytes([0x05, 0])))       # 55 GetStateSensorReadings with rearm bits
good.append(pldm(REQ, 3, P, 0x21, struct.pack('<H', 5) + bytes([0, 0])))          # 56 no rearm bits
good.append(resp(3, P, 0x21, bytes([2]) + bytes([1, 2, 3, 4]) + bytes([2, 3, 4, 5])))   # 57 two states
good.append(pldm(REQ, 4, P, 0x11, struct.pack('<HB', 6, 1)))                      # 58 GetSensorReading
for size, val in ((0, b'\x01'), (1, b'\xff'), (2, b'\x01\x02'), (3, b'\xff\xff'), (4, b'\x01\x02\x03\x04'),
                  (5, b'\xff\xff\xff\xff'), (6, b'')):
    good.append(resp(4, P, 0x11, bytes([size, 0, 1, 2, 3, 4]) + val))             # 59-65 every size
good.append(pldm(REQ, 5, P, 0x31, struct.pack('<HB', 7, 0) + b'\x01'))            # 66 SetNumericEffecterValue
for size, val in ((1, b'\xff'), (2, b'\x01\x02'), (3, b'\xff\xff'), (4, b'\x01\x02\x03\x04'), (5, b'\xff\xff\xff\xff'), (6, b'')):
    good.append(pldm(REQ, 5, P, 0x31, struct.pack('<HB', 7, size) + val))         # 67-72
good.append(resp(5, P, 0x31))                                                     # 73
good.append(pldm(REQ, 6, P, 0x32, struct.pack('<H', 7)))                          # 74 GetNumericEffecterValue
for size, val in ((0, b'\x01\x02'), (1, b'\xff\xfe'), (2, b'\x01\x02\x03\x04'), (3, b'\xff\xff\xfe\xff'),
                  (4, b'\x01\x02\x03\x04\x05\x06\x07\x08'), (5, b'\xff\xff\xff\xff\xfe\xff\xff\xff'), (6, b'')):
    good.append(resp(6, P, 0x32, bytes([size, 1]) + val))                         # 75-81 every size
good.append(pldm(REQ, 7, P, 0x39, struct.pack('<HB', 7, 2) + bytes([1, 2, 3, 4])))   # 82 SetStateEffecterStates
good.append(resp(7, P, 0x39))                                                     # 83
good.append(pldm(REQ, 8, P, 0x51, struct.pack('<IIBHH', 1, 0, 1, 100, 3)))        # 84 GetPDR
good.append(resp(8, P, 0x51, struct.pack('<IIBH', 2, 0, 1, 4) + b'abcd'))         # 85 start, 4 octets
good.append(resp(8, P, 0x51, struct.pack('<IIBH', 0, 0, 4, 0) + b'\x55'))             # 86 end with CRC and no record data
good.append(resp(8, P, 0x51, struct.pack('<IIBH', 0, 0, 0, 0)))                   # 87 nothing, no CRC
good.append(resp(8, P, 0x51, struct.pack('<IIBH', 0, 0, 1, 5) + b'ab'))           # 88 data length differs: corrupt
good.append(pldm(REQ, 9, P, 0x70))                                                # 89 unsupported command

# ---- FRU data -------------------------------------------------------------------------
def rec(rid, rtype, enc, fields):
    out = struct.pack('<HBBB', rid, rtype, len(fields), enc)
    for ft, val in fields:
        out += bytes([ft, len(val)]) + val
    return out
U16 = 'utf-16-le'
tbl = (rec(1, 1, 1, [(1, b'chassis'), (2, b'serial-1')]) +                  # ISO 8859-1
       rec(2, 1, 2, [(1, 'café'.encode())]) +                          # UTF-8
       rec(3, 1, 3, [(1, b'\xff\xfe' + 'bom'.encode(U16))]) +               # UTF-16 with a BOM
       rec(4, 1, 4, [(1, 'le'.encode(U16))]) +                              # UTF-16LE
       rec(5, 1, 5, [(1, 'be'.encode('utf-16-be'))]) +                      # UTF-16BE
       rec(6, 1, 6, [(1, b'xx')]) +                                         # unsupported encoding
       rec(7, 2, 1, []))                                                    # OEM record type, no fields
tbl_oem = rec(8, 2, 1, [(1, b'x')]) + b'\0' * 8                             # OEM type with a field: "Unsupported" per field
F = FRU
good.append(pldm(REQ, 1, F, 0x01))                                                       # 90 GetFRURecordTableMetadata
good.append(resp(1, F, 0x01, bytes([1, 0]) + struct.pack('<IIHHI', 4096, len(tbl), 7, 7, 0x1234)))   # 91
good.append(pldm(REQ, 2, F, 0x02, struct.pack('<IB', 0, 1)))                              # 92 GetFRURecordTable
good.append(resp(2, F, 0x02, struct.pack('<IB', 0, 5) + tbl))                             # 93 response with every encoding
good.append(resp(2, F, 0x02, struct.pack('<IB', 0, 5) + tbl + b'\xaa\xbb'))               # 94 response with bytes after the table
good.append(resp(2, F, 0x02, struct.pack('<IB', 0, 5) + tbl_oem))                         # 95 OEM record type with a field
good.append(resp(2, F, 0x02, b'', cc=0x81))                                               # 96 FRU completion code
good.append(resp(2, F, 0x02, b'', cc=0x05))                                               # 97 generic completion code
good.append(pldm(REQ, 3, F, 0x03, struct.pack('<IB', 0, 5) + tbl + struct.pack('<I', 0xdeadbeef)))   # 98 SetFRURecordTable with CRC
good.append(pldm(REQ, 3, F, 0x03, struct.pack('<IB', 0, 5) + tbl + b'\0\0' + struct.pack('<I', 0xdeadbeef)))   # 99 with padding before the CRC
good.append(pldm(REQ, 3, F, 0x03, struct.pack('<IB', 0, 5) + tbl[:0] + b'\0\0\0'))        # 100 only a short tail: no CRC
good.append(resp(3, F, 0x03, struct.pack('<I', 0)))                                       # 101
good.append(pldm(REQ, 4, F, 0x04, struct.pack('<IHHBBB', 0, 1, 2, 1, 3, 1)))              # 102 GetFRURecordByOption
good.append(resp(4, F, 0x04, struct.pack('<IB', 0, 5) + tbl + struct.pack('<I', 1)))      # 103 response with CRC
good.append(pldm(REQ, 5, F, 0x30))                                                        # 104 unsupported command

# ---- firmware update ----------------------------------------------------------------------------
def comp(i):
    return (struct.pack('<HHBIBB', 10 + i, 100 + i, i, 0x01020304, 1, 5) + b'20260115' +
            struct.pack('<IBB', 0x05060708, 1, 4) + b'20260116' + struct.pack('<HI', 0x0003, 120) +
            b'v1.0.' + b'next')
fwu_body = (struct.pack('<IHBBBB', 60, 2, 1, 6, 1, 4) + b'active' + b'pend' + comp(0) + comp(1))
W = FWU
good.append(pldm(REQ, 1, W, 0x02))                                                        # 105 GetFirmwareParameters
good.append(resp(1, W, 0x02, fwu_body))                                                   # 106 two components
good.append(resp(1, W, 0x02, struct.pack('<IHBBBB', 60, 0, 1, 0, 1, 0)))                  # 107 no components, no strings
good.append(resp(1, W, 0x02, b'', cc=0x85))                                               # 108 FWU completion code
good.append(resp(1, W, 0x02, b'', cc=0x97))                                               # 109 generic completion code (above 0x96)
good.append(pldm(REQ, 2, W, 0x10))                                                        # 110 other firmware update command

# ---- the typemap reproducer: two GetPLDMCommands requests for different types reuse
# one instance id; responses must decode by the request before them, in both passes
for inst in (20, 20):
    good.append(pldm(REQ, inst, BASE, 0x05, bytes([0]) + VER))                            # 111, 113
    good.append(resp(inst, BASE, 0x05, bytes([0x07]) + bytes(31)))                        # 112, 114

# ---- the 16-bit offset reproducer: FRU table over 64 KiB (kept in the malformed capture)
big = struct.pack('<IB', 0, 5) + rec(1, 1, 0, []) * 8200                                  # 8 octets per record, > 65535 octets
bad_big = pldm(REQ, 21, F, 0x03, big)
# a table over 64 KiB that is valid: records with fields to pass the 16-bit boundary
big_ok = struct.pack('<IB', 0, 5) + rec(1, 1, 1, [(1, b'a' * 200)] * 2) * 170              # 170 records of 413 octets: 70210
good.append(pldm(REQ, 22, F, 0x03, big_ok + struct.pack('<I', 0x1234)))                   # 115 FRU table over 64 KiB

# ---- malformed and error paths ----------------------------------------------------------
bad.append(bad_big)                                                                       # 1 records without any field (wrapped offset before the fix)
bad.append(mctp(bytes([0x01, 0x80, 0x00])))                                               # 2 PLDM header without a command (three octets)
bad.append(mctp(bytes([0x01, 0x80])))                                                     # 3 two octets
bad.append(mctp(bytes([0x01])))                                                           # 4 only the message type
bad.append(pldm(REQ, 1, BASE, 0x03, b'\0\0'))                                             # 5 GetPLDMVersion cut short
bad.append(resp(1, BASE, 0x04, bytes([0x3d, 0x00])))                                      # 6 GetPLDMTypes cut short
bad.append(pldm(REQ, 2, P, 0x0a, bytes([1, 0x42, 0])))                                    # 7 event without data
bad.append(resp(3, P, 0x11, bytes([2, 0, 1])))                                            # 8 reading cut short
bad.append(resp(2, F, 0x02, struct.pack('<IB', 0, 5) + rec(1, 1, 1, [(1, b'chassis')])[:-3]))   # 9 field value cut short
bad.append(resp(2, F, 0x02, struct.pack('<IB', 0, 5) + struct.pack('<HBBB', 1, 1, 200, 1) + b'\x01\x02ab' * 3))  # 10 record with 200 fields cut short
bad.append(resp(1, W, 0x02, fwu_body[:30]))                                               # 11 firmware parameters cut short
bad.append(resp(1, W, 0x02, struct.pack('<IHBBBB', 60, 5, 1, 0, 1, 0) + comp(0)))         # 12 five components, one present
bad.append(resp(30, BASE, 0x05, bytes(5)))                                                # 13 base commands response too short for type 2 (state from the typemap)

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'pldm-coverage.pcap'), good)
    pcap(os.path.join(out, 'pldm-coverage-malformed.pcap'), bad)
