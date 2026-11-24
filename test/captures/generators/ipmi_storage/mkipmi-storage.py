#!/usr/bin/env python3
# Generates test/captures/ipmi_storage_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-ipmi-storage.c (IPMI NetFn Storage: FRU, SDR
# repository, SEL and auxiliary log commands).
# usage: mkipmi-storage.py <outdir> [-v]   (prints the frame ranges with -v)
# Reached through RMCP+ on UDP 623; dissected with -o ipmi.dissect_bus_commands:TRUE.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from ipmilib import Cap, gz, req, rsp

NF = 10
ranges = []
def mark(cap, name, start):
    ranges.append((start, len(cap.frames), name))

class G:
    seq = 0

def nseq():
    G.seq = (G.seq % 63) + 1
    return G.seq

def pair(cap, cmd, rq, rs, cc=0, how='udp'):
    n = nseq()
    for m in (req(NF, cmd, rq, n), rsp(NF, cmd, rs, n, cc)):
        cap.udp(m) if how == 'udp' else cap.exp(m)

def rq(cap, cmd, data=b''):
    cap.udp(req(NF, cmd, data, nseq()))

def rs(cap, cmd, data=b'', cc=0):
    cap.udp(rsp(NF, cmd, data, nseq(), cc))

def u16(v): return struct.pack('<H', v)
def u32(v): return struct.pack('<I', v)

TS = (0xffffffff, 0x00001000, 0x20000000, 0x20000001, 0x5f000000)
SEL_ENTRY = u16(1) + bytes([2]) + u32(0x5f000000) + u16(0x20) + bytes([0x04, 0x01, 0x12, 0x6f, 0xa0, 0x01, 0x02])

def build(cap):
    # --- FRU
    s = len(cap.frames)
    pair(cap, 0x10, b'\x00', u16(512) + b'\x00')                    # Get FRU Inventory Area Info, accessed by bytes
    pair(cap, 0x10, b'\x01', u16(4096) + b'\x01')                   # by words
    pair(cap, 0x11, b'\x00' + u16(0) + b'\x08', bytes([8]) + bytes(range(8)))      # Read FRU Data
    pair(cap, 0x11, b'\x01' + u16(0x100) + b'\x20', bytes([1, 0xaa]))
    pair(cap, 0x11, b'\x01' + u16(0x100) + b'\x20', b'', cc=0x81)
    pair(cap, 0x12, b'\x00' + u16(8) + b'\x01\x02\x03\x04', b'\x04')   # Write FRU Data
    pair(cap, 0x12, b'\x00' + u16(8) + b'\x01', b'', cc=0x80)
    pair(cap, 0x12, b'\x00' + u16(8) + b'\x01', b'', cc=0x81)
    mark(cap, 'FRU: Get Inventory Area Info, Read, Write', s + 1)

    # --- SDR repository
    s = len(cap.frames)
    for ts in TS:
        pair(cap, 0x20, b'', b'\x51' + u16(100) + u16(0x4000) + u32(ts) + u32(0x1000) + b'\xaf')    # Get SDR Repository Info
    pair(cap, 0x20, b'', b'\x51' + u16(0) + u16(0) + u32(0) + u32(0) + b'\x00')
    pair(cap, 0x21, b'', u16(100) + u16(16) + u16(50) + u16(40) + b'\x10')
    pair(cap, 0x22, b'', u16(0x1234))                              # Reserve SDR Repository
    pair(cap, 0x23, u16(0x1234) + u16(0) + b'\x00\xff', u16(1) + bytes(range(16)))   # Get SDR, entire record
    pair(cap, 0x23, u16(0x1234) + u16(5) + b'\x05\x10', u16(0xffff) + bytes(range(16)))
    pair(cap, 0x24, bytes(range(20)), u16(0x0007))                  # Add SDR
    pair(cap, 0x25, u16(0x1234) + u16(0) + b'\x00\x00' + bytes(range(8)), u16(9))     # Partial Add SDR
    pair(cap, 0x25, u16(0x1234) + u16(9) + b'\x08\x01' + bytes(range(8)), u16(9))
    pair(cap, 0x25, u16(0x1234) + u16(9) + b'\x08\x01' + bytes(range(8)), b'', cc=0x80)
    pair(cap, 0x26, u16(0x1234) + u16(7), u16(7))                   # Delete SDR
    pair(cap, 0x27, u16(0x1234) + b'CLR\xaa', b'\x00')              # Clear SDR Repository
    pair(cap, 0x27, u16(0x1234) + b'CLR\x00', b'\x01')
    pair(cap, 0x27, u16(0x1234) + b'XYZ\x55', b'\x03')
    for ts in TS:
        pair(cap, 0x28, b'', u32(ts))                              # Get SDR Repository Time
    pair(cap, 0x29, u32(0x5f000000), b'')                          # Set SDR Repository Time
    pair(cap, 0x2a, b'', b'')                                      # Enter/Exit Update Mode
    pair(cap, 0x2b, b'', b'')
    pair(cap, 0x2c, b'\x01', b'\x01')                              # Run Initialization Agent
    pair(cap, 0x2c, b'\x00', b'\x00')
    mark(cap, 'SDR repository commands', s + 1)

    # --- SEL
    s = len(cap.frames)
    for ts in TS:
        pair(cap, 0x40, b'', b'\x51' + u16(100) + u16(0x4000) + u32(ts) + u32(0x5f000000) + b'\xbf')    # Get SEL Info
    pair(cap, 0x40, b'', b'', cc=0x81)
    pair(cap, 0x41, b'', u16(100) + u16(16) + u16(50) + u16(40) + b'\x10')
    pair(cap, 0x42, b'', u16(0x4321))                              # Reserve SEL
    pair(cap, 0x42, b'', b'', cc=0x81)
    pair(cap, 0x43, u16(0x4321) + u16(0) + b'\x00\xff', u16(2) + SEL_ENTRY)                      # Get SEL Entry
    pair(cap, 0x43, u16(0) + u16(0xffff) + b'\x04\x08', u16(0xffff) + SEL_ENTRY[4:12])
    pair(cap, 0x43, u16(0) + u16(0xffff) + b'\x00\xff', b'', cc=0x81)
    pair(cap, 0x44, SEL_ENTRY, u16(3))                             # Add SEL Entry
    pair(cap, 0x44, SEL_ENTRY, b'', cc=0x80)
    pair(cap, 0x44, SEL_ENTRY, b'', cc=0x81)
    pair(cap, 0x45, u16(0x4321) + u16(0) + b'\x00\x00' + SEL_ENTRY[:8], u16(3))       # Partial Add SEL Entry
    pair(cap, 0x45, u16(0x4321) + u16(3) + b'\x08\x01' + SEL_ENTRY[8:], u16(3))
    pair(cap, 0x45, u16(0x4321) + u16(3) + b'\x08\x01' + SEL_ENTRY[8:], b'', cc=0x80)
    pair(cap, 0x45, u16(0x4321) + u16(3) + b'\x08\x01' + SEL_ENTRY[8:], b'', cc=0x81)
    pair(cap, 0x46, u16(0x4321) + u16(3), u16(3))                   # Delete SEL Entry
    pair(cap, 0x46, u16(0x4321) + u16(3), b'', cc=0x80)
    pair(cap, 0x46, u16(0x4321) + u16(3), b'', cc=0x81)
    pair(cap, 0x47, u16(0x4321) + b'CLR\xaa', b'\x00')              # Clear SEL
    pair(cap, 0x47, u16(0x4321) + b'CLR\x00', b'\x01')
    for ts in TS:
        pair(cap, 0x48, b'', u32(ts))                              # Get SEL Time
        pair(cap, 0x49, u32(ts), b'')                              # Set SEL Time
    mark(cap, 'SEL commands', s + 1)

    # --- Auxiliary log status: the response is decoded by the log type of the request
    s = len(cap.frames)
    pair(cap, 0x5a, b'\x00', u32(0x5f000000) + u32(12))             # MCA log
    pair(cap, 0x5a, b'\x01', u32(0x1000) + b'\x57\x01\x00' + b'\x11' * 7)       # OEM 1
    pair(cap, 0x5a, b'\x02', u32(0xffffffff) + b'\x57\x01\x00' + b'\x22' * 7)    # OEM 2
    pair(cap, 0x5a, b'\x03', u32(1) + u32(2) + u32(3))              # unknown log type
    pair(cap, 0x5a, b'\xf0', u32(1) + u32(2) + u32(3))              # type in the low nibble only
    rs(cap, 0x5a, u32(0x1000) + u32(5))                             # response without a request
    pair(cap, 0x5b, b'\x00' + u32(0x5f000000) + u32(7), b'')        # Set Auxiliary Log Status
    pair(cap, 0x5b, b'\x10' + u32(0) + u32(7), b'')                 # log type 0 with reserved bits set (fixed)
    pair(cap, 0x5b, b'\x01' + u32(0x1000) + b'\x57\x01\x00' + b'\x33' * 8, b'')
    pair(cap, 0x5b, b'\x02' + u32(0x1000) + b'\x57\x01\x00' + b'\x33' * 8, b'')
    pair(cap, 0x5b, b'\x03' + b'\x01\x02\x03\x04', b'')             # unknown log type
    pair(cap, 0x5b, b'\xf3' + b'\x01\x02\x03\x04', b'')
    pair(cap, 0x5c, b'', b'\x00\x00')                               # not decoded
    pair(cap, 0x5d, b'\x00\x00', b'')
    pair(cap, 0x7f, b'\x01', b'\x02')                               # unknown
    mark(cap, 'Auxiliary log status (Get/Set), undecoded and unknown commands', s + 1)

    s = len(cap.frames)
    pair(cap, 0x10, b'\x00', u16(512) + b'\x00', how='exp')
    mark(cap, 'Exported PDU', s + 1)

def build_malformed(cap):
    G.seq = 0
    short = {0x10: (b'', b'\x01'), 0x11: (b'\x01\x02', b''), 0x12: (b'\x01\x02', b''), 0x20: (b'', b'\x01' * 13),
             0x21: (b'', b'\x01' * 8), 0x22: (b'', b'\x01'), 0x23: (b'\x01' * 5, b'\x01'), 0x24: (b'', b''),
             0x25: (b'\x01' * 5, b'\x01'), 0x26: (b'\x01' * 3, b'\x01'), 0x27: (b'\x01' * 5, b''), 0x28: (b'', b'\x01'),
             0x29: (b'\x01', b''), 0x2c: (b'', b''), 0x40: (b'', b'\x01' * 13), 0x41: (b'', b'\x01' * 8),
             0x42: (b'', b'\x01'), 0x43: (b'\x01' * 5, b'\x01'), 0x44: (b'', b''), 0x45: (b'\x01' * 5, b'\x01'),
             0x46: (b'\x01' * 3, b'\x01'), 0x47: (b'\x01' * 5, b''), 0x48: (b'', b'\x01\x02'), 0x49: (b'\x01\x02', b''),
             0x5a: (b'', b'\x01'), 0x5b: (b'\x00\x01\x02', b'')}
    for c, (q, r) in short.items():
        cap.exp(req(NF, c, q, 1))
        cap.exp(rsp(NF, c, r, 1))
    # Read FRU Data returning no data: the empty byte array raises an exception (observation)
    cap.exp(rsp(NF, 0x11, bytes([0]), 6))
    # auxiliary log status cut short for each log type
    cap.exp(req(NF, 0x5a, b'\x00', 2)); cap.exp(rsp(NF, 0x5a, b'\x01\x02\x03\x04\x05', 2))
    cap.exp(req(NF, 0x5a, b'\x01', 3)); cap.exp(rsp(NF, 0x5a, b'\x01\x02\x03\x04\x05\x06\x07\x08', 3))
    cap.exp(req(NF, 0x5b, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09', 4))
    cap.exp(req(NF, 0x5b, b'\x03', 5))

def main():
    out = sys.argv[1]
    cap = Cap(); build(cap)
    cap.write_pcapng(os.path.join(out, 'ipmi-storage-coverage.pcapng'))
    gz(os.path.join(out, 'ipmi-storage-coverage.pcapng'))
    os.replace(os.path.join(out, 'ipmi-storage-coverage.pcapng.gz'), os.path.join(out, 'ipmi_storage_coverage.pcapng.gz'))
    bad = Cap(); build_malformed(bad)
    bad.write_pcapng(os.path.join(out, 'ipmi-storage-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for a, b, n in ranges:
            print('%5d-%-5d %s' % (a, b, n))
        print('main %d frames, malformed %d frames' % (len(cap.frames), len(bad.frames)))

main()
