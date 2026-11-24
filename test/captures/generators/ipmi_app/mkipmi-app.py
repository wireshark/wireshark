#!/usr/bin/env python3
# Generates test/captures/ipmi_app_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-ipmi-app.c (IPMI NetFn Application).
# usage: mkipmi-app.py <outdir> [-v]   (prints the frame ranges with -v)
# The commands are reached through RMCP+ on UDP 623 (default path); they are
# only dissected with -o ipmi.dissect_bus_commands:TRUE.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from ipmilib import Cap, gz, ipmb, req, rsp

NF = 6
ranges = []
def mark(cap, name, start):
    ranges.append((start, len(cap.frames), name))

class G:
    seq = 1

def pair(cap, cmd, rq, rs, cc=0, how='udp', **kw):
    G.seq = (G.seq % 63) + 1
    q = req(NF, cmd, rq, G.seq)
    r = rsp(NF, cmd, rs, G.seq, cc)
    for m in (q, r):
        cap.udp(m, **kw) if how == 'udp' else cap.exp(m)

def rq(cap, cmd, data=b''):
    G.seq = (G.seq % 63) + 1
    cap.udp(req(NF, cmd, data, G.seq))

def rs(cap, cmd, data=b'', cc=0):
    G.seq = (G.seq % 63) + 1
    cap.udp(rsp(NF, cmd, data, G.seq, cc))

def build(cap):
    # --- IPM device global commands
    s = len(cap.frames)
    devid = bytes([0x20, 0x81, 0x05, 0x02, 0x02, 0xbf, 0x57, 0x01, 0x00, 0x34, 0x12, 1, 2, 3, 4])
    pair(cap, 0x01, b'', devid)                                  # Get Device ID with auxiliary revision
    pair(cap, 0x01, b'', bytes([0, 0, 0x80, 0x99, 0x51, 0x00, 0, 0, 0, 0, 0]))   # none supported, update in progress
    pair(cap, 0x01, b'', bytes([0xff, 0xff, 0x7f, 0x59, 0x15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 9, 9, 9, 9]))
    pair(cap, 0x02, b'', b'')                                    # Cold Reset
    pair(cap, 0x03, b'', b'')                                    # Warm Reset
    for res, fail in ((0x55, 0), (0x56, 0), (0xff, 0), (0x57, 0xff), (0x57, 0x00), (0x57, 0xa5), (0x58, 0x12), (0x60, 0x34)):
        pair(cap, 0x04, b'', bytes([res, fail]))                 # Get Self Test Results
    rq(cap, 0x05, b'\x01\x02\x03')                               # Manufacturing Test On
    rs(cap, 0x05, b'')
    pair(cap, 0x06, bytes([0x80 | 0x05, 0x80 | 0x02]), b'')      # Set ACPI Power State
    pair(cap, 0x06, bytes([0x7f, 0x2a]), b'')
    pair(cap, 0x07, b'', bytes([0x05, 0x03]))                    # Get ACPI Power State
    pair(cap, 0x07, b'', bytes([0x2a, 0x2a]))
    pair(cap, 0x08, b'', bytes.fromhex('00112233445566778899aabbccddeeff'))   # Get Device GUID
    mark(cap, 'Get Device ID, resets, self test, test mode, ACPI power state, GUID', s + 1)

    # --- commands without a decoder, and unknown commands
    s = len(cap.frames)
    for c in (0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x35, 0x36, 0x37, 0x3d, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
              0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x52, 0x54, 0x55, 0x56, 0x57,
              0x58, 0x59, 0x60, 0x61, 0x62, 0x63, 0x64):
        pair(cap, c, b'\x01\x02', b'\x03\x04')
    pair(cap, 0x7f, b'\x01', b'\x02')                                # unknown
    mark(cap, 'Commands that are not decoded (expert info) and an unknown command', s + 1)

    # --- watchdog
    s = len(cap.frames)
    rq(cap, 0x22); rs(cap, 0x22, b'', cc=0x80)                    # Reset Watchdog Timer, not initialized
    pair(cap, 0x22, b'', b'')
    pair(cap, 0x24, bytes([0xc4, 0x13, 5, 0x3e, 0x10, 0x27]), b'')     # Set Watchdog Timer
    pair(cap, 0x24, bytes([0x01, 0x00, 0, 0x00, 0, 0]), b'')
    pair(cap, 0x25, b'', bytes([0x45, 0x23, 3, 0x3e, 0x10, 0x27, 0xe8, 0x03]))   # Get Watchdog Timer
    pair(cap, 0x25, b'', bytes([0xc3, 0x7f, 0, 0x00, 0, 0, 0, 0]))
    mark(cap, 'Watchdog timer', s + 1)

    # --- BMC global enables and message flags
    s = len(cap.frames)
    pair(cap, 0x2e, b'\xff', b'')
    pair(cap, 0x2e, b'\x00', b'')
    pair(cap, 0x2f, b'', b'\xff')
    pair(cap, 0x2f, b'', b'\x00')
    pair(cap, 0x30, b'\xff', b'')
    pair(cap, 0x30, b'\x00', b'')
    pair(cap, 0x31, b'', b'\xff')
    pair(cap, 0x31, b'', b'\x00')
    pair(cap, 0x32, bytes([0x01, 0x00]), bytes([0x01, 0x00]))      # Enable Message Channel Receive
    pair(cap, 0x32, bytes([0x0f, 0x02]), bytes([0x0f, 0x01]))
    mark(cap, 'BMC global enables, message flags, message channel receive', s + 1)

    # --- Get Message / Send Message (bridging)
    s = len(cap.frames)
    inner = ipmb(0x20, 6, 0x81, 9, 0x01, b'')
    inner_nt = inner[1:]
    for chan, msg in ((0, inner_nt), (1, bytes([4]) + inner), (1, inner), (1, inner_nt), (15, bytes([4]) + inner), (7, inner_nt)):
        rq(cap, 0x33); rs(cap, 0x33, bytes([(2 << 4) | chan]) + msg)
    rq(cap, 0x33); rs(cap, 0x33, b'', cc=0x80)                     # queue empty
    for chan, track, msg in ((0, 0, inner), (1, 1, bytes([5]) + inner), (3, 2, inner), (15, 0, inner), (0, 0, b'\x00' + inner)):
        rq(cap, 0x34, bytes([(track << 6) | 0x20 | 0x10 | chan]) + msg)
        rs(cap, 0x34, b'')
    rq(cap, 0x34, bytes([0]) + inner)
    rs(cap, 0x34, ipmb(0x81, 7, 0x20, 9, 0x01, b'\x00' + devid))   # response data holding an IPMB response
    for cc in (0x80, 0x81, 0x82, 0x83):
        pair(cap, 0x34, bytes([0]) + inner, b'', cc=cc)
    mark(cap, 'Get Message and Send Message (channels, tracking, nested messages)', s + 1)

    # --- authentication and session commands
    s = len(cap.frames)
    pair(cap, 0x38, bytes([0x8e, 0x04]), bytes([0x0e, 0xbf, 0x3f, 0x03, 0x00, 0x00, 0x00, 0x00]))   # Get Channel Authentication Capabilities
    pair(cap, 0x38, bytes([0x01, 0x02]), bytes([0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x09]))
    pair(cap, 0x38, bytes([0x0f, 0x05]), bytes([0x0f, 0x97, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x00]))
    pair(cap, 0x39, bytes([0x02]) + b'admin'.ljust(16, b'\0'), bytes([1, 2, 3, 4]) + bytes(range(0xa0, 0xb0)))     # Get Session Challenge
    pair(cap, 0x39, bytes([0x05]) + b'\0' * 16, bytes([1, 2, 3, 4]) + bytes(16), cc=0x81)
    pair(cap, 0x3a, bytes([0x02, 0x04]) + bytes(range(0xc0, 0xd0)) + struct.pack('<I', 0x1000),
         bytes([0x02]) + struct.pack('<II', 0x20202020, 0x30) + bytes([0x04]))                                # Activate Session
    pair(cap, 0x3a, bytes([0x00, 0x01]) + bytes(16) + struct.pack('<I', 1), bytes([0x00]) + bytes(8) + bytes([0x01]), cc=0x84)
    pair(cap, 0x3b, bytes([0x03]), bytes([0x03]))                  # Set Session Privilege Level
    pair(cap, 0x3b, bytes([0x00]), bytes([0x04]), cc=0x80)
    pair(cap, 0x3c, struct.pack('<I', 0x20202020), b'')            # Close Session
    pair(cap, 0x3c, struct.pack('<I', 0) + b'\x07', b'', cc=0x88)
    mark(cap, 'Channel authentication capabilities, session challenge, activate session, privilege level, close session', s + 1)

    # --- Exported PDU (ipmi) and the same command in IPMI v1.5 session wrappers
    s = len(cap.frames)
    pair(cap, 0x01, b'', devid, how='exp')
    pair(cap, 0x01, b'', devid, v15=True)
    pair(cap, 0x25, b'', bytes([0x45, 0x23, 3, 0x3e, 0x10, 0x27, 0xe8, 0x03]), v15=True, auth=2)
    mark(cap, 'Exported PDU and IPMI v1.5 sessions', s + 1)
    build_nested(cap)

def build_nested(cap):
    # Send Message in Send Message (the recursion fixed in packet-ipmi.c): requests of 1 to 5 levels, responses of 1 to 3
    s = len(cap.frames)
    m = req(NF, 0x01, b'', 9)
    for n in range(5):
        m = req(NF, 0x34, bytes([0]) + m, 9)
        cap.udp(m)
    m = rsp(NF, 0x01, bytes([0]) + bytes(15), 9)
    for n in range(3):
        m = rsp(NF, 0x34, m, 9)
        cap.udp(m)
    mark(cap, 'Send Message nested in Send Message (5 request levels, 3 response levels)', s + 1)

def build_malformed(cap):
    G.seq = 1
    # truncated payloads of each command with a decoder
    short = {0x04: (b'', b''), 0x06: (b'\x01', b''), 0x24: (b'\x01\x02\x03', b''), 0x32: (b'\x01', b'\x01'),
             0x38: (b'\x01', b'\x01\x02'), 0x39: (b'\x01' + b'abc', b'\x01\x02'), 0x3a: (b'\x01\x02\x03', b'\x01\x02'),
             0x3b: (b'', b''), 0x3c: (b'\x01\x02', b''), 0x25: (b'', b'\x01\x02\x03'), 0x01: (b'', b'\x01\x02\x03'),
             0x07: (b'', b'\x05'), 0x08: (b'', b'\x01\x02\x03'), 0x2e: (b'', b''), 0x2f: (b'', b''),
             0x30: (b'', b''), 0x31: (b'', b'')}
    for c, (q, r) in short.items():
        cap.exp(req(NF, c, q, 1))
        cap.exp(rsp(NF, c, r, 1))
    cap.exp(rsp(NF, 0x04, b'\x57', 2))
    cap.exp(rsp(NF, 0x33, b'\x00', 2))
    cap.exp(rsp(NF, 0x33, b'\x01\x20\x18', 2))
    cap.exp(req(NF, 0x34, b'\x00', 3))
    cap.exp(req(NF, 0x34, b'\x01\x20\x18', 3))
    cap.exp(rsp(NF, 0x34, b'\x20\x18', 3))
    msg = req(NF, 0x01, b'', 9)
    for n in range(40):
        msg = req(NF, 0x34, bytes([0]) + msg, 9)
    cap.exp(msg)

def main():
    out = sys.argv[1]
    cap = Cap(); build(cap)
    cap.write_pcapng(os.path.join(out, 'ipmi-app-coverage.pcapng'))
    gz(os.path.join(out, 'ipmi-app-coverage.pcapng'))
    os.replace(os.path.join(out, 'ipmi-app-coverage.pcapng.gz'), os.path.join(out, 'ipmi_app_coverage.pcapng.gz'))
    bad = Cap(); build_malformed(bad)
    bad.write_pcapng(os.path.join(out, 'ipmi-app-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for a, b, n in ranges:
            print('%5d-%-5d %s' % (a, b, n))
        print('main %d frames, malformed %d frames' % (len(cap.frames), len(bad.frames)))

main()
