#!/usr/bin/env python3
# Generates test/captures/ipmi_bridge_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-ipmi-bridge.c (IPMI NetFn Bridge / ICMB; the
# commands are not decoded, only named).
# usage: mkipmi-bridge.py <outdir> [-v]   (prints the frame ranges with -v)
# Reached through RMCP+ on UDP 623; named with -o ipmi.dissect_bus_commands:TRUE.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ipmilib import Cap, gz, req, rsp

NF = 2
ranges = []
def mark(cap, name, start):
    ranges.append((start, len(cap.frames), name))

CMDS = ([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0a, 0x0b, 0x0c]    # bridge management
        + [0x10, 0x11, 0x12, 0x13, 0x14]                                              # discovery
        + [0x20, 0x21]                                                                # bridging
        + [0x30, 0x31, 0x32, 0x33, 0x34, 0x35]                                        # events
        + list(range(0xc0, 0xff))                                                     # OEM
        + [0xff])                                                                     # error report

def build(cap):
    s = len(cap.frames)
    seq = 0
    for c in CMDS:
        seq = (seq % 63) + 1
        cap.udp(req(NF, c, bytes([c, 1, 2]), seq))
        cap.udp(rsp(NF, c, bytes([c, 3]), seq, cc=0 if c & 1 else 0xc1))
    mark(cap, 'Every ICMB command as request and response (named, not decoded)', s + 1)
    s = len(cap.frames)
    for c in (0x07, 0x15, 0x40, 0xbf):               # not in the table
        seq = (seq % 63) + 1
        cap.udp(req(NF, c, b'\x01', seq))
        cap.udp(rsp(NF, c, b'\x02', seq))
    cap.udp(req(NF, 0x00, b'', 1))                   # no data
    cap.udp(rsp(NF, 0x00, b'', 1))
    cap.exp(req(NF, 0x02, b'\x01', 2))
    cap.exp(rsp(NF, 0x02, b'\x01', 2))
    mark(cap, 'Commands not in the table, empty data, Exported PDU', s + 1)

def build_malformed(cap):
    cap.exp(req(NF, 0x00, b'', 1)[:5])
    cap.exp(rsp(NF, 0x20, b'', 1)[:6])
    cap.exp(b'\x20\x08')

def main():
    out = sys.argv[1]
    cap = Cap(); build(cap)
    cap.write_pcapng(os.path.join(out, 'ipmi-bridge-coverage.pcapng'))
    gz(os.path.join(out, 'ipmi-bridge-coverage.pcapng'))
    os.replace(os.path.join(out, 'ipmi-bridge-coverage.pcapng.gz'), os.path.join(out, 'ipmi_bridge_coverage.pcapng.gz'))
    bad = Cap(); build_malformed(bad)
    bad.write_pcapng(os.path.join(out, 'ipmi-bridge-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for a, b, n in ranges:
            print('%5d-%-5d %s' % (a, b, n))
        print('main %d frames, malformed %d frames' % (len(cap.frames), len(bad.frames)))

main()
