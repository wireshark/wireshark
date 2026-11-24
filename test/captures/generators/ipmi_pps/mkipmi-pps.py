#!/usr/bin/env python3
# Generates test/captures/ipmi_pps_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-ipmi-pps.c (IPMI NetFn OEM/Group with the
# Pigeon Point Systems defining body; the commands are named, not decoded).
# usage: mkipmi-pps.py <outdir> [-v]   (prints the frame ranges with -v)
# Reached through RMCP+ on UDP 623; named with -o ipmi.dissect_bus_commands:TRUE.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ipmilib import Cap, gz, req, rsp

NF = 0x2e
SIG = bytes([0x0a, 0x40, 0x00])
REV = bytes([0x00, 0x40, 0x0a])
ranges = []
def mark(cap, name, start):
    ranges.append((start, len(cap.frames), name))

CMDS = list(range(0x00, 0x2e)) + list(range(0x30, 0x3a)) + list(range(0x40, 0x4a))

def build(cap):
    s = len(cap.frames)
    seq = 0
    for c in CMDS:
        seq = (seq % 63) + 1
        cap.udp(req(NF, c, SIG + bytes([c, 1]), seq))
        cap.udp(rsp(NF, c, SIG + bytes([c]), seq))
    mark(cap, 'Every PPS command as request and response, signature 0a 40 00', s + 1)
    s = len(cap.frames)
    for c in (0x00, 0x13, 0x30, 0x49):
        seq = (seq % 63) + 1
        cap.udp(req(NF, c, REV + b'\x01', seq))
        cap.udp(rsp(NF, c, REV, seq, cc=0xc1))
    mark(cap, 'The reversed signature 00 40 0a', s + 1)
    s = len(cap.frames)
    for c in (0x2e, 0x2f, 0x3a, 0x4a, 0xff):          # not in the table
        seq = (seq % 63) + 1
        cap.udp(req(NF, c, SIG + b'\x01', seq))
        cap.udp(rsp(NF, c, SIG + b'\x02', seq))
    cap.udp(req(NF, 0x01, bytes([0x0a, 0x40, 0x01]) + b'\x01', 50))      # another defining body
    cap.udp(rsp(NF, 0x01, bytes([0x0a, 0x40, 0x01]) + b'\x01', 50))
    cap.exp(req(NF, 0x00, SIG + b'\x01', 51))
    cap.exp(rsp(NF, 0x00, SIG, 51))
    mark(cap, 'Commands not in the table, another signature, Exported PDU', s + 1)

def build_malformed(cap):
    cap.exp(req(NF, 0x00, SIG, 1)[:8])
    cap.exp(rsp(NF, 0x00, b'', 1)[:8])
    cap.exp(b'\x20\xb8\x26')

def main():
    out = sys.argv[1]
    cap = Cap(); build(cap)
    cap.write_pcapng(os.path.join(out, 'ipmi-pps-coverage.pcapng'))
    gz(os.path.join(out, 'ipmi-pps-coverage.pcapng'))
    os.replace(os.path.join(out, 'ipmi-pps-coverage.pcapng.gz'), os.path.join(out, 'ipmi_pps_coverage.pcapng.gz'))
    bad = Cap(); build_malformed(bad)
    bad.write_pcapng(os.path.join(out, 'ipmi-pps-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for a, b, n in ranges:
            print('%5d-%-5d %s' % (a, b, n))
        print('main %d frames, malformed %d frames' % (len(cap.frames), len(bad.frames)))

main()
