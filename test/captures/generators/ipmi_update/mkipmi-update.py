#!/usr/bin/env python3
# Generates test/captures/ipmi_update_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-ipmi-update.c (IPMI NetFn Firmware Update, the
# Pigeon Point Systems commands; named only, not decoded).
# usage: mkipmi-update.py <outdir> [-v]   (prints the frame ranges with -v)
# Reached through RMCP+ on UDP 623. The commands are only named with
# -o ipmi.dissect_bus_commands:TRUE -o ipmi.selected_oem:pps; without the OEM
# selection NetFn 8 is "Unknown command".
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ipmilib import Cap, gz, req, rsp

NF = 8
ranges = []
def mark(cap, name, start):
    ranges.append((start, len(cap.frames), name))

def build(cap):
    s = len(cap.frames)
    seq = 0
    for c in range(0, 8):                            # 0 to 6 are in the table, 7 is not
        seq += 1
        cap.udp(req(NF, c, bytes([c, 1, 2, 3]), seq))
        cap.udp(rsp(NF, c, bytes([c, 4]), seq))
    cap.udp(req(NF, 0x00, b'', 20))                  # no data
    cap.udp(rsp(NF, 0x00, b'', 20, cc=0xd1))         # device in firmware update mode
    cap.exp(req(NF, 0x03, b'\x01', 21))
    cap.exp(rsp(NF, 0x03, b'', 21))
    mark(cap, 'Upgrade commands 0-6 and an unknown command (request and response), Exported PDU', s + 1)

def build_malformed(cap):
    cap.exp(req(NF, 0x00, b'', 1)[:5])
    cap.exp(b'\x20\x20')

def main():
    out = sys.argv[1]
    cap = Cap(); build(cap)
    cap.write_pcapng(os.path.join(out, 'ipmi-update-coverage.pcapng'))
    gz(os.path.join(out, 'ipmi-update-coverage.pcapng'))
    os.replace(os.path.join(out, 'ipmi-update-coverage.pcapng.gz'), os.path.join(out, 'ipmi_update_coverage.pcapng.gz'))
    bad = Cap(); build_malformed(bad)
    bad.write_pcapng(os.path.join(out, 'ipmi-update-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for a, b, n in ranges:
            print('%5d-%-5d %s' % (a, b, n))
        print('main %d frames, malformed %d frames' % (len(cap.frames), len(bad.frames)))

main()
