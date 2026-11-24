#!/usr/bin/env python3
# Generates test/captures/iana_oui_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for packet-iana-oui.c (LLC SNAP, OUI 00:00:5e).
Usage: mkiana_oui.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pylib import csum, H, mac, Pcap, S

def snap(dst, src, oui, pid, payload):
    llc = bytes([0xaa, 0xaa, 0x03]) + oui + struct.pack('>H', pid) + payload
    return mac(dst) + mac(src) + struct.pack('>H', len(llc)) + llc

IANA = bytes.fromhex('00005e')

def main(out):
    p = Pcap(1)
    # One frame for every PID in the value string table, one unknown PID
    for pid in (1, 2, 3, 4, 5, 6, 7, 8, 9, 0x00ff):
        pay = bytes(range(pid & 0xf, (pid & 0xf) + 20))
        if pid == 3:
            # minimal NHRP resolution request: fixed header, no extensions,
            # mandatory part with empty addresses
            pay = struct.pack('>HH5sBHHHBBBB', 1, 0x0800, bytes(5), 1, 28, 0, 0, 1, 1, 0, 0) \
                + struct.pack('>BBHI', 0, 0, 0, 1)
            pay = pay[:12] + struct.pack('>H', csum(pay)) + pay[14:]
        p.add(snap('01:00:5e:00:00:05', H, IANA, pid, pay))
    # Without a payload after the PID
    p.add(snap('01:00:5e:00:00:05', S, IANA, 5, b''))
    p.write(os.path.join(out, 'iana-oui-coverage.pcap'))

main(sys.argv[1])
