#!/usr/bin/env python3
# Generates test/captures/hpteam_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for packet-hpteam.c (HP NIC Teaming heartbeat, LLC SNAP
OUI 00:80:5f PID 0x0002).  Usage: mkhpteam.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pylib import mac, Pcap, S

HP = bytes.fromhex('00805f')

def snap(dst, src, oui, pid, payload, ctrl=0x03):
    llc = bytes([0xaa, 0xaa, ctrl]) + oui + struct.pack('>H', pid) + payload
    return mac(dst) + mac(src) + struct.pack('>H', len(llc)) + llc

def main(out):
    p = Pcap(1)
    # Heartbeats from three team ports to the teaming multicast address,
    # 63 octets of "insignificant data" as in the HP white paper
    for i, src in enumerate(('02:00:00:00:00:01', '02:00:00:00:00:02', '02:00:00:00:00:03')):
        p.add(snap('03:00:c7:00:00:ee', src, HP, 2, bytes((i + j) & 0xff for j in range(63))))
    # Heartbeat with a short and an empty payload
    p.add(snap('03:00:c7:00:00:ee', S, HP, 2, b'\x01\x02\x03'))
    p.add(snap('03:00:c7:00:00:ee', S, HP, 2, b''))
    # Other PID with the HP OUI: not HP NIC Teaming (data)
    p.add(snap('03:00:c7:00:00:ee', S, HP, 0x1234, bytes(8)))
    p.write(os.path.join(out, 'hpteam-coverage.pcap'))

main(sys.argv[1])
