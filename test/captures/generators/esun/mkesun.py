#!/usr/bin/env python3
# Generates test/captures/esun_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the synthetic ESUN coverage captures. Usage: mkesun.py <outdir>
# ESUN has no ethertype of its own (Decode As only); the frames use the
# IEEE local experimental ethertype 0x88B5:
#   tshark -d eth.type==0x88b5,esun -r esun-coverage.pcap
import os
import struct
import sys

ETYPE = 0x88B5

def write_pcap(fn, frames, linktype=1):
    with open(fn, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)) + fr)

def eth(payload, src=1, dst=2):
    return (bytes.fromhex("0200000000%02x" % dst) + bytes.fromhex("0200000000%02x" % src)
            + struct.pack(">H", ETYPE) + payload)

def esun(rev, f, cos, ecn, flow, ttl, ud, rsvd):
    b0 = (rev << 6) | (f << 5) | (cos << 2) | ecn
    b3 = (ttl << 4) | (ud << 2) | rsvd
    return struct.pack(">BHB", b0, flow, b3)

def main(out):
    frames = [
        # 1: F=1, flow label in the Info column, payload after the header
        eth(esun(0, 1, 5, 2, 0x1234, 15, 2, 1) + b"ESUN payload"),
        # 2: F=0, flow label shown as ignored, payload
        eth(esun(1, 0, 3, 1, 0xBEEF, 8, 1, 0) + bytes(range(16))),
        # 3: header only (no payload), every bit field at its maximum, F=1
        eth(esun(3, 1, 7, 3, 0xFFFF, 15, 3, 3)),
        # 4: header only, all zero, F=0
        eth(esun(0, 0, 0, 0, 0, 0, 0, 0)),
        # 5: 3 octets, too short: ESUN rejects it, shown as Ethertype data
        eth(b"\x20\x00\x01"),
        # 6: F=1, payload padded to the Ethernet minimum
        eth(esun(2, 1, 1, 0, 0x0001, 1, 0, 2) + b"\x00" * 42, src=2, dst=1),
    ]
    write_pcap(os.path.join(out, "esun-coverage.pcap"), frames)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
