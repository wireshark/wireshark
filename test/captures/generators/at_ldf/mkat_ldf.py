#!/usr/bin/env python3
# Generates test/captures/at_ldf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Allied Telesis Loop
Detection dissector (packet-at-ldf.c).

All frames are built from scratch with struct; no captured traffic is
used. A switch (02:00:00:00:00:03) sends loop detection frames: IEEE 802.3
frames with an LLC header (DSAP 0, SSAP 0, control 0xE3 TEST) to the
Allied Telesis address 00:00:f4:27:71:01, which is how the dissector
recognises them.

Usage: mkat_ldf.py <output directory>

Writes:
  at_ldf-coverage.pcap            loop detection frames with source ports
                                  above 65535, untagged and 802.1Q tagged,
                                  and an LLC TEST frame to another address
                                  (not AT LDF)
  at_ldf-coverage-malformed.pcap  frames shorter than the fixed 79 octets
"""

import struct
import sys

AT_DST = bytes.fromhex('0000f4277101')
SWITCH = bytes.fromhex('020000000003')
OTHER_DST = bytes.fromhex('020000000009')


class Pcap:
    def __init__(self, snaplen=65535):
        self.frames = []
        self.snaplen = snaplen

    def llc(self, payload, dst=AT_DST, vlan=None, src=SWITCH, caplen=None):
        llc = b'\x00\x00\xe3' + payload
        tag = b'' if vlan is None else struct.pack('>HH', 0x8100, vlan)
        frame = dst + src + tag + struct.pack('>H', len(llc)) + llc
        if len(frame) < 60:
            frame += b'\0' * (60 - len(frame))
        self.frames.append((frame, caplen))

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, self.snaplen, 1)]
        t = 1700000000
        for i, (f, caplen) in enumerate(self.frames):
            c = f[:caplen] if caplen else f
            out.append(struct.pack('<IIII', t + i, 0, len(c), len(f)) + c)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def ldf(vlan, port, ttl=8, ident=0x11111111111111, text=b'loop detect', version=1):
    """The 79 octet loop detection frame: version, source VLAN, four octet
    source port, TTL, 7 octet identifier, 64 octet null padded text."""
    return (struct.pack('>BHIB', version, vlan, port, ttl) + ident.to_bytes(7, 'big') +
            text.ljust(64, b'\0'))


def main_capture(cap):
    # 1: the atldf_port.py reproducer: port 65541 used to be
    # shown in the Info column as its low 16 bits (5)
    cap.llc(ldf(10, 0x00010005))                                          # 1
    cap.llc(ldf(1, 1, ttl=1, ident=0x0123456789abcd))                     # 2 small values
    cap.llc(ldf(4094, 0xffffffff, ttl=255, ident=0xffffffffffffff,
                text=b'L' * 64, version=2))                               # 3 maximum values, text without a null
    cap.llc(ldf(100, 0x00020003, ident=0x00a1b2c3d4e5f6), vlan=100)       # 4 802.1Q tagged, port 131075
    cap.llc(ldf(0, 0, ttl=0, ident=0, text=b''))                          # 5 all zero, empty text
    # 6: an LLC TEST frame to another address: not AT LDF, shown as data
    cap.llc(ldf(10, 0x00010005), dst=OTHER_DST)                           # 6


def malformed_capture(cap):
    full = ldf(10, 0x00010005)
    cap.llc(full[:40])                                                    # 1 shorter than 79 octets
    cap.llc(full[:5])                                                     # 2 too short for the port
    cap.llc(full, caplen=50)                                              # 3 cut short by the capture


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    main_capture(cap)
    cap.write(outdir + '/at_ldf-coverage.pcap')
    cap = Pcap()
    malformed_capture(cap)
    cap.write(outdir + '/at_ldf-coverage-malformed.pcap')


if __name__ == '__main__':
    main()
