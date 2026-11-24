#!/usr/bin/env python3
# Generates test/captures/mpeg_pat_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MPEG PAT coverage captures: Program Association Tables (table
ID 0x00) in MPEG-TS packets on PID 0, carried in UDP (heuristic mp2t_udp).
The malformed capture uses Exported PDUs (mpeg_pat).
Usage: mkmpeg_pat.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mpeglib import (
    exp_pdu, ext_header, LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, section, TS, udp_frame,
    write_pcap,
)


def pat(progs, tsid=1, version=1, cur_next=1, sect=0, last=0, reserved=7,
        **kw):
    body = ext_header(tsid, version, cur_next, sect, last)
    for num, pid in progs:
        body += struct.pack(">HH", num, (reserved << 13) | pid)
    return section(0x00, body, **kw)


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        pk = ts.sections(0, list(sects))
        frames.append(udp_frame(b"".join(pk), dport=5004))

    # 1: one program, plus the network PID (program number 0)
    add(pat([(0, 0x0010), (1, 0x1000)]))
    # 2: several programs
    add(pat([(0, 0x0010), (0x0101, 0x0100), (0x0102, 0x0200),
             (0xFFFF, 0x1FFF)], tsid=0x1234, version=2))
    # 3: no programs
    add(pat([], version=3))
    # 4: next version (current_next 0), section 1 of 2, reserved bits 0
    add(pat([(7, 0x0700)], version=31, cur_next=0, sect=1, last=2,
            reserved=0))
    # 5: bad CRC (no expert info unless verification is enabled)
    add(pat([(1, 0x0100)], badcrc=True))
    # 6: 60 programs: the PAT spans two TS packets
    add(pat([(n, 0x0100 + n) for n in range(1, 61)], tsid=7, version=4))
    # 7: two sections back to back in one TS packet
    add(pat([(1, 0x100)], sect=0, last=1), pat([(2, 0x200)], sect=1, last=1))
    # 8: syntax indicator 0 (the dissector does not look at it)
    add(pat([(1, 0x100)], ssi=False))
    return frames


def build_malformed():
    f = []
    ok = pat([(1, 0x100), (2, 0x200)])
    # one program entry of two octets (a section_length that is not a
    # multiple of four after the header)
    f.append(section(0x00, ext_header(1, 1) + b"\x00\x01\xe1\x00" + b"\x00\x02"))
    # section_length 0, 1 and beyond the data
    f.append(section(0x00, b"", crc=False, length=0))
    f.append(section(0x00, ext_header(1, 1), crc=False, length=5))
    f.append(section(0x00, ext_header(1, 1) + b"\x00\x01\xe1\x00", length=400))
    # CRC missing, cut inside the header and inside a program entry
    f.append(ok[:-4])
    f.append(ok[:7])
    f.append(ok[:3])
    f.append(ok[:-6])
    return [exp_pdu("mpeg_pat", x) for x in f]


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(os.path.join(out, "mpeg-pat-coverage.pcap"), build_main(),
               LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "mpeg-pat-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)
