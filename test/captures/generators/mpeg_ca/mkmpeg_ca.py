#!/usr/bin/env python3
# Generates test/captures/mpeg_ca_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MPEG CA coverage captures: Conditional Access Tables (table ID
0x01) in MPEG-TS packets on PID 1, carried in UDP (heuristic mp2t_udp).
The malformed capture uses Exported PDUs (mpeg_sect). Usage: mkmpeg_ca.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mpeglib import (
    descr, exp_pdu, LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, section, TS, udp_frame,
    write_pcap,
)


def cat(descs, version=1, cur_next=1, sect=0, last=0, reserved=3, **kw):
    # reserved(18) version(5) current_next(1) | section | last section
    body = bytes([0xFF, 0xFF, 0xC0 | (version << 1) | cur_next, sect, last])
    return section(0x01, body + b"".join(descs), **kw)


def ca_descr(system_id, pid, private=b"", reserved=7):
    return descr(0x09, struct.pack(">HH", system_id, (reserved << 13) | pid)
                 + private)


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        pk = ts.sections(1, list(sects))
        frames.append(udp_frame(b"".join(pk), dport=5004))

    # 1: reproducer of "MPEG-CA: Fix the descriptor loop bound": a six
    # octet CA descriptor and an empty two octet descriptor before the CRC
    add(cat([bytes([0x09, 4, 0x12, 0x34, 0xE1, 0x00]), bytes([0x05, 0])]))
    # 2: CA descriptors with private data, other descriptors
    add(cat([ca_descr(0x0100, 0x0101, b"\x01\x02\x03\x04\x05"),
             ca_descr(0x0B00, 0x1FFF, b"\x00"),
             descr(0x05, b"CUEI"), descr(0x42, b"\xff\xff\xff")], version=2))
    # 3: no descriptors
    add(cat([], version=3))
    # 4: next version (current_next 0), section 1 of 2
    add(cat([ca_descr(0x0500, 0x0200)], version=31, cur_next=0, sect=1,
            last=2))
    # 5: bad CRC (no expert info unless verification is enabled)
    add(cat([ca_descr(0x0600, 0x0300, b"\xaa")], badcrc=True))
    # 6: a CA descriptor without private data, an ISO 639 descriptor and a
    # short unknown descriptor as the last one before the CRC
    add(cat([ca_descr(0x0700, 0x0400), descr(0x0A, b"eng\x00"),
             bytes([0x2A, 1, 0x7F])]))
    # 7: reserved bits of the section header zero, syntax indicator 0
    add(cat([ca_descr(0x0800, 0x0500)], reserved=0, ssi=False))
    # 8: a CAT that spans two TS packets
    many = [ca_descr(0x0100 + i, 0x0100 + i, bytes([i]) * 8)
            for i in range(14)]
    add(cat(many, version=4))
    # 9: two sections back to back in one TS packet
    add(cat([ca_descr(0x0900, 0x0600)], sect=0, last=1),
        cat([ca_descr(0x0901, 0x0601)], sect=1, last=1))
    return frames


def build_malformed():
    f = []
    ok = cat([ca_descr(0x0100, 0x0101, b"\x01\x02")])
    # descriptor length beyond the section
    f.append(cat([bytes([0x09, 0x40, 0x01, 0x00, 0xE1, 0x01])]))
    # a one octet descriptor tail where a descriptor header is expected
    f.append(section(0x01, bytes([0xFF, 0xFF, 0xC1, 0, 0]) +
                     ca_descr(1, 2) + b"\x09", crc=True))
    # section length 0 and below the minimum
    f.append(section(0x01, bytes([0xFF, 0xFF, 0xC1, 0, 0]), crc=False,
                     length=0))
    f.append(section(0x01, bytes([0xFF, 0xFF, 0xC1, 0, 0]), crc=False,
                     length=2))
    # section length beyond the data
    f.append(section(0x01, bytes([0xFF, 0xFF, 0xC1, 0, 0]) + ca_descr(1, 2),
                     length=200))
    # CRC missing, section cut inside the header fields
    f.append(ok[:-4])
    f.append(ok[:6])
    f.append(ok[:3])
    return [exp_pdu("mpeg_ca", x) for x in f]


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(os.path.join(out, "mpeg-ca-coverage.pcap"), build_main(),
               LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "mpeg-ca-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)
