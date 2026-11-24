#!/usr/bin/env python3
# Generates test/captures/mpeg_sect_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MPEG SECT coverage captures: sections whose table ID has no
dissector of its own (the generic section code) and a TDT (which uses the
MJD time helper), in MPEG-TS packets over UDP (heuristic mp2t_udp). The
malformed capture uses Exported PDUs (mpeg_sect).
Usage: mkmpeg_sect.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mpeglib import (
    exp_pdu, ext_header, LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, section, TS, udp_frame,
    write_pcap,
)


def build_main():
    ts = TS()
    frames = []

    def add(pid, *sects):
        pk = ts.sections(pid, list(sects))
        frames.append(udp_frame(b"".join(pk), dport=5004))

    # 1-5: table IDs without a dissector: Transport Stream Description,
    # Scene Description, Object Description, RST and Stuffing Table (no
    # syntax indicator, no CRC)
    add(0x30, section(0x03, ext_header(1, 1) + b"\x01\x02\x03\x04"))
    add(0x30, section(0x04, ext_header(2, 2) + b"scene"))
    add(0x30, section(0x05, ext_header(3, 3) + b"object"))
    add(0x30, section(0x71, b"\x00\x01\x02\x03\x04\x05\x06\x07", ssi=False,
                      crc=False))
    # 5: stuffing table, 200 octets
    add(0x30, section(0x72, b"\xff" * 200, ssi=False, crc=False))
    # 6: a private table ID with a bad CRC (no expert info unless
    # verification is enabled)
    add(0x31, section(0xC1, ext_header(4, 4) + b"private", badcrc=True))
    # 7: a table ID with the syntax indicator and a good CRC
    add(0x31, section(0x7A, ext_header(5, 5) + b"seven"))
    # 8: a 900 octet section on several TS packets
    add(0x32, section(0x06, ext_header(6, 6) + bytes(range(256)) * 3 + b"end"))
    # 9: three short sections back to back in one TS packet, reserved bits
    # zero, a section with the syntax indicator set but no body
    add(0x33, section(0x03, ext_header(7, 7)),
        section(0x04, b"", reserved=0, ssi=False, crc=False),
        section(0x05, b"", ssi=True))
    # 10: a section of the maximum length (4095 octets after the header)
    big = section(0xC2, bytes(4095 - 4), ssi=True)
    assert len(big) == 4098
    add(0x34, big)
    # 11: TDT: 2023-02-25 12:34:56 (MJD 60000), uses the MJD time helper
    add(0x14, section(0x70, struct.pack(">H", 60000) + b"\x12\x34\x56",
                      ssi=False, crc=False))
    # 12: TDT 1970-01-01 00:00:00 (MJD 40587) and the last day of MJD
    add(0x14, section(0x70, struct.pack(">H", 40587) + b"\x00\x00\x00",
                      ssi=False, crc=False),
        section(0x70, struct.pack(">H", 65535) + b"\x23\x59\x59",
                ssi=False, crc=False))
    # 13: an ETV EISS section: its dissector reads the section header with
    # the reserved bits and the item list (packet_mpeg_sect_header_extra)
    add(0x35, section(0xE0, bytes([0, 0, 0, 1, 0]) + struct.pack(
        ">HIHB", 8, 0x00000001, 0x0002, 0), ssi=False, reserved=0))
    return frames


def build_malformed():
    f = []
    # a section shorter than the three octet header
    f.append(b"\xc1\xb0")
    # longer than the maximum section (4099 octets): not dissected
    f.append(section(0xC3, bytes(4097), length=4095, ssi=True) + b"\0" * 3)
    # section_length 0 and 1 with the syntax indicator (the CRC offset
    # wraps), section_length beyond the data
    f.append(section(0xC4, b"", crc=False, length=0))
    f.append(section(0xC5, b"", crc=False, length=1))
    f.append(section(0xC6, b"\x00" * 6, crc=False, length=3000))
    # a CRC field cut short
    f.append(section(0xC7, b"\x00" * 6)[:-2])
    # TDT with invalid time fields (hour 25, minute 60, second 60) and
    # short
    f.append(section(0x70, struct.pack(">H", 60000) + b"\x25\x34\x56",
                     ssi=False, crc=False))
    f.append(section(0x70, struct.pack(">H", 60000) + b"\x12\x60\x56",
                     ssi=False, crc=False))
    f.append(section(0x70, struct.pack(">H", 60000) + b"\x12\x34\x60",
                     ssi=False, crc=False))
    f.append(section(0x70, struct.pack(">H", 60000) + b"\x12",
                     ssi=False, crc=False))
    return [exp_pdu("mpeg_sect", x) for x in f]


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(os.path.join(out, "mpeg-sect-coverage.pcap"), build_main(),
               LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "mpeg-sect-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)
