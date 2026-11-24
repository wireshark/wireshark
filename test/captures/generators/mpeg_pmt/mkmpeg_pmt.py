#!/usr/bin/env python3
# Generates test/captures/mpeg_pmt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MPEG PMT coverage captures: Program Map Tables (table ID 0x02)
in MPEG-TS packets on PIDs 0x1000 and 0x1001, carried in UDP (heuristic
mp2t_udp). The malformed capture uses Exported PDUs (mpeg_pmt).
Usage: mkmpeg_pmt.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mpeglib import (
    descr, exp_pdu, ext_header, LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, section, TS,
    udp_frame, write_pcap,
)


def es(stype, pid, descs=b"", reserved=7, rsv2=15):
    return (bytes([stype]) + struct.pack(">HH", (reserved << 13) | pid,
                                         (rsv2 << 12) | len(descs)) + descs)


def pmt(progno, pcr, pinfo, streams, version=1, cur_next=1, sect=0, last=0,
        **kw):
    body = (struct.pack(">H", progno) + bytes([0xC0 | (version << 1) | cur_next,
                                              sect, last]) +
            struct.pack(">HH", 0xE000 | pcr, 0xF000 | len(pinfo)) + pinfo +
            b"".join(streams))
    return section(0x02, body, **kw)


STREAM_TYPES = (list(range(0, 0x37)) + [0x7F, 0x81, 0x86, 0xA1, 0xC0, 0xFE])


def build_main():
    ts = TS()
    frames = []

    def add(pid, *sects):
        pk = ts.sections(pid, list(sects))
        frames.append(udp_frame(b"".join(pk), dport=5004))

    # 1: program info with a registration descriptor, video and audio
    add(0x1000, pmt(1, 0x100, descr(0x05, b"HDMV"),
                    [es(0x02, 0x100), es(0x03, 0x101)]))
    # 2: every stream type of the value table (the section spans TS
    # packets)
    add(0x1000, pmt(2, 0x200, b"", [es(t, 0x200 + i)
                                    for i, t in enumerate(STREAM_TYPES)],
                    version=2))
    # 3: ES info loops: a registration descriptor behind another one and a
    # short one (length 2), a language descriptor only, no descriptors,
    # a registration descriptor longer than four octets
    add(0x1000, pmt(3, 0x300, b"", [
        es(0x06, 0x300, descr(0x0A, b"eng\x00") + descr(0x05, b"AB") +
           descr(0x05, b"VANC")),
        es(0x06, 0x301, descr(0x0A, b"deu\x01")),
        es(0x1B, 0x302),
        es(0x24, 0x303, descr(0x05, b"HEVC\x01\x02\x03")),
        es(0x81, 0x304, descr(0x05, b"AC-3")),
    ], version=3))
    # 4: a PMT for the next version (current_next 0): stream types are not
    # recorded
    add(0x1000, pmt(4, 0x400, b"", [es(0x1B, 0x400), es(0x03, 0x401)],
                    version=31, cur_next=0, sect=1, last=2))
    # 5: bad CRC
    add(0x1000, pmt(5, 0x500, b"", [es(0x02, 0x500)], badcrc=True))
    # 6: two sections in one TS packet on PID 0x1001
    add(0x1001, pmt(6, 0x600, b"", [es(0x02, 0x600)]),
        pmt(7, 0x700, b"", [es(0x03, 0x700)]))
    # 7: no PCR PID (0x1fff), no program info, no streams, reserved bits
    # zero
    add(0x1001, pmt(8, 0x1FFF, b"", [], version=5))
    add(0x1001, pmt(9, 0x1FFF, b"", [es(0x0F, 0x900, b"", reserved=0,
                                        rsv2=0)]))
    # 8: several program info descriptors and ES info descriptors of
    # several types (the descriptor dissector decodes them)
    add(0x1000, pmt(10, 0x100, descr(0x05, b"CUEI") +
                    descr(0x0E, b"\xc0\x10\x00"),
                    [es(0x02, 0x100, descr(0x0A, b"eng\x00")),
                     es(0x03, 0x101, descr(0x0A, b"fra\x03") +
                        descr(0x11, b"\xff\x00\x10"))]))
    return frames


def build_malformed():
    f = []
    ok = pmt(1, 0x100, descr(0x05, b"HDMV"), [es(0x02, 0x100), es(0x03, 0x101)])
    # program info length beyond the section
    body = (struct.pack(">H", 1) + bytes([0xC1, 0, 0]) +
            struct.pack(">HH", 0xE100, 0xF000 | 500))
    f.append(section(0x02, body))
    # ES info length beyond the section
    f.append(section(0x02, struct.pack(">H", 1) + bytes([0xC1, 0, 0]) +
                     struct.pack(">HH", 0xE100, 0xF000) +
                     bytes([0x02]) + struct.pack(">HH", 0xE100, 0xF000 | 200)))
    # a descriptor in the ES loop that is longer than the loop
    f.append(pmt(1, 0x100, b"", [es(0x06, 0x100, bytes([0x05, 0x20, 1, 2]))]))
    # an ES loop entry cut inside the entry, a registration descriptor
    # that is cut (the registration ID scan stops)
    f.append(pmt(1, 0x100, b"", [es(0x06, 0x100, bytes([0x05, 0x04, 1]))]))
    f.append(section(0x02, struct.pack(">H", 1) + bytes([0xC1, 0, 0]) +
                     struct.pack(">HH", 0xE100, 0xF000) + b"\x02\xe1\x00"))
    # section_length 0 and 5, CRC missing, cut in the header
    f.append(section(0x02, b"", crc=False, length=0))
    f.append(section(0x02, ext_header(1, 1), crc=False, length=5))
    f.append(ok[:-4])
    f.append(ok[:9])
    f.append(ok[:3])
    return [exp_pdu("mpeg_pmt", x) for x in f]


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(os.path.join(out, "mpeg-pmt-coverage.pcap"), build_main(),
               LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "mpeg-pmt-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)
