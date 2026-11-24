#!/usr/bin/env python3
# Generates test/captures/dvb_bat_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB BAT coverage captures: BAT sections (table ID 0x4A) in
MPEG-TS packets on PID 0x0011 (linktype 243). Usage: mkdvb_bat.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from dvbts import descr, ext_header, LINKTYPE_MPEG_2_TS, section, TS, write_pcap

PID_SDT_BAT = 0x0011


def bat(bouquet_id, version, descrs, streams, sect=0, last=0, cur_next=1):
    d = b"".join(descrs)
    s = b"".join(streams)
    body = (ext_header(bouquet_id, version, cur_next, sect, last) +
            struct.pack(">H", 0xF000 | len(d)) + d +
            struct.pack(">H", 0xF000 | len(s)) + s)
    return section(0x4A, body)


def stream(tsid, onid, descrs):
    d = b"".join(descrs)
    return struct.pack(">HHH", tsid, onid, 0xF000 | len(d)) + d


def service_list(services):
    return descr(0x41, b"".join(struct.pack(">HB", sid, t)
                                for sid, t in services))


bouquet_name = descr(0x47, b"Synthetic Bouquet")
country = descr(0x49, b"\xff" + b"GBRDEU")
linkage = descr(0x4A, struct.pack(">HHHB", 0x0001, 0x0002, 0x0003, 0x01))
pdsd = descr(0x5F, struct.pack(">I", 0x00000028))
multiling = descr(0x5C, b"eng" + bytes([6]) + b"Banque" + b"deu" +
                  bytes([6]) + b"Bukett")


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        frames.extend(ts.sections(PID_SDT_BAT, list(sects)))

    # 1: bouquet with name, country availability and linkage descriptors
    # and two transport streams with service lists
    add(bat(0x1001, 1, [bouquet_name, country, linkage], [
        stream(0x0001, 0x0002, [service_list([(0x0101, 0x01),
                                              (0x0102, 0x02)])]),
        stream(0x0003, 0x0002, [service_list([(0x0201, 0x19)]), pdsd]),
    ], sect=0, last=1))
    # 2: second section: no bouquet descriptors, a transport stream
    # without descriptors
    add(bat(0x1001, 1, [], [stream(0x0004, 0x0005, [])], sect=1, last=1))
    # 3: next version, no transport streams
    add(bat(0x1002, 2, [multiling], [], cur_next=0))
    # 4: empty BAT
    add(bat(0x1003, 31, [], []))
    # 5-6: a BAT with many transport streams that spans two TS packets
    add(bat(0x1004, 3, [bouquet_name], [
        stream(0x0100 + i, 0x0002,
               [service_list([(0x1000 + i * 4 + j, 0x01) for j in range(4)])])
        for i in range(12)]))
    # 7: two BAT sections in one TS packet
    add(bat(0x1005, 0, [bouquet_name], [], sect=0, last=1),
        bat(0x1005, 0, [], [stream(0x0010, 0x0002, [linkage])], sect=1, last=1))
    return frames


def build_malformed():
    ts = TS()
    frames = []
    # 1: bouquet descriptors length beyond the section
    body = ext_header(0x2001, 0) + struct.pack(">H", 0xF0FF) + bouquet_name
    frames += ts.sections(PID_SDT_BAT, [section(0x4A, body)])
    # 2: transport stream loop length beyond the section
    body = ext_header(0x2002, 0) + struct.pack(">HH", 0xF000, 0xF0FF) + \
        struct.pack(">HHH", 1, 2, 0xF000)
    frames += ts.sections(PID_SDT_BAT, [section(0x4A, body)])
    # 3: transport descriptors length beyond the section
    body = ext_header(0x2003, 0) + struct.pack(">HH", 0xF000, 0xF006) + \
        struct.pack(">HHH", 1, 2, 0xF0FF)
    frames += ts.sections(PID_SDT_BAT, [section(0x4A, body)])
    # 4: section cut before the bouquet descriptors length
    frames += ts.sections(PID_SDT_BAT, [section(0x4A, ext_header(0x2004, 0),
                                                crc=False)])
    return frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-bat-coverage.pcap"), build_main(),
               LINKTYPE_MPEG_2_TS)
    write_pcap(os.path.join(out, "dvb-bat-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_MPEG_2_TS)
