#!/usr/bin/env python3
# Generates test/captures/dvb_sit_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB SIT coverage captures: Selection Information Table
sections (table ID 0x7F, as in a partial transport stream recorded from
a DVB stream) in MPEG-TS packets on PID 0x001F (linktype 243). Every
packet is built with struct; nothing comes from a real network.
Usage: mkdvb_sit.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from dvbts import descr, ext_header, LINKTYPE_MPEG_2_TS, section, TS, write_pcap

PID_SIT = 0x001F


def sit(version, descrs, services, sect=0, last=0, cur_next=1):
    d = b"".join(descrs)
    body = (ext_header(0xFFFF, version, cur_next, sect, last) +
            struct.pack(">H", 0xF000 | len(d)) + d + b"".join(services))
    return section(0x7F, body)


def service(sid, descrs, running=4):
    d = b"".join(descrs)
    return struct.pack(">HH", sid, 0x8000 | (running << 12) | len(d)) + d


def svc_descr(stype, provider, name):
    return descr(0x48, bytes([stype, len(provider)]) + provider +
                 bytes([len(name)]) + name)


# Partial transport stream descriptor: peak rate 15 Mbit/s, smoothing
# rate and buffer undefined
partial_ts = descr(0x63, struct.pack(">I", 0xC00000 | 37500)[1:] +
                   bytes([0xFF, 0xFF, 0xFF]) + struct.pack(">H", 0xFFFF))
network_name = descr(0x40, b"Synthetic Network")
pdsd = descr(0x5F, struct.pack(">I", 0x00000028))


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        frames.extend(ts.sections(PID_SIT, list(sects)))

    # 1: transmission info (partial transport stream, network name) and
    # two services with service descriptors, running status 4 and 1
    add(sit(1, [partial_ts, network_name], [
        service(0x0101, [svc_descr(0x01, b"Synthetic", b"Channel One")]),
        service(0x0102, [svc_descr(0x02, b"Synthetic", b"Radio Two"),
                         pdsd], running=1),
    ]))
    # 2: no transmission info, every running status 0-7, services
    # without descriptors
    add(sit(2, [], [service(0x0200 + r, [], running=r) for r in range(8)]))
    # 3: next version, transmission info only, no services
    add(sit(3, [partial_ts], [], cur_next=0))
    # 4: empty SIT, version 31
    add(sit(31, [], []))
    # 5-6: a SIT with twelve services that spans two TS packets
    add(sit(4, [partial_ts], [
        service(0x0300 + i, [svc_descr(0x01, b"Prov", b"Service %02d" % i)])
        for i in range(12)]))
    # 7: two SIT sections in one TS packet
    add(sit(5, [partial_ts], [service(0x0401, [])], sect=0, last=1),
        sit(5, [], [service(0x0402, [pdsd])], sect=1, last=1))
    return frames


def build_malformed():
    ts = TS()
    frames = []
    # 1: transmission info length beyond the section
    body = ext_header(0xFFFF, 0) + struct.pack(">H", 0xF0FF) + network_name
    frames += ts.sections(PID_SIT, [section(0x7F, body)])
    # 2: service descriptors length beyond the section
    body = ext_header(0xFFFF, 0) + struct.pack(">H", 0xF000) + \
        struct.pack(">HH", 0x0001, 0xC0FF)
    frames += ts.sections(PID_SIT, [section(0x7F, body)])
    # 3: section cut in the middle of a service entry
    body = ext_header(0xFFFF, 0) + struct.pack(">H", 0xF000) + \
        struct.pack(">H", 0x0001)
    frames += ts.sections(PID_SIT, [section(0x7F, body, crc=False,
                                            length=len(body) + 8)])
    # 4: section cut before the transmission info length
    frames += ts.sections(PID_SIT, [section(0x7F, ext_header(0xFFFF, 0),
                                            crc=False)])
    return frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-sit-coverage.pcap"), build_main(),
               LINKTYPE_MPEG_2_TS)
    write_pcap(os.path.join(out, "dvb-sit-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_MPEG_2_TS)
