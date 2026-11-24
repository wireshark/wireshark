#!/usr/bin/env python3
# Generates test/captures/dvb_sdt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB SDT coverage captures: SDT sections (table ID 0x42
actual transport stream, 0x46 other transport stream) in MPEG-TS packets
on PID 0x0011 (linktype 243). Every packet is built with struct; nothing
comes from a real network. Usage: mkdvb_sdt.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from dvbts import descr, ext_header, LINKTYPE_MPEG_2_TS, section, TS, write_pcap

PID_SDT_BAT = 0x0011


def sdt(tsid, onid, version, services, sect=0, last=0, cur_next=1,
        tid=0x42):
    body = (ext_header(tsid, version, cur_next, sect, last) +
            struct.pack(">HB", onid, 0xFF) + b"".join(services))
    return section(tid, body)


def service(sid, descrs, sched=0, pf=0, running=4, free_ca=0):
    d = b"".join(descrs)
    return (struct.pack(">HB", sid, 0xFC | (sched << 1) | pf) +
            struct.pack(">H", (running << 13) | (free_ca << 12) | len(d)) + d)


def svc_descr(stype, provider, name):
    return descr(0x48, bytes([stype, len(provider)]) + provider +
                 bytes([len(name)]) + name)


ca_ident = descr(0x53, struct.pack(">HH", 0x0100, 0x0500))
multiling = descr(0x5D, b"eng" + bytes([3]) + b"Prv" + bytes([7]) +
                  b"Channel" + b"fra" + bytes([3]) + b"Fou" + bytes([6]) +
                  b"Chaine")
linkage = descr(0x4A, struct.pack(">HHHB", 0x0001, 0x0002, 0x0003, 0x05))
pdsd = descr(0x5F, struct.pack(">I", 0x00000028))


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        frames.extend(ts.sections(PID_SDT_BAT, list(sects)))

    # 1: actual transport stream, section 0 of 1: three services with
    # every running status 0-2, EIT flags and the free CA mode
    add(sdt(0x0001, 0x0002, 1, [
        service(0x0101, [svc_descr(0x01, b"Synthetic", b"Channel One")],
                sched=1, pf=1, running=0, free_ca=0),
        service(0x0102, [svc_descr(0x02, b"Synthetic", b"Radio Two"),
                         ca_ident], sched=1, pf=0, running=1, free_ca=1),
        service(0x0103, [multiling, pdsd], sched=0, pf=1, running=2),
    ], sect=0, last=1))
    # 2: section 1 of 1: running status 3-7, one service without
    # descriptors
    add(sdt(0x0001, 0x0002, 1, [
        service(0x0104, [], running=3),
        service(0x0105, [linkage], running=4),
        service(0x0106, [svc_descr(0x19, b"", b"HD")], running=5),
        service(0x0107, [], running=6),
        service(0x0108, [], running=7, free_ca=1),
    ], sect=1, last=1))
    # 3: other transport stream (0x46), next version, one service with
    # no descriptors (the smallest service entry)
    add(sdt(0x0010, 0x0020, 2, [service(0x0201, [])], cur_next=0, tid=0x46))
    # 4: SDT without services, version 31
    add(sdt(0x0011, 0x0020, 31, []))
    # 5-6: an SDT with twelve services that spans two TS packets
    add(sdt(0x0012, 0x0002, 3, [
        service(0x0300 + i, [svc_descr(0x01, b"Prov", b"Service %02d" % i)],
                sched=1, pf=1) for i in range(12)]))
    # 7: two SDT sections in one TS packet (actual and other)
    add(sdt(0x0013, 0x0002, 0, [service(0x0401, [ca_ident])]),
        sdt(0x0014, 0x0002, 0, [service(0x0402, [pdsd])], tid=0x46))
    return frames


def build_malformed():
    ts = TS()
    frames = []
    # 1: service descriptors loop length beyond the section
    body = ext_header(0x2001, 0) + struct.pack(">HB", 2, 0xFF) + \
        struct.pack(">HBH", 0x0001, 0xFF, 0x80FF)
    frames += ts.sections(PID_SDT_BAT, [section(0x42, body)])
    # 2: section cut in the middle of a service entry
    body = ext_header(0x2002, 0) + struct.pack(">HB", 2, 0xFF) + \
        struct.pack(">HB", 0x0001, 0xFF)
    frames += ts.sections(PID_SDT_BAT, [section(0x42, body, crc=False,
                                                length=len(body) + 8)])
    # 3: section shorter than the fixed header
    frames += ts.sections(PID_SDT_BAT, [section(0x46, ext_header(0x2003, 0),
                                                crc=False)])
    # 4: section length below 4 (the "length - 4" wraps) cut in the
    # header
    frames += ts.sections(PID_SDT_BAT, [section(0x42, b"\x20\x03",
                                                crc=False)])
    return frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-sdt-coverage.pcap"), build_main(),
               LINKTYPE_MPEG_2_TS)
    write_pcap(os.path.join(out, "dvb-sdt-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_MPEG_2_TS)
