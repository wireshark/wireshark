#!/usr/bin/env python3
# Generates test/captures/dvb_nit_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB NIT coverage captures: NIT sections (table ID 0x40
actual network, 0x41 other network) in MPEG-TS packets on PID 0x0010
(linktype 243). Every packet is built with struct; nothing comes from a
real network. Usage: mkdvb_nit.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from dvbts import descr, ext_header, LINKTYPE_MPEG_2_TS, section, TS, write_pcap

PID_NIT = 0x0010


def nit(network_id, version, descrs, streams, sect=0, last=0, cur_next=1,
        tid=0x40):
    d = b"".join(descrs)
    s = b"".join(streams)
    body = (ext_header(network_id, version, cur_next, sect, last) +
            struct.pack(">H", 0xF000 | len(d)) + d +
            struct.pack(">H", 0xF000 | len(s)) + s)
    return section(tid, body)


def stream(tsid, onid, descrs):
    d = b"".join(descrs)
    return struct.pack(">HHH", tsid, onid, 0xF000 | len(d)) + d


def service_list(services):
    return descr(0x41, b"".join(struct.pack(">HB", sid, t)
                                for sid, t in services))


network_name = descr(0x40, b"Synthetic Network")
multiling_name = descr(0x5B, b"eng" + bytes([7]) + b"Network" + b"deu" +
                       bytes([7]) + b"Netzwerk")
linkage = descr(0x4A, struct.pack(">HHHB", 0x0001, 0x0002, 0x0003, 0x04))
pdsd = descr(0x5F, struct.pack(">I", 0x00000028))
# Satellite: 11.778 GHz, 19.2 E, horizontal, DVB-S2 8PSK, 27.5 MS/s, 3/4
satellite = descr(0x43, bytes.fromhex("01177800") + bytes.fromhex("0192") +
                  bytes([0x80 | (0 << 5) | (0 << 3) | 0x04 | 0x02]) +
                  bytes.fromhex("02750003"))
# Cable: 346.0 MHz, 64-QAM, 6.9 MS/s, FEC outer RS, inner not defined
cable = descr(0x44, bytes.fromhex("03460000") + struct.pack(">H", 0xFFF2) +
              bytes([0x03]) + bytes.fromhex("00690000"))
# Terrestrial: 506 MHz (in 10 Hz units), 8 MHz, 64-QAM, 2/3, 1/32, 8k
terrestrial = descr(0x5A, struct.pack(">I", 50600000) +
                    bytes([0x1F, 0x91, 0x01]) + b"\xff" * 4)


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        frames.extend(ts.sections(PID_NIT, list(sects)))

    # 1: reproducer of the fixed bug: one transport stream entry without
    # descriptors and no network descriptors (dvbnit_tsloop.py)
    add(nit(0x0001, 0, [], [stream(0x1234, 0x5678, [])]))
    # 2: actual network, section 0 of 1: network name, linkage and private
    # data specifier; two transport streams with satellite delivery and
    # service list descriptors
    add(nit(0x0002, 1, [network_name, linkage, pdsd], [
        stream(0x0011, 0x0002, [satellite, service_list([(0x0101, 0x01),
                                                         (0x0102, 0x02)])]),
        stream(0x0012, 0x0002, [satellite, service_list([(0x0201, 0x19)])]),
    ], sect=0, last=1))
    # 3: section 1 of 1: no network descriptors, a cable stream and a
    # stream without descriptors
    add(nit(0x0002, 1, [], [stream(0x0013, 0x0002, [cable]),
                            stream(0x0014, 0x0002, [])], sect=1, last=1))
    # 4: other network (0x41), next version, multilingual network name and
    # a terrestrial stream
    add(nit(0x0003, 2, [multiling_name], [stream(0x0021, 0x0003,
                                                 [terrestrial])],
            cur_next=0, tid=0x41))
    # 5: empty NIT, version 31
    add(nit(0x0004, 31, [], []))
    # 6-7: a NIT with twenty transport streams that spans two TS packets
    add(nit(0x0005, 3, [network_name], [
        stream(0x0100 + i, 0x0002,
               [service_list([(0x1000 + i * 2 + j, 0x01) for j in range(2)])])
        for i in range(20)]))
    # 8: two NIT sections in one TS packet
    add(nit(0x0006, 0, [network_name], [], sect=0, last=1),
        nit(0x0006, 0, [], [stream(0x0031, 0x0006, [pdsd])], sect=1, last=1))
    return frames


def build_malformed():
    ts = TS()
    frames = []
    # 1: network descriptors length beyond the section
    body = ext_header(0x2001, 0) + struct.pack(">H", 0xF0FF) + network_name
    frames += ts.sections(PID_NIT, [section(0x40, body)])
    # 2: transport stream loop length beyond the section
    body = ext_header(0x2002, 0) + struct.pack(">HH", 0xF000, 0xF0FF) + \
        struct.pack(">HHH", 1, 2, 0xF000)
    frames += ts.sections(PID_NIT, [section(0x40, body)])
    # 3: transport descriptors length beyond the section
    body = ext_header(0x2003, 0) + struct.pack(">HH", 0xF000, 0xF006) + \
        struct.pack(">HHH", 1, 2, 0xF0FF)
    frames += ts.sections(PID_NIT, [section(0x40, body)])
    # 4: section cut before the network descriptors length
    frames += ts.sections(PID_NIT, [section(0x40, ext_header(0x2004, 0),
                                            crc=False)])
    # 5: transport stream entry cut after the stream IDs
    body = ext_header(0x2005, 0) + struct.pack(">HH", 0xF000, 0xF004) + \
        struct.pack(">HH", 1, 2)
    frames += ts.sections(PID_NIT, [section(0x41, body, crc=False)])
    return frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-nit-coverage.pcap"), build_main(),
               LINKTYPE_MPEG_2_TS)
    write_pcap(os.path.join(out, "dvb-nit-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_MPEG_2_TS)
