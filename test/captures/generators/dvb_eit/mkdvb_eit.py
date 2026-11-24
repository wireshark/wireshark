#!/usr/bin/env python3
# Generates test/captures/dvb_eit_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB EIT coverage captures: EIT sections in MPEG-TS packets
on PID 0x12 (linktype 243). Usage: mkdvb_eit.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from dvbts import descr, ext_header, LINKTYPE_MPEG_2_TS, section, TS, write_pcap

PID_EIT = 0x0012


def mjd_time(mjd, h, m, s):
    bcd = lambda v: ((v // 10) << 4) | (v % 10)
    return struct.pack(">H", mjd) + bytes([bcd(h), bcd(m), bcd(s)])


def bcd3(h, m, s):
    bcd = lambda v: ((v // 10) << 4) | (v % 10)
    return bytes([bcd(h), bcd(m), bcd(s)])


def event(evt_id, start, duration, running, free_ca, descrs):
    d = b"".join(descrs)
    return (struct.pack(">H", evt_id) + start + duration +
            struct.pack(">H", (running << 13) | (free_ca << 12) | len(d)) + d)


def eit(tid, sid, version, sect, last, tsid, onid, seg_last, last_tid, events,
        cur_next=1):
    body = (ext_header(sid, version, cur_next, sect, last) +
            struct.pack(">HHBB", tsid, onid, seg_last, last_tid) +
            b"".join(events))
    return section(tid, body)


# Descriptors of the event loops (dissected by packet-mpeg-descriptor.c)
short_event = descr(0x4D, b"eng" + bytes([10]) + b"Synthetic " +
                    bytes([14]) + b"Coverage event")
ext_items = (bytes([8]) + b"Director" + bytes([5]) + b"Alice" +
             bytes([4]) + b"Cast" + bytes([3]) + b"Bob")
extended_event = descr(0x4E, bytes([0x01]) + b"eng" + bytes([len(ext_items)]) +
                       ext_items + bytes([9]) + b"More text")
content = descr(0x54, bytes([0x10, 0x00, 0x23, 0x00]))
parental = descr(0x55, b"GBR" + bytes([0x09]))
component = descr(0x50, bytes([0xF1, 0x03, 0x01]) + b"eng" + b"Video")
pdsd = descr(0x5F, struct.pack(">I", 0x00000028))


def build_main():
    ts = TS()
    frames = []
    t = mjd_time(60000, 12, 30, 0)

    def add(*sects):
        frames.extend(ts.sections(PID_EIT, list(sects)))

    # 1: present/following, actual TS, two events with descriptors
    add(eit(0x4E, 0x0101, 1, 0, 1, 0x0001, 0x0002, 1, 0x4E, [
        event(0x1001, t, bcd3(1, 30, 0), 4, 0,
              [short_event, content, parental]),
        event(0x1002, mjd_time(60000, 14, 0, 0), bcd3(0, 45, 30), 1, 1,
              [component, pdsd]),
    ]))
    # 2: following section of the same table, not yet applicable
    add(eit(0x4E, 0x0101, 2, 1, 1, 0x0001, 0x0002, 1, 0x4E, [
        event(0x1003, mjd_time(60000, 23, 59, 59), bcd3(0, 0, 1), 2, 0, []),
    ], cur_next=0))
    # 3: present/following, other TS, running status 3 and 5
    add(eit(0x4F, 0x0202, 0, 0, 0, 0x0003, 0x0004, 0, 0x4F, [
        event(0x2001, mjd_time(59000, 0, 0, 0), bcd3(2, 0, 0), 3, 0, []),
        event(0x2002, mjd_time(59000, 2, 0, 0), bcd3(2, 0, 0), 5, 1, []),
    ]))
    # 4: schedule, actual TS, an event with undefined start time (the
    # reproducer of the fix, dvb_eit_undef_time.py, as an MPEG-TS
    # section) and running status 0 (undefined)
    repro_event = struct.pack(">H", 0x1234) + b"\xff" * 5 + b"\x01\x30\x00" + \
        struct.pack(">H", 0x8000)
    add(section(0x4E, struct.pack(">HBBBHHBB", 0x0001, 0xC1, 0, 0, 0x0002,
                                  0x0003, 0, 0x4E) + repro_event))
    # 5: schedule, actual TS, an unparseable start time (hour 25) and
    # running status 6 (reserved)
    add(eit(0x50, 0x0303, 3, 0, 0, 0x0001, 0x0002, 0, 0x57, [
        event(0x3001, mjd_time(60000, 25, 0, 0), bcd3(0, 10, 0), 6, 0,
              [short_event]),
    ]))
    # 6: schedule, other TS, no events
    add(eit(0x6F, 0x0404, 31, 0, 0, 0x0005, 0x0006, 0, 0x6F, []))
    # 7-8: a schedule section with many events that spans two TS packets
    evs = [event(0x4000 + i, mjd_time(60001, i, 0, 0), bcd3(1, 0, 0), 1, 0,
                 [short_event]) for i in range(8)]
    add(eit(0x60, 0x0505, 4, 0, 0, 0x0007, 0x0008, 0, 0x60, evs))
    # 9: two sections in one TS packet: schedule (0x58) with an extended
    # event descriptor, and an empty other-TS section (0x5F)
    add(eit(0x58, 0x0606, 5, 0, 1, 0x0009, 0x000A, 1, 0x58, [
            event(0x5001, t, bcd3(0, 30, 0), 4, 0, [extended_event])]),
        eit(0x5F, 0x0606, 5, 1, 1, 0x0009, 0x000A, 1, 0x5F, []))
    return frames


def build_malformed():
    ts = TS()
    frames = []
    # 1: event header cut short by the section length (exception in the
    # event loop)
    body = ext_header(0x0101, 0, 1, 0, 0) + struct.pack(">HHBB", 1, 2, 0, 0x4E)
    body += struct.pack(">H", 0x7777) + mjd_time(60000, 1, 2, 3)
    frames += ts.sections(PID_EIT, [section(0x4E, body)])
    # 2: descriptor loop length beyond the section
    ev = struct.pack(">H", 0x7778) + mjd_time(60000, 1, 2, 3) + bcd3(0, 1, 0) + \
        struct.pack(">H", 0x8000 | 0x0FF0) + short_event
    body = ext_header(0x0101, 0, 1, 0, 0) + struct.pack(">HHBB", 1, 2, 0, 0x4E) + ev
    frames += ts.sections(PID_EIT, [section(0x4E, body)])
    # 3: section shorter than the fixed header
    frames += ts.sections(PID_EIT, [section(0x4E, ext_header(1, 0)[:3], crc=False)])
    # 4: bad CRC
    s = bytearray(eit(0x4E, 0x0101, 1, 0, 0, 1, 2, 0, 0x4E, []))
    s[-1] ^= 0xFF
    frames += ts.sections(PID_EIT, [bytes(s)])
    return frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-eit-coverage.pcap"), build_main(),
               LINKTYPE_MPEG_2_TS)
    write_pcap(os.path.join(out, "dvb-eit-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_MPEG_2_TS)
