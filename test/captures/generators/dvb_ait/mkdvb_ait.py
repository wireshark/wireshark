#!/usr/bin/env python3
# Generates test/captures/dvb_ait_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB AIT coverage captures: AIT sections (table ID 0x74) in
MPEG-TS packets on PID 0x0100 (linktype 243). Usage: mkdvb_ait.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from dvbts import descr, ext_header, LINKTYPE_MPEG_2_TS, section, TS, write_pcap

PID_AIT = 0x0100


def ait(app_type, version, descrs, apps, test_flag=0, sect=0, last=0,
        cur_next=1):
    d = b"".join(descrs)
    a = b"".join(apps)
    body = (ext_header((test_flag << 15) | app_type, version, cur_next, sect,
                       last) +
            struct.pack(">H", 0xF000 | len(d)) + d +
            struct.pack(">H", 0xF000 | len(a)) + a)
    return section(0x74, body)


def app(org, app_id, ctrl, descrs):
    d = b"".join(descrs)
    return struct.pack(">IHBH", org, app_id, ctrl, 0xF000 | len(d)) + d


def app_desc(profiles, svc_bound, vis, prio, labels):
    p = b"".join(struct.pack(">HBBB", prof, *ver) for prof, ver in profiles)
    return descr(0x00, bytes([len(p)]) + p +
                 bytes([(svc_bound << 7) | (vis << 5) | 0x1F, prio]) +
                 bytes(labels))


def app_name(names):
    return descr(0x01, b"".join(l + bytes([len(n)]) + n for l, n in names))


def trpt_oc(label, remote=None, comp=0x10):
    if remote:
        sel = bytes([0xFF]) + struct.pack(">HHH", *remote) + bytes([comp])
    else:
        sel = bytes([0x7F, comp])
    return descr(0x02, struct.pack(">HB", 0x0001, label) + sel)


def trpt_http(label, base, exts):
    sel = bytes([len(base)]) + base + bytes([len(exts)])
    sel += b"".join(bytes([len(e)]) + e for e in exts)
    return descr(0x02, struct.pack(">HB", 0x0003, label) + sel)


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        frames.extend(ts.sections(PID_AIT, list(sects)))

    # 1: HbbTV AIT (type 0x0010): common loop with an HTTP transport
    # protocol descriptor, one autostart application with application,
    # application name and simple application location descriptors
    add(ait(0x0010, 1, [
        trpt_http(1, b"http://example.invalid/app/",
                  [b"https://example.invalid/", b"http://example.test/"]),
    ], [
        app(0x00000017, 0x0001, 0x01, [
            app_desc([(0x0000, (1, 2, 3)), (0x0001, (1, 3, 1))], 1, 3, 5,
                     [1, 2]),
            app_name([(b"eng", b"Guide"), (b"deu", b"Fuehrer")]),
            descr(0x15, b"index.html?x=1"),
        ]),
    ]))
    # 2: DVB-J AIT (type 0x0001), test application, object carousel
    # transport in the common loop (local and remote), applications with
    # every control code and the descriptors without own decoding, and an
    # empty application name descriptor
    add(ait(0x0001, 2, [
        trpt_oc(2),
        trpt_oc(3, remote=(0x0001, 0x0002, 0x0003), comp=0x21),
        descr(0x5F, struct.pack(">I", 0x00000028)),
    ], [
        app(0x00000017, 0x0002, 0x02, [
            app_desc([(0x0001, (1, 0, 0))], 0, 0, 1, []),
            descr(0x05, struct.pack(">IHB", 0x17, 0x0003, 0x01)),
            descr(0x06, b"\x80\x00"),
        ]),
        app(0x00000017, 0x0003, 0x03, [
            app_desc([], 0, 1, 2, [3]),
            descr(0x0B, b"\x01\x00\x01"),
            descr(0x10, b"\x80\x00\x00\x00\x01"),
        ]),
        app(0x00000017, 0x0004, 0x04, [descr(0x14, b"\x07")]),
        app(0x00000017, 0x0005, 0x05, [descr(0x17, b"\x01\x04http")]),
        app(0x00000017, 0x0006, 0x06, [descr(0x6F, b"\x00\x10\x01")]),
        app(0x00000017, 0x0007, 0x07, [descr(0x01, b"")]),
        app(0x00000017, 0x0008, 0x08, []),
    ], test_flag=1))
    # 3: transport protocol descriptors without selector bytes and with an
    # unknown protocol ID; application with an unknown control code
    add(ait(0x0010, 3, [
        descr(0x02, struct.pack(">HB", 0x0001, 4)),
        descr(0x02, struct.pack(">HB", 0x0003, 5)),
        descr(0x02, struct.pack(">HB", 0x0004, 6) + b"\x01\x02\x03"),
    ], [
        app(0x00000018, 0x4001, 0x09, [app_name([(b"fra", b"")])]),
    ], sect=0, last=1))
    # 4: empty AIT, next version, second section
    add(ait(0x0010, 4, [], [], sect=1, last=1, cur_next=0))
    # 5-6: an AIT with many applications that spans two TS packets
    add(ait(0x0010, 5, [], [
        app(0x00000019, 0x0100 + i, 0x02, [
            app_desc([(0x0000, (1, 1, 1))], 1, 3, i, [1]),
            app_name([(b"eng", b"App %d" % i)])]) for i in range(8)]))
    return frames


def build_malformed():
    ts = TS()
    frames = []
    # 1: application name length beyond the descriptor and the section
    frames += ts.sections(PID_AIT, [ait(0x0010, 0, [
        descr(0x01, b"eng" + bytes([200]) + b"x")], [])])
    # 2: application loop length beyond the section
    body = ext_header(0x0010, 0) + struct.pack(">HH", 0xF000, 0xF0FF) + \
        struct.pack(">IHB", 1, 2, 1)
    frames += ts.sections(PID_AIT, [section(0x74, body)])
    # 3: HTTP selector with URL extension count beyond the data
    frames += ts.sections(PID_AIT, [ait(0x0010, 0, [
        descr(0x02, struct.pack(">HB", 3, 1) + b"\x00\x09")], [])])
    # 4: application descriptor whose profiles run past the section
    frames += ts.sections(PID_AIT, [ait(0x0010, 0, [], [
        app(1, 1, 1, [descr(0x00, bytes([0x40]) + b"\x00\x01\x01\x01\x01")])])])
    return frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-ait-coverage.pcap"), build_main(),
               LINKTYPE_MPEG_2_TS)
    write_pcap(os.path.join(out, "dvb-ait-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_MPEG_2_TS)
