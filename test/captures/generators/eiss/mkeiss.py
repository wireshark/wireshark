#!/usr/bin/env python3
# Generates test/captures/eiss_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ETV-AM EISS dissector
(packet-eiss.c, OC-SP-ETV-AM1.0 Integrated Signaling Stream).

EISS sections (table ID 0xE0) are carried in 188 octet MPEG-TS packets
on PID 0x0100 (linktype 243, MPEG_2_TS), each starting with a pointer
field. MP2T hands them to MPEG SECT, which looks the table ID up in
mpeg_sect.tid. A section has the section syntax indicator and reserved
bits zero, a reserved octet, section numbers, a protocol version,
application type 8, organisation and application IDs, a list of 15
octet platform IDs and descriptors: 0xE0 Application Information (with
the Initial Resource Locator), 0xE1 Media Time and 0xE2 Stream Event,
then the CRC. Every packet is built with struct (helpers in dvbts.py);
no captured traffic is used.

Usage: mkeiss.py <output directory>

Writes:
  eiss-coverage.pcap            every descriptor, platform ID lists,
                                application IDs and control codes, a
                                section spread over two TS packets
  eiss-coverage-malformed.pcap  every error expert info, an unknown
                                descriptor, truncated sections
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from dvbts import LINKTYPE_MPEG_2_TS, TS, write_pcap, crc32_mpeg2

TID = 0xE0
PID = 0x0100


def section(body, ssi=False, reserved=0, length=None, crc=True):
    blen = len(body) + 4
    if length is None:
        length = blen
    s = bytes([TID]) + struct.pack(
        ">H", (0x8000 if ssi else 0) | (reserved << 12) | (length & 0xFFF))
    s += body
    if crc:
        s += struct.pack(">I", crc32_mpeg2(s))
    return s


def platform(n):
    """One 15 octet platform ID: hardware manufacturer, model and
    version, software manufacturer, model and version, profile."""
    return (struct.pack(">I", 0x00A0B0 + n)[1:] + struct.pack(">HBB", 0x1000 + n, 1, n) +
            struct.pack(">I", 0x00C0D0 + n)[1:] + struct.pack(">HBB", 0x2000 + n, 2, n) +
            bytes([0x10 + n]))


def eiss(descs, platforms=(), sect=0, last=0, app_id=0x0001, org=0x12345678,
         vmaj=1, vmin=0, app_type=8, reserved2=0, plat_len=None):
    p = b"".join(platform(n) for n in platforms)
    if plat_len is None:
        plat_len = len(p)
    body = struct.pack(">BBBBBHIHB", reserved2, sect, last, vmaj, vmin,
                       app_type, org, app_id, plat_len) + p + b"".join(descs)
    return body


def aid(ctrl, irl, vmaj=1, vmin=2, pmaj=1, pmin=0, test=0, prio=5, irl_type=1,
        irl_len=None):
    """ETV Application Information Descriptor (0xE0)."""
    if irl_len is None:
        irl_len = len(irl)
    v = bytes([ctrl, vmaj, vmin, pmaj, pmin, test]) + b"\0\0\0" + bytes([prio])
    v += struct.pack(">H", (irl_type << 10) | irl_len) + irl
    return bytes([0xE0, len(v)]) + v


def mtd(t):
    """ETV Media Time Descriptor (0xE1)."""
    return bytes([0xE1, 4]) + struct.pack(">I", t)


def sed(t, payload, reserved=0):
    """ETV Stream Event Descriptor (0xE2): 12 bit length, time, payload."""
    ln = 4 + len(payload)
    return bytes([0xE2]) + struct.pack(">HI", (reserved << 12) | ln, t) + payload


def main_sections():
    S = []
    # 1: one platform ID; Application Information (AUTOSTART, IRL
    #    string), Media Time and Stream Event descriptors
    S.append(section(eiss([aid(0x01, b"http://etv.example/app/1"),
                           mtd(90000),
                           sed(180000, b"event-data")],
                          platforms=[1])))
    # 2: two platform IDs, no descriptors, section 0 of 1, signed
    #    application ID
    S.append(section(eiss([], platforms=[2, 3], sect=0, last=1,
                          app_id=0x4001)))
    # 3: section 1 of 1, application ID reserved by DVB; PRESENT, DESTROY,
    #    reserved control codes 0x00 and 0x04, test flag, empty IRL
    S.append(section(eiss([aid(0x02, b"/a2", test=1, irl_type=0x3f),
                           aid(0x03, b"", prio=0),
                           aid(0x00, b"x"),
                           aid(0x04, b"/reserved")],
                          sect=1, last=1, app_id=0x8000, vmaj=2, vmin=1)))
    # 4: wildcard application IDs; a Stream Event without payload and one
    #    with the largest time value
    S.append(section(eiss([sed(0, b""), sed(0xFFFFFFFF, b"\x01\x02")],
                          app_id=0xFFFE)))
    S.append(section(eiss([mtd(0), mtd(1)], app_id=0xFFFF)))
    # 6: no descriptors and no platforms at all
    S.append(section(eiss([], app_id=0x3FFF)))
    # 7-8: a section with four platform IDs and long IRLs that spans two
    #      TS packets
    S.append(section(eiss([aid(0x01, b"http://etv.example/" + b"p" * 60),
                           sed(7, b"E" * 40)],
                          platforms=[4, 5, 6, 7])))
    # 9: the fix "EISS: Fix the IRL string and a duplicate field name":
    #    the IRL string is the irl_length octets after the length field
    #    (it was read as a string with a 2 octet length prefix, here
    #    0x6874 = "ht", past the end of the descriptor), and the Stream
    #    Event descriptor length is eiss.sed.desc_length.
    S.append(section(eiss([aid(0x01, b"http://etv.example/fix"),
                           sed(9, b"\x00\x01")])))
    return S


def malformed_sections():
    S = []
    # 1: section syntax indicator set
    S.append(section(eiss([mtd(1)]), ssi=True))
    # 2: reserved bits set
    S.append(section(eiss([mtd(2)]), reserved=7))
    # 3: section length above 1021 (the section is cut by the TS packet)
    S.append(section(eiss([mtd(3)]), length=1022, crc=False) + b"\0" * 4)
    # 4: reserved2 not zero, section number above the last
    S.append(section(eiss([mtd(4)], reserved2=0xFF, sect=2, last=1)))
    # 5: application type other than 8
    S.append(section(eiss([mtd(5)], app_type=7)))
    # 6: platform ID length not a multiple of 15 (16)
    S.append(section(eiss([], platforms=[1, 2], plat_len=16)))
    # 7: unknown descriptor tag (the rest of the section is skipped)
    S.append(section(eiss([b"\x99\x02\x00\x00", mtd(7)])))
    # 8: an IRL length past the end of the section
    S.append(section(eiss([aid(0x01, b"short", irl_len=300)])))
    # 9: a Stream Event descriptor length below 4
    S.append(section(eiss([bytes([0xE2]) + struct.pack(">HI", 2, 0)])))
    # 10: a Stream Event descriptor with its reserved bits set: the
    #     dissector takes all 16 bits as the length
    S.append(section(eiss([sed(1, b"\x01\x02", reserved=0xF), mtd(10)])))
    return S


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    ts = TS()
    frames = []
    for s in main_sections():
        frames += ts.sections(PID, [s])
    write_pcap(os.path.join(out, "eiss-coverage.pcap"), frames,
               LINKTYPE_MPEG_2_TS)
    ts = TS()
    frames = []
    for s in malformed_sections():
        frames += ts.sections(PID, [s[:183]])
    # 11: a TS packet with only the first 10 octets of a section
    frames += ts.sections(PID, [section(eiss([mtd(10)]))[:10]])
    write_pcap(os.path.join(out, "eiss-coverage-malformed.pcap"), frames,
               LINKTYPE_MPEG_2_TS)


if __name__ == "__main__":
    main()
