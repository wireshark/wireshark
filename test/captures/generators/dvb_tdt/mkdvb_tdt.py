#!/usr/bin/env python3
# Generates test/captures/dvb_tdt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB TDT coverage captures: Time and Date Table sections
(table ID 0x70, no section syntax, no CRC) in MPEG-TS packets on PID
0x0014 (linktype 243). Every packet is built with struct; nothing comes
from a real network. Usage: mkdvb_tdt.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import datetime
import struct
from dvbts import (
    exp_pdu, LINKTYPE_MPEG_2_TS, LINKTYPE_WIRESHARK_UPPER_PDU, section, TS, write_pcap,
)

PID_TDT_TOT = 0x0014


def bcd(v):
    return ((v // 10) << 4) | (v % 10)


def mjd_utc(y, mo, d, h, mi, s):
    """5 octet UTC time: 16 bit MJD and BCD hours, minutes, seconds."""
    mjd = 40587 + (datetime.date(y, mo, d) - datetime.date(1970, 1, 1)).days
    return struct.pack(">HBBB", mjd, bcd(h), bcd(mi), bcd(s))


def tdt(utc):
    # section_syntax_indicator 0, reserved_future_use 1, reserved 11
    return section(0x70, utc, ssi=False, reserved=7, crc=False)


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        frames.extend(ts.sections(PID_TDT_TOT, list(sects)))

    # 1: 2026-11-03 12:34:56 UTC
    add(tdt(mjd_utc(2026, 11, 3, 12, 34, 56)))
    # 2: hour 0x25 is not a valid BCD hour: "Unparseable time", which
    # keeps the field name with the fix on the branch
    add(tdt(struct.pack(">H", 61347) + bytes([0x25, 0x00, 0x00])))
    # 3: the last second of a day
    add(tdt(mjd_utc(1999, 12, 31, 23, 59, 59)))
    # 4: minute 0x60, also unparseable
    add(tdt(struct.pack(">H", 61347) + bytes([0x12, 0x60, 0x00])))
    # 5: the start of the Unix epoch (MJD 40587)
    add(tdt(mjd_utc(1970, 1, 1, 0, 0, 0)))
    # 6: two TDT sections in one TS packet, one second apart
    add(tdt(mjd_utc(2026, 11, 3, 12, 35, 0)),
        tdt(mjd_utc(2026, 11, 3, 12, 35, 1)))
    return frames


def build_malformed():
    """In TS packets the stuffing after a short section is read as part of
    it, so the short sections go in Exported PDUs naming mpeg_sect."""
    frames = []
    # 1: section cut in the middle of the UTC time
    frames.append(exp_pdu("mpeg_sect", section(0x70, b"\xef\x9b\x12",
                                               ssi=False, reserved=7,
                                               crc=False, length=5)))
    # 2: section with only the header
    frames.append(exp_pdu("mpeg_sect", section(0x70, b"", ssi=False,
                                               reserved=7, crc=False,
                                               length=5)))
    return frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-tdt-coverage.pcap"), build_main(),
               LINKTYPE_MPEG_2_TS)
    write_pcap(os.path.join(out, "dvb-tdt-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)
