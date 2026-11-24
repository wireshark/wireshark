#!/usr/bin/env python3
# Generates test/captures/dvb_tot_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB TOT coverage captures: Time Offset Table sections
(table ID 0x73, no section syntax but with a CRC) in MPEG-TS packets on
PID 0x0014 (linktype 243), as broadcast with the TDT. Every packet is
built with struct; nothing comes from a real network.
Usage: mkdvb_tot.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import datetime
import struct
from dvbts import (
    descr, exp_pdu, LINKTYPE_MPEG_2_TS, LINKTYPE_WIRESHARK_UPPER_PDU, section, TS, write_pcap,
)

PID_TDT_TOT = 0x0014


def bcd(v):
    return ((v // 10) << 4) | (v % 10)


def mjd_utc(y, mo, d, h, mi, s):
    """5 octet UTC time: 16 bit MJD and BCD hours, minutes, seconds."""
    mjd = 40587 + (datetime.date(y, mo, d) - datetime.date(1970, 1, 1)).days
    return struct.pack(">HBBB", mjd, bcd(h), bcd(mi), bcd(s))


def tot(utc, descrs):
    d = b"".join(descrs)
    # section_syntax_indicator 0, reserved_future_use 1, reserved 11
    return section(0x73, utc + struct.pack(">H", 0xF000 | len(d)) + d,
                   ssi=False, reserved=7)


def tdt(utc):
    return section(0x70, utc, ssi=False, reserved=7, crc=False)


def lto_entry(country, region, polarity, offset, change, next_offset):
    return (country + bytes([(region << 2) | 0x02 | polarity]) +
            bytes([bcd(offset[0]), bcd(offset[1])]) + change +
            bytes([bcd(next_offset[0]), bcd(next_offset[1])]))


# Local time offset: Germany +01:00 changing to +02:00 on 2027-03-28,
# region 0; Portugal (Azores, region 2) -01:00
lto = descr(0x58,
            lto_entry(b"DEU", 0, 0, (1, 0), mjd_utc(2027, 3, 28, 1, 0, 0),
                      (2, 0)) +
            lto_entry(b"PRT", 2, 1, (1, 0), mjd_utc(2027, 3, 28, 1, 0, 0),
                      (0, 0)))
pdsd = descr(0x5F, struct.pack(">I", 0x00000028))


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        frames.extend(ts.sections(PID_TDT_TOT, list(sects)))

    now = mjd_utc(2026, 11, 3, 12, 34, 56)
    # 1: TOT with a local time offset descriptor for two countries
    add(tot(now, [lto]))
    # 2: TOT without descriptors
    add(tot(mjd_utc(2026, 11, 3, 12, 35, 26), []))
    # 3: hour 0x24 is not a valid BCD hour: "Unparseable time"
    add(tot(struct.pack(">H", 61347) + bytes([0x24, 0x00, 0x00]), [lto]))
    # 4: TOT with a private data specifier and a local time offset
    add(tot(mjd_utc(2026, 11, 3, 12, 35, 56), [pdsd, lto]))
    # 5: TDT and TOT in one TS packet, as on PID 0x0014 of a real stream
    add(tdt(mjd_utc(2026, 11, 3, 12, 36, 26)),
        tot(mjd_utc(2026, 11, 3, 12, 36, 26), [lto]))
    return frames


def build_malformed():
    """In TS packets the stuffing after a short section is read as part of
    it, so the short sections go in Exported PDUs naming mpeg_sect."""
    frames = []
    now = mjd_utc(2026, 11, 3, 12, 34, 56)
    # 1: descriptors loop length beyond the section
    frames.append(exp_pdu("mpeg_sect", section(
        0x73, now + struct.pack(">H", 0xF0FF) + lto, ssi=False, reserved=7)))
    # 2: section cut before the descriptors loop length
    frames.append(exp_pdu("mpeg_sect", section(
        0x73, now, ssi=False, reserved=7, crc=False, length=11)))
    # 3: section cut before the CRC
    frames.append(exp_pdu("mpeg_sect", section(
        0x73, now + struct.pack(">H", 0xF000), ssi=False, reserved=7,
        crc=False, length=11)))
    # 4: section cut in the middle of the UTC time
    frames.append(exp_pdu("mpeg_sect", section(
        0x73, now[:3], ssi=False, reserved=7, crc=False, length=11)))
    return frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-tot-coverage.pcap"), build_main(),
               LINKTYPE_MPEG_2_TS)
    write_pcap(os.path.join(out, "dvb-tot-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)
