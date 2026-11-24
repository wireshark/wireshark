#!/usr/bin/env python3
# Generates test/captures/mpeg_descriptor_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MPEG descriptor coverage captures. The descriptors are in the
program info and ES info loops of PMTs (table ID 2) in MPEG-TS packets
carried in UDP (heuristic mp2t_udp). The malformed capture uses Exported
PDUs (mpeg_sect). Usage: mkmpeg_descriptor.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mpeglib import (
    exp_pdu, LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, section, TS, udp_frame, write_pcap,
)


def d(tag, body=b""):
    return bytes([tag, len(body)]) + body


def u16(n):
    return struct.pack(">H", n)


def u32(n):
    return struct.pack(">I", n)


def bcd(s):
    """Digits string to packed BCD."""
    if len(s) % 2:
        s += "0"
    return bytes(int(s[i], 16) << 4 | int(s[i + 1], 16)
                 for i in range(0, len(s), 2))


def pstr(b):
    return bytes([len(b)]) + b


# DVB text encodings (first octets of a string)
ENC = {"": b"", "8859-5": b"\x01", "8859-9": b"\x05", "table": b"\x10\x00\x07",
       "ucs2": b"\x11", "utf8": b"\x15", "ext": b"\x1f\x01"}


def txt(s, enc=""):
    return ENC[enc] + s


def pmt(descs, es_streams=(), progno=1):
    """A PMT whose program info loop holds the descriptors."""
    body = (u16(progno) + bytes([0xC1, 0, 0]) + u16(0xE100) +
            u16(0xF000 | len(descs)) + descs +
            b"".join(es_streams))
    return section(0x02, body)


def es(stype, pid, descs=b""):
    return bytes([stype]) + u16(0xE000 | pid) + u16(0xF000 | len(descs)) + descs


# the per-tag descriptor bodies ------------------------------------------------

def tag_descriptors():
    L = []
    a = L.append
    # 0x02 video stream: MPEG-1 only; MPEG-2 with every field
    a(d(0x02, bytes([0x80 | (4 << 3) | 0x04 | 0x02 | 0x01])))
    a(d(0x02, bytes([(1 << 7) | (5 << 3) | 0x02, 0x48, 0x40 | 0x20 | 0x1F])))
    a(d(0x02, bytes([(0 << 7) | (2 << 3), 0x44, 0x80])))
    a(d(0x03, bytes([0x80 | 0x40 | 0x20 | 0x10 | 0x08])))
    a(d(0x03, b"\x00"))
    a(d(0x05, b"CUEI"))
    a(d(0x05, b"HDMV\x01\x02\xff"))
    a(d(0x05, b"GA94\x03"))
    for v in (0, 1, 2, 3, 4, 5):
        a(d(0x06, bytes([v])))
    a(d(0x09, u16(0x0500) + u16(0xE000 | 0x0100)))
    a(d(0x09, u16(0x0B00) + u16(0xE000 | 0x0101) + b"\x01\x02\x03"))
    a(d(0x0A, b"eng" + b"\x00"))
    a(d(0x0A, b"engfradeu" + b"\x03"))
    a(d(0x0A, b"x"))
    a(d(0x0B, bytes([0x80 | 0x40 | 0x05, 0xC0 | 0x20 | 0x1F])))
    a(d(0x0E, bytes([0xC0, 0x12, 0x34])))
    a(d(0x10, bytes([0xC0, 0x01, 0x02, 0xC0, 0x00, 0x03])[:3] + bytes([0xC0, 0x00, 0x03])))
    a(d(0x11, b"\xfe"))
    a(d(0x11, b"\xff"))
    # 0x13 carousel identifier: format 1 with and without private data and
    # an object key; format 0
    key = b"\x01\x02\x03"
    a(d(0x13, u32(0x1000) + b"\x01" + b"\x07" + u16(0x0100) + u16(4000) +
        u32(100000) + b"\x01" + u32(200000) + b"\x05" + bytes([len(key)]) +
        key + b"\xaa\xbb"))
    a(d(0x13, u32(0x1001) + b"\x01" + b"\x07" + u16(0x0100) + u16(4000) +
        u32(100000) + b"\x00" + u32(100000) + b"\x05" + b"\x00"))
    a(d(0x13, u32(0x1002) + b"\x00" + b"\x01\x02\x03"))
    a(d(0x13, u32(0x1003) + b"\x00"))
    # 0x14 association tag: use 0 with selector 8, use 0 with a wrong
    # selector length (returns), use 1 with selector bytes, private bytes
    a(d(0x14, u16(0x40) + u16(0) + b"\x08" + u32(0x01020304) + u32(5000)))
    a(d(0x14, u16(0x41) + u16(0) + b"\x08" + u32(7) + u32(9) + b"\xca\xfe"))
    a(d(0x14, u16(0x42) + u16(0) + b"\x04" + b"\x00\x00\x00\x00"))
    a(d(0x14, u16(0x43) + u16(1) + b"\x03" + b"\x01\x02\x03" + b"\x09"))
    a(d(0x28, bytes([0x64, 0xE0 | 0x0C, 0x28, 0x80 | 0x40 | 0x3F])))
    a(d(0x28, bytes([0x4D, 0x00, 0x1F, 0x00])))
    a(d(0x3F, b"\x04\x01\x02"))
    a(d(0x3F, b"\x02"))
    # 0x40 network name, with the DVB character set prefixes
    for enc in ("", "8859-9", "table", "ucs2", "utf8", "ext"):
        a(d(0x40, txt(b"Net", enc)))
    a(d(0x41, u16(0x0101) + b"\x01" + u16(0x0102) + b"\x19" + u16(0x0103) +
        b"\x02"))
    a(d(0x42, b"\xff" * 4))
    # 0x43 satellite (both modulation systems), 0x44 cable, 0x5A terrestrial
    a(d(0x43, bcd("01175000") + bcd("1925") +
        bytes([0x80 | 0x20 | 0x00 | 0x04 | 0x01]) + bcd("0275000")[:3] +
        bytes([0x00 | 0x03])))
    a(d(0x43, bcd("01207500") + bcd("0130") +
        bytes([0x00 | 0x40 | 0x10 | 0x08 | 0x01]) + bcd("0275000")[:3] +
        bytes([0x00 | 0x05])))
    a(d(0x44, bcd("03060000") + b"\xff\xf2" + b"\x03" + bcd("0069000")[:3] +
        b"\x00\x03"[:1] + b"\x00"))
    a(d(0x44, bcd("04100000") + b"\xff\xf0" + b"\x05" + bcd("0069000")[:3] +
        b"\x05"))
    # 0x45 VBI data: teletext services (1, 2, 4-7) and others
    a(d(0x45, b"\x01\x02\xe4\xe5\x02\x01\xc7\x04\x01\xff\x05\x00\x09\x03\xaa\xbb\xcc"))
    a(d(0x46, b"\x05\x00"))
    a(d(0x47, txt(b"Bouquet", "8859-9")))
    a(d(0x47, b"Plain"))
    # 0x48 service: with provider and service names, with empty ones
    a(d(0x48, b"\x01" + pstr(txt(b"Prov", "utf8")) + pstr(txt(b"Svc", "8859-5"))))
    a(d(0x48, b"\x19" + pstr(b"") + pstr(b"")))
    a(d(0x49, b"\x80" + b"GBR" + b"DEU"))
    a(d(0x49, b"\x00" + b"FRA"))
    # 0x4A linkage: 0x08 (hand-over 1/2/3/0, origin 0/1), 0x0D, 0x81, other
    base = u16(1) + u16(2) + u16(3)
    a(d(0x4A, base + b"\x08" + bytes([(1 << 4) | 0x0E | 1]) + u16(0x20) + u16(0x30)))
    a(d(0x4A, base + b"\x08" + bytes([(2 << 4) | 0x0E]) + u16(0x20)))
    a(d(0x4A, base + b"\x08" + bytes([(3 << 4) | 0x0E | 1]) + u16(0x21) + u16(0x31)))
    a(d(0x4A, base + b"\x08" + bytes([(0 << 4) | 0x0E | 1]) + u16(0x31)))
    a(d(0x4A, base + b"\x0d" + u16(0x77) + bytes([0xC0 | 0x20 | 0x10 | 0x0F])))
    a(d(0x4A, base + b"\x81" + u16(0x1234) + b"\x01" + u16(0x0001) + u16(0xFFF0) +
        u16(0x0002) + u16(0xFFF1) + b"\x01\x02"))
    a(d(0x4A, base + b"\x81" + b"\x01\x02"))
    a(d(0x4A, base + b"\x04" + b"private"))
    a(d(0x4B, u16(1) + u16(2) + u16(3) + u16(4) + u16(5) + u16(6)))
    a(d(0x4C, u16(0x1234)))
    # 0x4D short event with text and name in several encodings
    a(d(0x4D, b"eng" + pstr(txt(b"News", "")) + pstr(txt(b"At ten", "utf8"))))
    a(d(0x4D, b"deu" + pstr(b"") + pstr(b"")))
    # 0x4E extended event: two items and text
    items = pstr(b"Actor") + pstr(b"Jane") + pstr(b"Dir") + pstr(b"Joe")
    a(d(0x4E, bytes([(0 << 4) | 1]) + b"eng" +
        pstr(items) + pstr(txt(b"Long text", "utf8"))))
    a(d(0x4E, bytes([(1 << 4) | 1]) + b"eng" + b"\x00" + pstr(b"")))
    a(d(0x4F, u16(0x0102) + u16(0x0304)))
    # 0x50 component: content type, high stream content (including NGA)
    a(d(0x50, bytes([0x05, 0x01, 0x10]) + b"eng" + txt(b"MPEG video", "")))
    a(d(0x50, bytes([0x09, 0x02, 0x11]) + b"deu" + b"x"))
    a(d(0x50, bytes([0xE0 | 0x0B, 0x7F]) + bytes([0x12]) + b"eng" + b"NGA"))
    a(d(0x50, bytes([0x00 | 0x0B, 0x01]) + bytes([0x13]) + b"eng" + b""))
    a(d(0x50, bytes([0x04, 0x01])))
    # 0x51 mosaic: cell linkage 1, 2, 3, 4 and none, elementary cells
    mos = b"\x80"
    mos += bytes([0x04 << 2, 0x07]) + b"\x02" + b"\x01\x02" + b"\x01" + u16(0x0100)
    mos += bytes([0x08 << 2 | 0, 0x07]) + b"\x00" + b"\x02" + u16(1) + u16(2) + u16(3)
    mos += bytes([0x0C << 2, 0x07]) + b"\x01" + b"\x03" + b"\x03" + u16(4) + u16(5) + u16(6)
    mos += bytes([0x10 << 2, 0x07]) + b"\x01" + b"\x04" + b"\x04" + u16(7) + u16(8) + u16(9) + u16(10)
    mos += bytes([0x14 << 2, 0x07]) + b"\x00" + b"\x00"
    a(d(0x51, mos))
    a(d(0x52, b"\x07"))
    a(d(0x53, u16(0x0500) + u16(0x0B00)))
    a(d(0x54, b"\x10\x00\x21\x05\xf0\xff"))
    a(d(0x55, b"GBR" + b"\x05"))
    a(d(0x56, b"eng" + bytes([(2 << 3) | 1, 0x88]) + b"deu" + bytes([(1 << 3) | 7, 0x00])))
    # 0x57 telephone: every length, and no number
    a(d(0x57, bytes([0x20 | 0x13, 0x4D, 0x24]) + b"49" + b"030" + b"5" + b"12" + b"3456"))
    a(d(0x57, bytes([0x00, 0x00, 0x00])))
    a(d(0x57, bytes([0x00, 0x00, 0x01]) + b"7"))
    a(d(0x57, bytes([0x00, 0x00, 0x20]) + b"11"))
    a(d(0x57, bytes([0x00, 0x04, 0x00]) + b"4"))
    a(d(0x57, bytes([0x00, 0x40, 0x00]) + b"22"))
    a(d(0x57, bytes([0x00, 0x01, 0x00]) + b"3"))
    # 0x58 local time offset: valid, invalid time of change, two countries
    lto = (b"GBR" + bytes([0x04 << 2 | 0x02 | 0, 0x01, 0x00]) +
           u16(60000) + b"\x01\x00\x00" + b"\x01\x00")
    lto2 = (b"DEU" + bytes([0x00 | 1, 0x01, 0x30]) + u16(60001) + b"\x25\x61\x62" +
            b"\x02\x00")
    a(d(0x58, lto))
    a(d(0x58, lto + lto2))
    a(d(0x59, b"eng" + b"\x10" + u16(1) + u16(2) + b"deu" + b"\x20" + u16(3) + u16(3)))
    a(d(0x5A, u32(47400000) + b"\x20\xc0\x2a\x35" + b"\xff\xff\xff\xff"[:4]))
    a(d(0x5A, u32(0) + b"\xe0\x00\x00\x00" + b"\x00" * 4))
    # 0x5B/5C/5D/5E multilingual descriptors
    a(d(0x5B, b"eng" + pstr(txt(b"Net", "")) + b"deu" + pstr(txt(b"Netz", "utf8"))))
    a(d(0x5B, b"fr"))
    a(d(0x5B, b"eng"))
    a(d(0x5B, b"eng" + b"\x20" + b"abc"))
    a(d(0x5C, b"eng" + pstr(b"Bq")))
    a(d(0x5D, b"eng" + pstr(b"Prov") + pstr(b"Svc") + b"deu" + pstr(b"P") + pstr(b"S")))
    a(d(0x5D, b"eng" + pstr(b"Pr")))
    a(d(0x5D, b"eng" + b"\x20" + b"p"))
    a(d(0x5D, b"eng" + b"\x01" + b"p" + b"\x20" + b"s"))
    a(d(0x5D, b"en"))
    a(d(0x5E, b"\x07" + b"eng" + pstr(b"Comp") + b"deu" + pstr(b"Kompo")))
    a(d(0x5E, b"\x07" + b"eng" + b"\x20" + b"x"))
    a(d(0x5E, b"\x07" + b"en"))
    a(d(0x5E, b"\x07" + b"eng"))
    a(d(0x61, b"\xfc\x03" + b"\x00" * 2))
    a(d(0x61, b"\xfc\x03"[:1] + b"\x03"))
    a(d(0x63, b"\xc0\x01\x02" + b"\xc0\x03\x04" + b"\xc0\x05"))
    a(d(0x63, b"\xff\xff\xff" + b"\xff\xff\xff" + b"\xff\xff"))
    a(d(0x63, b"\xc0\x01\x02" + b"\xc0\x03"))
    a(d(0x63, b"\xc0\x01"))
    a(d(0x64, u16(0x0005) + b"\x01" + b"\x02\x01\x02" + b"eng" + pstr(b"Data")))
    a(d(0x64, u16(0x0006) + b"\x02" + b"\x00" + b"deu" + b"\x00"))
    a(d(0x66, u16(0x00F0) + b"\x01\x02\x03"))
    a(d(0x66, u16(0x0010)))
    a(d(0x69, b"\xf0\x12\x34"))
    # 0x6A AC-3: every flag
    a(d(0x6A, bytes([0x80 | 0x40 | 0x20 | 0x10 | 0x0F, 0x20 | 0x10 | 0x08 | 0x03,
                     0x08, 0x01, 0x02]) + b"info"))
    a(d(0x6A, bytes([0x00])))
    a(d(0x6F, u16(0x0010) + b"\x01" + u16(0x0001) + b"\x02"))
    a(d(0x71, b"\x01\x02\x03"))
    a(d(0x72, bytes([0x80 | 0x7F]) + u16(1) + u16(2)))
    a(d(0x72, bytes([0x7F])))
    a(d(0x73, b"example.invalid"))
    a(d(0x75, u16(0x0001) + b"\xf9" + u16(0x0002) + b"\xfa"))
    # 0x76 content identifier: CRID location 0 (with bytes), 2 and 3
    a(d(0x76, bytes([(1 << 2) | 0, 5]) + b"crid1" + bytes([(2 << 2) | 2]) +
        bytes([(3 << 2) | 3])))
    a(d(0x7D, u16(0x0001) + u16(0x0002) + b"\x05\x01"))
    a(d(0x7E, bytes([0x80 | 0x70 | 0x08 | 0x04 | 0x02 | 0x01][:1])))
    # 0x7F ETSI extension: supplementary audio with and without language
    # and private data, others
    a(d(0x7F, b"\x06" + bytes([0x80 | 0x10 | 0x04 | 0x01]) + b"eng" + b"pd"))
    a(d(0x7F, b"\x06" + bytes([0x00])))
    a(d(0x7F, b"\x06" + bytes([0x01]) + b"eng"))
    a(d(0x7F, b"\x0f" + b"\x01\x02"))
    a(d(0x7F, b"\x0f"))
    # 0x81 ATSC A/52 audio: each optional field in turn and every early end
    sysa = bytes([0x20, 0x01])
    a(d(0x81, sysa + bytes([0x45]) + b"\x65" + b"\x01" + b"\x00" + b"\x00" +
        bytes([0xC0]) + b"fra" + b"deu" + b"extra"))
    a(d(0x81, sysa + bytes([0x00]) + b"\x65" + b"\x66" + b"\x01" + b"\x00" +
        bytes([0x80]) + b"fra"))
    a(d(0x81, sysa + bytes([0x00]) + b"\x65" + b"\x66" + b"\x40" + b"\x00" +
        bytes([0x40]) + b"deu"))
    a(d(0x81, sysa + bytes([0x40 | 0x02]) + b"\x65" + b"\x03" + b"\x03" +
        b"ab" + bytes([0x00])))
    a(d(0x81, sysa))
    a(d(0x81, sysa + b"\x45"))
    a(d(0x81, sysa + b"\x45\x65"))
    a(d(0x81, sysa + b"\x02\x65\x01"))
    a(d(0x81, sysa + b"\x02\x65\x01\x00"))
    a(d(0x81, sysa + b"\x02\x65\x01\x00\x00"))
    # 0x83 NorDig LCN v1, wrong length; 0x87 v2
    a(d(0x83, u16(0x0101) + u16(0xFC00 | 1) + u16(0x0102) + u16(0xFC00 | 2)))
    a(d(0x83, u16(0x0101) + u16(0xFC00 | 1) + b"\x00"))
    a(d(0x87, b"\x01" + pstr(txt(b"List", "")) + b"DEU" + pstr(
        u16(0x0101) + u16(0xFC00 | 1) + u16(0x0102) + u16(0xFC00 | 2))))
    a(d(0x87, b"\x02" + pstr(b"") + b"GBR" + pstr(b"") +
        b"\x03" + pstr(b"x") + b"FRA" + pstr(u16(0x0201) + u16(0xFC00 | 7))))
    a(d(0x87, b"\x01" + pstr(b"") + b"GBR" + bytes([200]) + u16(1) + u16(1)))
    a(d(0x87, b"\x01"))
    a(d(0x87, b"\x01\x00"))
    a(d(0x87, b"\x01\x05" + b"abc"))
    return L


def logon_descriptors():
    """Logon initialize descriptors of every length and layout."""
    L = []
    a = L.append
    a(d(0xA2, b"\x01"))
    a(d(0xA2, b"\x01\x00\x02"))
    a(d(0xA2, b"\x01\x00\x02" + bytes([0x20 | 0x10 | 0x08 | 0x04 | 0x02 | 0x01])))
    # len >= 5: burst type 1 with connectivity bit, and without; burst
    # type 0; capacity type flag
    base = b"\x01\x00\x02" + b"\x00"
    a(d(0xA2, base + bytes([0x20 | 0x10]) + b"\x01\x00\x12\x00\x34\x00" + b"\x00" * 6))
    a(d(0xA2, base + bytes([0x20]) + b"\x01\x00\x12\x00\x34\x00" + b"\x00" * 6))
    a(d(0xA2, base + bytes([0x00]) + b"\x01\x23\x01\x23" + b"\x00" * 6))
    a(d(0xA2, base + bytes([0x40 | 0x20 | 0x10]) + b"\x01\x00\x12\x00\x34\x00" +
        b"\x01\x02\x03" + b"\x00\x20" + b"\x01\x02\x03" + b"\x00\x08"))
    a(d(0xA2, base + bytes([0x40]) + b"\x01\x23\x01\x23" + b"\x01\x02\x03" +
        b"\x00\x20" + b"\x01\x02\x03" + b"\x00\x08"))
    return L


def other_descriptors():
    L = []
    a = L.append
    # 0xA7 RCS content, 0xC4 ST 2038 with nested descriptors
    a(d(0xA7, b"\x74\x75"))
    a(d(0xC4, d(0x52, b"\x01") + d(0x0A, b"eng\x00")))
    a(d(0xC4, b""))
    # tags in the tag table without a decoder, and unknown tags
    for t in (0x04, 0x07, 0x08, 0x0C, 0x0D, 0x0F, 0x12, 0x15, 0x1B, 0x1C,
              0x20, 0x2C, 0x46, 0x60, 0x62, 0x65, 0x67, 0x68, 0x6B, 0x70,
              0x74, 0x77, 0x7A, 0x7B, 0x7C, 0xA0, 0xA1, 0xA3, 0xAE, 0xB6,
              0x80, 0xB4, 0xC0, 0xD0, 0xFE):
        a(d(t, b"\x01\x02\x03"))
    a(d(0xF0, b""))                  # empty descriptor
    return L


def ciplus_descriptors():
    L = []
    a = L.append
    spec = d(0x5F, u32(0x00000040))
    # CI+ service (0xcc) and protection (0xce) descriptors
    a(spec + d(0xCC, u16(0x1234) + b"\x01" + u16(0xC000 | 0x3000 | 0x0001)
               + pstr(b"Prov") + pstr(b"Service")))
    a(spec + d(0xCE, b"\x00") + d(0xCE, bytes([0x40 | 0x01, 3]) + u16(1) + u16(2) + u16(3) + b"pd"))
    a(spec + d(0xCE, bytes([0x40 | 0x01, 0])))
    # another private data specifier: the CI+ tags are unknown
    a(d(0x5F, u32(0x00000029)) + d(0xCC, b"\x01\x02\x03"))
    # the private data specifier changes in the loop
    a(spec + d(0xCE, b"\x00") + d(0x5F, u32(0)) + d(0xCE, b"\x00"))
    return L


def build_main():
    ts = TS()
    frames = []

    def add(pid, *sects):
        pk = ts.sections(pid, list(sects))
        frames.append(udp_frame(b"".join(pk), dport=5004))

    def chunked(descs, per=1500, base=1):
        """Descriptors in PMTs of at most `per` octets of program info."""
        out, cur = [], b""
        for x in descs:
            if len(cur) + len(x) > per:
                out.append(cur)
                cur = b""
            cur += x
        if cur:
            out.append(cur)
        return out

    n = 1
    for group in (tag_descriptors(), logon_descriptors(), other_descriptors(),
                  ciplus_descriptors()):
        for loop in chunked(group):
            add(0x1000, pmt(loop, progno=n))
            n += 1
    # descriptors in ES info loops
    add(0x1000, pmt(d(0x05, b"HDMV"), [
        es(0x02, 0x100, d(0x02, bytes([0x48, 0x4A, 0x40])) + d(0x0E, b"\xc0\x10\x00")),
        es(0x03, 0x101, d(0x0A, b"eng\x00") + d(0x03, b"\x08")),
        es(0x06, 0x102, d(0x6A, b"\x00") + d(0x59, b"eng\x10" + u16(1) + u16(2))),
        es(0x06, 0x103, d(0x56, b"eng" + bytes([0x08, 0x88]))),
    ], progno=n))
    return frames


def build_malformed():
    f = []
    # reproducers of the descriptor decoding findings (not fixed on the
    # branch): the CI+ content label length is computed from the absolute
    # tvb offset and the next descriptor is parsed inside the label; the
    # content identifier's CRID location 1 does not skip its 2 octet ref
    spec = d(0x5F, u32(0x00000040))
    label = b"ABCDEFGHIJKLMNOPQRSTUVWXY"
    cl = bytes([1, 2]) + b"eng" + label
    crid = bytes([(1 << 2) | 1, 0x12, 0x34, (2 << 2) | 1, 0x56, 0x78])
    f.append(pmt(spec + d(0xCB, cl) + d(0x76, crid)))
    f.append(pmt(d(0x76, crid)))
    # a CI+ content label that is shorter than the tvb offset (the label
    # length wraps)
    f.append(pmt(spec + d(0xCB, bytes([1, 2]) + b"eng" + b"ab")))
    f.append(pmt(spec + d(0xCB, bytes([1, 2]))))
    # descriptors that run past the end of the loop or the section
    for tag, body in ((0x09, b"\x01"), (0x0E, b"\xc0"), (0x13, b"\x00\x00\x10"),
                      (0x14, b"\x00\x40\x00"), (0x4A, b"\x00\x01"),
                      (0x4D, b"eng\x10ab"), (0x4E, b"\x00eng\xff"),
                      (0x58, b"GBR"), (0x5A, b"\x00\x00"), (0x45, b"\x01\xf0"),
                      (0x43, b"\x01\x17"), (0x44, b"\x01"), (0x48, b"\x01\x30"),
                      (0x76, b"\x00\x40"), (0x87, b"\x01\x04abc"),
                      (0x56, b"eng"), (0x51, b"\x80\x04\x07\x09"),
                      (0x57, b"\x00\x00\x10"), (0x6A, b"\xf0"),
                      (0x81, b"\x20\x01\x02\x41\x05"), (0xA2, b"\x01\x00\x02\x00\x60")):
        # a lying descriptor length: claims more octets than present
        g = bytes([tag, len(body) + 12]) + body
        f.append(section(0x02, u16(1) + bytes([0xC1, 0, 0]) + u16(0xE100) +
                         u16(0xF000 | len(g)) + g))
    # a PMT with an empty program info followed by an ES info loop holding
    # a lying descriptor
    f.append(section(0x02, u16(1) + bytes([0xC1, 0, 0]) + u16(0xE100) +
                     u16(0xF000) + bytes([0x02]) + u16(0xE100) + u16(0xF000 | 3) +
                     bytes([0x6A, 0x40, 0x01])))
    # the ST 2038 descriptor with nested descriptors that are not confined
    # to the parent: 120 levels of 0xc4
    nest = b""
    for _ in range(120):
        nest = bytes([0xC4, len(nest)]) + nest
    f.append(pmt(nest))
    nest2 = d(0x52, b"\x01")
    for _ in range(100):
        nest2 = d(0xC4, nest2)
        if len(nest2) > 250:
            break
    f.append(pmt(nest2))
    # satellite delivery with invalid BCD digits and a bad time of change
    f.append(pmt(d(0x43, bytes([0xFF] * 4 + [0xAB, 0xCD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))))
    f.append(pmt(d(0x58, b"GBR" + bytes([0x03, 0xFF, 0xFF]) + u16(65535) +
                   b"\xff\xff\xff" + b"\xaa\xbb")))
    return [exp_pdu("mpeg_sect", x) for x in f]


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(os.path.join(out, "mpeg-descriptor-coverage.pcap"),
               build_main(), LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "mpeg-descriptor-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)
