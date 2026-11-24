#!/usr/bin/env python3
# Generates test/captures/mpeg_pes_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MPEG PES coverage captures. PES packets are carried in
MPEG-TS over UDP (heuristic mp2t_udp), after a PAT and a PMT that give the
elementary streams their types. The malformed capture uses Exported PDUs
(mpeg-pes). Usage: mkmpeg_pes.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mpeglib import (
    descr, exp_pdu, ext_header, LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, section, TS,
    udp_frame, write_pcap,
)


class Bits:
    """MSB-first bit packer for the PER-aligned video headers."""
    def __init__(self):
        self.v = 0
        self.n = 0

    def put(self, val, bits):
        self.v = (self.v << bits) | (val & ((1 << bits) - 1))
        self.n += bits
        return self

    def align(self):
        """Aligned PER pads to an octet boundary before a 0..255 integer."""
        pad = (-self.n) % 8
        return self.put(0, pad)

    def bytes(self):
        pad = (-self.n) % 8
        return (self.v << pad).to_bytes((self.n + pad) // 8, "big")


PFX = b"\x00\x00\x01"


def seq_header(h=720, v=576, aspect=2, fr=3, bitrate=0x3FFFF, vbv=112,
               cons=0, intra=0, nonintra=0, matrix=True):
    b = (Bits().put(h, 12).put(v, 12).put(aspect, 4).put(fr, 4)
         .put(bitrate, 18).put(1, 1).put(vbv, 10).put(cons, 1)
         .put(intra, 1).put(nonintra, 1))
    return PFX + b"\xb3" + b.bytes() + (bytes(range(64)) if matrix else b"")


def seq_ext(profile=0x48, prog=1, chroma=1, hext=0, vext=0, brext=0,
            vbvext=0, low=0, n=0, d=0):
    # the module is decoded as aligned PER: the 0..255 integers start on an
    # octet boundary, so the field is 53 bits and its last byte is shared
    # with what follows
    b = (Bits().put(1, 4).align().put(profile, 8).put(prog, 1)
         .put(chroma, 2).put(hext, 2).put(vext, 2).put(brext, 12)
         .put(1, 1).align().put(vbvext, 8).put(low, 1).put(n, 2).put(d, 2))
    return PFX + b"\xb5" + b.bytes()


def gop(drop=0, hh=1, mm=2, ss=3, fr=4, closed=1, broken=0):
    # the ASN.1 module has hour 0..32 (6 bits) and minute, second and
    # frame 0..64 (7 bits each): 36 bits, the last byte is shared with the
    # next start code
    b = (Bits().put(drop, 1).put(hh, 6).put(mm, 7).put(1, 1).put(ss, 7)
         .put(fr, 7).put(closed, 1).put(broken, 1).put(0, 5))
    return PFX + b"\xb8" + b.bytes()


def picture(seq=5, ftype=1, vbv=0xFFFF, data=b"\x00" * 8):
    b = Bits().put(seq, 10).put(ftype, 3).put(vbv, 16).put(0, 3)
    return PFX + b"\x00" + b.bytes() + data


def ts40(prefix, v):
    return bytes([(prefix << 4) | (((v >> 30) & 7) << 1) | 1,
                  (v >> 22) & 0xFF, (((v >> 15) & 0x7F) << 1) | 1,
                  (v >> 7) & 0xFF, ((v & 0x7F) << 1) | 1])


def clock(v, ext, top=1):
    """6 byte SCR/ESCR: top is 1 for the pack header ('01'), 0 for ESCR."""
    b = (Bits().put(top, 2).put((v >> 30) & 7, 3).put(1, 1)
         .put((v >> 15) & 0x7FFF, 15).put(1, 1).put(v & 0x7FFF, 15)
         .put(1, 1).put(ext, 9).put(1, 1))
    return b.bytes()


def pes(sid, payload, flags1=0x80, flags2=0, hdr=b"", length=None):
    body = bytes([flags1, flags2, len(hdr)]) + hdr + payload
    if length is None:
        length = len(body)
    return PFX + bytes([sid]) + struct.pack(">H", length) + body


def pes_plain(sid, payload, length=None):
    if length is None:
        length = len(payload)
    return PFX + bytes([sid]) + struct.pack(">H", length) + payload


def pack_hdr(scr=0x123456789 & 0x1FFFFFFFF, ext=7, rate=25200 // 50,
             stuff=0):
    return (PFX + b"\xba" + clock(scr, ext) +
            struct.pack(">I", (rate << 10) | 0x300 | (0x1F << 3) | stuff)[0:0] +
            bytes([(rate >> 14) & 0xFF, (rate >> 6) & 0xFF,
                   ((rate & 0x3F) << 2) | 3, 0xF8 | stuff]) + b"\xff" * stuff)


def pat():
    body = ext_header(1, 1) + struct.pack(">HH", 1, 0xE000 | 0x1000)
    return section(0x00, body)


def pmt(streams):
    es = b""
    for st, pid, descs in streams:
        es += bytes([st]) + struct.pack(">HH", 0xE000 | pid,
                                         0xF000 | len(descs)) + descs
    body = (struct.pack(">H", 1) + bytes([0xC1, 0, 0]) +
            struct.pack(">HH", 0xE000 | 0x100, 0xF000) + es)
    return section(0x02, body)


def build_main():
    ts = TS()
    pkts = []       # list of lists of TS packets, one list per datagram
    pkts.append(ts.sections(0, [pat()]) +
                ts.sections(0x1000, [pmt([
                    (0x02, 0x100, b""),
                    (0x03, 0x101, b""),
                    (0x1B, 0x102, b""),
                    (0x24, 0x103, descr(0x05, b"HEVC")),
                    (0x06, 0x104, descr(0x05, b"ABCD")),
                    (0x1B, 0x105, b""),
                ])]))

    def add(pid, *pess, pcr=None):
        d = []
        for p in pess:
            d += ts.pes(pid, p, pcr=pcr)
        pkts.append(d)

    es_chain = (seq_header() + seq_ext()[:-1] + gop()[:-1] +
                picture(data=b"\xaa" * 20))
    # sequence header, sequence extension, GOP and picture nested in one
    # video PES packet; PTS and DTS
    add(0x100, pes(0xE0, es_chain, flags2=0xC0,
                   hdr=ts40(3, 900000) + ts40(1, 897000)), pcr=1234567)
    # sequence header with other values; PTS only; load matrices flags
    add(0x100, pes(0xE0, seq_header(1920, 1080, 3, 4, 100, 50, 1, 1, 1) +
                   picture(ftype=2), flags2=0x80, hdr=ts40(2, 90000)))
    # picture frame types as top level elementary streams
    for ft, sid in ((1, 0xE1), (2, 0xE2), (3, 0xE3), (4, 0xE4), (0, 0xE5),
                    (5, 0xE6), (7, 0xE7)):
        add(0x100, pes(sid, picture(ftype=ft, data=bytes(range(10))),
                       flags2=0x80, hdr=ts40(2, 180000 + ft)))
    # a bare picture, GOP and sequence header start codes (no PES header)
    add(0x100, picture(seq=1023, ftype=3, data=b"\x01" * 4),
        gop(1, 23, 59, 59, 29, 0, 1)[:-1] + picture(), seq_header(matrix=True)
        + gop()[:-1] + picture())
    # ES rate, ESCR
    add(0x100, pes(0xE0, picture(), flags2=0x30,
                   hdr=clock(0x1ABCDEF01, 100, 0) + b"\x80\x00\x03"))
    # DSM trick mode, all controls (1-5), the reserved ones too
    for ctl, low in ((0, 0x0F), (1, 0x15), (2, 0x08), (3, 0x1B), (4, 0x03),
                     (5, 0x00), (7, 0x1F)):
        add(0x100, pes(0xE0, picture(), flags2=0x08,
                       hdr=bytes([(ctl << 5) | low])))
    # additional copy info and CRC
    add(0x100, pes(0xE0, picture(), flags2=0x06,
                   hdr=b"\x81" + b"\x12\x34"))
    # every extension: private data, pack length, sequence counter, P-STD
    # buffer (scale 0 and 1), extension 2
    ext = (b"\xf1" + bytes(range(16)) + b"\x2a" + b"\x81\x7f" +
           b"\x60\x80" + b"\x80\x03")
    add(0x100, pes(0xE0, picture(), flags2=0x01, hdr=ext))
    add(0x100, pes(0xE0, picture(), flags2=0x01,
                   hdr=b"\x10" + b"\x40\x20"))
    # every header field together
    add(0x100, pes(0xE0, picture(), flags2=0xFF,
                   hdr=ts40(3, 5) + ts40(1, 4) + clock(77, 3, 0) +
                   b"\x80\x00\x05" + b"\x40" + b"\x01" + b"\x00\x02" +
                   b"\x10" + b"\x41\x00"))
    # PES packet length 0 (unbounded) video, two TS packets, closed by
    # the next PES start
    add(0x100, pes(0xE8, picture(data=b"\x55" * 250), flags2=0x80,
                   hdr=ts40(2, 12345), length=0),
        pes(0xE9, picture(ftype=2), flags2=0x80, hdr=ts40(2, 12346)))
    # audio, with and without a PES header extension; audio frame data
    add(0x101, pes(0xC0, b"\xff\xfb\x90\x64" + b"\x00" * 413, flags2=0x80,
                   hdr=ts40(2, 90000)))
    add(0x101, pes(0xC1, b"\x01\x02\x03\x04", flags2=0x80,
                   hdr=ts40(2, 90001)),
        pes(0xDF, b"data", flags2=0x00))
    # an elementary stream that starts with 0xff but is no audio frame
    add(0x101, pes(0xC3, b"\xff\x00\x00\x00", flags2=0x80,
                   hdr=ts40(2, 5)))
    # private stream 1 with a header, with data
    add(0x101, pes(0xBD, b"\x80\x01\x02\x03", flags2=0x80,
                   hdr=ts40(2, 7)))
    # private stream 1 and audio without the '10' marker: length and data
    add(0x101, pes_plain(0xBD, b"\x0f" + b"abcdefg"),
        pes_plain(0xC2, b"\x00\x11\x22\x33"))
    # stream types from the PMT: H.264 and H.265 byte streams, a
    # registration ID that no dissector claims
    add(0x102, pes(0xE0, b"\x00\x00\x00\x01\x09\xf0", flags2=0x80,
                   hdr=ts40(2, 99)))
    add(0x103, pes(0xE0, b"\x00\x00\x00\x01\x46\x01\x50", flags2=0x80,
                   hdr=ts40(2, 99)))
    add(0x104, pes(0xBD, b"\xff\xfb\x90\x64" + b"\x00" * 413, flags2=0x80,
                   hdr=ts40(2, 99)))
    # system-level streams in a transport stream
    add(0x100, pes_plain(0xBE, b"\xff" * 20),
        pes_plain(0xBF, b"\x01\x02\x03\x04\x05"),
        pes_plain(0xBB, b"\x00\x01\x02\x03"),
        pes_plain(0xBC, b"\x00\x01\x02\x03"))
    add(0x100, pack_hdr(), pack_hdr(stuff=3),
        PFX + b"\xba" + b"\x21\x00\x01\x00\x01\x80\x00\x01" + b"\xff" * 4,
        PFX + b"\xb9", PFX + b"\xb9")
    # a PES packet with a program number with no PMT stream, and another
    # PES carrying a nested PES packet
    add(0x110, pes(0xBD, pes(0xE0, picture(), flags2=0x80,
                             hdr=ts40(2, 1)), flags2=0x80,
                   hdr=ts40(2, 2)))
    frames = []
    for i, d in enumerate(pkts):
        frames.append(udp_frame(b"".join(d), sport=5004,
                                dport=5004))
    return frames


def build_malformed():
    f = []
    # audio PES with length 0: only allowed for video (warning)
    f.append(pes(0xC0, b"\xff\xfb\x90\x64" + b"\x00" * 40, flags2=0x80,
                 hdr=ts40(2, 1), length=0))
    f.append(pes(0xBD, b"abc", flags2=0x80, hdr=ts40(2, 1), length=0))
    # header data length longer than the packet
    f.append(PFX + b"\xe0\x00\x10" + b"\x80\x80\x20" + ts40(2, 1))
    # PTS flag with a short header
    f.append(PFX + b"\xe0\x00\x08" + b"\x80\x80\x03" + b"\x21\x00\x01")
    # all flags, header data too short for the fields
    f.append(PFX + b"\xe0\x00\x10" + b"\x80\xff\x04" + b"\x21\x00\x01\x00\x01"
             + b"\x00" * 6)
    # extension flags with no data behind them
    f.append(PFX + b"\xe0\x00\x08" + b"\x80\x01\x02" + b"\xff\x00" + b"\0" * 3)
    # trick mode flag with an empty header and a CRC flag
    f.append(PFX + b"\xe0\x00\x06" + b"\x80\x0a\x01" + b"\x00\x00")
    # sequence header cut short, GOP cut short, picture cut short,
    # extension cut short
    f.append(PFX + b"\xb3\x2d\x02\x40")
    f.append(PFX + b"\xb8\x00")
    f.append(PFX + b"\x00\x00")
    f.append(PFX + b"\xb5\x14")
    f.append(PFX + b"\xb3" + b"\x2d\x02\x40\x23\xff\xff\xe0\x9c\x00" + b"\0" * 30)
    # frame rate index out of range
    f.append(seq_header(fr=12))
    # pack header cut short; system header, padding, private 2 lengths
    # beyond the data
    f.append(PFX + b"\xba\x44\x00")
    f.append(PFX + b"\xbb\x00\x20\x00")
    f.append(PFX + b"\xbe\x00\x20\x00")
    f.append(PFX + b"\xbf\x01\x00\x00")
    f.append(PFX + b"\xbd\x00\x20\x0f\x01")
    # a very short PES, a PES with an unknown stream id nibble
    f.append(PFX + b"\xe0\x00")
    f.append(PFX[:2])
    # nesting: a private stream whose payload is a PES packet, many times
    nest = pes(0xE0, picture(), flags2=0x80, hdr=ts40(2, 1))
    for _ in range(300):
        nest = pes(0xBD, nest[:60000], flags2=0x80, hdr=ts40(2, 1))
    f.append(nest)
    return [exp_pdu("mpeg-pes", x) for x in f]


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(os.path.join(out, "mpeg-pes-coverage.pcap"), build_main(),
               LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "mpeg-pes-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)
