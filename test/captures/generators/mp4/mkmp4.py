#!/usr/bin/env python3
# Generates test/captures/mp4_coverage.mp4.gz, mp4_coverage_http.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic MP4 / ISOBMFF coverage files (Python struct only).
usage: mkmp4.py <outdir>
  mp4_coverage.mp4          main file: ftyp, moov with two tracks, moof, sidx, styp ...
  mp4_coverage_http.pcap    HTTP responses with video/mp4 and audio/mp4 bodies (the media types),
                            the reproducer of the ctts fix, the timescale reset, expert-info cases
  mp4_coverage_malformed.pcap  truncated and odd boxes (coverage only)
"""
import os
import struct
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(out, exist_ok=True)


def box(t, body=b"", large=False):
    if large:
        return struct.pack(">I4sQ", 1, t, 16 + len(body)) + body
    return struct.pack(">I4s", 8 + len(body), t) + body


def full(t, ver=0, flags=0, body=b"", large=False):
    return box(t, struct.pack(">I", (ver << 24) | flags) + body, large)


def mvhd(ver=0, timescale=1000, duration=5000, next_tid=3, rate=(1, 5), vol=(1, 25)):
    t = struct.pack(">II", 3_000_000_000, 3_000_000_100) if ver == 0 else struct.pack(">QQ", 3_000_000_000, 3_000_000_100)
    d = struct.pack(">I" if ver == 0 else ">Q", duration)
    return full(b"mvhd", ver, 0, t + struct.pack(">I", timescale) + d + struct.pack(">HH", *rate) +
                struct.pack(">BB", *vol) + b"\0" * 2 + b"\0" * 8 + b"\0" * 36 + b"\0" * 24 + struct.pack(">I", next_tid))


def tkhd(ver=0, flags=7, track=1, duration=5000, w=(640, 5), h=(480, 25)):
    t = struct.pack(">II", 3_000_000_000, 3_000_000_100) if ver == 0 else struct.pack(">QQ", 3_000_000_000, 3_000_000_100)
    d = struct.pack(">I" if ver == 0 else ">Q", duration)
    return full(b"tkhd", ver, flags, t + struct.pack(">I", track) + b"\0" * 4 + d + b"\0" * 8 + b"\0" * 2 * 4 +
                b"\0" * 36 + struct.pack(">HHHH", *w, *h))


def hdlr(kind=b"vide", name=b"VideoHandler"):
    return full(b"hdlr", 0, 0, b"\0" * 4 + kind + b"\0" * 12 + name + b"\0")


def stts(entries):
    return full(b"stts", 0, 0, struct.pack(">I", len(entries)) + b"".join(struct.pack(">II", *e) for e in entries))


def ctts(ver, entries):
    fmt = ">Ii" if ver == 1 else ">II"
    return full(b"ctts", ver, 0, struct.pack(">I", len(entries)) + b"".join(struct.pack(fmt, *e) for e in entries))


def stsz(size, count, entries=()):
    return full(b"stsz", 0, 0, struct.pack(">II", size, count) + b"".join(struct.pack(">I", e) for e in entries))


def stsc(entries):
    return full(b"stsc", 0, 0, struct.pack(">I", len(entries)) + b"".join(struct.pack(">III", *e) for e in entries))


def stco(offs):
    return full(b"stco", 0, 0, struct.pack(">I", len(offs)) + b"".join(struct.pack(">I", o) for o in offs))


def elst(ver, entries):
    out_ = struct.pack(">I", len(entries))
    for e in entries:
        if ver == 1:
            out_ += struct.pack(">QqHH", *e)
        else:
            out_ += struct.pack(">IIHH", *e)
    return full(b"elst", ver, 0, out_)


def sidx(ver, entries, ref=1, ts=90000, ept=0, fo=0):
    if ver == 0:
        b = struct.pack(">IIII", ref, ts, ept, fo)
    else:
        b = struct.pack(">IIQQ", ref, ts, ept, fo)
    b += struct.pack(">HH", 0, len(entries))
    for typ, size, dur, sap, st, delta in entries:
        b += struct.pack(">III", (typ << 31) | size, dur, (sap << 31) | (st << 28) | delta)
    return full(b"sidx", ver, 0, b)


def ftyp(t=b"ftyp", brand=b"isom", ver=0x200, compat=(b"isom", b"iso2", b"avc1", b"mp41")):
    return box(t, brand + struct.pack(">I", ver) + b"".join(compat))


def dref(n_url=2):
    ents = full(b"url ", 0, 1) + full(b"url ", 0, 0, b"http://example.invalid/media\0")
    return full(b"dref", 0, 0, struct.pack(">I", 2) + ents)


def stsd(entries):
    return full(b"stsd", 0, 0, struct.pack(">I", len(entries)) + b"".join(entries))


# main file ---------------------------------------------------------------------------
sample_entry_video = box(b"avc1", b"\0" * 6 + struct.pack(">H", 1) + b"\0" * 70)
sample_entry_audio = box(b"mp4a", b"\0" * 6 + struct.pack(">H", 1) + b"\0" * 20)

video_stbl = box(b"stbl",
                 stsd([sample_entry_video, sample_entry_audio]) +
                 stts([(10, 100), (5, 200)]) +
                 ctts(0, [(10, 0), (5, 50)]) +
                 stsz(1000, 15) +
                 stsc([(1, 5, 1), (3, 3, 1)]) +
                 stco([1000, 6000, 11000]) +
                 box(b"stss", b"\0" * 8))
video_trak = box(b"trak",
                 tkhd(0, 7, 1) +
                 box(b"edts", elst(0, [(5000, 0, 1, 5), (1000, 4294967295, 1, 0)]) + elst(1, [(5000, 0, 2, 50)])) +
                 box(b"mdia", full(b"mdhd", 0, 0, b"\0" * 20) + hdlr(b"vide", b"VideoHandler") +
                     box(b"minf", full(b"vmhd", 0, 1, b"\0" * 8) +
                         box(b"dinf", dref()) + video_stbl)))
audio_stbl = box(b"stbl",
                 stsd([sample_entry_audio]) +
                 stts([(100, 1024)]) +
                 ctts(1, [(3, -5), (2, 7)]) +                      # the reproducer of the ctts fix
                 stsz(0, 4, [100, 200, 300, 400]) +
                 full(b"stz2", 0, 0, b"\0" * 8) +
                 stsc([(1, 4, 1)]) +
                 stco([2000]))
audio_trak = box(b"trak",
                 tkhd(1, 3, 2, 123456) +
                 box(b"mdia", hdlr(b"soun", b"") + box(b"minf", full(b"smhd", 0, 0, b"\0" * 4) + audio_stbl)))
moov = box(b"moov", mvhd(0) + video_trak + audio_trak +
           box(b"mvex", full(b"mehd", 0, 0, struct.pack(">I", 5000)) + full(b"trex", 0, 0, b"\0" * 20)) +
           box(b"udta", box(b"meta", b"\0" * 8) + box(b"xxxx", b"")))
# a second movie header: version 1 (64-bit times), no known next track id
moov2 = box(b"moov", mvhd(1, 90000, 1 << 33, 0xFFFFFFFF) +
            box(b"trak", box(b"edts", elst(1, [(1 << 33, 0, 1, 0), (90000, 90000, 0, 5)]))))
# a third with a zero timescale
moov3 = box(b"moov", mvhd(0, 0, 100, rate=(2, 0), vol=(0, 0)) +
            box(b"trak", box(b"edts", elst(0, [(100, 0, 1, 0)]))))
mdat = box(b"mdat", bytes(range(64)))
moof = box(b"moof", full(b"mfhd", 0, 0, struct.pack(">I", 7)) +
           box(b"traf", full(b"tfhd", 0, 0x20000, struct.pack(">II", 1, 0)) + full(b"trun", 0, 0x201, struct.pack(">II", 1, 0))))
sidx0 = sidx(0, [(0, 1000, 90000, 1, 1, 0), (1, 2000, 45000, 0, 2, 5)])
sidx1 = sidx(1, [(0, 3000, 90000, 1, 3, 0x0FFFFFFF)], ref=2, ept=1 << 33, fo=77)
styp = ftyp(b"styp", b"msdh", 0, (b"msdh", b"msix"))
large = box(b"free", b"\0" * 20, large=True)             # a box with the 64-bit largesize
nested = box(b"udta", box(b"udta", box(b"udta", full(b"hdlr", 0, 0, b"\0" * 4 + b"text" + b"\0" * 12 + b"T\0"))))
main = (ftyp() + moov + moov2 + moov3 + mdat + moof + sidx0 + sidx1 + styp + large + nested + box(b"free", b""))
open(os.path.join(out, "mp4_coverage.mp4"), "wb").write(main)


# HTTP pcap --------------------------------------------------------------------------
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []
        self.n = 0

    def http(self, data, ctype=b"video/mp4", url=b"/f.mp4"):
        self.n += 1
        sport = 40000 + self.n
        ct = (b"Content-Type: " + ctype + b"\r\n") if ctype else b""
        req = b"GET " + url + b" HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
        resp = (b"HTTP/1.1 200 OK\r\n" + ct + b"Content-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
        c, s = bytes([192, 0, 2, 2]), bytes([192, 0, 2, 1])
        self.frames.append(self.pkt(c, s, sport, 80, 1, 1, req))
        self.frames.append(self.pkt(s, c, 80, sport, 1, 1 + len(req), resp))

    @staticmethod
    def pkt(src, dst, sp, dp, seq, ack, payload):
        tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 0x50, 0x18, 65535, 0, 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        mac = lambda x: b"\x02\0\0\0\0" + bytes([x])
        return (mac(2 if src[3] == 1 else 1) + mac(1 if src[3] == 1 else 2) + b"\x08\x00" + ip + tcp)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack("<IIII", 1794659420 + i, 0, len(fr), len(fr)) + fr)


ctts_v1 = ftyp() + box(b"moov", box(b"trak", box(b"mdia", box(b"minf", box(b"stbl", ctts(1, [(1, -5), (2, 7)]))))))
only_elst = box(b"moov", box(b"trak", box(b"edts", elst(0, [(100, 50, 1, 0)]))))
deep = b"".join(struct.pack(">I4s", 0, b"udta") for _ in ())  # placeholder, built below


def nest(n, inner):
    for _ in range(n):
        inner = box(b"udta", inner)
    return inner


p = Pcap()
p.http(main, b"video/mp4", b"/movie.mp4")                          # the main file, video/mp4
p.http(styp + sidx0 + moof + mdat, b"audio/mp4", b"/seg.m4s")        # fragment, audio/mp4
p.http(box(b"moov", mvhd(0, 1000, 5000) + box(b"trak", box(b"edts", elst(0, [(1000, 0, 1, 0)])))),
       b"video/mp4", b"/a.mp4")                                    # timescale 1000
p.http(only_elst, b"video/mp4", b"/b.mp4")                         # no mvhd: no timescale (reset per file)
p.http(ctts_v1, b"video/mp4", b"/ctts.mp4")                        # reproducer: ctts version 1
p.http(ftyp() + nest(25, box(b"free", b"")), b"video/mp4", b"/deep.mp4")   # recursion limit
p.http(ftyp() + struct.pack(">I4sQ", 1, b"free", 1 << 40) + b"\0" * 8, b"video/mp4", b"/huge.mp4")  # box too large
p.http(ftyp() + struct.pack(">I4s", 4, b"free") + b"\0" * 8, b"video/mp4", b"/small.mp4")      # size below 8
p.http(ftyp() + struct.pack(">I4s", 0, b"mdat") + b"\0" * 16, b"video/mp4", b"/zero.mp4")        # size 0
p.http(b"\0\0\0\x10junk" + b"\0" * 8, b"video/mp4", b"/junk.mp4")                                 # not an MP4: unknown type
p.write(os.path.join(out, "mp4_coverage_http.pcap"))

# Malformed -----------------------------------------------------------------------------
m = Pcap()
m.http(ftyp() + full(b"mvhd", 0, 0, b"\0" * 10) , b"video/mp4")                  # truncated mvhd
m.http(box(b"moov", full(b"stsz", 0, 0, struct.pack(">II", 0, 100))), b"video/mp4")  # missing entries
m.http(box(b"moov", full(b"stco", 0, 0, struct.pack(">I", 1000))), b"video/mp4")
m.http(box(b"moov", full(b"stts", 0, 0, struct.pack(">I", 1000))), b"video/mp4")
m.http(box(b"moov", full(b"ctts", 0, 0, struct.pack(">I", 1000))), b"video/mp4")
m.http(box(b"moov", full(b"stsc", 0, 0, struct.pack(">I", 1000))), b"video/mp4")
m.http(box(b"moov", full(b"elst", 1, 0, struct.pack(">I", 1000))), b"video/mp4")
m.http(box(b"moov", full(b"sidx", 0, 0, struct.pack(">IIIIHH", 1, 1, 0, 0, 0, 500))), b"video/mp4")
m.http(box(b"moov", full(b"hdlr", 0, 0, b"\0" * 20 + b"name-without-nul")), b"video/mp4")
m.http(box(b"moov", full(b"dref", 0, 0, struct.pack(">I", 50) + box(b"free", b""))), b"video/mp4")
m.http(box(b"moov", full(b"stsd", 0, 0, struct.pack(">I", 50) + box(b"free", b""))), b"video/mp4")
m.http(box(b"moov", full(b"tkhd", 1, 0, b"\0" * 20)), b"video/mp4")
m.http(box(b"moov", full(b"dref", 0, 0, struct.pack(">I", 2) + struct.pack(">I4s", 4, b"url "))), b"video/mp4")   # entry size below 8
m.http(box(b"moov", full(b"stsd", 0, 0, struct.pack(">I", 2) + struct.pack(">I4s", 4, b"avc1"))), b"video/mp4")
m.http(b"\0\0\0\0", b"video/mp4")                                                    # shorter than a box header
m.http(ftyp()[:-2], b"video/mp4")
m.http(struct.pack(">I4s", 12, b"moov") + b"\0\0", b"video/mp4")                  # box larger than the data
m.http(struct.pack(">I4s", 8, b"moov"), b"video/mp4")                              # empty container
m.http(box(b"moov", box(b"trak", struct.pack(">I4s", 100, b"free"))), b"video/mp4")  # child past the parent
m.write(os.path.join(out, "mp4_coverage_malformed.pcap"))
print(len(main))
