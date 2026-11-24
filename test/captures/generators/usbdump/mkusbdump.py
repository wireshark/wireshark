#!/usr/bin/env python3
# Generates the usbdump captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the FreeBSD usbdump file reader (plugins/wiretap/usbdump).

Usage: mkusbdump.py <outdir>
Writes
  usbdump_coverage.usbdump.gz     main capture: two multiframes, record headers of
                                  18 and 28 bytes, alignments 1, 4 and 8
  usbdump_hugecaplen.usbdump      caplen 0xfffffff0 (must be rejected with an error)
  usbdump-bad-*.usbdump           other malformed files, only for the coverage number
"""
import gzip
import os
import struct
import sys

MAGIC = struct.pack("<I", 0x9a90000e)


def file_header(version=3):
    return MAGIC + struct.pack(">H", version) + b"\0" * 26


def rec(data, hdrlen=18, align=4, ts=0, caplen=None, extra_pad=b"\xaa"):
    """One bpf record: header, data, alignment padding."""
    if caplen is None:
        caplen = len(data)
    h = struct.pack("<IIIIBB", 1700000000 + ts, ts * 1000, caplen, len(data), hdrlen, align)
    if hdrlen > 18:
        h += (extra_pad * (hdrlen - 18))[:hdrlen - 18]
    out = h + data
    pad = align - ((hdrlen + caplen) & (align - 1))
    if pad < align:
        out += b"\0" * pad
    return out


def multiframe(*records):
    body = b"".join(records)
    return struct.pack("<I", len(body)) + body


# --- usbpf (FreeBSD) USB pseudo header, 128 bytes, then frames -----------
CONTROL, ISOC, BULK, INTR = 0, 1, 2, 3
SUBMIT, COMPLETE = 0, 1
ST_CONTROL_HDR = 0x100


def usbpf(urb_type, xfer, frames, endpoint=0x80, addr=2, status=0, bus=0,
          speed=3, interval=0):
    """frames: list of (flags, data); the frame length field is len(data)."""
    h = struct.pack("<IIBBBB", 0, bus, addr, 0, urb_type, xfer)
    h += struct.pack("<IIIIIII", 0, status, 0, interval, len(frames), 64, 1)
    h += struct.pack("<BBBB", endpoint, 0, 0, 0)[:1] + struct.pack("<B", speed)
    h = h.ljust(128, b"\0")
    body = b""
    for flags, data in frames:
        body += struct.pack("<II", len(data), flags)
        if flags & 2:
            body += data + b"\0" * ((-len(data)) % 4)
    out = h + body
    return struct.pack("<I", len(out)) + out[4:]


DATA_FOLLOWS, READ = 2, 1
SETUP_GET_DEV = bytes([0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00])
DEV_DESC = bytes([18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x86, 0x80, 0x3a, 0x00,
                  0x00, 0x01, 1, 2, 3, 1])


def main(outdir):
    r = []
    # URBs
    r.append(usbpf(SUBMIT, CONTROL, [(DATA_FOLLOWS, SETUP_GET_DEV)], status=ST_CONTROL_HDR))
    r.append(usbpf(COMPLETE, CONTROL, [(0, b""), (DATA_FOLLOWS | READ, DEV_DESC)]))
    r.append(usbpf(SUBMIT, BULK, [(DATA_FOLLOWS, b"hello usb")], endpoint=0x02))
    r.append(usbpf(COMPLETE, BULK, [(DATA_FOLLOWS | READ, b"0123456789abcdef")], endpoint=0x81))
    r.append(usbpf(SUBMIT, INTR, [(0, b"")], endpoint=0x83, interval=8))
    r.append(usbpf(COMPLETE, INTR, [(DATA_FOLLOWS | READ, bytes([1, 2, 3, 4]))], endpoint=0x83, interval=8))
    # multiframe 1: header 18/align 4, header 28 (10 bytes of padding)/align 8,
    # header 18/align 1 (no padding), header 18/align 4 again
    mf1 = multiframe(rec(r[0], 18, 4, 1), rec(r[1], 28, 8, 2), rec(r[2], 18, 1, 3),
                     rec(r[3], 18, 4, 4))
    # multiframe 2 (the size field after the first one is read at its end)
    mf2 = multiframe(rec(r[4], 28, 4, 5), rec(r[5], 18, 8, 6))
    main_file = file_header() + mf1 + mf2
    with gzip.GzipFile(os.path.join(outdir, "usbdump_coverage.usbdump.gz"), "wb",
                       mtime=0, compresslevel=9) as f:
        f.write(main_file)

    # caplen 0xfffffff0 (review finding: unbounded allocation); the first
    # record is fine
    ok = rec(r[2], 18, 4, 1)
    huge = rec(b"\0" * 16, 18, 4, 2, caplen=0xfffffff0)
    body = ok + huge
    with open(os.path.join(outdir, "usbdump_hugecaplen.usbdump"), "wb") as f:
        f.write(file_header() + struct.pack("<I", len(body)) + body)

    def w(name, data):
        with open(os.path.join(outdir, "usbdump-bad-%s.usbdump" % name), "wb") as f:
            f.write(data)

    w("version", file_header(4) + mf1)                     # version 0.4
    w("notusb", b"x" * 64)                                 # wrong magic
    w("tiny", b"\x0e\x00")                                 # shorter than the magic
    w("magiconly", MAGIC)                                  # no version
    w("magicver", MAGIC + b"\x00")                         # half a version
    w("shorthdr", file_header()[:20])                      # cut inside the header
    w("shortmf", file_header()[:34])                       # no multiframe size
    w("overrun", file_header() + struct.pack("<I", 20) + rec(r[2], 18, 4, 1))  # multiframe too small
    w("overrun2", file_header() + struct.pack("<I", 40) + rec(r[2], 18, 4, 1)) # header fits, data not
    w("overrun3", file_header() + struct.pack("<I", 18 + len(r[2])) + rec(r[2], 18, 4, 1)) # padding does not fit
    w("trailing", file_header() + mf1 + b"\x01\x02")       # short next multiframe size
    w("cutdata", (file_header() + mf1)[:-6])               # record cut short
    w("cuthdr", (file_header() + mf1)[:60])                # record header cut short
    w("cutpad", file_header() + struct.pack("<I", 18 + len(r[2]) + 4) + rec(r[2], 18, 4, 1)[:-2])
    w("cuthdrpad", file_header() + struct.pack("<I", 28) + rec(r[2], 28, 4, 1)[:24])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
