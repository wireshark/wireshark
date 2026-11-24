#!/usr/bin/env python3
# Helper module for the aprs capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic APRS-over-AX.25 pcaps (linktype 3) for robustness testing. No real traffic."""
import struct
import random
import os

def addr(call, ssid=0, last=False, raw=None):
    if raw is not None:
        b = bytes(raw)
    else:
        b = bytes((ord(c) << 1) for c in call.ljust(6)[:6])
    return b + bytes([0x60 | ((ssid & 0xf) << 1) | (1 if last else 0)])

def frame(info, dst=None, dstraw=None):
    d = addr(dst or "APRS", raw=dstraw)
    s = addr("N0CALL", 1, last=True)
    return d + s + b"\x03\xf0" + info

def pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 3))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

out = os.path.dirname(os.path.abspath(__file__))
fr = []
# Mic-E: every byte value 0..255 in each of the 6 destination address chars
for v in range(256):
    raw = [v] * 6
    for dti in (b"`", b"'", b"\x1c", b"\x1d"):
        fr.append(frame(dti + bytes([(v + k) & 0xff for k in range(8)]) + b"]status", dstraw=raw))
# Mic-E info bytes extreme, short and long
for v in (0, 27, 28, 0x7f, 0x80, 0xff):
    fr.append(frame(b"`" + bytes([v]) * 8, dst="TEST11"))
    fr.append(frame(b"`" + bytes([v]) * 3, dst="TEST11"))
fr.append(frame(b"`" + b"\x7f" * 8 + b"," + b"\xff" * 2000, dst="PPPPPP"))
# Compressed position, all byte values in course/speed/compression fields
for v in range(256):
    b = bytes([v])
    fr.append(frame(b"!/" + b * 8 + b"_" + b + b + b + b"weather" ))
    fr.append(frame(b"=/" + b * 8 + b"\\" + b"{" + b + b + b"12345678"))
    fr.append(frame(b"!\\" + b * 8 + b"@" + b + b + b + b"000/000HC 0000 0000 00000 0000 0000 0000"))
# Item names with high bytes (UTF-8 replacement expansion)
fr.append(frame(b")" + b"\x80" * 9 + b"!" + b"4903.50N/07201.75W>comment"))
fr.append(frame(b")" + b"\xff" * 3 + b"!" + b"4903.50N/07201.75W>comment"))
fr.append(frame(b")ITEM_" + b"4903.50N/07201.75W>comment"))
fr.append(frame(b")" + b"\x00" * 10))
# Uncompressed positions + messages
for msg in (b"D", b"P", b"R", b"T", b"1", b"Z", b""):
    fr.append(frame(b"!4903.50N/07201.75W\\" + msg + b"23/456/789/012"))
    fr.append(frame(b"@092345z4903.50N/07201.75W_" + msg + b"23/456g005t077r000p000P000h50b09900Lxyz"))
# Weather with all key letters at end of buffer
for k in b"csgtrPphblLS#xX":
    fr.append(frame(b"_10090556c220s004g005t077" + bytes([k])))
    fr.append(frame(b"_10090556" + bytes([k])))
# Object, status, misc DTIs with random garbage
rnd = random.Random(46)
dtis = b"\x1c\x1d!#$%&)*+,./:;<=>?@T['_`{}"
for i in range(3000):
    dti = bytes([rnd.choice(dtis)])
    n = rnd.randrange(0, 60)
    fr.append(frame(dti + bytes(rnd.randrange(256) for _ in range(n)),
                    dstraw=[rnd.randrange(256) for _ in range(6)]))
pcap(os.path.join(out, "aprs_fuzz.pcap"), fr)
# Targeted single-packet correctness repros
pcap(os.path.join(out, "aprs_item_utf8.pcap"), [frame(b")" + b"\x80" * 9 + b"!" + b"4903.50N/07201.75W>comment")])
# compressed course 'z' -> (122-33)*4 = 356 degrees; speed '!'
pcap(os.path.join(out, "aprs_cse.pcap"), [frame(b"!/5L!!<*e7>z!T comment")])
# Mic-E APRS101 example-like: course 251 deg: DC=0x20+? build: spd 20kn cse 251
# SP=28+2=30, DC=28+0*10+2=30 ; SE=28+51=79
pcap(os.path.join(out, "aprs_mice_cse.pcap"), [frame(b"`" + bytes([28+112, 28+20, 28+50, 30, 30, 79]) + b">/", dst="S32U6T")])
