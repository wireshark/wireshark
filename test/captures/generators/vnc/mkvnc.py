#!/usr/bin/env python3
# Generates test/captures/vnc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic VNC (RFB) captures for packet-vnc.c.

Usage: mkvnc.py <outdir> [-v]
Writes vnc-coverage.pcap (main capture, no malformed packets or error
expert infos), vnc-coverage-malformed.pcap (paths only malformed input
reaches) and the reproducers of the fixes on the branch.
Everything is built with struct; addresses are from 192.0.2.0/24.
"""
import os
import struct
import sys
import zlib

from netlib import Net, Flow

CIP = (192, 0, 2, 10)
SIP = (192, 0, 2, 20)

# Encoding numbers
RAW, COPYRECT, RRE, CORRE, HEXTILE, ZLIBE, TIGHT, ZLIBHEX, ULTRA = 0, 1, 2, 4, 5, 6, 7, 8, 9
ZRLE = 16
H264 = 0x48323634
EXTCLIP = 0xC0A1E5CE
LASTRECT = 0xFFFFFF20
DESKTOPSIZE = 0xFFFFFF21
POINTERPOS = 0xFFFFFF18
RICHCURSOR = 0xFFFFFF11
XCURSOR = 0xFFFFFF10
EXTDESK = (-308) & 0xffffffff
KBDLED = 0xFFFE0000
SUPMSGS = 0xFFFE0001
SUPENCS = 0xFFFE0002
SRVIDENT = 0xFFFE0003
CONTEXTINFO = 0xFFFFFDF4
SLRLE = 0xFFFFFDF3


def pf(bpp, depth, big=0, true=1, rmax=255, gmax=255, bmax=255, rs=16, gs=8, bs=0):
    return struct.pack('>BBBBHHHBBB3x', bpp, depth, big, true, rmax, gmax, bmax, rs, gs, bs)


PF32 = pf(32, 24)
PF16 = pf(16, 16, 0, 1, 31, 63, 31, 11, 5, 0)
PF8 = pf(8, 8, 0, 1, 7, 7, 3, 0, 3, 6)


def server_init(w, h, fmt, name=b'synthetic desktop'):
    return struct.pack('>HH', w, h) + fmt + (struct.pack('>I', len(name)) + name if name is not None else b'')


# client messages
def c_setpf(fmt):
    return b'\x00\x00\x00\x00' + fmt


def c_setenc(*encs):
    return struct.pack('>BxH', 2, len(encs)) + b''.join(struct.pack('>I', e & 0xffffffff) for e in encs)


def c_fbreq(inc, x, y, w, h):
    return struct.pack('>BBHHHH', 3, inc, x, y, w, h)


def c_key(down, key):
    return struct.pack('>BB2xI', 4, down, key)


def c_pointer(mask, x, y):
    return struct.pack('>BBHH', 5, mask, x, y)


def c_cuttext(text):
    return struct.pack('>B3xI', 6, len(text)) + text


def c_cuttext_ext(flags, caps=(), values=(), compress=True, raw_len=None):
    """Extended clipboard (negative length). values are the already built
    uncompressed value bytes (4 octet length + data each)."""
    body = struct.pack('>I', flags) + b''.join(struct.pack('>I', c) for c in caps)
    if values:
        data = b''.join(struct.pack('>I', len(v)) + v for v in values)
        body += zlib.compress(data) if compress else data
    n = -len(body) if raw_len is None else raw_len
    return struct.pack('>B3xi', 6, n) + body


def c_ml(t, payload=b''):
    return struct.pack('>BBH', 128, t, len(payload)) + payload


def c_contupd(en, x, y, w, h):
    return struct.pack('>BBHHHH', 150, en, x, y, w, h)


def msg_fence(t, flags, payload=b''):
    return struct.pack('>B3xIB', t, flags, len(payload)) + payload


def c_qemu_key(down, keysym, keycode):
    return struct.pack('>BBHII', 255, 0, down, keysym, keycode)


# server messages
def rect(x, y, w, h, enc):
    return struct.pack('>HHHHI', x, y, w, h, enc & 0xffffffff)


def fbupdate(*rects, n=None):
    return struct.pack('>BxH', 0, len(rects) if n is None else n) + b''.join(rects)


def s_colormap(first, entries):
    return struct.pack('>BxHH', 1, first, len(entries)) + b''.join(struct.pack('>HHH', *e) for e in entries)


def cm(first, entries):
    """SetColourMapEntries followed by three bell messages: the dissector asks
    for three more octets after a complete colour map (see README)."""
    return s_colormap(first, entries) + b'\x02\x02\x02'


def s_cuttext(text):
    return struct.pack('>B3xI', 3, len(text)) + text


def s_ml(t, payload=b''):
    return struct.pack('>BBH', 128, t, len(payload)) + payload


def px(n, bpp=4, seed=0):
    return bytes(((i * 7 + seed) & 0xff) | 1 for i in range(n * bpp))


def compact(n):
    """Compact length: 1, 2 or 3 octets."""
    if n < 128:
        return bytes([n])
    if n < 16384:
        return bytes([(n & 0x7f) | 0x80, n >> 7])
    return bytes([(n & 0x7f) | 0x80, ((n >> 7) & 0x7f) | 0x80, n >> 14])


# ML payloads
ML = {
    1: struct.pack('>BBHHHI', 1, 2, 0x0102, 800, 480, 0x00000020),
    2: struct.pack('>BBHHHHHH', 1, 1, 3, 800, 480, 200, 120, 600),
    3: b'enUSdeDE' + struct.pack('>5I', 0x1, 0x2, 0x3, 0x4, 0x5),
    4: b'frFRitIT' + struct.pack('>5I', 0x10, 0x20, 0x30, 0x40, 0x50),
    5: struct.pack('>II', 0xffe1, 0x10003),
    6: struct.pack('>II', 0xffe2, 0x10004),
    7: struct.pack('>BBH', 1, 3, 77) + struct.pack('>3I', 0x20, 0x21, 0x22),
    8: struct.pack('>I', 1),
    9: struct.pack('>I6H', 2, 10, 20, 30, 40, 50, 60),
    10: struct.pack('>I', 3),
    11: struct.pack('>I', 0x0f),
    12: struct.pack('>I', 0x0e),
    16: struct.pack('>4HIH', 1, 2, 3, 4, 0x1001, 5),
    18: struct.pack('>IH', 0x1002, 6),
    20: bytes([3]) + struct.pack('>HHBB', 1, 2, 3, 4) + struct.pack('>HHBB', 5, 6, 7, 8) + struct.pack('>HHBB', 9, 10, 11, 12),
    21: struct.pack('>IH', 0x1003, 5) + b'Hello',
    22: struct.pack('>H', 40),
}


def hextile(w, h, bpp, tiles):
    """tiles: list of (mask, data) in row-major order."""
    out = b''
    for mask, data in tiles:
        out += bytes([mask]) + data
    return out


# --------------------------------------------------------------------------
# Session builders
def start(net, cport, ver_s=b'RFB 003.008\n', ver_c=b'RFB 003.008\n', sport=5900):
    f = Flow(net, CIP, cport, SIP, sport, 1, 2)
    f.handshake()
    f.send(1, ver_s)
    f.send(0, ver_c)
    return f


def std_session(net, cport, fmt=PF32, w=64, h=48, sport=5900, ver=b'RFB 003.008\n', name=b'synthetic desktop'):
    """3.8, None security, up to ServerInit."""
    f = start(net, cport, ver, ver, sport)
    f.send(1, b'\x01\x01')
    f.send(0, b'\x01')
    f.send(1, struct.pack('>I', 0))
    f.send(0, b'\x01')
    f.send(1, server_init(w, h, fmt, name))
    return f


def build_main(net, verbose):
    # ---------------------------------------------------------------------
    net.mark('Session 1 (3.8, None): startup')
    f = start(net, 40001)
    f.send(1, bytes([10, 1, 2, 5, 6, 16, 17, 18, 19, 20, 30]))   # security types
    f.send(0, b'\x01')
    f.send(1, struct.pack('>I', 0))
    f.send(0, b'\x01')
    f.send(1, server_init(64, 48, PF32))

    net.mark('Session 1: client messages')
    f.send(0, c_fbreq(0, 0, 0, 64, 48))
    f.send(0, c_setpf(PF32))
    f.send(0, c_cuttext(b'plain clipboard text'))
    for first in (RAW, RRE, CORRE, HEXTILE, ZLIBE, TIGHT, 1, 0x12345678):
        f.send(0, c_setenc(0xFFFFFF21, first, 0xFFFFFF11, 0xFFFFFF18))
    f.send(0, c_setenc())                                          # no encodings
    f.send(0, c_fbreq(1, 4, 8, 16, 16))
    f.send(0, c_key(1, 0xff0d))
    f.send(0, c_key(0, 0x0041))
    f.send(0, c_pointer(0x01, 10, 20))
    f.send(0, c_pointer(0xff, 65535, 0))
    f.send(0, c_contupd(1, 0, 0, 64, 48))
    f.send(0, msg_fence(248, 0x80000003, b'fence'))
    f.send(0, msg_fence(248, 0x0, b''))
    f.send(0, c_qemu_key(1, 0x61, 0x1e))
    f.send(0, struct.pack('>BB', 255, 9) + b'\x00' * 8)          # unknown QEMU subtype
    f.send(0, bytes([7, 0, 0, 0]))                                # unknown client message
    f.send(0, bytes([250, 0, 0, 0]))                              # Xvp (listed but not decoded)

    net.mark('Session 1: client MirrorLink')
    f.send(0, c_ml(0))
    f.send(0, c_ml(0, b'xx'))                                       # ByeBye with extra data
    for t in (2, 4, 6, 8, 10, 12, 22, 21):
        f.send(0, c_ml(t, ML[t]))
    f.send(0, c_ml(13))
    f.send(0, c_ml(14, b'\x01\x02\x03'))
    f.send(0, c_ml(99, b'\xaa\xbb'))

    # ---------------------------------------------------------------------
    net.mark('Session 1: server messages')
    # The FramebufferUpdate with every plain encoding; one message per segment
    f.send(1, fbupdate(rect(0, 0, 2, 2, RAW)[:] + px(4)))
    f.send(1, fbupdate(rect(0, 0, 8, 8, COPYRECT) + struct.pack('>HH', 16, 16)))
    # RRE: 2 subrects
    rre = struct.pack('>I', 2) + b'\x01\x02\x03\x04' + (b'\x05\x06\x07\x08' + struct.pack('>HHHH', 1, 2, 3, 4)) * 2
    f.send(1, fbupdate(rect(0, 0, 16, 16, RRE) + rre))
    f.send(1, fbupdate(rect(0, 0, 16, 16, RRE) + struct.pack('>I', 0) + b'\x01\x02\x03\x04'))
    # Hextile 17x17 (four tiles of different sizes)
    ht = hextile(17, 17, 4, [
        (0x01, px(256)),                                              # raw 16x16
        (0x02 | 0x04 | 0x08, b'\x01\x02\x03\x04' + b'\x05\x06\x07\x08' + bytes([2]) + b'\x12\x34\x56\x78'),
        (0x02 | 0x08 | 0x10, b'\x01\x02\x03\x04' + bytes([1]) + b'\x09\x0a\x0b\x0c' + b'\x11\x22'),
        (0x00, b''),
    ])
    f.send(1, fbupdate(rect(0, 0, 17, 17, HEXTILE) + ht))
    # LastRect after a rect, with a bigger rect count
    f.send(1, fbupdate(rect(1, 1, 1, 1, RAW) + px(1), rect(0, 0, 0, 0, LASTRECT), n=0xffff))
    f.send(1, fbupdate(rect(0, 0, 0, 0, LASTRECT), n=3))
    # Pseudo encodings and encodings without payload
    f.send(1, fbupdate(rect(5, 6, 0, 0, POINTERPOS), rect(0, 0, 100, 80, DESKTOPSIZE),
                       rect(0, 0, 0, 0, KBDLED), rect(0, 0, 0, 0, 0x12345678)))
    f.send(1, fbupdate(rect(0, 0, 100, 80, EXTDESK) + bytes([2, 0, 0, 0]) +
                       struct.pack('>IHHHHI', 1, 0, 0, 50, 80, 0) + struct.pack('>IHHHHI', 2, 50, 0, 50, 80, 1)))
    f.send(1, fbupdate(rect(0, 0, 100, 80, EXTDESK) + bytes([0, 0, 0, 0])))
    f.send(1, fbupdate(rect(3, 4, 2, 2, RICHCURSOR) + px(4) + b'\xc0\xc0'))
    f.send(1, fbupdate(rect(3, 4, 9, 2, XCURSOR) + b'\x00\x00\x00\xff\xff\xff' + b'\xaa' * 4 + b'\x55' * 4))
    f.send(1, fbupdate(rect(0, 0, 64, 0, SUPMSGS) + b'\xff' * 32 + b'\x0f' * 32))
    f.send(1, fbupdate(rect(0, 0, 70, 0, SUPMSGS) + b'\xff' * 32 + b'\x0f' * 32 + b'\x00' * 6))
    f.send(1, fbupdate(rect(0, 0, 10, 0, SUPMSGS) + b'\xff' * 10))
    f.send(1, fbupdate(rect(0, 0, 10, 2, SUPENCS) + struct.pack('>II', 0, 5) + b'ab'))
    f.send(1, fbupdate(rect(0, 0, 6, 0, SRVIDENT) + b'VNCsrv'))
    f.send(1, fbupdate(rect(0, 0, 0, 0, CONTEXTINFO) + struct.pack('>IHHIII', 0x1004, 1, 2, 3, 4, 5)))
    # SLRLE: depth 24 -> 4 octets per run, 2 scanlines
    f.send(1, fbupdate(rect(0, 0, 8, 2, SLRLE) + struct.pack('>H', 2) + b'\x01' * 8 + struct.pack('>H', 0)))
    f.send(1, fbupdate(rect(0, 0, 32, 24, H264) + struct.pack('>IIII', 6, 2, 32, 24) + b'\x00\x00\x01\x65\x88\x80'))
    f.send(1, fbupdate(rect(0, 0, 32, 24, H264) + struct.pack('>IIII', 0, 0, 32, 24)))
    # several rectangles of different encodings in one update
    f.send(1, fbupdate(rect(0, 0, 1, 1, RAW) + px(1), rect(1, 1, 8, 8, COPYRECT) + b'\x00\x01\x00\x02',
                       rect(2, 2, 0, 0, POINTERPOS)))
    # ZRLE: raw subencoding (1x1), palette subencoding, other subencoding
    for sub in (b'\x00' + b'\x11\x22\x33\x44', bytes([130]) + b'\x01\x02\x03\x04\x05\x06\x07\x08', b'\x01\x77\x88\x99'):
        z = zlib.compress(sub)
        w, h = (1, 1) if sub[0] == 0 else (4, 4)
        f.send(1, fbupdate(rect(0, 0, w, h, ZRLE) + struct.pack('>I', len(z)) + z))
    # Tight at depth 24: fill, jpeg (compact lengths 1, 2, 3 octets), basic encodings
    t = []
    t.append(rect(0, 0, 4, 4, TIGHT) + b'\x80' + b'\x10\x20\x30')                         # fill
    t.append(rect(0, 0, 4, 4, TIGHT) + b'\x8f' + b'\x10\x20\x30')                         # fill, reset bits
    t.append(rect(0, 0, 4, 4, TIGHT) + b'\x90' + compact(5) + b'JFIF!')                    # jpeg 1 octet length
    t.append(rect(0, 0, 4, 4, TIGHT) + b'\x90' + compact(200) + b'J' * 200)                # 2 octet length
    t.append(rect(0, 0, 1, 1, TIGHT) + b'\x00' + b'\x01\x02\x03')                          # basic, no filter, small
    t.append(rect(0, 0, 1, 3, TIGHT) + b'\x40\x00' + b'\x01' * 9)                          # explicit copy filter, 9 octets
    t.append(rect(0, 0, 2, 2, TIGHT) + b'\x60\x00' + compact(9) + zlib.compress(b'x' * 16)[:9])  # compressed, stream 2? filter
    t.append(rect(0, 0, 8, 2, TIGHT) + b'\x40\x01\x01' + b'\x00\x00\x00\xff\xff\xff' + b'\xa5\x5a')  # palette 2 colours
    t.append(rect(0, 0, 4, 4, TIGHT) + b'\x41\x01\x03' + b'\x01' * 12 + compact(6) + b'abcdef')   # palette 4 colours, compressed
    t.append(rect(0, 0, 1, 1, TIGHT) + b'\x40\x01\x00' + b'\x01\x02\x03')                  # palette count byte 0 -> no palette
    t.append(rect(0, 0, 1, 1, TIGHT) + b'\x40\x01\xff' + b'\x01\x02\x03')                  # palette byte 255 wraps
    t.append(rect(0, 0, 1, 3, TIGHT) + b'\x40\x02' + b'\x05' * 9)                          # gradient filter
    t.append(rect(0, 0, 1, 3, TIGHT) + b'\x40\x07' + b'\x05' * 9)                          # unknown filter
    for x in t:
        f.send(1, fbupdate(x))
    f.send(1, fbupdate(t[0], t[2], t[4]))
    # Tight with the "unused" rectangle count and LastRect
    f.send(1, fbupdate(t[0], rect(0, 0, 0, 0, LASTRECT), n=0xffff))
    # compact length of 3 octets (16384 octets of image data)
    f.send(1, fbupdate(rect(0, 0, 64, 48, TIGHT) + b'\x90' + compact(16400) + b'\x00' * 16400))
    # colour map, bell, cut text, ML, end of continuous updates, fence
    f.send(1, cm(0, [(1, 2, 3), (4, 5, 6), (65535, 0, 128)]))
    f.send(1, cm(10, []))
    f.send(1, bytes([2]))                                                     # bell
    f.send(1, msg_fence(248, 0x1, b'sync') + bytes([2]) + bytes([2]))    # several messages in a segment
    f.send(1, msg_fence(248, 0x80000000))
    f.send(1, bytes([150]) + b'\x00')                                         # end continuous updates (last in segment)

    net.mark('Session 1: server MirrorLink')
    f.send(1, s_ml(0))
    for t_ in sorted(ML):
        f.send(1, s_ml(t_, ML[t_]))
    f.send(1, s_ml(7, struct.pack('>BBH', 1, 0, 0)))
    f.send(1, s_ml(20, bytes([0])))
    f.send(1, s_ml(13))
    f.send(1, s_ml(14, b'\x01\x02'))
    f.send(1, s_ml(99, b'\x01\x02\x03'))
    f.send(1, s_ml(1, ML[1] + b'extra!') + bytes([2]))
    f.send(1, bytes([77, 1, 2, 3, 4]))                                        # unknown server message
    f.close()

    # ---------------------------------------------------------------------
    net.mark('Session 2 (3.8, 16 bit and 8 bit pixel formats)')
    f = std_session(net, 40002, PF16, 64, 48)
    f.send(1, fbupdate(rect(0, 0, 2, 2, RAW) + px(4, 2)))
    f.send(1, fbupdate(rect(0, 0, 16, 16, RRE) + struct.pack('>I', 1) + b'\x01\x02' + b'\x03\x04' + struct.pack('>HHHH', 1, 2, 3, 4)))
    ht = hextile(5, 5, 2, [(0x02 | 0x04 | 0x08 | 0x10, b'\x01\x02' + b'\x03\x04' + bytes([1]) + b'\x05\x06' + b'\x11\x22')])
    f.send(1, fbupdate(rect(0, 0, 5, 5, HEXTILE) + ht))
    f.send(1, fbupdate(rect(0, 0, 4, 4, TIGHT) + b'\x80' + b'\x10\x20'))             # fill: depth 16 -> bpp octets
    f.send(1, fbupdate(rect(0, 0, 8, 2, TIGHT) + b'\x40\x01\x01' + b'\x00\x01\x02\x03' + b'\xa5\x5a'))   # palette depth 16
    f.send(1, fbupdate(rect(0, 0, 2, 2, SLRLE) + struct.pack('>H', 1) + b'\x01\x02\x03' + struct.pack('>H', 0)))
    f.send(1, fbupdate(rect(0, 0, 2, 2, RICHCURSOR) + px(4, 2) + b'\xc0\xc0'))
    f.send(0, c_setpf(PF8))
    f.send(1, fbupdate(rect(0, 0, 2, 2, RAW) + px(4, 1)))
    f.send(1, fbupdate(rect(0, 0, 4, 4, TIGHT) + b'\x80' + b'\x10'))
    f.send(1, fbupdate(rect(0, 0, 8, 2, TIGHT) + b'\x40\x01\x03' + b'\x00\x01\x02\x03' + compact(16) + b'\x01' * 16))    # palette 4 of 8 bit
    f.send(1, fbupdate(rect(0, 0, 2, 2, SLRLE) + struct.pack('>H', 1) + b'\x01\x02' + struct.pack('>H', 0)))
    f.send(0, c_setpf(pf(15, 15, 1, 1, 31, 31, 31, 10, 5, 0)))
    f.send(1, fbupdate(rect(0, 0, 2, 2, SLRLE) + struct.pack('>H', 1) + b'\x01\x02\x03' + struct.pack('>H', 0)))
    f.send(0, c_setpf(pf(8, 6, 0, 0, 0, 0, 0, 0, 0, 0)))                   # colour map mode
    f.send(1, cm(0, [(i * 256, i * 128, 65535 - i) for i in range(16)]))

    # ---------------------------------------------------------------------
    net.mark('Session 3: reassembly of server messages over TCP segments')
    f = std_session(net, 40003, PF32, 64, 48)
    f.split(1, fbupdate(rect(0, 0, 16, 16, RAW) + px(256)), 30, 400)
    f.split(1, fbupdate(rect(0, 0, 2, 2, RAW) + px(4), rect(0, 0, 2, 2, COPYRECT) + b'\x00\x01\x00\x02'), 5, 25)
    f.split(1, fbupdate(rect(0, 0, 16, 16, RRE) + struct.pack('>I', 3) + b'\x01\x02\x03\x04' +
                        (b'\x05\x06\x07\x08' + struct.pack('>HHHH', 1, 2, 3, 4)) * 3), 17, 22, 40)
    f.split(1, fbupdate(rect(0, 0, 17, 17, HEXTILE) + hextile(17, 17, 4, [
        (0x01, px(256)),
        (0x02 | 0x04 | 0x08, b'\x01\x02\x03\x04' + b'\x05\x06\x07\x08' + bytes([2]) + b'\x12\x34\x56\x78'),
        (0x02 | 0x08 | 0x10, b'\x01\x02\x03\x04' + bytes([1]) + b'\x09\x0a\x0b\x0c' + b'\x11\x22'),
        (0x00, b'')])), 14, 18, 300, 320, 330)
    z = zlib.compress(bytes([130]) + b'\x01\x02\x03\x04\x05\x06\x07\x08')
    f.split(1, fbupdate(rect(0, 0, 4, 4, ZRLE) + struct.pack('>I', len(z)) + z), 17, 19, 25)
    f.split(1, fbupdate(rect(0, 0, 4, 4, TIGHT) + b'\x90' + compact(200) + b'J' * 200), 16, 17, 19, 100)
    f.split(1, fbupdate(rect(0, 0, 8, 2, TIGHT) + b'\x40\x01\x01' + b'\x00\x00\x00\xff\xff\xff' + b'\xa5\x5a'), 16, 17, 18, 20)
    f.split(1, fbupdate(rect(0, 0, 4, 4, TIGHT) + b'\x41\x01\x03' + b'\x01' * 12 + compact(200) + b'a' * 200), 17, 18, 19, 40, 50)
    f.split(1, fbupdate(rect(0, 0, 4, 4, TIGHT) + b'\x00' + compact(48) + b'\x01' * 48), 17, 18, 20)
    f.split(1, fbupdate(rect(0, 0, 4, 4, TIGHT) + b'\x80' + b'\x01\x02\x03'), 17, 19)
    f.split(1, fbupdate(rect(0, 0, 3, 3, RICHCURSOR) + px(9) + b'\x01' * 3), 14, 30)
    f.split(1, fbupdate(rect(0, 0, 9, 2, XCURSOR) + b'\x00\x00\x00\xff\xff\xff' + b'\xaa' * 4 + b'\x55' * 4), 14, 18, 26)
    f.split(1, fbupdate(rect(0, 0, 100, 80, EXTDESK) + bytes([2, 0, 0, 0]) +
                        struct.pack('>IHHHHI', 1, 0, 0, 50, 80, 0) + struct.pack('>IHHHHI', 2, 50, 0, 50, 80, 1)), 14, 20, 40)
    f.split(1, fbupdate(rect(0, 0, 70, 0, SUPMSGS) + b'\xff' * 32 + b'\x0f' * 32 + b'\x00' * 6), 16, 30)
    f.split(1, fbupdate(rect(0, 0, 10, 2, SUPENCS) + struct.pack('>II', 0, 5) + b'ab'), 16, 22)
    f.split(1, fbupdate(rect(0, 0, 6, 0, SRVIDENT) + b'VNCsrv'), 16, 18)
    f.split(1, fbupdate(rect(0, 0, 0, 0, CONTEXTINFO) + struct.pack('>IHHIII', 0x1004, 1, 2, 3, 4, 5)), 16, 25)
    f.split(1, fbupdate(rect(0, 0, 8, 2, SLRLE) + struct.pack('>H', 2) + b'\x01' * 8 + struct.pack('>H', 0)), 16, 17, 20, 25)
    f.split(1, fbupdate(rect(0, 0, 32, 24, H264) + struct.pack('>IIII', 6, 2, 32, 24) + b'\x00\x00\x01\x65\x88\x80'), 16, 20, 40)
    f.split(1, cm(0, [(1, 2, 3), (4, 5, 6), (65535, 0, 128)]), 6, 12)
    f.split(1, s_ml(7, ML[7]), 2, 4, 6, 10)
    f.split(1, s_ml(11, ML[11]), 2, 5)
    f.split(1, msg_fence(248, 0x3, b'payload'), 5, 9, 12)
    # a PDU for which the dissector asks for one more segment repeatedly
    f.split(1, fbupdate(rect(0, 0, 32, 32, RAW) + px(1024)), 20, 300, 800, 1200, 1600, 2000, 2400, 3000, 3500)
    f.close()

    # ---------------------------------------------------------------------
    net.mark('Session 4: RFB 3.3, server chooses the security type (None)')
    f = start(net, 40004, b'RFB 003.003\n', b'RFB 003.003\n')
    f.send(1, struct.pack('>I', 1))
    f.send(0, b'\x00')                    # ClientInit
    f.send(1, server_init(32, 32, PF32, None))   # no name
    f.send(0, c_fbreq(0, 0, 0, 32, 32))
    f.send(1, fbupdate(rect(0, 0, 1, 1, RAW) + px(1)))

    net.mark('Session 5: RFB 3.3, VNC authentication, failed')
    f = start(net, 40005, b'RFB 003.003\n', b'RFB 003.003\n')
    f.send(1, struct.pack('>I', 2))
    f.send(1, bytes(range(16)))
    f.send(0, bytes(range(16, 32)))
    f.send(1, struct.pack('>I', 1))      # failed; no reason in 3.3

    net.mark('Session 6: RFB 3.3, security type 0 (connection failed), and an unsupported type')
    f = start(net, 40006, b'RFB 003.003\n', b'RFB 003.003\n')
    f.send(1, struct.pack('>I', 0) + struct.pack('>I', 6) + b'failed')
    f = start(net, 40007, b'RFB 003.003\n', b'RFB 003.003\n')
    f.send(1, struct.pack('>I', 77))

    net.mark('Session 7: RFB 3.3, ARD authentication')
    f = start(net, 40008, b'RFB 003.003\n', b'RFB 003.003\n')
    f.send(1, struct.pack('>I', 30))
    f.send(1, struct.pack('>HH', 2, 16) + b'\x11' * 16 + b'\x22' * 16)
    f.send(0, b'\x33' * 128 + b'\x44' * 16)
    f.send(1, struct.pack('>I', 0))
    f.send(0, b'\x01')
    f.send(1, server_init(16, 16, PF32))

    net.mark('Session 8: RFB 3.7, VNC authentication, failed (no reason text)')
    f = start(net, 40009, b'RFB 003.007\n', b'RFB 003.007\n')
    f.send(1, b'\x01\x02')
    f.send(0, b'\x02')
    f.send(1, bytes(range(16)))
    f.send(0, bytes(range(16, 32)))
    f.send(1, struct.pack('>I', 1))

    net.mark('Session 9: RFB 3.7, None security goes straight to ClientInit')
    f = start(net, 40010, b'RFB 003.007\n', b'RFB 003.007\n')
    f.send(1, b'\x01\x01')
    f.send(0, b'\x01')
    f.send(0, b'\x01')                  # ClientInit
    f.send(1, server_init(16, 16, PF32))
    f.send(1, fbupdate(rect(0, 0, 1, 1, RAW) + px(1)))

    net.mark('Session 10: RFB 3.8, VNC authentication, failed with reason; failed result in 3.8')
    f = start(net, 40011)
    f.send(1, b'\x01\x02')
    f.send(0, b'\x02')
    f.send(1, bytes(range(16)))
    f.send(0, bytes(range(16, 32)))
    f.send(1, struct.pack('>II', 1, 14) + b'Wrong password')

    net.mark('Session 11: RFB 3.8, VNC authentication OK')
    f = start(net, 40012)
    f.send(1, b'\x01\x02')
    f.send(0, b'\x02')
    f.send(1, bytes(range(16)))
    f.send(0, bytes(range(16, 32)))
    f.send(1, struct.pack('>I', 0))
    f.send(0, b'\x00')
    f.send(1, server_init(16, 16, PF32))

    net.mark('Session 12: RFB 3.8 ARD and unsupported security types')
    f = start(net, 40013)
    f.send(1, b'\x02\x1e\x01')
    f.send(0, b'\x1e')
    f.send(1, struct.pack('>HH', 2, 4) + b'\x11' * 4 + b'\x22' * 4)
    f.send(0, b'\x33' * 128 + b'\x44' * 4)
    f.send(1, struct.pack('>I', 0))
    f = start(net, 40014)
    f.send(1, b'\x01\x11')
    f.send(0, b'\x11')           # Ultra: not supported by the dissector
    f.send(1, b'\x00\x00\x00\x00')
    f = start(net, 40015)
    f.send(1, b'\x01\x02')
    f.send(0, b'\x02')           # VNC
    f.send(1, bytes(16))
    f.send(0, bytes(16))
    f.send(1, struct.pack('>I', 2))   # result other than OK/failed

    # ---------------------------------------------------------------------
    net.mark('Session 13: TightVNC security (16), no tunnels, STDV NOAUTH__')
    def cap(code, vendor, sig):
        return struct.pack('>I', code) + vendor + sig
    f = start(net, 40016)
    f.send(1, b'\x01\x10')
    f.send(0, b'\x10')
    f.send(1, struct.pack('>I', 0))                                    # no tunnels
    f.send(1, struct.pack('>I', 1) + cap(1, b'STDV', b'NOAUTH__'))     # 1 auth type: None
    f.send(0, struct.pack('>I', 1))                                    # select None
    f.send(0, b'\x01')                                                 # ClientInit
    f.send(1, server_init(32, 32, PF32))
    f.send(1, struct.pack('>HHHH', 2, 1, 2, 0) + b''.join(struct.pack('>I', i) + v + b'MSGNAME%d' % i for i, v in ((1, b'STDV'), (2, b'TRDV'))) +
           b''.join(struct.pack('>I', i) + b'TGHT' + b'CMSGNAM%d' % i for i in (1,)) +
           b''.join(struct.pack('>I', i) + b'STDV' + b'ENCNAME%d' % i for i in (1, 2)))
    f.send(1, fbupdate(rect(0, 0, 4, 4, TIGHT) + b'\x80\x01\x02\x03'))
    f.send(0, c_fbreq(1, 0, 0, 32, 32))

    net.mark('Session 14: TightVNC, VNC authentication')
    f = start(net, 40017)
    f.send(1, b'\x01\x10'); f.send(0, b'\x10')
    f.send(1, struct.pack('>I', 0))
    f.send(1, struct.pack('>I', 2) + cap(2, b'STDV', b'VNCAUTH_') + cap(1, b'STDV', b'NOAUTH__'))
    f.send(0, struct.pack('>I', 2))
    f.send(1, bytes(16)); f.send(0, bytes(16)); f.send(1, struct.pack('>I', 0)); f.send(0, b'\x01')
    f.send(1, server_init(32, 32, PF32))

    net.mark('Session 15-18: TightVNC auth codes: VeNCrypt, GTK SASL, ULGNAUTH, XTRNAUTH')
    for i, (code, v, s, reply) in enumerate((
            (19, b'VENC', b'VENCRYPT', 1), (20, b'GTKV', b'SASL____', 20),
            (119, b'TGHT', b'ULGNAUTH', 119), (130, b'TGHT', b'XTRNAUTH', 130))):
        f = start(net, 40018 + i)
        f.send(1, b'\x01\x10'); f.send(0, b'\x10')
        f.send(1, struct.pack('>I', 0))
        f.send(1, struct.pack('>I', 1) + cap(code, v, s))
        f.send(0, struct.pack('>I', reply))
        if reply == 1:
            f.send(0, b'\x01')
            f.send(1, server_init(16, 16, PF32))
        else:
            f.send(1, b'\x00\x01\x02\x03')      # "Unknown packet (TightVNC)"
            f.send(1, bytes(16))                # then a VNC challenge

    net.mark('Session 19: TightVNC with no authentication types')
    f = start(net, 40022)
    f.send(1, b'\x01\x10'); f.send(0, b'\x10')
    f.send(1, struct.pack('>I', 0))
    f.send(1, struct.pack('>I', 0) + cap(1, b'STDV', b'NOAUTH__'))
    f.send(0, b'\x01')
    f.send(1, server_init(16, 16, PF32))

    net.mark('Session 20: TightVNC tunnel types offered')
    f = start(net, 40023)
    f.send(1, b'\x01\x10'); f.send(0, b'\x10')
    f.send(1, struct.pack('>I', 1) + cap(0, b'TGHT', b'NOTUNNEL'))
    f.send(0, struct.pack('>I', 0))

    net.mark('Session 21-24: TightVNC auth code mismatches and unknown codes (warnings)')
    for i, (code, v, s) in enumerate(((1, b'XXXX', b'NOAUTH__'), (2, b'STDV', b'NOTVNC__'), (19, b'VENC', b'XXXXXXXX'),
                                      (20, b'XXXX', b'SASL____'), (119, b'TGHT', b'XXXXXXXX'), (130, b'XXXX', b'XTRNAUTH'))):
        f = start(net, 40024 + i)
        f.send(1, b'\x01\x10'); f.send(0, b'\x10')
        f.send(1, struct.pack('>I', 0))
        f.send(1, struct.pack('>I', 1) + cap(code, v, s))

    # ---------------------------------------------------------------------
    net.mark('Session 30: VeNCrypt, selecting None (stays plain)')
    def vencrypt_start(cport, auth_types):
        f = start(net, cport)
        f.send(1, b'\x01\x13')
        f.send(0, b'\x13')
        f.send(1, b'\x00\x02')                  # server version 0.2
        f.send(0, b'\x00\x02')                  # client version 0.2
        f.send(1, b'\x00' + bytes([len(auth_types)]) + b''.join(struct.pack('>I', a) for a in auth_types))
        return f
    f = vencrypt_start(40030, (1, 2, 256, 257, 258, 259, 260, 261, 262, 263, 264, 999))
    f.send(0, struct.pack('>I', 1))             # None
    f.send(0, b'\x01')
    f.send(1, server_init(16, 16, PF32))

    net.mark('Session 31: VeNCrypt, VNC authentication')
    f = vencrypt_start(40031, (2,))
    f.send(0, struct.pack('>I', 2))
    f.send(1, bytes(16)); f.send(0, bytes(16)); f.send(1, struct.pack('>I', 0))

    net.mark('Session 32: VeNCrypt, TLS (the TLS records are opaque)')
    f = vencrypt_start(40032, (257, 260))
    f.send(0, struct.pack('>I', 257))
    f.send(1, b'\x01')                          # server ack
    # a TLS 1.2 ClientHello: plain text, built here without any key material
    ch_body = (b'\x03\x03' + bytes(32) + b'\x00' + struct.pack('>H', 2) + b'\x00\x2f' + b'\x01\x00' + b'\x00\x00')
    hs = b'\x01' + struct.pack('>I', len(ch_body))[1:] + ch_body
    f.send(0, b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs)
    f.send(1, b'\x16\x03\x03\x00\x04\x0e\x00\x00\x00')
    f.send(0, b'\x17\x03\x03\x00\x04\x01\x02\x03\x04')

    net.mark('Session 33: VeNCrypt split over TCP segments')
    f = start(net, 40033)
    f.send(1, b'\x01\x13')
    f.send(0, b'\x13')
    f.trickle(1, b'\x00\x02', 1)                # server version, one octet at a time
    f.trickle(0, b'\x00\x02', 1)
    f.trickle(1, b'\x00\x03' + struct.pack('>3I', 257, 2, 260), 5)
    f.trickle(0, struct.pack('>I', 257), 3)
    f.send(1, b'\x01')

    net.mark('Session 34: security type list split over segments')
    f = start(net, 40034)
    f.trickle(1, b'\x03\x01\x02\x10', 3)
    f.send(0, b'\x01')
    f.send(1, struct.pack('>I', 0))
    f.send(0, b'\x01')
    f.send(1, server_init(16, 16, PF32))

    # ---------------------------------------------------------------------
    net.mark('Session 40: TCP port 17000 recognised by the heuristic (RFB version message)')
    f = std_session(net, 40040, PF32, 16, 16, sport=17000)
    f.send(0, c_fbreq(0, 0, 0, 16, 16))
    f.send(1, fbupdate(rect(0, 0, 1, 1, RAW) + px(1)))
    f.send(0, c_key(1, 0x61))

    net.mark('Session 41: first segments are not RFB version messages (waiting for them)')
    f = Flow(net, CIP, 40041, SIP, 5901, 1, 2)
    f.handshake()
    f.send(1, b'hello')
    f.send(1, b'RFB 003.008\n')
    f.send(0, b'not it')
    f.send(0, b'RFB 003.008\n')
    f.send(1, b'\x01\x01')
    f.send(0, b'\x01')
    f.send(1, struct.pack('>I', 0))
    f.send(0, b'\x01')
    f.send(1, server_init(16, 16, PF32))
    f.send(1, struct.pack('>BBB', 2, 2, 2))      # three bells

    net.mark('Session 43: non-VNC TCP data on a port with no dissector, tried by the VNC heuristic')
    f = Flow(net, CIP, 40043, SIP, 17002, 1, 2)
    f.handshake()
    for d in (b'hello world!', b'RFB 003x008\n', b'RFB 003.008X', b'short', b'RFB 003.008\nand more'):
        f.send(1, d)
        f.send(0, d)

    net.mark('Session 42: version messages with a minor version 3.889 (Apple) and a different port')
    f = start(net, 40042, b'RFB 003.889\n', b'RFB 003.889\n', sport=5901)
    f.send(1, b'\x01\x01')
    f.send(0, b'\x01')
    f.send(1, struct.pack('>I', 0))
    f.send(0, b'\x01')
    f.send(1, server_init(16, 16, PF32))

    # ---------------------------------------------------------------------
    net.mark('Session 51: SetColourMapEntries with the count at offset + 3')
    f = std_session(net, 40051, PF32, 16, 16)
    f.send(1, cm(256, [(i, i, i) for i in range(5)]))
    f.send(1, bytes([2]) + cm(3, [(1, 2, 3), (4, 5, 6)]))   # not the first message of the segment

    net.mark('Session 52: extended clipboard (enabled by the first SetEncodings)')
    f = std_session(net, 40052, PF32, 16, 16)
    f.send(0, c_setenc(EXTCLIP, TIGHT, RAW))
    f.send(0, c_cuttext_ext(0x01000001, caps=(0x20000,)))                       # caps, text
    f.send(0, c_cuttext_ext(0x0100000f, caps=(0x20000, 0x20001, 0x20002, 0x20003)))
    f.send(0, c_cuttext_ext(0x02000001))                                        # request text
    f.send(0, c_cuttext_ext(0x04000000))                                        # peek
    f.send(0, c_cuttext_ext(0x08000003))                                        # notify
    f.send(0, c_cuttext_ext(0x1000000f, values=(b'text\x00', b'{\\rtf1 x}', b'<b>html</b>', b'\x01\x02\x03\x04')))
    f.send(0, c_cuttext_ext(0x10000001, values=(b'only text\x00',), compress=True))
    f.send(0, c_cuttext(b'old style text in extended mode'))
    f.send(0, struct.pack('>B3xi', 6, 0) + b'')            # zero length, original format
    f.send(0, struct.pack('>B3xi', 6, 5) + b'abcde')       # positive: original format, 5 octets of text
    f.send(0, struct.pack('>B3xi', 6, -4) + struct.pack('>I', 0x04000000))   # peek
    # rich cursor, hextile and raw with large products
    f.send(1, fbupdate(rect(0, 0, 1, 1, RICHCURSOR) + px(1) + b'\x80'))


def build_malformed(net):
    net.mark('M1: too many rectangles, too many sub-rectangles, colours and cut text')
    f = std_session(net, 41001, PF32, 64, 48)
    f.send(1, fbupdate(n=6000))
    f.send(1, fbupdate(rect(0, 0, 4, 4, RRE) + struct.pack('>I', 20000) + b'\x01\x02\x03\x04'))
    f.send(1, struct.pack('>BxHH', 1, 0, 20000) + bytes(16))
    f.send(1, bytes([3, 0x00, 0x03, 0x0d, 0x40]) + bytes(8))           # the dissector reads the padding as the length
    f.send(1, bytes([2]))

    net.mark('M2: Tight comp_ctl 0xA0 (invalid) and an invalid rectangle in a Tight stream')
    f = std_session(net, 41002, PF32, 64, 48)
    f.send(1, fbupdate(rect(0, 0, 1, 1, TIGHT) + b'\xa0' + bytes(8)))
    f.send(1, fbupdate(rect(0, 0, 1, 1, TIGHT) + b'\xff' + bytes(8)))
    f.send(1, bytes([2]))

    net.mark('M2b: more than 5000 rectangles with the unused rectangle count')
    f = std_session(net, 41022, PF32, 64, 48)
    f.send(1, fbupdate(*[rect(i & 0xff, 0, 0, 0, POINTERPOS) for i in range(5004)], n=0xffff))
    net.mark('M3: gtk-vnc greeting with a NUL instead of the newline')
    f = Flow(net, CIP, 41003, SIP, 5900, 1, 2)
    f.handshake()
    f.send(1, b'RFB 003.008\n')
    f.send(0, b'RFB 003.008\x00')
    f.send(1, b'\x01\x01')
    f = Flow(net, CIP, 41023, SIP, 17003, 1, 2)
    f.handshake()
    f.send(1, b'RFB 003.008\x00')            # accepted by the heuristic, with the error

    net.mark('M3b: unsupported security type 77 in 3.3, then data in that state')
    f = start(net, 41020, b'RFB 003.003\n', b'RFB 003.003\n')
    f.send(1, struct.pack('>I', 77))
    f.send(0, b'\x01')
    f = start(net, 41021)
    f.send(1, b'\x01\x10'); f.send(0, b'\x10')
    f.send(1, struct.pack('>I', 0))
    f.send(1, struct.pack('>I', 1) + struct.pack('>I', 19) + b'VENCVENCRYPT')
    f.send(0, struct.pack('>I', 19))

    net.mark('M4: TightVNC unknown authentication codes')
    def cap(code, vendor, sig):
        return struct.pack('>I', code) + vendor + sig
    f = start(net, 41004)
    f.send(1, b'\x01\x10'); f.send(0, b'\x10')
    f.send(1, struct.pack('>I', 0))
    f.send(1, struct.pack('>I', 1) + cap(77, b'TGHT', b'UNKNOWN_'))
    f.send(0, struct.pack('>I', 78))

    net.mark('M5: ZRLE data that does not decompress, and a raw subencoding with too little data')
    f = std_session(net, 41005, PF32, 64, 48)
    f.send(1, fbupdate(rect(0, 0, 4, 4, ZRLE) + struct.pack('>I', 12) + bytes(range(1, 13))))
    z = zlib.compress(b'\x00\x01\x02')
    f.send(1, fbupdate(rect(0, 0, 1, 1, ZRLE) + struct.pack('>I', len(z)) + z))
    z = zlib.compress(bytes([130]) + b'\x01\x02')
    f.send(1, fbupdate(rect(0, 0, 1, 1, ZRLE) + struct.pack('>I', len(z)) + z))
    z = zlib.compress(b'')
    f.send(1, fbupdate(rect(0, 0, 1, 1, ZRLE) + struct.pack('>I', len(z)) + z))

    net.mark('M6: truncated messages that throw (colour map, cut text, FramebufferUpdate headers)')
    f = std_session(net, 41006, PF32, 64, 48)
    f.send(1, bytes([1, 0, 0, 0]))                 # colour map: count read before the check
    f.send(1, bytes([3, 0, 0]))                    # cut text length cut short
    f.send(1, bytes([0]))                          # FramebufferUpdate without padding
    f.send(1, bytes([0, 0, 0]))                    # without the full rectangle count
    f.send(0, bytes([6, 0, 0]))                    # client cut text cut short
    f.send(0, bytes([2, 0]))                       # SetEncodings cut short
    f.send(0, bytes([0, 0, 0, 0, 32]))             # SetPixelFormat cut short
    f.send(0, bytes([3, 0, 0]))                    # FramebufferUpdateRequest cut short
    f.send(0, bytes([4, 1]))
    f.send(0, bytes([5, 1, 0]))
    f.send(0, bytes([255]))                        # QEMU without subtype
    f.send(0, bytes([128]))                        # MirrorLink header cut short
    f.send(0, bytes([150, 1]))                     # EnableContinuousUpdates cut short
    f.send(0, bytes([248, 0, 0, 0, 0, 0, 0]))      # Fence cut short
    f.send(1, struct.pack('>B3xI', 3, 5) + b'ab')   # cut text with too little data (reassembles)

    net.mark('M7: ServerInit and startup messages cut short')
    f = start(net, 41007)
    f.send(1, b'\x05\x01\x02')                     # says 5 types, has 2
    f = start(net, 41008)
    f.send(1, b'\x01\x01'); f.send(0, b'\x01'); f.send(1, struct.pack('>I', 0)); f.send(0, b'\x01')
    f.send(1, struct.pack('>HHBB', 1, 1, 32, 24))  # ServerInit cut short
    f = start(net, 41009, b'RFB 003.008\n', b'RFB 003.008\n')
    f.send(1, b'\x01\x02'); f.send(0, b'\x02'); f.send(1, bytes(8))     # challenge too short
    f.send(0, bytes(4))
    f = start(net, 41010)
    f.send(1, b'\x01\x01'); f.send(0, b'\x01')
    f.send(1, struct.pack('>II', 1, 100) + b'short')                      # failure text longer than the data
    f = start(net, 41011)
    f.send(1, b'\x01\x10'); f.send(0, b'\x10')
    f.send(1, struct.pack('>I', 2) + bytes(20))                           # tunnel list cut short
    f = start(net, 41012)
    f.send(1, b'\x01\x10'); f.send(0, b'\x10')
    f.send(1, struct.pack('>I', 0))
    f.send(1, struct.pack('>I', 1) + bytes(10))                           # auth capability cut short
    f = start(net, 41013, b'RFB 003.003\n', b'RFB 003.003\n')
    f.send(1, struct.pack('>I', 30))
    f.send(1, struct.pack('>HH', 2, 64) + b'\x11' * 16)                  # ARD challenge cut short
    f = start(net, 41014, b'RFB 003.003\n', b'RFB 003.003\n')
    f.send(1, struct.pack('>I', 30))
    f.send(1, struct.pack('>HH', 2, 4) + b'\x11' * 8)
    f.send(0, b'\x33' * 100)                                              # ARD response cut short

    net.mark('M8: oversized lengths')
    f = std_session(net, 41015, PF32, 64, 48)
    f.send(1, fbupdate(rect(0, 0, 65535, 65535, RAW) + px(4)))             # needs more than we send
    f.send(1, bytes([2]))
    f = std_session(net, 41016, PF32, 64, 48)
    f.send(1, fbupdate(rect(0, 0, 20000, 20000, RICHCURSOR) + px(4)))
    f = std_session(net, 41017, PF32, 64, 48)
    f.send(1, fbupdate(rect(0, 0, 1, 1, HEXTILE) + b'\x08\xff' + b'\x00' * 4))     # hextile with too few subrects
    f = std_session(net, 41018, PF32, 64, 48)
    f.send(0, struct.pack('>B3xi', 6, -2147483648) + b'\x00' * 8)         # INT_MIN length
    f.send(0, c_setenc(EXTCLIP, RAW))
    f.send(0, struct.pack('>B3xi', 6, -2147483648) + b'\x00' * 8)
    f.send(0, struct.pack('>B3xi', 6, 2147483647) + b'\x00' * 8)
    f.send(0, struct.pack('>B3xi', 6, -16) + struct.pack('>I', 0x01000001) + b'\x00' * 4 + b'\x01\x02\x03\x04')
    f.send(0, struct.pack('>B3xi', 6, -4) + struct.pack('>I', 0x0000000f))          # flags with all values but no data
    f = std_session(net, 41019, PF32, 64, 48)
    f.send(0, c_setenc(EXTCLIP, RAW))
    f.send(0, c_cuttext_ext(0x10000001, values=(b'x',), compress=False, raw_len=-9))       # not zlib data

    net.mark('M9: reproducer of the cut text fix (vnc_cuttext_desegment): every frame is a complete ServerCutText')
    f = std_session(net, 41030, PF32, 16, 16)
    for _ in range(5):
        f.send(1, struct.pack('>B3xI', 3, 4) + b'a' * 4)
    f.send(1, struct.pack('>B3xI', 3, 4) + b'a' * 4 + bytes([2]))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    net = Net()
    build_main(net, verbose)
    net.write(os.path.join(out, 'vnc-coverage.pcap'))
    if verbose:
        net.report('main')
    print('vnc-coverage.pcap: %d frames' % len(net.pkts))
    net = Net()
    build_malformed(net)
    net.write(os.path.join(out, 'vnc-coverage-malformed.pcap'))
    if verbose:
        net.report('malformed')
    print('vnc-coverage-malformed.pcap: %d frames' % len(net.pkts))


if __name__ == '__main__':
    main()
