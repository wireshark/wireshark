#!/usr/bin/env python3
# Generates test/captures/gif_coverage.gif.gz, gif_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic GIF coverage files for file-gif.c.

usage: mkgif.py <outdir> [-v]
gif-coverage.gif (main: GIF89a with every block kind), gif-coverage-87.gif
(GIF87a), gif-coverage-http.pcap (HTTP: media type image/gif and the HTTP
heuristic) and gif-coverage-malformed.pcap.  Pixel data is a few bytes.
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv


def w(name, data):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(data)
    if VERBOSE:
        print(name, len(data))


def blocks(*bs):
    """Data sub-blocks followed by the zero length terminator."""
    return b''.join(bytes([len(b)]) + b for b in bs) + b'\0'


def header(ver=b'GIF89a', w_=2, h_=2, flags=0x80, bg=0, aspect=0, gct=True):
    d = ver + struct.pack('<HH', w_, h_) + bytes([flags, bg, aspect])
    if flags & 0x80:
        d += bytes(range(3 * (1 << ((flags & 7) + 1))))
    return d


def image(left=0, top=0, w_=2, h_=2, flags=0, lct=b'', lzw=blocks(b'\x44\x01')):
    return b',' + struct.pack('<HHHH', left, top, w_, h_) + bytes([flags]) + lct + b'\x02' + lzw


GCE = b'!\xf9' + blocks(b'\x04\x00\x00\x00\x00')
COMMENT = b'!\xfe' + blocks(b'synthetic ', b'test')
APP = b'!\xff' + blocks(b'NETSCAPE2.0', b'\x01\x00\x00')
PLAIN = b'!\x01' + blocks(b'\x0c\x00\x00\x00\x00\x02\x00\x02\x00\x01\x01\x00\x00', b'hi')
UNKNOWN_EXT = b'!\x77' + blocks(b'abc')

# ------------------------------------------------------------------- main
# GIF89a, global table of 4 colors (flags 0xF1: colour resolution 8 bits,
# the fix of the mask 0x70), ordered (0x08), aspect ratio, several images
main = (header(b'GIF89a', 2, 2, 0xF1 | 0x08, 1, 49)
        + GCE + COMMENT + APP + PLAIN + UNKNOWN_EXT
        + image(0, 0, 2, 2, 0)
        # local color table (4 colors), ordered, interlaced
        + GCE + image(0, 0, 1, 1, 0x80 | 0x40 | 0x20 | 0x01, bytes(range(12)))
        # local table without the ordered flag, other resolution
        + image(1, 1, 1, 1, 0x80 | 0x01, bytes(range(12)), blocks(b'\x44', b'\x01\x02'))
        + b';')
w('gif-coverage.gif', main)

# GIF87a: the ordered flags are not shown, aspect ratio byte is ignored
g87 = (header(b'GIF87a', 4, 4, 0x70 | 0x80 | 0x02, 0, 0)
       + image(0, 0, 4, 4, 0)
       + image(0, 0, 2, 2, 0x80 | 0x02, bytes(range(24)))
       + b';')
w('gif-coverage-87.gif', g87)

# no global table, aspect ratio 0 (not shown), no trailer
nogct = header(b'GIF89a', 1, 1, 0x00, 0, 0) + image(0, 0, 1, 1, 0) + COMMENT
w('gif-coverage-nogct.gif', nogct)

# unknown block types (the fix: item length of the unknown block): two bytes
unk = header(b'GIF89a', 1, 1, 0x80, 0, 0) + b'\x99\x98' + image(0, 0, 1, 1, 0) + b'\x00' + b';'
w('gif-coverage-unknown-block.gif', unk)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def http_pcap(fname, responses):
    """responses: list of (content type or None, body, extra header)"""
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
    ts = 0
    for k, (ctype, body) in enumerate(responses):
        hdr = 'HTTP/1.1 200 OK\r\n'
        if ctype:
            hdr += 'Content-Type: %s\r\n' % ctype
        hdr += 'Content-Length: %d\r\n\r\n' % len(body)
        data = hdr.encode() + body
        seq = 1000
        sport = 40000 + k
        for i in range(0, len(data), 1400):
            segd = data[i:i + 1400]
            src, dst = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
            tcp = struct.pack('!HHIIBBHHH', 80, sport, seq, 1, 0x50, 0x18, 65535, 0, 0)
            ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(segd))
            tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + segd)) + tcp[18:]
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(segd), 1, 0, 64, 6, 0, src, dst)
            ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
            pkt = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + tcp + segd
            out.append(struct.pack('<IIII', 1, ts, len(pkt), len(pkt)) + pkt)
            ts += 1
            seq += len(segd)
    open(os.path.join(OUT, fname), 'wb').write(b''.join(out))
    if VERBOSE:
        print(fname, len(responses), 'responses')
http_pcap('gif-coverage-http.pcap', [
    ('image/gif', main),
    ('image/gif', g87),
    (None, nogct),                     # the http heuristic
    ('application/octet-stream', g87),
    ('image/gif', unk),
    (None, b'GIF89a'),                 # too short
    (None, b'GIF90a' + b'\0' * 30),    # unknown version
])

bad = []
# truncated: screen descriptor cut, global table cut, extension without terminator,
# image descriptor cut, sub-block longer than the file
bad.append(('cut-screen', b'GIF89a\x02\x00\x02\x00\x80\x00\x00' + b'\0' * 3 + b'\0' * 9))
bad.append(('cut-gct', b'GIF89a\x02\x00\x02\x00\x80\x00\x00' + b'\0' * 12))
bad.append(('cut-ext', header() + b'!\xfe\x05ab'))
bad.append(('cut-image', header() + b',\x00\x00\x00\x00'))
bad.append(('cut-lct', header() + b',\x00\x00\x00\x00\x02\x00\x02\x00\x80\x01\x01\x02\x03'))
bad.append(('cut-block', header() + image(lzw=b'\x40\x01\x02')))
bad.append(('cut-sublen', header() + b'!\xff\xff' + b'\0' * 10))
for n, d in bad:
    w('gif-bad-%s.gif' % n, d)
http_pcap('gif-coverage-malformed.pcap', [('image/gif', d) for n, d in bad])
