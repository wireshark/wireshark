#!/usr/bin/env python3
# Generates test/captures/png_coverage.pcap.gz, png_coverage.png.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic PNG coverage files for file-png.c.

usage: mkpng.py <outdir> [-v]
png-coverage.png (main: every chunk the dissector decodes, all colour
types), png-coverage-http.pcap (HTTP: media type image/png, the HTTP
heuristic) and png-coverage-malformed.pcap.  The images are 1x1 pixels.
"""
import struct
import sys
import os
import zlib

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv


def w(name, data):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(data)
    if VERBOSE:
        print(name, len(data))


SIG = b'\x89PNG\r\n\x1a\n'


def chunk(typ, data=b'', crc=True):
    c = zlib.crc32(typ + data) & 0xffffffff if crc else 0
    return struct.pack('>I', len(data)) + typ + data + struct.pack('>I', c)


def ihdr(ct=2, depth=8, interlace=0, w_=1, h=1, comp=0, filt=0):
    return chunk(b'IHDR', struct.pack('>IIBBBBB', w_, h, depth, ct, comp, filt, interlace))


def idat(raw=b'\0\0\0\0'):
    return chunk(b'IDAT', zlib.compress(raw))


def f32(x):
    return struct.pack('>I', int(x * 100000))


def png(ct=2, extra=()):
    return SIG + ihdr(ct) + b''.join(extra) + idat() + chunk(b'IEND')


# ------------------------------------------------------------------ main
main = SIG + b''.join([
    ihdr(3, 8, 1, 1, 1),
    chunk(b'gAMA', f32(0.45455)),
    chunk(b'cHRM', b''.join(f32(x) for x in (0.3127, 0.329, 0.64, 0.33, 0.3, 0.6, 0.15, 0.06))),
    chunk(b'sRGB', b'\x00'),
    chunk(b'sBIT', b'\x08\x08\x08'),
    chunk(b'iCCP', b'sRGB\0\0' + zlib.compress(b'x' * 8)),
    chunk(b'PLTE', b'\xff\x00\x00\x00\xff\x00'),
    chunk(b'tRNS', b'\xff\x80'),
    chunk(b'bKGD', b'\x01'),                         # palette index (1 octet)
    chunk(b'pHYs', struct.pack('>IIB', 2835, 2835, 1)),
    chunk(b'tIME', struct.pack('>HBBBBB', 2026, 11, 14, 1, 2, 3)),
    chunk(b'tEXt', b'Title\0synthetic test image'),
    chunk(b'tEXt', b'Comment\0'),                    # keyword, empty text
    chunk(b'iTXt', b'Author\0\0\0en\0Author\0synthetic'),
    chunk(b'zZZz', b'\x01\x02\x03'),                 # unknown ancillary (default branch)
    chunk(b'prVT', b''),                             # unknown private, no data
    idat(b'\0\x01'),
    chunk(b'IEND'),
])
w('png-coverage.png', main)

# the other colour types and background sizes
rgb = png(2, [chunk(b'bKGD', struct.pack('>HHH', 255, 0, 255)), chunk(b'sRGB', b'\x03')])
gray = png(0, [chunk(b'bKGD', struct.pack('>H', 128)), chunk(b'sRGB', b'\x01')])
gray_a = png(4, [chunk(b'bKGD', struct.pack('>H', 128)), chunk(b'sRGB', b'\x02')])
rgba = png(6, [chunk(b'bKGD', struct.pack('>HHH', 1, 2, 3))])
bkgd_other = png(2, [chunk(b'bKGD', b'\x01\x02\x03')])      # length 3: no field
w('png-coverage-rgb.png', rgb)
w('png-coverage-gray.png', gray)

# ------------------------------------------------------------------ HTTP
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
http_pcap('png-coverage-http.pcap', [
    ('image/png', main),
    ('image/png', rgb),
    ('image/png', gray),
    (None, gray_a),                    # the http heuristic
    ('image/png', rgba),
    (None, bkgd_other),
    (None, SIG + b'\x00\x00'),         # too short for the heuristic
    (None, b'\x89PNG\r\n\x1a\x0b' + b'\0' * 30),   # wrong signature
])

# ------------------------------------------------------------------ malformed
bad = []
# chunk length above INT_MAX: expert info, the walk stops
bad.append(('big', SIG + ihdr() + struct.pack('>I', 0x80000001) + b'IDAT' + b'\0' * 8))
# chunk longer than the file (the subset is cut: exception)
bad.append(('long', SIG + ihdr() + struct.pack('>I', 1000) + b'IDAT' + b'\0' * 8))
# IHDR cut short
bad.append(('ihdr', SIG + chunk(b'IHDR', b'\0\0\0\x01\0\0\0\x01\x08') + chunk(b'IEND')))
# tEXt without a NUL and with an empty keyword
bad.append(('text-nonul', SIG + ihdr() + chunk(b'tEXt', b'keywordwithoutnul') + chunk(b'IEND')))
bad.append(('text-empty-key', SIG + ihdr() + chunk(b'tEXt', b'\0value') + chunk(b'IEND')))
# short pHYs, tIME, cHRM, gAMA, sRGB
bad.append(('phys', SIG + ihdr() + chunk(b'pHYs', b'\0\0\0\x01') + chunk(b'IEND')))
bad.append(('time', SIG + ihdr() + chunk(b'tIME', b'\x07\xea\x0b') + chunk(b'IEND')))
bad.append(('chrm', SIG + ihdr() + chunk(b'cHRM', b'\0' * 12) + chunk(b'IEND')))
bad.append(('gama', SIG + ihdr() + chunk(b'gAMA', b'\0\0') + chunk(b'IEND')))
bad.append(('srgb', SIG + ihdr() + chunk(b'sRGB', b'') + chunk(b'IEND')))
# last chunk without CRC / chunk header cut
bad.append(('nocrc', SIG + ihdr() + struct.pack('>I', 0) + b'IEND'))
bad.append(('cut-hdr', SIG + ihdr() + b'\0\0\0\0IE'))
for n, d in bad:
    w('png-bad-%s.png' % n, d)
http_pcap('png-coverage-malformed.pcap', [('image/png', d) for n, d in bad])
