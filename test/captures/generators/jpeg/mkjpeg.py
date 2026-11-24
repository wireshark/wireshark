#!/usr/bin/env python3
# Generates test/captures/jpeg_coverage.jpg.gz, jpeg_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic JPEG (JFIF/EXIF) coverage files for file-jpeg.c.

usage: mkjpeg.py <outdir> [-v]
Writes jpeg-coverage.jpg (main, decodes cleanly except for the one
reproducer warning of the fix), jpeg-coverage-exif-be.jpg, the HTTP
capture jpeg-coverage-http.pcap and the malformed files.
Nothing here is a real image: the "entropy coded" data is a few bytes.
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


def seg(marker, payload):
    return struct.pack('>HH', marker, len(payload) + 2) + payload


JFIF = seg(0xFFE0, b'JFIF\0' + bytes([1, 2, 1]) + struct.pack('>HH', 72, 72) + bytes([0, 0]))
# 2x1 thumbnail: x*y*3 bytes of RGB
JFIF_THUMB = seg(0xFFE0, b'JFIF\0' + bytes([1, 1, 0]) + struct.pack('>HH', 1, 1)
                 + bytes([2, 1]) + bytes(range(6)))
JFXX = seg(0xFFE0, b'JFXX\0' + bytes([0x10]) + b'\x01\x02\x03')
APP0_UNKNOWN = seg(0xFFE0, b'AVI1\0' + b'\x00' * 6)


# ---------------------------------------------------------------- TIFF / EXIF

def tiff(ifds, e='<'):
    """ifds: list of dicts {entries: [(tag, type, count, data)], next: index|None}.
    data is bytes (already encoded), ('ptr', idx) for a LONG pointing at ifd idx,
    or ('raw', value) for a literal 4 byte offset field value.
    Layout: header (8), then the IFDs in order, each followed by its
    out-of-line data."""
    def esize(ifd):
        n = len(ifd['entries'])
        ext = sum((len(x[3]) + 1) & ~1 for x in ifd['entries']
                  if isinstance(x[3], bytes) and len(x[3]) > 4)
        return 2 + 12 * n + 4 + ext
    offs = []
    pos = 8
    for ifd in ifds:
        offs.append(pos)
        pos += esize(ifd)
    out = (b'II' if e == '<' else b'MM') + struct.pack(e + 'HI', 42, offs[0])
    for i, ifd in enumerate(ifds):
        n = len(ifd['entries'])
        body = struct.pack(e + 'H', n)
        ext = b''
        extpos = offs[i] + 2 + 12 * n + 4
        for tag, typ, cnt, data in ifd['entries']:
            if isinstance(data, tuple) and data[0] == 'ptr':
                field = struct.pack(e + 'I', offs[data[1]])
            elif isinstance(data, tuple) and data[0] == 'raw':
                field = struct.pack(e + 'I', data[1])
            elif len(data) <= 4:
                field = data + b'\0' * (4 - len(data))
            else:
                field = struct.pack(e + 'I', extpos + len(ext))
                ext += data + (b'\0' if len(data) & 1 else b'')
            body += struct.pack(e + 'HHI', tag, typ, cnt) + field
        nxt = ifd.get('next')
        body += struct.pack(e + 'I', offs[nxt] if nxt is not None else 0)
        out += body + ext
    return out


def U16(e, *v): return struct.pack(e + '%dH' % len(v), *v)
def U32(e, *v): return struct.pack(e + '%dI' % len(v), *v)
def S32(e, *v): return struct.pack(e + '%di' % len(v), *v)


def exif_ifds(e):
    """IFD0 -> IFD1; IFD0 points at an Exif IFD (which holds an Interop pointer)
    and a GPS IFD.  Every field type, inline and out-of-line values."""
    ifd0 = {'entries': [
        (0x010F, 2, 5, b'Make\0'),                       # ASCII, out of line
        (0x0110, 2, 3, b'XY\0'),                         # ASCII inline
        (0x0112, 3, 1, U16(e, 1)),                       # SHORT inline
        (0x011A, 5, 1, U32(e, 72, 1)),                   # RATIONAL
        (0x0131, 2, 9, b'synthetic\0'[:9]),
        (0x8769, 4, 1, ('ptr', 2)),                      # Exif IFD pointer
        (0x8825, 4, 1, ('ptr', 3)),                      # GPS IFD pointer
    ], 'next': 1}
    ifd1 = {'entries': [
        (0x0103, 3, 1, U16(e, 6)),
        (0x0201, 4, 1, U32(e, 0)),
        (0x0202, 4, 1, U32(e, 0)),
    ], 'next': None}
    exif = {'entries': [
        (0x829A, 5, 1, U32(e, 1, 250)),
        (0x8827, 3, 2, U16(e, 100, 200)),                # SHORT x2 inline
        (0x9000, 7, 4, b'0230'),                         # UNDEFINED
        (0x9003, 2, 20, b'2026:11:14 00:00:00\0'),
        (0x9201, 10, 1, S32(e, -3, 1)),                  # SRATIONAL
        (0x9204, 9, 1, S32(e, -7)),                      # SLONG
        (0x9206, 9, 2, S32(e, 5, -5)),                   # SLONG out of line
        (0x927C, 7, 6, b'\x01\x02\x03\x04\x05\x06'),     # UNDEFINED out of line
        (0xA000, 1, 4, b'\x01\x02\x03\x04'),             # BYTE inline
        (0xA001, 1, 6, b'\x01\x02\x03\x04\x05\x06'),     # BYTE out of line
        (0xA002, 4, 2, U32(e, 64, 48)),                  # LONG x2 out of line
        (0xA005, 4, 1, ('ptr', 4)),                      # Interop pointer
        (0xA0FF, 99, 1, U32(e, 0)),                      # unknown type (inline)
        (0xA0FE, 99, 9, ('raw', 8)),                     # unknown type, offset
    ], 'next': None}
    gps = {'entries': [
        (0x0000, 1, 4, bytes([2, 3, 0, 0])),
        (0x0001, 2, 2, b'N\0'),
        (0x0002, 5, 3, U32(e, 37, 1, 48, 1, 0, 100)),
        (0x0005, 1, 1, b'\x00'),
    ], 'next': None}
    interop = {'entries': [
        (0x0001, 2, 4, b'R98\0'),
        (0x0002, 7, 4, b'0100'),
    ], 'next': None}
    return [ifd0, ifd1, exif, gps, interop]


def app1_exif(t):
    return seg(0xFFE1, b'Exif\0\0' + t)


APP1_XMP = seg(0xFFE1, b'http://ns.adobe.com/xap/1.0/\0<x:xmpmeta/>')
APP2_FPXR = seg(0xFFE2, b'FPXR\0\x00\x01\x02')
APP2_ICC = seg(0xFFE2, b'ICC_PROFILE\0\x01\x01' + b'\0' * 8)
DQT = seg(0xFFDB, bytes([0]) + bytes(range(1, 65)))
SOF0 = seg(0xFFC0, bytes([8]) + struct.pack('>HH', 16, 24) + bytes([3])
           + bytes([1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]))
DHT = seg(0xFFC4, bytes([0x00]) + bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]) + bytes(range(12)))
DRI = seg(0xFFDD, struct.pack('>H', 4))
COM = seg(0xFFFE, b'synthetic test image')
SOS = seg(0xFFDA, bytes([3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0x10]))
ECS = b'\x12\x34\xff\x00\x56\x78\xff\x00\x9a'      # FF00 is an escaped FF
SOI = b'\xff\xd8'
EOI = b'\xff\xd9'


def other_markers():
    """Markers that carry only the generic segment display or no segment."""
    b = b''
    for m in (0xFFC1, 0xFFC2, 0xFFC3, 0xFFC5, 0xFFC6, 0xFFC7, 0xFFC8, 0xFFC9, 0xFFCA,
              0xFFCB, 0xFFCD, 0xFFCE, 0xFFCF):
        b += seg(m, bytes([8]) + struct.pack('>HH', 8, 8) + bytes([1, 1, 0x11, 0]))
    b += seg(0xFFCC, b'\x00\x01')            # DAC: generic segment
    b += seg(0xFFDC, b'\x00\x10')            # DNL
    b += seg(0xFFDE, b'\x00\x10')            # DHP
    b += seg(0xFFDF, b'\x00\x10')            # EXP
    for m in range(0xFFE3, 0xFFF0):          # APP3-APP15
        b += seg(m, b'x%d\0' % (m & 15))
    for m in range(0xFFF0, 0xFFFE):          # JPG0-JPG13
        b += seg(m, b'jpg')
    return b


def scan(restarts=True):
    s = SOS + ECS
    if restarts:
        for n in range(8):
            s += bytes([0xFF, 0xD0 + n]) + b'\xab\xcd'
    return s


def jpeg(*parts):
    return SOI + b''.join(parts) + EOI


# ---------------------------------------------------------------- main file
main = jpeg(
    JFIF_THUMB, JFXX, APP0_UNKNOWN,
    app1_exif(tiff(exif_ifds('<'), '<')),
    APP1_XMP, APP2_FPXR, APP2_ICC,
    seg(0xFFED, b'Photoshop 3.0\0'),
    DQT, SOF0, DHT, DRI, COM,
    other_markers(),
    b'\xff\x01',            # TEM: marker without a segment
    b'\xff\xff\xff\xff',    # fill bytes before the SOS marker
    scan(),
)
w('jpeg-coverage.jpg', main)

# Exif first (no JFIF APP0): shows the "first identifier is not JFIF"
# warning only if it is not Exif; Exif first is the accepted variant.
be = jpeg(JFIF, app1_exif(tiff(exif_ifds('>'), '>')), DQT, SOF0, DHT, COM, scan(False))
w('jpeg-coverage-exif-be.jpg', be)
exif_first = jpeg(app1_exif(tiff(exif_ifds('<'), '<')), SOF0, scan(False))
w('jpeg-coverage-exif-first.jpg', exif_first)

# JFIF with the minimal thumbnail-free APP0 and nothing else; a second image
# with an SOF progressive marker and SOS only
w('jpeg-coverage-min.jpg', jpeg(JFIF, SOF0, scan(False)))

# ----------------------------------------------- reproducer of the fix (main)
# IFD0 whose Exif pointer repeats and loops back to IFD0 itself: each
# extension type is followed once, the repeats get an expert info.
def repro_ifds(n=6):
    e = '<'
    ent = []
    for i in range(n):
        ent.append((0x8769 if i < n - 2 else (0x8825 if i == n - 2 else 0xA005), 4, 1, ('ptr', 0)))
    return [{'entries': ent, 'next': None}]

repro = jpeg(JFIF, app1_exif(tiff(repro_ifds(6), '<')), scan(False))
w('jpeg-coverage-repro.jpg', repro)


def repro_big(n=5400):
    return jpeg(JFIF, app1_exif(tiff(repro_ifds(n), '<')))
# a few hundred entries are enough for the test (the original has 5400)
w('jpeg-coverage-quadratic.jpg', repro_big(1500))

# ---------------------------------------------------------------- main capture
# All the valid files in one stream: a JPEG file is a single frame, so the
# committed capture is the "main" file; the others go to the HTTP pcap.


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


http_pcap('jpeg-coverage-http.pcap', [
    ('image/jpeg', main),
    ('image/jpg', be),
    ('image/jfif', repro),
    (None, jpeg(JFIF, SOF0, scan(False))),   # no type: the http heuristic
    ('image/jpeg', exif_first),
    # not claimed by the heuristic: too short, no SOI (plain text), SOI without JFIF/Exif
    (None, b'\xff\xd8\xff\xe0'),
    (None, b'plain text body, not an image at all.'),
    (None, b'\xff\xd8\xff\xe0\x00\x10JFXX\0' + b'\0' * 20),
])

# ---------------------------------------------------------------- malformed
# Paths that only broken files reach.
bad = []
# Reserved marker (0xFF02): the walk stops
bad.append(('jpeg-bad-reserved.jpg', SOI + JFIF + b'\xff\x02' + b'\0' * 8))
# First APP segment is not JFIF/Exif -> not claimed by the heuristic; as a
# media type it is dissected and warns.  APP1 Exif first then non-JFIF
bad.append(('jpeg-bad-first-app1.jpg', SOI + seg(0xFFE1, b'Exif\0\0' + b'MM\0*\0\0\0\x08\0\0\0\0\0\0') + EOI))
# Wrong byte order in the TIFF header
bad.append(('jpeg-bad-tiff-order.jpg', SOI + JFIF + seg(0xFFE1, b'Exif\0\0' + b'XX\0*\0\0\0\x08\0\0\0\0\0\0') + EOI))
# IFD start offset below the header size
bad.append(('jpeg-bad-ifd-start.jpg', SOI + JFIF + seg(0xFFE1, b'Exif\0\0' + b'II*\0\x04\0\0\0\0\0\0\0\0\0') + EOI))
# value offset past the end
t = tiff([{'entries': [(0x010F, 2, 40, ('raw', 0x7fff))], 'next': None}])
bad.append(('jpeg-bad-value-offset.jpg', SOI + JFIF + app1_exif(t) + EOI))
# extension pointer past the end
t = tiff([{'entries': [(0x8769, 4, 1, ('raw', 0x7fff))], 'next': None}])
bad.append(('jpeg-bad-ext-offset.jpg', SOI + JFIF + app1_exif(t) + EOI))
# next IFD offset below the end of this IFD
t = bytearray(tiff([{'entries': [(0x0112, 3, 1, U16('<', 1))], 'next': None}]))
t[8 + 2 + 12:8 + 2 + 16] = struct.pack('<I', 9)
bad.append(('jpeg-bad-next-offset.jpg', SOI + JFIF + app1_exif(bytes(t)) + EOI))
# next IFD offset leaves less than 6 bytes
t = bytearray(tiff([{'entries': [(0x0112, 3, 1, U16('<', 1))], 'next': None}]))
t[8 + 2 + 12:8 + 2 + 16] = struct.pack('<I', len(t))
bad.append(('jpeg-bad-next-short.jpg', SOI + JFIF + app1_exif(bytes(t)) + EOI))
# truncated segment (length past the end), truncated SOF
bad.append(('jpeg-bad-trunc-seg.jpg', SOI + JFIF + b'\xff\xdb\x00\x50' + b'\0' * 10))
bad.append(('jpeg-bad-trunc-sof.jpg', SOI + JFIF + b'\xff\xc0\x00\x20' + bytes([8, 0, 1, 0, 1, 9, 1, 0x11])))
bad.append(('jpeg-bad-trunc-sos.jpg', SOI + JFIF + b'\xff\xda\x00\x20' + bytes([9, 1, 0, 2])))
# thumbnail larger than the segment
bad.append(('jpeg-bad-thumb.jpg', SOI + seg(0xFFE0, b'JFIF\0' + bytes([1, 1, 0]) + struct.pack('>HH', 1, 1) + bytes([200, 200]) + b'\0' * 4) + EOI))
# a lone 0xFF at the very end, and a marker cut after the first byte
bad.append(('jpeg-bad-ff-end.jpg', SOI + JFIF + b'\x12\x34\xff'))
bad.append(('jpeg-bad-short-len.jpg', SOI + JFIF + b'\xff\xe2\x00'))
# APP2 / APP0 / APP1 with the identifier not terminated
bad.append(('jpeg-bad-ident.jpg', SOI + JFIF + b'\xff\xe2\x00\x08ABCDEF' + EOI))
for n, d in bad:
    w(n, d)
http_pcap('jpeg-coverage-malformed.pcap', [('image/jpeg', d) for n, d in bad] + [('image/jpeg', repro_big(1500))])
