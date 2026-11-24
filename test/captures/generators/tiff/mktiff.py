#!/usr/bin/env python3
# Generates test/captures/tiff_coverage.pcap.gz, tiff_coverage.tif.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic TIFF coverage files for file-tiff.c.

usage: mktiff.py <outdir> [-v]
tiff-coverage.tif (main, little endian, clean), tiff-coverage-be.tif (big
endian, two IFDs), tiff-coverage-http.pcap (HTTP, media type image/tiff,
holds the files plus the reproducer of the fix and bodies the heuristic
must not claim) and tiff-coverage-malformed.pcap.
Nothing here is a real image: strips are a few bytes.
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


def A(s): return s.encode() + b'\0'


def main_ifds(e):
    ent = [
        (254, 4, 1, U32(e, 0)),                  # NewSubfileType: not decoded (note)
        (255, 3, 1, U16(e, 1)),                  # SubfileType (note)
        (256, 4, 1, U32(e, 4)),                  # width LONG
        (257, 3, 1, U16(e, 2)),                  # length SHORT
        (258, 3, 3, U16(e, 8, 8, 8)),            # bits per sample (out of line)
        (259, 3, 1, U16(e, 5)),                  # compression
        (262, 3, 1, U16(e, 2)),                  # photometric
        (263, 3, 1, U16(e, 1)),                  # threshholding
        (264, 3, 1, U16(e, 16)),
        (265, 3, 1, U16(e, 16)),
        (266, 3, 1, U16(e, 1)),                  # fill order
        (269, 2, 9, A('doc name')),              # document name
        (270, 2, 3, b'ab\0'),                    # image description, inline
        (271, 2, 6, A('Maker')),
        (272, 2, 3, b'XY\0'),
        (273, 4, 1, U32(e, 0)),                  # strip offsets LONG x1
        (274, 3, 1, U16(e, 1)),
        (277, 3, 1, U16(e, 3)),
        (278, 3, 1, U16(e, 2)),
        (279, 4, 2, U32(e, 6, 6)),               # strip byte counts out of line
        (280, 3, 1, U16(e, 0)),                  # min sample value (unknown)
        (282, 5, 1, U32(e, 300, 1)),             # X resolution
        (283, 5, 1, U32(e, 300, 1)),
        (284, 3, 1, U16(e, 1)),
        (285, 2, 5, A('page')),
        (290, 3, 1, U16(e, 2)),
        (293, 4, 1, U32(e, 0x00000002)),         # T6 options
        (296, 3, 1, U16(e, 2)),
        (305, 2, 4, b'sw\0\0'),
        (306, 2, 20, A('2026:11:14 00:00:00')),
        (315, 2, 7, A('artist')),
        (316, 2, 5, A('host')),
        (317, 3, 1, U16(e, 2)),
        (322, 4, 1, U32(e, 16)),
        (323, 4, 1, U32(e, 16)),
        (332, 3, 1, U16(e, 1)),
        (334, 3, 1, U16(e, 4)),
        (337, 2, 4, b'tp\0\0'),
        (0x8298, 2, 12, A('(c) nobody')),
        # unknown tags: every type length, inline and out of line
        (513, 4, 3, U32(e, 1, 2, 3)),            # LONG x3: pointer
        (532, 5, 2, U32(e, 0, 1, 255, 1)),       # RATIONAL x2
        (700, 1, 2, b'\x01\x02'),                # BYTE x2 inline
        (701, 6, 1, b'\xff'),                    # SBYTE
        (702, 7, 4, b'ABCD'),                    # UNDEFINED
        (703, 8, 2, struct.pack(e + 'hh', -1, 2)),   # SSHORT
        (704, 9, 1, S32(e, -5)),                 # SLONG
        (705, 10, 1, S32(e, -1, 2)),             # SRATIONAL
        (706, 11, 1, struct.pack(e + 'f', 1.5)),     # FLOAT
        (707, 12, 1, struct.pack(e + 'd', 2.5)),     # DOUBLE
        (708, 2, 6, A('hello')),                 # ASCII (unknown tag)
    ]
    ent.sort(key=lambda x: x[0])
    ifd1 = [(256, 4, 1, U32(e, 2)), (257, 4, 1, U32(e, 2)), (259, 3, 1, U16(e, 1))]
    ifd2 = [(256, 1, 1, b'\x01'), (257, 3, 1, U16(e, 1))]
    return [{'entries': ent, 'next': 1}, {'entries': ifd1, 'next': 2},
            {'entries': ifd2, 'next': None}]


main = tiff(main_ifds('<'), '<')
w('tiff-coverage.tif', main)
be = tiff(main_ifds('>'), '>')
w('tiff-coverage-be.tif', be)

# Reproducer of the fix: count * type length wraps 32 bits (LONG, count
# 0x40000001 = 4 octets after the wrap) in an unknown tag and an array tag.
def one(entries, e='<'):
    return tiff([{'entries': entries, 'next': None}], e)

repro = one([
    (258, 3, 0x80000001, ('raw', 0x1000)),       # array tag: 2 * count wraps to 2
    (999, 4, 0x40000001, ('raw', 0x1000)),       # unknown tag: 4 * count wraps to 4
    (998, 12, 0x20000001, ('raw', 0x1000)),      # unknown tag, DOUBLE: wraps to 8
    (997, 4, 0x3fffffff, ('raw', 0x1000)),       # 0xfffffffc: no wrap, but above INT_MAX
])
w('tiff-coverage-repro.tif', repro)

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



http_pcap('tiff-coverage-http.pcap', [
    ('image/tiff', main),
    ('image/tiff', be),
    ('image/tiff', repro),
    (None, main),                       # no content type: wtap_file heuristic is not for HTTP
])

bad = []
def add(name, entries, e='<'):
    bad.append((name, one(entries, e)))

add('tiff-bad-uint-count', [(256, 4, 2, U32('<', 1, 2))])
add('tiff-bad-uint-type', [(256, 2, 1, b'a\0\0\0'), (257, 5, 1, ('raw', 0))])
add('tiff-bad-array-type', [(258, 2, 2, b'a\0\0\0'), (273, 5, 1, ('raw', 0))])
add('tiff-bad-array-count', [(258, 3, 0, b'')])
add('tiff-bad-string-type', [(269, 3, 1, U16('<', 1))])
add('tiff-bad-string-count', [(269, 2, 0, b'')])
add('tiff-bad-rational-count', [(282, 5, 2, U32('<', 1, 1, 1, 1))])
add('tiff-bad-rational-type', [(282, 4, 1, U32('<', 1))])
add('tiff-zero-denom', [(282, 5, 1, U32('<', 1, 0))])
add('tiff-bad-t6-count', [(293, 4, 2, U32('<', 1, 1))])
add('tiff-bad-t6-type', [(293, 3, 1, U16('<', 1))])
add('tiff-bad-unknown-type', [(990, 99, 1, U32('<', 1))])
add('tiff-bad-unknown-count0', [(990, 4, 0, b'')])
# next IFD offset not above the current one
t = bytearray(one([(256, 4, 1, U32('<', 1))]))
t[8 + 2 + 12:8 + 2 + 16] = struct.pack('<I', 8)
bad.append(('tiff-bad-next-ifd', bytes(t)))
# truncated: entry count larger than the data
bad.append(('tiff-trunc-ifd', b'II*\0\x08\0\0\0\x10\0\x00\x01'))
# lead IFD offset past the end
bad.append(('tiff-bad-lead-ifd', b'II*\0\xff\x00\0\0' + b'\0' * 8))
# value offset past the end of the data
bad.append(('tiff-bad-value-offset', one([(258, 3, 3, ('raw', 0xfff0)), (282, 5, 1, ('raw', 0xfff0))])))
for n, d in bad:
    w(n + '.tif', d)
# media type image/tiff but not a TIFF: too short, unknown byte order, magic is not 42
bad.append(('x1', b'II*'))
bad.append(('x2', b'XX*\0' + b'\0' * 16))
bad.append(('x3', b'II\x2b\0' + b'\0' * 16))
http_pcap('tiff-coverage-malformed.pcap', [('image/tiff', d) for n, d in bad])
