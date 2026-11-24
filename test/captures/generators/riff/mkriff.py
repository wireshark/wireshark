#!/usr/bin/env python3
# Generates test/captures/riff_coverage.pcap.gz, riff_coverage.wav.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic RIFF coverage files for file-riff.c.

usage: mkriff.py <outdir> [-v]
riff-coverage.wav (main: WAVE with several chunks), riff-coverage.avi,
riff-coverage.webp, riff-coverage-http.pcap (HTTP: every registered media
type) and riff-coverage-malformed.pcap.  The data is a few bytes of
silence, not a real recording.
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


def ck(cid, data):
    d = cid + struct.pack('<I', len(data)) + data
    return d + (b'\0' if len(data) & 1 else b'')


def riff(form, *chunks, size=None):
    body = form + b''.join(chunks)
    return b'RIFF' + struct.pack('<I', len(body) if size is None else size) + body


FMT = ck(b'fmt ', struct.pack('<HHIIHH', 1, 1, 8000, 8000, 1, 8))
wav = riff(b'WAVE', FMT, ck(b'LIST', b'INFOISFT\x0e\0\0\0synthetic test\0\0'),
           ck(b'fact', struct.pack('<I', 8)), ck(b'data', b'\x80' * 8), ck(b'junk', b'\0\0\0\0'))
w('riff-coverage.wav', wav)

avih = ck(b'avih', struct.pack('<IIIIIIIIIIIIII', 40000, 0, 0, 0x10, 1, 0, 1, 0, 2, 2, 0, 0, 0, 0))
avi = riff(b'AVI ', ck(b'LIST', b'hdrl' + avih), ck(b'LIST', b'movi' + ck(b'00dc', b'\0\0')),
           ck(b'idx1', struct.pack('<4sIII', b'00dc', 0x10, 4, 2)))
w('riff-coverage.avi', avi)

webp = riff(b'WEBP', ck(b'VP8L', b'\x2f\x00\x00\x00\x00\x00'), ck(b'EXIF', b'II*\0\x08\0\0\0\0\0\0\0'))
w('riff-coverage.webp', webp)

# a RIFF form with no chunks at all, an unknown form with a nested RIFF chunk
w('riff-coverage-empty.riff', riff(b'ABCD'))
w('riff-coverage-nested.riff', riff(b'ZZZZ', ck(b'RIFF', riff(b'WAVE', FMT)[8:]), ck(b'data', b'')))
# trailing bytes after the file size, a file size smaller than the data
w('riff-coverage-size.riff', riff(b'WAVE', FMT, ck(b'data', b'\x80' * 4), size=4))

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
http_pcap('riff-coverage-http.pcap', [
    ('audio/vnd.wave', wav), ('audio/x-wav', wav), ('audio/wav', wav), ('audio/wave', wav),
    ('video/vnd.avi', avi), ('video/avi', avi), ('video/msvideo', avi), ('video/x-msvideo', avi),
    ('image/webp', webp),
])

bad = []
# the dissector does not skip the pad byte of an odd sized chunk (see README):
# real WAV/WebP files with such a chunk are malformed
bad.append(('oddchunk', riff(b'WAVE', FMT, ck(b'junk', b'\0\0\0'))))
bad.append(('oddwebp', riff(b'WEBP', ck(b'VP8L', b'\x2f\x00\x00\x00\x00'))))
# media type but too short for the magic, or not RIFF: not claimed
bad.append(('short', b'RIF'))
bad.append(('notriff', b'RIFX' + b'\0' * 20))
# chunk size larger than the data
bad.append(('chunk-size', riff(b'WAVE', b'fmt ' + struct.pack('<I', 500) + b'\0' * 8)))
# a chunk header cut after the id
bad.append(('chunk-hdr', riff(b'WAVE', b'fmt ')))
bad.append(('chunk-hdr2', riff(b'WAVE', b'data\x04\0')))
# file size larger than the data (the form chunk subset is cut)
bad.append(('file-size', riff(b'WAVE', FMT, size=0x1000)))
# an odd sized chunk without the pad byte: the next header is misaligned
bad.append(('nopad', riff(b'WAVE', b'junk' + struct.pack('<I', 3) + b'abc', ck(b'data', b'\0\0'))))
# the header cut after the size field
bad.append(('hdr', b'RIFF\x04\0\0\0'))
for n, d in bad:
    w('riff-bad-%s.riff' % n, d)
http_pcap('riff-coverage-malformed.pcap', [('audio/wav', d) for n, d in bad])
