#!/usr/bin/env python3
# Generates test/captures/ogg_coverage.ogg.gz, ogg_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic Ogg coverage files for file-ogg.c.

usage: mkogg.py <outdir> [-v]
ogg-coverage.ogg (main: several logical streams, all page flags, segment
tables of every shape), ogg-coverage-http.pcap (HTTP: every registered media
type and the HTTP heuristic) and ogg-coverage-malformed.pcap.  The payload
is made-up bytes, not audio.
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


def _crc_table():
    t = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            r = ((r << 1) ^ 0x04c11db7) if r & 0x80000000 else (r << 1)
            r &= 0xffffffff
        t.append(r)
    return t


CRC = _crc_table()


def ogg_crc(data):
    c = 0
    for b in data:
        c = ((c << 8) & 0xffffffff) ^ CRC[((c >> 24) & 0xff) ^ b]
    return c


def page(segs, flags=0, pos=0, serial=1, seq=0):
    hdr = b'OggS' + bytes([0, flags]) + struct.pack('<qIII', pos, serial, seq, 0) + bytes([len(segs)])
    hdr += bytes(len(s) for s in segs)
    p = hdr + b''.join(segs)
    return p[:22] + struct.pack('<I', ogg_crc(p)) + p[26:]


main = b''.join([
    page([b'\x01vorbis' + b'\0' * 23], 0x02, 0, 1, 0),             # BOS
    page([b'OpusHead\x01\x01' + b'\0' * 9, b''], 0x02, 0, 2, 0),   # BOS, empty segment
    page([b'comment' * 5, b'x' * 255, b'y' * 10], 0x00, 0, 1, 1),
    page([b'z' * 255], 0x00, -1, 2, 1),                             # lacing 255: packet continues
    page([b'rest of the packet'], 0x01, 1024, 2, 2),                # continued packet
    page([], 0x00, 2048, 1, 2),                                     # no segments
    page([b'last'], 0x04, 4096, 1, 3),                              # EOS
    page([b'end'], 0x05, 8192, 2, 3),                               # continued + EOS
])
w('ogg-coverage.ogg', main)

# garbage before and between pages (the sync word search)
sync = (b'\0\1\2\3 junk ' + page([b'a' * 5], 0x02) + b'\xff' * 11 + page([b'b' * 5], 0x04, 9, 1, 1)
        + b'trailer' * 5)
w('ogg-coverage-sync.ogg', sync)
w('ogg-coverage-max.ogg', page([bytes([i % 7]) * (i % 3) for i in range(255)], 0x02) + b'\0' * 30)

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
http_pcap('ogg-coverage-http.pcap', [
    ('audio/ogg', main), ('video/ogg', main), ('application/ogg', main),
    ('audio/x-vorbis+ogg', main), ('audio/x-opus+ogg', main), ('video/theora+ogg', main),
    (None, main),                        # the http heuristic
    ('audio/ogg', sync),
    (None, b'garbage ' + page([b'abc'], 0x02) + b'tail tail tail tail tail tail'),   # heuristic after garbage
    (None, b'No Ogg here, not even 27 bytes'),
])

bad = []
# no capture pattern at all with the media type: expert info
bad.append(('nomagic', b'this is not an ogg file at all, just text' * 2))
# a page whose segment table is cut
bad.append(('cut-table', page([b'a' * 5, b'b' * 5], 0x02)[:40] + b'\0' * 30))
# a page with the segment data shorter than the table says
bad.append(('cut-data', page([b'a' * 100, b'b' * 100], 0x02)[:80] + b'\xaa' * 5))
# "OggS" at the very end: too short for a page header
bad.append(('cut-hdr', page([b'x'], 0x02) + b'OggS' + b'\0' * 10))
for n, d in bad:
    w('ogg-bad-%s.ogg' % n, d)
http_pcap('ogg-coverage-malformed.pcap', [('audio/ogg', d) for n, d in bad])
