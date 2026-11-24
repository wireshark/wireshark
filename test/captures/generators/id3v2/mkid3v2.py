#!/usr/bin/env python3
# Generates test/captures/id3v2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic ID3v2 coverage captures. ID3v2 tags reach the
dissector in MPEG audio (media type audio/mpeg) carried by HTTP.
Usage: mkid3v2.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import zlib
from c9lib import pcap, Flow

def ss(n):
    return bytes([(n >> 21) & 0x7f, (n >> 14) & 0x7f, (n >> 7) & 0x7f, n & 0x7f])

def frame(fid, data, ver=3, flags=0, size=None):
    n = len(data) if size is None else size
    sz = ss(n) if ver == 4 else struct.pack('>I', n)
    return fid + sz + struct.pack('>H', flags) + data

def tag(frames, ver=3, pad=0, flags=0):
    body = b''.join(frames) + b'\0' * pad
    return b'ID3' + bytes([ver, 0, flags]) + ss(len(body)) + body

def png():
    def ch(t, d):
        return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    return (b'\x89PNG\r\n\x1a\n' + ch(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0))
            + ch(b'IEND', b''))

U16 = b'\xff\xfe'
def u16(s):
    return U16 + s.encode('utf-16-le')

frames = []
marks = []
conn = [0]

def http(body, ctype=b'audio/mpeg', note=''):
    n = conn[0]; conn[0] += 1
    marks.append((len(frames) + 1, note))
    f = Flow(40000 + n, 80, frames, cip='10.0.0.1', sip='10.0.0.2')
    f.open()
    f.c2s(b'GET /song%d.mp3 HTTP/1.1\r\nHost: media.example\r\n\r\n' % n)
    f.s2c(b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype + b'\r\nContent-Length: %d\r\n\r\n' % len(body) + body)
    f.close()

# v2.3: text frames in every encoding, TXXX, COMM, PRIV, UFID, APIC, padding
http(tag([
    frame(b'TIT2', b'\x00Song title'),
    frame(b'TPE1', b'\x03Artist \xc3\xa4'),
    frame(b'TALB', b'\x01' + u16('Album')),
    frame(b'TIT3', b'\x02' + 'Sub'.encode('utf-16-be')),
    frame(b'TCON', b'\x04Genre with unknown encoding'),
    frame(b'TXXX', b'\x00desc\x00value'),
    frame(b'TXXX', b'\x01' + u16('d') + b'\0\0' + u16('v')),
    frame(b'COMM', b'\x00eng' + b'short\x00' + b'a comment'),
    frame(b'COMM', b'\x01eng' + u16('d') + b'\0\0' + u16('text')),
    frame(b'PRIV', b'owner@example.org\x00' + bytes(range(8))),
    frame(b'UFID', b'http://example.org/id\x00' + b'0123456789'),
    frame(b'APIC', b'\x00image/png\x00' + b'\x03' + b'cover\x00' + png()),
    frame(b'APIC', b'\x00image/x-unknown\x00' + b'\x00' + b'\x00' + b'data'),
    frame(b'WXXX', b'\x00desc\x00http://example.org/'),
    frame(b'TPE2', b''  + b'\x00Band'),
], ver=3, pad=20), note='v2.3 tag in HTTP')

# v2.4: synchsafe frame sizes (one over 127 octets), flags, no padding
http(tag([
    frame(b'TIT2', b'\x03' + b'T' * 200, ver=4),
    frame(b'TPE1', b'\x03Artist', ver=4, flags=0x0002),
    frame(b'TSST', b'\x03Subtitle', ver=4),
    frame(b'UFID', b'o\x00', ver=4),
    frame(b'COMM', b'\x03eng\x00', ver=4),
], ver=4, flags=0x10), note='v2.4 tag')

# a tag with only padding after the header (a tag of exactly 10 octets
# is malformed: see the malformed capture)
http(tag([], ver=3, pad=30), note='padding only')

# two tags and a second response with the second tag: v2.2 style version byte
http(tag([frame(b'TIT2', b'\x00one')]) + tag([frame(b'TPE1', b'\x00two')]), note='two tags in one body')

# not accepted by the ID3v2 dissector: too short, size with high bits set (left to the data dissector)
http(b'ID3\x03\x00\x00\x00', note='ID3 tag too short')
http(b'ID3\x03\x00\x00\x00\x00\x00\x80' + bytes(10), note='bad synchsafe size')
# audio/mp3 media type
http(tag([frame(b'TIT2', b'\x00mp3 type')]), ctype=b'audio/mp3', note='audio/mp3')

pcap(os.path.join(sys.argv[1], 'id3v2-coverage.pcap'), frames)

# ---- malformed capture ----
frames = []; main_marks = marks; marks = []; conn[0] = 100
# UFID whose size is smaller than the owner string: the reproducer of the fix
http(tag([frame(b'UFID', b'a\x00', size=0)]), note='UFID size 0')
http(tag([frame(b'UFID', b'owner\x00id', size=3)]), note='UFID size 3')
# a tag of exactly ten octets: the high bit check reads octet 10 (past the tag)
http(tag([], ver=4), note='empty tag')
# frame size beyond the tag
http(tag([frame(b'TIT2', b'\x00short', size=500)]), note='size beyond tag')
http(tag([frame(b'APIC', b'\x00image/png', size=11)]), note='APIC without NUL')
# tag size larger than the data
http(b'ID3\x03\x00\x00' + ss(5000) + frame(b'TIT2', b'\x00x'), note='tag size beyond data')
http(tag([frame(b'COMM', b'\x00en', size=2)]), note='short COMM')
http(tag([frame(b'TIT2', b'', size=0)]), note='empty text frame')
http(tag([frame(b'PRIV', b'abc', size=100)]), note='PRIV beyond tag')
pcap(os.path.join(sys.argv[1], 'id3v2-coverage-malformed.pcap'), frames)
if '-v' in sys.argv:
    for m in main_marks: print(*m)
