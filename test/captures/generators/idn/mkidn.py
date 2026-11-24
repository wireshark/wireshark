#!/usr/bin/env python3
# Generates test/captures/idn_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic IDN (ILDA Digital Network) coverage captures
(UDP 7255). Usage: mkidn.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from c9lib import pcap, udp_frame

A, B = '192.0.2.1', '192.0.2.2'
frames = []
marks = []

def send(payload, src=A, dst=B, sp=7255, dp=7255):
    frames.append(udp_frame(src, dst, sp, dp, payload, len(frames) + 1))

def mark(name):
    marks.append((len(frames) + 1, name))

def hdr(cmd, seq=0, flags=0):
    return struct.pack('>BBH', cmd, flags, seq)

def msg(chunk, cfg=None, dic=b'', chdr=b'', data=b'', ch=1, cclf=None, total=None,
        ts=0, cmd=0x40, seq=0):
    """IDN message: channel message header, optional configuration header
    (cfg = (scwc, cfl, service id, service mode)), dictionary, chunk
    header and data. total_size is computed unless given."""
    cnl = 0x80 | ch | (0x40 if (cfg is not None if cclf is None else cclf) else 0)
    body = b''
    if cfg is not None:
        body += struct.pack('>BBBB', *cfg) + dic
    body += chdr + data
    t = 8 + len(body) if total is None else total
    return hdr(cmd, seq) + struct.pack('>HBBI', t, cnl, chunk, ts) + body

def cfl(sdm=1, close=0, routing=0):
    return (sdm << 4) | (close << 1) | routing

def tags(*t):
    return b''.join(struct.pack('>H', x) for x in t)

def chunk_hdr(scm=1, rest=b'\0\0\0'):
    return bytes([scm << 4]) + rest

# laser tags
X, Y, Z, U4 = 0x4200, 0x4210, 0x4220, 0x4201
RED, GREEN, BLUE, U1, U2 = 0x527E, 0x5214, 0x51CC, 0x51BD, 0x5241
PREC, NOP, H0, H1 = 0x4010, 0x4000, 0x4100, 0x4101
WP, INTENSITY, BB = 0x5C00, 0x5C10, 0x5C20
VOID = 0

# ---------- 1. simple commands ----------
mark('simple commands')
send(b'\x00')                                           # VOID
send(hdr(0x08, 1))                                      # PING_REQUEST
send(b'\x09')                                           # PING_RESPONSE
send(hdr(0x10, 2))                                      # SCAN_REQUEST
send(hdr(0x11, 3) + struct.pack('>BBBB', 40, 0x12, 0xf0, 0)  # SCAN_RESPONSE
     + bytes([16, 1]) + bytes(range(1, 15)) + b'Synthetic scanner\0\0\0')
send(hdr(0x11, 4) + struct.pack('>BBBB', 40, 0x01, 0x01, 0)
     + bytes([16, 2]) + bytes(14) + b'Idle unit' + bytes(11))
send(hdr(0x12, 5))                                      # SERVICEMAP_REQUEST
ent = lambda sid, mode, fl, relay, name: struct.pack('>BBBB', sid, mode, fl, relay) + name.ljust(20, b'\0')
send(hdr(0x13, 6) + struct.pack('>BBBB', 4, 24, 1, 2)   # SERVICEMAP_RESPONSE
     + ent(0, 0, 0, 0, b'Relay one') + ent(1, 1, 1, 0, b'Graphic service')
     + ent(2, 5, 0, 1, b'DMX service'))
send(hdr(0x13, 7) + struct.pack('>BBBB', 4, 24, 0, 0))  # empty service map
send(hdr(0x47, 8) + struct.pack('>BBH', 4, 0x00, 0x0000))  # MESSAGE_ACK
send(hdr(0x47, 9) + struct.pack('>BBH', 4, 0xfe, 0x0001))  # ACK with error code
send(hdr(0x20, 10))                                     # unknown command
send(hdr(0x45, 11) + struct.pack('>HBBI', 8, 0x81, 0x00, 5))  # ACKREQ_CLOSE, void
send(hdr(0x44, 12) + struct.pack('>HBBI', 8, 0x82, 0x00, 5))  # CLOSE, void
send(hdr(0x41, 13) + struct.pack('>HBBI', 8, 0x83, 0x00, 5))  # ACKREQ, void

# ---------- 2. StageFeed ----------
mark('stagefeed')
send(b'\x70')
send(b'\x71')
send(struct.pack('>BBHBBBBBBH', 0x78, 0x05, 1, 20, 0x01, 0x07, 3, 4, 2, 7255)
     + bytes([192, 0, 2, 9]) + bytes(16))
send(struct.pack('>BBHBBH', 0x79, 0x05, 1, 8, 0x00, 0))

# ---------- 3. Laser projector (service mode 1, channel 1) ----------
mark('laser')
def laser_cfg(words, dic, ch=1, sdm=1, close=0, routing=0, sid=1, mode=1):
    return (words, cfl(sdm, close, routing), sid, mode), dic

# frame chunk, XY + RGB + intensity, sample size 7
d = tags(X, Y, RED, GREEN, BLUE, INTENSITY, VOID, VOID)
cfg = (4, cfl(1), 1, 1)
samples = bytes(range(7 * 25))
send(msg(0x02, cfg, d, chunk_hdr(1, b'\x00\x00\x10'), samples, ch=1))
# same config, next chunk without config header (config from conversation)
send(msg(0x02, None, b'', chunk_hdr(1, b'\x00\x00\x10'), samples[:7 * 12], ch=1, seq=1))
# first fragment and sequel fragments
send(msg(0x03, None, b'', chunk_hdr(1, b'\x00\x00\x20'), samples[:7 * 5], ch=1, seq=2))
send(msg(0xC0, None, b'', b'', samples[:7 * 3], ch=1, seq=3))     # SEQ
send(msg(0xC0, (4, cfl(1), 1, 1), d, b'', samples[:7 * 3], ch=1, cclf=True, seq=4))  # LAST
# wave samples, 16-bit X Y with precision, colors, hints, NOP, Z, U4
d = tags(X, PREC, Y, PREC, Z, U4, RED, GREEN, BLUE, U1, U2, NOP, H0, H1, WP, BB)
send(msg(0x01, (8, cfl(1, 0, 1), 1, 1), d, chunk_hdr(1, b'\x00\x01\x00'),
         bytes(range(16)) * 3, ch=2))
# breaks, space modifiers, unknown tags and void areas
d = tags(0x1000, 0x100f, 0x1100, 0x11ff, X, Y, 0x2000, 0x7000, 0x0001, 0x0000, 0x53ff, 0x5000, 0x5100, 0x4300, 0x1000)
send(msg(0x02, (7, cfl(1, 1, 0), 3, 1), d, chunk_hdr(1), bytes(range(10)) * 4, ch=3))
# SCM different from the configured SDM is an error: malformed capture only
# configuration with all voids: no sample size
send(msg(0x02, (1, cfl(2), 1, 2), tags(0, 0), chunk_hdr(2), bytes(8), ch=4))
# no samples at all
send(msg(0x02, (1, cfl(1), 1, 1), tags(X, Y), chunk_hdr(1), b'', ch=5))
# message with only the header (total size 8)
send(msg(0x02, None, b'', b'', b'', ch=5, total=8))
# void chunk on a channel with a configuration; void chunk with config header
send(msg(0x00, None, b'', b'', b'', ch=5))
send(msg(0x00, (1, cfl(1), 1, 1), tags(X, Y), b'', b'', ch=6))
# unknown chunk type with and without configuration
send(msg(0x55, None, b'', b'', bytes(4), ch=5))
send(msg(0x55, None, b'', b'', bytes(4), ch=40))
# no configuration for this channel (note)
send(msg(0x02, None, b'', chunk_hdr(1), bytes(8), ch=41))
# SCWC zero: configuration without words (warning)
send(msg(0x02, (0, cfl(1), 1, 1), b'', b'', bytes(8), ch=42))
# a configuration for another source address and the same channel
send(msg(0x02, (2, cfl(1), 1, 1), tags(X, Y, RED, GREEN), chunk_hdr(1), bytes(40), ch=1), src='192.0.2.5')

# ---------- 4. DMX / dimmer levels / octet strings ----------
mark('dmx')
# one range with base and count
dic = bytes([0x43, 0x00, 0x01, 0x20])
send(msg(0x18, (1, cfl(2), 1, 5), dic, chunk_hdr(2), bytes(range(32)), ch=7))
# two ranges, the second without count, padded
dic = bytes([0x43, 0x00, 0x01, 0x10, 0x42, 0x00, 0x21, 0x00])
send(msg(0x18, (2, cfl(2), 1, 5), dic, chunk_hdr(2), bytes(range(16)) + bytes(range(100, 140)), ch=8))
# second configuration for the same channel (config replaced), octet string
dic = bytes([0x43, 0x00, 0x01, 0x0c])
send(msg(0x11, (1, cfl(2), 1, 5), dic, chunk_hdr(2), bytes(range(12)), ch=8))
# unknown tags and unknown octet tags in the dictionary
dic = bytes([0x20, 0x42, 0x00, 0x01])
send(msg(0x18, (1, cfl(2), 1, 6), dic, chunk_hdr(2), bytes(range(5)), ch=9))
dic = bytes([3, 0xaa, 0xbb, 0xcc, 0x42, 0x00, 0x01, 0x20, 0x00])
send(msg(0x18, (2, cfl(2), 1, 6), dic, chunk_hdr(2), bytes(range(7)), ch=10))
# a void tag before the first word, and octet tags after it
send(msg(0x18, (1, cfl(2), 1, 6), bytes([0x00, 0x42, 0x00, 0x01]), chunk_hdr(2), bytes(range(20)), ch=14))
send(msg(0x18, (1, cfl(2), 1, 6), bytes([0x42, 0x00, 0x01, 0x02, 0xaa, 0xbb]), chunk_hdr(2), bytes(range(20)), ch=15))
# range past 512 channels is an error: malformed capture only
# octet segment: chunk header with data sequence and offset, with and without word count
send(msg(0x10, (1, cfl(2), 1, 5), b'', chunk_hdr(2, b'\x01\x00\x20'), bytes(range(40)), ch=12))
send(msg(0x10, (1, cfl(2), 1, 5), b'', chunk_hdr(2, b'\x11\x00\x20'), bytes(range(16)), ch=12))
send(msg(0x10, (0, cfl(2), 1, 5), b'', chunk_hdr(2, b'\x00\x00\x00'), bytes(range(5)), ch=13))
send(msg(0x10, None, b'', chunk_hdr(2, b'\x02\x00\x10'), bytes(range(3)), ch=13))

# ---------- 5. Audio (service mode 0x0c) ----------
mark('audio')
def audio(cat, dic_tags, samples, flags=0x10, duration=10, ch=20, words=1, total=None, cfgh=True, mode=0x0c):
    d = tags(*dic_tags)
    a = struct.pack('>B', flags) + duration.to_bytes(3, 'big')
    cfg = (words, cfl(1), 1, mode) if cfgh else None
    return msg(0x20, cfg, d if cfgh else b'', b'', a + samples, ch=ch, total=total)

# category 8 (8 bit channel count), 16 bit format, 2 channels, 25 samples
send(audio(8, [0x8100 | 2, 0x0000], bytes(range(100)), ch=20))
# next message on that channel without a config header, 5 samples
send(audio(8, [], bytes(range(20)), ch=20, cfgh=False))
# 8 bit format, 3 channels
send(audio(8, [0x8003, 0x0000], bytes(range(30)), ch=21))
# 24 bit format, 2 channels, 12 samples
send(audio(8, [0x8202, 0x0000], bytes(range(72)), ch=22))
# unknown format 3
send(audio(8, [0x8302, 0x0000], bytes(range(16)), ch=23))
# category 6 layouts
for lay, chans, n in ((1, 6, 6), (1, 8, 8), (1, 4, 4), (3, 8, 8), (0, 1, 1), (0, 2, 2), (0, 3, 3),
                      (0, 4, 4), (0, 5, 5), (0, 7, 7), (0, 9, 9), (2, 2, 2)):
    send(audio(6, [0x6000 | (lay << 4 | chans), 0x0000], bytes(range(n * 12)), ch=24))
# category 0 and an unknown category, in one dictionary
send(audio(0, [0x0123, 0x3456], bytes(10), ch=25, words=1))
send(audio(0, [0x0123, 0x0000], bytes(10), ch=26, words=1))
# category 6 then category 0 tag (config->audio_category is the last one)
send(audio(0, [0x6011, 0x0123], bytes(10), ch=27))
# audio header without a duration, odd flags
send(audio(8, [0x8001, 0x0000], bytes(10), ch=28, duration=0, flags=0x30))
# sample count claims fewer samples than are present (size mismatch warning)
send(audio(8, [0x8101, 0x0000], bytes(40), ch=29, total=8 + 8 + 4 + 10))
# total size larger than the data: the sample count is clamped to what is there
send(audio(8, [0x8201, 0x0000], bytes(range(40)), ch=32, total=8 + 8 + 4 + 600))
# total size smaller than the headers (clamped to 0 samples)
send(audio(8, [0x8101, 0x0000], bytes(8), ch=30, total=10))
# audio config with zero channels: reproducer of the fix (no sample bytes)
mark('audio reproducer')
send(msg(0x20, (1, cfl(1), 1, 0x0c), tags(0, 0), b'', b'\x00\x00\x00\x01', ch=31, total=0xffff))
# audio without any configuration
send(msg(0x20, None, b'', b'', b'\x00\x00\x00\x01' + bytes(4), ch=50))
# audio with scwc 0
send(msg(0x20, (0, cfl(1), 1, 0x0c), b'', b'', b'\x00\x00\x00\x01' + bytes(4), ch=51))

# ---------- 6. Retransmission of an earlier frame (second pass state) ----------
mark('repeat')
send(msg(0x02, None, b'', chunk_hdr(1, b'\x00\x00\x10'), samples[:7 * 4], ch=1, seq=9))

outdir = sys.argv[1]
pcap(os.path.join(outdir, 'idn-coverage.pcap'), frames)

# ---------- malformed capture ----------
frames = []; marks_main = marks; marks = []
# SCM mismatch (error)
send(msg(0x02, (2, cfl(1), 1, 1), tags(X, Y), chunk_hdr(2), bytes(8), ch=1))
send(msg(0x02, None, b'', chunk_hdr(3), bytes(8), ch=1))
# DMX range beyond 512 channels
send(msg(0x18, (1, cfl(2), 1, 5), bytes([0x43, 0x02, 0x00, 0x20]), chunk_hdr(2), bytes(range(40)), ch=7))
send(msg(0x18, (1, cfl(2), 1, 5), bytes([0x43, 0x01, 0xf8, 0x20]), chunk_hdr(2), bytes(range(40)), ch=7))
# DMX range to the end of 512 channels, no count
send(msg(0x18, (1, cfl(2), 1, 5), bytes([0x42, 0x01, 0xf0, 0x00]), chunk_hdr(2), bytes(range(40)), ch=7))
# truncated headers and dictionaries
send(b'')
send(hdr(0x40)[:2])
send(hdr(0x11) + bytes(10))
send(hdr(0x13) + struct.pack('>BBBB', 4, 24, 3, 3) + bytes(30))
send(hdr(0x47) + b'\x04')
send(hdr(0x40) + struct.pack('>HBBI', 20, 0xc0, 0x02, 0) + struct.pack('>BBBB', 8, 0x10, 1, 1) + tags(X))
send(hdr(0x40) + struct.pack('>HBBI', 20, 0xc0, 0x02, 0) + struct.pack('>BBBB', 1, 0x10, 1, 1))
send(hdr(0x40) + struct.pack('>HBB', 20, 0xc0, 0x02))
send(b'\x78\x00\x00')
send(b'\x79\x00')
# laser samples cut short of the sample size
send(msg(0x02, (2, cfl(1), 1, 1), tags(X, Y, RED, GREEN), chunk_hdr(1), bytes(4), ch=2, total=20))
send(msg(0x02, None, b'', chunk_hdr(1), bytes(10), ch=2))
# DMX dictionary cut short, DMX data cut short
send(msg(0x18, (2, cfl(2), 1, 5), bytes([0x43, 0x00]), b'', b'', ch=8))
send(msg(0x18, None, b'', chunk_hdr(2), bytes(3), ch=7))
# audio cut short
send(msg(0x20, (1, cfl(1), 1, 0x0c), tags(0x8102, 0), b'', b'\x00\x00', ch=9))
send(msg(0x20, (1, cfl(1), 1, 0x0c), tags(0x8102, 0), b'', b'\x00\x00\x00\x01\x00\x00\x00\x00\x00', ch=9, total=8+4+4+8))
send(msg(0x20, (1, cfl(1), 1, 0x0c), tags(0x8102, 0), b'', b'\x00\x00\x00\x01\x00\x00\x00\x00', ch=9, total=8+4+4+40))
pcap(os.path.join(outdir, 'idn-coverage-malformed.pcap'), frames)

if '-v' in sys.argv:
    for n, m in marks_main:
        print(n, m)
