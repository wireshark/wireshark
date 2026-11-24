#!/usr/bin/env python3
# Generates test/captures/cigi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Common Image Generator
Interface dissector (packet-cigi.c).

CIGI has no registered port and its heuristic is disabled by default, so
the captures are dissected with "-d udp.port==8004,cigi". The host
(192.0.2.1, port 8005) sends to the image generator (192.0.2.2, port
8004) and the IG answers. Every CIGI message (UDP datagram) starts with
an IG Control or Start of Frame packet that gives the version:

  CIGI 2 and 3: packet id (1 octet), packet size (1 octet), version at
                offset 2; CIGI 3 adds the byte swap magic at offset 6
                (0x8000 as sent) and from 3.2 on the minor version in the
                high nibble of octet 4 (IG Control) or 5 (Start of Frame).
  CIGI 4:       packet size (2 octets), packet id (2 octets, IG Control 0,
                Start of Frame 0xFFFF), version at offset 4, minor version
                in the high nibble of octet 7; the byte order is that of
                the sender, found from the leftmost octet of the size.

Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcigi.py <output directory>

Writes:
  cigi-coverage.pcap            every packet type of CIGI 2, 3.0, 3.2,
                                3.3 and 4 in both byte orders, user
                                defined / registered / unknown packets,
                                an unknown version (1) and the reproducers
                                of the fixes on the branch
  cigi-coverage-malformed.pcap  frames that are not CIGI, wrong packet
                                sizes, packets cut short
"""

import os
import struct
import sys

HOST = (192, 0, 2, 1)
IG = (192, 0, 2, 2)
HOST_PORT = 8005
IG_PORT = 8004

# ---------------------------------------------------------------- CIGI 2
# (packet id, size) of the fixed size packets
CIGI2_HOST = [
    (2, 56),   # Entity Control
    (3, 20),   # Component Control
    (4, 32),   # Articulated Parts Control
    (5, 32),   # Rate Control
    (6, 36),   # Environment Control
    (7, 44),   # Weather Control
    (8, 32),   # View Control
    (9, 24),   # Sensor Control
    (21, 16),  # Trajectory Definition
    (22, 32),  # Special Effect Definition
    (23, 32),  # View Definition
    (24, 24),  # Collision Detection Segment Definition
    (25, 20),  # Collision Detection Volume Definition
    (41, 32),  # Height Above Terrain Request
    (42, 56),  # Line of Sight Occult Request
    (43, 48),  # Line of Sight Range Request
    (44, 24),  # Height of Terrain Request
]
CIGI2_IG = [
    (102, 24),  # Height Above Terrain Response
    (103, 40),  # Line of Sight Response
    (104, 24),  # Collision Detection Segment Response
    (105, 12),  # Sensor Response
    (106, 24),  # Height of Terrain Response
    (107, 8),   # Collision Detection Volume Response
]

# ---------------------------------------------------------------- CIGI 3
CIGI3_HOST = [
    (2, 48),   # Entity Control
    (3, 24),   # Conformal Clamped Entity Control
    (4, 32),   # Component Control
    (5, 16),   # Short Component Control
    (6, 32),   # Articulated Part Control
    (7, 16),   # Short Articulated Part Control
    (8, 32),   # Rate Control
    (9, 16),   # Celestial Sphere Control
    (10, 32),  # Atmosphere Control
    (11, 48),  # Environmental Region Control
    (12, 56),  # Weather Control
    (13, 24),  # Maritime Surface Conditions Control
    (14, 32),  # Wave Control
    (15, 8),   # Terrestrial Surface Conditions Control
    (16, 32),  # View Control
    (17, 24),  # Sensor Control
    (18, 8),   # Motion Tracker Control
    (19, 24),  # Earth Reference Model Definition
    (20, 24),  # Trajectory Definition
    (21, 32),  # View Definition
    (22, 40),  # Collision Detection Segment Definition
    (23, 48),  # Collision Detection Volume Definition
    (24, 32),  # HAT/HOT Request
    (25, 64),  # Line of Sight Segment Request
    (26, 56),  # Line of Sight Vector Request
    (27, 8),   # Position Request
    (28, 32),  # Environmental Conditions Request
]
CIGI3_SYMBOL_FIXED = [
    (29, 56),  # Symbol Surface Definition
    (33, 8),   # Symbol Clone
    (34, 40),  # Symbol Control
]
CIGI3_IG = [
    (102, 16),  # HAT/HOT Response
    (103, 40),  # HAT/HOT Extended Response
    (104, 16),  # Line of Sight Response
    (105, 56),  # Line of Sight Extended Response
    (106, 24),  # Sensor Response
    (107, 48),  # Sensor Extended Response
    (108, 48),  # Position Response
    (109, 32),  # Weather Conditions Response
    (110, 8),   # Aerosol Concentration Response
    (111, 16),  # Maritime Surface Conditions Response
    (112, 8),   # Terrestrial Surface Conditions Response
    (113, 16),  # Collision Detection Segment Notification
    (114, 16),  # Collision Detection Volume Notification
    (115, 8),   # Animation Stop Notification
    (116, 16),  # Event Notification
]

# ---------------------------------------------------------------- CIGI 4
CIGI4_HOST = [
    (0x01, 48),  # Entity Position
    (0x02, 32),  # Conformal Clamped Entity Position
    (0x03, 40),  # Component Control
    (0x04, 24),  # Short Component Control
    (0x05, 32),  # Articulated Part Control
    (0x06, 24),  # Short Articulated Part Control
    (0x07, 32),  # Velocity Control
    (0x08, 24),  # Celestial Sphere Control
    (0x09, 32),  # Atmosphere Control
    (0x0A, 48),  # Environmental Region Control
    (0x0B, 72),  # Weather Control
    (0x0C, 24),  # Maritime Surface Conditions Control
    (0x0D, 32),  # Wave Control
    (0x0E, 16),  # Terrestrial Surface Conditions Control
    (0x0F, 40),  # View Control
    (0x10, 32),  # Sensor Control
    (0x11, 16),  # Motion Tracker Control
    (0x12, 24),  # Earth Reference Model Definition
    (0x13, 32),  # Acceleration Control
    (0x14, 40),  # View Definition
    (0x15, 40),  # Collision Detection Segment Definition
    (0x16, 48),  # Collision Detection Volume Definition
    (0x17, 40),  # HAT/HOT Request
    (0x18, 72),  # Line of Sight Segment Request
    (0x19, 64),  # Line of Sight Vector Request
    (0x1A, 8),   # Position Request
    (0x1B, 32),  # Environmental Conditions Request
    (0x1C, 64),  # Symbol Surface Definition
    (0x20, 16),  # Symbol Clone
    (0x21, 48),  # Symbol Control
    (0x22, 24),  # Short Symbol Control
    (0x25, 16),  # Entity Control
    (0x26, 16),  # Animation Control
]
CIGI4_IG = [
    (0x0FF1, 24),  # Event Notification
    (0x0FF2, 8),   # Animation Stop Notification
    (0x0FF3, 16),  # Collision Detection Volume Notification
    (0x0FF4, 24),  # Collision Detection Segment Notification
    (0x0FF5, 16),  # Terrestrial Surface Conditions Response
    (0x0FF6, 24),  # Maritime Surface Conditions Response
    (0x0FF7, 16),  # Aerosol Concentration Response
    (0x0FF8, 32),  # Weather Conditions Response
    (0x0FF9, 48),  # Position Response
    (0x0FFA, 56),  # Sensor Extended Response
    (0x0FFB, 24),  # Sensor Response
    (0x0FFC, 64),  # Line of Sight Extended Response
    (0x0FFD, 24),  # Line of Sight Response
    (0x0FFE, 40),  # HAT/HOT Extended Response
    (0x0FFF, 16),  # HAT/HOT Response
]


def fill(n, seed):
    """Deterministic filler for the body of a packet."""
    return bytes((seed * 13 + i * 37 + 5) & 0xff for i in range(n))


def f32(v, e):
    return struct.pack(e + 'f', v)


# ------------------------------------------------------------ CIGI 2/3
def p8(pid, size, body=None):
    """A CIGI 2/3 packet with a one octet id and size."""
    if body is None:
        body = fill(size - 2, pid)
    assert len(body) == size - 2, (pid, size, len(body))
    return bytes([pid, size]) + body


def cigi2_igc(frame=1):
    # version 2, database 3, IG mode 1 (operate), tracking, boresight
    return p8(1, 16, struct.pack('>BBBBBBII', 2, 3, 0x58, 0, 0, 0, frame, 1000 * frame))


def cigi2_sof(frame=1):
    return p8(101, 16, struct.pack('>BBBBBBII', 2, 3, 0x40, 0, 0, 0, frame, 1000 * frame))


def cigi2_igm(msg_id, text):
    return p8(108, 4 + len(text), struct.pack('>H', msg_id) + text)


def cigi3_igc(minor, le, frame=1):
    swap = b'\x00\x80' if le else b'\x80\x00'
    e = '<' if le else '>'
    flags = (minor << 4) | 0x05 if minor else 0x05   # IG mode operate, timestamp valid
    if minor >= 3:
        flags |= 0x08                                   # extrapolation enable
    if minor:
        return p8(1, 24, bytes([3, 7, flags, 0]) + swap
                  + struct.pack(e + 'IIII', frame, 100 * frame, frame - 1, 0))
    return p8(1, 16, bytes([3, 7, flags, 0]) + swap + struct.pack(e + 'II', frame, 100 * frame))


def cigi3_sof(minor, le, frame=1):
    swap = b'\x00\x80' if le else b'\x80\x00'
    e = '<' if le else '>'
    flags = (minor << 4) | 0x05 if minor else 0x05
    if minor:
        return p8(101, 24, bytes([3, 7, 0, flags]) + swap
                  + struct.pack(e + 'IIII', frame, 100 * frame, frame - 1, 0))
    return p8(101, 16, bytes([3, 7, 0, flags]) + swap + struct.pack(e + 'II', frame, 100 * frame))


def cigi3_igm(le, msg_id, text):
    e = '<' if le else '>'
    return p8(117, 4 + len(text), struct.pack(e + 'H', msg_id) + text)


def cigi3_symbol_text(le, sym, text):
    e = '<' if le else '>'
    body = struct.pack(e + 'HBBH', sym, 0x25, 2, 0) + f32(0.5, e) + text
    return p8(30, 2 + len(body), body)


def cigi3_symbol_circle(le, sym, ncircles):
    e = '<' if le else '>'
    body = struct.pack(e + 'HBBH', sym, 1, 0, 0xF0F0) + f32(1.0, e) + f32(0.25, e)
    for c in range(ncircles):
        body += b''.join(f32(v, e) for v in (0.1 * c, -0.1 * c, 0.5, 0.25, 0.0, 180.0 + c))
    return p8(31, 2 + len(body), body)


def cigi3_symbol_line(le, sym, nvertices):
    e = '<' if le else '>'
    body = struct.pack(e + 'HBBH', sym, 2, 0, 0xFF00) + f32(2.0, e) + f32(0.5, e)
    for v in range(nvertices):
        body += f32(0.01 * v, e) + f32(-0.01 * v, e)
    return p8(32, 2 + len(body), body)


def cigi3_short_symbol_control(le, sym, sel1, val1, sel2, val2):
    """val is 4 octets (raw) for each attribute."""
    e = '<' if le else '>'
    body = struct.pack(e + 'HBBBB', sym, 0x15, 0, sel1, sel2) + val1 + val2 + bytes(16)
    return p8(35, 32, body)


# --------------------------------------------------------------- CIGI 4
def p16(e, pid, size, body=None):
    if body is None:
        body = fill(size - 4, pid & 0xff ^ pid >> 8)
    assert len(body) == size - 4, (pid, size, len(body))
    return struct.pack(e + 'HH', size, pid) + body


def cigi4_igc(e, minor=2, frame=1):
    # version 4, database 9, IG mode 1, timestamp valid, minor version
    return p16(e, 0x0000, 24, struct.pack(e + 'BBBB', 4, 9, 0, (minor << 4) | 0x05)
               + struct.pack(e + 'IIII', frame, 100 * frame, frame - 1, 0))


def cigi4_sof(e, minor=2, frame=1):
    return p16(e, 0xFFFF, 24, struct.pack(e + 'BBBB', 4, 9, 0, (minor << 4) | 0x05)
               + struct.pack(e + 'IIII', frame, 100 * frame, frame - 1, 0x07))


def cigi4_text(e, sym, text):
    body = struct.pack(e + 'BBH', 0x25, 2, sym) + f32(0.5, e) + text
    return p16(e, 0x1D, 4 + len(body), body)


def cigi4_circle(e, sym, ncircles):
    body = struct.pack(e + 'HHBBH', sym, 0xF0F0, 1, 0, 0) + f32(1.0, e) + f32(0.25, e) + bytes(4)
    for c in range(ncircles):
        body += b''.join(f32(v, e) for v in (0.1 * c, -0.1 * c, 0.5, 0.25, 0.0, 180.0 + c))
    return p16(e, 0x1E, 4 + len(body), body)


def cigi4_polygon(e, sym, nvertices):
    body = struct.pack(e + 'HHBBH', sym, 0xFF00, 2, 0, 0) + f32(2.0, e) + f32(0.5, e) + bytes(4)
    for v in range(nvertices):
        body += f32(0.01 * v, e) + f32(-0.01 * v, e)
    return p16(e, 0x1F, 4 + len(body), body)


def cigi4_circle_textured(e, sym, ncircles):
    body = struct.pack(e + 'HHBBH', sym, 77, 0x03, 0, 0) + bytes(4)
    for c in range(ncircles):
        body += b''.join(f32(v, e) for v in (0.1 * c, -0.1 * c, 0.5, 0.25, 0.0, 360.0,
                                              0.5, 0.5, 0.5, 15.0 * c))
    return p16(e, 0x23, 4 + len(body), body)


def cigi4_polygon_textured(e, sym, nvertices):
    body = struct.pack(e + 'HHBBH', sym, 78, 0x02, 0, 0) + bytes(4)
    for v in range(nvertices):
        body += b''.join(f32(x, e) for v_ in [v] for x in (0.01 * v_, -0.01 * v_, 0.1 * v_, 0.2 * v_))
    return p16(e, 0x24, 4 + len(body), body)


def cigi4_igm(e, msg_id, text):
    body = struct.pack(e + 'HH', msg_id, 0) + text
    return p16(e, 0x0FF0, 4 + len(body), body)


# ------------------------------------------------------------ framing
def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(data, to_ig=True, ident=1):
    src, dst = (HOST, IG) if to_ig else (IG, HOST)
    sport, dport = (HOST_PORT, IG_PORT) if to_ig else (IG_PORT, HOST_PORT)
    uhdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + uhdr + data) or 0xffff
    u = uhdr[:6] + struct.pack('>H', c) + data
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ident & 0xffff, 0,
                     64, 17, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02')
    if not to_ig:
        smac, dmac = dmac, smac
    return dmac + smac + b'\x08\x00' + ip + u


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, (i % 10) * 100000, len(p), len(p)))
            f.write(p)


# ------------------------------------------------------------ captures
def cigi3_frames(minor, le, base):
    """Host frame with every host packet, IG frame with every IG packet."""
    e = '<' if le else '>'
    host = cigi3_igc(minor, le, base)
    for pid, size in CIGI3_HOST:
        host += p8(pid, size, fill(size - 2, pid + base))
    for pid, size in CIGI3_SYMBOL_FIXED:
        host += p8(pid, size, fill(size - 2, pid + base))
    host += cigi3_symbol_text(le, 10, b'ALT 1500 FT')
    host += cigi3_symbol_circle(le, 11, 2)
    host += cigi3_symbol_line(le, 12, 3)
    if minor < 3:
        # Before 3.3 the Short Symbol Control is not dissected (data). The
        # 3.3 one always ends with an error (32 octets defined, 16 read),
        # so it is only in the malformed capture.
        host += p8(35, 32)
    host += p8(201, 8, b'USERDEF\x00'[:6])      # first user defined id
    ig = cigi3_sof(minor, le, base)
    for pid, size in CIGI3_IG:
        ig += p8(pid, size, fill(size - 2, pid + base))
    ig += cigi3_igm(le, 42, b'IG ready\x00')
    ig += p8(255, 6, b'\x01\x02\x03\x04')          # last user defined id
    ig += p8(150, 4, b'\xde\xad')                  # unknown id
    return [udp_frame(host, True, base), udp_frame(ig, False, base)]


def cigi4_frames(le, base):
    e = '<' if le else '>'
    host = cigi4_igc(e, 2, base)
    for pid, size in CIGI4_HOST:
        host += p16(e, pid, size, fill(size - 4, pid + base))
    host += cigi4_text(e, 20, b'HDG 270\x00')
    host += cigi4_circle(e, 21, 2)
    host += cigi4_polygon(e, 22, 3)
    host += cigi4_circle_textured(e, 23, 2)
    host += cigi4_polygon_textured(e, 24, 3)
    host += p16(e, 0x8000, 8, b'LOCL')            # locally defined (first)
    host += p16(e, 0xFFFE, 8, b'locl')            # locally defined (last)
    host += p16(e, 0x1000, 8, b'REGI')            # registered (first)
    host += p16(e, 0x7FFF, 8, b'regi')            # registered (last)
    host += p16(e, 0x0100, 8, b'\xde\xad\xbe\xef')  # unknown id
    ig = cigi4_sof(e, 2, base)
    for pid, size in CIGI4_IG:
        ig += p16(e, pid, size, fill(size - 4, pid + base))
    ig += cigi4_igm(e, 43, b'IG4 ready\x00\x00\x00')
    return [udp_frame(host, True, base), udp_frame(ig, False, base)]


def main_frames():
    frames = []
    # 1-2: CIGI 2 (always big endian)
    host = cigi2_igc(1)
    for pid, size in CIGI2_HOST:
        host += p8(pid, size)
    frames.append(udp_frame(host, True, 1))
    ig = cigi2_sof(1)
    for pid, size in CIGI2_IG:
        ig += p8(pid, size)
    ig += cigi2_igm(7, b'CIGI 2 IG')
    frames.append(udp_frame(ig, False, 1))
    # 3-14: CIGI 3.0, 3.2, 3.3, each big then little endian
    base = 2
    for minor in (0, 2, 3):
        for le in (False, True):
            frames += cigi3_frames(minor, le, base)
            base += 1
    # 15-18: CIGI 4 big then little endian
    frames += cigi4_frames(False, 20)
    frames += cigi4_frames(True, 21)
    # 19: a CIGI 4 message whose first packet is a Start of Frame (IG to host)
    frames.append(udp_frame(cigi4_sof('>', 0, 30) + cigi4_igm('>', 1, b'SOF first\x00\x00\x00'),
                            False, 30))
    # 20: CIGI 1 (no dissector for it: shown with the unknown version tree)
    v1 = bytes([1, 16, 1, 0, 0x40]) + bytes(11) + bytes([101, 12, 1]) + bytes(9) + bytes([7, 4, 0xaa, 0xbb])
    frames.append(udp_frame(v1, True, 31))
    # 21: CIGI 1 starting with a Start of Frame (id 101, 12 octets)
    frames.append(udp_frame(bytes([101, 12, 1]) + bytes(9) + bytes([9, 6, 1, 2, 3, 4]), False, 32))
    # 22-25: reproducer cigi_version_state.py (CIGI 3, 3, 4, 3)
    v3_igc = bytes([1, 16, 3, 0, 0, 0, 0x80, 0x00]) + bytes(8)
    v3_entity = bytes([2, 48]) + bytes(range(46))
    v4_igc = struct.pack('>HHBBBB', 24, 0, 4, 0, 0, 0x20) + bytes(16)
    for i, p in enumerate((v3_igc + v3_entity, v3_igc + v3_entity, v4_igc, v3_igc + v3_entity)):
        frames.append(udp_frame(p, True, 40 + i))
    # 26: reproducer cigi_v3_short_trailer.py frame 2: a 4 octet user
    # defined packet at the end of the message
    frames.append(udp_frame(v3_igc + bytes([201, 4, 0xaa, 0xbb]), True, 44))
    # 27: reproducer cigi_v4_byte_order.py: a big endian Image Generator
    # Message of 272 octets (leftmost octet of the size is not zero)
    msg = b'hello ' * 44
    igm = struct.pack('>HHHH', 0x110, 0x0FF0, 7, 0) + msg[:0x110 - 8]
    frames.append(udp_frame(v4_igc + igm, False, 45))
    # 28: the same in little endian
    v4_igc_le = struct.pack('<HHBBBB', 24, 0, 4, 0, 0, 0x20) + bytes(16)
    igm_le = struct.pack('<HHHH', 0x110, 0x0FF0, 7, 0) + msg[:0x110 - 8]
    frames.append(udp_frame(v4_igc_le + igm_le, False, 46))
    return frames


def malformed_frames():
    frames = []
    e = '>'
    # 1: too short for any version
    frames.append(udp_frame(b'\x01\x10', True, 100))
    # 2-4: version 1 IG Control with the wrong size, IG mode 3, SOF wrong size
    frames.append(udp_frame(bytes([1, 15, 1, 0, 0]) + bytes(10), True, 101))
    frames.append(udp_frame(bytes([1, 16, 1, 0, 0xc0]) + bytes(11), True, 102))
    frames.append(udp_frame(bytes([101, 13, 1]) + bytes(10), True, 103))
    # 5: version 1 IG Control cut before the IG mode
    frames.append(udp_frame(bytes([1, 16, 1, 0]), True, 104))
    # 6: version 1, first packet neither IG Control nor SOF
    frames.append(udp_frame(bytes([7, 16, 1, 0]) + bytes(12), True, 105))
    # 7-11: version 2: IGC wrong size, IGC cut before the mode, IG mode 3,
    # SOF wrong size, other first packet
    frames.append(udp_frame(bytes([1, 17, 2, 0, 0]) + bytes(12), True, 106))
    frames.append(udp_frame(bytes([1, 16, 2, 0]), True, 107))
    frames.append(udp_frame(bytes([1, 16, 2, 0, 0xc0]) + bytes(11), True, 108))
    frames.append(udp_frame(bytes([101, 17, 2]) + bytes(14), True, 109))
    frames.append(udp_frame(bytes([2, 56, 2]) + bytes(53), True, 110))
    # 12-17: version 3: too short for the byte swap, IGC wrong size, IG mode
    # 3, SOF wrong size, other first packet, bad byte swap magic
    frames.append(udp_frame(bytes([1, 16, 3, 0, 0, 0]), True, 111))
    frames.append(udp_frame(bytes([1, 20, 3, 0, 0, 0, 0x80, 0]) + bytes(12), True, 112))
    frames.append(udp_frame(bytes([1, 16, 3, 0, 3, 0, 0x80, 0]) + bytes(8), True, 113))
    frames.append(udp_frame(bytes([101, 20, 3, 0, 0, 0, 0x80, 0]) + bytes(12), True, 114))
    frames.append(udp_frame(bytes([2, 48, 3, 0, 0, 0, 0x80, 0]) + bytes(40), True, 115))
    frames.append(udp_frame(bytes([1, 16, 3, 0, 0, 0, 0x12, 0x34]) + bytes(8), True, 116))
    # 18-25: version 4: no version octet, version not 4, neither octet 0
    # zero, IGC wrong size, IGC cut before the mode, IG mode 3, SOF wrong
    # size, other first packet
    frames.append(udp_frame(struct.pack('>HH', 24, 0), True, 117))
    frames.append(udp_frame(struct.pack('>HHB', 24, 0, 5) + bytes(19), True, 118))
    frames.append(udp_frame(bytes([0x18, 0x18, 0, 0, 4]) + bytes(19), True, 119))
    frames.append(udp_frame(struct.pack('>HHB', 28, 0, 4) + bytes(23), True, 120))
    frames.append(udp_frame(struct.pack('>HHBB', 24, 0, 4, 0), True, 121))
    frames.append(udp_frame(struct.pack('>HHBBBB', 24, 0, 4, 0, 0, 3) + bytes(16), True, 122))
    frames.append(udp_frame(struct.pack('>HHB', 28, 0xFFFF, 4) + bytes(23), True, 123))
    frames.append(udp_frame(struct.pack('>HHB', 48, 0x01, 4) + bytes(43), True, 124))
    # 26: first packet larger than the frame; 27: unknown version 7
    frames.append(udp_frame(bytes([1, 16, 3, 0, 0, 0, 0x80, 0]) + bytes(4), True, 125))
    frames.append(udp_frame(bytes([1, 16, 7, 0, 0, 0]) + bytes(10), True, 126))
    # CIGI 1 (unknown version tree): packet size < 2, IGC size < 3
    frames.append(udp_frame(bytes([1, 16, 1, 0, 0]) + bytes(11) + bytes([7, 1]), True, 127))
    frames.append(udp_frame(bytes([1, 16, 1, 0, 0]) + bytes(11) + bytes([101, 2]), True, 128))
    # CIGI 2: size < 2, a fixed size packet with the wrong size, an IGM
    # shorter than 4, a packet cut short
    frames.append(udp_frame(cigi2_igc() + bytes([2, 1]), True, 129))
    frames.append(udp_frame(cigi2_igc() + p8(3, 24), True, 130))
    frames.append(udp_frame(cigi2_sof() + bytes([108, 3, 0]), False, 131))
    frames.append(udp_frame(cigi2_igc() + p8(2, 56)[:30], True, 132))
    # CIGI 3: size < 2, IGC 3.4 (unknown minor), symbol text without text,
    # IGM without text, a packet cut short, a fixed packet with the wrong size
    frames.append(udp_frame(cigi3_igc(0, False) + bytes([2, 0]), True, 133))
    frames.append(udp_frame(bytes([1, 24, 3, 0, 0x45, 0, 0x80, 0]) + bytes(16), True, 134))
    frames.append(udp_frame(cigi3_igc(3, False) + p8(30, 13, bytes(11)), True, 135))
    frames.append(udp_frame(cigi3_sof(0, False) + p8(117, 5, bytes(3)), False, 136))
    frames.append(udp_frame(cigi3_igc(0, False) + p8(2, 48)[:20], True, 137))
    frames.append(udp_frame(cigi3_igc(2, True) + p8(24, 40, bytes(38)), True, 138))
    # CIGI 4: size < 4, symbol text without text, IGM without text, a
    # packet cut short, an inner IG Control with a wrong size field
    frames.append(udp_frame(cigi4_igc(e) + struct.pack('>HH', 2, 1), True, 139))
    frames.append(udp_frame(cigi4_igc(e) + p16(e, 0x1D, 13, bytes(9)), True, 140))
    frames.append(udp_frame(cigi4_sof(e) + p16(e, 0x0FF0, 9, bytes(5)), False, 141))
    frames.append(udp_frame(cigi4_igc(e) + p16(e, 0x01, 48)[:20], True, 142))
    frames.append(udp_frame(cigi4_igc(e) + p16(e, 0x00, 28, bytes(24)), True, 143))
    # CIGI 4 Symbol Circle Definition with 10 octets after the last circle
    # (the circle loop stops short of the packet size)
    frames.append(udp_frame(cigi4_igc(e) + p16(e, 0x1E, 58, bytes(54)), True, 143))
    # CIGI 2 user definable and unknown packets: always flagged, as
    # cigi2_add_tree() takes the offset from cigi_add_data() on the subset
    frames.append(udp_frame(cigi2_igc() + p8(236, 8, b'USER02'), True, 145))
    frames.append(udp_frame(cigi2_sof() + p8(255, 6, b'\x01\x02\x03\x04'), False, 146))
    frames.append(udp_frame(cigi2_igc() + p8(150, 4, b'\xde\xad'), True, 147))
    # CIGI 3.3 Short Symbol Control (always flagged: 32 octets defined, 16
    # read), one per frame as the loop stops after it: attribute select 9
    # (colour), 5-11 (float) and other (integer), big and little endian
    for le in (False, True):
        e3 = '<' if le else '>'
        for args in ((13, 9, bytes([0x11, 0x22, 0x33, 0x44]), 6, f32(1.5, e3)),
                     (14, 1, struct.pack(e3 + 'I', 7), 9, bytes([0x55, 0x66, 0x77, 0x88])),
                     (15, 11, f32(-2.0, e3), 0, struct.pack(e3 + 'I', 0))):
            frames.append(udp_frame(cigi3_igc(3, le) + cigi3_short_symbol_control(le, *args),
                                    True, 148))
    # The the review fuzz generator's unknown version case
    frames.append(udp_frame(bytes([1, 16, 1, 0, 0]) + bytes(11) + bytes([7, 2, 1, 2]) + bytes(5), True, 144))
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cigi-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cigi-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
