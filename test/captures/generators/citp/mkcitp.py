#!/usr/bin/env python3
# Generates test/captures/citp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Controller Interface
Transport Protocol dissector (packet-citp.c).

CITP is used between lighting consoles, visualisers and media servers.
Every message starts with a 20 octet header ("CITP", version, message
index, message size, part count and index, content type) followed by a
layer: PINF (peer information), SDMX (DMX levels), FPTC (fixture patch),
FSEL (fixture selection), FINF (fixture information), CAEX (capture
extensions) or MSEX (media server extensions, versions 1.0 to 1.2).
CITP runs over UDP ports 4809-4810 and over TCP (found by a heuristic).
Every packet is built from scratch with struct (and zlib for the PNG
images); no captured traffic is used.

Usage: mkcitp.py <output directory>

Writes:
  citp-coverage.pcap            every message type of every layer that
                                decodes cleanly, the SDMX encryption
                                reproducer, the MSEX layers reproducer,
                                CITP over TCP with several PDUs in one
                                segment and a PDU over three segments
  citp-coverage-malformed.pcap  unknown content types and formats, size
                                mismatches, truncated messages, the
                                paths with known dissector bugs (StFr
                                fragments, LSta element names, CAEX JPEG
                                images)
"""

import os
import struct
import sys
import zlib

CONSOLE = (192, 0, 2, 1)
SERVER = (192, 0, 2, 2)
VISUALISER = (192, 0, 2, 3)
TCPPEER = (192, 0, 2, 4)


# --------------------------------------------------------------------------
# Link, IP and transport layers

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src, dst, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return (bytes.fromhex('02000000') + bytes(dst)[2:] + bytes.fromhex('02000000') + bytes(src)[2:]
            + b'\x08\x00' + h + payload)


def udp(payload, sport=4809, dport=4809, src=CONSOLE, dst=SERVER):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(u))
    c = csum(pseudo + u) or 0xffff
    return ipv4(17, u[:6] + struct.pack('>H', c) + u[8:], src, dst)


class Tcp:
    """One TCP connection; segments are sent with PSH/ACK and the right
    sequence numbers in each direction."""
    def __init__(self, a, ap, b, bp):
        self.a, self.ap, self.b, self.bp = a, ap, b, bp
        self.seq = {True: 1000, False: 9000}

    def handshake(self):
        f = []
        for fwd, flags in ((True, 0x02), (False, 0x12), (True, 0x10)):
            f.append(self.seg(b'', fwd, flags))
            if flags & 0x02:
                self.seq[fwd] += 1
        return f

    def seg(self, data, fwd=True, flags=0x18):
        src, sp, dst, dp = (self.a, self.ap, self.b, self.bp) if fwd else (self.b, self.bp, self.a, self.ap)
        ack = self.seq[not fwd] if flags & 0x10 else 0
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN/ACK
        t = (struct.pack('>HHIIBBHHH', sp, dp, self.seq[fwd], ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0)
             + opts + data)
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(pseudo + t)) + t[18:]
        self.seq[fwd] += len(data)
        return ipv4(6, t, src, dst)


# --------------------------------------------------------------------------
# CITP encoding

def u(s):
    """UCS-2 little endian, NUL terminated."""
    return s.encode('utf-16-le') + b'\0\0'


def z(s):
    """UTF-8, NUL terminated."""
    return s.encode('utf-8') + b'\0'


MSG_INDEX = [0]


def citp(content_type, body, size=None, part_count=1, part_index=0):
    MSG_INDEX[0] += 1
    if size is None:
        size = 20 + len(body)
    return (b'CITP' + bytes([1, 0]) + struct.pack('<HIHH', MSG_INDEX[0], size, part_count, part_index)
            + content_type + body)


def msex(ver, ctype, body):
    return citp(b'MSEX', bytes(ver) + ctype + body)


def caex(code, body=b''):
    return citp(b'CAEX', struct.pack('<I', code) + body)


def png1():
    def chunk(t, d):
        return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00')) + chunk(b'IEND', b''))


PNG = png1()
# SOI, a JFIF APP0 segment, EOI
JPEG = (b'\xff\xd8\xff\xe0' + struct.pack('>H', 16) + b'JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00'
        + b'\xff\xd9')

V10, V11, V12 = (1, 0), (1, 1), (1, 2)
UUID = '2b9c1e5a-41f0-4d6e-9a7b-0c3d5e6f7a8b'
assert len(UUID) == 36


def lib_id(level, l1=0, l2=0, l3=0):
    return bytes([level, l1, l2, l3])


def cnt(ver, n):
    """MSEX counts are 8 bit before 1.2 and 16 bit from 1.2."""
    return struct.pack('<H', n) if ver >= V12 else bytes([n])


def versions(*vs):
    return bytes([len(vs)]) + b''.join(bytes(v) for v in vs)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


# --------------------------------------------------------------------------
# Layers

def pinf_frames():
    return [
        # PNam (console), PLoc (media server) on port 4810, an empty message
        udp(citp(b'PINF', b'PNam' + z('Console'))),
        udp(citp(b'PINF', b'PLoc' + struct.pack('<H', 6436) + z('MediaServer') + z('Server 1') + z('Idle')),
            4810, 4810, SERVER, CONSOLE),
        udp(citp(b'PINF', b'')),
    ]


def sdmx_frames():
    caps = [1, 2, 3, 4, 101, 102, 103, 104, 105]
    return [
        udp(citp(b'SDMX', b'Capa' + struct.pack('<H', len(caps)) + struct.pack('<%dH' % len(caps), *caps))),
        udp(citp(b'SDMX', b'Capa' + struct.pack('<H', 0))),
        udp(citp(b'SDMX', b'UNam' + bytes([3]) + z('Stage left'))),
        udp(citp(b'SDMX', b'UNan' + struct.pack('<H', 300) + z('Wide universe'))),
        # Channel blocks without an encryption identifier: the levels go to dmx-chan
        udp(citp(b'SDMX', b'ChBk' + bytes([0, 1]) + struct.pack('<HH', 0, 8) + bytes([0, 32, 64, 96, 128, 160, 192, 255]))),
        udp(citp(b'SDMX', b'ChBl' + bytes([1]) + struct.pack('<HHH', 513, 100, 4) + bytes([1, 2, 3, 4]))),
        udp(citp(b'SDMX', b'ChLs' + struct.pack('<H', 2) + bytes([1]) + struct.pack('<HB', 10, 255)
                 + bytes([2]) + struct.pack('<HB', 511, 0))),
        udp(citp(b'SDMX', b'ChLt' + struct.pack('<H', 1) + struct.pack('<HHB', 1000, 7, 128))),
        udp(citp(b'SDMX', b'SXSr' + z('ArtNet/0/0'))),
        udp(citp(b'SDMX', b'SXUS' + bytes([4]) + z('BSRE1.31/7'))),
        udp(citp(b'SDMX', b'SXUT' + struct.pack('<H', 1024) + z('Net2/1'))),
    ]


def sdmx_enid_frames():
    """The reproducer of the SDMX encryption fix (the review
    citp_sdmx_enid_state.py, on its own conversation), plus the same
    identifier again and a wide channel block."""
    chbk = b'ChBk' + bytes([0, 1]) + struct.pack('<HH', 0, 4) + bytes([1, 2, 3, 4])
    src = VISUALISER
    return [
        udp(citp(b'SDMX', chbk), src=src),                     # plain levels
        udp(citp(b'SDMX', b'EnId' + z('KeyA')), src=src),
        udp(citp(b'SDMX', chbk), src=src),                     # encrypted with KeyA
        udp(citp(b'SDMX', b'EnId' + z('KeyB')), src=src),
        udp(citp(b'SDMX', b'EnId' + z('KeyB')), src=src),      # the same identifier again
        udp(citp(b'SDMX', b'ChBl' + bytes([0]) + struct.pack('<HHH', 2, 0, 3) + b'\xaa\xbb\xcc'),
            src=src),                                          # encrypted with KeyB
    ]


def fptc_frames():
    return [
        udp(citp(b'FPTC', b'Ptch' + struct.pack('<I', 0) + struct.pack('<HBBHH', 17, 2, 0, 100, 16)
                 + z('Martin') + z('MAC Aura'))),
        udp(citp(b'FPTC', b'UPtc' + struct.pack('<I', 1) + struct.pack('<H', 0))),
        udp(citp(b'FPTC', b'UPtc' + struct.pack('<I', 2) + struct.pack('<HHH', 2, 17, 18))),
        udp(citp(b'FPTC', b'SPtc' + struct.pack('<I', 3) + struct.pack('<HHHH', 3, 1, 2, 3))),
    ]


def fsel_frames():
    return [
        udp(citp(b'FSEL', b'Sele' + bytes([1, 0]) + struct.pack('<HHH', 2, 17, 18))),
        udp(citp(b'FSEL', b'Sele' + bytes([0, 0]) + struct.pack('<HH', 1, 19))),
        udp(citp(b'FSEL', b'DeSe' + struct.pack('<H', 0))),
        udp(citp(b'FSEL', b'DeSe' + struct.pack('<HH', 1, 17))),
    ]


def finf_frames():
    return [
        udp(citp(b'FINF', b'SFra' + struct.pack('<H', 0))),
        udp(citp(b'FINF', b'SFra' + struct.pack('<HHH', 2, 17, 18))),
        # two filters, two gobos
        udp(citp(b'FINF', b'Fram' + struct.pack('<HBB', 17, 2, 2) + z('Red\nBlue\nStars\nBreakup')),
            src=SERVER, dst=CONSOLE),
        # a filter only
        udp(citp(b'FINF', b'Fram' + struct.pack('<HBB', 18, 1, 0) + z('CTO')), src=SERVER, dst=CONSOLE),
    ]


def view_inner():
    return struct.pack('<HH', 640, 480) + struct.pack('<3f', 1.0, 2.0, 3.0) + struct.pack('<3f', 0.0, 0.0, -1.0)


def fixture_idents():
    return (bytes([5]) + struct.pack('<H', 2) + struct.pack('<H', 0x4d50)
            + bytes([0]) + struct.pack('<H', 2) + struct.pack('<H', 0x0102)
            + bytes([1]) + struct.pack('<H', 8) + struct.pack('<Q', 0x0102030405060708)
            + bytes([2]) + struct.pack('<H', 16) + bytes(range(16))
            + bytes([3]) + struct.pack('<H', 16) + bytes(range(16, 32))
            + bytes([4]) + struct.pack('<H', 16) + bytes(range(32, 48)))


def pos_angles():
    return struct.pack('<3f', 1.5, 2.5, 3.5) + struct.pack('<3f', 0.0, 90.0, 180.0)


def caex_frames():
    f = []
    a = lambda code, body=b'': f.append(udp(caex(code, body), src=VISUALISER, dst=CONSOLE))
    a(0xFFFFFFFF, bytes([3]))                                  # NAck
    a(0x00000100)                                              # Get Live View Status
    a(0x00000101, bytes([1]) + view_inner())                   # Live View Status
    a(0x00000200, bytes([1]) + view_inner())                   # Get Live View Image
    a(0x00000201, bytes([1]) + struct.pack('<I', 0))           # Live View Image, JPEG, empty
    a(0x00010100, bytes([1, 2]) + u('Name') + u('') + u('Cue name') + u('Mode') + u('Merge\tReplace') + u('Record mode'))
    a(0x00010200, bytes([2]) + u('Name') + u('Opening') + u('Mode') + u('Merge'))
    a(0x00010300, bytes([2]))                                  # Set Recorder Clearing Capabilities
    a(0x00010400)                                              # Clear Recorder
    a(0x00020102, bytes([2]))                                  # Show Sync Version
    a(0x00020100, u('Summer Show'))                            # Enter Show
    a(0x00020103, z('Winter Show'))                            # Enter Show V2
    a(0x00020101)                                              # Leave Show
    a(0x00020150, bytes([1]))                                  # Set Fixture Transformation Space
    a(0x00020200)                                              # Fixture List Request
    # Fixture List: every identifier type and every field
    fix = (struct.pack('<I', 101) + u('Martin') + u('MAC Aura') + u('Mode 1') + struct.pack('<H', 14)
           + bytes([0, 6]) + fixture_idents()
           + bytes([1, 2]) + struct.pack('<H', 101) + u('U1') + struct.pack('<H', 5) + u('C7') + u('FOH')
           + pos_angles())
    dim = (struct.pack('<I', 102) + u('Generic') + u('Dimmer') + u('') + struct.pack('<H', 1)
           + bytes([1, 0]) + bytes([0, 0]) + struct.pack('<H', 0) + u('') + struct.pack('<H', 0) + u('') + u('')
           + pos_angles())
    a(0x00020201, bytes([1]) + struct.pack('<H', 2) + fix + dim)
    a(0x00020201, bytes([0]) + struct.pack('<H', 0))           # empty list
    # Fixture List V2: UTF-8 strings, 16-bit universe, purpose, focus, external id
    fix2 = (struct.pack('<I', 201) + bytes([1]) + struct.pack('<HH', 1000, 1) + z('Unit 9') + struct.pack('<H', 9)
            + z('C9') + z('Wash') + z('Centre') + z('Note') + z('EXT-201') + pos_angles())
    a(0x00020205, struct.pack('<H', 1) + fix2)
    # Fixture Modify: nothing changed, everything changed, patch and note
    a(0x00020202, struct.pack('<H', 3)
      + struct.pack('<IB', 101, 0x00)
      + struct.pack('<IB', 102, 0x3f) + bytes([1, 3]) + struct.pack('<H', 50) + u('U2') + struct.pack('<H', 6)
      + u('C8') + u('moved') + pos_angles()
      + struct.pack('<IB', 103, 0x11) + bytes([0, 0]) + struct.pack('<H', 0) + u('n'))
    # Fixture Modify V2 (every field, there is no changed fields mask)
    a(0x00020206, struct.pack('<H', 1) + fix2)
    a(0x00020203, struct.pack('<HII', 2, 101, 102))           # Fixture Remove
    a(0x00020204, struct.pack('<H', 1) + bytes(range(48, 64)) + struct.pack('<I', 101))  # Fixture Identify
    a(0x00020300, struct.pack('<HI', 1, 102))                 # Fixture Selection
    a(0x00020300, struct.pack('<H', 0))                       # Fixture Selection, none
    a(0x00020400, struct.pack('<H', 2) + struct.pack('<IBB', 101, 1, 0) + struct.pack('<IBB', 102, 0, 1))
    a(0x00030100)                                              # Get Laser Feed List
    a(0x00030101, struct.pack('<IB', 0xcafe, 2) + u('Feed A') + u('Feed B'))
    a(0x00030102, bytes([1, 30]))                              # Laser Feed Control
    a(0x00030200, struct.pack('<IBIH', 0xcafe, 1, 77, 2)
      + bytes([0x34, 0x12, 0xab]) + struct.pack('<H', 0x7fff)
      + bytes([0xff, 0xff, 0xff]) + struct.pack('<H', 0x0000))
    return f


def msex_frames():
    f = []
    m = lambda ver, ct, body, src=SERVER, dst=CONSOLE: f.append(udp(msex(ver, ct, body), src=src, dst=dst))
    # CInf (client), SInf 1.0 (the MSEX layers reproducer: no layers and
    # two layers), SInf 1.2 with every field, Nack
    m(V12, b'CInf', versions(V10, V11, V12), CONSOLE, SERVER)
    m(V12, b'CInf', versions(), CONSOLE, SERVER)
    m(V10, b'SInf', u('Srv') + bytes([1, 2]) + bytes([0]))
    m(V10, b'SInf', u('Srv') + bytes([1, 2]) + bytes([2]) + z('dmx:1') + z('dmx:2'))
    m(V12, b'SInf', z(UUID) + u('Media Server') + bytes([3, 4, 5]) + versions(V11, V12)
      + struct.pack('<H', 0x01ff) + bytes([3]) + b'RGB8JPEGPNG ' + bytes([2]) + b'fJPGfPNG'
      + bytes([1]) + z('ArtNet/0/0/1'))
    m(V12, b'SInf', z(UUID) + u('') + bytes([1, 0, 0]) + versions() + struct.pack('<H', 0) + bytes([0, 0, 0]))
    m(V11, b'Nack', b'GELI')
    # LSta with no layers (layers decode with a wrong element name
    # encoding, see the malformed capture)
    m(V12, b'LSta', bytes([0]))
    # GELI: 1.0 all libraries, 1.0 two libraries, 1.1 with a parent at
    # every level, 1.2 (16-bit count)
    m(V10, b'GELI', bytes([1, 0]), CONSOLE, SERVER)
    m(V10, b'GELI', bytes([2, 2, 0, 1]), CONSOLE, SERVER)
    m(V11, b'GELI', bytes([1]) + lib_id(0) + bytes([0]), CONSOLE, SERVER)
    m(V11, b'GELI', bytes([1]) + lib_id(1, 4) + bytes([1, 7]), CONSOLE, SERVER)
    m(V11, b'GELI', bytes([1]) + lib_id(2, 4, 5) + bytes([0]), CONSOLE, SERVER)
    m(V12, b'GELI', bytes([3]) + lib_id(3, 4, 5, 6) + struct.pack('<H', 1) + bytes([9]), CONSOLE, SERVER)
    # ELIn: 1.0 (numbers), 1.1 (ids, sub counts), 1.2 (serial numbers,
    # 16-bit counts); a library without a name
    m(V10, b'ELIn', bytes([1]) + bytes([2])
      + bytes([0, 0, 255]) + u('Clips') + bytes([12])
      + bytes([1, 0, 255]) + u('') + bytes([0]))
    m(V11, b'ELIn', bytes([2]) + bytes([1]) + lib_id(1, 1) + bytes([0, 127]) + u('Effects') + bytes([2, 30]))
    m(V12, b'ELIn', bytes([1]) + struct.pack('<H', 1) + lib_id(2, 1, 2) + struct.pack('<I', 1234)
      + bytes([0, 255]) + u('Sub') + struct.pack('<HH', 0, 300))
    m(V10, b'ELIn', bytes([4, 0]))                             # no libraries
    # ELUp: 1.0, 1.2 with affected element and sub arrays
    m(V10, b'ELUp', bytes([1, 3, 0x01]))
    aff_e = bytearray(32); aff_e[0] = 0x81; aff_e[31] = 0x80
    aff_s = bytearray(32); aff_s[1] = 0x02
    m(V12, b'ELUp', bytes([1]) + lib_id(1, 3) + bytes([0x3f]) + bytes(aff_e) + bytes(aff_s))
    m(V12, b'ELUp', bytes([2]) + lib_id(0) + bytes([0]) + bytes(32) + bytes(32))
    # GEIn: all elements, three elements
    m(V10, b'GEIn', bytes([1, 3, 0]), CONSOLE, SERVER)
    m(V11, b'GEIn', bytes([2]) + lib_id(1, 1) + bytes([3, 1, 2, 3]), CONSOLE, SERVER)
    # MEIn: 1.0 and 1.2 (serial numbers), EEIn with and without
    # parameters, GLIn 1.1 (no library type) and 1.2 (library type)
    ts = struct.pack('<II', 1700000000, 500000000)
    m(V10, b'MEIn', bytes([3, 1]) + bytes([1, 0, 255]) + u('Clouds') + ts + struct.pack('<HHIB', 1920, 1080, 3000, 25))
    m(V12, b'MEIn', lib_id(1, 3) + struct.pack('<H', 1) + bytes([2]) + struct.pack('<I', 99) + bytes([0, 255])
      + u('Fire') + ts + struct.pack('<HHIB', 1280, 720, 100, 60))
    m(V10, b'MEIn', bytes([3, 0]))
    m(V11, b'EEIn', lib_id(1, 2) + bytes([2])
      + bytes([1, 0, 127]) + u('Blur') + bytes([2]) + u('Radius') + u('Angle')
      + bytes([2, 128, 255]) + u('Invert') + bytes([0]))
    m(V11, b'GLIn', lib_id(1, 5) + bytes([1]) + bytes([1, 0, 255]) + u('Mesh') + ts)
    m(V12, b'GLIn', bytes([9]) + lib_id(1, 5) + struct.pack('<H', 1) + bytes([1]) + struct.pack('<I', 7)
      + bytes([0, 255]) + u('Cube') + ts)
    # GELT: 1.0 two library numbers, 1.1 all libraries, 1.2 one library id
    m(V10, b'GELT', b'RGB8' + struct.pack('<HH', 64, 48) + bytes([1, 1]) + bytes([2, 1, 2]), CONSOLE, SERVER)
    m(V11, b'GELT', b'JPEG' + struct.pack('<HH', 64, 48) + bytes([0, 1]) + bytes([0]), CONSOLE, SERVER)
    m(V12, b'GELT', b'PNG ' + struct.pack('<HH', 32, 32) + bytes([0, 2]) + struct.pack('<H', 1) + lib_id(1, 1),
      CONSOLE, SERVER)
    # GETh: 1.0 all elements, 1.1 two elements
    m(V10, b'GETh', b'RGB8' + struct.pack('<HH', 64, 48) + bytes([1, 1]) + bytes([3]) + bytes([0]), CONSOLE, SERVER)
    m(V11, b'GETh', b'JPEG' + struct.pack('<HH', 64, 48) + bytes([0, 1]) + lib_id(1, 3) + bytes([2, 4, 5]),
      CONSOLE, SERVER)
    # ELTh with RGB8, JPEG and PNG thumbnails; EThn
    m(V10, b'ELTh', bytes([1, 2]) + b'RGB8' + struct.pack('<HHH', 1, 1, 3) + b'\xff\x00\x00')
    m(V11, b'ELTh', bytes([1]) + lib_id(1, 2) + b'JPEG' + struct.pack('<HHH', 1, 1, len(JPEG)) + JPEG)
    m(V12, b'ELTh', bytes([2]) + lib_id(1, 2) + b'PNG ' + struct.pack('<HHH', 1, 1, len(PNG)) + PNG)
    m(V11, b'EThn', bytes([1]) + lib_id(1, 3) + bytes([4]) + b'PNG ' + struct.pack('<HHH', 1, 1, len(PNG)) + PNG)
    # GVSr, VSrc with two sources and with none
    m(V10, b'GVSr', b'', CONSOLE, SERVER)
    m(V10, b'VSrc', struct.pack('<H', 2)
      + struct.pack('<H', 1) + u('Output 1') + bytes([0, 1]) + struct.pack('<HHH', 0, 1920, 1080)
      + struct.pack('<H', 2) + u('Layer 2') + bytes([255, 2]) + struct.pack('<HHH', 1, 640, 480))
    # RqSt with every format
    for fmt in (b'RGB8', b'JPEG', b'PNG ', b'fJPG', b'fPNG'):
        m(V10, b'RqSt', struct.pack('<H', 1) + fmt + struct.pack('<HHBB', 160, 120, 25, 5), CONSOLE, SERVER)
    # StFr: 1.0 RGB8, 1.1 JPEG, 1.2 PNG (with the server UUID)
    m(V10, b'StFr', struct.pack('<H', 1) + b'RGB8' + struct.pack('<HHH', 1, 1, 3) + b'\x00\x80\xff')
    m(V11, b'StFr', struct.pack('<H', 1) + b'JPEG' + struct.pack('<HHH', 1, 1, len(JPEG)) + JPEG)
    m(V12, b'StFr', UUID.encode() + struct.pack('<H', 2) + b'PNG ' + struct.pack('<HHH', 1, 1, len(PNG)) + PNG)
    return f


def tcp_frames():
    """CITP over TCP (heuristic): two PDUs in one segment, a PDU over
    three segments, and a reply."""
    c = Tcp(CONSOLE, 50000, TCPPEER, 6436)
    f = c.handshake()
    pnam = citp(b'PINF', b'PNam' + z('TCP console'))
    cinf = msex(V12, b'CInf', versions(V11, V12))
    f.append(c.seg(pnam + cinf))
    big = msex(V12, b'StFr', UUID.encode() + struct.pack('<H', 3) + b'PNG ' + struct.pack('<HHH', 1, 1, len(PNG)) + PNG)
    f.append(c.seg(big[:30], False))
    f.append(c.seg(big[30:60], False))
    f.append(c.seg(big[60:], False))
    f.append(c.seg(msex(V12, b'GVSr', b'')))
    # Another connection that the heuristic rejects: a segment shorter
    # than a CITP header and one without the cookie (TCP data)
    d = Tcp(CONSOLE, 50020, TCPPEER, 50021)
    f.append(d.seg(b'short'))
    f.append(d.seg(b'this is not a CITP message'))
    return f


# --------------------------------------------------------------------------
# Malformed capture

def malformed_frames():
    f = []
    add = lambda payload, **kw: f.append(udp(payload, **kw))
    # 1-2: the review citp_msex_misc.py: StFr fJPG (the fragment header
    #      is read from the start of the MSEX data), LSta 1.0 with a layer
    #      (the UCS-2 element name is read as ASCII)
    frag = struct.pack('<IHHI', 7, 2, 1, 1000) + b'\xff\xd8\xff\xd9'
    add(msex(V12, b'StFr', b'0' * 36 + struct.pack('<H', 5) + b'fJPG' + struct.pack('<HHH', 64, 48, len(frag)) + frag))
    add(msex(V10, b'LSta', bytes([1]) + bytes([1, 0, 3, 4]) + u('Clip') + struct.pack('<II', 10, 100)
             + bytes([25]) + struct.pack('<I', 1)))
    # 3: LSta 1.2 with a layer; 4: StFr fPNG
    add(msex(V12, b'LSta', bytes([1]) + bytes([2, 1, 1]) + lib_id(1, 2) + bytes([3]) + u('Fire')
             + struct.pack('<II', 0, 50) + bytes([30]) + struct.pack('<I', 0x3f)))
    frag = struct.pack('<IHHI', 8, 1, 0, 0) + PNG
    add(msex(V11, b'StFr', struct.pack('<H', 5) + b'fPNG' + struct.pack('<HHH', 1, 1, len(frag)) + frag))
    # 5: CAEX Live View Image with JPEG data (the data is not counted in
    #    the consumed length); 6: an image format other than JPEG;
    #    7: Get Live View Image with format 2
    add(caex(0x00000201, bytes([1]) + struct.pack('<I', len(JPEG)) + JPEG))
    add(caex(0x00000201, bytes([2]) + struct.pack('<I', 4) + b'data'))
    add(caex(0x00000200, bytes([2]) + view_inner()))
    # 8: a fixture identifier of unknown type 9
    add(caex(0x00020201, bytes([1]) + struct.pack('<H', 1) + struct.pack('<I', 1) + u('M') + u('N') + u('')
             + struct.pack('<H', 1) + bytes([0, 1]) + bytes([9]) + struct.pack('<H', 2) + b'\x01\x02'
             + bytes([0, 0]) + struct.pack('<H', 0) + u('') + struct.pack('<H', 0) + u('') + u('') + pos_angles()))
    # 9: unknown CITP content type; 10-16: unknown content type of every layer
    add(citp(b'XXXX', b'abcd'))
    add(citp(b'PINF', b'PXxx'))
    add(citp(b'SDMX', b'Xxxx'))
    add(citp(b'FPTC', b'Xxxx' + struct.pack('<I', 0)))
    add(citp(b'FSEL', b'Xxxx'))
    add(citp(b'FINF', b'Xxxx'))
    add(caex(0x12345678))
    add(msex(V12, b'Xxxx', b''))
    # 17-18: MSEX versions 2.0 and 0.9 (Unrecognised MSEX version)
    add(msex((2, 0), b'GVSr', b''))
    add(msex((0, 9), b'GVSr', b''))
    # 19-22: unknown thumbnail and stream formats
    add(msex(V10, b'GELT', b'GIF8' + struct.pack('<HH', 1, 1) + bytes([0, 1]) + bytes([0])))
    add(msex(V10, b'ELTh', bytes([1, 2]) + b'GIF8' + struct.pack('<HHH', 1, 1, 2) + b'\0\0'))
    add(msex(V10, b'RqSt', struct.pack('<H', 1) + b'H264' + struct.pack('<HHBB', 1, 1, 1, 1)))
    add(msex(V10, b'StFr', struct.pack('<H', 1) + b'H264' + struct.pack('<HHH', 1, 1, 2) + b'\0\0'))
    # 23: message size larger than the data consumed (PNam followed by
    #     junk); 24: message size past the end of the packet
    add(citp(b'PINF', b'PNam' + z('x') + b'junk'))
    add(citp(b'PINF', b'PNam' + z('x'), size=200))
    # 25: FINF Fram without names (the NUL is not consumed)
    add(citp(b'FINF', b'Fram' + struct.pack('<HBB', 1, 0, 0) + b'\0'))
    # 26: a ChBk with a channel count past the end; 27: ChLs cut short
    add(citp(b'SDMX', b'ChBk' + bytes([0, 1]) + struct.pack('<HH', 0, 512) + b'\x01\x02'))
    add(citp(b'SDMX', b'ChLs' + struct.pack('<H', 5) + bytes([1, 0])))
    # 28: CITP header cut short; 29: not CITP (data); 30: 3 octets
    add(citp(b'PINF', b'PNam' + z('x'))[:14])
    add(b'NOPE' + bytes(30))
    add(b'CIT')
    # 31-32: CAEX cue capabilities and fixture list cut short
    add(caex(0x00010100, bytes([1, 5]) + u('Name')))
    add(caex(0x00020201, bytes([1]) + struct.pack('<H', 3) + struct.pack('<I', 1)))
    # 33: MSEX element information with 200 elements and one present
    add(msex(V10, b'MEIn', bytes([3, 200]) + bytes([1, 0, 255]) + u('x')))
    # 34: SDMX EnId without a NUL terminator
    add(citp(b'SDMX', b'EnId' + b'Key'), src=VISUALISER, sport=4810)
    # 35: VSrc without sources (the empty source list is added with
    #     length -1 at the end of the message and throws)
    add(msex(V10, b'VSrc', struct.pack('<H', 0)))
    # 36-39: TCP: a segment of 11 octets after the heuristic matched,
    #        then octets that are not CITP
    c = Tcp(CONSOLE, 50010, TCPPEER, 6437)
    f.append(c.seg(citp(b'PINF', b'PNam' + z('t'))))
    f.append(c.seg(b'CITP\x01\x00\x01\x00\x30\x00\x00'))
    f.append(c.seg(b'\x00' * 20))
    f.append(c.seg(b'garbage!'))
    return f


def main_capture(out):
    frames = (pinf_frames() + sdmx_frames() + sdmx_enid_frames() + fptc_frames() + fsel_frames()
              + finf_frames() + caex_frames() + msex_frames() + tcp_frames())
    write_pcap(os.path.join(out, 'citp-coverage.pcap'), frames)


def malformed_capture(out):
    write_pcap(os.path.join(out, 'citp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(out)
    malformed_capture(out)
