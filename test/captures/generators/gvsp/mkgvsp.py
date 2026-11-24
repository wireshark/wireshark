#!/usr/bin/env python3
# Generates test/captures/gvsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the GVSP coverage captures.  Usage: mkgvsp.py <outdir>

Writes gvsp-coverage.pcap (decodes cleanly) and
gvsp-coverage-malformed.pcapng (paths only malformed input reaches, with an
Exported PDU interface).  Everything is synthetic.

GVSP has no port of its own.  Like a real capture, the main capture starts
with the GVCP write of the stream channel destination port register
(UDP 50010) that makes the GVCP dissector register the GVSP dissector for the
port.  A few more frames use UDP ports 55555/55556 that only the (default
disabled) heuristic dissector "gvsp_udp" recognises.
"""
import struct
import socket
import sys
import os

CAM = '192.0.2.2'
HOST = '192.0.2.1'
HMAC = bytes([2, 0, 0, 0, 0, 1])
CMAC = bytes([2, 0, 0, 0, 0, 2])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp_frame(sp, dp, payload, src, dst, smac, dmac):
    u = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return dmac + smac + b'\x08\x00' + h + u


STREAM_PORT = 50010


def stream(payload, dp=STREAM_PORT, sp=40001):
    return udp_frame(sp, dp, payload, CAM, HOST, CMAC, HMAC)


# ----------------------------------------------------------------- headers
def v1(fmt, block, pid, body=b'', status=0):
    return struct.pack('>HHB', status, block, fmt) + struct.pack('>I', pid)[1:] + body


def v2(fmt, block, pid, body=b'', status=0, flags=0, b7=0):
    return struct.pack('>HBBB', status, 0, flags, fmt | 0x80) + b'\0\0' + bytes([b7]) \
        + struct.pack('>QI', block, pid) + body


LEADER, TRAILER, PAYLOAD, ALLIN, PH264, PMZ, PMP, PGENDC = 1, 2, 3, 4, 5, 6, 7, 8
IMAGE, RAW, FILE, CHUNK, EXTCHUNK, JPEG, JPEG2000, H264, MZ, MP, GENDC = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
CB = 0x4000

TS = 0x0000_0001_2345_6789


def aoi(sx=640, sy=480, ox=0, oy=0, px=0, py=0):
    return struct.pack('>IIIIHH', sx, sy, ox, oy, px, py)


def pix(v=0x01080001):
    return struct.pack('>I', v)


def leader_body(pt, fi=(0x00, 0x00), pixfmt=0x01080001, fname=b'image.bin\0'):
    ptb = struct.pack('>H', pt)
    t = pt & 0x3FFF
    ts = struct.pack('>Q', TS)
    if t == IMAGE:
        return bytes(fi) + ptb + ts + pix(pixfmt) + aoi()
    if t == RAW:
        return b'\0\0' + ptb + ts + struct.pack('>Q', 1000)
    if t == FILE:
        return b'\0\0' + ptb + ts + struct.pack('>Q', 1000) + fname
    if t == CHUNK:
        return b'\0\0' + ptb + ts
    if t == EXTCHUNK:
        return bytes(fi) + ptb + ts + pix(pixfmt) + aoi()
    if t in (JPEG, JPEG2000):
        return bytes(fi) + ptb + ts + struct.pack('>QQI', 5000, 1000000000, 0x01)
    if t == H264:
        return bytes(fi) + ptb + struct.pack('>Q', 20000) + b'\0' + bytes([1]) + struct.pack('>H', 1400) \
            + b'\0' + h264common()
    if t == MZ:
        return bytes(fi) + ptb + ts + struct.pack('>I', 0x00000003) + pix(pixfmt) + aoi()
    if t == GENDC:
        return b'\0\0' + ptb + ts + struct.pack('>QII', 4096, 0x80000000, 256)
    raise ValueError(pt)


def h264common():
    return bytes([66, 0xA0, 31]) + struct.pack('>HHII', 3, 4, 5, 6)


def trailer_body(pt, sizey=480):
    ptb = struct.pack('>H', pt)
    t = pt & 0x3FFF
    if t in (IMAGE, MZ):
        return b'\0\0' + ptb + struct.pack('>I', sizey)
    if t == CHUNK:
        return b'\0\0' + ptb + struct.pack('>I', 128)
    if t == EXTCHUNK:
        return b'\0\0' + ptb + struct.pack('>III', 128, sizey, 0x1234)
    return b'\0\0' + ptb


def chunk_info():
    return struct.pack('>II', 64, 0x77)


DATA = bytes(range(16))

frames = []
bad = []        # (idb, bytes) for the pcapng

# --------------------------------------------------- GVCP: learn the port
gvcp_cmd = struct.pack('>BBHHH', 0x42, 1, 0x82, 8, 1) + struct.pack('>II', 0x0d00, STREAM_PORT)
gvcp_ack = struct.pack('>HHHH', 0, 0x83, 4, 1) + struct.pack('>HH', 0, 1)
frames.append(udp_frame(50000, 3956, gvcp_cmd, HOST, CAM, HMAC, CMAC))
frames.append(udp_frame(3956, 50000, gvcp_ack, CAM, HOST, CMAC, HMAC))

blk = [0]


def nb():
    blk[0] += 1
    return blk[0]


# -------------------------------------------- 32 bit ids: one image block
b = nb()
frames.append(stream(v1(LEADER, b, 0, leader_body(IMAGE, fi=(0x80, 0x01)))))
for i in range(1, 4):
    frames.append(stream(v1(PAYLOAD, b, i, DATA * 4)))
frames.append(stream(v1(TRAILER, b, 4, trailer_body(IMAGE))))

# every payload type: leader, payload, trailer, and all-in, each with and
# without the chunk bit; 16 bit block ids
for pt in (IMAGE, RAW, FILE, CHUNK, EXTCHUNK, JPEG, JPEG2000, H264, MZ):
    for cb in (0, CB):
        b = nb()
        t = pt | cb
        frames.append(stream(v1(LEADER, b, 0, leader_body(t, fi=(0x40, 0x02)))))
        if pt == H264:
            frames.append(stream(v1(PH264, b, 1, struct.pack('>Q', TS) + DATA)))
        elif pt == MZ:
            frames.append(stream(v1(PMZ, b, 1, b'\0\x21' + b'\0\0\0\0\x10\x00' + DATA)))
        else:
            frames.append(stream(v1(PAYLOAD, b, 1, DATA)))
        tr = trailer_body(t)
        if cb:
            tr += chunk_info()
        frames.append(stream(v1(TRAILER, b, 2, tr)))
        # all-in: leader and trailer, optional chunk info, data
        body = leader_body(t, fi=(0x00, 0x00)) + trailer_body(t)
        if cb:
            body += chunk_info()
        if pt == H264:
            body += struct.pack('>Q', TS)
        elif pt == MZ:
            body += b'\0\x21' + b'\0\0\0\0\x10\x00'
        frames.append(stream(v1(ALLIN, b, 0, body + DATA)))

# all-in without payload data, a payload type all-in does not know (multi-part)
frames.append(stream(v1(ALLIN, nb(), 0, leader_body(IMAGE) + trailer_body(IMAGE))))
frames.append(stream(v1(ALLIN, nb(), 0, struct.pack('>HH', 0, MP) + bytes(30))))
frames.append(stream(v1(ALLIN, nb(), 0, struct.pack('>HH', 0, 0x0123) + bytes(30))))   # unknown payload type
frames.append(stream(v1(LEADER, nb(), 0, struct.pack('>HH', 0, 0x0123) + bytes(30))))
frames.append(stream(v1(TRAILER, nb(), 0, struct.pack('>HH', 0, 0x0123) + bytes(30))))
frames.append(stream(v1(9, nb(), 0, struct.pack('>HH', 0, IMAGE) + bytes(30))))       # unknown format
frames.append(stream(v1(0, nb(), 0, struct.pack('>HH', 0, IMAGE) + bytes(30))))       # unknown format
frames.append(stream(v1(0x7f, nb(), 0, b'\0\0\0\0\0\0')))                               # unknown format, nothing after the header

# statuses: errors, packet resend without extended ids (no payload) and
# errors with a payload that is not dissected
for st in (0x0100, 0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x8006, 0x8007, 0x8008, 0x8009, 0x800A,
           0x800B, 0x800C, 0x800D, 0x800E, 0x800F, 0x8010, 0x8011, 0x8012, 0x8013, 0x8014, 0x8015,
           0x8016, 0x8017, 0x8FFF):
    frames.append(stream(v1(PAYLOAD, nb(), 3, DATA, status=st)))
for fmt, body in ((PH264, struct.pack('>Q', TS) + DATA), (PMZ, bytes(8) + DATA), (PMP, bytes(8) + DATA)):
    frames.append(stream(v1(fmt, nb(), 3, body, status=0x8001)))
frames.append(stream(v1(PAYLOAD, nb(), 3, b'', status=0)))        # no payload at all
frames.append(stream(v1(PH264, nb(), 3, b'', status=0)))
frames.append(stream(v1(PMZ, nb(), 3, b'', status=0)))
frames.append(stream(v1(PMP, nb(), 3, b'', status=0)))
frames.append(stream(v1(PGENDC, nb(), 3, b'', status=0)))
frames.append(stream(v1(PH264, nb(), 3, struct.pack('>Q', TS) + DATA)))
frames.append(stream(v1(PMZ, nb(), 3, b'\0\x01\0\0\0\0\0\x20' + DATA)))
frames.append(stream(v1(PMP, nb(), 3, b'\x02\x03\0\0\0\0\0\x20' + DATA)))
frames.append(stream(v1(PGENDC, nb(), 3, struct.pack('>IQBBH', 16, 0, 0, 0, 7) + DATA)))   # plain GenDC data

# ------------------------------------- extended ids (64 bit block, 32 bit packet)
for pt in (IMAGE, RAW, FILE, CHUNK, EXTCHUNK, JPEG, JPEG2000, H264, MZ):
    for cb in (0, CB):
        b = nb() + (1 << 33)
        t = pt | cb
        b7 = 3 if pt == MZ else 0
        frames.append(stream(v2(LEADER, b, 0, leader_body(t), b7=b7)))
        tr = trailer_body(t)
        if cb:
            tr += chunk_info()
        frames.append(stream(v2(TRAILER, b, 70000, tr)))
        body = leader_body(t) + trailer_body(t) + (chunk_info() if cb else b'')
        if pt == H264:
            body += struct.pack('>Q', TS)
        elif pt == MZ:
            body += b'\0\x21' + b'\0\0\0\0\x10\x00'
        frames.append(stream(v2(ALLIN, b, 1, body + DATA)))
# flags, packet resend status with a payload, payload packets
b = nb()
frames.append(stream(v2(PAYLOAD, b, 5, DATA, flags=0x01, status=0x0100)))
frames.append(stream(v2(PAYLOAD, b, 6, DATA, flags=0x02)))
frames.append(stream(v2(PAYLOAD, b, 7, DATA, flags=0x04)))
frames.append(stream(v2(PAYLOAD, b, 8, DATA, flags=0x07)))
frames.append(stream(v2(PAYLOAD, b, 9, DATA, status=0x8002)))
frames.append(stream(v2(PH264, b, 5, struct.pack('>Q', TS) + DATA, flags=0x01, status=0x0100)))
frames.append(stream(v2(PMZ, b, 5, b'\0\x40' + b'\0\0\0\0\x30\x00' + DATA)))
frames.append(stream(v2(PMP, b, 5, b'\x01\x40' + b'\0\0\0\0\x30\x00' + DATA)))
frames.append(stream(v2(PAYLOAD, b, 10, b'', status=0)))
frames.append(stream(v2(LEADER, b, 0, leader_body(IMAGE), flags=0x03)))        # leader and flags
frames.append(stream(v2(9, b, 0, bytes(30))))                                     # unknown format

# ------------------------------------------------------------ multi-part
MPTYPES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0A, 0x0B, 0x0C, 0x8000]


def mp_part(t, length=1000):
    p = struct.pack('>H', t) + length.to_bytes(6, 'big')
    if t in (0x0B, 0x0C):
        p += struct.pack('>I', 0x00000001)                  # data format
    elif t in (0x0A, 0x8000):
        p += struct.pack('>I', 0x00000009)
    else:
        p += struct.pack('>I', 0x01080001)                  # pixel format
    p += b'\0\0' + bytes([t & 0xF, 1])                        # reserved, source id, additional zones
    p += struct.pack('>I', 0x00000003)                      # zone direction
    p += struct.pack('>HH', 5, 7)                           # data purpose, region id
    if t in (1, 2, 3, 4, 5, 6, 7, 8, 9):
        p += aoi(320, 200, 4, 8, 1, 2)
        p += bytes(48 - len(p))
    elif t in (0x0B, 0x0C):
        p += bytes([0x80, 0, 0, 0]) + struct.pack('>QI', 1000000000, 1)
        p += bytes(48 - len(p))
    else:
        p += struct.pack('>6I', 1, 2, 3, 4, 5, 6)
    assert len(p) == 48, (t, len(p))
    return p


def mp_trailer_part(t):
    p = struct.pack('>H', t) + (2000).to_bytes(6, 'big')
    if t in (1, 2, 3, 4, 5, 6, 7, 8, 9):
        p += struct.pack('>I', 480) + bytes(4)
    else:
        p += struct.pack('>II', 11, 22)
    assert len(p) == 16
    return p


for parts in (MPTYPES, [1], [0x0B, 1], [0x0A]):
    b = nb() + (1 << 34)
    lead = struct.pack('>HH', 0, MP) + struct.pack('>Q', TS) + b''.join(mp_part(t) for t in parts)
    frames.append(stream(v2(LEADER, b, 0, lead, b7=len(parts))))
    for j, t in enumerate(parts[:3]):
        frames.append(stream(v2(PMP, b, 1 + j, bytes([j, 0x20]) + b'\0\0\0\0\0\0' + DATA)))
    tr = struct.pack('>HH', 0, MP) + b''.join(mp_trailer_part(t) for t in parts)
    frames.append(stream(v2(TRAILER, b, 9, tr)))
# a leader that claims more parts than it holds is limited by the length
b = nb() + (1 << 34)
frames.append(stream(v2(LEADER, b, 0, struct.pack('>HH', 0, MP) + struct.pack('>Q', TS) + mp_part(1), b7=5)))
# multi-part trailer with the payload type only, and with the chunk bit
frames.append(stream(v2(TRAILER, b, 1, struct.pack('>HH', 0, MP))))
frames.append(stream(v2(TRAILER, b, 1, struct.pack('>HH', 0, MP | CB) + mp_trailer_part(1) + chunk_info())))


# ---------------------------------------------------------------- GenDC
def gendc_descriptor(layout):
    """layout: list of components, each a list of part types.  Returns the
    descriptor bytes.  Offsets are relative to the start of the descriptor
    (the code adds 16 to a base that points at the payload header)."""
    ncomp = len(layout)
    pos = 56 + 8 * ncomp
    comp_off = []
    part_blobs = []
    comp_blobs = []
    # first lay out components with their part offset arrays
    placed = []
    for parts in layout:
        comp_off.append(pos)
        pos += 48 + 8 * len(parts)
        placed.append(pos)  # parts of this component start here
        part_sizes = []
        offs = []
        for t in parts:
            offs.append(pos)
            sz = 64 if t in (0x4000, 0x4001, 0x4100) else 52 if t in (0x4200, 0x4201, 0x4202) else 67 if t == 0x4203 else 40
            sz = max(sz, 64)
            pos += sz
            part_sizes.append(sz)
        comp = struct.pack('<HHIHHHHIIQQIHH', 0x2000, 3, 48 + 8 * len(parts), 0, 1, 2, 3, 10, 20, TS, 0x0001,
                           0x01080001, 0, len(parts))
        comp += b''.join(struct.pack('<Q', o) for o in offs)
        comp_blobs.append(comp)
        pb = b''
        for t, sz in zip(parts, part_sizes):
            flags = 0x0002 if t == 0x4001 else 0x0000
            h = struct.pack('<HHIIHHQQQ', t, flags, sz, 0x01080001, 0, 4, 0x10, 0x2000, 0x300)
            if t in (0x4000, 0x4001, 0x4100):
                h += struct.pack('<QIIQ', 4096, 8, 0, 0x5555)
            elif t in (0x4200, 0x4201, 0x4202):
                h += struct.pack('<IIHH', 64, 48, 2, 4)
            elif t == 0x4203:
                h += struct.pack('<IIHH', 64, 48, 2, 4) + bytes([66, 0xA0, 31]) + struct.pack('<HHII', 3, 4, 5, 6)
            h = h.ljust(sz, b'\0')
            pb += h
        part_blobs.append(pb)
    total = pos
    hdr = b'GNDC' + bytes([1, 0, 0, 0]) + struct.pack('<HHI', 0x1000, 0x0001, total)
    hdr += struct.pack('<Q', 0x1122334455667788)
    hdr += struct.pack('<HHIQQII', 0x0003, 0, 0, 100000, total, total, ncomp)
    assert len(hdr) == 56, len(hdr)
    hdr += b''.join(struct.pack('<Q', o) for o in comp_off)
    body = hdr
    for c, p in zip(comp_blobs, part_blobs):
        body += c + p
    assert len(body) == total, (len(body), total)
    return body


def gendc_payload(desc, data_flags=0xE0, flow_flags=0x01):
    return struct.pack('>IQBBH', len(desc), 0, data_flags, flow_flags, 3) + desc


LAYOUT = [[0x4200, 0x4100], [0x4001, 0x4000, 0x4201], [0x4202, 0x4203, 0x9999]]
desc = gendc_descriptor(LAYOUT)
b = nb() + (1 << 35)
frames.append(stream(v2(LEADER, b, 0, leader_body(GENDC))))
frames.append(stream(v2(PGENDC, b, 1, gendc_payload(desc))))
frames.append(stream(v2(PGENDC, b, 2, gendc_payload(b'\0' * 64 + DATA, data_flags=0x00))))     # data
frames.append(stream(v2(PGENDC, b, 3, gendc_payload(b'\0' * 64, data_flags=0x40))))           # descriptor, not start
frames.append(stream(v2(PGENDC, b, 4, gendc_payload(desc, data_flags=0xA0, flow_flags=0x00))))
frames.append(stream(v2(TRAILER, b, 5, struct.pack('>HH', 0, GENDC))))
desc1 = gendc_descriptor([[0x4001]])
frames.append(stream(v2(PGENDC, b, 6, gendc_payload(desc1, data_flags=0x60))))
desc2 = gendc_descriptor([[0x4100], [0x4200], [0x4201]])
frames.append(stream(v2(PGENDC, b, 7, gendc_payload(desc2))))

# ------------------------------------- the heuristic dissector (ports 55555, 55556)
def hstream(payload, dp):
    return udp_frame(40002, dp, payload, CAM, HOST, CMAC, HMAC)


b = nb()
HP = 55555
# the heuristic reads the payload type of a leader from bytes 8-9 (the field
# info bytes of an image leader), so the field info is set to IMAGE here
frames.append(hstream(v1(LEADER, b, 0, leader_body(IMAGE, fi=(0x00, 0x01))), HP))
frames.append(hstream(v1(PAYLOAD, b, 1, DATA), HP))
frames.append(hstream(v1(TRAILER, b, 2, trailer_body(IMAGE)), HP))
frames.append(hstream(v2(ALLIN, b, 3, leader_body(RAW) + trailer_body(RAW) + DATA), HP))
# not recognised by the heuristic: bad status, bad format, unknown payload
# type in the leader, too short (these stay UDP data)
HR = 55556
frames.append(hstream(v1(LEADER, b, 0, leader_body(IMAGE), status=0x1234), HR))
frames.append(hstream(v1(0, b, 0, leader_body(IMAGE)), HR))
frames.append(hstream(v1(9, b, 0, leader_body(IMAGE)), HR))
frames.append(hstream(v1(LEADER, b, 0, struct.pack('>HH', 0, 0x0123) + bytes(30)), HR))
frames.append(hstream(b'\0\0\0\0\x01\0\0', HR))
frames.append(hstream(v2(PAYLOAD, b, 0, b'')[:19], HR))
frames.append(hstream(v1(PAYLOAD, b, 1, DATA, status=0x8000), HR))
frames.append(hstream(v1(PAYLOAD, b, 1, DATA, status=0x8018), HR))
frames.append(hstream(v1(LEADER, b, 0, b'\0'), HR))             # leader with a single byte after the header

# ---------------------------------------------------------------------
# malformed capture (pcapng: interface 0 Ethernet, interface 1 Exported PDU)
# ---------------------------------------------------------------------
def BAD(payload, dp=STREAM_PORT):
    bad.append((0, stream(payload, dp)))


def exported_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload


def BADX(payload):
    bad.append((1, exported_pdu('gvsp', payload)))


# the reproducer of "GVSP: Limit the work done for GenDC component and part
# offsets": N component offsets pointing at one component whose P part
# offsets point at one part header (here 2000 x 2000, 64 KB)
N = P = 2000
hdr = struct.pack('>HHB', 0, 1, PGENDC) + b'\x00\x00\x01'
pay = struct.pack('>IQBBH', 0, 0, 0xE0, 0, 0)
cont = b'GNDC' + bytes([1, 0, 0, 0]) + struct.pack('<HHI', 0x1000, 0, 0) + struct.pack('<Q', 0)
cont += struct.pack('<HHIQQII', 0, 0, 0, 0, 0, 0, N)
comp_rel = 72 + 8 * N - 16
comp = struct.pack('<HHIHHHHIIQQIHH', 0x2000, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, P)
part_rel = comp_rel + 48 + 8 * P
part = struct.pack('<HHIIHHQQQ', 0x4200, 0, 64, 0, 0, 0, 0, 0, 0) + b'\0' * 24
repro = hdr + pay + cont + struct.pack('<Q', comp_rel) * N + comp + struct.pack('<Q', part_rel) * P + part
BADX(repro)
# small variants: component offsets that do not increase, part offsets that
# do not increase, more than 1024 parts in total
def gendc_raw(comp_offsets, comps):
    body = hdr + pay
    c = b'GNDC' + bytes([1, 0, 0, 0]) + struct.pack('<HHI', 0x1000, 0, 0) + struct.pack('<Q', 0)
    c += struct.pack('<HHIQQII', 0, 0, 0, 0, 0, 0, len(comp_offsets))
    c += b''.join(struct.pack('<Q', o) for o in comp_offsets)
    return body + c + comps


def mkcomp(part_offs):
    return struct.pack('<HHIHHHHIIQQIHH', 0x2000, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, len(part_offs)) \
        + b''.join(struct.pack('<Q', o) for o in part_offs)


base = 56 + 16
c1 = base
p1 = c1 + 48 + 16
pt = struct.pack('<HHIIHHQQQ', 0x4200, 0, 64, 0, 0, 0, 0, 0, 0) + b'\0' * 24
BADX(gendc_raw([c1, c1], mkcomp([p1, p1 + 64]) + pt + pt))                 # component offset repeats
BADX(gendc_raw([c1], mkcomp([p1, p1]) + pt + pt))                          # part offset repeats
BADX(gendc_raw([c1], mkcomp([p1 + 64, p1]) + pt + pt))                     # part offsets decrease
# 1100 components of 1 part each: more than 1024 parts
n = 1100
cbase = 56 + 8 * n
offs = [cbase + i * (48 + 8 + 64) for i in range(n)]
comps = b''
for i in range(n):
    comps += mkcomp([offs[i] + 56]) + pt
BADX(gendc_raw(offs, comps))

# truncated packets and short payloads that raise exceptions
BAD(v1(LEADER, 1, 0, leader_body(IMAGE)[:20]))
BAD(v1(LEADER, 1, 0, leader_body(RAW)[:10]))
BAD(v1(LEADER, 1, 0, leader_body(FILE)[:25]))
BAD(v1(LEADER, 1, 0, leader_body(FILE).rstrip(b'\0')))         # file name without terminator
BAD(v1(LEADER, 1, 0, leader_body(CHUNK)[:8]))
BAD(v1(LEADER, 1, 0, leader_body(EXTCHUNK)[:30]))
BAD(v1(LEADER, 1, 0, leader_body(JPEG)[:20]))
BAD(v1(LEADER, 1, 0, leader_body(JPEG2000)[:30]))
BAD(v1(LEADER, 1, 0, leader_body(H264)[:20]))
BAD(v1(LEADER, 1, 0, leader_body(MZ)[:30]))
BAD(v1(LEADER, 1, 0, leader_body(GENDC)[:20]))
BAD(v1(TRAILER, 1, 0, trailer_body(IMAGE)[:5]))
BAD(v1(TRAILER, 1, 0, trailer_body(CHUNK)[:5]))
BAD(v1(TRAILER, 1, 0, trailer_body(EXTCHUNK)[:10]))
BAD(v1(TRAILER, 1, 0, trailer_body(RAW)[:3]))
BAD(v1(TRAILER, 1, 0, trailer_body(IMAGE | CB)))               # chunk info missing
BAD(v1(ALLIN, 1, 0, leader_body(IMAGE)[:30]))
BAD(v1(ALLIN, 1, 0, leader_body(IMAGE) + trailer_body(IMAGE)[:6]))
BAD(v1(ALLIN, 1, 0, leader_body(IMAGE | CB) + trailer_body(IMAGE | CB) + b'\0\0'))
BAD(v1(ALLIN, 1, 0, leader_body(FILE).rstrip(b'\0')))
BAD(v1(ALLIN, 1, 0, struct.pack('>HH', 0, RAW) + bytes(8)))
BAD(v1(PH264, 1, 0, b'\0\0\0'))
BAD(v1(PMZ, 1, 0, b'\0\0\0'))
BAD(v1(PMP, 1, 0, b'\0\0\0'))
BAD(v1(PGENDC, 1, 0, b'\0\0\0'))
BAD(v1(PGENDC, 1, 0, struct.pack('>IQBBH', 16, 0, 0xE0, 0, 0) + b'GNDC'))        # descriptor truncated
BAD(v1(PGENDC, 1, 0, struct.pack('>IQBBH', 16, 0, 0xE0, 0, 0) + desc[:70]))
BAD(v1(PGENDC, 1, 0, struct.pack('>IQBBH', 16, 0, 0xE0, 0, 0) + desc[:200]))
BAD(v1(PGENDC, 1, 0, struct.pack('>IQBBH', 16, 0, 0xE0, 0, 0) + desc[:len(desc) - 20]))
BAD(v1(PGENDC, 1, 0, struct.pack('>IQBBH', 16, 0, 0xE0, 0, 0)))
BAD(v1(PGENDC, 1, 0, struct.pack('>IQBBH', 16, 0, 0xE0, 0, 0)[:12]))
# huge component count / offsets beyond the packet
badd = bytearray(desc)
struct.pack_into('<I', badd, 52, 100000)
BAD(v1(PGENDC, 1, 0, gendc_payload(bytes(badd))))
badd = bytearray(desc)
struct.pack_into('<Q', badd, 56, 1 << 40)
BAD(v1(PGENDC, 1, 0, gendc_payload(bytes(badd))))
badd = bytearray(desc)
struct.pack_into('<H', badd, 56 + 24 + 8 + 46 - 8, 5000)       # part count of the first component
BAD(v1(PGENDC, 1, 0, gendc_payload(bytes(badd))))
# multi-part leader: without extended ids it reads the part count before the packet
BAD(v1(LEADER, 1, 0, struct.pack('>HH', 0, MP) + struct.pack('>Q', TS) + mp_part(1)))
BAD(v2(LEADER, 1, 0, struct.pack('>HH', 0, MP) + struct.pack('>Q', TS) + mp_part(1)[:30], b7=1))
BAD(v2(LEADER, 1, 0, struct.pack('>HH', 0, MP) + struct.pack('>Q', TS)[:4], b7=1))
BAD(v2(TRAILER, 1, 0, struct.pack('>HH', 0, MP) + mp_trailer_part(1)[:10]))
BAD(v2(TRAILER, 1, 0, struct.pack('>HH', 0, MP)[:2]))
BAD(v2(LEADER, 1, 0, leader_body(IMAGE)[:5]))
BAD(v2(LEADER, 1, 0, leader_body(MZ)[:3], b7=3))
# extended id packet shorter than 20 bytes is not GVSP at all
BAD(v2(PAYLOAD, 1, 0, b'')[:19])
BAD(b'\0\0\0\0')                                                    # shorter than 8 bytes
BAD(b'\0\0\0\0\x01')
# multi-part payload / multizone payload with too little data
BAD(v2(PMP, 1, 0, b'\0\0\0\0\0'))
BAD(v2(PMZ, 1, 0, b'\0\0\0\0\0'))
BAD(v2(PH264, 1, 0, b'\0\0\0'))
BAD(v1(PAYLOAD, 1, 0, DATA)[:9] + b'')
# Exported PDU naming gvsp
BADX(v1(LEADER, 1, 0, leader_body(IMAGE)))
BADX(v1(LEADER, 1, 0, leader_body(IMAGE)[:10]))
BADX(v1(PAYLOAD, 1, 1, DATA))


def pcap(path, fr):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(fr):
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(p), len(p)))
            f.write(p)


def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)


def pcapng(path, idbs, fr):
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, p) in enumerate(fr):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    open(path, 'wb').write(out)


out = sys.argv[1]
os.makedirs(out, exist_ok=True)
pcap(os.path.join(out, 'gvsp-coverage.pcap'), frames)
pcapng(os.path.join(out, 'gvsp-coverage-malformed.pcapng'), [1, 252], bad)
print(len(frames), 'main frames,', len(bad), 'malformed frames')
