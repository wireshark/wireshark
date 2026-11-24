#!/usr/bin/env python3
# Generates test/captures/dect_nr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic DECT NR+ coverage captures (pcap, LINKTYPE 301).

Usage: mkdect_nr.py <outdir>

Writes dect_nr-coverage.pcap (main, clean) and
dect_nr-coverage-malformed.pcap (paths only malformed input reaches).
Every octet is built here with struct; nothing comes from a real network.
The MAC PDUs marked as ciphered carry made-up opaque bytes, not
ciphertext: no encryption is done anywhere.
"""
import os
import struct
import sys

LINKTYPE_DECT_NR = 301


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_DECT_NR))
        for i, d in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000, len(d), len(d)))
            f.write(d)


# ---------------------------------------------------------------- PHY
def phf1(nw, tx, len_type=0, plen=0, pwr=0, mcs=0, res=0, pad=True):
    """Type 1 (40 bit) PHF. With pad, 5 zero octets follow, as AUTO expects."""
    b = struct.pack('>BBHB', (0 << 5) | (len_type << 4) | plen, nw, tx,
                    (pwr << 4) | (res << 3) | mcs)
    return b + (b'\x00' * 5 if pad else b'')


def phf2(nw, tx, rx, fmt=0, len_type=0, plen=0, pwr=0, mcs=0, ss=0, b7=0,
         fbfmt=0, fbinfo=0):
    """Type 2 (80 bit) PHF. rx must be nonzero for AUTO to pick type 2."""
    return struct.pack('>BBHBHBH', (fmt << 5) | (len_type << 4) | plen, nw, tx,
                       (pwr << 4) | mcs, rx, (ss << 6) | b7,
                       (fbfmt << 12) | fbinfo)


# ---------------------------------------------------------------- MAC
def mac(sec, typ, ver=0):
    return bytes([(ver << 6) | (sec << 4) | typ])


def hdr_data(sn, reset=0, res=0):
    return struct.pack('>H', (res << 13) | (reset << 12) | (sn & 0xfff))


def hdr_beacon(nw24, tx):
    return struct.pack('>I', nw24)[1:] + struct.pack('>I', tx)


def hdr_unicast(sn, rx, tx, dwa=0, rst=0):
    return struct.pack('>HII', (dwa << 13) | (rst << 12) | (sn & 0xfff), rx, tx)


def hdr_rdb(sn, tx, reset=0):
    return struct.pack('>HI', (reset << 12) | (sn & 0xfff), tx)


def mux(ie, payload, ext=1):
    """MAC multiplexing header + IE. ext 0: no length, 1: 8 bit, 2: 16 bit."""
    if ext == 0:
        return bytes([ie]) + payload
    if ext == 1:
        return bytes([(1 << 6) | ie, len(payload)]) + payload
    return bytes([(2 << 6) | ie]) + struct.pack('>H', len(payload)) + payload


def mux_short(ie, payload=None):
    """MAC extension 3: 5 bit IE type, length bit (0 = no payload, 1 = 1 octet)."""
    if payload is None:
        return bytes([(3 << 6) | ie])
    assert len(payload) == 1
    return bytes([(3 << 6) | (1 << 5) | ie]) + payload


# ---------------------------------------------------------------- DLC
def dlc_hdr(t, res=0):
    return bytes([(t << 4) | res])


def dlc_sisn(t, si, sn, so=None):
    b = struct.pack('>H', (t << 12) | (si << 10) | (sn & 0x3ff))
    if si in (2, 3):
        b += struct.pack('>H', so)
    return b


def routing(qos=0, delay=None, hcl=0, dest=0, rtype=0, src=0x11223344,
            dst=0x55667788, hop_count=1, hop_limit=5, seq=9):
    b = bytes([(qos << 1) | (1 if delay is not None else 0),
               (hcl << 6) | (dest << 3) | rtype])
    if dest not in (3, 4):
        b += struct.pack('>I', src)
    if dest not in (1, 2, 4):
        b += struct.pack('>I', dst)
    if hcl in (1, 2):
        b += bytes([hop_count])
    if hcl == 2:
        b += bytes([hop_limit])
    if delay is not None:
        b += struct.pack('>I', delay)
    if rtype == 5:
        b += bytes([seq])
    return b


def dlc_ext(ie, payload, coding=1):
    """DLC extension header. coding 0: no length, 1: 8 bit, 2: 16 bit."""
    if coding == 0:
        return bytes([ie]) + payload
    if coding == 1:
        return bytes([(1 << 6) | ie, len(payload)]) + payload
    return bytes([(2 << 6) | ie]) + struct.pack('>H', len(payload)) + payload


# ---------------------------------------------------------------- CVG
def cvg1(ie, payload, ext=1, length=None):
    """CVG header format 1 (MT=0). The length is the IE payload length."""
    n = len(payload) if length is None else length
    if ext == 0:
        return bytes([ie]) + payload
    if ext == 1:
        return bytes([(1 << 6) | ie, n]) + payload
    return bytes([(2 << 6) | ie]) + struct.pack('>H', n) + payload


def data_ie(si, seq, payload, sdu_len=None, so=None, res=0):
    b = struct.pack('>H', (si << 14) | ((1 if sdu_len is not None else 0) << 13) |
                    (res << 12) | (seq & 0xfff))
    if sdu_len is not None:
        b += struct.pack('>H', sdu_len)
    if si in (2, 3):
        b += struct.pack('>H', so)
    return b + payload


def cvg_data1(si, seq, payload, ext=1, **kw):
    """Format 1 Data IE; the dissector takes the length as the payload
    length after the SI/SN/SDU length/offset octets."""
    die = data_ie(si, seq, payload, **kw)
    hdrlen = len(die) - len(payload)
    if ext == 0:
        return bytes([1]) + die
    if ext == 1:
        return bytes([(1 << 6) | 1, len(payload)]) + die
    return bytes([(2 << 6) | 1]) + struct.pack('>H', len(payload)) + die


def cvg_data_ep1(ep, si, seq, payload, ext=1, **kw):
    die = struct.pack('>H', ep) + data_ie(si, seq, payload, **kw)
    if ext == 0:
        return bytes([2]) + die
    return bytes([(1 << 6) | 2, len(payload)]) + die


def arq_entry(info, seq, an=0, extra=b''):
    return struct.pack('>H', (an << 15) | (info << 12) | (seq & 0xfff)) + extra


# A minimal IPv6 header (next header 59 "No Next Header", no payload)
IPV6 = struct.pack('>IHBB', 0x60000000, 0, 59, 64) + \
    bytes.fromhex('fe800000000000000000000000000001') + \
    bytes.fromhex('fe800000000000000000000000000002')


def build_main():
    F = []

    # ---- 1-5: reproducers from the review, unchanged
    pad2 = mux(0, b'\x00\x00')
    # dect_nr_rdid_twopass: Data MAC header before the Unicast header that
    # teaches the Long RD IDs of the same Short RD IDs
    F.append(phf2(0x10, 0x1111, 0x2222) + mac(0, 0) + hdr_data(1) + pad2)
    F.append(phf2(0x10, 0x1111, 0x2222) + mac(0, 2) + hdr_unicast(2, 0x0a0b0c0d, 0x01020304) + pad2)
    # dect_nr_cvg_same_sn: two complete SDUs with the same SN in one frame
    cvg = cvg_data1(0, 5, b'AAAA') + cvg_data1(0, 5, b'BBBBBBBB')
    F.append(phf2(0x10, 0x1111, 0x2222) + mac(0, 0) + hdr_data(1) + mux(3, dlc_hdr(1) + cvg))
    d1 = mux(3, dlc_sisn(3, 0, 7) + cvg1(3, b'CCCC'))
    d2 = mux(3, dlc_sisn(3, 0, 7) + cvg1(3, b'DDDDDDDD'))
    F.append(phf2(0x10, 0x1111, 0x2222) + mac(0, 0) + hdr_data(2) + d1 + d2)
    # dect_nr_arq_fb_reserved_len: ARQ feedback with reserved feedback info 6
    arq = bytes([0x00, 0x01, 0x60, 0x02, 0x00, 0x00])
    F.append(phf2(0x10, 0x1111, 0x2222) + mac(0, 0) + hdr_data(1) +
             mux(3, dlc_hdr(1) + bytes([(1 << 6) | 6, len(arq)]) + arq))

    # ---- 6-23: Physical Header Field
    # 6: type 1 PHF only (PCC without a MAC PDU), slot length type
    F.append(phf1(0x20, 0x2001, len_type=1, plen=3, pwr=5, mcs=2))
    # 7: type 1 PHF with the reserved bit set and a Data MAC header
    #    (no conversation: the receiver ID is 0)
    F.append(phf1(0x20, 0x2001, plen=0, mcs=7, res=1) + mac(0, 0) + hdr_data(3) + pad2)
    # 8: type 2, header format 0, no feedback, PCC only
    F.append(phf2(0x21, 0x2101, 0x2102, plen=15, pwr=15, mcs=11, ss=1, b7=(2 << 4) | (1 << 3) | 5))
    # 9-15: feedback formats 1-7
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=1, fbinfo=(3 << 9) | (1 << 8) | (5 << 4) | 7))
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=2, fbinfo=(5 << 9) | (1 << 8) | (2 << 4) | 3))
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=3, fbinfo=(1 << 9) | (1 << 8) | (6 << 5) | (0 << 4) | 4))
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=4, fbinfo=(0xa5 << 4) | 2))
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=5, fbinfo=(7 << 9) | (0 << 8) | (2 << 6) | 33))
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=6, fbinfo=(4 << 9) | (9 << 4) | 1))
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=7, fbinfo=(3 << 8) | (1 << 7) | (5 << 3)))
    # 16: feedback format 7 without CQI
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=7, fbinfo=(15 << 8)))
    # 17: feedback format 15 (escape), 18: reserved format 9
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=15, fbinfo=0xabc))
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=9, fbinfo=0x123))
    # 19: header format 001 (reserved field instead of the DF fields)
    F.append(phf2(0x21, 0x2101, 0x2102, fmt=1, len_type=1, plen=1, b7=0, fbfmt=1, fbinfo=0x0101))
    # 20: broadcast receiver (no conversation), feedback format 4 with all HARQ bits
    F.append(phf2(0x21, 0x2101, 0xffff, fbfmt=4, fbinfo=(0xff << 4) | 15))
    # 21: feedback with a MAC PDU (Data header + padding)
    F.append(phf2(0x21, 0x2101, 0x2102, fbfmt=1, fbinfo=0x0210) + mac(0, 0) + hdr_data(4) + pad2)

    # ---- MAC headers
    NW, FT, PT = 0x30, 0x3001, 0x3002
    FT_L, PT_L = 0x30303001, 0x30303002
    # Beacon header with a Network Beacon (no-length IE), then Cluster Beacon
    nb = bytes([(1 << 4) | (1 << 3) | (1 << 2) | 3, (2 << 4) | 3]) + struct.pack('>H', 1657) + \
        struct.pack('>I', 100000) + bytes([0x0b]) + struct.pack('>H', 1659) + \
        struct.pack('>HHH', 1661, 1663, 1665)
    F.append(phf1(NW, FT) + mac(0, 1) + hdr_beacon(0x303030, FT_L) + mux(8, nb, ext=0))
    nb0 = bytes([0, (0 << 4) | 0]) + struct.pack('>H', 1657) + struct.pack('>I', 5)
    F.append(phf1(NW, FT) + mac(0, 1) + hdr_beacon(0x303030, FT_L) + mux(8, nb0))
    cb = bytes([7, (1 << 4) | (1 << 3) | (1 << 2) | (1 << 1) | 1, (3 << 4) | 5, (2 << 4) | (1 << 2) | 2,
                0x0c, 0x20]) + struct.pack('>H', 1677) + struct.pack('>I', 200000)
    F.append(phf1(NW, FT) + mac(0, 1) + hdr_beacon(0x303030, FT_L) + mux(9, cb) +
             mux(19, bytes([(1 << 3) | (1 << 2) | 3, 10, (1 << 7) | 3, (1 << 7) | (3 << 3) | 2,
                            (1 << 7) | (4 << 3) | 6, 2, 5, 9]) + struct.pack('>HH', 1657, 1659)) +
             mux(21, bytes([0x7f, 0x22]) + struct.pack('>I', 0x31313131) + struct.pack('>H', 1661) +
                 struct.pack('>I', 3000) + bytes([0x80, 0x10, 0x44])))
    cb0 = bytes([8, 0, 0x22, 0x30])
    F.append(phf1(NW, FT) + mac(0, 1) + hdr_beacon(0x303030, FT_L) + mux(9, cb0) +
             mux(19, bytes([0, 0x10, 5, 0x08, 0x08])) +  # 8 bit start subslot
             mux(19, struct.pack('>BHBBB', 0, 0x0110, 5, 0x08, 0x08)))  # 9 bit
    # Association Request from PT (Unicast header teaches both Long RD IDs)
    areq = bytes([(1 << 5) | (2 << 2) | (1 << 1) | 1, 0x80, (3 << 5) | 4, (2 << 5) | 3, 0x01, 0x02,
                  (5 << 4) | 3]) + struct.pack('>H', 1657) + struct.pack('>I', 77777) + struct.pack('>H', 1659)
    F.append(phf2(NW, PT, FT) + mac(0, 2) + hdr_unicast(1, FT_L, PT_L) + mux(10, areq) +
             mux(20, bytes([(1 << 5) | 2, 0x3f, (2 << 5) | (1 << 2), 0x35, 0x5a, 0x24, 0x40,
                            (3 << 5) | (4 << 1), 0x45, 0x6b, 0x38, 0x50])) +
             mux_short(2, bytes([0xe5])) + mux_short(1, bytes([0x5c])))
    # Association Request: 7 flows (reserved), no FT mode / current fields
    F.append(phf2(NW, PT, FT) + mac(0, 2) + hdr_unicast(2, FT_L, PT_L) +
             mux(10, bytes([(0 << 5) | (7 << 2), 0x00, 0x21, 0x21])) + mux(20, bytes([0, 0, 0, 0, 0, 0, 0])))
    # Association Response accepted (HARQ, flows, group) and rejected
    arsp = bytes([(1 << 7) | (1 << 5) | (2 << 2) | (1 << 1), (2 << 5) | 3, (3 << 5) | 4, 0x01, 0x02, 0x05, 0x07])
    F.append(phf2(NW, FT, PT) + mac(0, 2) + hdr_unicast(1, PT_L, FT_L, dwa=1) + mux(11, arsp) +
             mux(18, bytes([(1 << 6) | (1 << 4) | (1 << 1) | 1, 0xc0, 10, 0x85]) + struct.pack('>H', PT) +
                 bytes([3, 8, 4]) + struct.pack('>H', 1657) + bytes([2])) +
             mux(23, bytes([0x05, 0x81, 0x02, 0x83])) + mux_short(3, bytes([0xb3])))
    F.append(phf2(NW, FT, PT) + mac(0, 2) + hdr_unicast(2, PT_L, FT_L) + mux(11, bytes([0x00, (3 << 4) | 5])))
    # Association Response: all flows accepted (7), no HARQ or group
    F.append(phf2(NW, FT, PT) + mac(0, 2) + hdr_unicast(3, PT_L, FT_L) + mux(11, bytes([(1 << 7) | (7 << 2)])))
    # Data MAC header (Short RD IDs only): Long RD IDs from the unicast frames
    F.append(phf2(NW, PT, FT) + mac(0, 0) + hdr_data(3) + mux(12, bytes([(2 << 4)])) +
             mux_short(4, bytes([0x2a])))
    # Reconfiguration Request / Response with HARQ fields and flows
    rcq = bytes([(1 << 7) | (1 << 6) | (1 << 5) | (2 << 2) | 1, (2 << 5) | 3, (1 << 5) | 2, 0x81, 0x02])
    F.append(phf2(NW, PT, FT) + mac(0, 0) + hdr_data(4) + mux(13, rcq))
    rcs = bytes([(1 << 7) | (1 << 6) | (3 << 2) | 2, 0x22, 0x33, 0x81, 0x42, 0x03])
    F.append(phf2(NW, FT, PT) + mac(0, 0) + hdr_data(4) + mux(14, rcs))
    F.append(phf2(NW, FT, PT) + mac(0, 0) + hdr_data(5) + mux(14, bytes([7 << 2])) + mux(13, bytes([7 << 2])))
    # RD Broadcasting header with Route Info, Source Routing, Joining Beacon/Info,
    # Access Token, Load Info, Measurement Report
    F.append(phf1(NW, PT) + mac(0, 3) + hdr_rdb(9, PT_L, reset=1) +
             mux(17, struct.pack('>IBB', 0x0aaaaaaa, 3, 7)) +
             mux(26, struct.pack('>IBBB', 0x12345678, 0x50, 2, 9)) +
             mux(27, bytes([(3 << 6) | (4 << 2)]) + struct.pack('>HHH', 1657, 1659, 1661)) +
             mux(28, bytes([3]) + struct.pack('>HHH', 0x8001, 0x8002, 0x8003)) +
             mux(29, struct.pack('>I', 0xdeadbeef)) +
             mux(24, bytes([0x0f, 0x80]) + struct.pack('>H', 300) + bytes([0x40, 0x20, 0x10, 0xc0, 0x30])) +
             mux(24, bytes([0x00, 0xff, 50, 0x00])) +
             mux(25, bytes([0x1f, 0x10, 0x74, 0x80, 5])) +
             mux(25, bytes([0x1c, 0x7f, 0xff, 0x10])) +
             mux(25, bytes([0x18, 0xe0, 0x90])) +
             mux(25, bytes([0x10, 0xf0])) +
             mux(25, bytes([0x10, 0x90])) +
             mux(25, bytes([0x01])))
    # Neighbouring IE without optional fields; joining beacon/info empty
    F.append(phf1(NW, PT) + mac(0, 3) + hdr_rdb(10, PT_L) + mux(21, bytes([0, 0x11])) +
             mux(27, bytes([0])) + mux(28, bytes([0])) + mux(22, bytes([0x00]) + struct.pack('>H', PT)))
    # Broadcast Indication: random access response with each feedback type,
    # Short and Long RD IDs; paging
    bi = (mux(22, bytes([(1 << 5) | (1 << 3) | (1 << 1) | 1]) + struct.pack('>H', PT) + bytes([0x05])) +
          mux(22, bytes([(1 << 5) | (1 << 4) | (2 << 1)]) + struct.pack('>I', PT_L) + bytes([0x0b])) +
          mux(22, bytes([(1 << 5) | (1 << 4) | (3 << 1)]) + struct.pack('>I', PT_L) + bytes([0x45])) +
          mux(22, bytes([(1 << 5) | (0 << 1)]) + struct.pack('>H', PT)) +
          mux(22, bytes([(0 << 5) | (1 << 4)]) + struct.pack('>I', PT_L)))
    F.append(phf1(NW, FT) + mac(0, 1) + hdr_beacon(0x303030, FT_L) + bi)
    # Resource Allocation IE: release, DL/UL/both, 8 and 9 bit start subslot,
    # all optional fields
    ra = (mux(18, bytes([0x00])) +
          mux(18, bytes([(1 << 6), 0x00, 4, 0x02])) +                       # DL, 8 bit
          mux(18, bytes([(1 << 6), 0x00]) + struct.pack('>H', 0x0101) + bytes([0x02])) +  # DL, 9 bit
          mux(18, bytes([(2 << 6), 0x00, 4, 0x82])) +                       # UL, 8 bit
          mux(18, bytes([(2 << 6), 0x00]) + struct.pack('>H', 0x0102) + bytes([0x82])) +  # UL, 9 bit
          mux(18, bytes([(3 << 6), 0x00, 4, 0x02, 12, 0x02])) +             # DL+UL, 8 bit
          mux(18, bytes([(3 << 6) | (1 << 5) | (1 << 4) | (2 << 1) | 1, 0xc0]) +
              struct.pack('>HBHB', 0x0103, 0x02, 0x0104, 0x82) + struct.pack('>H', PT) +
              bytes([5, 7, 1]) + struct.pack('>H', 1657) + bytes([3])))       # DL+UL, 9 bit, all fields
    F.append(phf2(NW, FT, PT) + mac(0, 0) + hdr_data(6) + ra)
    # Short IEs without payload and Padding (short, 1 octet), Additional MAC message,
    # Escape and IE type extension, reserved IE types
    F.append(phf2(NW, FT, PT) + mac(0, 0) + hdr_data(7) +
             mux_short(0) + mux_short(1) + mux_short(17) + mux_short(0, b'\x00') +
             mux_short(30, b'\x99') + mux(15, b'\x01\x02\x03') + mux(62, b'\xee\xee') +
             mux(63, b'\x05\x01\x02') + mux(0, b'', ext=1) + mux(23, bytes([0x80, 0x01]), ext=2) +
             mux(0, b'\x00\x00\x00', ext=0))
    # Group Assignment IE without a length (single and two tags), Additional
    # MAC message without a length
    F.append(phf2(NW, FT, PT) + mac(0, 0) + hdr_data(8) + mux(23, bytes([0x82, 0x01]), ext=0) +
             mux(23, bytes([0x03, 0x01, 0x82]), ext=0) + mux(15, b'\x10\x20\x30', ext=0))
    # Reserved MAC IE types, short IE type 5 and a length mismatch
    F.append(phf2(NW, FT, PT) + mac(0, 0) + hdr_data(9) + mux(7, b'\x01\x02') + mux(30, b'\x03') +
             mux_short(5, b'\x44') + mux(17, b'\x01\x02\x03\x04\x05\x06\x07\x08'))
    # MAC header escape and a reserved MAC header type
    F.append(phf2(NW, FT, PT) + mac(0, 15) + b'\x01\x02\x03\x04')
    F.append(phf2(NW, FT, PT) + mac(0, 6, ver=1) + b'\x05\x06\x07')
    # Data MAC header with reset bit and nonzero reserved bits
    F.append(phf2(NW, FT, PT) + mac(0, 0) + hdr_data(10, reset=1, res=2) + pad2)

    # ---- MAC security (no cipher keys at default preferences). The MAC
    # PDUs after the Security Info IE are plaintext IEs plus a 5 octet MIC,
    # so that "Handle MAC PDUs as decrypted" decodes them; with a cipher
    # key preference they go through the decryption and decode as noise.
    SN, ST, SR = 0x40, 0x4001, 0x4002
    STL, SRL = 0x40404001, 0x40404002
    mic = b'\x4d\x49\x43\x21\x21'
    plain = mux(12, bytes([(1 << 4)])) + mux_short(4, bytes([0x01]))
    F.append(phf2(SN, ST, SR) + mac(0, 2) + hdr_unicast(1, SRL, STL) + pad2)
    # Security Info IE (version 0, key 0, IV type 1, HPC 0x100) + "ciphered" IEs
    F.append(phf2(SN, ST, SR) + mac(2, 2) + hdr_unicast(10, SRL, STL) +
             mux(16, bytes([(0 << 6) | (0 << 4) | 1]) + struct.pack('>I', 0x100)) + plain + mic)
    # Security mode 1 without the IE: HPC from the conversation
    F.append(phf2(SN, ST, SR) + mac(1, 0) + hdr_data(11) + plain + mic)
    # PSN 0: the HPC is incremented
    F.append(phf2(SN, ST, SR) + mac(1, 0) + hdr_data(0) + plain + mic)
    F.append(phf2(SN, ST, SR) + mac(1, 0) + hdr_data(1) + plain + mic)
    # Keys 1, 2, 3 and security version 1; IV type 0 (not stored)
    for key in (1, 2, 3):
        F.append(phf2(SN, ST, SR) + mac(2, 0) + hdr_data(1 + key) +
                 mux(16, bytes([(key << 4) | 1]) + struct.pack('>I', 0x200 + key)) + plain + mic)
    F.append(phf2(SN, ST, SR) + mac(2, 0) + hdr_data(5) +
             mux(16, bytes([(1 << 6) | 1]) + struct.pack('>I', 0x300)) + plain + mic)
    F.append(phf2(SN, ST, SR) + mac(2, 0) + hdr_data(6) +
             mux(16, bytes([0]) + struct.pack('>I', 0x400)) + plain + mic)
    # Security mode 1 without a conversation: missing security info
    F.append(phf1(SN, ST) + mac(1, 0) + hdr_data(7) + plain + mic)
    # PSN rolling back by more than 0x7ff
    F.append(phf2(SN, ST, SR) + mac(0, 0) + hdr_data(0xf00) + pad2)
    F.append(phf2(SN, ST, SR) + mac(1, 0) + hdr_data(0x010) + plain + mic)

    # ---- DLC
    DN, DT, DR = 0x50, 0x5001, 0x5002
    dh = phf2(DN, DT, DR)
    cvg_t = cvg1(3, b'transparent')
    # Service type 0 with routing header, every Destination Address type
    rh = b''
    for dest in range(8):
        rh += mux(1 if dest % 2 else 2, dlc_hdr(0) + routing(qos=dest % 8, dest=dest, rtype=dest % 5) + cvg_t)
    F.append(dh + mac(0, 0) + hdr_data(1) + rh)
    # Hop count / hop limit / delay / routing type 5 / reserved bits
    F.append(dh + mac(0, 0) + hdr_data(2) +
             mux(3, dlc_hdr(0) + routing(hcl=1, dest=0, rtype=5, delay=0x1000) + cvg_t) +
             mux(4, dlc_hdr(0) + routing(hcl=2, dest=1, rtype=1) + cvg_t) +
             mux(5, dlc_hdr(0) + routing(hcl=3, dest=2, rtype=2) + cvg_t) +
             mux(6, dlc_hdr(1, res=3) + cvg_t, ext=2))
    # Service type 0 + extension headers: routing, CVG PDU, next hop, route
    # register, route error, escape, reserved, 16 bit and no length coding,
    # reserved coding
    ext = (dlc_ext(0, routing(dest=4, hcl=0)) + dlc_ext(1, cvg_t) + dlc_ext(2, struct.pack('>I', 0x01010101)) +
           dlc_ext(3, struct.pack('>I', 0x02020202)) + dlc_ext(4, b'\x01' + struct.pack('>I', 0x03030303)) +
           dlc_ext(62, b'\xee\xee') + dlc_ext(33, b'\x01\x02') + dlc_ext(1, cvg_t, coding=2) +
           bytes([(3 << 6) | 1]) + dlc_ext(2, struct.pack('>I', 0x04040404), coding=0))
    F.append(dh + mac(0, 0) + hdr_data(3) + mux(1, dlc_hdr(5) + ext))
    # Timers configuration control IE, escape, reserved service types
    F.append(dh + mac(0, 0) + hdr_data(4) + mux(1, dlc_hdr(4) + b'\x07') + mux(2, dlc_hdr(14) + b'\xee\xee') +
             mux(2, dlc_hdr(7) + b'\x00\x01') + mux(1, dlc_hdr(15) + b'\x02'))
    # Service type 1-3 complete SDUs: with routing (2), without (3), ext headers (6)
    F.append(dh + mac(0, 0) + hdr_data(5) +
             mux(1, dlc_sisn(2, 0, 100) + routing(dest=5) + cvg_t) +
             mux(1, dlc_sisn(3, 0, 101) + cvg_t) +
             mux(1, dlc_sisn(6, 0, 102) + dlc_ext(1, cvg_t)))
    # Segmented SDUs (reassembled): type 3 in three segments
    sdu = cvg1(3, b'0123456789abcdefghijklmnopqrstuvwxyz')
    a, b, c = sdu[:10], sdu[10:25], sdu[25:]
    F.append(dh + mac(0, 0) + hdr_data(6) + mux(3, dlc_sisn(3, 1, 200) + a))
    F.append(dh + mac(0, 0) + hdr_data(7) + mux(3, dlc_sisn(3, 3, 200, len(a)) + b))
    F.append(dh + mac(0, 0) + hdr_data(8) + mux(3, dlc_sisn(3, 2, 200, len(a) + len(b)) + c))
    # type 2 (with routing header) in two segments
    sdu2 = cvg1(3, b'ROUTED-SEGMENTED-SDU')
    F.append(dh + mac(0, 0) + hdr_data(9) + mux(3, dlc_sisn(2, 1, 201) + routing(dest=6) + sdu2[:8]))
    F.append(dh + mac(0, 0) + hdr_data(10) + mux(3, dlc_sisn(2, 2, 201, 8) + routing(dest=6) + sdu2[8:]))
    # type 6 in two segments, each segment holding whole extension headers
    # (the dissector parses the last segment's own octets, see README)
    F.append(dh + mac(0, 0) + hdr_data(11) + mux(3, dlc_sisn(6, 1, 202) + dlc_ext(2, struct.pack('>I', 0x05050505))))
    F.append(dh + mac(0, 0) + hdr_data(12) + mux(3, dlc_sisn(6, 2, 202, 6) + dlc_ext(1, cvg_t)))

    # ---- CVG
    CN, CT, CR = 0x60, 0x6001, 0x6002
    ch = phf2(CN, CT, CR)

    def cframe(sn, cvgpdu, ie=3):
        return ch + mac(0, 0) + hdr_data(sn) + mux(ie, dlc_hdr(1) + cvgpdu, ext=2)

    # Every CVG IE type in format 1 headers
    sec_ie = bytes([(2 << 4) | 1]) + struct.pack('>I', 0x12345678)
    txs = bytes([(1 << 7) | 3, 20]) + struct.pack('>H', 0x0123)
    arq_all = (arq_entry(0, 1, an=1) + arq_entry(1, 2, extra=struct.pack('>H', 10)) +
               arq_entry(2, 3, extra=struct.pack('>H', 20)) +
               arq_entry(3, 4, extra=struct.pack('>HH', 30, 40)) +
               arq_entry(4, 5, extra=struct.pack('>H', 6)) + arq_entry(5, 7))
    F.append(cframe(1, cvg1(0, struct.pack('>H', 0x8002)) + cvg1(4, sec_ie) + cvg1(5, txs) +
                    cvg1(6, arq_all) + cvg1(7, struct.pack('>H', 0x0042)) + cvg1(8, b'\x03') +
                    cvg1(30, b'\xee\xee', ext=2) + cvg1(3, b'last')))
    # Data IE: SDU length field, 16 bit CVG length, no length (rest of PDU)
    F.append(cframe(2, cvg_data1(0, 10, b'sdu-with-len', sdu_len=12) +
                    cvg_data1(0, 11, b'sixteen-bit-len', ext=2) + cvg_data1(0, 12, b'no-length', ext=0)))
    # Data EP IE to IPv6, 6LoWPAN (uncompressed IPv6 dispatch) and an unknown endpoint
    F.append(cframe(3, cvg_data_ep1(0x8002, 0, 20, IPV6) + cvg_data_ep1(0x8003, 0, 21, b'\x41' + IPV6, sdu_len=41) +
                    cvg_data_ep1(0x1234, 0, 22, b'opaque', ext=0)))
    # Format 2 headers: Data IE without length, ARQ feedback (with and
    # without length), IE type coding, Escape with no length
    F.append(cframe(4, bytes([(1 << 6) | (1 << 5) | (1 << 3) | 2, 2]) + arq_entry(5, 9) +
                    bytes([(0 << 6) | (1 << 5) | (1 << 3) | 1]) + arq_entry(0, 10) +
                    bytes([(1 << 6) | (1 << 5) | (2 << 3) | 3, 1, 8, 0x05]) +
                    bytes([(1 << 6) | (1 << 5) | (2 << 3), 2, 7]) + struct.pack('>H', 0x0001) +
                    bytes([(0 << 6) | (1 << 5) | (0 << 3) | 4]) + data_ie(0, 30, b'format-2-data')))
    F.append(cframe(5, bytes([(1 << 5) | (2 << 3) | 1, 30]) + b'escape-without-length'))
    # Reserved: CVG IE type 9, format 2 code 3, CVG extension 3, reserved
    # ARQ feedback info 7, nonzero reserved bits
    F.append(cframe(6, cvg1(9, b'\x01\x02') + bytes([(1 << 6) | (1 << 5) | (3 << 3), 2, 0xaa, 0xbb]) +
                    bytes([(3 << 6) | 3]) + cvg1(6, arq_entry(7, 1) + b'\x00\x00') +
                    cvg1(4, bytes([0x80 | 0x11]) + struct.pack('>I', 1)) + cvg1(8, b'\xf1') +
                    cvg1(7, struct.pack('>H', 0xf001)) + cvg1(5, bytes([0x78, 1, 0xf8, 0])) +
                    cvg_data1(0, 13, b'res', res=1) + cvg_data_ep1(0x1234, 0, 23, b'res', res=1)))
    # Segmented CVG Data IE (reassembled over three frames)
    F.append(cframe(7, cvg_data1(1, 40, b'first-')))
    F.append(cframe(8, cvg_data1(3, 40, b'middle-', so=6)))
    F.append(cframe(9, cvg_data1(2, 40, b'last', so=13)))
    # Segmented CVG Data EP IE carrying IPv6 (two frames)
    F.append(cframe(10, cvg_data_ep1(0x8002, 1, 41, IPV6[:20])))
    F.append(cframe(11, cvg_data_ep1(0x8002, 2, 41, IPV6[20:], so=20)))
    # DLC ext header CVG PDU over higher layer signalling flow 2 and user
    # plane flow 4
    F.append(ch + mac(0, 0) + hdr_data(12) + mux(2, dlc_hdr(5) + dlc_ext(1, cvg1(7, b'\x00\x05'))) +
             mux(6, dlc_hdr(1) + cvg1(8, b'\x01')))
    return F


def build_malformed():
    F = []
    pad2 = mux(0, b'\x00\x00')
    h = phf2(0x70, 0x7001, 0x7002)
    # Reviewer reproducers that are not fixed on the branch
    # dect_nr_dlc6_reassembled: segmented DLC IE type 6
    cvg = cvg1(3, b'HELLOWORLD')
    sdu = bytes([(1 << 6) | 1, len(cvg)]) + cvg
    a, b = sdu[:5], sdu[5:]
    F.append(h + mac(0, 0) + hdr_data(1) + mux(3, dlc_sisn(6, 1, 3) + a))
    F.append(h + mac(0, 0) + hdr_data(2) + mux(3, dlc_sisn(6, 2, 3, len(a)) + b))
    # dect_nr_cvg_f2_data_len: format 2 Data IE with a length
    die = data_ie(0, 9, b'WXYZ')
    F.append(h + mac(0, 0) + hdr_data(3) + mux(3, dlc_hdr(1) + bytes([(1 << 6) | (1 << 5), len(die)]) + die +
                                               cvg_data1(0, 10, b'WXYZ')))
    # DLC IE without a length (IE length not set, error)
    F.append(h + mac(0, 0) + hdr_data(4) + mux(3, dlc_hdr(1) + cvg1(3, b'x'), ext=0))
    # DLC PDU shorter than its IE length; DLC PDU missing
    F.append(h + mac(0, 0) + hdr_data(5) + bytes([(1 << 6) | 3, 40]) + dlc_hdr(1) + cvg1(3, b'short'))
    F.append(h + mac(0, 0) + hdr_data(6) + bytes([(1 << 6) | 3, 40]))
    # CVG Data IE shorter than its length
    F.append(h + mac(0, 0) + hdr_data(7) + mux(3, dlc_hdr(1) + bytes([(1 << 6) | 1, 50]) + data_ie(0, 1, b'abc')))
    # Security mode 3 (MIC parsed as IEs: MIC missing)
    F.append(h + mac(3, 0) + hdr_data(8) + pad2)
    # Security mode 1, too short for a MIC
    F.append(h + mac(1, 0) + hdr_data(9))
    # Truncated headers and IEs
    F.append(h + mac(0, 2) + b'\x00\x01\x02')
    F.append(h + mac(0, 0) + hdr_data(10) + bytes([(1 << 6) | 8, 20]) + b'\x1f\x00')
    for ie in (8, 9, 10, 11, 13, 14, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29):
        F.append(h + mac(0, 0) + hdr_data(11) + mux(ie, b'\xff', ext=0))
    F.append(h + mac(0, 0) + hdr_data(12) + mux(3, dlc_hdr(1) + bytes([(2 << 6) | 6, 0, 30]) + b'\x30\x00'))
    F.append(h + mac(0, 0) + hdr_data(13) + mux(3, dlc_hdr(0) + bytes([0x01, 0x80])))
    F.append(h + mac(0, 0) + hdr_data(14) + mux(3, dlc_hdr(5) + bytes([(1 << 6) | 1, 30, 3])))
    F.append(h + phf2(0x70, 0x7001, 0x7002)[:3])
    F.append(phf1(0x70, 0x7001)[:4])
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dect_nr-coverage.pcap'), build_main())
    write_pcap(os.path.join(out, 'dect_nr-coverage-malformed.pcap'), build_malformed())


if __name__ == '__main__':
    main()
