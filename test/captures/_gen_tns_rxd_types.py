#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_rxd_types.pcap: a describe of three columns of
different kinds followed by a row, so the dissector's per-type TTI_RXD value
framings (ordinary DALC, ROWID, LONG) are exercised.

    Frame 1 — TTI_DCB describing: NUMBER "N", ROWID "R", LONG "L", DATE "D"
    Frame 2 — TTI_RXD with one row:
                NUMBER 10   -> c1 0b
                ROWID       -> indicator + obj/file/unused/block/slot
                LONG "abc"  -> single chunk + two trailing length indicators
                DATE        -> 2024-01-15 10:30:00 (7 bytes)

Bytes are built by hand in the Oracle 11g wire shape.
"""
import os
import struct

TTI_RXD = 7
TTI_DCB = 16
TYPE_NUMBER = 2
TYPE_ROWID = 11
TYPE_LONG = 8
TYPE_DATE = 12


def ub4(val: int) -> bytes:
    if val == 0:
        return b"\x00"
    if val <= 0xFF:
        return bytes([1, val])
    if val <= 0xFFFF:
        return bytes([2]) + struct.pack(">H", val)
    if val <= 0xFFFFFF:
        return bytes([3]) + struct.pack(">I", val)[1:]
    return bytes([4]) + struct.pack(">I", val)


def sb4(val: int) -> bytes:
    if val == 0:
        return b"\x00"
    b = bytearray(ub4(abs(val)))
    if val < 0:
        b[0] |= 0x80
    return bytes(b)


def dalc(s: bytes) -> bytes:
    return bytes([len(s)]) + s


def swl(s: bytes) -> bytes:
    return ub4(0) if not s else ub4(len(s)) + dalc(s)


def bwl(s: bytes) -> bytes:
    return ub4(0) if not s else ub4(len(s)) + dalc(s)


def oac(data_type, charset, csform, max_size):
    return (
        bytes([data_type]) + b"\x00" + b"\x00" + sb4(0)
        + ub4(max_size) + ub4(0) + ub4(0) + bwl(b"") + ub4(0)
        + ub4(charset) + bytes([csform]) + ub4(max_size)
    )


def dcb_column(data_type, charset, csform, max_size, name):
    return (
        oac(data_type, charset, csform, max_size)
        + b"\x01" + bytes([len(name)]) + swl(name) + swl(b"") + swl(b"")
        + ub4(0) + ub4(0)
    )


def build_dcb() -> bytes:
    columns = [
        dcb_column(TYPE_NUMBER, 0, 0, 22, b"N"),
        dcb_column(TYPE_ROWID, 0, 0, 16, b"R"),
        dcb_column(TYPE_LONG, 873, 1, 0, b"L"),
        dcb_column(TYPE_DATE, 0, 0, 7, b"D"),
    ]
    b = bytes([TTI_DCB])
    b += dalc(b"\x00" * 16)
    b += ub4(80)
    b += ub4(len(columns))
    b += b"\x00"
    for col in columns:
        b += col
    b += bwl(b"")
    b += ub4(0) * 4
    b += bwl(b"")
    return b


def rowid_value() -> bytes:
    # indicator (reserved size, non-zero) then obj/file/unused/block/slot ub4.
    return (
        bytes([0x0A])
        + ub4(100)  # data object
        + ub4(4)    # relative file
        + ub4(0)    # unused
        + ub4(50)   # block
        + ub4(0)    # slot
    )


def long_value(data: bytes) -> bytes:
    # single-chunk value (< 0xFE) then two trailing ub4 length indicators.
    return bytes([len(data)]) + data + ub4(0) + ub4(0)


def date_value() -> bytes:
    # 2024-01-15 10:30:00 -> century+100, year+100, month, day, h+1, m+1, s+1.
    return dalc(bytes([120, 124, 1, 15, 11, 31, 1]))


def build_rxd() -> bytes:
    row = dalc(b"\xc1\x0b") + rowid_value() + long_value(b"abc") + date_value()
    return bytes([TTI_RXD]) + row


frames = [build_dcb(), build_rxd()]


def ipv4_checksum(h: bytes) -> int:
    s = sum(((h[i] << 8) | h[i + 1]) for i in range(0, len(h), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_checksum(src: bytes, dst: bytes, seg: bytes) -> int:
    pseudo = src + dst + b"\x00\x06" + struct.pack(">H", len(seg))
    buf = pseudo + seg
    if len(buf) % 2:
        buf += b"\x00"
    s = sum(((buf[i] << 8) | buf[i + 1]) for i in range(0, len(buf), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def wrap(body: bytes, seq: int, ip_id: int) -> bytes:
    tns = struct.pack(">HhBBhh", len(body) + 10, 0, 6, 0, 0, 0) + body
    src_ip = bytes([10, 0, 0, 2])
    dst_ip = bytes([10, 0, 0, 1])
    tcp_no_csum = struct.pack(">HHIIBBHHH", 1521, 54321, seq, 0, 0x50, 0x18, 65535, 0, 0)
    csum = tcp_checksum(src_ip, dst_ip, tcp_no_csum + tns)
    tcp = tcp_no_csum[:16] + struct.pack(">H", csum) + tcp_no_csum[18:]
    seg = tcp + tns
    ip_total = 20 + len(seg)
    ip_no = struct.pack(">BBHHHBBH", 0x45, 0, ip_total, ip_id, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip_no[:10] + struct.pack(">H", ipv4_checksum(ip_no)) + ip_no[12:]
    return ip + seg


out = os.path.join(os.path.dirname(__file__), "tns_rxd_types.pcap")
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    seq = 1
    for i, body in enumerate(frames):
        pkt = wrap(body, seq=seq, ip_id=i + 1)
        seq += len(body) + 10
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
