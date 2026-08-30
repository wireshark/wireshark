#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_dcb.pcap with the SELECT describe/row-header
response tokens:

    Frame 1 — TTI_DCB describe of a 2-column result set:
                col 1  NUMBER   "ID"    (scale -127, the NUMBER default)
                col 2  VARCHAR2 "NAME"  (charset AL32UTF8, csform 1, size 100)
    Frame 2 — TTI_RXH row header (num_iters = 2).

Bytes are constructed by hand in the Oracle 11g wire shape.
"""
import os
import struct

# TTC token ids.
TTI_RXH = 6
TTI_DCB = 16

# Oracle native data-type ids.
TYPE_VARCHAR = 1
TYPE_NUMBER = 2


def ub4(val: int) -> bytes:
    """Variable-length unsigned integer in the Oracle ub4 form."""
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
    """Signed variable-length integer (sign-magnitude): the high bit of the
    length byte flags a negative value. NUMBER scale -127 -> 0x81 0x7f."""
    if val == 0:
        return b"\x00"
    b = bytearray(ub4(abs(val)))
    if val < 0:
        b[0] |= 0x80
    return bytes(b)


def dalc(s: bytes) -> bytes:
    return bytes([len(s)]) + s


def swl(s: bytes) -> bytes:
    """str_with_length: a ub4 count and, when non-zero, a DALC blob."""
    if not s:
        return ub4(0)
    return ub4(len(s)) + dalc(s)


def bwl(s: bytes) -> bytes:
    """bytes_with_length: a ub4 count and, when non-zero, a length-prefixed
    blob. Only the empty form is needed here."""
    if not s:
        return ub4(0)
    return ub4(len(s)) + dalc(s)


def oac(data_type: int, precision: int, scale: int, max_length: int,
        charset: int, csform: int, max_size: int) -> bytes:
    return (
        bytes([data_type])       # type (ub1)
        + b"\x00"                # flag (ub1)
        + bytes([precision])     # precision (sb1)
        + sb4(scale)             # scale (ub4)
        + ub4(max_length)        # max data length / buffer size (ub4)
        + ub4(0)                 # max array elements (ub4)
        + ub4(0)                 # cont flags (ub4)
        + bwl(b"")               # type OID (bytes_with_length)
        + ub4(0)                 # version (ub4)
        + ub4(charset)           # charset id (ub4)
        + bytes([csform])        # charset form (ub1)
        + ub4(max_size)          # max size (ub4)
    )


def dcb_column(data_type: int, precision: int, scale: int, max_length: int,
               charset: int, csform: int, max_size: int, name: bytes) -> bytes:
    return (
        oac(data_type, precision, scale, max_length, charset, csform, max_size)
        + b"\x01"                # nulls allowed (ub1)
        + bytes([len(name)])     # v7 name length (ub1)
        + swl(name)              # column name (str_with_length)
        + swl(b"")               # schema name (str_with_length)
        + swl(b"")               # type name (str_with_length)
        + ub4(0)                 # column position (ub4)
        + ub4(0)                 # uds flags (ub4, 11g)
    )


def build_dcb() -> bytes:
    columns = [
        dcb_column(TYPE_NUMBER, 0, -127, 22, 0, 0, 22, b"ID"),
        dcb_column(TYPE_VARCHAR, 0, 0, 100, 873, 1, 100, b"NAME"),
    ]
    b = bytes([TTI_DCB])
    b += dalc(b"\x00" * 16)      # describe-info preamble (cursor uuid + date)
    b += ub4(80)                 # max row size (ub4)
    b += ub4(len(columns))       # num columns (ub4)
    b += b"\x00"                 # reserved byte (num columns > 0)
    for col in columns:
        b += col
    b += bwl(b"")                # current date (bytes_with_length)
    b += ub4(0) * 4              # dcbflag / dcbmdbz / dcbmnpr / dcbmxpr
    b += bwl(b"")                # dcbqcky (bytes_with_length)
    return b


def build_rxh(num_iters: int) -> bytes:
    return (
        bytes([TTI_RXH])
        + b"\x00"                # flag (ub1)
        + ub4(1)                 # num requests
        + ub4(1)                 # iteration number
        + ub4(num_iters)         # num iterations
        + ub4(0)                 # buffer length
        + ub4(0)                 # bit vector length (0 => no vector)
        + bwl(b"")               # rxhrid (bytes_with_length)
    )


frames = [
    build_dcb(),
    build_rxh(2),
]


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
    # TNS DATA framing (10 bytes).
    tns = struct.pack(">HhBBhh", len(body) + 10, 0, 6, 0, 0, 0) + body

    src_ip = bytes([10, 0, 0, 2])
    dst_ip = bytes([10, 0, 0, 1])
    # Server -> client (replies), so dst_port is the client ephemeral port.
    tcp_no_csum = struct.pack(
        ">HHIIBBHHH",
        1521, 54321,
        seq, 0,
        0x50, 0x18, 65535, 0, 0,
    )
    csum = tcp_checksum(src_ip, dst_ip, tcp_no_csum + tns)
    tcp = tcp_no_csum[:16] + struct.pack(">H", csum) + tcp_no_csum[18:]
    seg = tcp + tns

    ip_total = 20 + len(seg)
    ip_no = struct.pack(">BBHHHBBH", 0x45, 0, ip_total, ip_id, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip_no[:10] + struct.pack(">H", ipv4_checksum(ip_no)) + ip_no[12:]
    return ip + seg


out = os.path.join(os.path.dirname(__file__), "tns_dcb.pcap")
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    # Cumulative TCP sequence so a smaller follow-on frame is not read as a
    # retransmission and dropped before the TNS layer is dissected.
    seq = 1
    for i, body in enumerate(frames):
        pkt = wrap(body, seq=seq, ip_id=i + 1)
        seq += len(body) + 10
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
