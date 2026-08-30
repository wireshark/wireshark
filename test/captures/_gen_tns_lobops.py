#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_lobops.pcap with two TTI_LOBOPS request frames:

    Frame 1 — READ (op 0x0002) from source offset 1, read amount 8192
    Frame 2 — GET_LENGTH (op 0x0001) from source offset 1

Bytes are constructed by hand from the same common request layout
the Oracle 11g wire shape uses. The
dissector decodes the header through the source offset and shows the
opcode; the locator and trailing amount are left to the data dissector.
"""
import os
import struct

TTI_FUN = 3
TTI_LOBOPS = 96

OP_GET_LENGTH = 0x0001
OP_READ = 0x0002


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


def build_lobops(seq: int, op: int, source_offset: int, loc_len: int,
                 amount: int | None) -> bytes:
    b = bytes([TTI_FUN, TTI_LOBOPS, seq])
    b += bytes([1])              # source pointer flag (locator present)
    b += ub4(loc_len)            # source locator length (raw / persistent)
    b += bytes([0])              # dest pointer flag
    b += ub4(amount or 0)        # dest length (read amount target)
    b += ub4(0)                  # short source offset
    b += ub4(0)                  # short dest offset
    b += bytes([0, 0, 0])        # charset / short-amount / null-lob flags
    b += ub4(op)                 # operation
    b += bytes([0, 0])           # scn-array pointer flag + length
    b += ub4(source_offset)      # source offset (1-based)
    b += ub4(0)                  # dest offset
    b += bytes([1 if amount is not None else 0])  # amount pointer flag
    b += bytes([0] * 6)          # three reserved ub2 array-LOB slots
    b += bytes(loc_len)          # locator (raw placeholder bytes)
    if amount is not None:
        b += ub4(amount)         # trailing amount to read (READ)
    return b


# A realistic persistent-LOB locator is ~84-86 bytes. (A locator length of
# exactly 40 would encode as 01 28 and, with the leading source-pointer flag,
# form 01 01 28 — the CREATE_TEMP opener.)
frames = [
    build_lobops(1, OP_READ, 1, 86, 8192),
    build_lobops(2, OP_GET_LENGTH, 1, 86, None),
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

    src_ip = bytes([10, 0, 0, 1])
    dst_ip = bytes([10, 0, 0, 2])
    # Client -> server (requests), so dst_port is the listener port 1521.
    tcp_no_csum = struct.pack(
        ">HHIIBBHHH",
        54321, 1521,
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


out = os.path.join(os.path.dirname(__file__), "tns_lobops.pcap")
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
