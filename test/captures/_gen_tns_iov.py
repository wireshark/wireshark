#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_iov.pcap with two TTI_IOV frames:

    Frame 1 — a PL/SQL block with 3 binds (IN, OUT, IN OUT); because two
              binds are OUT/IN OUT a TTI_RXD row of the returned values
              follows the direction vector.
    Frame 2 — a block with 2 pure-IN binds; no values follow.

Bytes are constructed by hand in the Oracle 11g wire shape. Only the direction vector is decoded by the dissector;
the trailing RXD values (which need each bind's type to decode) are left
to the generic data dissector.
"""
import os
import struct

# Bind directions (TNS_BIND_DIR_*).
OUT = 16
IN = 32
IN_OUT = 48


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


def dalc(s: bytes) -> bytes:
    return bytes([len(s)]) + s


def build_iov(directions: list[int], rxd_values: list[bytes] | None) -> bytes:
    num_binds = len(directions)
    num_iters, num_requests = divmod(num_binds, 256)
    b = bytes([11])          # TTI_IOV token
    b += b"\x00"             # flag
    b += ub4(num_requests)
    b += ub4(num_iters)
    b += ub4(0)              # num iters this time
    b += ub4(0)              # uac buffer length
    b += ub4(0)              # fast-fetch bit vector length (0 => no bytes)
    b += ub4(0)              # rowid length (0 => no bytes)
    b += bytes(directions)
    if rxd_values:
        b += bytes([7])      # TTI_RXD token
        for v in rxd_values:
            b += dalc(v)     # value blob
            b += ub4(0)      # per-value return code (0 => present)
    return b


frames = [
    # IN, OUT, IN OUT -> two returned values: NUMBER 10 (c1 0b) and
    # VARCHAR "hi!".
    build_iov([IN, OUT, IN_OUT], [b"\xc1\x0b", b"hi!"]),
    # Two pure-IN binds -> no RXD row follows.
    build_iov([IN, IN], None),
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


out = os.path.join(os.path.dirname(__file__), "tns_iov.pcap")
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    # Cumulative TCP sequence so successive frames don't overlap (a smaller
    # frame after a larger one would otherwise read as a pure retransmission
    # and the TNS layer would never be dissected).
    seq = 1
    for i, body in enumerate(frames):
        pkt = wrap(body, seq=seq, ip_id=i + 1)
        seq += len(body) + 10
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
