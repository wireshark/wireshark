#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_marker.pcap with two TNS_MARKER packets:

    Frame 1 — break marker (01 00 01): interrupt the call
    Frame 2 — reset marker (01 00 02): clear the line

A TNS_MARKER (packet type 12) has an 8-byte header and a 3-byte body
whose final byte selects break vs reset.
"""
import os
import struct

TNS_TYPE_MARKER = 12


def build_marker(func: int) -> bytes:
    # Marker body: type=01, data=00, function (01 break / 02 reset).
    return bytes([0x01, 0x00, func])


frames = [
    build_marker(0x01),  # break
    build_marker(0x02),  # reset
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
    # TNS non-DATA framing (8-byte header): ub2 length, ub2 checksum,
    # type, reserved, ub2 header checksum.
    tns = struct.pack(">HHBBH", len(body) + 8, 0, TNS_TYPE_MARKER, 0, 0) + body

    src_ip = bytes([10, 0, 0, 2])
    dst_ip = bytes([10, 0, 0, 1])
    # Server -> client marker.
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


out = os.path.join(os.path.dirname(__file__), "tns_marker.pcap")
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    # Cumulative TCP sequence so a follow-on frame is not read as a
    # retransmission and dropped before the TNS layer is dissected.
    seq = 1
    for i, body in enumerate(frames):
        pkt = wrap(body, seq=seq, ip_id=i + 1)
        seq += len(body) + 8
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
