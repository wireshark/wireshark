#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_malformed.pcap with two hostile TTI piggyback
frames, both client -> server:

    Frame 1 — cursor count of 256 in a packet with three bytes left after it
    Frame 2 — an Oracle variable-length integer whose width byte is 5, which
              is not one of the 0..4 widths the form allows

Both numbers come straight off the wire, so a dissector must treat them as
malformed input rather than as something that cannot happen.

Bytes are constructed by hand in the Oracle 11g wire shape.
"""
import os
import struct

SQLNET_PIGGYBACK_FUNC = 17


def piggyback(cursors: bytes) -> bytes:
    """A piggyback request body: function id, piggyback id, sequence, then
    the cursor count in whatever encoding the caller wants to try."""
    return bytes([SQLNET_PIGGYBACK_FUNC, 0x01, 0x02]) + cursors


frames = [
    # ub4 width 2, value 0x0100 = 256 cursors, with nothing to hold them
    piggyback(b"\x02\x01\x00"),
    # width byte 5 - outside the 0..4 the encoding defines
    piggyback(b"\x05\x01\x02\x03\x04\x05"),
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


def wrap(body: bytes, seq: int) -> bytes:
    # TNS DATA framing (10 bytes).
    tns = struct.pack(">HhBBhh", len(body) + 10, 0, 6, 0, 0, 0) + body

    src_ip = bytes([10, 0, 0, 1])
    dst_ip = bytes([10, 0, 0, 2])
    # Client -> server (requests).
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
    ip_no = struct.pack(">BBHHHBBH", 0x45, 0, ip_total, seq, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip_no[:10] + struct.pack(">H", ipv4_checksum(ip_no)) + ip_no[12:]
    return ip + seg


out = os.path.join(os.path.dirname(__file__), "tns_malformed.pcap")
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    # Sequence numbers accumulate: a later, shorter frame reusing an earlier
    # one's sequence space reads as a retransmission and is never dissected.
    seq = 1
    for i, body in enumerate(frames):
        pkt = wrap(body, seq)
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
        seq += len(body) + 10
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
