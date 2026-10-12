#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_connect_long.pcap: a connect descriptor too
long for the CONNECT packet, sent in a DATA packet straight after it, as
python-oracledb does for a descriptor over 230 bytes.

    Frame 1 - CONNECT, version 318: connect data length 238 and offset 74,
              but the packet ends at offset 74, carrying no connect data
    Frame 2 - DATA, data flags 0, carrying the 238-byte descriptor

Bytes are built by hand.
"""
import os
import struct

TNS_CONNECT = 1
TNS_DATA = 6
CD_OFFSET = 74


def descriptor(length: int) -> bytes:
    """A connect descriptor padded to length bytes by its host name."""
    head = b"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST="
    tail = (b")(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=FREEPDB1)"
            b"(CID=(PROGRAM=python)(HOST=client)(USER=user))))")
    host = b"db." + b"x" * (length - len(head) - len(tail) - len(b"db.example")) + b"example"
    d = head + host + tail
    assert len(d) == length, len(d)
    return d


def connect(cd_len: int) -> bytes:
    """A CONNECT body (after the 8-byte header) ending at CD_OFFSET."""
    b = struct.pack(">HHHHHHHH", 318, 300, 0, 8192, 65535, 0, 0, 0x0100)
    b += struct.pack(">HHI", cd_len, CD_OFFSET, 0)
    b += bytes([0x41, 0x41])          # flags 0 and 1
    b += bytes(CD_OFFSET - 8 - len(b))
    return b


DESC = descriptor(238)
frames = [
    (TNS_CONNECT, connect(len(DESC))),
    (TNS_DATA, b"\x00\x00" + DESC),
]


OUT_NAME = "tns_connect_long.pcap"


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


CLIENT = (bytes([10, 0, 0, 1]), 54321)
SERVER = (bytes([10, 0, 0, 2]), 1521)


def wrap(ptype: int, body: bytes, seq: int, ip_id: int) -> bytes:
    """A client-to-server TNS packet in the 16-bit length envelope."""
    tns = struct.pack(">HHBBH", len(body) + 8, 0, ptype, 0, 0) + body
    (src_ip, sport), (dst_ip, dport) = CLIENT, SERVER
    tcp_no_csum = struct.pack(">HHIIBBHHH", sport, dport, seq, 1, 0x50, 0x18, 65535, 0, 0)
    csum = tcp_checksum(src_ip, dst_ip, tcp_no_csum + tns)
    tcp = tcp_no_csum[:16] + struct.pack(">H", csum) + tcp_no_csum[18:]
    seg = tcp + tns
    ip_no = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(seg), ip_id, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip_no[:10] + struct.pack(">H", ipv4_checksum(ip_no)) + ip_no[12:]
    return ip + seg


out = os.path.join(os.path.dirname(__file__), OUT_NAME)
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    seq = 1
    for i, (ptype, body) in enumerate(frames):
        pkt = wrap(ptype, body, seq, i + 1)
        seq += len(body) + 8
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
