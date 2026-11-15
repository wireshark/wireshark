#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_resend.pcap: the flags byte of a RESEND.

    Frame 1 - a listener's RESEND on a plain connection: no flags
    Frame 2 - a listener's RESEND on a TLS connection it hands to a
              dedicated server: flag 0x08, the server's own TLS handshake
              to come before the client sends its CONNECT again

Bytes are built by hand: the 8-byte packet header alone, as the
listeners of 11g to 21c send it.
"""
import os
import struct

TNS_TYPE_RESEND = 11

frames = [
    (False, struct.pack(">HHBBH", 8, 0, TNS_TYPE_RESEND, 0x00, 0)),
    (False, struct.pack(">HHBBH", 8, 0, TNS_TYPE_RESEND, 0x08, 0)),
]

CLIENTS = [(bytes([10, 0, 0, 1]), 54321), (bytes([10, 0, 0, 3]), 54322)]
SERVER = (bytes([10, 0, 0, 2]), 1521)
OUT_NAME = "tns_resend.pcap"


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


def wrap(conn: int, tns: bytes, to_server: bool, ip_id: int) -> bytes:
    client = CLIENTS[conn]
    (src_ip, sport), (dst_ip, dport) = (client, SERVER) if to_server else (SERVER, client)
    tcp_no_csum = struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18, 65535, 0, 0)
    csum = tcp_checksum(src_ip, dst_ip, tcp_no_csum + tns)
    tcp = tcp_no_csum[:16] + struct.pack(">H", csum) + tcp_no_csum[18:]
    seg = tcp + tns
    ip_no = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(seg), ip_id, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip_no[:10] + struct.pack(">H", ipv4_checksum(ip_no)) + ip_no[12:]
    return ip + seg


out = os.path.join(os.path.dirname(__file__), OUT_NAME)
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    # one connection each, so neither frame reads as the other's
    # retransmission
    for i, (to_server, tns) in enumerate(frames):
        pkt = wrap(i, tns, to_server, i + 1)
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
