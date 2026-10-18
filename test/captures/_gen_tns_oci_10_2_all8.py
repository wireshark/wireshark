#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_10_2_all8.pcap: executes from sqlplus
10.2, whose preamble is narrow but puts the SQL at 148, and whose pointer
fields hold real addresses rather than the indicator.

    Frame 1 - sqlplus 10.2's TTI_DTY: flag 2 (an OCI client), field
              version 4
    Frame 2 - the server's answer: its time zone block
    Frame 3 - an execute of "SELECT USER FROM DUAL" on cursor 0, no binds
    Frame 4 - an execute of "BEGIN :r := 42; END;" with one bind
    Frame 5 - frame 3 again on a second connection, whose negotiation was
              not seen: without the field version nothing says it is an
              OCI execute

The executes are the ones sqlplus 10.2.0.5 sent to an 11g server, as
captured off a live session. Bytes are built by hand.
"""
import os
import struct

DTY_SQLPLUS_10_2 = bytes.fromhex(
    "02690369030224060101010d01010401010101010101ffff0308030301003f01473f0102"
    "01010301000001050201000018800000003c3c3c80000000d007")
TZ_BLOCK = bytes.fromhex("800000003c3c3c80000000")

ALL8_SELECT = bytes.fromhex(
    "035e06618000000000000098fd6929000000004200000034d36729000000000d00000000"
    "0000000000000068d3672900000000000000000100000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000006a"
    "d367290000000020fe6929000000000000000000000000000000000000000080d3672900"
    "0000001653454c45435420555345522046524f4d204455414c0001000000000000000000"
    "000000000000000000000000000000000000010000000000000000000000000000000000"
    "000000000000")
ALL8_OUT_BIND = bytes.fromhex(
    "035e342904040000000000f8036a29000000004200000034d36729000000000d00000000"
    "0000000000000068d3672900000000000000000100000000000000c8ed69290000000001"
    "00000000000000000000000000000000000000000000000000000000000000000000006a"
    "d3672900000000c8ed6929000000000000000000000000000000000000000080d3672900"
    "00000016424547494e203a72203a3d2034323b20454e443b0a0001000000010000000000"
    "000000000000000000000000000000000000080000000000000000000000000000000000"
    "000000000000010203000016000000000000000000000000000000000000000000000000"
    "000000000000000000000007fd01")


frames = [
    (0, True, DTY_SQLPLUS_10_2),
    (0, False, bytes([2]) + TZ_BLOCK),
    (0, True, ALL8_SELECT),
    (0, True, ALL8_OUT_BIND),
    (1, True, ALL8_SELECT),
]


OUT_NAME = "tns_oci_10_2_all8.pcap"
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


CLIENTS = [(bytes([10, 0, 0, 1]), 54321), (bytes([10, 0, 0, 1]), 54322)]
SERVER = (bytes([10, 0, 0, 2]), 1521)


def wrap(conn: int, body: bytes, to_server: bool, seq: int, ack: int, ip_id: int) -> bytes:
    tns = struct.pack(">HhBBhh", len(body) + 10, 0, 6, 0, 0, 0) + body
    client = CLIENTS[conn]
    (src_ip, sport), (dst_ip, dport) = (client, SERVER) if to_server else (SERVER, client)
    tcp_no_csum = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, 0x18, 65535, 0, 0)
    csum = tcp_checksum(src_ip, dst_ip, tcp_no_csum + tns)
    tcp = tcp_no_csum[:16] + struct.pack(">H", csum) + tcp_no_csum[18:]
    seg = tcp + tns
    ip_no = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(seg), ip_id, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip_no[:10] + struct.pack(">H", ipv4_checksum(ip_no)) + ip_no[12:]
    return ip + seg


out = os.path.join(os.path.dirname(__file__), OUT_NAME)
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    # Cumulative TCP sequence numbers per connection and direction, so a
    # smaller follow-on frame is not read as a retransmission and dropped
    # before TNS sees it.
    seq = {(c, d): 1 for c in (0, 1) for d in (True, False)}
    for i, (conn, to_server, body) in enumerate(frames):
        pkt = wrap(conn, body, to_server, seq[conn, to_server], seq[conn, not to_server], i + 1)
        seq[conn, to_server] += len(body) + 10
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
