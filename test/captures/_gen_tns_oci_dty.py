#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_dty.pcap: the data-type round of an OCI
client (sqlplus), whose TTI_DTY has encoding flag 2 and no type table.

    Frame 1 - sqlplus 11.2's TTI_DTY: charsets 873, flag 2, field version
              6, then the time zone block (offset +00:00:00), timezone
              file version 14 and national charset 2000
    Frame 2 - the server's answer: the time zone block and the timezone
              file version
    Frame 3 - a 136-byte OCI status: success, row count 1, command 2,
              before any execute has been seen
    Frames 4 and 5 - the same round from sqlplus 10.2 (field version 4)
              on a second connection, without the timezone file version
              either way

The two requests are the ones sqlplus sends, as captured off a live
session. Bytes are built by hand.
"""
import os
import struct

TTI_OER = 4

DTY_SQLPLUS_11_2 = bytes.fromhex(
    "02690369030227060101010f010106010101010101017fff030a030701017f017fff0109"
    "0101bf010506000107040702010000180003800000003c3c3c800000000000000ed007")
DTY_SQLPLUS_10_2 = bytes.fromhex(
    "02690369030224060101010d01010401010101010101ffff0308030301003f01473f0102"
    "01010301000001050201000018800000003c3c3c80000000d007")
TZ_BLOCK = bytes.fromhex("800000003c3c3c80000000")
TZFILE_VERSION = 14


def oci_oer(status, seq, rowcount, command, call_seq):
    """A 136-byte OCI status block."""
    b = bytearray(136)
    b[0] = TTI_OER
    b[1] = status
    b[5:7] = struct.pack("<H", seq)
    b[7] = 1
    b[8:12] = struct.pack("<I", rowcount)
    b[18] = 1
    b[22] = command
    b[49:51] = struct.pack("<H", call_seq)
    return bytes(b)


frames = [
    (0, True, DTY_SQLPLUS_11_2),
    (0, False, bytes([2]) + TZ_BLOCK + struct.pack(">I", TZFILE_VERSION)),
    (0, False, oci_oer(1, 5, 1, 2, 6)),
    (1, True, DTY_SQLPLUS_10_2),
    (1, False, bytes([2]) + TZ_BLOCK),
]


OUT_NAME = "tns_oci_dty.pcap"
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
