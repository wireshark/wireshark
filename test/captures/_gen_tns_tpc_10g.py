#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_tpc_10g.pcap: two-phase commit on a 10g
session, whose transaction switch carries no internal or external name.

    Frame 1 - the client's TTI_DTY, negotiating field version 4 (10.2)
    Frame 2 - a transaction switch (103) starting the branch of XID
              (format 4660, "gtrid-1", "bqual-1"), flags 1 (new) and a
              60-second timeout
    Frame 3 - a state change (104) preparing it, with the transaction
              context the switch's reply returned

The calls are built field by field as a thin client sends them to 10g.
"""
import os
import struct


def dty(field_version: int) -> bytes:
    """A client TTI_DTY whose compile capabilities carry field_version
    (capability 7): charsets, flag, the 38 capability bytes behind their
    length, the table header and identity map (zeros here), and the
    override list's terminator."""
    caps = bytearray(38)
    caps[7] = field_version
    return (bytes([2]) + b"\x69\x03\x69\x03\x01" + bytes([len(caps)]) + caps
            + bytes(8) + bytes(980) + b"\x00")


START = bytes.fromhex(
    '03670401010000021234010701070101800101013c01010167747269642d3162'
    '7175616c2d310000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000'
)
PREPARE = bytes.fromhex(
    '03680501030101a8021234010701070101800000010000010203040506070809'
    '0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829'
    '2a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849'
    '4a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263646566676869'
    '6a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283848586878889'
    '8a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a76774'
    '7269642d31627175616c2d310000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000'
)

frames = [
    (True, dty(4)),
    (True, START),
    (True, PREPARE),
]


OUT_NAME = "tns_tpc_10g.pcap"


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


def wrap(body: bytes, to_server: bool, seq: int, ack: int, ip_id: int) -> bytes:
    tns = struct.pack(">HhBBhh", len(body) + 10, 0, 6, 0, 0, 0) + body
    (src_ip, sport), (dst_ip, dport) = (CLIENT, SERVER) if to_server else (SERVER, CLIENT)
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
    # Cumulative TCP sequence numbers per direction, so a smaller follow-on
    # frame is not read as a retransmission and dropped before TNS sees it.
    seq = {True: 1, False: 1}
    for i, (to_server, body) in enumerate(frames):
        pkt = wrap(body, to_server, seq[to_server], seq[not to_server], i + 1)
        seq[to_server] += len(body) + 10
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
