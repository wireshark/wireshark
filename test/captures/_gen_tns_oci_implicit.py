#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_implicit.pcap: the implicit result sets a
PL/SQL block returns with DBMS_SQL.RETURN_RESULT, as a 21c server sends
them to an OCI client (sqlplus 23.26).

    Frame 1 - sqlplus executes "declare c sys_refcursor; begin open c for
              select 1 as n from dual; dbms_sql.return_result(c); end;"
    Frame 2 - the reply opens with the TTI_IRD block: one result, a NUMBER
              column N, on cursor 3
    Frame 3 - the same execute again
    Frame 4 - two results: N on cursor 3, then a CHAR(1) column S and a
              NUMBER column M on cursor 4

The executes and the blocks are the bytes sqlplus and the server sent; the
status that ends each reply is left out.
"""
import os
import struct

EXECUTE = bytes.fromhex(
    '035e0b2100040000000000feffffffffffffff26010000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000626465636c6172652063207379735f7265'
    '66637572736f723b20626567696e206f70656e206320666f722073656c656374'
    '2031206173206e2066726f6d206475616c3b2064626d735f73716c2e72657475'
    '726e5f726573756c742863293b20656e643b0100000001000000000000000000'
    '0000000000000000000000000000090000000000000000800000000000000000'
    '000000000000'
)
ONE_RESULT = bytes.fromhex(
    '1b01000000000002000000010000005c01020000810200000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00010101000000014e00000000000000000000000000000700000007605031ba'
    '5a7f0000000000e81f000000000000000000000000000003000000'
)
TWO_RESULTS = bytes.fromhex(
    '1b02000000000002000000010000005c01020000810200000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00010101000000014e00000000000000000000000000000700000007601033d9'
    'bf7f0000000000e81f0000000000000000000000000000030000000000030000'
    '00020000005c0160800000010000000000000000000000000000000000000000'
    '00000000000000000000006903010001000000fe3f0000010101000000015300'
    '0000000000000000000000000001020000810200000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000101'
    '01000000014d00000000000000000100000000000700000007601033d9bf7f00'
    '00000000e81f000000000000000000000000000004000000'
)


frames = [
    (0, True, EXECUTE),
    (0, False, ONE_RESULT),
    (0, True, EXECUTE),
    (0, False, TWO_RESULTS),
]


OUT_NAME = "tns_oci_implicit.pcap"


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


CLIENTS = [(bytes([10, 0, 0, 1]), 54321)]
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
    seq = {(c, d): 1 for c in range(len(CLIENTS)) for d in (True, False)}
    for i, (conn, to_server, body) in enumerate(frames):
        pkt = wrap(conn, body, to_server, seq[conn, to_server], seq[conn, not to_server], i + 1)
        seq[conn, to_server] += len(body) + 10
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
