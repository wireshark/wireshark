#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_return_params.pcap: the return
parameters an 11g server sends an OCI client ahead of an execute's
status, and the status itself.

Connection 1, sqlplus 11.2:
    Frame 1 - "BEGIN open :rc for select level n, 'r' || level s from
              dual connect by level <= 3; END;", binding a REF CURSOR
    Frame 2 - the reply: the opened cursor 3, then the return parameters
              and the status of the block, cursor 4

Connection 2, sqlplus 11.2:
    Frame 3 - "insert into pyo_drcp_probe values (1, 'one')"
    Frame 4 - the reply: the return parameters, the status of cursor 3,
              one row, and the rowid of the row it inserted

Connection 3, an OCI 11.2 client:
    Frame 5 - "alter session set nls_date_format = 'YYYY-MM-DD'"
    Frame 6 - the reply: the return parameters with the session's 18 NLS
              settings, then the server's piggybacks and the status

The replies are what the server sent, except that the server pointer in
frame 2's header is zeroed. Frame 1 is what sqlplus sent; frames 3 and
5 are built field by field as the client sends them.
"""
import os
import struct

OPEN_REFCURSOR = bytes.fromhex(
    '035e142904040000000000feffffffffffffff0b01000000000000feffffffff'
    'ffffff0d00000000000000fefffffffffffffffeffffffffffffff0000000001'
    '0000000000000000000000feffffffffffffff01000000000000000000000000'
    '000000feffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff489cc826000000000000000000000000fefffffffffffffffeffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '000000fe40424547494e206f70656e203a726320666f722073656c656374206c'
    '6576656c206e2c20277227207c7c206c6576656c20732066726f6d206475616c'
    '20636f6e6e19656374206279206c6576656c203c3d20333b20454e443b0a0000'
    '0100000001000000000000000000000000000000000000000000000008000000'
    '0000000000000000000000000000000000000000016601000001000000000000'
    '0000000000000000000000000000000000000000000000000000000000070400'
    '000000'
)
OPEN_REFCURSOR_REPLY = bytes.fromhex(
    '0b010593010000000000010000000000000000000000000000000000e8070000'
    '00000000000000000000000000000c7f000030074c3f00000002000000510102'
    '0000001600000000000000000000000000000000000000000000000000000000'
    '00000000000000010101000000014e0000000000000000000000000000010180'
    '0000290000000000000000000000000000000000000000000000690301002900'
    '0000000000000101010000000153000000000000000001000000000007000000'
    '07787e0b060e0c0a00000000e81f000000000000000000000000000003000000'
    '000008060016fa75000000000004000000000000000000000000000000000000'
    '0000000000040100000013000101000000000000000000040000002f00000000'
    '0000000000000000000000000000000000000000000014000001000000000000'
    '0000000000000000000000000020f6310a000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000'
)
INSERT = bytes.fromhex(
    '035e062180000000000000feffffffffffffff8400000000000000feffffffff'
    'ffffff0d00000000000000fefffffffffffffffeffffffffffffff0000000001'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000feffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'fffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '0000002c696e7365727420696e746f2070796f5f647263705f70726f62652076'
    '616c7565732028312c20276f6e65272901000000010000000000000000000000'
    '0000000000000000000000000400000000000000000000000000000000000000'
    '00000000'
)
INSERT_REPLY = bytes.fromhex(
    '080600a26f700000000000030000000100000000000000000000000000000000'
    '00000004020000001d00010100000000000000000003000c000200000000006c'
    'd5010004000000560100000000000000000000001e0000010000000000000000'
    '000000000000000000000020f6310a000000000d000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000d000d010001d56c0004000001560000'
)
ALTER_SESSION = bytes.fromhex(
    '035e052180000000000000feffffffffffffff9000000000000000feffffffff'
    'ffffff0d00000000000000fefffffffffffffffeffffffffffffff0000000001'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000feffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'fffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '00000030616c7465722073657373696f6e20736574206e6c735f646174655f66'
    '6f726d6174203d2027595959592d4d4d2d444427010000000100000000000000'
    '0000000000000000000000000000000007000000000000000000000000000000'
    '0000000000000000'
)
ALTER_SESSION_REPLY = bytes.fromhex(
    '0806004cc1700000000000020000000000000000000000000000000000120000'
    '0000000800000008414d45524943414e1000000000000700000007414d455249'
    '43410900000000000100000001240000000000000700000007414d4552494341'
    '01000000000002000000022e2c0200000000000800000008414c333255544638'
    '0a00000000000900000009475245474f5249414e0c00000000000a0000000a59'
    '5959592d4d4d2d44440700000000000800000008414d45524943414e08000000'
    '0000060000000642494e4152590b00000000000e0000000e48482e4d492e5353'
    '58464620414d390000000000180000001844442d4d4f4e2d52522048482e4d49'
    '2e535358464620414d3a0000000000120000001248482e4d492e535358464620'
    '414d20545a523b00000000001c0000001c44442d4d4f4e2d52522048482e4d49'
    '2e535358464620414d20545a523c000000000001000000012434000000000006'
    '0000000642494e4152593200000000000400000004425954453d000000000005'
    '0000000546414c53453e00000000001702050005323737373217040100140000'
    '0000020000004300000039220401000000040001000000000000000000000200'
    '00002a0000000000000000000000000000000000000000000000000000060000'
    '000000000000000000000000000000000000000020f6310a0000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000'
)

frames = [
    (0, True, OPEN_REFCURSOR),
    (0, False, OPEN_REFCURSOR_REPLY),
    (1, True, INSERT),
    (1, False, INSERT_REPLY),
    (2, True, ALTER_SESSION),
    (2, False, ALTER_SESSION_REPLY),
]


OUT_NAME = "tns_oci_return_params.pcap"


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


CLIENTS = [(bytes([10, 0, 0, 1]), 54321), (bytes([10, 0, 0, 3]), 54322), (bytes([10, 0, 0, 5]), 54323)]
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
