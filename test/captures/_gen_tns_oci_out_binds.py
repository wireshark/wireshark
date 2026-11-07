#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_out_binds.pcap: the OUT values of a
PL/SQL block, as a server sends them to an OCI client (sqlplus).

Connection 1, sqlplus 23.26 against an 18c server:
    Frame 1 - "begin open :rc for select 1 as id, 'a' as name from dual
              union all select 2, 'bb' from dual; end;", binding a REF
              CURSOR with no cursor id
    Frame 2 - the reply: the cursor's describe, two columns ID and NAME,
              and the id it was opened as, 3
    Frame 3 - sqlplus re-executes cursor 3 to fetch the rows

Connection 2, sqlplus 11.2 against an 11g server:
    Frame 4 - "BEGIN :n := 42; END;", binding a NUMBER
    Frame 5 - the reply: the NUMBER 42

Connection 3, an OCI 11.2 client against an 11g server:
    Frame 6 - "BEGIN UPDATE pyo_drcp_r SET n = :1 WHERE id = :2
              RETURNING n INTO :3; END;", binding 7 and 99 IN and a
              NUMBER OUT
    Frame 7 - the reply: directions IN, IN, OUT and the one OUT value, a
              NULL with return code 3105, since no row matched

Connection 4, sqlplus 11.2 against an 11g server:
    Frame 8 - "BEGIN open :rc for select level n, 'r' || level s from
              dual connect by level <= 3; END;", binding a REF CURSOR
    Frame 9 - the reply: the cursor's describe, columns N and S, and the
              id it was opened as, 3

Connection 5, an OCI 11.2 client against an 11g server:
    Frame 10 - "begin open :1 for select 1 from dual; close :1; end;",
               binding a REF CURSOR
    Frame 11 - the reply: the closed cursor, with no columns

The bytes are what sqlplus and the servers sent, except that the server
pointer, SCN and sequence counter in frame 5's header are zeroed and its
value is set to 42, the statement's (it came from a block assigning 7).
Frames 6 and 10 are built field by field as the client sends them, and
the server pointer in frames 7, 9 and 11 is zeroed. The status that ends
each reply is left out.
"""
import os
import struct

OPEN_REFCURSOR = bytes.fromhex(
    '035e0b2904040000000000feffffffffffffff23010000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff010000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000061626567696e206f70656e203a72632066'
    '6f722073656c65637420312061732069642c20276127206173206e616d652066'
    '726f6d206475616c20756e696f6e20616c6c2073656c65637420322c20276262'
    '272066726f6d206475616c3b20656e643b010000000100000000000000000000'
    '0000000000000000000000000008000000000000000080000000000000000000'
    '0000000000016601000001000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000070400000000'
)
REFCURSOR_REPLY = bytes.fromhex(
    '0b0105c3010000000000010000000000000000000000000000000000a52d6e7f'
    '0000a0c3a52d6e7f0000000057930000000030074c04000000020000005c0102'
    '0000810200000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000102020000000249440000000000000000'
    '0000000000000101800000020000000000000000000000000000000000000000'
    '00000000000000000000006903010002000000fe3f0000010404000000044e41'
    '4d4500000000000000000100000000000700000007000000000a200800000000'
    '00000000000000000000000000000000030000000000'
)
PRINT_REFCURSOR = bytes.fromhex(
    '035e0d4000000003000000000000000000000000000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000000000000300000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000f000000000000000000000000'
    '0000000000000000000000010000000000000000000000000000000000000000'
    '000000'
)
ASSIGN = bytes.fromhex(
    '035e152904040000000000feffffffffffffff4200000000000000feffffffff'
    'ffffff0d00000000000000fefffffffffffffffeffffffffffffff0000000001'
    '0000000000000000000000feffffffffffffff01000000000000000000000000'
    '000000feffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff4871cd2b000000000000000000000000fefffffffffffffffeffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '00000016424547494e203a6e203a3d2034323b20454e443b0a00010000000100'
    '0000000000000000000000000000000000000000000008000000000000000000'
    '0000000000000000000000000000010203000016000000000000000000000000'
    '000000000000000000000000000000000000000000000007fd01'
)
ASSIGN_REPLY = bytes.fromhex(
    '0b0105cc010000000000010000000000000000000000000000000000e8070000'
    '000000000000000000000000000000000000100702c12b0000'
)

IN_OUT_BLOCK = bytes.fromhex(
    '035e052904040000000000feffffffffffffffde00000000000000feffffffff'
    'ffffff0d00000000000000fefffffffffffffffeffffffffffffff0000000001'
    '0000000000000000000000feffffffffffffff03000000000000000000000000'
    '000000feffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'fffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '000000fe40424547494e205550444154452070796f5f647263705f7220534554'
    '206e203d203a31205748455245206964203d203a322052455455524e494e4720'
    '6e20494e540a4f203a333b20454e443b00010000000100000000000000000000'
    '0000000000000000000000000008000000000000000000000000000000000000'
    '0000000000010203000016000000000000000000000000000000000000000000'
    '0000000000000000000000000000010203000016000000000000000000000000'
    '0000000000000000000000000000000000000000000000010203000016000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0702c10802c164fd01'
)
IN_OUT_REPLY = bytes.fromhex(
    '0b010592030000000000010000000000000000000000000000000000e8070000'
    '0000000000000000000000000000217f000020201007ff210c'
)

OPEN_11G = bytes.fromhex(
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
OPEN_11G_REPLY = bytes.fromhex(
    '0b010593010000000000010000000000000000000000000000000000e8070000'
    '00000000000000000000000000000c7f000030074c3f00000002000000510102'
    '0000001600000000000000000000000000000000000000000000000000000000'
    '00000000000000010101000000014e0000000000000000000000000000010180'
    '0000290000000000000000000000000000000000000000000000690301002900'
    '0000000000000101010000000153000000000000000001000000000007000000'
    '07787e0b060e0c0a00000000e81f000000000000000000000000000003000000'
    '0000'
)
UNOPENED = bytes.fromhex(
    '035e052904040000000000feffffffffffffff9c00000000000000feffffffff'
    'ffffff0d00000000000000fefffffffffffffffeffffffffffffff0000000001'
    '0000000000000000000000feffffffffffffff01000000000000000000000000'
    '000000feffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'fffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '00000034626567696e206f70656e203a3120666f722073656c65637420312066'
    '726f6d206475616c3b20636c6f7365203a313b20656e643b0100000001000000'
    '0000000000000000000000000000000000000000080000000000000000000000'
    '0000000000000000000000000166030000010000000000000000000000000000'
    '000000000000000000000000000000000000000000070400000000'
)
UNOPENED_REPLY = bytes.fromhex(
    '0b010546010000000000010000000000000000000000000000000000e8070000'
    '0000000000000000000000000000597f000030074c0000000000000000070000'
    '0007787e0b060e13020000000000000000000000000000000000000000000000'
    '000000'
)

frames = [
    (0, True, OPEN_REFCURSOR),
    (0, False, REFCURSOR_REPLY),
    (0, True, PRINT_REFCURSOR),
    (1, True, ASSIGN),
    (1, False, ASSIGN_REPLY),
    (2, True, IN_OUT_BLOCK),
    (2, False, IN_OUT_REPLY),
    (3, True, OPEN_11G),
    (3, False, OPEN_11G_REPLY),
    (4, True, UNOPENED),
    (4, False, UNOPENED_REPLY),
]


OUT_NAME = "tns_oci_out_binds.pcap"
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


CLIENTS = [(bytes([10, 0, 0, 1]), 54321), (bytes([10, 0, 0, 3]), 54322), (bytes([10, 0, 0, 5]), 54323),
           (bytes([10, 0, 0, 7]), 54324), (bytes([10, 0, 0, 9]), 54325)]
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
