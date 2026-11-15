#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_describe.pcap: the describe of a
query's columns, as a server sends it to an OCI client.

Connection 1, an OCI 11.2 program and a 10g server:
    Frames 1-4 - the protocol and data-type rounds, the server offering
                 field version 4 (10.2)
    Frame 5    - an execute of "select 1 from dual"
    Frame 6    - the reply: a describe whose leading field has a ub1
                 length, one column, then the row and the status
    Frame 7    - an execute of "SELECT g, AVG(n) FROM PYO_AVG GROUP BY g
                 ORDER BY g"
    Frame 8    - the reply: two columns, neither with the uds flags 11g
                 adds, then three rows and ORA-01403

Connection 2, sqlplus 11.2 and an 11g server:
    Frames 9-10 - the data-type round, at field version 6 (11.2)
    Frame 11    - an execute of "select 1 n, 'abc' s, date '2026-11-05' d,
                  cast(null as varchar2(10)) z from dual"
    Frame 12    - the reply: a describe whose leading field has a ub4
                  length, four columns with their uds flags, then the row
                  and the status

The replies, and frames 3, 5 and 9, are what the clients and servers
(Oracle 10.2.0.5 and 11.2.0.2) sent; frames 7 and 11 are built field by
field as the client sends them, and frames 1, 2, 4 and 10 by hand.
"""
import os
import struct

PRO = bytes([1, 6, 5, 4, 3, 2, 1, 0]) + b"python\x00"
FDO = bytearray(16)
FDO[5], FDO[6] = 2, 1
FDO[12:14] = struct.pack(">H", 2000)
COMPILE_CAPS = bytearray(53)
COMPILE_CAPS[7] = 4
PRO_REPLY = (bytes([1, 6, 0]) + b"x86_64/Linux 2.4.xx\x00"
             + struct.pack("<HBH", 873, 1, 0) + struct.pack(">H", len(FDO)) + bytes(FDO)
             + bytes([len(COMPILE_CAPS)]) + COMPILE_CAPS + bytes([11]) + bytes(11))
DTY = bytes.fromhex(
    '02690369038327060101010f010106010101010101017fff030a030701017f01'
    '7fff01090101bf010506000107040702010000180003800000003c3c3c800000'
    '00d007'
)
DTY_REPLY = bytes.fromhex("02800000003c3c3c80000000")
SELECT = bytes.fromhex(
    '035e056180000000000000feffffffffffffff12000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff1273656c65637420312066726f'
    '6d206475616c0100000000000000000000000000000000000000000000000000'
    '0000010000000000000000000000000000000000000000000000'
)
QUERY_REPLY = bytes.fromhex(
    '1017b4c94d7dfbbcf023ed720251c896e0aa787e0b0217052f02000000010000'
    '004d010200000002000000000000000000000000000000000000000000000000'
    '0000000000000000000000010101000000013100000000000000000000070000'
    '0007787e0b08013c2e01000000e81f0000020000000200000006010200010000'
    '0000000100000000000000000000000000000000000eda057f00000000000000'
    '00000000000000ff7f00000702c1020806001f3c4b0000000000010000000000'
    '0000000000000000000000000100000000000b0000000b800000003d3c3c8000'
    '0000a30000000000040100000004000101000000000000000000010000000300'
    '0000000000000000000000000000000000000000000000000005000001000000'
    '36010000000000000000000000000000809aaf06000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000'
)
GROUP_BY = bytes.fromhex(
    '035e076180000000000000feffffffffffffff33000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000f0000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff3353454c45435420672c204156'
    '47286e292046524f4d2050594f5f4156472047524f55502042592067204f5244'
    '4552204259206701000000000000000000000000000000000000000000000000'
    '000000010000000000000000000000000000000000000000000000'
)
GROUP_BY_REPLY = bytes.fromhex(
    '1017c55bed22dc3ccef7bde8baba0e466aa6787e0b080407332c000000020000'
    '004d010200008116000000000000000000000000000000000000000000000000'
    '0000000000000000000000010101000000014700000000000000000000010200'
    '0000160000000000000000000000000000000000000000000000000000000000'
    '00000000000001060600000006415647284e2900000000000000000100070000'
    '0007787e0b0804073301000000e81f00000a0000000a00000006010200020000'
    '0000006400000000000000000000000000000000003f6c127f00000000000000'
    '00000000003f6c127f00000702c1020dca0d23394f5b0d23394f5b0d560702c1'
    '0315c10243434343434343434343434343434343434344150200030702c10400'
    '080600daac4b0000000000010000000000000000000000000000000000000000'
    '0000000401000000220001030000007b050000000001001600030020000005b5'
    '4201000100000052610000050000000000000000240000010000003601000000'
    '0000000000000000000000809aaf060000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000194f52412d30313430333a206e6f20646174612066'
    '6f756e640a'
)
DTY_11G = bytes.fromhex(
    '02690369030227060101010f010106010101010101017fff030a030701017f01'
    '7fff01090101bf010506000107040702010000180003800000003c3c3c800000'
    '000000000ed007'
)
QUERY_11G = bytes.fromhex(
    '035e056180000000000000fefffffffffffffff000000000000000feffffffff'
    'ffffff0d00000000000000fefffffffffffffffeffffffffffffff000000000f'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000feffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'fffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '000000fe4073656c6563742031206e2c20276162632720732c20646174652027'
    '323032362d31312d30352720642c2063617374286e756c6c2061732076617263'
    '68617232281031302929207a2066726f6d206475616c00010000000000000000'
    '0000000000000000000000000000000000000001000000000000000000000000'
    '0000000000000000000000'
)
QUERY_11G_REPLY = bytes.fromhex(
    '101700000056e715103ce7ddc2f94151759ed3eaa2787e0b0516313316000000'
    '0400000051010200008102000000000000000000000000000000000000000000'
    '0000000000000000000000000000010101000000014e00000000000000000000'
    '0000000001608000000300000000000000000000000000000000000000000000'
    '0069030100030000000000000001010100000001530000000000000000010000'
    '000000010c000000010000000000000000000000000000000000000000000000'
    '0000000000000000000000000101010000000144000000000000000002000000'
    '000001018000000a000000000000000000000000000000000000000000000069'
    '0301000a00000000000000010101000000015a00000000000000000300000000'
    '000700000007787e0b0516313300000000e81f00000200000002000000000000'
    '00060122ef0400000000000100000000000000000000000000000000005f0e7c'
    '7f0000000000000000000000009597000000000702c1020361626307787e0b05'
    '01010100080600906f7000000000000100000000000000000000000000000000'
    '0000000000000004010000001300010100000000000000000001004c00030000'
    '0000000000000000000000000000000000000000000000001400000100000000'
    '00000000000000000000000000000020f6310a00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000'
)
DTY_11G_REPLY = bytes.fromhex("02800000003c3c3c800000000000000e")

frames = [
    (0, True, PRO),
    (0, False, PRO_REPLY),
    (0, True, DTY),
    (0, False, DTY_REPLY),
    (0, True, SELECT),
    (0, False, QUERY_REPLY),
    (0, True, GROUP_BY),
    (0, False, GROUP_BY_REPLY),
    (1, True, DTY_11G),
    (1, False, DTY_11G_REPLY),
    (1, True, QUERY_11G),
    (1, False, QUERY_11G_REPLY),
]


OUT_NAME = "tns_oci_describe.pcap"
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


CLIENTS = [(bytes([10, 0, 0, 1]), 54321), (bytes([10, 0, 0, 3]), 54322)]
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
