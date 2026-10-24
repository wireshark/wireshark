#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_binds.pcap: executes from an OCI client
(sqlplus) that carry binds - behind the SQL, the al8i4 array, one
fixed-width descriptor per bind, then the TTI_RXD row of values.

    Frame 1 - sqlplus 23.26, narrow preamble in the 12c band (SQL at 240):
              "SELECT :vc7, :vc4k, :ch13, :nch5, :nvc9, :n FROM dual" with
              VARCHAR2(7), VARCHAR2(4000), CHAR(13), NCHAR(5), NVARCHAR2(9)
              and NUMBER binds, 49-byte descriptors. The VARCHAR2(4000)'s
              12000-byte buffer sends its value ("defgh") last; the NCHAR
              values ("?" in UTF-16) are chunked with one-byte lengths
    Frame 2 - the same statement from sqlplus 11.2 (SQL at 176), on a
              second connection: 41-byte descriptors, NCHAR values plain
    Frame 3 - "SELECT :n, :n FROM dual" from the same sqlplus 11.2: the
              second descriptor's flag 0x80 marks a repeated name, which
              has no value in the row

Frames 1 and 2 are the bytes sqlplus sent to a test server with those
values; frame 3 is built from frame 2's parts.
"""
import os
import struct

SIX_BINDS_23_26 = bytes.fromhex(
    '035e1e6980000000000000feffffffffffffff9f000000feffffffffffffff0d000000fe'
    'fffffffffffffffeffffffffffffff000000000100000000000000feffffffffffffff06'
    '0000000000000000000000feffffffffffffff0000000000000000fefffffffffffffffe'
    'fffffffffffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000003553454c454354203a7663372c'
    '203a7663346b2c203a636831332c203a6e6368352c203a6e7663392c203a6e2046524f4d'
    '206475616c01000000000000000000000000000000000000000000000000000000010000'
    '000000000000800000000000000000000000000000010103000015000000000000000000'
    '000000000000000000000000000000000000000000006903010000000000000000000101'
    '030000e02e00000000000000000000000000000000000000000000000000000000000069'
    '030100000000000000000001600300002700000000000000000000000000000000000000'
    '00000000000000000000000069030100000000000000000001600300000a000000000000'
    '00000000001000000000000000000000000000000000000000d007020005000000000000'
    '000101030000120000000000000000000000100000000000000000000000000000000000'
    '0000d0070200090000000000000001020300001600000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000070361626302696afe'
    '0100013f00fe0100013f0002c12b056465666768'
)
SIX_BINDS_11_2 = bytes.fromhex(
    '035e1a6980000000000000feffffffffffffff9f000000feffffffffffffff0d000000fe'
    'fffffffffffffffeffffffffffffff000000000100000000000000feffffffffffffff06'
    '0000000000000000000000feffffffffffffff0000000000000000fefffffffffffffffe'
    'fffffffffffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffff000000000000000000000000000000000000000000000000000000003553454c45'
    '4354203a7663372c203a7663346b2c203a636831332c203a6e6368352c203a6e7663392c'
    '203a6e2046524f4d206475616c0100000000000000000000000000000000000000000000'
    '000000000001000000000000000000000000000000000000000000000001010300001500'
    '000000000000000000000000000000000000000000006903010000000000000000000101'
    '030000e02e00000000000000000000000000000000000000000000690301000000000000'
    '000000016003000027000000000000000000000000000000000000000000000069030100'
    '000000000000000001600300000a00000000000000100000000000000000000000000000'
    '00d007020005000000000000000101030000120000000000000010000000000000000000'
    '000000000000d00702000900000000000000010203000016000000000000000000000000'
    '0000000000000000000000000000000000000000000000070361626302696a02003f0200'
    '3f02c12b056465666768'
)


def repeated_name() -> bytes:
    """sqlplus 11.2's preamble with "SELECT :n, :n FROM dual": a NUMBER
    descriptor, the same with flag 0x80 and no buffer, and a row of one
    value."""
    sql = b"SELECT :n, :n FROM dual"
    six_sql = SIX_BINDS_11_2[175]
    al8i4 = SIX_BINDS_11_2[176 + six_sql:176 + six_sql + 52]
    number = SIX_BINDS_11_2[176 + six_sql + 52 + 5 * 41:176 + six_sql + 52 + 6 * 41]
    repeat = bytearray(number)
    repeat[2] = 0x80
    repeat[5:9] = bytes(4)
    head = bytearray(SIX_BINDS_11_2[:175])
    head[2] = 0x1b
    head[19:23] = struct.pack("<I", 3 * len(sql))
    head[71:75] = struct.pack("<I", 2)
    return (bytes(head) + bytes([len(sql)]) + sql + al8i4 + number
            + bytes(repeat) + bytes.fromhex("0702c12b"))


frames = [
    (0, True, SIX_BINDS_23_26),
    (1, True, SIX_BINDS_11_2),
    (1, True, repeated_name()),
]


OUT_NAME = "tns_oci_binds.pcap"


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
    seq = {(c, d): 1 for c in range(len(CLIENTS)) for d in (True, False)}
    for i, (conn, to_server, body) in enumerate(frames):
        pkt = wrap(conn, body, to_server, seq[conn, to_server], seq[conn, not to_server], i + 1)
        seq[conn, to_server] += len(body) + 10
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
