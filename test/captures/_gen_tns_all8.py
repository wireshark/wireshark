#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_all8.pcap with two TTI_ALL8 (SQL execute)
request frames:

    Frame 1 — SELECT (options 0x8021 = parse+execute+fetch, fetch 15 rows):
                "SELECT ID, NAME FROM USERS"
    Frame 2 — DML with autocommit (options 0x8121):
                "DELETE FROM USERS WHERE ID = 5"
    Frame 3 — DML with two binds (options 0x8029):
                "UPDATE USERS SET NAME=:1 WHERE ID=:2"
                bind 1 VARCHAR "hi", bind 2 NUMBER 10 — a bare OAC per bind
                then a TTI_RXD row of DALC values.

Bytes are constructed by hand in the Oracle 11g wire shape.
"""
import os
import struct

# TTC tokens / OCI function ids.
TTI_FUN = 3
TTI_RXD = 7
TTI_ALL8 = 94

# Oracle native data-type ids.
TYPE_VARCHAR = 1
TYPE_NUMBER = 2


def ub4(val: int) -> bytes:
    """Variable-length unsigned integer in the Oracle ub4 form."""
    if val == 0:
        return b"\x00"
    if val <= 0xFF:
        return bytes([1, val])
    if val <= 0xFFFF:
        return bytes([2]) + struct.pack(">H", val)
    if val <= 0xFFFFFF:
        return bytes([3]) + struct.pack(">I", val)[1:]
    return bytes([4]) + struct.pack(">I", val)


def dalc(s: bytes) -> bytes:
    return bytes([len(s)]) + s


def oac(data_type: int, charset: int, csform: int, max_size: int) -> bytes:
    return (
        bytes([data_type])       # type (ub1)
        + b"\x00"                # flag (ub1)
        + b"\x00"                # precision (sb1)
        + ub4(0)                 # scale (ub4)
        + ub4(max_size)          # max data length / buffer size (ub4)
        + ub4(0)                 # max array elements (ub4)
        + ub4(0)                 # cont flags (ub4)
        + ub4(0)                 # type OID (empty)
        + ub4(0)                 # version (ub4)
        + ub4(charset)           # charset id (ub4)
        + bytes([csform])        # charset form (ub1)
        + ub4(max_size)          # max size (ub4)
    )


def build_all8(seq: int, sql: bytes, options: int, fetch: int,
               stmt_type: int, binds: list | None = None) -> bytes:
    binds = binds or []
    al8 = [options, fetch, 0, 0, 0, 0, 0, stmt_type, 0, 0, 0, 0, 0]
    b = bytes([TTI_FUN, TTI_ALL8, seq])
    b += ub4(options)            # options
    b += ub4(0)                  # cursor id (0 = new)
    b += bytes([1])              # query present flag
    b += ub4(len(sql))           # query length
    b += bytes([1])              # all8 present flag
    b += ub4(len(al8))           # all8 length
    b += bytes([0, 0])           # two reserved bytes
    b += ub4(0)                  # long max value
    b += ub4(fetch)              # fetch rows
    b += ub4(0)                  # max value
    b += bytes([1 if binds else 0])  # bind indicator
    b += ub4(len(binds))         # bind count
    b += bytes([0, 0, 0, 0, 0])  # five reserved bytes
    b += bytes([0])              # define-columns present flag
    b += ub4(0)                  # define-columns count
    b += bytes([0, 0, 1])        # marker
    b += bytes([0, 0, 0, 0, 0])  # server version slot (5 bytes)
    b += sql                     # SQL text (flat on 11g)
    for elem in al8:             # al8i4 option array
        b += ub4(elem)
    if binds:
        for data_type, charset, csform, max_size, _value in binds:
            b += oac(data_type, charset, csform, max_size)
        b += bytes([TTI_RXD])    # one value row
        for _dt, _cs, _cf, _ms, value in binds:
            b += dalc(value)
    return b


frames = [
    build_all8(1, b"SELECT ID, NAME FROM USERS", 0x8021, 15, 1),
    build_all8(2, b"DELETE FROM USERS WHERE ID = 5", 0x8121, 0, 0),
    build_all8(3, b"UPDATE USERS SET NAME=:1 WHERE ID=:2", 0x8029, 0, 0, binds=[
        (TYPE_VARCHAR, 873, 1, 32, b"hi"),
        (TYPE_NUMBER, 0, 0, 22, b"\xc1\x0b"),
    ]),
]


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


def wrap(body: bytes, seq: int, ip_id: int) -> bytes:
    # TNS DATA framing (10 bytes).
    tns = struct.pack(">HhBBhh", len(body) + 10, 0, 6, 0, 0, 0) + body

    src_ip = bytes([10, 0, 0, 1])
    dst_ip = bytes([10, 0, 0, 2])
    # Client -> server (requests), so dst_port is the listener port 1521.
    tcp_no_csum = struct.pack(
        ">HHIIBBHHH",
        54321, 1521,
        seq, 0,
        0x50, 0x18, 65535, 0, 0,
    )
    csum = tcp_checksum(src_ip, dst_ip, tcp_no_csum + tns)
    tcp = tcp_no_csum[:16] + struct.pack(">H", csum) + tcp_no_csum[18:]
    seg = tcp + tns

    ip_total = 20 + len(seg)
    ip_no = struct.pack(">BBHHHBBH", 0x45, 0, ip_total, ip_id, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip_no[:10] + struct.pack(">H", ipv4_checksum(ip_no)) + ip_no[12:]
    return ip + seg


out = os.path.join(os.path.dirname(__file__), "tns_all8.pcap")
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    # Cumulative TCP sequence so a smaller follow-on frame is not read as a
    # retransmission and dropped before the TNS layer is dissected.
    seq = 1
    for i, body in enumerate(frames):
        pkt = wrap(body, seq=seq, ip_id=i + 1)
        seq += len(body) + 10
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
