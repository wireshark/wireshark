#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_status.pcap: the statuses a server sends
an OCI client (sqlplus), whose integers are fixed-width little-endian.

    Frame 1 - an OCI execute of "SELECT * FROM NOSUCH" (the wide preamble)
    Frame 2 - its 136-byte status: error 942 at position 14, then the
              message "ORA-00942: table or view does not exist"
    Frame 3 - an OCI execute of an INSERT
    Frame 4 - its 136-byte status: success, 1 row, command type 2
              (INSERT), sequence 5, answering call 6
    Frame 5 - an OCI execute of "SELECT 1 FROM DUAL"
    Frame 6 - the compact 24-byte status of a query's execute, command
              type 3 (SELECT)
    Frame 7 - a commit call
    Frame 8 - its 7-byte TTI_STA: call status 5, sequence 7

Bytes are built by hand.
"""
import os
import struct

# TTC tokens / OCI function ids.
TTI_FUN = 3
TTI_OER = 4
TTI_RXH = 6
TTI_RXD = 7
TTI_RPA = 8
TTI_STA = 9
TTI_IOV = 11
TTI_DCB = 16
TTI_ALL8 = 94

# Oracle datatype codes.
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


def sb4(val: int) -> bytes:
    if val == 0:
        return b"\x00"
    b = bytearray(ub4(abs(val)))
    if val < 0:
        b[0] |= 0x80
    return bytes(b)


def dalc(s: bytes) -> bytes:
    return bytes([len(s)]) + s


def bwl(s: bytes) -> bytes:
    """bytes_with_length: a ub4 count, then a DALC only when non-empty."""
    return ub4(0) if not s else ub4(len(s)) + dalc(s)


def oac(data_type, max_length, charset=0, csform=0, max_size=0,
        precision=0, scale=0):
    return (
        bytes([data_type]) + b"\x00" + bytes([precision]) + sb4(scale)
        + ub4(max_length) + ub4(0) + ub4(0) + bwl(b"") + ub4(0)
        + ub4(charset) + bytes([csform]) + ub4(max_size)
    )


def dcb_column(data_type, max_length, name, charset=0, csform=0,
               max_size=0, precision=0, scale=0):
    return (
        oac(data_type, max_length, charset, csform, max_size, precision, scale)
        + b"\x01" + bytes([len(name)]) + bwl(name) + bwl(b"") + bwl(b"")
        + ub4(0) + ub4(0)
    )


def describe_body(columns) -> bytes:
    """The describe body shared by TTI_DCB and a nested cursor value."""
    b = ub4(80)                  # max row size
    b += ub4(len(columns))       # num columns
    if columns:
        b += b"\x00"
    for col in columns:
        b += col
    b += bwl(b"")                # current date
    b += ub4(0) * 4              # dcbflag / mdbz / mnpr / mxpr
    b += bwl(b"")                # dcbqcky
    return b


def dcb(columns) -> bytes:
    return bytes([TTI_DCB]) + dalc(b"\x00" * 16) + describe_body(columns)


def all8(seq, sql, options, binds=(), rows=(), cursor=0, al8=None,
         defines=()) -> bytes:
    """An 11g-shape TTI_ALL8 execute. `binds` and `defines` are OAC blobs,
    `rows` are the already-encoded value rows (each gets a leading
    TTI_RXD)."""
    al8 = al8 if al8 is not None else [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    b = bytes([TTI_FUN, TTI_ALL8, seq])
    b += ub4(options) + ub4(cursor)
    b += bytes([1 if sql else 0]) + ub4(len(sql))
    b += bytes([1]) + ub4(len(al8))
    b += bytes([0, 0]) + ub4(0) + ub4(0) + ub4(0)
    b += bytes([1 if binds else 0]) + ub4(len(binds))
    b += bytes([0, 0, 0, 0, 0])
    b += bytes([1 if defines else 0]) + ub4(len(defines))
    b += bytes([0, 0, 1]) + bytes([0, 0, 0, 0, 0])
    b += sql
    for elem in al8:
        b += ub4(elem)
    for o in list(binds) + list(defines):
        b += o
    for r in rows:
        b += bytes([TTI_RXD]) + r
    return b


def oer(err_code=0, cursor=0, rowcount=0, call_status=0, msg=b"") -> bytes:
    """An 11g-shape TTI_OER."""
    b = bytes([TTI_OER])
    b += ub4(call_status) + ub4(0) + ub4(rowcount) + ub4(err_code)
    b += ub4(0) + ub4(0) + ub4(cursor) + ub4(0)
    b += bytes(6)
    b += ub4(0) + ub4(0) + b"\x00" + ub4(0) + ub4(0)
    b += ub4(0) + bytes(2) + ub4(0) + ub4(0)
    b += bwl(b"")
    b += ub4(0) + ub4(0) + ub4(0)
    if err_code:
        b += dalc(msg)
    return b

import struct as _s

IND = bytes.fromhex("feffffffffffffff")
FUNC_COMMIT = 14


def oci_all8(seq, sql):
    b = bytearray(196 + len(sql))
    b[0:3] = bytes([TTI_FUN, TTI_ALL8, seq])
    b[11:19] = IND
    b[19:23] = _s.pack("<I", 3 * len(sql))
    b[27:35] = IND
    b[195] = len(sql)
    b[196:] = sql
    return bytes(b)


def oci_oer(status, seq, rowcount, err, pos, command, call_seq, compact=False):
    b = bytearray(24 if compact else 136)
    b[0] = TTI_OER
    b[1] = status
    b[5:7] = _s.pack("<H", seq)
    b[7] = 1
    b[8:12] = _s.pack("<I", rowcount)
    b[12:16] = _s.pack("<I", err)
    b[18] = 2 if command in (3, 47) else 1
    b[20] = pos
    b[22] = command
    if not compact:
        b[49:51] = _s.pack("<H", call_seq)
        b[52] = 1
        b[56:58] = _s.pack("<H", 0x0136)
        b[72:76] = bytes.fromhex("20f6310a")
    return bytes(b)


MSG = b"ORA-00942: table or view does not exist\n"
frames = [
    (True, oci_all8(4, b"SELECT * FROM NOSUCH")),
    (False, oci_oer(5, 4, 0, 942, 14, 3, 4) + dalc(MSG)),
    (True, oci_all8(6, b"INSERT INTO T VALUES (1)")),
    (False, oci_oer(1, 5, 1, 0, 0, 2, 6)),
    (True, oci_all8(7, b"SELECT 1 FROM DUAL")),
    (False, oci_oer(1, 6, 0, 0, 0, 3, 0, compact=True)),
    (True, bytes([TTI_FUN, FUNC_COMMIT, 8])),
    (False, bytes([TTI_STA]) + _s.pack("<IH", 5, 7)),
]


OUT_NAME = "tns_oci_status.pcap"


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
