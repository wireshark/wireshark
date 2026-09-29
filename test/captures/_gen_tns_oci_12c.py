#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_12c.pcap: an OCI client (sqlplus 23.26)
on a session at the 12c band, whose messages are wider than at 11g.

    Frame 1 - the narrow execute preamble with 64 zero bytes inserted ahead
              of the SQL: cursor 0, "SELECT * FROM T", no binds; bind count
              still at 71, the SQL's length at 239 and the SQL at 240
    Frame 2 - the same statement in the 11g layout, SQL at 176, for
              comparison
    Frame 3 - a 144-byte status for a DML: success, the 11g row count 0 and
              the ub8 row count 3 at 136, the one sqlplus reports
    Frame 4 - a 144-byte status for ORA-00942: the error number at 12 and
              again at 132, then the message
    Frame 5 - a fetch as sqlplus 23.26 sends it, fixed-width:
              03 05 0f 02 00 00 00 0f 00 00 00 asks cursor 2 for 15 rows

Offsets count from the TTI_FUN byte. The slots not named here are zero.
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
        precision=0, scale=0, fv=0, flag=0, max_elements=0):
    """A column / bind descriptor. From field version 12.2 (8) the scale is
    one signed byte and an oaccolid follows the max size."""
    return (
        bytes([data_type, flag, precision])
        + (bytes([scale & 0xFF]) if fv >= 8 else sb4(scale))
        + ub4(max_length) + ub4(max_elements) + ub4(0) + bwl(b"") + ub4(0)
        + ub4(charset) + bytes([csform]) + ub4(max_size)
        + (ub4(0) if fv >= 8 else b"")
    )


def dcb_column(data_type, max_length, name, charset=0, csform=0,
               max_size=0, precision=0, scale=0, fv=0):
    """A describe column. 10g (below 6) has no uds flags; 23ai appends the
    SQL domain schema and name (17), an annotation count (20) and the
    vector dimensions, format and flags (24)."""
    return (
        oac(data_type, max_length, charset, csform, max_size, precision, scale, fv)
        + b"\x01" + bytes([len(name)]) + bwl(name) + bwl(b"") + bwl(b"")
        + ub4(0) + (ub4(0) if fv == 0 or fv >= 6 else b"")
        + (bwl(b"") + bwl(b"") if fv >= 17 else b"")
        + (ub4(0) if fv >= 20 else b"")
        + (ub4(0) + b"\x00\x00" if fv >= 24 else b"")
    )


def describe_body(columns, fv=0) -> bytes:
    """The describe body shared by TTI_DCB and a nested cursor value; the
    query-cache key came with 11g (6)."""
    b = ub4(80)                  # max row size
    b += ub4(len(columns))       # num columns
    if columns:
        b += b"\x00"
    for col in columns:
        b += col
    b += bwl(b"")                # current date
    b += ub4(0) * 4              # dcbflag / mdbz / mnpr / mxpr
    if fv == 0 or fv >= 6:
        b += bwl(b"")            # dcbqcky
    return b


def dcb(columns, fv=0) -> bytes:
    return bytes([TTI_DCB]) + dalc(b"\x00" * 16) + describe_body(columns, fv)


def all8(seq, sql, options, binds=(), rows=(), cursor=0, al8=None,
         defines=(), fv=0) -> bytes:
    """A TTI_ALL8 execute, in the 11g shape unless a field version is given.
    `binds` and `defines` are OAC blobs, `rows` are the already-encoded
    value rows (each gets a leading TTI_RXD)."""
    al8 = al8 if al8 is not None else [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    b = bytes([TTI_FUN, TTI_ALL8, seq])
    if fv >= 18:
        b += ub4(0)              # ub8 call token
    b += ub4(options) + ub4(cursor)
    b += bytes([1 if sql else 0]) + ub4(len(sql))
    b += bytes([1]) + ub4(len(al8))
    b += bytes([0, 0]) + ub4(0) + ub4(0) + ub4(0)
    b += bytes([1 if binds else 0]) + ub4(len(binds))
    b += bytes([0, 0, 0, 0, 0])
    b += bytes([1 if defines else 0]) + ub4(len(defines))
    b += bytes([0, 0, 1]) + bytes([0, 0, 0, 0, 0])
    if fv >= 7:
        b += bytes([0, 0, 0])    # al8pidmlrc pointer, length, pointer
    if fv >= 8:
        b += bytes([0, 0, 0, 0, 0])  # SQL signature and SQL id fields
    if fv >= 9:
        b += bytes([0, 0])       # chunk ids pointer, count
    b += (dalc(sql) if sql else b"") if fv >= 7 else sql
    for elem in al8:
        b += ub4(elem)
    for o in list(binds) + list(defines):
        b += o
    for r in rows:
        b += bytes([TTI_RXD]) + r
    return b


def dty(field_version: int) -> bytes:
    """A client TTI_DTY whose compile capabilities carry field_version
    (capability 7): charsets, flag, the 38 capability bytes behind their
    length, the table header and identity map (zeros here), and the
    override list's terminator."""
    caps = bytearray(38)
    caps[7] = field_version
    return (bytes([2]) + b"\x69\x03\x69\x03\x01" + bytes([len(caps)]) + caps
            + bytes(8) + bytes(980) + b"\x00")


def oer(err_code=0, cursor=0, rowcount=0, call_status=0, msg=b"", fv=0) -> bytes:
    """A TTI_OER; from field version 12.1 (7) with the extended error
    number and row count, from 20.1 (14) the SQL type and checksum too."""
    b = bytes([TTI_OER])
    b += ub4(call_status) + ub4(0) + ub4(rowcount) + ub4(err_code)
    b += ub4(0) + ub4(0) + ub4(cursor) + ub4(0)
    b += bytes(6)
    b += ub4(0) + ub4(0) + b"\x00" + ub4(0) + ub4(0)
    b += ub4(0) + bytes(2) + ub4(0) + ub4(0)
    b += bwl(b"")
    b += ub4(0) + ub4(0) + ub4(0)
    if fv >= 7:
        b += ub4(err_code) + ub4(rowcount)
    if fv >= 14:
        b += ub4(0) + ub4(0)
    if err_code:
        b += dalc(msg)
    return b

import struct as _s

TTI_ALL8 = 94
IND = bytes([0xFE] + [0xFF] * 7)


def oci_all8(seq, cursor, sql, binds, band_12c):
    """A narrow OCI execute preamble; at the 12c band the SQL sits 64 zero
    bytes further on."""
    bind_off, sql_off = 71, (240 if band_12c else 176)
    b = bytearray(sql_off + len(sql))
    b[0:3] = bytes([TTI_FUN, TTI_ALL8, seq])
    b[7:11] = _s.pack("<I", cursor)
    b[11:19] = IND
    b[19:23] = _s.pack("<I", 3 * len(sql))
    b[23:31] = IND
    b[bind_off:bind_off + 4] = _s.pack("<I", binds)
    b[sql_off - 1] = len(sql)
    b[sql_off:] = sql
    return bytes(b)


def oci_oer_12c(seq, rows, err, command, call_seq, msg=b""):
    """A status block at the 12c band: 144 bytes, with the error number
    again at 132 and a ub8 row count at 136."""
    b = bytearray(144)
    b[0] = TTI_OER
    b[1] = 1
    b[5:7] = _s.pack("<H", seq)
    b[7] = 1
    b[12:16] = _s.pack("<I", err)
    b[18] = 1
    b[22] = command
    b[49:51] = _s.pack("<H", call_seq)
    b[132:136] = _s.pack("<I", err)
    b[136:144] = _s.pack("<Q", rows)
    return bytes(b) + (dalc(msg) if err else b"")


frames = [
    (True, oci_all8(4, 0, b"SELECT * FROM T", 0, True)),
    (True, oci_all8(5, 0, b"SELECT * FROM T", 0, False)),
    (False, oci_oer_12c(6, 3, 0, 2, 5)),
    (False, oci_oer_12c(7, 0, 942, 3, 6, b"ORA-00942: table or view does not exist\n")),
    (True, bytes.fromhex("03050f020000000f000000")),
]


OUT_NAME = "tns_oci_12c.pcap"


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
