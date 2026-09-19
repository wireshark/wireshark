#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_al8i4.pcap: TTI_ALL8 executes whose al8i4
argument array carries different things.

    Frame 1 - the first execute of a query: slot 1 is 0 prefetch rows,
              slot 7 marks a query, slot 9 carries IMPLICIT_RESULTSET
    Frame 2 - a re-execute of that query: slot 1 is the fetch array size,
              100 rows to prefetch
    Frame 3 - an array INSERT of four rows asking for per-row counts:
              slot 1 is the execution count 4, slot 9 is 0xC000
              (DML_ROWCOUNTS | IMPLICIT_RESULTSET)
    Frame 4 - a scrollable cursor positioned ABSOLUTE to row 5: slot 9 is
              0x82 (SCROLLABLE | NO_CANCEL_ON_EOF), slots 10 and 11 hold
              the orientation and the position

Bytes are built by hand in the Oracle 11g wire shape.
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
         defines=0) -> bytes:
    """An 11g-shape TTI_ALL8 execute. `binds` are OAC blobs, `rows` are the
    already-encoded value rows (each gets a leading TTI_RXD)."""
    al8 = al8 if al8 is not None else [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    b = bytes([TTI_FUN, TTI_ALL8, seq])
    b += ub4(options) + ub4(cursor)
    b += bytes([1 if sql else 0]) + ub4(len(sql))
    b += bytes([1]) + ub4(len(al8))
    b += bytes([0, 0]) + ub4(0) + ub4(0) + ub4(0)
    b += bytes([1 if binds else 0]) + ub4(len(binds))
    b += bytes([0, 0, 0, 0, 0])
    b += bytes([1 if defines else 0]) + ub4(defines)
    b += bytes([0, 0, 1]) + bytes([0, 0, 0, 0, 0])
    b += sql
    for elem in al8:
        b += ub4(elem)
    for o in binds:
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

def al8i4(parse, count, is_query, flags, orientation=0, pos=0):
    return [parse, count, 0, 0, 0, 0, 0, is_query, 0, flags, orientation, pos, 0]


frames = [
    (True, all8(1, b"SELECT ID FROM T", 0x8021, al8=al8i4(1, 0, 1, 0x8000))),
    (True, all8(2, b"", 0x8060, cursor=7, al8=al8i4(0, 100, 1, 0x8000))),
    (True, all8(3, b"INSERT INTO T (ID) VALUES (:1)", 0x8029,
                binds=[oac(TYPE_NUMBER, 22)],
                rows=[dalc(bytes([0xc1, n + 1])) for n in range(1, 5)],
                al8=al8i4(1, 4, 0, 0xC000))),
    (True, all8(4, b"", 0x8040, cursor=7, al8=al8i4(0, 1, 1, 0x82, 0x20, 5))),
]


OUT_NAME = "tns_al8i4.pcap"


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
