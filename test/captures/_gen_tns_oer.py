#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oer.pcap with three TTI_OER frames:

    Frame 1 — successful DML: call_status=0, rowcount=3, err_code=0
    Frame 2 — failure        : err_code=1 ("ORA-00001: unique constraint (...)
                                violated") with message text
    Frame 3 — failure whose message is the 0xFF null marker, which stands for
                                itself and carries no data after it
    Frame 4 — failure with a non-empty oerrdd, so that field is a ub4 count
                                followed by a DALC rather than a bare DALC

Bytes are constructed by hand in the Oracle 11g wire shape.
"""
import os
import struct
import sys


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


def dalc(s: bytes | None) -> bytes:
    if not s:
        return b"\x00"
    if len(s) < 254:
        return bytes([len(s)]) + s
    # Chunked form, 0xFE marker + (len, bytes)+ terminated by 0-length.
    out = b"\xfe"
    while s:
        chunk = s[:64]
        s = s[64:]
        out += bytes([len(chunk)]) + chunk
    out += b"\x00"
    return out


def bytes_with_length(s: bytes | None) -> bytes:
    """A ub4 count, and a DALC carrying the value only when it is non-empty."""
    if not s:
        return ub4(0)
    return ub4(len(s)) + dalc(s)


def build_oer(call_status: int, rowcount: int, err_code: int, cursor_id: int,
              message: bytes | None, message_raw: bytes | None = None,
              oerrdd: bytes | None = None) -> bytes:
    b = b"\x04"                       # TTI_OER token
    b += ub4(call_status)
    b += ub4(0)                       # end-to-end seq#
    b += ub4(rowcount)
    b += ub4(err_code)
    b += ub4(0)                       # array elem error #1
    b += ub4(0)                       # array elem error #2
    b += ub4(cursor_id)
    b += ub4(0)                       # error position
    b += b"\x00" * 6                  # sql_type, fatal, flags, user_cursor_opts,
                                      #   upi_param, warn_flags
    b += ub4(0)                       # rowid.rba
    b += ub4(0)                       # rowid.partition_id
    b += b"\x00"                      # rowid reserved
    b += ub4(0)                       # rowid.block_num
    b += ub4(0)                       # rowid.slot_num
    b += ub4(0)                       # os error
    b += b"\x00\x00"                  # statement #, call #
    b += ub4(0)                       # padding (ub2 in 11g)
    b += ub4(1)                       # successful iterations
    b += bytes_with_length(oerrdd)    # oerrdd (logical rowid)
    b += ub4(0)                       # num batch errcodes
    b += ub4(0)                       # num batch offsets
    b += ub4(0)                       # num batch messages
    if err_code != 0:
        b += message_raw if message_raw is not None else dalc(message or b"")
    return b


frames = [
    build_oer(call_status=0, rowcount=3, err_code=0, cursor_id=42, message=None),
    build_oer(call_status=0, rowcount=0, err_code=1, cursor_id=42,
              message=b"ORA-00001: unique constraint (TEST.PK) violated\n"),
    # A null message. 0xFF is a marker, not a length of 255 - reading it as
    # one walks off the end of the frame.
    build_oer(call_status=0, rowcount=0, err_code=1722, cursor_id=9,
              message=None, message_raw=b"\xff"),
    # A logical rowid in oerrdd. Read as a bare DALC the count byte is taken
    # for a length, and every field after it lands one field early.
    build_oer(call_status=0, rowcount=0, err_code=942, cursor_id=7,
              message=b"ORA-00942: table or view does not exist\n",
              oerrdd=b"\x01\x02\x03\x04\x05\x06\x07\x08"),
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


def wrap(body: bytes, seq: int, ident: int) -> bytes:
    # TNS DATA framing (10 bytes).
    tns = struct.pack(">HhBBhh", len(body) + 10, 0, 6, 0, 0, 0) + body

    src_ip = bytes([10, 0, 0, 2])
    dst_ip = bytes([10, 0, 0, 1])
    # Server -> client (replies), so dst_port is the client ephemeral port.
    tcp_no_csum = struct.pack(
        ">HHIIBBHHH",
        1521, 54321,
        seq, 0,
        0x50, 0x18, 65535, 0, 0,
    )
    csum = tcp_checksum(src_ip, dst_ip, tcp_no_csum + tns)
    tcp = tcp_no_csum[:16] + struct.pack(">H", csum) + tcp_no_csum[18:]
    seg = tcp + tns

    ip_total = 20 + len(seg)
    ip_no = struct.pack(">BBHHHBBH", 0x45, 0, ip_total, ident, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip_no[:10] + struct.pack(">H", ipv4_checksum(ip_no)) + ip_no[12:]
    return ip + seg


out = os.path.join(os.path.dirname(__file__), "tns_oer.pcap")
with open(out, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    # Sequence numbers have to advance by the bytes actually sent, or TCP
    # reads the later frames as retransmissions and never dissects them.
    seq = 1
    for i, body in enumerate(frames):
        pkt = wrap(body, seq=seq, ident=i + 1)
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
        seq += len(body) + 10  # TNS DATA header
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
