#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_aq_array.pcap: an array enqueue and an array
dequeue.

    Frame 1 - the client's TTI_DTY, negotiating field version 8 (12.2)
    Frame 2 - an array enqueue of two messages on queue "MYQ": a row
              header with the queue name and the payload type's OID, then
              a row per message with its properties and RAW payload, and
              the closing status byte
    Frame 3 - its reply: for each message the properties, an empty
              recipient list, no payload, and then both message ids
    Frame 4 - an array dequeue of two messages for consumer "SUB1", each
              repeating the queue name and the dequeue options
    Frame 5 - its reply: each message's properties and payload, and its id

Bytes are built by hand in the layout python-oracledb writes.
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

FUNC_AQ_ARRAY = 145
FV = 8
TTI_RXH = 6
toid = bytes(range(0x10, 0x20))
msgids = bytes(range(0x20, 0x40))


def two_lengths(v: bytes) -> bytes:
    return ub4(0) if not v else ub4(len(v)) + dalc(v)


def kv(text: bytes, binary: bytes, keyword: int) -> bytes:
    return two_lengths(text) + two_lengths(binary) + ub4(keyword)


def msg_props(correlation=b"") -> bytes:
    b = ub4(0) + ub4(0) + sb4(-1)
    b += two_lengths(correlation) + ub4(0) + two_lengths(b"") + ub4(0) + ub4(0)
    b += two_lengths(b"") + ub4(4) + b"\x0e"
    b += kv(b"", b"", 64) + kv(b"", b"", 65) + kv(b"", b"\x00", 66) + kv(b"", b"", 69)
    return b + ub4(0) + ub4(0) + ub4(0) + ub4(0)


def array_header(op, iters) -> bytes:
    if op == 1:
        return (b"\x00" + ub4(0) + ub4(1) + b"\x01\x00" + sb4(op) + b"\x01" + ub4(iters))
    return b"\x01" + ub4(iters) + ub4(1) + b"\x01\x01" + sb4(op) + b"\x00"


enq_bodies = b""
for i, payload in enumerate((b"first", b"second")):
    enq_bodies += (bytes([TTI_RXD]) + ub4(0) + msg_props(b"corr-%d" % (i + 1))
                   + ub4(0) + sb4(2) + ub4(0) + sb4(0) + ub4(len(payload)) + payload)
enqueue = (bytes([TTI_FUN, FUNC_AQ_ARRAY, 1]) + array_header(1, 2)
           + ub4(0) + bytes([TTI_RXH]) + two_lengths(b"MYQ") + toid + ub4(1) + ub4(0)
           + enq_bodies + bytes([TTI_STA]))

deq_bodies = b""
for _ in range(2):
    deq_bodies += (two_lengths(b"MYQ") + msg_props() + ub4(0) + two_lengths(b"SUB1")
                   + sb4(3) + sb4(3) + sb4(1) + sb4(0) + two_lengths(b"") + two_lengths(b"")
                   + two_lengths(b"") + ub4(0) + ub4(0) + sb4(0) + two_lengths(toid))
dequeue = bytes([TTI_FUN, FUNC_AQ_ARRAY, 2]) + array_header(2, 2) + deq_bodies


def reply(payloads) -> bytes:
    b = bytes([TTI_RPA]) + ub4(len(payloads))
    for payload in payloads:
        b += ub4(1) + b"\x00" + msg_props()
        b += ub4(0)                                   # recipients
        if payload:
            b += ub4(len(payload))
            b += (bwl(toid) + bwl(b"") + bwl(b"") + ub4(1) + ub4(len(payload))
                  + ub4(0) + dalc(payload))
        else:
            b += ub4(0)
        b += ub4(len(msgids)) + dalc(msgids) + ub4(0) + ub4(0)
    return b + oer(fv=FV)


frames = [
    (True, dty(FV)),
    (True, enqueue),
    (False, reply([b"", b""])),
    (True, dequeue),
    (False, reply([b"first", b"second"])),
]


OUT_NAME = "tns_aq_array.pcap"


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
