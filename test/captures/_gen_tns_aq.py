#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_aq.pcap: Advanced Queuing enqueue and dequeue.

    Frame 1 - the client's TTI_DTY, negotiating field version 8 (12.2)
    Frame 2 - an enqueue on queue "MYQ": the message properties with
              correlation "corr-1" and no expiration, visibility "on
              commit", the payload type's OID and a RAW payload
    Frame 3 - its reply: the message id the queue gave
    Frame 4 - a dequeue from "MYQ" for consumer "SUB1": mode remove,
              navigation "first message", waiting for ever, with the
              condition "priority = 1"
    Frame 5 - its reply: the message's properties, an empty recipient
              list, the payload in the object framing and the message id

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

FUNC_AQ_ENQ = 121
FUNC_AQ_DEQ = 122
FV = 8
toid = bytes(range(0x10, 0x20))
msgid = bytes(range(0x20, 0x30))
payload = b"hello queue"


def two_lengths(v: bytes) -> bytes:
    return ub4(0) if not v else ub4(len(v)) + dalc(v)


def kv(text: bytes, binary: bytes, keyword: int) -> bytes:
    return two_lengths(text) + two_lengths(binary) + ub4(keyword)


def msg_props(correlation=b"", enq_time=b"") -> bytes:
    b = ub4(0) + ub4(0) + sb4(-1)           # priority, delay, expiration
    b += two_lengths(correlation) + ub4(0) + two_lengths(b"") + ub4(0)
    b += (ub4(len(enq_time)) + dalc(enq_time)) if enq_time else ub4(0)
    b += two_lengths(b"")                   # transaction id
    b += ub4(4) + b"\x0e"
    b += kv(b"", b"", 64) + kv(b"", b"", 65) + kv(b"", b"\x00", 66) + kv(b"", b"", 69)
    return b + ub4(0) + ub4(0) + ub4(0) + ub4(0)


enqueue = (bytes([TTI_FUN, FUNC_AQ_ENQ, 1]) + b"\x01" + ub4(3)
           + msg_props(b"corr-1")
           + b"\x00" + ub4(0)                       # recipients
           + ub4(2)                                 # visibility: on commit
           + b"\x00" + ub4(0) + ub4(0)              # relative message id
           + b"\x01" + ub4(len(toid)) + ub4(1)      # payload type, version
           + b"\x00" + b"\x01" + ub4(len(payload))  # payload pointers
           + b"\x01" + ub4(16) + ub4(0)             # return message id, flags
           + (b"\x00" + ub4(0)) * 4                 # extensions, sequences
           + b"\x00"                                # output ack length
           + (b"\x00" + ub4(0)) * 3 + b"\x00\x00"   # correlation, sender
           + dalc(b"MYQ") + toid + payload)
dequeue = (bytes([TTI_FUN, FUNC_AQ_DEQ, 2]) + b"\x01" + ub4(3)
           + b"\x01\x01\x01\x01"                    # properties, recipients
           + b"\x01" + ub4(4)                       # consumer name
           + ub4(3) + ub4(1) + ub4(1) + sb4(-1)     # mode, navigation, visibility, wait
           + b"\x00" + ub4(0)                       # select message id
           + b"\x00" + ub4(0)                       # correlation
           + b"\x01" + ub4(len(toid)) + ub4(1)      # payload type, version
           + b"\x01\x01" + ub4(16) + ub4(0)         # payload, message id, flags
           + b"\x01" + ub4(14)                      # condition
           + b"\x00" + ub4(0)                       # extensions
           + dalc(b"MYQ") + dalc(b"SUB1") + toid + dalc(b"priority = 1"))
date = bytes([120, 124, 3, 4, 6, 8, 10])            # 2024-03-04 05:07:09
message = (msg_props(b"corr-1", date) + ub4(0)
           + bwl(toid) + bwl(b"") + bwl(b"") + ub4(1)
           + ub4(len(payload)) + ub4(0) + dalc(payload) + msgid)
frames = [
    (True, dty(FV)),
    (True, enqueue),
    (False, bytes([TTI_RPA]) + msgid + ub4(0) + oer(fv=FV)),
    (True, dequeue),
    (False, bytes([TTI_RPA]) + ub4(len(message)) + message + oer(fv=FV)),
]


OUT_NAME = "tns_aq.pcap"


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
