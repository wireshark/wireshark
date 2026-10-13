#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_txn_priority.pcap: a 23ai client setting its
transaction priority with an ALTER SESSION piggyback (function 204), and
the server reporting it back as keyword 204 of a session-state sync.

    Frame 1 - TTI_DTY negotiating field version 23.1 ext 1 (18)
    Frame 2 - piggyback 204: TXN_PRIORITY = low, then the commit, both
              with the 23ai call token; the piggyback is the one
              python-oracledb 26 sends for txn_priority 'low'
    Frame 3 - the server's sync piggyback reporting TXN_PRIORITY low, as
              23ai sends it
    Frame 4 - piggyback 204 with an empty value and flag 1, restoring the
              database default, then the commit

Bytes are built by hand.
"""
import os
import struct

TTI_FUN = 3
TTI_PGY = 17
TTI_SPB = 23
FUNC_COMMIT = 14
FUNC_ALTER_SESSION = 204
SPB_SYNC = 5
KEYWORD_TXN_PRIORITY = 204


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


def bwl(s: bytes) -> bytes:
    """bytes_with_length: a ub4 count, then a DALC only when non-empty."""
    return ub4(0) if not s else ub4(len(s)) + dalc(s)


def dty(field_version: int) -> bytes:
    """A client TTI_DTY whose compile capabilities carry field_version
    (capability 7): charsets, flag, the 38 capability bytes behind their
    length, the table header and identity map (zeros here), and the
    override list's terminator."""
    caps = bytearray(38)
    caps[7] = field_version
    return (bytes([2]) + b"\x69\x03\x69\x03\x01" + bytes([len(caps)]) + caps
            + bytes(8) + bytes(980) + b"\x00")


def alter_session(seq, param, value):
    """Piggyback 204 with the 23ai call token: flags, a pointer and one
    parameter, its value, and flag 1 when the value is empty."""
    return (bytes([TTI_PGY, FUNC_ALTER_SESSION, seq]) + b"\x00"
            + ub4(0) + b"\x01" + ub4(1)
            + bwl(param) + bwl(value) + ub4(0 if value else 1))


def sync(keyword, value):
    """A session-state sync server piggyback with one key/value pair: a
    text, no binary value, and the keyword number."""
    pair = ub4(len(value)) + dalc(value) + ub4(0) + ub4(keyword)
    return (bytes([TTI_SPB, SPB_SYNC]) + ub4(1) + bytes([0x10]) + ub4(1)
            + bytes([0x16]) + pair + ub4(0))


def commit(seq):
    return bytes([TTI_FUN, FUNC_COMMIT, seq, 0])


SET = alter_session(3, b"TXN_PRIORITY", b"low")
# as captured from python-oracledb 26 against 23ai
assert SET == bytes.fromhex(
    "11 cc 03 00 00 01 01 01 01 0c 0c 54 58 4e 5f 50 52 49 4f 52 49 54 59"
    "01 03 03 6c 6f 77 00"), SET.hex()
REPORT = sync(KEYWORD_TXN_PRIORITY, b"low")
assert REPORT == bytes.fromhex(
    "17 05 01 01 10 01 01 16 01 03 03 6c 6f 77 00 01 cc 00"), REPORT.hex()

frames = [
    (True, dty(18)),
    (True, SET + commit(4)),
    (False, REPORT),
    (True, alter_session(5, b"TXN_PRIORITY", b"") + commit(6)),
]


OUT_NAME = "tns_txn_priority.pcap"


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
