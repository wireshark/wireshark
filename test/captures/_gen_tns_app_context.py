#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_app_context.pcap: a client setting and
clearing an application context namespace with a piggyback (function 154)
in front of a commit, as DBMS_SESSION.SET_CONTEXT / CLEAR_CONTEXT would.

    Frame 1 - TTI_DTY negotiating field version 23.1 ext 1 (18)
    Frame 2 - piggyback 154 setting CLIENTCONTEXT: ATTR1 = VALUE1,
              ATTR2 = V2, then the commit; both carry the 23ai call token,
              and the zero byte ahead of the namespace is there. The
              piggyback is the one python-oracledb 26 sends for
              set_app_context('CLIENTCONTEXT', ATTR1='VALUE1', ATTR2='V2')
    Frame 3 - TTI_DTY negotiating field version 11.2 (6)
    Frame 4 - piggyback 154 clearing CLIENTCONTEXT, then the commit; no
              token, and no zero byte ahead of the namespace

Bytes are built by hand.
"""
import os
import struct

TTI_FUN = 3
TTI_PGY = 17
FUNC_COMMIT = 14
FUNC_APP_CONTEXT = 154
APP_CONTEXT_SET = 1
APP_CONTEXT_CLEAR = 2


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


def app_context(seq, namespace, op, entries=(), token=False, zero=False):
    """Piggyback 154: the ub8 call token from 23.1 ext 1, pointer and
    namespace length, pointer and entry count, the operation, a zero byte
    from 12.1, the namespace, then each attribute, value and a ub4 0."""
    b = bytes([TTI_PGY, FUNC_APP_CONTEXT, seq])
    if token:
        b += b"\x00"
    b += b"\x01" + ub4(len(namespace))
    b += (b"\x01" if entries else b"\x00") + ub4(len(entries))
    b += ub4(op)
    if zero:
        b += b"\x00"
    b += dalc(namespace)
    for attr, value in entries:
        b += bwl(attr) + bwl(value) + ub4(0)
    return b


def commit(seq, token=False):
    return bytes([TTI_FUN, FUNC_COMMIT, seq]) + (b"\x00" if token else b"")


SET = app_context(3, b"CLIENTCONTEXT", APP_CONTEXT_SET,
                  [(b"ATTR1", b"VALUE1"), (b"ATTR2", b"V2")], token=True, zero=True)
# as captured from python-oracledb 26 against 23ai
assert SET == bytes.fromhex(
    "11 9a 03 00 01 01 0d 01 01 02 01 01 00 0d 43 4c 49 45 4e 54 43 4f 4e 54 45 58 54"
    "01 05 05 41 54 54 52 31 01 06 06 56 41 4c 55 45 31 00"
    "01 05 05 41 54 54 52 32 01 02 02 56 32 00"), SET.hex()

frames = [
    (True, dty(18)),
    (True, SET + commit(4, token=True)),
    (True, dty(6)),
    (True, app_context(5, b"CLIENTCONTEXT", APP_CONTEXT_CLEAR) + commit(6)),
]


OUT_NAME = "tns_app_context.pcap"


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
