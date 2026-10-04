#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_long_error.pcap: an error message too
long for a length byte, sent to an OCI client (sqlplus) in the chunked
form, with chunk lengths of either width.

    Frame 1 - an OCI execute of a PL/SQL block, the 11g layout
    Frame 2 - its 136-byte status: ORA-20001, then the 333-byte message
              as an 11g server sends it, fe ff <255 bytes> 4e <78 bytes>
              00 - ub1 chunk lengths
    Frame 3 - the same block at the 12c band
    Frame 4 - its 144-byte status, then the message as an 18c server
              sends it, fe 4d 01 00 00 <333 bytes> 00 00 00 00 - ub4 LE
              chunk lengths

Offsets count from the TTI_FUN byte. The slots not named here are zero.
Bytes are built by hand.
"""
import os
import struct

TTI_FUN = 3
TTI_OER = 4
TTI_ALL8 = 94
IND = bytes([0xFE] + [0xFF] * 7)

SQL = b"BEGIN RAISE_APPLICATION_ERROR(-20001, RPAD('A', 321, 'A')); END;"
MSG = b"ORA-20001: " + b"A" * 321 + b"\n"


def oci_all8(seq, sql, band_12c):
    """A narrow OCI execute preamble; at the 12c band the SQL sits 64 zero
    bytes further on."""
    sql_off = 240 if band_12c else 176
    b = bytearray(sql_off + len(sql))
    b[0:3] = bytes([TTI_FUN, TTI_ALL8, seq])
    b[11:19] = IND
    b[19:23] = struct.pack("<I", 3 * len(sql))
    b[23:31] = IND
    b[sql_off - 1] = len(sql)
    b[sql_off:] = sql
    return bytes(b)


def oci_oer(seq, err, call_seq, band_12c):
    """A status block for a failed PL/SQL call: 136 bytes, or 144 at the
    12c band, with the error number again at 132 and a ub8 row count."""
    b = bytearray(144 if band_12c else 136)
    b[0] = TTI_OER
    b[1] = 5
    b[5:7] = struct.pack("<H", seq)
    b[7] = 1
    b[12:16] = struct.pack("<I", err)
    b[18] = 1
    b[22] = 47
    b[49:51] = struct.pack("<H", call_seq)
    if band_12c:
        b[132:136] = struct.pack("<I", err)
    return bytes(b)


def chunks_ub1(text: bytes) -> bytes:
    b = b"\xfe"
    for i in range(0, len(text), 255):
        part = text[i:i + 255]
        b += bytes([len(part)]) + part
    return b + b"\x00"


def chunks_ub4le(text: bytes) -> bytes:
    return b"\xfe" + struct.pack("<I", len(text)) + text + struct.pack("<I", 0)


assert len(MSG) == 333
assert chunks_ub1(MSG)[:2] == b"\xfe\xff" and chunks_ub1(MSG)[257] == 0x4E
frames = [
    (True, oci_all8(4, SQL, False)),
    (False, oci_oer(5, 20001, 4, False) + chunks_ub1(MSG)),
    (True, oci_all8(6, SQL, True)),
    (False, oci_oer(6, 20001, 6, True) + chunks_ub4le(MSG)),
]


OUT_NAME = "tns_oci_long_error.pcap"


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
