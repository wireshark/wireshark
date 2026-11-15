#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/tns_oci_10g.pcap: an OCI 11.2 client's session
with a 10g server, which runs at the server's field version, 10.2,
though the client's data-type request says 11.2.

    Frame 1 - the client's TTI_PRO
    Frame 2 - the server's TTI_PRO reply, offering field version 4 (10.2)
    Frame 3 - the client's TTI_DTY: flag 0x83, field version 6 (11.2),
              and no timezone file version behind the time zone block
    Frame 4 - the server's answer: its time zone block
    Frame 5 - an execute of "select 1 from dual": the narrow preamble
              with the SQL at 148, then the al8i4 array
    Frame 6 - an execute of "begin open :1 for select 7 from dual; end;",
              a REF CURSOR bound OUT
    Frame 7 - the reply: the cursor's describe without the uds flags and
              the query key 11g adds, its id 1, then the status
    Frame 8 - a block that leaves its REF CURSOR unopened
    Frame 9 - the reply: the cursor's cell with no columns

Frames 3, 5, 7 and 9 are what an OCI 11.2 program and Oracle 10.2.0.5
sent; frames 6 and 8 are built field by field as the client sends them,
and frames 1, 2 and 4 by hand.
"""
import os
import struct

PRO = bytes([1, 6, 5, 4, 3, 2, 1, 0]) + b"python\x00"
FDO = bytearray(16)
FDO[5], FDO[6] = 2, 1
FDO[12:14] = struct.pack(">H", 2000)
COMPILE_CAPS = bytearray(53)
COMPILE_CAPS[7] = 4
PRO_REPLY = (bytes([1, 6, 0]) + b"x86_64/Linux 2.4.xx\x00"
             + struct.pack("<HBH", 873, 1, 0) + struct.pack(">H", len(FDO)) + bytes(FDO)
             + bytes([len(COMPILE_CAPS)]) + COMPILE_CAPS + bytes([11]) + bytes(11))
DTY = bytes.fromhex(
    '02690369038327060101010f010106010101010101017fff030a030701017f01'
    '7fff01090101bf010506000107040702010000180003800000003c3c3c800000'
    '00d007'
)
DTY_REPLY = bytes.fromhex("02800000003c3c3c80000000")
SELECT = bytes.fromhex(
    '035e056180000000000000feffffffffffffff12000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff1273656c65637420312066726f'
    '6d206475616c0100000000000000000000000000000000000000000000000000'
    '0000010000000000000000000000000000000000000000000000'
)
OPEN_REFCURSOR = bytes.fromhex(
    '035e062904040000000000feffffffffffffff2a000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff010000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff2a626567696e206f70656e203a'
    '3120666f722073656c65637420372066726f6d206475616c3b20656e643b0100'
    '0000010000000000000000000000000000000000000000000000080000000000'
    '0000000000000000000000000000000000000166030000010000000000000000'
    '0000000000000000000000000000000000000000000000000000000704000000'
    '00'
)
OPEN_REFCURSOR_REPLY = bytes.fromhex(
    '0b0105b0010000000000010000000000000088cbbe7700000000000000000000'
    '000000331419ff7f00000000ffd63e7f000030073c02000000010000004d0102'
    '0000000200000000000000000000000000000000000000000000000000000000'
    '000000000000000101010000000137000000000000000000000700000007787e'
    '0b0804182d00000000e81f00000000000000000000010000000000080600f579'
    '4c00000000000200000000000000000000000000000000000000000000000401'
    '00000008000101000000000000000000020000002f0000000000000000000000'
    '0000000000000000000000000000000a00000100000036010000000000000000'
    '000000000000809aaf0600000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000000000'
)
UNOPENED = bytes.fromhex(
    '035e072904040000000000feffffffffffffff40000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff010000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff40626567696e2069662031203d'
    '2030207468656e206f70656e203a3120666f722073656c65637420312066726f'
    '6d206475616c3b20656e642069663b20656e643b010000000100000000000000'
    '0000000000000000000000000000000008000000000000000000000000000000'
    '0000000000000000016603000001000000000000000000000000000000000000'
    '0000000000000000000000000000000000070400000000'
)
UNOPENED_REPLY = bytes.fromhex(
    '0b0105b0010000000000010000000000000050938b7700000000000000000000'
    '000000331419ff7f00000000ffd63e7f000030073c0000000000000000070000'
    '0007787e0b0804182d0000000000000000000000000000000000000000000008'
    '0600f5794c000000000001000000000000000000000000000000000000000000'
    '0000040100000004000101000000000000000000010000002f00000000000000'
    '0000000000000000000000000000000000000006000001000000360100000000'
    '00000000000000000000809aaf06000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000'
)

frames = [
    (True, PRO),
    (False, PRO_REPLY),
    (True, DTY),
    (False, DTY_REPLY),
    (True, SELECT),
    (True, OPEN_REFCURSOR),
    (False, OPEN_REFCURSOR_REPLY),
    (True, UNOPENED),
    (False, UNOPENED_REPLY),
]


OUT_NAME = "tns_oci_10g.pcap"


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
    # Cumulative TCP sequence numbers per direction, so a smaller
    # follow-on frame is not read as a retransmission and dropped before
    # TNS sees it.
    seq = {True: 1, False: 1}
    for i, (to_server, body) in enumerate(frames):
        pkt = wrap(body, to_server, seq[to_server], seq[not to_server], i + 1)
        seq[to_server] += len(body) + 10
        f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
        f.write(pkt)
print(f"wrote {out} ({os.path.getsize(out)} bytes, {len(frames)} frames)")
