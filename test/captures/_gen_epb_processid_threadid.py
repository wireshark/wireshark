#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate test/captures/epb_processid_threadid.pcapng.

The file has two sections, one little-endian and one big-endian, each with
one Ethernet interface and two UDP packets, so that the byte-order handling
of the pcapng epb_processid_threadid option (option code 8, two 32-bit
unsigned integers: the process ID followed by the thread ID) is exercised in
both directions:

    Frame 1 (little-endian section): process ID 1234, thread ID 5678
    Frame 2 (little-endian section): process ID 0, thread ID 0
    Frame 3 (big-endian section):    process ID 4321, thread ID 8765
    Frame 4 (big-endian section):    no epb_processid_threadid option
"""
import os
import struct

SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
EPB_TYPE = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D
OPT_ENDOFOPT = 0
OPT_EPB_PROCESSID_THREADID = 8
LINKTYPE_ETHERNET = 1


def pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def ipv4_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp_packet(seq: int) -> bytes:
    """A minimal Ethernet/IPv4/UDP packet with a 4-byte payload."""
    payload = struct.pack(">I", seq)
    udp = struct.pack(">HHHH", 40000, 40001, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), seq, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack(">H", ipv4_checksum(ip)) + ip[12:]
    eth = bytes.fromhex("000000000002") + bytes.fromhex("000000000001") + b"\x08\x00"
    return eth + ip + udp


def block(endian: str, block_type: int, body: bytes) -> bytes:
    body = pad4(body)
    total_length = 12 + len(body)
    return (struct.pack(endian + "II", block_type, total_length) + body +
            struct.pack(endian + "I", total_length))


def shb(endian: str) -> bytes:
    # Byte-order magic, major/minor version, section length (unspecified).
    return block(endian, SHB_TYPE, struct.pack(endian + "IHHq", BYTE_ORDER_MAGIC, 1, 0, -1))


def idb(endian: str) -> bytes:
    # LinkType, reserved, SnapLen; no options, so if_tsresol is 10^-6.
    return block(endian, IDB_TYPE, struct.pack(endian + "HHI", LINKTYPE_ETHERNET, 0, 65535))


def epb(endian: str, timestamp_us: int, packet: bytes, pid_tid) -> bytes:
    body = struct.pack(endian + "IIIII", 0, timestamp_us >> 32, timestamp_us & 0xFFFFFFFF,
                       len(packet), len(packet))
    body += pad4(packet)
    if pid_tid is not None:
        pid, tid = pid_tid
        body += struct.pack(endian + "HH", OPT_EPB_PROCESSID_THREADID, 8)
        body += struct.pack(endian + "II", pid, tid)
        body += struct.pack(endian + "HH", OPT_ENDOFOPT, 0)
    return block(endian, EPB_TYPE, body)


def main() -> None:
    base_ts = 1_757_500_000_000_000  # 2025-09-10T10:26:40Z in microseconds
    out = b""
    seq = 1
    for endian, cases in (("<", [(1234, 5678), (0, 0)]), (">", [(4321, 8765), None])):
        out += shb(endian) + idb(endian)
        for pid_tid in cases:
            out += epb(endian, base_ts + seq, udp_packet(seq), pid_tid)
            seq += 1
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "epb_processid_threadid.pcapng")
    with open(path, "wb") as f:
        f.write(out)
    print(f"wrote {path} ({len(out)} bytes)")


if __name__ == "__main__":
    main()
