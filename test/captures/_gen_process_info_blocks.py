#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the pcapng process information block test captures.

process_info_wireshark_cb.pcapng has a little-endian and a big-endian
section, each with one Ethernet interface, with process information carried
in Wireshark custom blocks (PEN 32622, block entry type 3), whose entries are
little-endian in both sections:

    Section 1 (little-endian):
        PIB 0: process 1234, with every option and a comment in the entry
        PIB 1: process 4321, with no options
        Frame 1: UDP packet from process 1234 (epb_processid_threadid)
        Frame 2: a Wireshark custom block with an unknown entry type (99),
                 which is kept as an opaque custom block record
        Frame 3: UDP packet from process 4321
    Section 2 (big-endian):
        PIB 2: process 77, with a name and a user ID in the entry and a
               comment among the options of the custom block itself
        Frame 4: UDP packet from process 77

process_info_darwin_dpib.pcapng has one little-endian section with legacy
Darwin process information blocks (block type 0x80000001), as written by
Apple's tcpdump, and packets that refer to them:

        DPIB 0: process 501 "mDNSResponder", with a UUID
        DPIB 1: process 1 "launchd"
        Frame 1: UDP packet with darwin_dpib_id 0
        Frame 2: UDP packet with darwin_dpib_id 1
        Frame 3: UDP packet with darwin_dpib_id 0 and darwin_edpib_id 1

process_info_pid_reuse.pcapng has one little-endian section with several
Wireshark process information blocks for the same process ID, to test which
one a packet is matched with:

        PIB 0: process 500 "first", started 10 us before the base time
        PIB 1: process 500 "second", started 20 us after the base time
        PIB 2: process 600 "old", no start time
        PIB 3: process 600 "new", no start time
        Frame 1: process 500, 5 us after the base time ("first")
        Frame 2: process 500, 25 us after the base time ("second")
        Frame 3: process 500, 100 us before the base time ("first", the
                 earliest, as no process had started yet)
        Frame 4: process 600 ("new", the last block)
        Frame 5: process 700, for which there is no block

The hex dump of the custom data of each Wireshark custom block (everything
after the PEN) of process_info_wireshark_cb.pcapng, as needed by the tests,
is printed.
"""
import os
import struct

SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
EPB_TYPE = 0x00000006
CB_COPY_TYPE = 0x00000BAD
LEGACY_DPIB_TYPE = 0x80000001
BYTE_ORDER_MAGIC = 0x1A2B3C4D
LINKTYPE_ETHERNET = 1

OPT_ENDOFOPT = 0
OPT_COMMENT = 1
OPT_EPB_PROCESSID_THREADID = 8
OPT_EPB_DARWIN_DPIB_ID = 32769
OPT_EPB_DARWIN_EDPIB_ID = 32771

OPT_PIB_NAME = 2
OPT_PIB_PATH = 3
OPT_PIB_CMDLINE = 4
OPT_PIB_PPID = 5
OPT_PIB_UID = 6
OPT_PIB_USER = 7
OPT_PIB_UUID = 8
OPT_PIB_STARTTIME = 9

OPT_DPIB_NAME = 2
OPT_DPIB_UUID = 4

PEN_WIRESHARK = 32622
WIRESHARK_CB_ENTRY_PROCESS_INFORMATION = 3

UUID = bytes.fromhex("6b8b4567327b23c6643c986966334873")


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


def options(endian: str, opts) -> bytes:
    """Encode a list of (code, value) options, or nothing if the list is empty."""
    if not opts:
        return b""
    out = b""
    for code, value in opts:
        out += struct.pack(endian + "HH", code, len(value)) + pad4(value)
    return out + struct.pack(endian + "HH", OPT_ENDOFOPT, 0)


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


def epb(endian: str, timestamp_us: int, packet: bytes, opts) -> bytes:
    body = struct.pack(endian + "IIIII", 0, timestamp_us >> 32, timestamp_us & 0xFFFFFFFF,
                       len(packet), len(packet))
    body += pad4(packet)
    body += options(endian, opts)
    return block(endian, EPB_TYPE, body)


def wireshark_cb_custom_data(entry_type: int, entry_data: bytes, cb_opts: bytes = b"") -> bytes:
    """The custom data of a Wireshark custom block: the entry, which is
    little-endian whatever the byte order of the section, and the options
    of the block, which are given already encoded."""
    return struct.pack("<II", entry_type, len(entry_data)) + pad4(entry_data) + cb_opts


def wireshark_cb(endian: str, custom_data: bytes) -> bytes:
    return block(endian, CB_COPY_TYPE, struct.pack(endian + "I", PEN_WIRESHARK) + custom_data)


def pib_entry(pid: int, opts) -> bytes:
    """The body of a Process Information Block, little-endian."""
    return struct.pack("<I", pid) + options("<", opts)


def legacy_dpib(endian: str, pid: int, opts) -> bytes:
    return block(endian, LEGACY_DPIB_TYPE, struct.pack(endian + "I", pid) + options(endian, opts))


def write(name: str, data: bytes) -> None:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data)} bytes)")


def gen_wireshark_cb() -> None:
    base_ts = 1_757_500_000_000_000  # 2025-09-10T10:26:40Z in microseconds
    custom_data = [
        wireshark_cb_custom_data(WIRESHARK_CB_ENTRY_PROCESS_INFORMATION, pib_entry(1234, [
            (OPT_PIB_NAME, b"curl"),
            (OPT_PIB_PATH, b"/usr/bin/curl"),
            (OPT_PIB_CMDLINE, b"curl\x00https://example.com/"),
            (OPT_PIB_PPID, struct.pack("<I", 1)),
            (OPT_PIB_UID, struct.pack("<I", 1000)),
            (OPT_PIB_USER, b"alice"),
            (OPT_PIB_UUID, UUID),
            (OPT_PIB_STARTTIME, struct.pack("<Q", 1767225600000000000)),
            (OPT_COMMENT, b"first process"),
        ])),
        wireshark_cb_custom_data(WIRESHARK_CB_ENTRY_PROCESS_INFORMATION, pib_entry(4321, [])),
        wireshark_cb_custom_data(99, b"hello"),
        wireshark_cb_custom_data(WIRESHARK_CB_ENTRY_PROCESS_INFORMATION, pib_entry(77, [
            (OPT_PIB_NAME, b"sshd"),
            (OPT_PIB_UID, struct.pack("<I", 0)),
        ]), options(">", [(OPT_COMMENT, b"section two")])),
    ]
    out = shb("<") + idb("<")
    out += wireshark_cb("<", custom_data[0])
    out += wireshark_cb("<", custom_data[1])
    out += epb("<", base_ts + 1, udp_packet(1), [(OPT_EPB_PROCESSID_THREADID, struct.pack("<II", 1234, 0))])
    out += wireshark_cb("<", custom_data[2])
    out += epb("<", base_ts + 2, udp_packet(2), [(OPT_EPB_PROCESSID_THREADID, struct.pack("<II", 4321, 0))])
    out += shb(">") + idb(">")
    out += wireshark_cb(">", custom_data[3])
    out += epb(">", base_ts + 3, udp_packet(3), [(OPT_EPB_PROCESSID_THREADID, struct.pack(">II", 77, 0))])
    write("process_info_wireshark_cb.pcapng", out)
    for i, data in enumerate(custom_data):
        print(f"custom data {i}: {data.hex()}")


def gen_darwin_dpib() -> None:
    base_ts = 1_757_500_000_000_000
    out = shb("<") + idb("<")
    out += legacy_dpib("<", 501, [(OPT_DPIB_NAME, b"mDNSResponder"), (OPT_DPIB_UUID, UUID)])
    out += legacy_dpib("<", 1, [(OPT_DPIB_NAME, b"launchd")])
    out += epb("<", base_ts + 1, udp_packet(1), [(OPT_EPB_DARWIN_DPIB_ID, struct.pack("<I", 0))])
    out += epb("<", base_ts + 2, udp_packet(2), [(OPT_EPB_DARWIN_DPIB_ID, struct.pack("<I", 1))])
    out += epb("<", base_ts + 3, udp_packet(3), [(OPT_EPB_DARWIN_DPIB_ID, struct.pack("<I", 0)),
                                                 (OPT_EPB_DARWIN_EDPIB_ID, struct.pack("<I", 1))])
    write("process_info_darwin_dpib.pcapng", out)


def gen_pid_reuse() -> None:
    base_ts = 1_757_500_000_000_000

    def pib(pid: int, name: bytes, start_offset_us=None) -> bytes:
        opts = [(OPT_PIB_NAME, name)]
        if start_offset_us is not None:
            opts.append((OPT_PIB_STARTTIME, struct.pack("<Q", (base_ts + start_offset_us) * 1000)))
        return wireshark_cb("<", wireshark_cb_custom_data(WIRESHARK_CB_ENTRY_PROCESS_INFORMATION,
                                                          pib_entry(pid, opts)))

    def packet(seq: int, offset_us: int, pid: int) -> bytes:
        return epb("<", base_ts + offset_us, udp_packet(seq),
                   [(OPT_EPB_PROCESSID_THREADID, struct.pack("<II", pid, 0))])

    out = shb("<") + idb("<")
    out += pib(500, b"first", -10) + pib(500, b"second", 20)
    out += pib(600, b"old") + pib(600, b"new")
    out += packet(1, 5, 500)
    out += packet(2, 25, 500)
    out += packet(3, -100, 500)
    out += packet(4, 1, 600)
    out += packet(5, 2, 700)
    write("process_info_pid_reuse.pcapng", out)


def main() -> None:
    gen_wireshark_cb()
    gen_darwin_dpib()
    gen_pid_reuse()


if __name__ == "__main__":
    main()
