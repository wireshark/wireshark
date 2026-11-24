#!/usr/bin/env python3
# Generates test/captures/dvb_data_mpe_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB data MPE coverage captures: MultiProtocol Encapsulation
sections (table ID 0x3E) in MPEG-TS packets on PID 0x0200 (linktype 243),
carrying IPv4, IPv6 and LLC/SNAP datagrams. Usage: mkdvb_data_mpe.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from dvbts import LINKTYPE_MPEG_2_TS, section, TS, write_pcap

PID_MPE = 0x0200


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4_udp(src, dst, sport, dport, payload, ident=1):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", csum(ph + udp) or 0xFFFF) + udp[8:]
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0x4000,
                      64, 17, 0, src, dst)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + udp


def ipv6_udp(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack("!IxxxB", len(udp), 17)
    udp = udp[:6] + struct.pack("!H", csum(ph + udp) or 0xFFFF) + udp[8:]
    return struct.pack("!IHBB", 0x60000000, len(udp), 17, 64) + src + dst + udp


def mpe(mac, datagram, llc_snap=0, payload_scr=0, addr_scr=0, reserved=3,
        sect=0, last=0, cur_next=1):
    """DSM-CC private section with the MAC address split and reversed."""
    m = mac
    body = (bytes([m[5], m[4],
                   (reserved << 6) | (payload_scr << 4) | (addr_scr << 2) |
                   (llc_snap << 1) | cur_next, sect, last,
                   m[3], m[2], m[1], m[0]]) + datagram)
    return section(0x3E, body, reserved=3)


SRC4 = bytes([192, 0, 2, 1])
MCAST4 = bytes([239, 1, 2, 3])
MAC4 = bytes([0x01, 0x00, 0x5e, 0x01, 0x02, 0x03])
SRC6 = bytes.fromhex("20010db8000000000000000000000001")
MCAST6 = bytes.fromhex("ff0e0000000000000000000000000123")
MAC6 = bytes([0x33, 0x33, 0x00, 0x00, 0x01, 0x23])
UCAST_MAC = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x42])


def build_main():
    ts = TS()
    frames = []

    def add(*sects):
        frames.extend(ts.sections(PID_MPE, list(sects)))

    # 1: IPv4 multicast UDP datagram
    add(mpe(MAC4, ipv4_udp(SRC4, MCAST4, 40000, 40001, b"MPE IPv4 datagram")))
    # 2: IPv6 multicast UDP datagram, not yet applicable
    add(mpe(MAC6, ipv6_udp(SRC6, MCAST6, 40000, 40002, b"MPE IPv6 datagram"),
            cur_next=0))
    # 3: LLC/SNAP encapsulated IPv4 to a unicast MAC
    snap = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
    add(mpe(UCAST_MAC, snap + ipv4_udp(SRC4, bytes([192, 0, 2, 66]), 40000,
                                       40003, b"MPE LLC/SNAP", ident=2),
            llc_snap=1))
    # 4-9: a 1000 octet datagram that spans six TS packets
    add(mpe(MAC4, ipv4_udp(SRC4, MCAST4, 40000, 40001,
                           bytes(range(256)) * 3 + b"x" * 204, ident=3)))
    # 10: two MPE sections in one TS packet (section 0 and 1 of 1)
    add(mpe(MAC4, ipv4_udp(SRC4, MCAST4, 40000, 40001, b"one", ident=4),
            sect=0, last=1),
        mpe(MAC4, ipv4_udp(SRC4, MCAST4, 40000, 40001, b"two", ident=5),
            sect=1, last=1))
    # 11: address scrambling control 1 (warning, MAC shown as scrambled
    # bytes, the IPv4 datagram is still dissected)
    add(mpe(bytes(6), ipv4_udp(SRC4, MCAST4, 40000, 40001, b"addr", ident=6),
            addr_scr=1))
    # 12: payload scrambling control 2 (warning, payload shown as data)
    add(mpe(MAC4, bytes(range(32)), payload_scr=2))
    # 13: reserved bits 01 instead of 11 (warning)
    add(mpe(MAC4, ipv4_udp(SRC4, MCAST4, 40000, 40001, b"rsvd", ident=7),
            reserved=1))
    return frames


def build_malformed():
    ts = TS()
    frames = []
    # 1: section cut inside the MAC address
    frames += ts.sections(PID_MPE, [section(0x3E, b"\x03\x02\xc1\x00", crc=False)])
    # 2: section length shorter than the header, so the CRC offset is
    # before the payload
    frames += ts.sections(PID_MPE, [section(0x3E, bytes(9), crc=False, length=2)])
    # 3: truncated IPv4 header in an MPE section
    frames += ts.sections(PID_MPE, [mpe(MAC4, b"\x45\x00\x00")])
    return frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-data-mpe-coverage.pcap"), build_main(),
               LINKTYPE_MPEG_2_TS)
    write_pcap(os.path.join(out, "dvb-data-mpe-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_MPEG_2_TS)
