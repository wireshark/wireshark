#!/usr/bin/env python3
# Generates test/captures/prp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the PRP trailer dissector
(packet-prp.c).

PRP (IEC 62439-3) is not a protocol of its own on the wire: the dissector
is a heuristic dissector of the "eth.trailer" list. It looks for a
Redundancy Control Trailer (RCT) at the end of an Ethernet frame:
PRP-0 is 4 octets (16 bit sequence number, 4 bit LAN id 0xA/0xB, 12 bit
LSDU size), PRP-1 is 6 octets (the same plus the suffix 0x88FB). PRP-0
may sit before padding in a short frame; PRP-1 is always last.
Every frame is built with struct; nothing is captured traffic.

Usage: mkprp.py <output directory>

Writes:
  prp-coverage.pcapng            PRP-0 and PRP-1 trailers on LAN A and B,
                                 correct and wrong LSDU sizes, trailer
                                 before padding, frames with an FCS
                                 (interface 1 has if_fcslen = 4), trailers
                                 shorter than 4 octets, no trailer
  prp-coverage-malformed.pcap    frame cut short in the trailer
"""
import os
import struct
import sys
import zlib

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def block(btype, body):
    body += b'\0' * ((4 - len(body) % 4) % 4)
    ln = 12 + len(body)
    return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)


def opt(code, val):
    return struct.pack('<HH', code, len(val)) + val + b'\0' * ((4 - len(val) % 4) % 4)


def pcapng(path, frames):
    """frames: list of (interface, bytes). Interface 0 has no FCS,
    interface 1 has if_fcslen = 4."""
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 65535))
    out += block(1, struct.pack('<HHI', 1, 0, 65535) + opt(13, b'\x04') + opt(0, b''))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (data, orig) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(data), orig))
            f.write(data)


def eth(etype, payload):
    return MAC_B + MAC_A + struct.pack('>H', etype) + payload


def arp(n=1):
    return struct.pack('>HHBBH', 1, 0x0800, 6, 4, n) + MAC_A + bytes([192, 168, 0, 1]) \
        + MAC_B + bytes([192, 168, 0, 2])


def udp_ip(datalen):
    udp = struct.pack('>HHHH', 4000, 9, 8 + datalen, 0) + bytes(range(datalen))
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0) \
        + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2])
    s = sum(struct.unpack('>10H', ip))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', ~s & 0xffff) + ip[12:]
    return ip + udp


def rct0(seq, lan, size):
    return struct.pack('>HH', seq, (lan << 12) | size)


def rct1(seq, lan, size):
    return rct0(seq, lan, size) + struct.pack('>H', 0x88FB)


def fcs(fr):
    return struct.pack('<I', zlib.crc32(fr) & 0xffffffff)


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    F = []  # (interface, frame)

    # Frame sizes: the LSDU size "correct" for the dissector is the frame
    # length minus the 14 octet Ethernet header.
    # 1-4: PRP-1 over UDP/IPv4 (a frame of at least 64 octets), LAN A/B,
    # correct size and wrong size
    for seq, lan, dl in ((1, 0xA, 40), (2, 0xB, 41), (3, 0xA, 60)):
        body = udp_ip(dl)
        size = len(body) + 6
        F.append((0, eth(0x0800, body + rct1(seq, lan, size))))
    F.append((0, eth(0x0800, udp_ip(40) + rct1(4, 0xB, 100))))      # wrong size
    # 5-7: PRP-0 at the end of long frames; the size is checked
    for seq, lan, dl in ((5, 0xA, 40), (6, 0xB, 50)):
        body = udp_ip(dl)
        F.append((0, eth(0x0800, body + rct0(seq, lan, len(body) + 4))))
    F.append((0, eth(0x0800, udp_ip(40) + rct0(7, 0xA, 5))))        # no match
    # 8-10: short frames (ARP): PRP-0 directly after the payload, PRP-1
    F.append((0, eth(0x0806, arp() + rct0(0x108, 0xA, 28 + 4))))
    F.append((0, eth(0x0806, arp(2) + rct1(0x109, 0xB, 28 + 6))))
    F.append((0, eth(0x0806, arp(2) + rct1(0x10a, 0xA, 7))))           # wrong
    # 11-12: PRP-0 followed by zero padding, 60 octet frame: found by the
    # search loop (i > 0); and trailer after zero padding (padding
    # stripped by Ethernet first)
    F.append((0, eth(0x0806, arp() + rct0(0x10b, 0xB, 28 + 4) + bytes(14))))
    F.append((0, eth(0x0806, arp() + bytes(14) + rct0(0x10c, 0xA, 28 + 14 + 4))))
    # 13: PRP-1 after padding (frame must reach 60 octets)
    F.append((0, eth(0x0806, arp() + bytes(12) + rct1(0x10d, 0xA, 28 + 12 + 6))))
    # 14-15: trailer shorter than 4 octets; trailer that is not an RCT
    F.append((0, eth(0x0800, udp_ip(40) + b'\x12\x34')))
    F.append((0, eth(0x0800, udp_ip(40) + b'\x12\x34\x56\x78\x9a')))
    # 16: LAN id not A or B
    F.append((0, eth(0x0800, udp_ip(40) + rct0(16, 0x3, 20 + 8 + 40 + 4))))
    # 17: no trailer at all
    F.append((0, eth(0x0800, udp_ip(40))))
    # 18-23: the same with an FCS (interface 1, if_fcslen = 4)
    for fr in (
        eth(0x0800, udp_ip(40) + rct1(18, 0xA, 20 + 8 + 40 + 6)),
        eth(0x0800, udp_ip(44) + rct0(19, 0xB, 20 + 8 + 44 + 4)),
        eth(0x0806, arp(1) + rct0(20, 0xA, 28 + 4)),
        eth(0x0806, arp(2) + rct1(21, 0xB, 28 + 6)),
        eth(0x0800, udp_ip(40)),
        eth(0x0800, udp_ip(40) + rct1(23, 0xB, 3)),
    ):
        F.append((1, fr + fcs(fr)))
    pcapng(os.path.join(outdir, 'prp-coverage.pcapng'), F)

    # malformed capture: frames cut short inside the trailer
    full = eth(0x0800, udp_ip(40) + rct1(30, 0xA, 20 + 8 + 40 + 6))
    M = [(full[:-1], len(full)), (full[:-3], len(full)), (full[:-5], len(full)),
         (full[:-6], len(full))]
    # PRP-1 whose first octet was taken as padding: the trailer the
    # dissector sees is 5 octets and the PRP-1 start is before its tvb
    pad1 = eth(0x0806, arp() + bytes(12) + rct1(13, 0xA, 28 + 12 + 6))
    M.append((pad1, len(pad1)))
    full0 = eth(0x0800, udp_ip(40) + rct0(31, 0xB, 20 + 8 + 40 + 4))
    M += [(full0[:-1], len(full0)), (full0[:-3], len(full0))]
    pcap(os.path.join(outdir, 'prp-coverage-malformed.pcap'), M)


if __name__ == '__main__':
    main(sys.argv[1])
