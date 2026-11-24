#!/usr/bin/env python3
# Generates test/captures/epon_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EPON dissector
(packet-epon.c, IEEE 802.3 EPON preamble).

The capture uses link-layer type 259 (LINKTYPE_EPON, WTAP_ENCAP_EPON),
which is handed to the EPON dissector by default. Each record starts
with the EPON preamble: the start-of-packet delimiter /S/ in byte 1, 2
or 3 (captured preamble of 8, 7 or 6 octets), the DPoE security octet
(0x55 when security is off), the mode bit and 15 bit LLID, and a CRC-8
over the preamble; an Ethernet frame (with FCS) follows unless the DPoE
octet says the frame is encrypted. Every packet is built from scratch
with struct; no captured traffic is used (addresses from 192.0.2.0/24).

Usage: mkepon.py <output directory>

Writes:
  epon-coverage.pcap            the three preamble lengths, unicast and
                                broadcast LLIDs, DPoE encrypted frames
                                with key ID 0 and 1, Ethernet with
                                ARP, IPv4/UDP and a VLAN tag
  epon-coverage-malformed.pcap  no /S/, a bad CRC, DPoE octets with bad
                                reserved bits or encryption off with
                                key 0, preambles cut short
"""

import os
import struct
import sys
import zlib


def crc8_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xE0 if c & 1 else c >> 1
        t.append(c)
    return t


CRC8 = crc8_table()


def crc8(data):
    fcs = 0
    for b in data:
        fcs = CRC8[fcs ^ b]
    return fcs


def pcap(path, frames, linktype=259):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4_udp(src, dst, sport, dport, payload):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(udp))
    udp = udp[:6] + struct.pack('>H', csum(ph + udp)) + udp[8:]
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000,
                      64, 17, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + udp


ONU = bytes.fromhex('020000000011')
OLT = bytes.fromhex('020000000022')
BCAST = b'\xff' * 6


def eth(dst, src, etype, payload, fcs=True):
    fr = dst + src + struct.pack('>H', etype) + payload
    if len(fr) < 60:
        fr += b'\0' * (60 - len(fr))
    if fcs:
        fr += struct.pack('<I', zlib.crc32(fr) & 0xffffffff)
    return fr


def arp_req():
    return struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, ONU,
                       bytes((192, 0, 2, 11)), b'\0' * 6, bytes((192, 0, 2, 22)))


def udp_frame(n):
    return eth(OLT, ONU, 0x0800, ipv4_udp((192, 0, 2, 11), (192, 0, 2, 22),
                                          40000 + n, 9, b'EPON test %d' % n))


def preamble(sld_byte, sec, llid, broadcast=False, crc=None):
    """sld_byte 1, 2 or 3: the captured preamble is 8, 7 or 6 octets."""
    lead = {1: b'\x55\x55', 2: b'\x55', 3: b''}[sld_byte]
    p = b'\xd5\x55' + bytes((sec,)) + struct.pack('>H', (0x8000 if broadcast else 0) | llid)
    # The CRC-8 covers the 5 octets from the /S/ delimiter to the LLID
    c = crc8(p) if crc is None else crc
    full = lead + p
    return full + bytes((c,))


def main_frames():
    F = []
    # 1: 8 octet preamble, security off, unicast LLID 1, ARP request
    F.append(preamble(1, 0x55, 1) + eth(BCAST, ONU, 0x0806, arp_req()))
    # 2: 7 octet preamble, unicast LLID 0x1234, IPv4/UDP
    F.append(preamble(2, 0x55, 0x1234) + udp_frame(2))
    # 3: 6 octet preamble, broadcast LLID 0x7fff, IPv4/UDP
    F.append(preamble(3, 0x55, 0x7fff, True) + udp_frame(3))
    # 4: DPoE encryption on, key ID 0: the rest is encrypted data
    F.append(preamble(1, 0x56, 5) + bytes(range(64)))
    # 5: DPoE encryption on, key ID 1, broadcast, 6 octet preamble
    F.append(preamble(3, 0x57, 6, True) + bytes(range(64, 128)))
    # 6: 7 octet preamble, VLAN tagged IPv4/UDP
    F.append(preamble(2, 0x55, 7) + eth(OLT, ONU, 0x8100,
             struct.pack('>HH', 100, 0x0800) +
             ipv4_udp((192, 0, 2, 11), (192, 0, 2, 22), 40006, 9, b'vlan')))
    # 7: Ethernet without FCS after the preamble
    F.append(preamble(1, 0x55, 8) + eth(OLT, ONU, 0x0800,
             ipv4_udp((192, 0, 2, 11), (192, 0, 2, 22), 40007, 9, b'no fcs' * 4),
             fcs=False))
    return F


def malformed_frames():
    F = []
    # 1: no start-of-packet delimiter
    F.append(b'\x55\x55\x55\x55\x55\x55\x55\x00' + udp_frame(1))
    # 2: bad CRC-8
    F.append(preamble(1, 0x55, 1, crc=0) + udp_frame(2))
    # 3: DPoE octet with bad reserved bits, encryption on
    F.append(preamble(1, 0x02, 3) + bytes(16))
    # 4: DPoE octet with encryption off and key ID 0
    F.append(preamble(2, 0x54, 4) + udp_frame(4))
    # 5: preamble cut after the delimiter
    F.append(b'\x55\x55\xd5\x55')
    # 6: shorter than the delimiter check
    F.append(b'\xd5')
    # 7: preamble only, no Ethernet frame
    F.append(preamble(3, 0x55, 9))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'epon-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'epon-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
