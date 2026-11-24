#!/usr/bin/env python3
# Generates test/captures/homeplug_av_vendor_vertexcom_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the VertexCom vendor part of
the HomePlug AV dissector (packet-homeplug-av-vendor-vertexcom.c).

HomePlug AV (ethertype 0x88E1) frames with a vendor MM type (top bit
set) carry a three octet OUI after the header; OUI 00:13:D7 is VertexCom.
The VS_* messages are decoded by heuristic dissectors that look at the MM
type, and only when at least 38 octets follow the OUI.  Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkhomeplug_av_vendor_vertexcom.py <output directory>

Writes:
  homeplug-av-vendor-vertexcom-coverage.pcap            every VS_* message with
                                                 a decoder, the options of
                                                 SNR, link statistics (Tx,
                                                 Rx, neither) and network
                                                 info, AV 1.0 and 1.1
                                                 headers, an unknown type
                                                 and a short message
  homeplug-av-vendor-vertexcom-coverage-malformed.pcap  link statistics
                                                 confirmation without its
                                                 request (state kept across
                                                 packets), cut-short
                                                 messages
"""
import struct
import sys

ETYPE = 0x88E1
OUI = bytes.fromhex('0013d7')

VS = [
    ('VS_GET_VERSION_REQ', 0xA000), ('VS_GET_VERSION_CNF', 0xA001), ('VS_RESET_REQ', 0xA008),
    ('VS_RESET_CNF', 0xA009), ('VS_GET_ETH_PHY_REQ', 0xA020), ('VS_GET_ETH_PHY_CNF', 0xA021),
    ('VS_ETH_STATS_REQ', 0xA024), ('VS_ETH_STATS_CNF', 0xA025), ('VS_GET_STATUS_REQ', 0xA030),
    ('VS_GET_STATUS_CNF', 0xA031), ('VS_GET_SNR_REQ', 0xA038), ('VS_GET_SNR_CNF', 0xA039),
    ('VS_GET_LINK_STATS_REQ', 0xA040), ('VS_GET_LINK_STATS_CNF', 0xA041),
    ('VS_GET_NW_INFO_REQ', 0xA0FC), ('VS_GET_NW_INFO_CNF', 0xA0FD),
    ('VS_SET_CAPTURE_STATE_REQ', 0xA100), ('VS_SET_CAPTURE_STATE_CNF', 0xA101),
    ('VS_SET_NVRAM_REQ', 0xA104), ('VS_SET_NVRAM_CNF', 0xA105), ('VS_GET_NVRAM_REQ', 0xA108),
    ('VS_GET_NVRAM_CNF', 0xA109), ('VS_GET_PWM_STATS_REQ', 0xA10C),
    ('VS_GET_PWM_STATS_CNF', 0xA10D), ('VS_GET_PWM_STATS_IND', 0xA10E),
    ('VS_GET_PWM_CONF_REQ', 0xA110), ('VS_GET_PWM_CONF_CNF', 0xA111),
    ('VS_SET_PWM_CONF_REQ', 0xA114), ('VS_SET_PWM_CONF_CNF', 0xA115),
    ('VS_PWM_GENERATION_REQ', 0xA118), ('VS_PWM_GENERATION_CNF', 0xA119),
    ('VS_SPI_STATS_REQ', 0xA11C), ('VS_SPI_STATS_CNF', 0xA11D), ('VS_SET_TX_CAL_REQ', 0xA128),
    ('VS_SET_TX_CAL_CNF', 0xA129), ('VS_SET_REMOTE_ACCESS_REQ', 0xA13C),
    ('VS_SET_REMOTE_ACCESS_CNF', 0xA13D), ('VS_GET_REMOTE_ACCESS_REQ', 0xA140),
    ('VS_GET_REMOTE_ACCESS_CNF', 0xA141), ('VS_FILE_ACCESS_REQ', 0xA4FC),
    ('VS_FILE_ACCESS_CNF', 0xA4FD),
]


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, pad=True, dst=1, src=2):
    fr = bytes([2, 0, 0, 0, 0, dst, 2, 0, 0, 0, 0, src]) + struct.pack('>H', ETYPE) + payload
    if pad and len(fr) < 60:
        fr += bytes(60 - len(fr))
    return fr


def mme(mmv, mmtype, payload, fmi=b'\x10\x05'):
    """MMV, MM type, the two fragmentation octets of an AV 1.1 header, the
    OUI and the message."""
    b = bytes([mmv]) + struct.pack('<H', mmtype)
    if mmv:
        b += fmi
    return b + OUI + payload


def P(*spec, n=60):
    """n zero octets with (offset, value) pairs patched in."""
    b = bytearray(n)
    for off, val in spec:
        if isinstance(val, int):
            val = bytes([val])
        if off + len(val) > len(b):
            b.extend(bytes(off + len(val) - len(b)))
        b[off:off + len(val)] = val
    return bytes(b)


def MAC(n):
    return bytes([2, 0, 0, 0, 0, n])


BIG = {0xA039: 1100, 0xA104: 1100, 0xA109: 1100}     # SNR list, NVRAM blocks


def variants():
    fr = []
    add = lambda mmv, t, p, pad=True: fr.append((mmv, t, p, pad))
    link_reqs = {0xA040}
    for n, t in VS:
        if t == 0xA041:
            continue                       # sent right after its request below
        add(1, t, bytes(BIG.get(t, 200)))
        if t == 0xA040:
            # the request sets the Tx/Rx flag that the confirmation uses
            add(1, 0xA041, bytes(100))                      # request flag 0: Tx statistics
            add(1, 0xA040, P((3, 1)))
            add(1, 0xA041, bytes(100))                      # flag 1: Rx statistics
            add(1, 0xA040, P((3, 2)))
            add(1, 0xA041, bytes(100))                      # neither: just the header
            add(1, 0xA040, P((3, 0), (4, 1), (5, MAC(3))))  # Tx request with an address
            add(1, 0xA041, P((0, 7), (1, 1)))
    # SNR confirmation: interval list with both end time formats, carrier groups
    add(1, 0xA039, P((0, 0), (1, 3), (2, 2), (3, struct.pack('<HH', 50, 200)),
                     (7, struct.pack('<H', 0x1234)), (9, 0), (10, bytes(range(256)) * 4), n=1100))
    add(1, 0xA039, P((2, 1), (3, struct.pack('<H', 97)), (5, struct.pack('<H', 0)), (7, 3),
                     (8, bytes([0x80 | (i & 0x7f) for i in range(1024)])), n=1100))
    add(1, 0xA039, P((2, 0), (5, 4)))                                   # carrier group above 3: no SNR list
    add(1, 0xA038, P((0, MAC(4)), (6, 5), (7, 1), (8, 2)))             # SNR request
    # network info with two stations
    add(1, 0xA0FD, P((0, bytes(range(1, 8))), (7, 0x2a), (8, 1), (9, MAC(1)), (15, 2),
                     (16, bytes([1]) + MAC(2) + struct.pack('<HHHH', 100, 90, 80, 70) + b'\x05'),
                     (32, bytes([2]) + MAC(3) + struct.pack('<HHHH', 200, 190, 180, 170) + b'\x06')))
    # file access with fragment data
    add(1, 0xA4FC, P((0, 1), (1, 2), (2, b'config.bin'), (34, struct.pack('<HHIIH', 3, 1, 0, 0xdeadbeef, 8)),
                     (50, b'fragment!'), n=70))
    add(1, 0xA4FD, P((0, 0), (1, 1), (2, 2), (3, b'config.bin'), (35, struct.pack('<HHIH', 3, 1, 0, 8)),
                     (47, b'fragment!'), n=70))
    # selected messages with non-zero values
    add(1, 0xA001, P((0, 0), (1, b'\x00\x01'), (3, 2), (4, b'1.2.3'), (20, b'avstack-7'), (84, b'alt-9'), (100, b'bootloader-1'), n=170),)
    add(1, 0xA001, P((1, b"\x01\x00"), n=180))
    add(1, 0xA021, P((0, 0), (1, 1), (2, 2), (3, 1), (4, 7)))
    add(1, 0xA031, P((0, 0), (1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1), (7, 1), (8, 1),
                     (9, struct.pack('<q', -5)), (17, struct.pack('<q', 1500)),
                     (25, struct.pack('>Q', 86400)), (33, struct.pack('>Q', 600)), (41, struct.pack('>H', 3)), n=70))
    add(1, 0xA114, P((0, 1), (1, 2), (2, 1), (3, struct.pack('>H', 1000)), (5, struct.pack('>H', 10)),
                     (7, struct.pack('>H', 20)), (9, struct.pack('>H', 30)), (11, struct.pack('>H', 40)),
                     (13, struct.pack('>H', 50))))
    # AV 1.0 header (no fragmentation octets), a type without a decoder, and a
    # message too short to be decoded (fewer than 38 octets after the OUI)
    for n, t in VS[:6]:
        add(0, t, bytes(200))
    add(0, 0xA138, bytes(60))
    add(1, 0xA03C, bytes(60))
    add(1, 0xA001, bytes(10), False)         # not padded to the Ethernet minimum
    add(0, 0xA001, bytes(37), False)
    return fr


def main(out):
    pcap(out + '/homeplug-av-vendor-vertexcom-coverage.pcap',
         [eth(mme(mmv, t, p), pad=pad) for mmv, t, p, pad in variants()])
    m = []
    # confirmation without its request: the flag kept from the previous
    # packet (or its initial value) decides whether Tx or Rx is decoded, so
    # the result differs between one and two passes (the first pass
    # already ran the later requests)
    m.append(eth(mme(1, 0xA041, bytes(80))))
    m.append(eth(mme(1, 0xA040, P((3, 1)))))
    m.append(eth(mme(1, 0xA041, bytes(80))))
    m.append(eth(mme(1, 0xA040, P((3, 0)))))
    m.append(eth(mme(1, 0xA041, bytes(80))))
    # cut-short messages (38 or more octets after the OUI, but fewer than the layout)
    m.append(eth(mme(1, 0xA001, bytes(40)), pad=False))                    # version string cut
    m.append(eth(mme(1, 0xA039, P((2, 3)) [:60]), pad=False))               # SNR interval list cut
    m.append(eth(mme(1, 0xA039, P((5, 0), n=500)), pad=False))              # SNR values cut
    m.append(eth(mme(1, 0xA0FD, P((15, 9), n=60)), pad=False))              # nine stations, one fits
    m.append(eth(mme(1, 0xA104, bytes(200)), pad=False))                    # NVRAM block cut
    m.append(eth(mme(1, 0xA4FC, bytes(40)), pad=False))                     # file access header cut
    m.append(eth(mme(1, 0xA025, bytes(40)), pad=False))                     # Ethernet statistics cut
    m.append(eth(mme(1, 0xA11D, bytes(50)), pad=False))                     # SPI statistics cut
    pcap(out + '/homeplug-av-vendor-vertexcom-coverage-malformed.pcap', m)


if __name__ == '__main__':
    main(sys.argv[1])
