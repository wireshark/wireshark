#!/usr/bin/env python3
# Generates test/captures/btmesh_beacon_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Bluetooth Mesh Beacon coverage captures for
packet-btmesh-beacon.c.

Usage: mkbtmesh_beacon.py <outdir>

Writes btmesh_beacon-coverage.pcap (main capture) and
btmesh_beacon-coverage-malformed.pcap.

Every packet is built with struct.  The main capture is Bluetooth HCI H4
with the Linux direction header (DLT 201): Mesh Beacons (AD type 0x2B) in
HCI LE Advertising Report events, then an LE connection with a GATT
discovery of the Mesh Proxy Service (0x1828) and Mesh Beacons carried by
the Mesh Proxy protocol on the Mesh Proxy Data Out characteristic,
complete and segmented.

The malformed capture is Exported PDU (DLT 252) naming the
"btmesh.beacon" dissector (no transport context).
"""
import os
import struct
import sys

SENT = 0
RECV = 1


def u8(v):
    return struct.pack('<B', v & 0xff)


def u16(v):
    return struct.pack('<H', v & 0xffff)


# ---------------------------------------------------------------------------
# HCI H4 framing
# ---------------------------------------------------------------------------
class Capture:
    def __init__(self, chandle=0x0040):
        self.frames = []
        self.chandle = chandle

    def raw(self, direction, h4):
        self.frames.append(struct.pack('>I', direction) + h4)

    def adv_report(self, addr, ad_data):
        """LE Meta event, LE Advertising Report with one ADV_NONCONN_IND
        report from a random address."""
        rep = bytes([0x01, 0x03, 0x01]) + addr[::-1] + bytes([len(ad_data)]) + ad_data + bytes([0xc4])
        ev = bytes([0x02]) + rep
        self.raw(RECV, bytes([0x04, 0x3e, len(ev)]) + ev)

    def le_connect(self, peer):
        ev = bytes([0x01, 0x00]) + u16(self.chandle) + bytes([0x00, 0x00]) + peer[::-1] + \
            u16(0x0018) + u16(0) + u16(0x00c8) + bytes([0x00])
        self.raw(RECV, bytes([0x04, 0x3e, len(ev)]) + ev)

    def att(self, direction, pdu):
        l2 = struct.pack('<HH', len(pdu), 0x0004) + pdu
        self.raw(direction, struct.pack('<BHH', 0x02, 0x2000 | self.chandle, len(l2)) + l2)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 201))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000,
                                    len(fr), len(fr)))
                f.write(fr)


def ad(t, data):
    return bytes([len(data) + 1, t]) + data


# ---------------------------------------------------------------------------
# Mesh Beacons
# ---------------------------------------------------------------------------
UUID = bytes.fromhex("70cf7c9732a345b691494810d2e9cbf4")


def unprov(oob=0x0000, uri_hash=b''):
    return bytes([0x00]) + UUID + struct.pack('>H', oob) + uri_hash


def secure(flags=0x00, ivindex=0x12345678):
    return bytes([0x01, flags]) + bytes.fromhex("3ecaff672f673370") + \
        struct.pack('>I', ivindex) + bytes.fromhex("8ea261582f364f6f")


URI_HASH = bytes.fromhex("d97478b3")
ADDR = b'\xc0\x11\x22\x33\x44\x55'


def proxy_discovery(c):
    c.att(SENT, u8(0x02) + u16(185))                                  # Exchange MTU
    c.att(RECV, u8(0x03) + u16(185))
    c.att(SENT, u8(0x10) + u16(0x0001) + u16(0xffff) + u16(0x2800))
    c.att(RECV, u8(0x11) + u8(6) + u16(0x0001) + u16(0x0006) + u16(0x1828))
    c.att(SENT, u8(0x08) + u16(0x0001) + u16(0x0006) + u16(0x2803))
    c.att(RECV, u8(0x09) + u8(7) + u16(0x0002) + u8(0x04) + u16(0x0003) + u16(0x2add) +
          u16(0x0004) + u8(0x10) + u16(0x0005) + u16(0x2ade))
    c.att(SENT, u8(0x04) + u16(0x0006) + u16(0x0006))
    c.att(RECV, u8(0x05) + u8(1) + u16(0x0006) + u16(0x2902))
    c.att(SENT, u8(0x12) + u16(0x0006) + u16(0x0001))
    c.att(RECV, u8(0x13))


def proxy_segments(data, sizes):
    """Mesh Beacon (Proxy PDU type 1) in SAR first/continuation/last
    segments."""
    out = []
    pos = 0
    for i, n in enumerate(sizes):
        out.append(bytes([((1 if i == 0 else 2) << 6) | 1]) + data[pos:pos + n])
        pos += n
    out.append(bytes([(3 << 6) | 1]) + data[pos:])
    return out


def main_capture(path):
    c = Capture()
    # 1-16: Unprovisioned Device Beacons over advertising: no OOB, each
    # OOB Information bit, all bits, and with a URI Hash
    flags_ad = ad(0x01, b'\x06')
    for oob in (0x0000, 0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040,
                0x0800, 0x1000, 0x2000, 0x4000, 0x8000, 0xf87f):
        c.adv_report(ADDR, ad(0x2b, unprov(oob)))
    c.adv_report(ADDR, ad(0x2b, unprov(0x0002, URI_HASH)))
    c.adv_report(ADDR, flags_ad + ad(0x2b, unprov(0x0000, URI_HASH)))
    # 17-20: Secure Network Beacons: every flag combination
    for flags, iv in ((0x00, 0x12345678), (0x01, 0x12345678), (0x02, 0x12345679), (0x03, 0x00000000)):
        c.adv_report(ADDR, ad(0x2b, secure(flags, iv)))
    # 21-38: Mesh Proxy: discovery, complete and segmented beacons
    # (Notification on Data Out)
    c.le_connect(b'\x11\x22\x33\x44\x55\x66')
    proxy_discovery(c)
    c.att(RECV, u8(0x1b) + u16(0x0005) + bytes([0x01]) + secure(0x02, 0x12345679))
    c.att(RECV, u8(0x1b) + u16(0x0005) + bytes([0x01]) + unprov(0x0010))
    for seg in proxy_segments(secure(0x01, 0x1234567a), [10]):
        c.att(RECV, u8(0x1b) + u16(0x0005) + seg)
    for seg in proxy_segments(unprov(0x0002, URI_HASH), [8, 8]):
        c.att(RECV, u8(0x1b) + u16(0x0005) + seg)
    c.write(path)


def malformed_capture(path):
    pdus = [
        bytes([0x02, 0x00]) + bytes(25),           # Mesh Private Beacon: not decoded
        bytes([0xff, 0x01, 0x02]),                 # unknown type
        bytes([0x02]),                             # unknown type, no data
        unprov(0x0780),                            # OOB RFU bits
        unprov(0x0080, URI_HASH),
        secure(0x04),                              # flags RFU bits
        secure(0xfc),
        unprov(0x0000, b'\x01'),                   # neither 0 nor 4 octets after OOB
        unprov(0x0000, b'\x01\x02\x03'),
        unprov(0x0000, URI_HASH + b'\x05'),
        secure() + b'\x00',                        # octet after the Authentication Value
        unprov()[:10],                             # truncated
        unprov()[:18],
        secure()[:12],
        secure()[:20],
        bytes([0x01]),
    ]

    def exp_pdu(name, payload):
        n = name.encode()
        pad = (4 - len(n) % 4) % 4
        return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        for i, p in enumerate(pdus):
            p = exp_pdu('btmesh.beacon', p)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def main(outdir):
    main_capture(os.path.join(outdir, 'btmesh_beacon-coverage.pcap'))
    malformed_capture(os.path.join(outdir, 'btmesh_beacon-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
