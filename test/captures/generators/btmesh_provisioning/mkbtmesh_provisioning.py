#!/usr/bin/env python3
# Generates test/captures/btmesh_provisioning_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Bluetooth Mesh Provisioning PDU coverage captures for
packet-btmesh-provisioning.c.

Usage: mkbtmesh_provisioning.py <outdir>

Writes btmesh_provisioning-coverage.pcap (main capture) and
btmesh_provisioning-coverage-malformed.pcap.

Every packet is built with struct.  The main capture is Bluetooth HCI H4
with the Linux direction header (DLT 201): Provisioning PDUs carried by
PB-ADV (AD type 0x29) in HCI LE Advertising Report events, unsegmented and
reassembled from Transaction Start/Continuation PDUs, then an LE
connection with a GATT discovery of the Mesh Provisioning Service (0x1827)
and Provisioning PDUs carried by the Mesh Proxy protocol on the Mesh
Provisioning Data In/Out characteristics, complete and segmented.

The malformed capture is Exported PDU (DLT 252) naming the
"btmesh.provisioning" dissector (no transport context).
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


def be16(v):
    return struct.pack('>H', v)


def fcs(data):
    """Provisioning PDU FCS (3GPP TS 27.010 CRC-8)."""
    crc = 0xff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xe0 if crc & 1 else crc >> 1
    return 0xff - crc


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


# ---------------------------------------------------------------------------
# PB-ADV
# ---------------------------------------------------------------------------
def ad(t, data):
    return bytes([len(data) + 1, t]) + data


def pbadv_transaction(link, trn, prov):
    """Provisioning PDU in PB-ADV Transaction Start (20 octets) and
    Continuation (23 octets) PDUs."""
    segs = [prov[:20]] + [prov[i:i + 23] for i in range(20, len(prov), 23)]
    segn = len(segs) - 1
    out = [struct.pack('>IB', link, trn) + bytes([segn << 2]) + struct.pack('>HB', len(prov), fcs(prov)) + segs[0]]
    for i, s in enumerate(segs[1:], 1):
        out.append(struct.pack('>IB', link, trn) + bytes([(i << 2) | 2]) + s)
    return out


# ---------------------------------------------------------------------------
# Provisioning PDUs
# ---------------------------------------------------------------------------
def invite(duration):
    return bytes([0x00, duration])


def capabilities(elements=1, algorithms=0x0001, pubkey=0x00, static=0x00,
                 out_size=0, out_action=0x0000, in_size=0, in_action=0x0000):
    return bytes([0x01, elements]) + be16(algorithms) + bytes([pubkey, static, out_size]) + \
        be16(out_action) + bytes([in_size]) + be16(in_action)


def start(method, action=0, size=0, algorithm=0, pubkey=0):
    return bytes([0x02, algorithm, pubkey, method, action, size])


PUBKEY = bytes([0x03]) + bytes(range(0x01, 0x41))
INPUT_COMPLETE = bytes([0x04])
CONFIRMATION = bytes([0x05]) + bytes(range(0x10, 0x20))
RANDOM = bytes([0x06]) + bytes(range(0x20, 0x30))
DATA = bytes([0x07]) + bytes(range(0x30, 0x51))
COMPLETE = bytes([0x08])


def failed(code):
    return bytes([0x09, code])


# Valid PDUs: every type, every authentication method, action and size,
# every error code
VALID = [
    invite(0), invite(30),
    capabilities(),
    capabilities(elements=255, algorithms=0x0001, pubkey=0x01, static=0x01, out_size=8,
                 out_action=0x001f, in_size=8, in_action=0x000f),
    capabilities(elements=3, algorithms=0x0000, out_size=1, out_action=0x0001,
                 in_size=4, in_action=0x0004),
    start(0), start(1), start(0, pubkey=1),
] + [start(2, a, s) for a, s in ((0, 1), (1, 2), (2, 4), (3, 6), (4, 8))] + \
    [start(3, a, s) for a, s in ((0, 1), (1, 3), (2, 5), (3, 8))] + [
    INPUT_COMPLETE, CONFIRMATION, RANDOM, COMPLETE,
] + [failed(c) for c in range(9)]

ADDR = b'\xc0\x11\x22\x33\x44\x55'


def proxy_discovery(c):
    c.att(SENT, u8(0x02) + u16(185))                                  # Exchange MTU
    c.att(RECV, u8(0x03) + u16(185))
    c.att(SENT, u8(0x10) + u16(0x0001) + u16(0xffff) + u16(0x2800))
    c.att(RECV, u8(0x11) + u8(6) + u16(0x0001) + u16(0x0006) + u16(0x1827))
    c.att(SENT, u8(0x08) + u16(0x0001) + u16(0x0006) + u16(0x2803))
    c.att(RECV, u8(0x09) + u8(7) + u16(0x0002) + u8(0x04) + u16(0x0003) + u16(0x2adb) +
          u16(0x0004) + u8(0x10) + u16(0x0005) + u16(0x2adc))
    c.att(SENT, u8(0x04) + u16(0x0006) + u16(0x0006))
    c.att(RECV, u8(0x05) + u8(1) + u16(0x0006) + u16(0x2902))
    c.att(SENT, u8(0x12) + u16(0x0006) + u16(0x0001))
    c.att(RECV, u8(0x13))


def proxy_segments(data, sizes):
    out = []
    pos = 0
    for i, n in enumerate(sizes):
        out.append(bytes([((1 if i == 0 else 2) << 6) | 3]) + data[pos:pos + n])
        pos += n
    out.append(bytes([(3 << 6) | 3]) + data[pos:])
    return out


def main_capture(path):
    c = Capture()
    link = 0x0A0B0C0D
    # PB-ADV, unsegmented: every PDU that fits in a Transaction Start
    for i, pdu in enumerate(VALID):
        trn = i if pdu[0] in (0x00, 0x02, 0x04, 0x05, 0x06) else 0x80 + i
        c.adv_report(ADDR, ad(0x29, pbadv_transaction(link, trn, pdu)[0]))
    # PB-ADV, segmented: Public Key (3 segments) and Data (2 segments)
    for p in pbadv_transaction(link, 0x40, PUBKEY):
        c.adv_report(ADDR, ad(0x29, p))
    for p in pbadv_transaction(link, 0x41, DATA):
        c.adv_report(ADDR, ad(0x29, p))
    # Mesh Proxy over GATT: complete and segmented Provisioning PDUs, from
    # the client (Write Command to Data In) and the server (Notification
    # on Data Out).  BT ATT keeps the Data In handle for the opposite
    # direction, so the Write Commands are sent by the remote device.
    c.le_connect(b'\x11\x22\x33\x44\x55\x66')
    proxy_discovery(c)
    c.att(RECV, u8(0x52) + u16(0x0003) + bytes([0x03]) + invite(5))
    c.att(RECV, u8(0x1b) + u16(0x0005) + bytes([0x03]) + capabilities(elements=2, out_size=4, out_action=0x0008))
    c.att(RECV, u8(0x52) + u16(0x0003) + bytes([0x03]) + start(2, 3, 4))
    for seg in proxy_segments(PUBKEY, [20, 20]):
        c.att(RECV, u8(0x52) + u16(0x0003) + seg)
    c.att(RECV, u8(0x1b) + u16(0x0005) + bytes([0x03]) + PUBKEY)
    c.att(RECV, u8(0x1b) + u16(0x0005) + bytes([0x03]) + INPUT_COMPLETE)
    c.att(RECV, u8(0x52) + u16(0x0003) + bytes([0x03]) + CONFIRMATION)
    c.att(RECV, u8(0x1b) + u16(0x0005) + bytes([0x03]) + CONFIRMATION)
    c.att(RECV, u8(0x52) + u16(0x0003) + bytes([0x03]) + RANDOM)
    c.att(RECV, u8(0x1b) + u16(0x0005) + bytes([0x03]) + RANDOM)
    for seg in proxy_segments(DATA, [16]):
        c.att(RECV, u8(0x52) + u16(0x0003) + seg)
    c.att(RECV, u8(0x1b) + u16(0x0005) + bytes([0x03]) + COMPLETE)
    c.write(path)


def malformed_capture(path):
    pdus = [
        bytes([0x40, 0x05]),                                      # padding bits set
        capabilities(elements=0),                                 # zero elements
        capabilities(algorithms=0x0003),                          # RFU algorithm
        capabilities(pubkey=0x02),                                # prohibited
        capabilities(static=0x02),                                # prohibited
        capabilities(out_size=9),                                 # RFU size
        capabilities(out_action=0x0020),                          # RFU action
        capabilities(in_size=9),
        capabilities(in_action=0x0010),
        start(0, algorithm=1),
        start(0, pubkey=2),
        start(0, 1, 0), start(0, 0, 1),                           # No OOB with action/size
        start(1, 1, 0), start(1, 0, 1),                           # Static OOB with action/size
        start(2, 5, 1), start(2, 0, 9), start(2, 0, 0),           # Output OOB
        start(3, 4, 1), start(3, 0, 9), start(3, 0, 0),           # Input OOB
        start(4, 1, 2), bytes([0x02, 0, 0, 0xff]),                # RFU method
        failed(9), failed(0xff),
        bytes([0x0a, 1, 2, 3]), bytes([0x3f]),                    # unknown PDU type
        invite(5) + b'\x00',                                      # extra octet
        COMPLETE + b'\x01\x02',
        bytes([0x00]),                                            # truncated
        capabilities()[:6],
        start(0)[:4],
        PUBKEY[:40],
        bytes([0x05]) + bytes(8),
        bytes([0x06]) + bytes(8),
        DATA[:20],
        bytes([0x09]),
    ]

    def exp_pdu(name, payload):
        n = name.encode()
        pad = (4 - len(n) % 4) % 4
        return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        for i, p in enumerate(pdus):
            p = exp_pdu('btmesh.provisioning', p)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def main(outdir):
    main_capture(os.path.join(outdir, 'btmesh_provisioning-coverage.pcap'))
    malformed_capture(os.path.join(outdir, 'btmesh_provisioning-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
