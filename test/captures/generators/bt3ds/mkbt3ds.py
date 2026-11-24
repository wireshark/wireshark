#!/usr/bin/env python3
# Generates test/captures/bt3ds_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth 3DS profile
dissector (packet-bt3ds.c).

The 3DS Connection Announcement is carried over L2CAP with PSM 0x0021
(BTL2CAP_PSM_3DS), in HCI ACL packets. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkbt3ds.py <output directory>

Writes:
  bt3ds-coverage.pcap            LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR (201):
                                 3DS messages on the connectionless L2CAP
                                 channel (CID 0x0002, PSM 0x0021), sent and
                                 received, every flag, battery levels 0, 50,
                                 100, 101, 254 and 255, a reserved opcode
                                 and reserved flag bits; and on a connection
                                 oriented channel opened with an L2CAP
                                 Connection Request/Response for PSM 0x0021
  bt3ds-coverage-malformed.pcap  LINKTYPE_BLUETOOTH_HCI_H4 (187, no
                                 direction): a message with unknown
                                 direction, one with data after the 3
                                 octets (warning), and messages cut short
                                 (exceptions)
"""

import os
import struct
import sys

SENT = 0
RECV = 1
HANDLE = 0x0001
PSM_3DS = 0x0021


def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def acl(l2cap, handle=HANDLE, pb=2):
    """HCI ACL data packet (H4 type 0x02), first automatically flushable
    fragment of a complete L2CAP PDU."""
    return b'\x02' + struct.pack('<HH', handle | (pb << 12), len(l2cap)) + l2cap


def l2cap(cid, payload):
    return struct.pack('<HH', len(payload), cid) + payload


def connless(payload, psm=PSM_3DS):
    """Connectionless (G-frame) channel: the PDU length includes the PSM."""
    return l2cap(0x0002, struct.pack('<H', psm) + payload)


def signal(code, ident, data):
    return l2cap(0x0001, struct.pack('<BBH', code, ident, len(data)) + data)


def phdr(direction, h4):
    return struct.pack('>I', direction) + h4


def msg(opcode=0, flags=0, battery=0):
    """3DS message: opcode, flags (bit 1 battery level display request,
    bit 0 association notification, bits 7-2 reserved), battery level."""
    return struct.pack('BBB', opcode, flags, battery)


def event(code, params):
    return b'\x04' + struct.pack('BB', code, len(params)) + params


# Remote device address, little endian on the wire (00:11:22:33:44:55).
REMOTE_BDADDR = bytes.fromhex('554433221100')


def main_frames():
    return [
        # 1: HCI Connection Complete for handle 0x0001 (ACL), so the ACL
        # frames belong to a connection handle session.
        phdr(RECV, event(0x03, struct.pack('<BH6sBB', 0, HANDLE, REMOTE_BDADDR, 1, 0))),
        # 2-7: connectionless, sent and received, every flag combination,
        # battery levels 50, 100, 0 and 255 (not supported).
        phdr(SENT, acl(connless(msg(0, 0x00, 50)))),
        phdr(RECV, acl(connless(msg(0, 0x01, 100)))),
        phdr(RECV, acl(connless(msg(0, 0x02, 0)))),
        phdr(SENT, acl(connless(msg(0, 0x03, 75)))),
        phdr(RECV, acl(connless(msg(0, 0x01, 255)))),
        phdr(SENT, acl(connless(msg(0, 0x00, 255)))),
        # 8-9: reserved battery levels (101 and 254): notes.
        phdr(SENT, acl(connless(msg(0, 0x00, 101)))),
        phdr(RECV, acl(connless(msg(0, 0x00, 254)))),
        # 10: reserved opcode (note), Info "Unknown".
        phdr(SENT, acl(connless(msg(0x01, 0x00, 20)))),
        # 11: reserved flag bits set (note).
        phdr(RECV, acl(connless(msg(0, 0xFF, 30)))),
        # 12-13: L2CAP Connection Request for PSM 0x0021 (SCID 0x0040) and
        # its Connection Response (DCID 0x0041, success).
        phdr(SENT, acl(signal(0x02, 1, struct.pack('<HH', PSM_3DS, 0x0040)))),
        phdr(RECV, acl(signal(0x03, 1, struct.pack('<HHHH', 0x0041, 0x0040, 0, 0)))),
        # 14-15: 3DS on the connection oriented channel, both directions.
        phdr(SENT, acl(l2cap(0x0041, msg(0, 0x01, 88)))),
        phdr(RECV, acl(l2cap(0x0040, msg(0, 0x02, 255)))),
    ]


def malformed_frames():
    return [
        # 1: unknown direction (no pseudo-header), Info
        # "UnknownDirection 3DG Connection Announcement".
        acl(connless(msg(0, 0x01, 42))),
        # 2: data after the 3 octets: "Unexpected data" warning.
        acl(connless(msg(0, 0x00, 10) + b'\xAA\xBB')),
        # 3-5: 2, 1 and 0 octets of 3DS message: exceptions.
        acl(connless(msg(0, 0x01, 0)[:2])),
        acl(connless(b'\x00')),
        acl(connless(b'')),
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bt3ds-coverage.pcap'), 201, main_frames())
    write_pcap(os.path.join(out, 'bt3ds-coverage-malformed.pcap'), 187, malformed_frames())


if __name__ == '__main__':
    main()
