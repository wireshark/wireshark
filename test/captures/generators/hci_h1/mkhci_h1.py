#!/usr/bin/env python3
# Generates test/captures/hci_h1_coverage.btsnoop.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth HCI H1
dissector (packet-hci_h1.c).

HCI H1 has no packet type octet: the type (command, event or ACL data)
and the direction come from the record header of a BTSNOOP file with
datalink type 1001 (H1). The flags of a record are bit 0 = received
(controller to host) and bit 1 = command/event (otherwise ACL data); a
sent command/event record is a command, a received one an event. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkhci_h1.py <output directory>

Writes:
  hci_h1-coverage.btsnoop            a BTSNOOP H1 file: commands, events
                                     and ACL data in both directions
  hci_h1-coverage-malformed.btsnoop  records cut short
  hci_h1-coverage-exppdu.pcap        Exported PDU frames naming hci_h1
                                     (no Bluetooth metadata is passed)
"""

import os
import struct
import sys

EPOCH = 0x00dcddb30f2f8000


def btsnoop(path, recs, datalink=1001):
    """recs: list of (flags, payload)."""
    with open(path, 'wb') as f:
        f.write(b'btsnoop\0' + struct.pack('>II', 1, datalink))
        ts = EPOCH + 1700000000 * 1000000
        for flags, data in recs:
            ts += 1000
            f.write(struct.pack('>IIIIQ', len(data), len(data), flags, 0, ts) + data)


def cmd(opcode, params=b''):
    return struct.pack('<HB', opcode, len(params)) + params


def evt(code, params=b''):
    return struct.pack('<BB', code, len(params)) + params


def acl(handle, data, pb=2):
    return struct.pack('<HH', handle | (pb << 12), len(data)) + data


def l2cap(cid, payload):
    return struct.pack('<HH', len(payload), cid) + payload


BDADDR = bytes([1, 2, 3, 4, 5, 6])
SENT_CMD, RCVD_EVT, SENT_ACL, RCVD_ACL = 2, 3, 0, 1

RECS = [
    (SENT_CMD, cmd(0x0c03)),                                     # Reset
    (RCVD_EVT, evt(0x0e, bytes([1, 0x03, 0x0c, 0]))),            # Command Complete
    (SENT_CMD, cmd(0x0c13, b'Test device'.ljust(248, b'\0'))),   # Write Local Name
    (RCVD_EVT, evt(0x0e, bytes([1, 0x13, 0x0c, 0]))),
    (SENT_CMD, cmd(0x1001)),                                     # Read Local Version
    (RCVD_EVT, evt(0x0f, bytes([0, 1, 0x01, 0x04]))),            # Command Status
    (SENT_CMD, cmd(0x0405, BDADDR + struct.pack('<HBBHB', 0xcc18, 0, 0, 0, 1))),  # Create Connection
    (RCVD_EVT, evt(0x03, struct.pack('<BH', 0, 0x0001) + BDADDR + bytes([1, 0]))),  # Connection Complete
    (SENT_ACL, acl(0x0001, l2cap(0x0001, bytes([2, 1, 4, 0, 1, 0x10, 0x40, 0])))),  # L2CAP connection request
    (RCVD_ACL, acl(0x0001, l2cap(0x0001, bytes([3, 1, 8, 0, 0x41, 0, 0x40, 0, 0, 0, 0, 0])))),  # response
    (SENT_ACL, acl(0x0001, l2cap(0x0041, b'\x01\x02\x03\x04'))),
    (RCVD_ACL, acl(0x0001, l2cap(0x0040, b'\x05\x06\x07\x08'))),
    # flags bits that the file format does not use are ignored
    (0x80000000 | RCVD_ACL, acl(0x0001, l2cap(0x0040, b'x'))),
    (RCVD_EVT, evt(0x13, struct.pack('<BHH', 1, 0x0001, 2))),     # Number of Completed Packets
    (SENT_CMD, cmd(0x0406, struct.pack('<HB', 0x0001, 0x13))),   # Disconnect
    (RCVD_EVT, evt(0x05, struct.pack('<BHB', 0, 0x0001, 0x16))), # Disconnection Complete
    (0x80000000 | SENT_CMD, cmd(0x0c03)),
]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    btsnoop(os.path.join(out, 'hci_h1-coverage.btsnoop'), RECS)

    mal = [
        (SENT_CMD, b'\x03'),                                    # command cut inside the header
        (RCVD_EVT, b'\x0e\x10\x01'),                            # event shorter than its length
        (SENT_ACL, b'\x01\x20\xff\x00\x01'),                    # ACL longer than the data
        (RCVD_ACL, b'\x01'),
        (SENT_CMD, b''),                                        # empty
        (RCVD_EVT, b''),
        (SENT_ACL, b''),
    ]
    btsnoop(os.path.join(out, 'hci_h1-coverage-malformed.btsnoop'), mal)

    # Exported PDU frames naming hci_h1: the dissector is called without
    # the Bluetooth metadata and returns without decoding anything
    tag = struct.pack('>HH', 12, 8) + b'hci_h1\0\0' + struct.pack('>HH', 0, 0)
    with open(os.path.join(out, 'hci_h1-coverage-exppdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        for i, (_, data) in enumerate(RECS[:3]):
            pkt = tag + data
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(pkt), len(pkt)) + pkt)


main()
