#!/usr/bin/env python3
# Generates test/captures/hci_h4_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth HCI H4
dissector (packet-hci_h4.c).

HCI H4 packets start with a one octet packet type (1 command, 2 ACL,
3 SCO, 4 event, 5 ISO) followed by the HCI packet. The dissector is
reached from the Bluetooth dissector for the link types
LINKTYPE_BLUETOOTH_HCI_H4 (187, no direction: it is taken from the
pcapng packet flags) and LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR (201, with
a four octet direction field). Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkhci_h4.py <output directory>

Writes:
  hci_h4-coverage.pcapng            both link types, every packet type,
                                    packets of unknown type, all
                                    directions
  hci_h4-coverage-malformed.pcapng  empty and truncated packets, an
                                    Exported PDU naming hci_h4 without
                                    Bluetooth metadata
"""

import os
import struct
import sys

# ------------------------------------------------------------ pcapng
def blk(t, body):
    pad = (-len(body)) % 4
    l = 12 + len(body) + pad
    return struct.pack('<II', t, l) + body + b'\0' * pad + struct.pack('<I', l)


def opt(code, val):
    pad = (-len(val)) % 4
    return struct.pack('<HH', code, len(val)) + val + b'\0' * pad


class Pcapng:
    def __init__(self, linktypes):
        self.data = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in linktypes:
            self.data += blk(1, struct.pack('<HHI', lt, 0, 65535))
        self.ts = 1700000000 * 1000000

    def epb(self, ifid, pkt, direction=None):
        """direction: None (no flags option), 0 unknown, 1 inbound, 2 outbound."""
        self.ts += 1000
        o = b''
        if direction is not None:
            o = opt(2, struct.pack('<I', direction)) + opt(0, b'')
        self.data += blk(6, struct.pack('<IIIII', ifid, self.ts >> 32, self.ts & 0xffffffff,
                                        len(pkt), len(pkt)) + pkt + b'\0' * ((-len(pkt)) % 4) + o)
        # the option block follows the padded packet data

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(self.data)


# --------------------------------------------------------------- HCI
def cmd(opcode, params=b''):
    return b'\x01' + struct.pack('<HB', opcode, len(params)) + params


def evt(code, params=b''):
    return b'\x04' + struct.pack('<BB', code, len(params)) + params


def acl(handle, data, pb=2):
    return b'\x02' + struct.pack('<HH', handle | (pb << 12), len(data)) + data


def l2cap(cid, payload):
    return struct.pack('<HH', len(payload), cid) + payload


def sco(handle, data):
    return b'\x03' + struct.pack('<HB', handle, len(data)) + data


def iso(handle, data):
    return b'\x05' + struct.pack('<HH', handle, len(data)) + data


BDADDR = bytes([1, 2, 3, 4, 5, 6])
PKTS = [
    cmd(0x0c03),                                          # Reset
    evt(0x0e, bytes([1, 0x03, 0x0c, 0])),                 # Command Complete (Reset)
    cmd(0x0c13, b'Test device'.ljust(248, b'\0')),        # Write Local Name
    evt(0x0e, bytes([1, 0x13, 0x0c, 0])),
    cmd(0x1001),                                          # Read Local Version
    evt(0x0f, bytes([0, 1, 0x01, 0x04])),                 # Command Status
    evt(0x03, struct.pack('<BH', 0, 0x0001) + BDADDR + bytes([1, 0])),   # Connection Complete
    evt(0x03, struct.pack('<BH', 0, 0x0002) + BDADDR + bytes([1, 0])),
    acl(0x0001, l2cap(0x0040, b'\x01\x02\x03\x04')),      # ACL, L2CAP data on a dynamic CID
    acl(0x0002, l2cap(0x0001, bytes([2, 1, 4, 0, 1, 0, 0x40, 0]))),  # signalling: connection request
    sco(0x0003, bytes(range(8))),
    iso(0x0004, struct.pack('<HH', 1, 0) + b'\x01\x02\x03\x04'),
    evt(0x13, struct.pack('<BHH', 1, 0x0001, 4)),         # Number of Completed Packets
]
# unknown packet types (the dissector shows the type and hands the rest
# to the data dissector)
UNKNOWN = [b'\x00\x01\x02\x03', b'\x06\x00', b'\x07abc', b'\xff' + bytes(range(10)), b'\x09']


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)

    # interface 0: H4 without pseudo header (direction from the packet
    # flags, none -> unknown), interface 1: H4 with the direction field
    p = Pcapng([187, 201])
    for i, pk in enumerate(PKTS):
        # no flags option, inbound, outbound in turn
        p.epb(0, pk, [None, 1, 2][i % 3])
    for pk in UNKNOWN:
        p.epb(0, pk, 1)
    p.epb(0, PKTS[0], 0)               # direction flags: unknown
    p.epb(0, PKTS[0], 3)               # direction bits 11
    for i, pk in enumerate(PKTS):
        p.epb(1, struct.pack('>I', i % 2) + pk)     # 0 sent, 1 received
    for pk in UNKNOWN:
        p.epb(1, struct.pack('>I', 0) + pk)
        p.epb(1, struct.pack('>I', 1) + pk)
    p.write(os.path.join(out, 'hci_h4-coverage.pcapng'))

    # -------------------------------------------------------- malformed
    q = Pcapng([187, 201, 252])
    q.epb(0, b'\x01', 1)                    # command without header
    q.epb(0, b'\x01\x03', 2)
    q.epb(0, b'\x04\x0e\x10\x01', 1)        # event shorter than its length
    q.epb(0, b'\x02\x01\x20\xff\x00\x01', 1)  # ACL longer than the data
    q.epb(0, b'\x03\x01', 1)
    q.epb(0, b'\x05\x01\x00\x20\x00\x01', 1)
    q.epb(0, b'', 1)                        # empty (record with no data)
    q.epb(1, struct.pack('>I', 0))          # phdr and nothing else
    q.epb(1, struct.pack('>I', 1) + b'\x01\x03')
    # Exported PDU naming hci_h4: no Bluetooth metadata is passed down
    tag = struct.pack('>HH', 12, 8) + b'hci_h4\0\0' + struct.pack('>HH', 0, 0)
    q.epb(2, tag + PKTS[0])
    q.epb(2, tag + PKTS[6])
    q.epb(2, tag + PKTS[1])
    q.write(os.path.join(out, 'hci_h4-coverage-malformed.pcapng'))


main()
