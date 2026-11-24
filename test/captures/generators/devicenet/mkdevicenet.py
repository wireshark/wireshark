#!/usr/bin/env python3
# Generates test/captures/devicenet_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DeviceNet dissector
(packet-devicenet.c).

DeviceNet is reached only through the "can.subdissector" Decode As table
(-d can.subdissector,devicenet): the dissector needs the struct can_info
that the CAN dissectors pass. The 11 bit CAN identifier selects the
message group, the message ID and the source MAC ID. Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkdevicenet.py <output directory>

Writes pcapng files with two interfaces:
  0  LINKTYPE_CAN_SOCKETCAN (227)
  1  LINKTYPE_WIRESHARK_UPPER_PDU (252) (main capture only)

  devicenet-coverage.pcapng            every group 1, 2, 3 and 4 message,
                                       the explicit message services, the
                                       fragmentation protocol, an invalid
                                       CAN ID, extended and RTR frames
                                       (not DeviceNet) and an Exported PDU
                                       naming "devicenet" (no CAN
                                       information)
  devicenet-coverage-malformed.pcapng  frames shorter than their message
"""

import os
import struct
import sys

T0 = 1700000000

CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    tot = 12 + len(body)
    return struct.pack('<II', 0x0A0D0D0A, tot) + body + struct.pack('<I', tot)


def idb(linktype):
    body = struct.pack('<HHI', linktype, 0, 0)
    tot = 12 + len(body)
    return struct.pack('<II', 1, tot) + body + struct.pack('<I', tot)


def epb(ifid, ts, data):
    t = int(ts * 1000000)
    body = (struct.pack('<IIIII', ifid, t >> 32, t & 0xffffffff, len(data), len(data))
            + pad4(data))
    tot = 12 + len(body)
    return struct.pack('<II', 6, tot) + body + struct.pack('<I', tot)


def write(path, frames, exported=False):
    with open(path, 'wb') as f:
        f.write(shb() + idb(227) + (idb(252) if exported else b''))
        for i, (ifid, data) in enumerate(frames):
            f.write(epb(ifid, T0 + i * 0.01, data))


def can(canid, data):
    """SocketCAN header (big endian ID in LINKTYPE_CAN_SOCKETCAN); classic
    frames are padded to 8 octets."""
    return (0, struct.pack('>IBBBB', canid, len(data), 0, 0, 0) + data.ljust(8, b'\0'))


def exported_pdu(name, payload):
    n = name.encode()
    return (1, struct.pack('>HH', 12, len(pad4(n))) + pad4(n)
            + struct.pack('>HH', 0, 0) + payload)


def grp1(msg, mac):
    return 0x000 | (msg << 6) | mac


def grp2(mac, msg):
    return 0x400 | (mac << 3) | msg


def grp3(msg, mac):
    return 0x600 | (msg << 6) | mac


def grp4(msg):
    return 0x7c0 | msg


MASTER = 1
SLAVE = 5


def frames_main():
    F = []
    # 1-5: group 1, the four named messages and another one
    for msg in (0xc, 0xd, 0xe, 0xf, 0x4):
        F.append(can(grp1(msg, SLAVE), bytes([msg, 0x11, 0x22, 0x33])))

    # 6-14: group 2, messages 0-6 and duplicate MAC ID check request
    # (physical port 1) and response (port 2)
    for msg in range(7):
        F.append(can(grp2(SLAVE, msg), bytes([MASTER, msg, 0xa5])))
    F.append(can(grp2(SLAVE, 7), bytes([0x01]) + struct.pack('<HI', 0x0001, 0x12345678)))
    F.append(can(grp2(SLAVE, 7), bytes([0x82]) + struct.pack('<HI', 0x005a, 0x0badcafe)))

    # 15-19: group 3 message 5, unconnected explicit responses: open
    # (actual body format 8/16, message IDs 3 and 4, connection 0x123),
    # close, heartbeat, shutdown, and a service that is not allowed here
    F.append(can(grp3(5, SLAVE), bytes([MASTER, 0xcb, 0x01, 0x34]) + struct.pack('<H', 0x123)))
    F.append(can(grp3(5, SLAVE), bytes([MASTER, 0xcc])))
    F.append(can(grp3(5, SLAVE), bytes([MASTER, 0xcd, 0x01, 0x02])))
    F.append(can(grp3(5, SLAVE), bytes([MASTER, 0xce])))
    F.append(can(grp3(5, SLAVE), bytes([MASTER, 0x8e, 0x01, 0x00])))

    # 20-22: group 3 message 6, unconnected explicit requests: open
    # (body format 16/16, group 3, source message ID 2), close
    # (connection 0x123), and a service that is not allowed here
    F.append(can(grp3(6, MASTER), bytes([SLAVE, 0x4b, 0x02, 0x32])))
    F.append(can(grp3(6, MASTER), bytes([SLAVE, 0x4c]) + struct.pack('<H', 0x123)))
    F.append(can(grp3(6, MASTER), bytes([SLAVE, 0x0e, 0x01, 0x01, 0x01])))

    # 23-26: group 3 message 4, explicit messages: Get Attribute Single
    # request and response, and two with service code 0 that carry a
    # class, instance, attribute and data (8/8 by default): Identity
    # instance 1 Vendor ID, and an unknown class
    F.append(can(grp3(4, MASTER), bytes([SLAVE, 0x0e, 0x01, 0x01, 0x07])))
    F.append(can(grp3(4, SLAVE), bytes([MASTER, 0x8e]) + b'Name'))
    F.append(can(grp3(4, MASTER), bytes([SLAVE, 0x00, 0x01, 0x01, 0x01, 0xaa, 0xbb, 0xcc])))
    F.append(can(grp3(3, SLAVE), bytes([MASTER, 0x80, 0x99, 0x02, 0x05, 0x01, 0x02, 0x03])))

    # 27-30: group 3 fragments: first, middle, last, acknowledge
    F.append(can(grp3(4, MASTER), bytes([0x80 | SLAVE, 0x00, 0x10]) + b'frag1'))
    F.append(can(grp3(4, MASTER), bytes([0x80 | SLAVE, 0x41]) + b'frag2x'))
    F.append(can(grp3(4, MASTER), bytes([0x80 | SLAVE, 0x82]) + b'end'))
    F.append(can(grp3(4, SLAVE), bytes([0x80 | MASTER, 0xc2, 0x00])))

    # 31: XID bit set, Reset request (service 5) with group 3 message 0
    F.append(can(grp3(0, MASTER), bytes([0x40 | SLAVE, 0x05, 0x01, 0x01])))

    # 32-39: service code 0 to the MAC IDs the Node bodytypes table of
    # runcov.sh names (10: 8/16, 11: 16/16, 12: 16/8, 13: CIP path,
    # 14: 8/8); 8/8 at default preferences
    for mac in (10, 11, 12, 13, 14):
        F.append(can(grp3(1, MASTER), bytes([mac, 0x00, 0x04, 0x01, 0x03, 0x10, 0x20, 0x30])))
    # Identity (class 1) instance 1 attribute 1 (Vendor ID) as 8/16 and
    # as 16/8 (the table entry named 16/16), and an attribute as 16/16
    F.append(can(grp3(2, MASTER), bytes([10, 0x00, 0x01, 0x01, 0x00, 0x02, 0x03, 0x04])))
    F.append(can(grp3(2, MASTER), bytes([11, 0x00, 0x01, 0x00, 0x01, 0x01, 0x03, 0x04])))
    F.append(can(grp3(2, MASTER), bytes([12, 0x80, 0x01, 0x00, 0x02, 0x07, 0x08, 0x09])))

    # 40-46: group 4: Communication Faulted response and request (2 and
    # 8 octet forms), Offline Ownership response and request, and
    # reserved message 0
    F.append(can(grp4(0x2c), bytes([0x45, 0x80 | 0x4b])))
    F.append(can(grp4(0x2d), bytes([0x05, 0x4b])))
    F.append(can(grp4(0x2d), bytes([0x00, 0x4b]) + struct.pack('<HI', 0x0001, 0x01020304)))
    F.append(can(grp4(0x2c), bytes([0x80, 0xcb]) + struct.pack('<HI', 0x0001, 0x01020304)))
    F.append(can(grp4(0x2e), bytes([0x05, 0x81]) + struct.pack('<HI', 0x0001, 0x01020304)))
    F.append(can(grp4(0x2f), bytes([0x05, 0x01]) + struct.pack('<HI', 0x0001, 0x01020304)))
    F.append(can(grp4(0x00), bytes([0x01])))

    # 47: a Communication Faulted request that is neither 2 nor 8 octets
    F.append(can(grp4(0x2d), bytes([0x05, 0x4b, 0x00])))

    # 48-50: an invalid CAN ID, and an extended and an RTR frame
    # (not DeviceNet)
    F.append(can(0x7f0, bytes([0x01, 0x02])))
    F.append(can(CAN_EFF_FLAG | 0x12345, bytes([0x01, 0x02])))
    F.append(can(CAN_RTR_FLAG | grp1(0xf, SLAVE), b''))

    # 51: an Exported PDU naming "devicenet" (second interface): no
    # struct can_info, so DeviceNet rejects it and the payload is data
    F.append(exported_pdu('devicenet', bytes([SLAVE, 0x4b, 0x02, 0x32])))
    return F


def frames_malformed():
    F = []
    F.append(can(grp3(4, MASTER), b''))                          # no MAC ID octet
    F.append(can(grp3(4, MASTER), bytes([SLAVE])))               # no service
    F.append(can(grp3(5, SLAVE), bytes([MASTER, 0xcb, 0x01])))  # short open response
    F.append(can(grp3(6, MASTER), bytes([SLAVE, 0x4b])))         # short open request
    F.append(can(grp3(6, MASTER), bytes([SLAVE, 0x4c, 0x01])))   # short close
    F.append(can(grp2(SLAVE, 7), bytes([0x01, 0x01])))           # short dup MAC check
    F.append(can(grp4(0x2e), bytes([0x05, 0x81, 0x01])))         # short ownership
    # service code 0 with 3, 4, 5, 6 and 7 octets (the 8/8 dissection
    # reads an attribute and 3 octets of data beyond these; the other
    # body types with the Node bodytypes table)
    for n in (3, 4, 5, 6, 7):
        for mac in (SLAVE, 10, 11, 12, 13, 14):
            F.append(can(grp3(1, MASTER), bytes([mac, 0x00, 0x04, 0x01, 0x03, 0x10, 0x20])[:n]))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    write(os.path.join(out, 'devicenet-coverage.pcapng'), frames_main(), True)
    write(os.path.join(out, 'devicenet-coverage-malformed.pcapng'), frames_malformed())


if __name__ == '__main__':
    main()
