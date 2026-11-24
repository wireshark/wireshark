#!/usr/bin/env python3
# Generates test/captures/btamp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic coverage captures for the Bluetooth AMP Manager dissector
# (epan/dissectors/packet-btamp.c). Every packet is built with struct;
# nothing comes from a real network.
#
# Usage: mkbtamp.py <outdir>
#   btamp-coverage.pcapng            main capture (H4 + L2CAP CID 0x0003,
#                                    and Exported PDU "btamp")
#   btamp-coverage-malformed.pcapng  truncated commands (exceptions)
import os
import struct
import sys

SENT, RECV = 0, 1
LT_H4_PHDR = 201
LT_EXP_PDU = 252
AMP_CID = 0x0003
HANDLE = 0x002a


class Pcapng:
    def __init__(self):
        self.blocks = []
        self.ifaces = {}
        self.ts = 1700000000 * 1000000
        self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

    def _block(self, btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = len(body) + 12
        self.blocks.append(struct.pack('<II', btype, total) + body + struct.pack('<I', total))

    def iface(self, linktype):
        if linktype not in self.ifaces:
            self.ifaces[linktype] = len(self.ifaces)
            self._block(1, struct.pack('<HHI', linktype, 0, 262144))
        return self.ifaces[linktype]

    def add(self, linktype, data):
        i = self.iface(linktype)
        self.ts += 1000
        self._block(6, struct.pack('<IIIII', i, self.ts >> 32, self.ts & 0xffffffff,
                                   len(data), len(data)) + data)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.blocks))


def crc16_arc(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


_txseq = [0]


def amp_iframe(direction, payload, handle=HANDLE):
    """ERTM I-frame on the AMP Manager fixed channel: control, the AMP
    command and the FCS. packet-btl2cap.c checks the FCS over the basic
    header and the control field only (crc16_plain_tvb_offset(tvb, 0,
    offset)), so it is computed the same way here."""
    txseq = _txseq[0] & 0x3f
    _txseq[0] += 1
    control = struct.pack('<H', txseq << 1)
    hdr = struct.pack('<HH', len(payload) + 4, AMP_CID) + control
    l2 = hdr + payload + struct.pack('<H', crc16_arc(hdr))
    acl = struct.pack('<HH', (handle & 0x0fff) | 0x2000, len(l2)) + l2
    return struct.pack('>I', direction) + b'\x02' + acl


def conn_complete(handle=HANDLE, bd_addr=bytes([0x66, 0x55, 0x44, 0x33, 0x22, 0x11])):
    """HCI Connection Complete event (received), so the ACL frames belong
    to a connection handle session."""
    params = struct.pack('<BH', 0, handle) + bd_addr + bytes([0x01, 0x00])
    return struct.pack('>I', RECV) + b'\x04' + bytes([0x03, len(params)]) + params


def exp_pdu(name, payload):
    n = name.encode()
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def amp(code, ident, data, length=None):
    if length is None:
        length = len(data)
    return struct.pack('<BBH', code, ident, length) + data


def entry(cid, ctype, status):
    return bytes([cid, ctype, status])


ASSOC = bytes(range(0x01, 0x11))          # 16 octets of AMP Assoc data


def main_capture():
    c = Pcapng()

    def acl(d, p):
        c.add(LT_H4_PHDR, amp_iframe(d, p))

    c.add(LT_H4_PHDR, conn_complete())

    # 1-2: Command Reject, reason "Command not understood" and unknown reason
    acl(SENT, amp(0x01, 1, struct.pack('<H', 0x0000)))
    acl(RECV, amp(0x01, 2, struct.pack('<H', 0x0005)))
    # 3: Discover Request (MPS 670, extended features 0)
    acl(SENT, amp(0x02, 3, struct.pack('<HH', 670, 0x0000)))
    # 4: Discover Response, BR/EDR + 802.11 + ECMA-368 controllers
    acl(RECV, amp(0x03, 3, struct.pack('<HH', 670, 0x0000) +
                  entry(0, 0, 1) + entry(1, 1, 6) + entry(2, 2, 3)))
    # 5: Discover Response, one entry and a 2-octet tail (< 3: loop ends)
    acl(RECV, amp(0x03, 4, struct.pack('<HH', 1000, 0x8000) +
                  entry(5, 1, 5) + b'\xee\xee'))
    # 6: Discover Response with an empty controller list
    acl(RECV, amp(0x03, 5, struct.pack('<HH', 670, 0x0000)))
    # 7: Change Notify, controllers with every status value 0, 2, 4 and an
    #    unknown type and status
    acl(SENT, amp(0x04, 6, entry(1, 1, 0) + entry(2, 1, 2) + entry(3, 1, 4) +
                  entry(4, 0x7f, 0x7f)))
    # 8: Change Response
    acl(RECV, amp(0x05, 6, b''))
    # 9: Get Info Request (controller 1)
    acl(SENT, amp(0x06, 7, bytes([1])))
    # 10: Get Info Response, success, guaranteed service type set
    acl(RECV, amp(0x07, 7, bytes([1, 0]) +
                  struct.pack('<IIIHH', 30000, 20000, 1000, 0x0001, 672)))
    # 11: Get Info Response, Invalid Controller ID, no guaranteed service
    acl(RECV, amp(0x07, 8, bytes([9, 1]) +
                  struct.pack('<IIIHH', 0, 0, 0, 0x0000, 0)))
    # 12: Get AMP Assoc Request
    acl(SENT, amp(0x08, 9, bytes([1])))
    # 13: Get AMP Assoc Response with 16 octets of Assoc
    acl(RECV, amp(0x09, 9, bytes([1, 0]) + ASSOC))
    # 14: Create Physical Link Request with Assoc
    acl(SENT, amp(0x0A, 10, bytes([1, 2]) + ASSOC))
    # 15: Create Physical Link Response
    acl(RECV, amp(0x0B, 10, bytes([2, 1, 0])))
    # 16: Disconnect Physical Link Request
    acl(SENT, amp(0x0C, 11, bytes([1, 2])))
    # 17: Disconnect Physical Link Response
    acl(RECV, amp(0x0D, 11, bytes([2, 1, 0])))
    # 18: unknown command code 0x0E with data
    acl(SENT, amp(0x0E, 12, b'\xde\xad\xbe\xef'))
    # 19: Get AMP Assoc Response with an empty Assoc
    acl(RECV, amp(0x09, 13, bytes([1, 1])))
    # 20-21: Exported PDU "btamp" without a direction (UnknownDirection):
    #    Discover Request and unknown command code 0xFF with data
    c.add(LT_EXP_PDU, exp_pdu('btamp', amp(0x02, 14, struct.pack('<HH', 670, 0))))
    c.add(LT_EXP_PDU, exp_pdu('btamp', amp(0xFF, 15, b'\x01\x02')))
    return c


def malformed_capture():
    c = Pcapng()

    def acl(d, p):
        c.add(LT_H4_PHDR, amp_iframe(d, p))

    c.add(LT_H4_PHDR, conn_complete())

    acl(SENT, b'\x02')                                # 1: header cut short
    acl(SENT, amp(0x01, 1, b'\x00'))                  # 2: Command Reject, 1 octet
    acl(SENT, amp(0x02, 2, b'\x9e\x02'))              # 3: Discover Request, no features
    acl(RECV, amp(0x03, 3, b'\x9e'))                  # 4: Discover Response, cut MPS
    acl(SENT, amp(0x06, 4, b''))                      # 5: Get Info Request, no ID
    acl(RECV, amp(0x07, 4, bytes([1, 0, 1, 2])))      # 6: Get Info Response, cut
    acl(SENT, amp(0x08, 5, b''))                      # 7: Get Assoc Request, no ID
    acl(RECV, amp(0x09, 5, bytes([1])))               # 8: Get Assoc Response, no status
    acl(SENT, amp(0x0A, 6, bytes([1])))               # 9: Create Request, no remote ID
    acl(RECV, amp(0x0B, 6, bytes([1, 2])))            # 10: Create Response, no status
    acl(SENT, amp(0x0C, 7, bytes([1])))               # 11: Disconnect Request, cut
    acl(RECV, amp(0x0D, 7, bytes([1, 2])))            # 12: Disconnect Response, cut
    # 13: unknown command code without data: proto_tree_add_item(..., -1)
    #     at the end of the tvb throws
    acl(SENT, amp(0x0E, 8, b''))
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'btamp-coverage.pcapng'))
    malformed_capture().write(os.path.join(out, 'btamp-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
