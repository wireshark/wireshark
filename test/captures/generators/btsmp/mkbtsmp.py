#!/usr/bin/env python3
# Generates test/captures/btsmp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Bluetooth SMP coverage captures for packet-btsmp.c.

Usage: mkbtsmp.py <outdir>

Writes btsmp-coverage.pcapng (main capture) and
btsmp-coverage-malformed.pcapng.  Every packet is built with struct:
Bluetooth HCI H4 with the Linux direction header (DLT 201) carrying an LE
connection with SMP on the LE fixed channel (CID 0x0006) and a BR/EDR
connection with SMP on the BR/EDR Security Manager channel (CID 0x0007),
plus a few frames as HCI H4 without a direction header (DLT 187) for the
unknown direction.  Nothing comes from a real device.
"""
import os
import struct
import sys

SENT, RECV = 0, 1
LT_H4_PHDR = 201
LT_H4 = 187
LE_HANDLE = 0x0040
BR_HANDLE = 0x0041
SMP_LE = 0x0006
SMP_BR = 0x0007

# LE Secure Connections debug public key (Core spec Vol 3, Part H, 2.3.5.6.1),
# little endian as sent on the air
DEBUG_X = bytes.fromhex('e69d350e480103ccdbfdf4ac1191f4efb9a5f9e9a7832c5e2cbe97f2d203b020')
DEBUG_Y = bytes.fromhex('8bd28915d08e1c742430ed8fc24563765c15525abf9a32636deb2a65499c80dc')


class Pcapng:
    def __init__(self):
        self.blocks = []
        self.ifaces = {}
        self.n = 0
        self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

    def _block(self, btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = len(body) + 12
        self.blocks.append(struct.pack('<II', btype, total) + body + struct.pack('<I', total))

    def iface(self, linktype):
        if linktype not in self.ifaces:
            self.ifaces[linktype] = len(self.ifaces)
            self._block(0x00000001, struct.pack('<HHI', linktype, 0, 65535))
        return self.ifaces[linktype]

    def add(self, linktype, data):
        i = self.iface(linktype)
        ts = (1700000000 + self.n) * 1000000
        self.n += 1
        self._block(0x00000006, struct.pack('<IIIII', i, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.blocks))


def h4(direction, ptype, body, phdr=True):
    return (struct.pack('>I', direction) if phdr else b'') + bytes([ptype]) + body


def le_conn_complete(handle, peer, phdr=True):
    # LE Meta, LE Connection Complete: status, handle, role central, peer
    # address type public, peer address, interval, latency, timeout, SCA
    ev = bytes([0x01, 0x00]) + struct.pack('<H', handle) + bytes([0x00, 0x00]) + peer[::-1] + \
        struct.pack('<HHH', 0x0018, 0, 0x00c8) + b'\x00'
    return h4(RECV, 0x04, bytes([0x3e, len(ev)]) + ev, phdr)


def br_conn_complete(handle, peer):
    # Connection Complete: status, handle, address, link type ACL, no encryption
    ev = struct.pack('<BH', 0, handle) + peer[::-1] + b'\x01\x00'
    return h4(RECV, 0x04, bytes([0x03, len(ev)]) + ev)


def acl(direction, handle, cid, payload, phdr=True):
    l2 = struct.pack('<HH', len(payload), cid) + payload
    return h4(direction, 0x02, struct.pack('<HH', (handle & 0x0fff) | 0x2000, len(l2)) + l2, phdr)


def key16(seed):
    return bytes((seed + i * 17) & 0xff for i in range(16))


def pairing(op, io, oob, authreq, maxkey, ikeys, rkeys):
    return bytes([op, io, oob, authreq, maxkey, ikeys, rkeys])


def main_capture():
    c = Pcapng()
    peer = bytes.fromhex('c0ffee112233')

    def le(d, p):
        c.add(LT_H4_PHDR, acl(d, LE_HANDLE, SMP_LE, p))

    def br(d, p):
        c.add(LT_H4_PHDR, acl(d, BR_HANDLE, SMP_BR, p))

    # 1: LE connection
    c.add(LT_H4_PHDR, le_conn_complete(LE_HANDLE, peer))
    # 2-12: LE legacy pairing, Just Works / passkey, with key distribution
    le(RECV, bytes([0x0B, 0x05]))                              # Security Request: Bonding, MITM
    le(SENT, pairing(0x01, 0x04, 0x00, 0x05, 16, 0x07, 0x07))  # Keyboard, Display
    le(RECV, pairing(0x02, 0x00, 0x00, 0x01, 16, 0x03, 0x07))  # Display Only
    le(SENT, bytes([0x03]) + key16(0x10))                      # Pairing Confirm
    le(RECV, bytes([0x03]) + key16(0x20))
    le(SENT, bytes([0x04]) + key16(0x30))                      # Pairing Random
    le(RECV, bytes([0x04]) + key16(0x40))
    le(RECV, bytes([0x06]) + key16(0x50))                      # Encryption Information
    le(RECV, bytes([0x07]) + struct.pack('<H', 0x1234) + bytes(range(1, 9)))  # Central Identification
    le(RECV, bytes([0x08]) + key16(0x60))                      # Identity Information
    le(RECV, bytes([0x09, 0x00]) + peer[::-1])                 # Identity Address Information, public
    # 13-14
    le(RECV, bytes([0x0A]) + key16(0x70))                      # Signing Information
    le(SENT, bytes([0x09, 0x01]) + bytes.fromhex('c11122334455')[::-1])  # random static address
    # 15-24: LE Secure Connections, numeric comparison, then passkey entry with keypress
    le(SENT, pairing(0x01, 0x01, 0x00, 0x2d, 16, 0x0b, 0x0b))  # Display Yes/No; Bonding MITM SC CT2
    le(RECV, pairing(0x02, 0x01, 0x01, 0x3d, 16, 0x02, 0x02))  # OOB present; + Keypress
    x_other = bytes((0xa0 + i) & 0xff for i in range(32))
    y_other = bytes((0x50 + 3 * i) & 0xff for i in range(32))
    le(SENT, bytes([0x0C]) + DEBUG_X + DEBUG_Y)                # debug key
    le(RECV, bytes([0x0C]) + x_other + y_other)                # ordinary key
    le(SENT, bytes([0x0C]) + DEBUG_X + y_other)                # debug X, other Y
    le(RECV, bytes([0x0C]) + x_other + DEBUG_Y)                # other X, debug Y
    le(RECV, bytes([0x03]) + key16(0x80))
    le(SENT, bytes([0x04]) + key16(0x90))
    le(SENT, bytes([0x0D]) + key16(0xa0))                      # DHKey Check
    le(RECV, bytes([0x0D]) + key16(0xb0))
    # 25-29: Keypress Notifications, every type
    for t in range(5):
        le(SENT, bytes([0x0E, t]))
    # 30-36: other IO capabilities, bonding values and AuthReq/key distribution bits
    le(SENT, pairing(0x01, 0x02, 0x00, 0x00, 7, 0x00, 0x00))   # Keyboard Only, No Bonding, no keys
    le(RECV, pairing(0x02, 0x03, 0x00, 0x02, 16, 0x0f, 0xf0))  # No Input No Output, bonding 2, every key, reserved
    le(SENT, pairing(0x01, 0x05, 0x02, 0xc3, 16, 0xff, 0x08))  # unknown IO capability and OOB, reserved AuthReq bits
    le(RECV, bytes([0x0B, 0xff]))                              # Security Request: every bit
    le(RECV, bytes([0x0B, 0x20]))                              # Security Request: No Bonding, CT2
    le(RECV, bytes([0x0B, 0x08]))                              # SecureConnection only
    le(RECV, bytes([0x0B, 0x10]))                              # Keypress only
    # 37-51: Pairing Failed, every reason and an unknown one
    for r in range(1, 0x10):
        le(RECV if r & 1 else SENT, bytes([0x05, r]))
    # 52: unknown Keypress Notification type
    le(SENT, bytes([0x0E, 0x05]))
    # 53: unknown opcode
    le(SENT, bytes([0x0F]))
    # 54: BR/EDR connection; 55-60: cross-transport key derivation on CID 7
    c.add(LT_H4_PHDR, br_conn_complete(BR_HANDLE, bytes.fromhex('0200000000aa')))
    br(SENT, pairing(0x01, 0x00, 0x00, 0x21, 16, 0x0e, 0x0e))  # Bonding, CT2; IRK CSRK Linkkey
    br(RECV, pairing(0x02, 0x00, 0x00, 0x21, 16, 0x06, 0x06))
    br(RECV, bytes([0x08]) + key16(0xc0))
    br(RECV, bytes([0x09, 0x00]) + bytes.fromhex('0200000000aa')[::-1])
    br(RECV, bytes([0x0A]) + key16(0xd0))
    br(SENT, bytes([0x05, 0x0E]))
    # 61-63: H4 without direction header: unknown direction
    c.add(LT_H4, le_conn_complete(0x0050, bytes.fromhex('c0ffee445566'), phdr=False))
    c.add(LT_H4, acl(SENT, 0x0050, SMP_LE, pairing(0x01, 0x03, 0x00, 0x01, 16, 0x01, 0x01), phdr=False))
    c.add(LT_H4, acl(SENT, 0x0050, SMP_LE, bytes([0x05, 0x08]), phdr=False))
    return c


def malformed_capture():
    c = Pcapng()
    peer = bytes.fromhex('c0ffee112233')

    def le(d, p):
        c.add(LT_H4_PHDR, acl(d, LE_HANDLE, SMP_LE, p))

    c.add(LT_H4_PHDR, le_conn_complete(LE_HANDLE, peer))
    le(SENT, b'')                                  # empty PDU
    le(SENT, bytes([0x01, 0x04, 0x00]))            # Pairing Request cut in the AuthReq
    le(SENT, bytes([0x01, 0x04, 0x00, 0x05, 16, 0x07]))  # cut before the responder keys
    le(SENT, bytes([0x03]) + key16(0)[:8])         # short Confirm
    le(SENT, bytes([0x04]))                        # Random without value
    le(SENT, bytes([0x05]))                        # Failed without reason
    le(SENT, bytes([0x06]) + key16(0)[:4])
    le(SENT, bytes([0x07, 0x12]))
    le(SENT, bytes([0x08]) + key16(0)[:15])
    le(SENT, bytes([0x09, 0x00, 0x11]))
    le(SENT, bytes([0x0A]))
    le(SENT, bytes([0x0B]))
    le(SENT, bytes([0x0C]) + DEBUG_X[:20])         # Public Key cut in X
    le(SENT, bytes([0x0C]) + DEBUG_X + DEBUG_Y[:10])  # cut in Y
    le(SENT, bytes([0x0D]) + key16(0)[:3])
    le(SENT, bytes([0x0E]))
    le(SENT, bytes([0x0C]) + DEBUG_X + DEBUG_Y + b'\x00\x01')  # trailing data
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'btsmp-coverage.pcapng'))
    malformed_capture().write(os.path.join(out, 'btsmp-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
