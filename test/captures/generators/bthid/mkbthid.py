#!/usr/bin/env python3
# Generates test/captures/bthid_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth HID dissector
(packet-bthid.c).

HID runs on L2CAP PSM 0x11 (control) and 0x13 (interrupt), both registered
by default. The captures are Bluetooth HCI H4 with pseudo-header (link type
201): an HCI Connection Complete event, the two L2CAP connections, then HID
messages. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkbthid.py <output directory>

Writes:
  bthid-coverage.pcap            the main capture (frame ranges in README)
  bthid-coverage-malformed.pcap  truncated messages
  bthid-coverage-exported.pcap   HID in Exported PDU frames (no L2CAP below,
                                 UnknownDirection), for the coverage run only
"""

import os
import struct
import sys

SENT, RECV = 0, 1
HANDLE = 0x0001
BD_ADDR = bytes.fromhex('665544332211')      # little endian 11:22:33:44:55:66

CTRL = (0x0040, 0x0041)      # PSM 0x0011 HID control (local CID, remote CID)
INTR = (0x0042, 0x0043)      # PSM 0x0013 HID interrupt

# ---------------------------------------------------------------- writers

def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for usec, data in frames:
            f.write(struct.pack('<IIII', usec // 1000000, usec % 1000000,
                                len(data), len(data)))
            f.write(data)


class Capture:
    """Frames 10 ms apart; add() returns the frame number."""

    def __init__(self, start=1700000000 * 1000000):
        self.t = start
        self.frames = []

    def add(self, data, gap=10000):
        self.t += gap
        self.frames.append((self.t, data))
        return len(self.frames)


# ---------------------------------------------------------------- HCI/L2CAP

def h4(direction, ptype, payload):
    return struct.pack('>I', direction) + bytes([ptype]) + payload


def hci_conn_complete():
    ev = struct.pack('<BH6sBB', 0, HANDLE, BD_ADDR, 1, 0)
    return h4(RECV, 0x04, bytes([0x03, len(ev)]) + ev)


def acl(direction, cid, payload):
    l2 = struct.pack('<HH', len(payload), cid) + payload
    a = struct.pack('<HH', (HANDLE & 0x0fff) | 0x2000, len(l2)) + l2
    return h4(direction, 0x02, a)


def l2cap_connect(cap, psm, chan, ident):
    """We connect to a PSM of the remote device. chan = (local, remote CID)."""
    scid, dcid = chan
    req = struct.pack('<BBHHH', 0x02, ident, 4, psm, scid)
    rsp = struct.pack('<BBHHHHH', 0x03, ident, 8, dcid, scid, 0, 0)
    cap.add(acl(SENT, 1, req))
    cap.add(acl(RECV, 1, rsp))


def l2cap_connect_in(cap, psm, chan, ident):
    """The remote device connects to one of our PSMs."""
    lcid, rcid = chan
    req = struct.pack('<BBHHH', 0x02, ident, 4, psm, rcid)
    rsp = struct.pack('<BBHHHHH', 0x03, ident, 8, lcid, rcid, 0, 0)
    cap.add(acl(RECV, 1, req))
    cap.add(acl(SENT, 1, rsp))


def on_chan(direction, chan, payload):
    lcid, rcid = chan
    return acl(direction, rcid if direction == SENT else lcid, payload)


def exp_pdu(name, payload):
    """Exported PDU without a direction tag (UnknownDirection)."""
    n = name.encode()
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


# ---------------------------------------------------------------- HID

def hid(ttype, param, payload=b''):
    return bytes([(ttype << 4) | (param & 0x0F)]) + payload


HANDSHAKE, HID_CONTROL, GET_REPORT, SET_REPORT = 0x0, 0x1, 0x4, 0x5
GET_PROTOCOL, SET_PROTOCOL, GET_IDLE, SET_IDLE, DATA, DATC = 0x6, 0x7, 0x8, 0x9, 0xA, 0xB

KBD_IN = bytes([0x22, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00])  # RIGHT SHIFT+LEFT SHIFT, a, b
KBD_IN2 = bytes([0xDD, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00])  # other modifiers, 1
KBD_LEDS = bytes([0x03])                                           # NumLock, CapsLock
MOUSE = bytes([0x05, 0x10, 0xF0, 0x01])                            # LEFT+MIDDLE, x, y, wheel


def setup(cap):
    cap.add(hci_conn_complete())
    l2cap_connect(cap, 0x0011, CTRL, 1)
    l2cap_connect(cap, 0x0013, INTR, 2)


def main_capture():
    cap = Capture()
    setup(cap)                                                       # 1-5
    i = lambda d, t, p, pl=b'': cap.add(on_chan(d, INTR, hid(t, p, pl)))
    ctl = lambda d, t, p, pl=b'': cap.add(on_chan(d, CTRL, hid(t, p, pl)))

    # 6-13: HANDSHAKE with every result code and a reserved one
    for rc in (0x0, 0x1, 0x2, 0x3, 0x4, 0xE, 0xF, 0x5):
        ctl(RECV, HANDSHAKE, rc)
    # 14-20: HID_CONTROL NOP .. Virtual Cable Unplug and a reserved one
    for op in range(0, 7):
        ctl(SENT, HID_CONTROL, op)
    # 21-28: GET_REPORT, size 0 (with and without Report ID) and size 1
    # (Report ID and BufferSize, and BufferSize alone), each report type
    ctl(SENT, GET_REPORT, 0x1, b'\x01')                   # Input, Report ID 1
    ctl(SENT, GET_REPORT, 0x2)                            # Output, no Report ID
    ctl(SENT, GET_REPORT, 0x8 | 0x3, b'\x02' + struct.pack('<H', 64))  # Feature
    ctl(SENT, GET_REPORT, 0x8 | 0x0, struct.pack('<H', 32))            # Other, no ID
    ctl(RECV, DATA, 0x1, b'\x01' + KBD_IN)                # the answer: Input
    ctl(RECV, HANDSHAKE, 0x2)                             # Invalid Report ID
    ctl(SENT, GET_REPORT, 0x4 | 0x1, b'\x03')             # reserved bit set
    ctl(RECV, DATA, 0x3, b'\x00\xAA\xBB')                 # Feature, protocol None
    # 29-32: SET_REPORT of each report type
    ctl(SENT, SET_REPORT, 0x2, b'\x01' + KBD_LEDS)
    ctl(RECV, HANDSHAKE, 0x0)
    ctl(SENT, SET_REPORT, 0x3, b'\x05\x11\x22\x33')
    ctl(SENT, SET_REPORT, 0x4 | 0x1, b'\x01')            # reserved bit set
    # 33-36: GET_PROTOCOL (with the protocol octet), SET_PROTOCOL Boot/Report
    ctl(SENT, GET_PROTOCOL, 0x0, b'\x01')
    ctl(SENT, GET_PROTOCOL, 0x0, b'\x02')                 # Report (mask 0x01)
    ctl(SENT, SET_PROTOCOL, 0x1)
    ctl(SENT, SET_PROTOCOL, 0x0)
    # 37-38: GET_IDLE and SET_IDLE (deprecated in HID 1.1)
    ctl(SENT, GET_IDLE, 0x0, b'\x00')
    ctl(SENT, SET_IDLE, 0x0, bytes([250]))                # 1.000 ms
    # 39-49: DATA on the interrupt channel: keyboard input (two modifier
    # sets), keyboard output LEDs, keyboard feature (not dissected
    # further), mouse, protocol None, unknown protocol code
    i(RECV, DATA, 0x1, b'\x01' + KBD_IN)
    i(RECV, DATA, 0x1, b'\x01' + KBD_IN2)
    i(SENT, DATA, 0x2, b'\x01' + KBD_LEDS)
    i(SENT, DATA, 0x3, b'\x01\x7F')
    i(RECV, DATA, 0x1, b'\x02' + MOUSE)
    i(RECV, DATA, 0x0, b'\x00\x01\x02')
    i(RECV, DATA, 0x1, b'\x07\x01\x02')
    # 46-47: the reproducer of the Info column fix: reserved bits set in
    # the DATA and DATC parameter (0xA5 Input, 0xBF Feature)
    i(RECV, DATA, 0x5, b'\x02' + MOUSE)
    i(RECV, DATC, 0xF, b'\x00\x10\x20')
    # 48: DATC Output keyboard LEDs
    i(SENT, DATC, 0x2, b'\x01\x04')
    # 49-54: reserved transaction types
    for t in (0x2, 0x3, 0xC, 0xD, 0xE, 0xF):
        ctl(SENT, t, 0x0)
    return cap.frames


def malformed_capture():
    cap = Capture()
    setup(cap)
    ctl = lambda d, t, p, pl=b'': cap.add(on_chan(d, CTRL, hid(t, p, pl)))
    ctl(SENT, SET_REPORT, 0x0)              # 6: SET_REPORT without data
    ctl(SENT, GET_PROTOCOL, 0x0)            # 7: no protocol octet
    ctl(SENT, GET_IDLE, 0x0)                # 8: no idle rate
    ctl(SENT, SET_IDLE, 0x0)                # 9
    ctl(SENT, GET_REPORT, 0x8 | 0x1, b'\x01')   # 10: BufferSize truncated
    ctl(RECV, DATA, 0x1)                    # 11: no protocol code
    ctl(RECV, DATA, 0x1, b'\x01\x22')       # 12: keyboard input truncated
    ctl(RECV, DATA, 0x2, b'\x01')           # 13: LEDs missing
    ctl(RECV, DATA, 0x1, b'\x02')           # 14: mouse report missing
    cap.add(on_chan(SENT, CTRL, b''))       # 15: empty
    return cap.frames


def exported_capture():
    cap = Capture()
    cap.add(exp_pdu('bthid', hid(HID_CONTROL, 0x3)))
    cap.add(exp_pdu('bthid', hid(DATA, 0x1, b'\x02' + MOUSE)))
    return cap.frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bthid-coverage.pcap'), 201, main_capture())
    write_pcap(os.path.join(out, 'bthid-coverage-malformed.pcap'), 201, malformed_capture())
    write_pcap(os.path.join(out, 'bthid-coverage-exported.pcap'), 252, exported_capture())


if __name__ == '__main__':
    main()
