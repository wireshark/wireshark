#!/usr/bin/env python3
# Generates test/captures/bthcrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth HCRP dissector
(packet-bthcrp.c).

HCRP has no fixed L2CAP PSM: L2CAP and HCRP find the channel type from SDP.
The captures are Bluetooth HCI H4 with pseudo-header (link type 201): an
HCI Connection Complete event, an L2CAP connection to SDP and an SDP
Service Search Attribute exchange in which the remote printer announces
HCR_Print (0x1126) with the HCRP control channel on PSM 0x1001 and the data
channel on PSM 0x1003 (additional protocol descriptor list), and HCR_Scan
(0x1127) on PSM 0x1007 with no HCRP protocol. The remote device then reads
our own record (HardcopyCableReplacement 0x1125, notification channel on
PSM 0x1005) and connects to it. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkbthcrp.py <output directory>

Writes:
  bthcrp-coverage.pcap            the main capture (frame ranges in README)
  bthcrp-coverage-malformed.pcap  truncated control PDUs
  bthcrp-coverage-exported.pcap   HCRP in Exported PDU frames (no L2CAP
                                  below, UnknownDirection), coverage only
"""

import os
import struct
import sys

SENT, RECV = 0, 1
HANDLE = 0x0001
BD_ADDR = bytes.fromhex('665544332211')      # little endian 11:22:33:44:55:66

# L2CAP channels: (local CID, remote CID)
SDP = (0x0040, 0x0041)       # PSM 0x0001
CTRL = (0x0042, 0x0043)      # PSM 0x1001 HCRP control (remote record)
DATA = (0x0044, 0x0045)      # PSM 0x1003 HCRP data (remote record)
NOTIF = (0x0046, 0x0070)     # PSM 0x1005 HCRP notification (our record)
SCAN = (0x0048, 0x0049)      # PSM 0x1007 HCR_Scan, L2CAP only

PSM_CTRL, PSM_DATA, PSM_NOTIF, PSM_SCAN = 0x1001, 0x1003, 0x1005, 0x1007

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


# ---------------------------------------------------------------- SDP

def de_u16(v):
    return b'\x09' + struct.pack('>H', v)


def de_u32(v):
    return b'\x0a' + struct.pack('>I', v)


def de_uuid16(v):
    return b'\x19' + struct.pack('>H', v)


def de_seq(*items):
    body = b''.join(items)
    return b'\x35' + bytes([len(body)]) + body


def sdp_exchange(cap, chan, records, tid, incoming=False):
    """A Service Search Attribute request and its response carrying
    'records' (a list of attribute lists). With incoming the remote device
    asks and we answer (our own records)."""
    req_params = (de_seq(de_uuid16(0x0100)) + struct.pack('>H', 0x0200) +
                  de_seq(de_u32(0x0000FFFF)) + b'\x00')
    req = struct.pack('>BHH', 0x06, tid, len(req_params)) + req_params
    lists = de_seq(*records)
    rsp_params = struct.pack('>H', len(lists)) + lists + b'\x00'
    rsp = struct.pack('>BHH', 0x07, tid, len(rsp_params)) + rsp_params
    cap.add(on_chan(RECV if incoming else SENT, chan, req))
    cap.add(on_chan(SENT if incoming else RECV, chan, rsp))


def remote_records():
    print_rec = de_seq(
        de_u16(0x0000), de_u32(0x00010001),
        de_u16(0x0001), de_seq(de_uuid16(0x1126)),
        de_u16(0x0004), de_seq(de_seq(de_uuid16(0x0100), de_u16(PSM_CTRL)),
                               de_seq(de_uuid16(0x0012))),
        de_u16(0x000D), de_seq(de_seq(de_seq(de_uuid16(0x0100), de_u16(PSM_DATA)),
                                      de_seq(de_uuid16(0x0014)))),
    )
    scan_rec = de_seq(
        de_u16(0x0000), de_u32(0x00010002),
        de_u16(0x0001), de_seq(de_uuid16(0x1127)),
        de_u16(0x0004), de_seq(de_seq(de_uuid16(0x0100), de_u16(PSM_SCAN))),
    )
    return [print_rec, scan_rec]


def local_records():
    return [de_seq(
        de_u16(0x0000), de_u32(0x00010003),
        de_u16(0x0001), de_seq(de_uuid16(0x1125)),
        de_u16(0x0004), de_seq(de_seq(de_uuid16(0x0100), de_u16(PSM_NOTIF)),
                               de_seq(de_uuid16(0x0016))),
    )]


# ---------------------------------------------------------------- HCRP

def creq(pdu, tid, params=b'', plen=None):
    if plen is None:
        plen = len(params)
    return struct.pack('>HHH', pdu, tid, plen) + params


def crsp(pdu, tid, status, params=b'', plen=None):
    if plen is None:
        plen = 2 + len(params)
    return struct.pack('>HHHH', pdu, tid, plen, status) + params


def setup(cap):
    cap.add(hci_conn_complete())
    l2cap_connect(cap, 0x0001, SDP, 1)
    sdp_exchange(cap, SDP, remote_records(), 1)
    l2cap_connect(cap, PSM_CTRL, CTRL, 2)
    l2cap_connect(cap, PSM_DATA, DATA, 3)


def main_capture():
    cap = Capture()
    setup(cap)                                                       # 1-9
    q = lambda payload: cap.add(on_chan(SENT, CTRL, payload))
    r = lambda payload: cap.add(on_chan(RECV, CTRL, payload))

    # 10-11 CR_DataChannelCreditGrant
    q(creq(0x0001, 1, struct.pack('>I', 10000)))
    r(crsp(0x0001, 1, 0x0001))
    # 12-13 CR_DataChannelCreditRequest
    q(creq(0x0002, 2))
    r(crsp(0x0002, 2, 0x0001, struct.pack('>I', 20000)))
    # 14-15 CR_DataChannelCreditReturn
    q(creq(0x0003, 3, struct.pack('>I', 300)))
    r(crsp(0x0003, 3, 0x0001, struct.pack('>I', 400)))
    # 16-17 CR_DataChannelCreditQuery
    q(creq(0x0004, 4, struct.pack('>I', 500)))
    r(crsp(0x0004, 4, 0x0002, struct.pack('>I', 600)))     # Credit Sync Error
    # 18-19 CR_GetLPTStatus
    q(creq(0x0005, 5))
    r(crsp(0x0005, 5, 0x0001, b'\x18'))                     # Select, Not Error
    # 20-21 CR_Get1284ID
    q(creq(0x0006, 6, struct.pack('>HH', 0, 64)))
    r(crsp(0x0006, 6, 0x0001, b'MFG:Example;MDL:Synthetic Printer;CMD:PCL;'))
    # 22-25 CR_SoftReset, CR_HardReset
    q(creq(0x0007, 7))
    r(crsp(0x0007, 7, 0x0001))
    q(creq(0x0008, 8))
    r(crsp(0x0008, 8, 0x0000))                              # Feature Unsupported
    # 26-29 CR_RegisterNotification: add, its response, remove, unknown value
    q(creq(0x0009, 9, struct.pack('>BII', 1, 0x11223344, 30000)))
    r(crsp(0x0009, 9, 0x0001, struct.pack('>II', 60000, 30000)))
    q(creq(0x0009, 10, struct.pack('>BII', 0, 0x11223344, 0)))
    q(creq(0x0009, 11, struct.pack('>BII', 7, 1, 2)))
    # 30-31 CR_NotificationConnectionAlive
    q(creq(0x000A, 12))
    r(crsp(0x000A, 12, 0xFFFF, struct.pack('>I', 45000)))  # Generic Failure
    # 32-33 vendor specific PDU with data, and its response
    q(creq(0x8001, 13, b'\xde\xad\xbe\xef'))
    r(crsp(0x8001, 13, 0x0001, b'\x01\x02'))
    # 34-35 reserved PDU IDs 0x000B and 0x0000
    q(creq(0x000B, 14))
    r(crsp(0x0000, 15, 0x0000))
    # 36-38 parameter length warnings: a response shorter than 2, a length
    # shorter than the payload, and longer than the payload
    r(crsp(0x0007, 16, 0x0001, plen=0))
    q(creq(0x0001, 17, struct.pack('>I', 1), plen=2))
    q(creq(0x0005, 18, plen=4))

    # 39-40 data channel, both directions
    cap.add(on_chan(SENT, DATA, b'\x1b%-12345X@PJL\r\n'))
    cap.add(on_chan(RECV, DATA, b'@PJL USTATUS DEVICE\r\n'))

    # 41-44 the remote device reads our notification record
    sdp_exchange(cap, SDP, local_records(), 2, incoming=True)
    l2cap_connect_in(cap, PSM_NOTIF, NOTIF, 4)
    # 45-47 N_Notification, a vendor specific and a reserved notification
    cap.add(on_chan(RECV, NOTIF, struct.pack('>HI', 0x0001, 0x11223344)))
    cap.add(on_chan(RECV, NOTIF, struct.pack('>H', 0x8002) + b'\x55\x66'))
    cap.add(on_chan(RECV, NOTIF, struct.pack('>H', 0x0002)))
    # 48 a notification in the wrong direction (unexpected data)
    cap.add(on_chan(SENT, NOTIF, struct.pack('>HI', 0x0001, 1)))

    # 49-51 HCR_Scan channel: HCRP without a known HCRP protocol
    l2cap_connect(cap, PSM_SCAN, SCAN, 5)
    cap.add(on_chan(SENT, SCAN, b'\x00\x01\x02\x03'))
    return cap.frames


def malformed_capture():
    cap = Capture()
    setup(cap)
    q = lambda payload: cap.add(on_chan(SENT, CTRL, payload))
    r = lambda payload: cap.add(on_chan(RECV, CTRL, payload))
    q(creq(0x0001, 1, plen=4))                       # 10: credit missing
    r(crsp(0x0002, 2, 0x0001, plen=6))               # 11
    q(creq(0x0003, 3, b'\x00', plen=4))              # 12
    r(crsp(0x0004, 4, 0x0001, plen=6))               # 13
    r(crsp(0x0005, 5, 0x0001, plen=3))               # 14: LPT status missing
    q(creq(0x0006, 6, b'\x00\x00', plen=4))          # 15: number of bytes missing
    q(creq(0x0009, 7, b'\x01\x00', plen=9))          # 16
    r(crsp(0x0009, 8, 0x0001, b'\x00\x00\x00\x01', plen=10))   # 17
    r(crsp(0x000A, 9, 0x0001, plen=6))               # 18
    r(struct.pack('>HHH', 0x0001, 10, 2))            # 19: response without status
    q(b'\x00\x01')                                   # 20: header truncated
    cap.add(on_chan(RECV, DATA, b''))                # 21: empty data PDU
    sdp_exchange(cap, SDP, local_records(), 2, incoming=True)
    l2cap_connect_in(cap, PSM_NOTIF, NOTIF, 4)
    cap.add(on_chan(RECV, NOTIF, struct.pack('>H', 0x0001)))   # 26: no context ID
    cap.add(on_chan(RECV, NOTIF, b'\x00'))                     # 27
    return cap.frames


def exported_capture():
    cap = Capture()
    cap.add(exp_pdu('bthcrp', creq(0x0005, 1)))
    cap.add(exp_pdu('bthcrp', b''))
    return cap.frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bthcrp-coverage.pcap'), 201, main_capture())
    write_pcap(os.path.join(out, 'bthcrp-coverage-malformed.pcap'), 201, malformed_capture())
    write_pcap(os.path.join(out, 'bthcrp-coverage-exported.pcap'), 252, exported_capture())


if __name__ == '__main__':
    main()
