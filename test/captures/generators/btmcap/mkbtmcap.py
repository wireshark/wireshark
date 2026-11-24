#!/usr/bin/env python3
# Generates test/captures/btmcap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth MCAP dissector
(packet-btmcap.c).

MCAP has no fixed L2CAP PSM: L2CAP finds it from SDP. The captures are
Bluetooth HCI H4 with pseudo-header (link type 201): an HCI Connection
Complete event, an L2CAP connection to SDP and an SDP Service Search
Attribute exchange in which the remote device announces an HDP Source
record (0x1401) with the MCAP control channel on PSM 0x1001 (and the MCAP
data channel on PSM 0x1003 in its additional protocol descriptor list),
then an L2CAP connection to PSM 0x1001 and MCAP control messages. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkbtmcap.py <output directory>

Writes:
  btmcap-coverage.pcap            the main capture (frame ranges in README)
  btmcap-coverage-malformed.pcap  truncated messages
  btmcap-coverage-exported.pcap   MCAP in Exported PDU frames (no L2CAP
                                  below, UnknownDirection), coverage only
"""

import os
import struct
import sys

SENT, RECV = 0, 1
HANDLE = 0x0001
BD_ADDR = bytes.fromhex('665544332211')      # little endian 11:22:33:44:55:66

SDP = (0x0040, 0x0041)       # PSM 0x0001 (local CID, remote CID)
MCL = (0x0042, 0x0043)       # PSM 0x1001 MCAP control channel
PSM_CTRL, PSM_DATA = 0x1001, 0x1003

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
    return [de_seq(
        de_u16(0x0000), de_u32(0x00010001),
        de_u16(0x0001), de_seq(de_uuid16(0x1401)),
        de_u16(0x0004), de_seq(de_seq(de_uuid16(0x0100), de_u16(PSM_CTRL)),
                               de_seq(de_uuid16(0x001E), de_u16(0x0100))),
        de_u16(0x000D), de_seq(de_seq(de_seq(de_uuid16(0x0100), de_u16(PSM_DATA)),
                                      de_seq(de_uuid16(0x001F)))),
    )]


# ---------------------------------------------------------------- MCAP

def std_req(op, mdl, extra=b''):
    return struct.pack('>BH', op, mdl) + extra


def std_rsp(op, rc, mdl, params=b''):
    return struct.pack('>BBH', op, rc, mdl) + params


def setup(cap):
    cap.add(hci_conn_complete())
    l2cap_connect(cap, 0x0001, SDP, 1)
    sdp_exchange(cap, SDP, remote_records(), 1)
    l2cap_connect(cap, PSM_CTRL, MCL, 2)


def main_capture():
    cap = Capture()
    setup(cap)                                                       # 1-7
    q = lambda payload: cap.add(on_chan(SENT, MCL, payload))
    r = lambda payload: cap.add(on_chan(RECV, MCL, payload))

    # 8-9 MD_CREATE_MDL_REQ (MDEP 0x01, configuration 0x01) and the
    # response with its configuration as response parameter
    q(std_req(0x01, 0x0001, b'\x01\x01'))
    r(std_rsp(0x02, 0x00, 0x0001, b'\x01'))
    # 10-11 a reserved MDEP ID, answered Invalid MDEP
    q(std_req(0x01, 0x0002, b'\x80\x00'))
    r(std_rsp(0x02, 0x03, 0x0002))
    # 12-13 MD_RECONNECT_MDL
    q(std_req(0x03, 0x0001))
    r(std_rsp(0x04, 0x00, 0x0001))
    # 14-15 MD_ABORT_MDL
    q(std_req(0x05, 0x0002))
    r(std_rsp(0x06, 0x00, 0x0002))
    # 16-17 MD_DELETE_MDL of all MDLs (0xFFFF is valid here)
    q(std_req(0x07, 0xFFFF))
    r(std_rsp(0x08, 0x00, 0xFFFF))
    # 18-19 MDL IDs 0x0000 (reserved) and 0xFF00 (outside the ranges)
    q(std_req(0x03, 0x0000))
    r(std_rsp(0x04, 0x05, 0xFF00))                          # Invalid MDL
    # 20-21 ERROR_RSP (Invalid Op Code) and an unknown response code
    r(std_rsp(0x00, 0x01, 0x0000))
    r(std_rsp(0x02, 0x0C, 0x0003))
    # 22-28 Clock Sync: capabilities, set (instant and timed), indication
    q(struct.pack('>BH', 0x11, 20))
    r(struct.pack('>BBBHHH', 0x12, 0x00, 0x02, 1000, 1, 10))
    q(struct.pack('>BBIQ', 0x13, 0x01, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF))
    r(struct.pack('>BBIQH', 0x14, 0x00, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 5))
    q(struct.pack('>BBIQ', 0x13, 0x00, 0x00012345, 1000000))
    r(struct.pack('>BBIQH', 0x14, 0x00, 0x00012345, 1000000, 5))
    r(struct.pack('>BIQH', 0x15, 0x00012400, 1500000, 6))
    # 29-33 unknown op codes: standard request 0x09 and 0x21, clock sync
    # request 0x17, standard response 0x0A, the pseudoresponse 0x16
    q(b'\x09')
    q(b'\x21')
    q(b'\x17')
    r(std_rsp(0x0A, 0x01, 0x0004))
    r(b'\x16\x00')
    # 34-38 expert infos (warnings): MD_CREATE_MDL_REQ for MDL 0xFFFF, a
    # failed response with response parameters, and the reproducer of the
    # response parameters fix: MD_ABORT_MDL_RSP, MD_RECONNECT_MDL_RSP and
    # MD_DELETE_MDL_RSP with parameters, each named in the expert info,
    # then shown as unexpected data
    q(std_req(0x01, 0xFFFF, b'\x01\x00'))
    r(std_rsp(0x02, 0x0B, 0x0005, b'\x02'))                 # Configuration Rejected
    r(std_rsp(0x06, 0x00, 0x0002, b'\xAA\xBB'))
    r(std_rsp(0x04, 0x00, 0x0001, b'\xCC'))
    r(std_rsp(0x08, 0x00, 0x0006, b'\xDD'))
    # 39 a request with trailing data
    q(std_req(0x05, 0x0007, b'\xEE\xFF'))
    return cap.frames


def malformed_capture():
    cap = Capture()
    setup(cap)
    q = lambda payload: cap.add(on_chan(SENT, MCL, payload))
    r = lambda payload: cap.add(on_chan(RECV, MCL, payload))
    q(b'\x01\x00')                          # 8: MDL ID truncated
    q(b'\x01\x00\x01')                      # 9: MDEP ID missing
    q(b'\x01\x00\x01\x01')                  # 10: configuration missing
    q(b'\x11\x00')                          # 11
    q(b'\x13\x00\xff\xff')                  # 12
    q(b'\x13\x00\xff\xff\xff\xff\x00')      # 13
    q(b'\x15\x00\x00\x00\x01')              # 14
    r(b'\x02')                              # 15: response code missing
    r(b'\x02\x00\x00')                      # 16
    r(b'\x12\x00\x02\x00')                  # 17
    r(b'\x14\x00\x00\x00\x00\x01\x00')      # 18
    cap.add(on_chan(SENT, MCL, b''))        # 19: empty
    return cap.frames


def exported_capture():
    cap = Capture()
    cap.add(exp_pdu('btmcap', std_req(0x03, 0x0001)))
    cap.add(exp_pdu('btmcap', std_rsp(0x04, 0x00, 0x0001)))
    return cap.frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'btmcap-coverage.pcap'), 201, main_capture())
    write_pcap(os.path.join(out, 'btmcap-coverage-malformed.pcap'), 201, malformed_capture())
    write_pcap(os.path.join(out, 'btmcap-coverage-exported.pcap'), 252, exported_capture())


if __name__ == '__main__':
    main()
