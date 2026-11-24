#!/usr/bin/env python3
# Generates test/captures/btavctp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic captures for packet-btavctp.c coverage.
# Usage: mkbtavctp.py <outdir>
# Writes btavctp-coverage.pcap (main, Bluetooth HCI H4 with direction) and
# btavctp-coverage-malformed.pcap (Exported PDUs: AVCTP without L2CAP, and
# truncated headers). Every packet is built here with struct; nothing is
# captured from a real network.
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
SENT, RECV = 0, 1

PID_AVRCP = 0x110E
PID_AVRCP_TARGET = 0x110C
PID_UNKNOWN = 0x1234


def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, data in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, (i % 10) * 100000, len(data), len(data)))
            f.write(data)


def h4(direction, ptype, body):
    return struct.pack('>I', direction) + bytes([ptype]) + body


def acl(direction, handle, cid, payload):
    l2 = struct.pack('<HH', len(payload), cid) + payload
    return h4(direction, 2, struct.pack('<HH', (handle & 0x0fff) | 0x2000, len(l2)) + l2)


def conn_complete(handle, bdaddr):
    ev = struct.pack('<BH', 0, handle) + bdaddr[::-1] + b'\x01\x00'
    return h4(RECV, 4, bytes([0x03, len(ev)]) + ev)


def l2_connect(handle, psm, scid, dcid, ident):
    req = struct.pack('<BBHHH', 0x02, ident, 4, psm, scid)
    rsp = struct.pack('<BBHHHHH', 0x03, ident, 8, dcid, scid, 0, 0)
    return [acl(SENT, handle, 1, req), acl(RECV, handle, 1, rsp)]


# AVCTP headers
def single(trans, cr, pid, data, ipid=0):
    return bytes([trans << 4 | 0 << 2 | cr << 1 | ipid]) + struct.pack('>H', pid) + data


def start(trans, cr, nop, pid, data, ipid=0):
    return bytes([trans << 4 | 1 << 2 | cr << 1 | ipid, nop]) + struct.pack('>H', pid) + data


def cont(trans, cr, data):
    return bytes([trans << 4 | 2 << 2 | cr << 1]) + data


def end(trans, cr, data):
    return bytes([trans << 4 | 3 << 2 | cr << 1]) + data


# AVRCP payloads
UNIT_INFO_CMD = bytes([0x01, 0xff, 0x30, 0xff, 0xff, 0xff, 0xff, 0xff])
UNIT_INFO_RSP = bytes([0x0c, 0xff, 0x30, 0x07, 0x48, 0x00, 0x19, 0x58])
SUBUNIT_INFO_RSP = bytes([0x0c, 0xff, 0x31, 0x07, 0x48, 0xff, 0xff, 0xff])
PASS_THROUGH_PLAY_RSP = bytes([0x09, 0x48, 0x7c, 0x44, 0x00])


def vendor_dep(ctype, pdu_id, params):
    return bytes([ctype, 0x48, 0x00]) + b'\x00\x19\x58' + bytes([pdu_id, 0]) + \
        struct.pack('>H', len(params)) + params


# GetCapabilities response: 13 supported events
GET_CAPS_RSP = vendor_dep(0x0c, 0x10, bytes([0x03, 13]) + bytes(range(1, 14)))
GET_COMPANY_RSP = vendor_dep(0x0c, 0x10, bytes([0x02, 4]) + b'\x00\x19\x58' + b'\x00\x00\x4c'
                             + b'\x00\x00\x0a' + b'\x00\x01\x2d')
# Browsing: SetBrowsedPlayer command and GetFolderItems command
SET_BROWSED_PLAYER = bytes([0x70]) + struct.pack('>HH', 2, 1)
GET_FOLDER_ITEMS = bytes([0x71]) + struct.pack('>H', 10) + bytes([0]) + struct.pack('>II', 0, 9) + bytes([0])


def build_main(path):
    frames = []
    F = {}

    def add(pkt, name=None):
        frames.append(pkt)
        if name:
            F[name] = len(frames)

    H, H2 = 0x001, 0x002
    CTRL = (0x40, 0x50)     # (local, remote) CIDs on handle 1
    BRWS = (0x41, 0x51)
    CTRL2 = (0x40, 0x50)    # same CIDs on handle 2

    def tx(handle, cids, pkt, name=None):
        add(acl(SENT, handle, cids[1], pkt), name)

    def rx(handle, cids, pkt, name=None):
        add(acl(RECV, handle, cids[0], pkt), name)

    add(conn_complete(H, bytes.fromhex('001bdc000201')))
    for p in l2_connect(H, 0x0017, CTRL[0], CTRL[1], 1):
        add(p)
    # Single packets: AVRCP responses (an AVRCP command answered later in
    # the file gets AVRCP's "No response" warning in the first pass only,
    # so the AVRCP commands here are browsing commands)
    rx(H, CTRL, single(0, 1, PID_AVRCP, UNIT_INFO_RSP), 'unit_info_rsp')
    rx(H, CTRL, single(1, 1, PID_AVRCP_TARGET, SUBUNIT_INFO_RSP), 'target_pid')
    rx(H, CTRL, single(2, 1, PID_AVRCP, PASS_THROUGH_PLAY_RSP))
    # Unknown profile identifier: data
    tx(H, CTRL, single(3, 0, PID_UNKNOWN, b'\x01\x02\x03'), 'unknown_pid')
    # IPID set (invalid profile) in a response without and with data
    rx(H, CTRL, single(3, 1, PID_UNKNOWN, b'', ipid=1), 'ipid_empty')
    rx(H, CTRL, single(4, 1, PID_AVRCP, UNIT_INFO_RSP, ipid=1), 'ipid_data')

    # Fragmented AVRCP GetCapabilities response: START (3 packets),
    # CONTINUE, END reassembled in the END frame
    rsp = GET_CAPS_RSP
    rx(H, CTRL, start(5, 1, 3, PID_AVRCP, rsp[:8]), 'frag_start')
    rx(H, CTRL, cont(5, 1, rsp[8:16]), 'frag_cont')
    rx(H, CTRL, end(5, 1, rsp[16:]), 'frag_end')

    # Second connection: fragments interleaved with those of handle 1
    add(conn_complete(H2, bytes.fromhex('001bdc000202')))
    for p in l2_connect(H2, 0x0017, CTRL2[0], CTRL2[1], 1):
        add(p)
    rsp2 = GET_COMPANY_RSP
    rx(H2, CTRL2, start(6, 1, 2, PID_AVRCP, rsp2[:10]), 'h2_start')
    rx(H, CTRL, start(6, 1, 4, PID_UNKNOWN, b'\xa0\xa1'), 'unk_start')
    rx(H, CTRL, cont(6, 1, b'\xa2\xa3'))
    rx(H2, CTRL2, end(6, 1, rsp2[10:]), 'h2_end')
    rx(H, CTRL, cont(6, 1, b'\xa4\xa5'))
    rx(H, CTRL, end(6, 1, b'\xa6\xa7'), 'unk_end')

    # The reproducer from btavctp_frag_after_end.py: START
    # (2 packets) and END reassemble; the stray CONTINUE after the END is
    # not added to the message. Then START (3 packets) and an END after
    # only 2: "Unexpected frame" in the END frame, also with -2.
    PID = 0x1234
    tx(H, CTRL, start(1, 0, 2, PID, b'AAAA'), 'repro_start')
    tx(H, CTRL, end(1, 0, b'BBBB'), 'repro_end')
    tx(H, CTRL, cont(1, 0, b'CCCC'), 'repro_cont')
    tx(H, CTRL, start(1, 0, 3, PID, b'DDDD'), 'repro_start2')
    tx(H, CTRL, end(1, 0, b'EEEE'), 'repro_end2')
    tx(H, CTRL, cont(1, 0, b'FFFF'), 'repro_cont2')

    # END and CONTINUE on a channel with no message started: unexpected
    for p in l2_connect(H, 0x001b, BRWS[0], BRWS[1], 2):
        add(p)
    tx(H, BRWS, cont(7, 0, b'\x11\x22'), 'orphan_cont')
    tx(H, BRWS, end(7, 0, b'\x33\x44'), 'orphan_end')
    # Browsing channel (PSM 0x1B): single AVRCP browsing commands
    tx(H, BRWS, single(8, 0, PID_AVRCP, SET_BROWSED_PLAYER), 'browse')
    tx(H, BRWS, single(9, 0, PID_AVRCP, GET_FOLDER_ITEMS))
    # A fragmented browsing command (AVRCP over START/END)
    tx(H, BRWS, start(10, 0, 2, PID_AVRCP, GET_FOLDER_ITEMS[:6]), 'browse_start')
    tx(H, BRWS, end(10, 0, GET_FOLDER_ITEMS[6:]), 'browse_end')

    write_pcap(path, 201, frames)
    return F


def exp_pdu(name, payload, p2p=None):
    tlv = struct.pack('>HH', 12, len(name)) + name.encode()
    if p2p is not None:
        tlv += struct.pack('>HHi', 35, 4, p2p)
    return tlv + struct.pack('>HH', 0, 0) + payload


def build_malformed(path):
    frames = [
        # AVCTP without L2CAP: default interface, no channel
        exp_pdu('btavctp', single(0, 0, PID_AVRCP, UNIT_INFO_CMD), SENT),
        exp_pdu('btavctp', single(0, 1, PID_AVRCP, UNIT_INFO_RSP), RECV),
        exp_pdu('btavctp', single(0, 0, PID_UNKNOWN, b'\x01')),
        exp_pdu('btavctp', start(1, 0, 2, PID_AVRCP, GET_CAPS_RSP[:8]), RECV),
        exp_pdu('btavctp', end(1, 0, GET_CAPS_RSP[8:]), RECV),
        exp_pdu('btavctp', cont(1, 0, b'\x00'), RECV),
        exp_pdu('btavctp', bytes([0x30, 0x01]), RECV),      # START with 0 packets... cut
        # Truncated headers
        exp_pdu('btavctp', b'', SENT),
        exp_pdu('btavctp', b'\x00\x11', SENT),
        exp_pdu('btavctp', b'\x04\x02\x11', SENT),
    ]
    write_pcap(path, 252, frames)


if __name__ == '__main__':
    F = build_main(f'{OUT}/btavctp-coverage.pcap')
    build_malformed(f'{OUT}/btavctp-coverage-malformed.pcap')
    for k, n in F.items():
        print(k, n)
