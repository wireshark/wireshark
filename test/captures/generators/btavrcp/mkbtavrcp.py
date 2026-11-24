#!/usr/bin/env python3
# Generates test/captures/btavrcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth AVRCP dissector
(packet-btavrcp.c).

AVRCP runs over AVCTP (PID 0x110E) on L2CAP PSM 0x17 (control) and PSM 0x1B
(browsing). The captures are Bluetooth HCI H4 with pseudo-header (link type
201): an HCI Connection Complete event, L2CAP connections, then AVCTP/AVRCP.
An SDP Service Search Attribute exchange announces an AVRCP target record
whose additional protocol descriptor list has a dynamic L2CAP PSM (cover
art, handed to OBEX) and an AVRCP controller record on another dynamic PSM
(AVRCP directly on L2CAP, without AVCTP). Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkbtavrcp.py <output directory>

Writes:
  btavrcp-coverage.pcap            the main capture (frame ranges in README)
  btavrcp-coverage-malformed.pcap  truncated and inconsistent PDUs
  btavrcp-coverage-exported.pcap   AVRCP in Exported PDU frames (no AVCTP or
                                   L2CAP below), for the coverage run only
"""

import os
import struct
import sys

SENT, RECV = 0, 1
HANDLE = 0x0001
BD_ADDR = bytes.fromhex('665544332211')      # little endian 11:22:33:44:55:66

# L2CAP channel ids: (local CID = SCID of our request, remote CID)
CTL = (0x0040, 0x0041)       # PSM 0x0017 AVCTP control
BRW = (0x0042, 0x0043)       # PSM 0x001B AVCTP browsing
SDP = (0x0044, 0x0045)       # PSM 0x0001 SDP
COVER = (0x0046, 0x0047)     # PSM 0x1005 AVRCP cover art (OBEX)
DIRECT = (0x0048, 0x0049)    # PSM 0x1007 AVRCP controller record, no AVCTP

PSM_COVER = 0x1005
PSM_DIRECT = 0x1007
LOCAL = (0x004A, 0x0070)     # PSM 0x1009 our AVRCP record, remote connects
PSM_LOCAL = 0x1009

BT_SIG = 0x001958
OTHER_COMPANY = 0x112233

# ctype
CONTROL, STATUS, SPEC_INQ, NOTIFY, GEN_INQ = 0, 1, 2, 3, 4
NOT_IMPL, ACCEPTED, REJECTED, IN_TRANSITION, STABLE, CHANGED, INTERIM = 8, 9, 10, 11, 12, 13, 15

PANEL = 0x48     # subunit type panel (9), id 0


# ---------------------------------------------------------------- writers

def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for usec, data, caplen in frames:
            if caplen is None:
                caplen = len(data)
            f.write(struct.pack('<IIII', usec // 1000000, usec % 1000000,
                                caplen, len(data)))
            f.write(data[:caplen])


class Capture:
    """Frames with timestamps. Each frame is 10 ms after the previous one
    unless a gap is given."""

    def __init__(self, start=1700000000 * 1000000):
        self.t = start
        self.frames = []

    def add(self, data, gap=10000, caplen=None):
        self.t += gap
        self.frames.append((self.t, data, caplen))
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
    scid, dcid = chan
    return acl(direction, dcid if direction == SENT else scid, payload)


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


def sdp_records():
    tg = de_seq(
        de_u16(0x0000), de_u32(0x00010001),
        de_u16(0x0001), de_seq(de_uuid16(0x110C)),
        de_u16(0x0004), de_seq(de_seq(de_uuid16(0x0100), de_u16(0x0017)),
                               de_seq(de_uuid16(0x0017), de_u16(0x0104))),
        de_u16(0x000D), de_seq(de_seq(de_seq(de_uuid16(0x0100), de_u16(PSM_COVER)),
                                      de_seq(de_uuid16(0x0008)))),
    )
    ct = de_seq(
        de_u16(0x0000), de_u32(0x00010002),
        de_u16(0x0001), de_seq(de_uuid16(0x110F)),
        de_u16(0x0004), de_seq(de_seq(de_uuid16(0x0100), de_u16(PSM_DIRECT))),
    )
    return de_seq(tg, ct)


def sdp_exchange(cap):
    req_params = (de_seq(de_uuid16(0x110E)) + struct.pack('>H', 0x0200) +
                  de_seq(de_u32(0x0000FFFF)) + b'\x00')
    req = struct.pack('>BHH', 0x06, 1, len(req_params)) + req_params
    lists = sdp_records()
    rsp_params = struct.pack('>H', len(lists)) + lists + b'\x00'
    rsp = struct.pack('>BHH', 0x07, 1, len(rsp_params)) + rsp_params
    cap.add(on_chan(SENT, SDP, req))
    cap.add(on_chan(RECV, SDP, rsp))


def sdp_exchange_in(cap):
    """The remote device asks for our AVRCP record (dynamic PSM)."""
    req_params = (de_seq(de_uuid16(0x110E)) + struct.pack('>H', 0x0200) +
                  de_seq(de_u32(0x0000FFFF)) + b'\x00')
    req = struct.pack('>BHH', 0x06, 2, len(req_params)) + req_params
    lists = de_seq(de_seq(
        de_u16(0x0000), de_u32(0x00010003),
        de_u16(0x0001), de_seq(de_uuid16(0x110E)),
        de_u16(0x0004), de_seq(de_seq(de_uuid16(0x0100), de_u16(PSM_LOCAL))),
    ))
    rsp_params = struct.pack('>H', len(lists)) + lists + b'\x00'
    rsp = struct.pack('>BHH', 0x07, 2, len(rsp_params)) + rsp_params
    cap.add(on_chan(RECV, SDP, req))
    cap.add(on_chan(SENT, SDP, rsp))


# ---------------------------------------------------------------- AVCTP/AVRCP

def avctp(trans, cr, payload, ptype=0, npackets=None, pid=0x110E, ipid=0):
    hdr = bytes([(trans << 4) | (ptype << 2) | (cr << 1) | ipid])
    if ptype == 1:
        hdr += bytes([npackets])
    if ptype in (0, 1):
        hdr += struct.pack('>H', pid)
    return hdr + payload


def avrcp(ctype, opcode, operands, subunit=PANEL):
    return bytes([ctype, subunit, opcode]) + operands


def vd(ctype, pdu, params=b'', ptype=0, plen=None, company=BT_SIG):
    if plen is None:
        plen = len(params)
    return avrcp(ctype, 0x00, struct.pack('>I', company)[1:] +
                 bytes([pdu, ptype]) + struct.pack('>H', plen) + params)


def passthrough(ctype, op, data=b''):
    return avrcp(ctype, 0x7C, bytes([op, len(data)]) + data)


class Avrcp:
    """AVRCP on the control or browsing channel. Commands are sent by us
    (C/R 0), responses received (C/R 1), unless swapped."""

    def __init__(self, cap, chan):
        self.cap = cap
        self.chan = chan
        self.trans = 0

    def cmd(self, payload, gap=10000, direction=SENT, caplen=None):
        self.trans = (self.trans + 1) & 0x0f
        return self.cap.add(on_chan(direction, self.chan, avctp(self.trans, 0, payload)),
                            gap, caplen)

    def rsp(self, payload, gap=10000, direction=RECV, caplen=None):
        return self.cap.add(on_chan(direction, self.chan, avctp(self.trans, 1, payload)),
                            gap, caplen)

    def raw(self, direction, avctp_payload, gap=10000):
        return self.cap.add(on_chan(direction, self.chan, avctp_payload), gap)


def attr_entry(aid, value, charset=0x006a):
    return struct.pack('>IHH', aid, charset, len(value)) + value


def u64(v):
    return struct.pack('>Q', v)


# browsing
def brw(pdu, params):
    return bytes([pdu]) + struct.pack('>H', len(params)) + params


def item_player(player_id, name, features, major=0x01, subtype=0, status=1):
    body = (struct.pack('>HBIB', player_id, major, subtype, status) + features +
            struct.pack('>HH', 0x006a, len(name)) + name)
    return bytes([0x01]) + struct.pack('>H', len(body)) + body


def item_folder(uid, name, ftype=1, playable=1):
    body = u64(uid) + bytes([ftype, playable]) + struct.pack('>HH', 0x006a, len(name)) + name
    return bytes([0x02]) + struct.pack('>H', len(body)) + body


def item_element(uid, name, attrs, mtype=0, length_adjust=0):
    body = (u64(uid) + bytes([mtype]) + struct.pack('>HH', 0x006a, len(name)) + name +
            bytes([len(attrs)]) + b''.join(attrs))
    return bytes([0x03]) + struct.pack('>H', len(body) + length_adjust) + body


# ---------------------------------------------------------------- main capture

def setup(cap):
    cap.add(hci_conn_complete())
    l2cap_connect(cap, 0x0001, SDP, 1)
    sdp_exchange(cap)
    l2cap_connect(cap, 0x0017, CTL, 2)
    l2cap_connect(cap, 0x001B, BRW, 3)


def main_capture():
    cap = Capture()
    marks = {}
    setup(cap)                                         # frames 1-11
    c = Avrcp(cap, CTL)

    # Unit and subunit info
    marks['unit'] = c.cmd(avrcp(STATUS, 0x30, b'\xff' * 5, subunit=0xff))
    c.rsp(avrcp(STABLE, 0x30, b'\x07' + bytes([PANEL]) + b'\x00\x19\x58', subunit=0xff))
    c.cmd(avrcp(STATUS, 0x31, b'\x07' + b'\xff' * 4, subunit=0xff))
    c.rsp(avrcp(STABLE, 0x31, b'\x07' + bytes([PANEL]) + b'\xff' * 3, subunit=0xff))

    # Pass-through: pressed/released, vendor unique, an unknown operation,
    # and a general inquiry
    marks['passthrough'] = c.cmd(passthrough(CONTROL, 0x44))
    c.rsp(passthrough(ACCEPTED, 0x44))
    c.cmd(passthrough(CONTROL, 0xC4))
    c.rsp(passthrough(ACCEPTED, 0xC4))
    c.cmd(passthrough(CONTROL, 0x7E))
    c.rsp(passthrough(ACCEPTED, 0x7E, b'\x00\x19\x58\x00\x00'))
    c.cmd(passthrough(CONTROL, 0x10))
    c.rsp(passthrough(NOT_IMPL, 0x10))
    c.cmd(passthrough(GEN_INQ, 0x41))
    c.rsp(passthrough(STABLE, 0x41))

    # Vendor dependent with another company: with and without a PDU ID
    marks['other_company'] = c.cmd(vd(STATUS, 0x01, company=OTHER_COMPANY))
    c.rsp(vd(STABLE, 0x01, company=OTHER_COMPANY))
    c.cmd(avrcp(STATUS, 0x00, struct.pack('>I', OTHER_COMPANY)[1:]))
    c.rsp(avrcp(NOT_IMPL, 0x00, struct.pack('>I', OTHER_COMPANY)[1:]))

    # GetCapabilities: company IDs, events, and an unknown capability
    marks['capabilities'] = c.cmd(vd(STATUS, 0x10, b'\x02'))
    c.rsp(vd(STABLE, 0x10, b'\x02\x02' + b'\x00\x19\x58' + struct.pack('>I', OTHER_COMPANY)[1:]))
    c.cmd(vd(STATUS, 0x10, b'\x03'))
    c.rsp(vd(STABLE, 0x10, b'\x03\x0d' + bytes(range(1, 14))))
    c.cmd(vd(STATUS, 0x10, b'\x01'))
    c.rsp(vd(STABLE, 0x10, b'\x01\x01'))

    # Player application settings
    marks['settings'] = c.cmd(vd(STATUS, 0x11))
    c.rsp(vd(STABLE, 0x11, b'\x04\x01\x02\x03\x04'))
    c.cmd(vd(STATUS, 0x12, b'\x01'))
    c.rsp(vd(STABLE, 0x12, b'\x02\x01\x02'))
    c.cmd(vd(STATUS, 0x13, b'\x02\x01\x02'))
    c.rsp(vd(STABLE, 0x13, b'\x02\x01\x02\x02\x03'))
    c.cmd(vd(CONTROL, 0x14, b'\x01\x02\x02'))
    c.rsp(vd(ACCEPTED, 0x14))
    marks['attr_text'] = c.cmd(vd(STATUS, 0x15, b'\x02\x01\x02'))
    c.rsp(vd(STABLE, 0x15, b'\x02' +
             b'\x01' + struct.pack('>H', 0x006a) + b'\x09Equalizer' +
             b'\x02' + struct.pack('>H', 0x006a) + b'\x06Repeat'))
    marks['value_text'] = c.cmd(vd(STATUS, 0x16, b'\x01\x02\x01\x02'))
    c.rsp(vd(STABLE, 0x16, b'\x02' +
             b'\x01' + struct.pack('>H', 0x006a) + b'\x03Off' +
             b'\x02' + struct.pack('>H', 0x006a) + b'\x02On'))
    c.cmd(vd(CONTROL, 0x17, b'\x02' + struct.pack('>HH', 0x006a, 0x0003)))
    c.rsp(vd(ACCEPTED, 0x17))
    c.cmd(vd(CONTROL, 0x18, b'\x01'))
    c.rsp(vd(ACCEPTED, 0x18))

    # GetElementAttributes of the playing track and of another one
    marks['element'] = c.cmd(vd(STATUS, 0x20, u64(0) + b'\x02' + struct.pack('>II', 1, 2)))
    c.rsp(vd(STABLE, 0x20, b'\x02' + attr_entry(1, b'Synthetic Song') +
             attr_entry(2, b'Test Band')))
    c.cmd(vd(STATUS, 0x20, u64(0x0102030405060708) + b'\x00'))
    c.rsp(vd(STABLE, 0x20, b'\x01' + attr_entry(7, b'180000')))

    # GetPlayStatus answered after 3.5 s (response time fix), and one that
    # crosses a second boundary (nanoseconds borrow branch)
    cap.t = (cap.t // 1000000 + 1) * 1000000 - 10000
    marks['play_status_cmd'] = c.cmd(vd(STATUS, 0x30))
    marks['play_status_rsp'] = c.rsp(vd(STABLE, 0x30, struct.pack('>IIB', 1000, 10, 1)), gap=3500000)
    cap.t = (cap.t // 1000000 + 1) * 1000000 - 10000
    marks['play_status_cmd2'] = c.cmd(vd(STATUS, 0x30), gap=800000)
    marks['play_status_rsp2'] = c.rsp(vd(STABLE, 0x30, struct.pack('>IIB', 240000, 5000, 2)), gap=500000)

    # RegisterNotification for every event: command, interim, changed
    events = [
        (0x01, b'\x00', b'\x01'),
        (0x02, u64(0), u64(0xFFFFFFFFFFFFFFFF)),
        (0x02, u64(0x0000000000000042), u64(0)),
        (0x03, b'', b''),
        (0x04, b'', b''),
        (0x05, struct.pack('>I', 0xFFFFFFFF), struct.pack('>I', 12345)),
        (0x06, b'\x00', b'\x02'),
        (0x07, b'\x00', b'\x01'),
        (0x08, b'\x01\x02\x02', b'\x02\x01\x01\x03\x02'),
        (0x09, b'', b''),
        (0x0A, b'', b''),
        (0x0B, struct.pack('>HH', 1, 0x1234), struct.pack('>HH', 2, 0x1235)),
        (0x0C, struct.pack('>H', 0x1234), struct.pack('>H', 0x1236)),
        (0x0D, b'\x40', b'\x7f'),
        (0x0E, b'\xaa\xbb', b'\xcc'),
    ]
    marks['notifications'] = cap_len = len(cap.frames) + 1
    for ev, interim, changed in events:
        c.cmd(vd(NOTIFY, 0x31, bytes([ev]) + struct.pack('>I', 5)))
        c.rsp(vd(INTERIM, 0x31, bytes([ev]) + interim))
        c.rsp(vd(CHANGED, 0x31, bytes([ev]) + changed))
    # A notification rejected as not implemented
    c.cmd(vd(NOTIFY, 0x31, b'\x0d' + struct.pack('>I', 0)))
    c.rsp(vd(NOT_IMPL, 0x31, b'\x0d'))
    marks['notifications_end'] = len(cap.frames)

    # Fragmented GetElementAttributes response: START, Request Continuing,
    # CONTINUE, Request Continuing, END (reassembled in the END frame)
    title = b'A synthetic title that is long enough to need three fragments ' * 6
    artist = b'Synthetic Artist'
    album = b'Synthetic Album'
    whole = (b'\x03' + attr_entry(1, title) + attr_entry(2, artist) + attr_entry(3, album))
    f1, f2, f3 = whole[:200], whole[200:400], whole[400:]
    marks['frag_cmd'] = c.cmd(vd(STATUS, 0x20, u64(0) + b'\x00'))
    marks['frag_start'] = c.rsp(vd(STABLE, 0x20, f1, ptype=1, plen=len(f1)))
    c.cmd(vd(CONTROL, 0x40, b'\x20'))
    marks['frag_continue'] = c.rsp(vd(STABLE, 0x20, f2, ptype=2))
    c.cmd(vd(CONTROL, 0x40, b'\x20'))
    marks['frag_end'] = c.rsp(vd(STABLE, 0x20, f3, ptype=3))
    marks['frag_len'] = len(whole)
    # Another END of the same PDU after the message was completed: before
    # the fix on the branch it reassembled the whole message again; now it
    # is a complete PDU of its own
    marks['late_end'] = c.rsp(vd(STABLE, 0x20, b'\x01' + attr_entry(2, b'Late Artist'), ptype=3))
    # A second fragmented response, aborted after the START
    c.cmd(vd(STATUS, 0x20, u64(0) + b'\x00'))
    marks['abort_start'] = c.rsp(vd(STABLE, 0x20, f1, ptype=1, plen=len(f1)))
    marks['abort'] = c.cmd(vd(CONTROL, 0x41, b'\x20'))
    c.rsp(vd(ACCEPTED, 0x41))
    # An END that belongs to no fragmented message (a complete PDU) and a
    # CONTINUE that was not requested
    marks['lone_end'] = c.rsp(vd(STABLE, 0x30, struct.pack('>IIB', 2000, 20, 0), ptype=3))
    marks['lone_continue'] = c.rsp(vd(STABLE, 0x15, b'\x00', ptype=2))

    # Volume, players and items
    marks['volume'] = c.cmd(vd(CONTROL, 0x50, b'\x40'), direction=RECV)
    c.rsp(vd(ACCEPTED, 0x50, b'\x40'), direction=SENT)
    c.cmd(vd(CONTROL, 0x60, struct.pack('>H', 1)))
    c.rsp(vd(ACCEPTED, 0x60, b'\x04'))
    c.cmd(vd(CONTROL, 0x74, b'\x01' + u64(0x11) + struct.pack('>H', 0x1234)))
    c.rsp(vd(ACCEPTED, 0x74, b'\x04'))
    c.cmd(vd(CONTROL, 0x90, b'\x03' + u64(0x22) + struct.pack('>H', 0x1234)))
    c.rsp(vd(ACCEPTED, 0x90, b'\x04'))
    # Rejected command
    marks['reject'] = c.cmd(vd(CONTROL, 0x60, struct.pack('>H', 9)))
    c.rsp(vd(REJECTED, 0x60, b'\x11'))
    # Unknown PDU ID without parameters
    c.cmd(vd(STATUS, 0x99))
    c.rsp(vd(NOT_IMPL, 0x99))

    # AVCTP fragmented AVRCP message (AVCTP START/END), reassembled by AVCTP
    c.trans = (c.trans + 1) & 0x0f
    msg = vd(STATUS, 0x20, u64(0) + b'\x03' + struct.pack('>III', 1, 2, 3))
    marks['avctp_frag'] = c.raw(SENT, avctp(c.trans, 0, msg[:10], ptype=1, npackets=2))
    c.raw(SENT, avctp(c.trans, 0, msg[10:], ptype=3))
    c.rsp(vd(STABLE, 0x20, b'\x01' + attr_entry(1, b'Synthetic Song')))

    # Browsing channel
    b = Avrcp(cap, BRW)
    marks['browsing'] = b.cmd(brw(0x70, struct.pack('>H', 1)))
    b.rsp(brw(0x70, b'\x04' + struct.pack('>HIHB', 0x1234, 42, 0x006a, 2) +
              struct.pack('>H', 5) + b'Music' + struct.pack('>H', 4) + b'Rock'))
    feat_all = b'\xff' * 9 + b'\x00' * 7
    feat_some = bytes([0x55, 0xaa, 0x0f, 0xf0, 0x33, 0xcc, 0x81, 0x7e, 0x1f]) + b'\x01' * 7
    marks['folder_items_players'] = b.cmd(brw(0x71, b'\x00' + struct.pack('>II', 0, 9) + b'\x00'))
    b.rsp(brw(0x71, b'\x04' + struct.pack('>HH', 0x1234, 2) +
              item_player(1, b'Player One', feat_all) +
              item_player(2, b'Player Two', feat_some, major=0x0c, subtype=1, status=0)))
    marks['folder_items_vfs'] = b.cmd(brw(0x71, b'\x01' + struct.pack('>II', 0, 9) + b'\x02' +
                                      struct.pack('>II', 1, 2)))
    b.rsp(brw(0x71, b'\x04' + struct.pack('>HH', 0x1234, 3) +
              item_folder(0x10, b'Albums', ftype=2, playable=0) +
              item_element(0x20, b'Track One', [attr_entry(1, b'Track One'), attr_entry(2, b'Artist')]) +
              b'\x07' + struct.pack('>H', 3) + b'xyz'))
    b.cmd(brw(0x72, struct.pack('>HB', 0x1234, 1) + u64(0x10)))
    b.rsp(brw(0x72, b'\x04' + struct.pack('>I', 7)))
    b.cmd(brw(0x73, b'\x01' + u64(0x20) + struct.pack('>HB', 0x1234, 1) + struct.pack('>I', 1)))
    b.rsp(brw(0x73, b'\x04\x01' + attr_entry(1, b'Track One')))
    b.cmd(brw(0x80, struct.pack('>HH', 0x006a, 4) + b'Rock'))
    b.rsp(brw(0x80, b'\x04' + struct.pack('>HI', 0x1234, 3)))
    # Error status, general reject, and an unknown browsing PDU
    marks['browsing_error'] = b.cmd(brw(0x72, struct.pack('>HB', 0x1234, 1) + u64(0x99)))
    b.rsp(brw(0x72, b'\x09'))
    b.cmd(brw(0x55, b''))
    b.rsp(brw(0xA0, b'\x00'))
    marks['general_reject_cmd'] = b.cmd(brw(0xA0, b''))

    # Cover art and AVRCP directly on L2CAP, PSMs announced by SDP
    l2cap_connect(cap, PSM_COVER, COVER, 4)
    target = bytes.fromhex('7163DD544A7E11E2B47C0050C2490048')
    obex_conn = (b'\x80' + struct.pack('>H', 7 + 3 + len(target)) + b'\x10\x00' +
                 struct.pack('>H', 0x0400) + b'\x46' + struct.pack('>H', 3 + len(target)) + target)
    marks['cover_art'] = cap.add(on_chan(SENT, COVER, obex_conn))
    obex_rsp = (b'\xa0' + struct.pack('>H', 7 + 5) + b'\x10\x00' + struct.pack('>H', 0x0400) +
                b'\xcb' + struct.pack('>I', 1))
    cap.add(on_chan(RECV, COVER, obex_rsp))
    l2cap_connect(cap, PSM_DIRECT, DIRECT, 5)
    marks['direct'] = cap.add(on_chan(SENT, DIRECT, passthrough(CONTROL, 0x46)))
    cap.add(on_chan(RECV, DIRECT, passthrough(ACCEPTED, 0x46)))

    # The remote device reads our SDP record and connects to its dynamic
    # PSM: AVRCP directly on L2CAP (without AVCTP the dissector takes the
    # direction, not a C/R bit, to tell commands from responses)
    sdp_exchange_in(cap)
    l2cap_connect_in(cap, PSM_LOCAL, LOCAL, 6)
    marks['local'] = cap.add(on_chan(SENT, LOCAL, passthrough(CONTROL, 0x4B)))
    cap.add(on_chan(RECV, LOCAL, passthrough(ACCEPTED, 0x4B)))

    # A command that is never answered
    marks['unanswered'] = c.cmd(passthrough(CONTROL, 0x45))
    return cap, marks


# ---------------------------------------------------------------- malformed

def malformed_capture():
    cap = Capture()
    setup(cap)
    c = Avrcp(cap, CTL)
    b = Avrcp(cap, BRW)
    # Unexpected trailing data (warning): vendor unique pass-through command
    # with its operands, unknown PDU with parameters
    c.cmd(passthrough(CONTROL, 0x7E, b'\x00\x19\x58\x00\x00'))
    c.cmd(vd(STATUS, 0x99, b'\x01'))
    # Media element item with a wrong item length (warning)
    b.rsp(brw(0x71, b'\x04' + struct.pack('>HH', 0x1234, 1) +
              item_element(0x20, b'T', [attr_entry(1, b'T')], length_adjust=1)))
    # END without Request Continuing: the END payload is parsed as a whole
    # PDU (btavrcp_reasm_two_pass.py)
    c.rsp(vd(STABLE, 0x20, b'\x01' + attr_entry(1, b'Hello'), ptype=1, plen=500))
    c.rsp(vd(STABLE, 0x20, b'XXXXXX', ptype=3))
    c.cmd(vd(CONTROL, 0x40, b'\x20'))
    c.rsp(vd(STABLE, 0x20, b' World', ptype=3))
    # START and CONTINUE cut short by the snapshot length
    c.rsp(vd(STABLE, 0x16, b'\x00' * 40, ptype=1), caplen=40)
    c.cmd(vd(CONTROL, 0x40, b'\x16'))
    c.rsp(vd(STABLE, 0x16, b'\x00' * 40, ptype=2), caplen=40)
    # Truncated PDUs: each throws
    for p in (vd(STABLE, 0x10, b'\x02\x05\x00'),
              vd(STABLE, 0x20, b'\x02' + attr_entry(1, b'abc')[:-1]),
              vd(STABLE, 0x15, b'\x01\x01\x00\x6a\x10ab'),
              vd(STABLE, 0x30, b'\x00\x00'),
              vd(INTERIM, 0x31, b'\x02\x00\x00'),
              avrcp(STABLE, 0x30, b'\x07'),
              avrcp(STABLE, 0x31, b'\x07\x48'),
              passthrough(ACCEPTED, 0x7E, b'\x00')[:-1] + b'',
              b'\x0c\x48'):
        c.rsp(p)
    for p in (brw(0x70, b'\x04' + struct.pack('>HIHB', 1, 1, 0x6a, 3) + struct.pack('>H', 2) + b'ab'),
              brw(0x71, b'\x04' + struct.pack('>HH', 1, 1) + b'\x01\x00\x40' + b'\x00' * 10),
              brw(0x71, b'\x04' + struct.pack('>HH', 1, 1) + b'\x02\x00\x20' + b'\x00' * 10),
              brw(0x71, b'\x04' + struct.pack('>HH', 1, 2)),
              brw(0x73, b'\x04\x02' + attr_entry(1, b'x')),
              brw(0x80, b'\x04\x00'),
              b'\x71'):
        b.rsp(p)
    c.cmd(vd(STATUS, 0x20, b'\x00' * 8 + b'\x05\x00\x00\x00\x01'))
    for p in (brw(0x71, b'\x00' + struct.pack('>II', 0, 1) + b'\x05\x00\x00\x00\x01'),
              brw(0x80, struct.pack('>HH', 0x6a, 50) + b'abc'),
              brw(0x73, b'\x01' + u64(0x20))):
        b.cmd(p)
    # AVCTP: invalid profile with AVRCP data after it
    c.raw(SENT, avctp(1, 0, vd(STATUS, 0x30), ipid=1))
    return cap


# ---------------------------------------------------------------- exported PDU

def exp_pdu(payload, p2p_dir):
    name = b'btavrcp'
    tlv = struct.pack('>HH', 12, len(name)) + name
    if p2p_dir is not None:
        tlv += struct.pack('>HHi', 35, 4, p2p_dir)
    tlv += struct.pack('>HH', 0, 0)
    return tlv + payload


def exported_capture():
    cap = Capture()
    cap.add(exp_pdu(vd(STATUS, 0x30), SENT))
    cap.add(exp_pdu(vd(STABLE, 0x30, struct.pack('>IIB', 1000, 10, 1)), RECV), gap=3500000)
    cap.add(exp_pdu(passthrough(CONTROL, 0x44), None))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap, marks = main_capture()
    write_pcap(os.path.join(out, 'btavrcp-coverage.pcap'), 201, cap.frames)
    write_pcap(os.path.join(out, 'btavrcp-coverage-malformed.pcap'), 201, malformed_capture().frames)
    write_pcap(os.path.join(out, 'btavrcp-coverage-exported.pcap'), 252, exported_capture().frames)
    for k, v in marks.items():
        print(k, v)


if __name__ == '__main__':
    main()
