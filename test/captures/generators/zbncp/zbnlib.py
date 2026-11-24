#!/usr/bin/env python3
# Helper module for the zbncp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic ZBOSS NCP (ZBNCP) frame builders for the coverage captures of
# packet-zbncp.c.  Everything here is generated with struct; no key
# material or ciphertext is produced.
import struct

LINKTYPE_ZBOSS_NCP = 292

REQ, RSP, IND = 0, 1, 2


def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def ll(payload, flags=0xC0, ptype=0x06):
    """Low level header (signature, length, type, flags, crc8) + payload.
    The CRCs are not checked by the dissector and are left as zero."""
    return struct.pack('<BBHBBB', 0xDE, 0xAD, len(payload) + 5, ptype, flags, 0) + payload


def hl(ptype, call_id, body=b'', tsn=1, cat=0, status=0, version=0):
    """High level packet: crc16 (zero), header, status of a response, body."""
    h = struct.pack('<BBH', version, ptype, call_id)
    if ptype in (REQ, RSP):
        h += bytes([tsn & 0xff])
    if ptype == RSP:
        h += bytes([cat, status])
    return b'\x00\x00' + h + body


def frame(ptype, call_id, body=b'', flags=0xC0, **kw):
    return ll(hl(ptype, call_id, body, **kw), flags)


def dump(frame_bytes, options=0, version=1, ncp_type=0x06):
    """ZBNCP dump info header in front of a frame."""
    return b'ZBNCP' + bytes([version, ncp_type, options]) + frame_bytes
