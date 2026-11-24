# Helper module for the dcom capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers for the packet-dcom.c reproducers: CO DCE/RPC over TCP with
multi-fragment requests (synthetic 192.0.2.x addresses, 02:00:00:00:00:xx MACs)."""
import struct
from dcom_bdef_rpclib import TCP, RPC, pcap

def guid_le(u):
    h = u.replace('-', '')
    return struct.pack('<IHH', int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)) + bytes.fromhex(h[16:])

UUID_ISYSACT = '000001a0-0000-0000-c000-000000000046'
UUID_IWBEMSERVICES = '9556dc99-828c-11cf-a37e-00aa003240c7'
IID_ISTORAGE = '0000000b-0000-0000-c000-000000000046'
IID_WMIO = 'dc12a681-737f-11cf-884d-00aa004b2e24'
NULL_GUID = '00000000-0000-0000-0000-000000000000'

def orpcthis():
    return struct.pack('<HHII', 5, 7, 0, 0) + b'\0' * 16 + struct.pack('<I', 0)

def orpcthat():
    return struct.pack('<II', 0, 0)

def seg_split(tcp, from_client, data, mss=1400):
    for i in range(0, len(data), mss):
        tcp.seg(from_client, data[i:i + mss])

def call_frag(r, opnum, req, resp=None, frag=4000):
    """Request (and optional response) split into several DCE/RPC fragments."""
    r.call_id += 1
    chunks = [req[i:i + frag] for i in range(0, len(req), frag)] or [b'']
    for n, c in enumerate(chunks):
        flags = (1 if n == 0 else 0) | (2 if n == len(chunks) - 1 else 0)
        body = struct.pack('<IHH', len(req), 0, opnum) + c
        seg_split(r.tcp, True, r.pdu(0, body, r.call_id, flags))
    if resp is not None:
        body = struct.pack('<IHBB', len(resp), 0, 0, 0) + resp
        seg_split(r.tcp, False, r.pdu(2, body, r.call_id))
