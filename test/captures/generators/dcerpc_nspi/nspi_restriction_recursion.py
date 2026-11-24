#!/usr/bin/env python3
# Helper module for the dcerpc_nspi capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""nspi_restriction_recursion.py: NspiGetMatches (opnum 5) request whose
restriction is RES_AND nested N levels deep (each level one
SAndRestriction holding a pointer to a 1-element array of SRestriction).
Checks that the nesting through deferred pointers is bounded.
argv: [N] [out.pcap]"""
import os
import struct
import sys
from nspi_common import nspi_rpc, pcap, HANDLE, SETTINGS

N = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
out = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(os.path.abspath(__file__))[0] + '.pcap'

def req(n):
    b = HANDLE + struct.pack('<I', 0) + SETTINGS
    b += struct.pack('<I', 0)            # PropTagArray NULL
    b += struct.pack('<I', 0)            # unknown2
    b += struct.pack('<I', 0x20000)      # restrictions ptr
    pid = 0x20004
    b += struct.pack('<IIII', 0, 0, 1, pid)  # rt=AND, disc=AND, cRes=1, lpRes
    for i in range(n):
        pid += 4
        last = (i == n - 1)
        if last:   # innermost: RES_PROPERTY with NULL lpProp
            b += struct.pack('<IIIIII', 1, 4, 4, 0, 0x3001001f, 0)
        else:
            b += struct.pack('<IIIII', 1, 0, 0, 1, pid)
    b += struct.pack('<I', 0)            # unknown3
    b += struct.pack('<I', 0)            # REQ_properties NULL
    return b

frames = []
t, r = nspi_rpc(frames, 50001)
body = req(N)
# split into fragments of <= 4280 bytes stub so a real PDU size is used
stub = body
call_id = 2
r.call_id = call_id
frag = 4200
off = 0
while off < len(stub):
    chunk = stub[off:off + frag]
    flags = (0x01 if off == 0 else 0) | (0x02 if off + frag >= len(stub) else 0)
    pdu = r.pdu(0, struct.pack('<IHH', len(stub), 0, 5) + chunk, call_id, flags)
    t.seg(True, pdu)
    off += frag
pcap(out, frames)
print(out, len(body))
