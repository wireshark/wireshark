#!/usr/bin/env python3
# Helper module for the dcerpc_tapi capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""tapi_count_wrap.py: TAPI ClientRequest (opnum 1) requests.
Call 1 is well formed: context handle, a [size_is,length_is] byte array of
8 octets, the length.  Call 2 sets the array actual_count to 0xFFFFFFFF:
dissect_tapi_TYPE_1() passes it as the int length -1 ("to the end of the
tvb") to proto_tree_add_item() and then does offset += 0xFFFFFFFF, which
wraps the unsigned offset back by one octet, so the trailing element_8 is
decoded from inside the array header.  Call 3 uses 0x80000010 (a
negative length other than -1): the exception is a malformed packet, the
expected outcome.  Synthetic addresses only."""
import struct
import os
from ndrgen import TCP, RPC, write_pcap

UUID_TAPI = '2f5f6520-ca46-1067-b319-00dd010662da'

def req(actual, data):
    s = b'\0' * 4 + b'\x11' * 16                     # context handle
    s += struct.pack('<III', len(data), 0, actual) + data
    s += b'\0' * ((-len(s)) % 4)
    s += struct.pack('<I', len(data))
    return s

frames = []
t = TCP(frames, 50201)
r = RPC(t, UUID_TAPI, (1, 0))
r.bind()
r.call(1, req(8, b'ABCDEFGH'), struct.pack('<I', 0))
r.call(1, req(0xFFFFFFFF, b'ABCDEFGH'), struct.pack('<I', 0))
r.call(1, req(0x80000010, b'ABCDEFGH'), struct.pack('<I', 0))
t.fin()
write_pcap(os.path.splitext(os.path.abspath(__file__))[0] + '.pcap', frames)
