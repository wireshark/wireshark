#!/usr/bin/env python3
# Helper module for the dcom capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Frame order dependence of the DCOM custom-marshaler registry.
dcom_get_routine_by_uuid() (packet-dcom.c) only finds routines that were
registered by an earlier dissection: the WMIO routine is registered from the
IWbemServices *response* ORPCTHAT handler (register_dcom_wmio()), sysact ones
from the ISystemActivator handlers.  Call 1 is a GetObject request carrying an
[in] IWbemClassObject (OBJREF_CUSTOM, iid=IID_IWbemClassObject); call 1's
response follows.  One pass: the request's OBJREF payload is not decoded;
with -2 (or in the GUI after any re-dissection) it is decoded as WMIO."""
import struct
import sys
from dcom_lib import (
    guid_le, IID_WMIO, NULL_GUID, orpcthat, orpcthis, pcap, RPC, TCP, UUID_IWBEMSERVICES,
)

out = sys.argv[1] if len(sys.argv) > 1 else 'dcom_marshaler_2pass.pcap'
wmio = struct.pack('<I', 0x12345678) + b'\0' * 12            # signature, junk
objref = struct.pack('<II', 0x574f454d, 4) + guid_le(IID_WMIO) + guid_le(NULL_GUID)
objref += struct.pack('<II', 0, len(wmio)) + wmio

def ppobject():
    s = struct.pack('<II', 0x00020000, 0x00020004) + struct.pack('<II', len(objref), len(objref)) + objref
    return s + b'\0' * ((-len(s)) % 4)

req = orpcthis() + struct.pack('<I', 0) + struct.pack('<I', 0) + struct.pack('<II', 0, 0)
req += ppobject() + struct.pack('<I', 0)
resp = orpcthat() + struct.pack('<I', 0) + struct.pack('<I', 0) + struct.pack('<I', 0)

frames = []
t = TCP(frames, 50412)
r = RPC(t, uuid=UUID_IWBEMSERVICES, ver=(0, 0))
r.bind()
r.call(6, req, resp)
t.fin()
pcap(out, frames)
