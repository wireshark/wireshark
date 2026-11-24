#!/usr/bin/env python3
# Helper module for the dcerpc_nspi capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""nspi_common.py: NSPI (f5cc5a18-4264-101a-8c59-08002b2f8426 v56.0) over CO DCE/RPC/TCP,
reusing the TCP/RPC helpers of mapi_common.py."""
import os
import struct
import sys
from mapi_common import TCP, RPC, pcap

UUID_NSPI = "f5cc5a18-4264-101a-8c59-08002b2f8426"
VER_NSPI = (56, 0)


def nspi_rpc(frames, cport, ndr64=False, le=True):
    t = TCP(frames, cport)
    r = RPC(t, le=le, ndr64=ndr64, uuid=UUID_NSPI, ver=VER_NSPI)
    r.bind()
    return t, r

HANDLE = b'\0' * 4 + bytes(range(1, 17))
SETTINGS = struct.pack('<II16sIII', 0, 0, b'\x11' * 16, 1252, 0x409, 0x409)
