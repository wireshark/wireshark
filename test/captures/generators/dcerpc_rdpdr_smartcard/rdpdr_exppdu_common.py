# Helper module for the dcerpc_rdpdr_smartcard capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tlv = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    tlv += struct.pack('>HH', 20, 4) + bytes([192, 0, 2, 1])
    tlv += struct.pack('>HH', 21, 4) + bytes([192, 0, 2, 2])
    tlv += struct.pack('>HH', 0, 0)
    return tlv + payload

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)
