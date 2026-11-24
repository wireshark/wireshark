# Helper module for the dcerpc_rcg capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
from rdpdr_exppdu_common import exp_pdu, write_pcap

def ber(tag, content):
    n = len(content)
    if n < 0x80:
        l = bytes([n])
    elif n < 0x100:
        l = bytes([0x81, n])
    else:
        l = bytes([0x82]) + struct.pack('>H', n)
    return bytes([tag]) + l + content

def rdpear_frame(package_name, package_buffer):
    inner = ber(0x30,
                ber(0xa1, ber(0x04, package_name.encode('utf-16-le'))) +
                ber(0xa2, ber(0x04, package_buffer)))
    # GSS-API CFX wrap token, not sealed (flags 0), EC 0, RRC 0
    tok = b'\x05\x04\x00\xff' + struct.pack('>HHQ', 0, 0, 1) + inner
    hdr = struct.pack('<IIIIQ', 0x4eacc3c8, len(tok), 0, 0, 0)
    return exp_pdu('rdp_ear', hdr + tok)
