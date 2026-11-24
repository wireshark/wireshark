# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared pieces for the BSSMAP generator: transport, message tables, element variants."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys
SRC = os.path.join(SRCDIR, 'epan/dissectors', '')

def exp_pdu(name, payload):
    n = name.encode(); n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload

def write_pcap(fn, pkts, linktype=252):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def mtp3(sccp, opc=2, dpc=1, sls=0):
    label = dpc | (opc << 14) | (sls << 28)
    return exp_pdu('mtp3', bytes([0x83]) + struct.pack('<I', label) + sccp)

def gt_addr(ssn): return bytes([0x42, ssn])

def udt(data, called=254, calling=254):
    cd = gt_addr(called); cg = gt_addr(calling)
    p1 = 3; p2 = p1 - 1 + 1 + len(cd); p3 = p2 - 1 + 1 + len(cg)
    return bytes([0x09, 0x00, p1, p2, p3, len(cd)]) + cd + bytes([len(cg)]) + cg + bytes([len(data)]) + data

def sccp_cr(slr, data, called=254, calling=254):
    cd = gt_addr(called); cg = gt_addr(calling)
    opt = bytes([0x04, len(cg)]) + cg + bytes([0x0f, len(data)]) + data + b'\0'
    return bytes([0x01]) + slr.to_bytes(3, 'little') + bytes([0x02, 2, 2 + len(cd)]) + bytes([len(cd)]) + cd + opt

def sccp_cc(dlr, slr):
    return bytes([0x02]) + dlr.to_bytes(3, 'little') + slr.to_bytes(3, 'little') + bytes([0x02, 0x00])

def sccp_dt1(dlr, data):
    return bytes([0x06]) + dlr.to_bytes(3, 'little') + bytes([0x00, 0x01, len(data)]) + data

def bssmap(msg): return bytes([0x00, len(msg)]) + msg

def strip_comments(s):
    s = re.sub(r'/\*.*?\*/', '', s, flags=re.S)
    return re.sub(r'//[^\n]*', '', s)
