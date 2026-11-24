#!/usr/bin/env python3
# Generates test/captures/mdp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MDP (Meraki Discovery Protocol) coverage captures.
Usage: mkmdp.py <outdir>.  Writes mdp-coverage.pcap and
mdp-coverage-malformed.pcap (Ethernet, ethertype 0x0712 / 0x0713)."""
import struct
import sys
import os

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

def eth(etype, payload, dst=b'\x01\x00\x5e\x00\x00\x00'):
    return dst + bytes.fromhex('00180a123456') + struct.pack('>H', etype) + payload

PRE = bytes(range(0x10, 0x10 + 28))

def tlv(t, v):
    if isinstance(v, str):
        v = v.encode()
    return struct.pack('BB', t, len(v)) + v

def mdp(*tlvs, pre=PRE):
    return pre + b''.join(tlvs)

DEV = tlv(2, 'MR42-office-3rd-floor')
NET = tlv(3, 'Q2XX-ABCD-1234')
LON = tlv(4, '-122.40306')
LAT = tlv(5, '37.78541')
S6 = tlv(6, '0a1b2c3d4e5f')
S7 = tlv(7, 'e0cb4e112233')
END = tlv(255, b'')

good = [
    eth(0x0712, mdp(DEV, NET, LON, LAT, S6, S7, END)),           # 1 every TLV type
    eth(0x0713, mdp(DEV, NET, END)),                              # 2 other ethertype
    eth(0x0712, mdp(tlv(9, bytes([1, 2, 3, 4])), END)),           # 3 unknown type
    eth(0x0712, mdp(tlv(2, b''), tlv(3, b''), END)),              # 4 empty strings
    eth(0x0712, mdp()),                                           # 5 preamble only
    eth(0x0712, mdp(tlv(2, 'x' * 200), tlv(4, '1'), tlv(5, '2'))),  # 6 long, no End
    eth(0x0713, mdp(tlv(7, 'e0cb4e000001'), tlv(6, '0a1b2c000001'), tlv(0, b'\xaa'), END)),  # 7
    eth(0x0712, mdp(tlv(2, 'AP-1'), tlv(3, 'N-1'), tlv(4, '0.0'), tlv(5, '0.0'), tlv(255, b'\x00\x00'))),  # 8 End with data
]
# The reproducer of the fixed bug: unknown TLV data in the TLV tree (frame 3 above)

bad = [
    eth(0x0712, mdp(DEV, bytes([3, 40]) + b'short')),   # 1 TLV length past the end
    eth(0x0712, mdp(DEV, bytes([3]))),                  # 2 TLV with the length byte missing
    eth(0x0712, mdp(DEV, bytes([5, 0]))),       # 3 empty latitude
    eth(0x0712, b'\x00' * 10),                          # 4 shorter than the preamble
    eth(0x0713, mdp(bytes([9, 200]) + b'\x01' * 5)),    # 5 unknown TLV past the end
]
out = sys.argv[1]
pcap(os.path.join(out, 'mdp-coverage.pcap'), good)
pcap(os.path.join(out, 'mdp-coverage-malformed.pcap'), bad)
