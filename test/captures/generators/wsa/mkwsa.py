#!/usr/bin/env python3
# Generates test/captures/wsa_extra.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate wsa-extra.pcap: the longitude range check of packet-wsa.c.

The committed captures test/captures/wsa_coverage.pcap.gz and
wsa_malformed.pcap.gz cover the WSA dissector (see README.md); what they
do not exercise is the longitude range check fixed by "WSA: Check the
longitude range on the 64-bit value": a raw 32-bit longitude above
3947483646 plus LON_MIN overflowed int32_t and the "Longitude out of
range" expert info was never added. This script takes frame 4 of
wsa_coverage.pcap.gz (a 3D location WSA) and sets the raw longitude to
values just under and past each limit. Synthetic: nothing comes from a
real network.

Frames 9 to 11 add the extension ids 15, 16 and 4 in a WSA header
extension list, a PSC with non-zero fill bits and a fragmented extension
length, which the committed captures do not reach.

Usage: mkwsa.py <output directory>   (reads test/captures/wsa_coverage.pcap.gz)
"""
import gzip
import os
import struct
import sys
from pcaplib import pcap

here = os.path.dirname(os.path.abspath(__file__))
# The committed WSA capture in test/captures.
d = gzip.open(os.path.join(here, '..', '..', 'wsa_coverage.pcap.gz')).read()
off = 24; frames = []
while off < len(d):
    cl = struct.unpack('<I', d[off + 8:off + 12])[0]
    frames.append(d[off + 16:off + 16 + cl]); off += 16 + cl
base = frames[3]
# the 32-bit raw longitude follows the 32 bit fill+latitude: find the latitude
lat = bytes.fromhex('6b49d201')
i = base.index(lat) + 4
assert base[i:i + 4] == bytes.fromhex('d693a400'), base.hex()     # 3600000000 = "unavailable"
out = []
for raw in (0, 3599999999, 3600000000, 3600000001, 3947483646, 3947483647, 4000000000, 0xffffffff):
    out.append(base[:i] + struct.pack('>I', raw) + base[i + 4:])

def wsa_frame(body):
    """WSMP (PSID 0x87) with unsecured IEEE 1609.2 data holding the WSA body."""
    return base[:18] + bytes([3 + len(body)]) + b'\x03\x80' + bytes([len(body)]) + body

# 9: header extensions with ids 15 (channel number), 16 (data rate) and 4
#    (transmit power), which no committed frame uses in a WSA
out.append(wsa_frame(bytes.fromhex('3830' '03' '0f0195' '10010c' '040114')))
# 10: a provider service context whose three fill bits are not zero
out.append(wsa_frame(bytes.fromhex('3830' '01' '0802' '2178')))
# 11: an extension with a fragmented (0xc0) length determinant
out.append(wsa_frame(bytes.fromhex('3830' '01' '06c0')))
os.makedirs(sys.argv[1], exist_ok=True)
pcap(os.path.join(sys.argv[1], 'wsa-extra.pcap'), out)
