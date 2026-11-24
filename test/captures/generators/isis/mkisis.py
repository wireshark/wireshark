#!/usr/bin/env python3
# Generates test/captures/isis_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates isis-coverage.pcap (clean) and isis-coverage-malformed.pcap for packet-isis.c
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from isislib import csnp, hello, lsp, lsp_entry, psnp, sidlen, tlv, write_pcap

out = sys.argv[1] if len(sys.argv) > 1 else '.'
AREA = tlv(1, b'\x03\x49\x00\x01')
NLPID = tlv(129, b'\xcc\x8e')

def basic(n=0, **h):
    """One of each PDU type with the given ID length; returns list of 9 PDUs."""
    l = sidlen(n)
    return [
        hello(1, [AREA], idlen=n, **h), hello(2, [AREA], idlen=n, **h), hello(3, [AREA], idlen=n, **h),
        lsp(1, [AREA], idlen=n, **h), lsp(2, [AREA], idlen=n, **h),
        csnp(1, [tlv(9, lsp_entry(l, 5))], idlen=n, **h), csnp(2, [tlv(9, lsp_entry(l, 5))], idlen=n, **h),
        psnp(1, [tlv(9, lsp_entry(l, 5))], idlen=n, **h), psnp(2, [tlv(9, lsp_entry(l, 5))], idlen=n, **h),
    ]

clean = []
clean += basic()                                  # 1-9   LLC / NLPID 0x83, all nine PDU types
clean += [(p, 'eth') for p in basic()]            # 10-18 same over ethertype 0x22F4
clean += [basic(8)[0], basic(8)[3], basic(8)[5], basic(8)[7]]      # 19-22 ID length 8
clean += [basic(255)[0], basic(255)[3], basic(255)[5], basic(255)[7]]  # 23-26 null ID (255)
clean += [basic(1)[1], basic(1)[4], basic(1)[6]]  # 27-29 ID length 1
clean += [hello(1, [AREA], ver=2), hello(1, [AREA], ver2=2), hello(1, [AREA], res=1)]   # 30-32 warnings
clean += [hello(1, [AREA], maxarea=3), hello(1, [AREA], ptype=15 | 0xe0)]               # 33-34 max areas, reserved bits
clean += [(hello(1, [AREA], ptype=5), 'eth'), lsp(1, [AREA], ptype=0x1f)]               # 35-36 unknown PDU type
clean += [(hello(1, [AREA], irpd=0x80), 'eth')]                                         # 37 other IRPD
write_pcap(os.path.join(out, 'isis-coverage.pcap'), clean)

mal = [hello(1, [AREA], hdrlen=7), hello(1, [AREA], hdrlen=0),
       (hello(1, [AREA], hdrlen=3), 'eth')]
write_pcap(os.path.join(out, 'isis-coverage-malformed.pcap'), mal)
print(len(clean), len(mal))
