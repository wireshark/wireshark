#!/usr/bin/env python3
# Generates test/captures/ovs_meter_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Usage: mkovs_meter.py <outdir>
# Synthetic capture for packet-netlink-ovs_meter.c.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ovslib import (
    be32, be64, family, genl, gmsg, i32, LE, nest, nla, NLA_F_NESTED, NLA_F_NET_BYTEORDER, nlmsg,
    raw, rawmsg, sll, struct, u32, u64, write,
)

FID = 0x25
M_ID, M_KBPS, M_STATS, M_BANDS, M_USED, M_CLEAR, M_MAX_METERS, M_MAX_BANDS, M_PAD = range(1, 10)
B_TYPE, B_RATE, B_BURST, B_STATS = 1, 2, 3, 4
stats = u64(1000) + u64(1500000)


def band(idx, typ=1, rate=1000, burst=100, with_stats=False):
    kids = nla(B_TYPE, u32(typ)) + nla(B_RATE, u32(rate)) + nla(B_BURST, u32(burst))
    if with_stats:
        kids += nla(B_STATS, u64(10) + u64(1200))
    return nest(idx, kids)


main = [family(FID, 'ovs_meter')]
# FEATURES request and reply
main.append(gmsg(FID, 1, b'', ifindex=0, pid=1000))
main.append(gmsg(FID, 1, nla(M_MAX_METERS, u32(1024)) + nla(M_MAX_BANDS, u32(8)), ifindex=0, seq=1))
# SET: id, flag, two bands (array: the index is the attribute type)
main.append(gmsg(FID, 2, nla(M_ID, u32(3)) + nla(M_KBPS) + nest(M_BANDS, band(0), band(1, 1, 5000, 500)),
                 pid=1000, seq=2))
# GET reply: statistics, bands with statistics, used
main.append(gmsg(FID, 4, nla(M_ID, u32(3)) + nla(M_STATS, stats) + nla(M_USED, u64(1700000000123)) +
                 nest(M_BANDS, band(0, with_stats=True), band(1, 1, 5000, 500, True)) + nla(M_CLEAR),
                 seq=3))
main.append(gmsg(FID, 4, nla(M_ID, u32(3)), pid=1000, seq=4))
main.append(gmsg(FID, 3, nla(M_ID, u32(3)), pid=1000, seq=5))       # DEL
main.append(gmsg(FID, 0, b'', ifindex=2))                             # UNSPEC
# band types: unspecified (0), unknown (7): "Unknown (7)" in the text
main.append(gmsg(FID, 2, nest(M_BANDS, band(0, 0), band(1, 7), band(2, 0xffffffff))))
# statistics of the wrong size (15, 17) are shown as data
main.append(gmsg(FID, 4, nla(M_STATS, stats[:15]) + nest(M_BANDS, nest(0, nla(B_STATS, b'\0' * 15), nla(B_STATS, b'\0' * 17)))))
# an empty bands attribute and a band without children
main.append(gmsg(FID, 2, nla(M_BANDS, flags=NLA_F_NESTED) + nest(M_BANDS, nest(0))))
# masked types (NESTED, NET_BYTEORDER) on scalars
main.append(gmsg(FID, 2, nla(M_ID, u32(9), flags=NLA_F_NESTED) + nla(M_MAX_METERS, be32(77), flags=NLA_F_NET_BYTEORDER) +
                 nla(M_USED, be64(99), flags=NLA_F_NET_BYTEORDER)))
# PAD, unspecified and unknown meter attributes; unknown band attributes
main.append(gmsg(FID, 2, nla(M_PAD, b'\0' * 4) + nla(0, b'\1') + nla(55, b'\1\2\3') +
                 nest(M_BANDS, nest(0, nla(0, b'\1'), nla(9, b'\1\2')))))
main.append(rawmsg(FID, 1, b''))
main.append(rawmsg(FID, 1, b'\1\0\0'))

mal = [family(FID, 'ovs_meter')]
for t, p in [(M_ID, 3), (M_USED, 7), (M_MAX_METERS, 2), (M_MAX_BANDS, 1)]:
    mal.append(gmsg(FID, 2, raw(t, b'\1' * p)))
mal.append(gmsg(FID, 2, nest(M_BANDS, nest(0, raw(B_RATE, b'\1\2')))))
mal.append(gmsg(FID, 2, nest(M_BANDS, nest(0, raw(B_TYPE, b'\1\2\3')))))
mal.append(gmsg(FID, 2, nest(M_BANDS, nest(0, raw(B_BURST, b'\1')))))
mal.append(gmsg(FID, 2, b''.join(nla(t, b'\1') for t in range(1, 10))))
mal.append(gmsg(FID, 2, nest(M_BANDS, nest(0, *[nla(t, b'\1') for t in range(1, 5)]))))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 3, M_ID) + b'\0' * 4))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 0x200, M_ID) + u32(1)))
mal.append(sll() + struct.pack(LE + 'IHHII', 300, FID, 0, 1, 0) + genl(1, i32(1) + nla(M_CLEAR)))
mal.append(sll() + nlmsg(FID, b'\x01\x01'))

write('ovs_meter', main, mal, sys.argv[1] if len(sys.argv) > 1 else '.')
