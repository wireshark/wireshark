#!/usr/bin/env python3
# Generates test/captures/ovs_ct_limit_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Usage: mkovs_ct_limit.py <outdir>
# Synthetic capture for packet-netlink-ovs_ct_limit.c.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ovslib import (
    family, genl, gmsg, i32, LE, nla, NLA_F_NESTED, NLA_F_NET_BYTEORDER, nlmsg, rawmsg, sll,
    struct, u32, write,
)

FID = 0x23
ZL = lambda zone, limit, count: i32(zone) + u32(limit) + u32(count)
A_ZL = 1

main = [family(FID, 'ovs_ct_limit')]
# SET with a few zone limits (the default zone -1 as well)
main.append(gmsg(FID, 1, nla(A_ZL, ZL(0, 100, 0) + ZL(5, 2000, 0) + ZL(-1, 65535, 0)), pid=1000))
# GET request: one zone, then the reply with counts
main.append(gmsg(FID, 3, nla(A_ZL, ZL(5, 0, 0)), pid=1000, seq=2))
main.append(gmsg(FID, 3, nla(A_ZL, ZL(5, 2000, 17) + ZL(0, 100, 99)), pid=0, seq=2))
# DEL
main.append(gmsg(FID, 2, nla(A_ZL, ZL(5, 0, 0)), pid=1000, seq=3))
# UNSPEC command, no attributes after the dp_ifindex
main.append(gmsg(FID, 0, b'', ifindex=2))
# Attribute with the NESTED flag (the type is masked), an unknown
# attribute type (raw data) and the attribute type 0
main.append(gmsg(FID, 1, nla(A_ZL, ZL(7, 7, 7), flags=NLA_F_NESTED) + nla(9, b'abcd') + nla(0, b'\x01\x02')))
# Net byte order flag: the zone limit fields are still read with the
# byte order of the capture host by this dissector
main.append(gmsg(FID, 1, nla(A_ZL, ZL(8, 8, 8), flags=NLA_F_NET_BYTEORDER)))
# ZONE_LIMIT shorter than one entry (12 octets): no entry; and 11
# trailing octets after one entry
main.append(gmsg(FID, 1, nla(A_ZL, b'\x01' * 8)))
main.append(gmsg(FID, 1, nla(A_ZL, ZL(1, 2, 3) + b'\0' * 11)))
# Empty ZONE_LIMIT attribute, and several in one message
main.append(gmsg(FID, 1, nla(A_ZL) + nla(A_ZL, ZL(3, 4, 5)) + nla(A_ZL, ZL(6, 7, 8))))
# Only the genl header (no OVS header), and a short OVS header
main.append(rawmsg(FID, 1, b''))
main.append(rawmsg(FID, 1, b'\x01\x00'))

mal = [family(FID, 'ovs_ct_limit')]
# Attribute length 3 (< 4) and an attribute longer than the message
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 3, 1) + b'\0' * 4))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 0x100, 1) + ZL(1, 2, 3)))
# Attribute truncated in the middle of the zone limit
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 16, 1) + ZL(1, 2, 3)[:8]))
# Message length field larger than the data
mal.append(sll() + struct.pack(LE + 'IHHII', 200, FID, 0, 1, 0) + genl(1, i32(1) + nla(1, ZL(1, 2, 3))))
# Generic netlink header cut short
mal.append(sll() + nlmsg(FID, b'\x01\x01'))

write('ovs_ct_limit', main, mal, sys.argv[1] if len(sys.argv) > 1 else '.')
