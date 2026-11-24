#!/usr/bin/env python3
# Generates test/captures/ovs_datapath_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Usage: mkovs_datapath.py <outdir>
# Synthetic capture for packet-netlink-ovs_datapath.c.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ovslib import (
    be32, cstr, family, genl, gmsg, i32, LE, nla, NLA_F_NESTED, NLA_F_NET_BYTEORDER, nlmsg, raw,
    rawmsg, sll, struct, u32, u64, write,
)

FID = 0x22
NAME, UPCALL_PID, STATS, MEGA, FEATURES, PAD, MASKS, PER_CPU, IFINDEX = range(1, 10)
stats = u64(1000) + u64(20) + u64(3) + u64(15)
mega = u64(900) + u32(4) + u32(0) + u64(500) + u64(0)

main = [family(FID, 'ovs_datapath')]
# NEW (userspace request): name, upcall pid, user features
main.append(gmsg(FID, 1, nla(NAME, cstr('ovs-system')) + nla(UPCALL_PID, u32(4242)) + nla(FEATURES, u32(0x0f)),
                 ifindex=0, pid=1000))
# Reply from the kernel: everything
main.append(gmsg(FID, 1, nla(NAME, cstr('ovs-system')) + nla(UPCALL_PID, u32(4242)) + nla(STATS, stats) +
                 nla(MEGA, mega) + nla(FEATURES, u32(0x05)) + nla(MASKS, u32(256)) +
                 nla(PER_CPU, u32(11) + u32(12) + u32(13) + u32(14)) + nla(IFINDEX, u32(7)),
                 ifindex=7))
# GET, SET, DEL
main.append(gmsg(FID, 3, nla(NAME, cstr('ovs-system')), ifindex=0, pid=1000, seq=2))
main.append(gmsg(FID, 4, nla(UPCALL_PID, u32(1)) + nla(MASKS, u32(512)) + nla(FEATURES, u32(0x0a)), ifindex=7, pid=1000, seq=3))
main.append(gmsg(FID, 2, nla(NAME, cstr('br0')), ifindex=0, pid=1000, seq=4))
# UNSPEC command with only the OVS header
main.append(gmsg(FID, 0, b'', ifindex=3))
# Megaflow stats without the cache hit counter (16 octets) and with a
# 24 octet payload (cache hit does not fit); no features set
main.append(gmsg(FID, 1, nla(MEGA, mega[:16]) + nla(MEGA, mega[:24]) + nla(FEATURES, u32(0))))
# Per CPU pids: one, six octets (the 2 odd octets are ignored), none
main.append(gmsg(FID, 1, nla(PER_CPU, u32(99)) + nla(PER_CPU, u32(1) + b'\x01\x02') + nla(PER_CPU)))
# Statistics of the wrong size (31 and 33 octets) and megaflow stats of
# 8 octets are shown as data
main.append(gmsg(FID, 1, nla(STATS, stats[:31]) + nla(STATS, stats + b'\0') + nla(MEGA, mega[:8])))
# NESTED / NET_BYTEORDER flags on known attributes (masked type)
main.append(gmsg(FID, 1, nla(NAME, cstr('flagged'), flags=NLA_F_NESTED) + nla(IFINDEX, u32(9), flags=NLA_F_NESTED) +
                 nla(MASKS, be32(64), flags=NLA_F_NET_BYTEORDER)))
# PAD, unspecified and unknown attribute types, a name without the NUL
main.append(gmsg(FID, 1, nla(PAD, b'\0' * 4) + nla(0, b'\x01') + nla(77, b'xyz') + nla(NAME, b'nonul')))
# Header only, and a short OVS header
main.append(rawmsg(FID, 1, b''))
main.append(rawmsg(FID, 1, b'\x01\x00\x00'))

# Malformed: reproducers of ovs_misc.py (attributes of 1 octet and empty
# attributes, on every handler), cut and oversized attributes
mal = [family(FID, 'ovs_datapath')]
dp = b''.join(nla(t, b'\x01') for t in range(1, 11)) + nla(1, b'dp0') + nla(4, b'\0' * 16) + nla(3, b'\0' * 32) + nla(8, b'')
mal.append(gmsg(FID, 1, dp))
for t in (UPCALL_PID, FEATURES, MASKS, IFINDEX):
    mal.append(gmsg(FID, 1, raw(t, b"\x0f")))          # shorter than the field: exception
mal.append(gmsg(FID, 1, raw(STATS, b"")))
mal.append(gmsg(FID, 1, raw(MEGA, b"\x01" * 20)))
mal.append(gmsg(FID, 1, raw(FEATURES, b"\x01" * 3)))
mal.append(gmsg(FID, 1, nla(NAME, b'')))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 3, NAME) + b'\0' * 4))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 0x200, NAME) + b'abc\0'))
mal.append(sll() + struct.pack(LE + 'IHHII', 300, FID, 0, 1, 0) + genl(1, i32(1) + nla(NAME, cstr('x'))))
mal.append(sll() + nlmsg(FID, b'\x01\x01'))

write('ovs_datapath', main, mal, sys.argv[1] if len(sys.argv) > 1 else '.')
