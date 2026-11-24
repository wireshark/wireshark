#!/usr/bin/env python3
# Generates test/captures/ovs_vport_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Usage: mkovs_vport.py <outdir>
# Synthetic capture for packet-netlink-ovs_vport.c.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ovslib import (
    be32, cstr, family, genl, gmsg, i32, LE, nest, nla, NLA_F_NESTED, NLA_F_NET_BYTEORDER, nlmsg,
    raw, rawmsg, sll, struct, u16, u32, u64, write,
)

FID = 0x26
V_PORT_NO, V_TYPE, V_NAME, V_OPTIONS, V_UPCALL_PID, V_STATS, V_PAD, V_IFINDEX, V_NETNSID, V_UPCALL_STATS = range(1, 11)
O_DST_PORT, O_EXTENSION = 1, 2
X_GBP = 1
U_SUCCESS, U_FAIL = 0, 1
stats = b''.join(u64(v) for v in (100, 90, 10000, 9000, 1, 2, 3, 4))

main = [family(FID, 'ovs_vport')]
# NEW: name, type, upcall pid, options (VXLAN with a port and the GBP extension)
main.append(gmsg(FID, 1, nla(V_TYPE, u32(4)) + nla(V_NAME, cstr('vxlan_sys_4789')) + nla(V_UPCALL_PID, u32(2468)) +
                 nest(V_OPTIONS, nla(O_DST_PORT, u16(4789)), nest(O_EXTENSION, nla(X_GBP, u32(1)))),
                 ifindex=7, pid=1000))
# reply: port number, type, name, pid(s), statistics, ifindex, netnsid, upcall statistics
main.append(gmsg(FID, 1, nla(V_PORT_NO, u32(2)) + nla(V_TYPE, u32(1)) + nla(V_NAME, cstr('eth1')) +
                 nla(V_UPCALL_PID, u32(11) + u32(12) + u32(13)) + nla(V_STATS, stats) + nla(V_IFINDEX, u32(9)) +
                 nla(V_NETNSID, u32(0xffffffff)) +
                 nest(V_UPCALL_STATS, nla(U_SUCCESS, u64(5000)), nla(U_FAIL, u64(3))), ifindex=7, seq=2))
# the other vport types
for i, (typ, name) in enumerate([(2, 'br0'), (3, 'gre_sys'), (5, 'genev_sys_6081'), (0, 'unspec')]):
    main.append(gmsg(FID, 1, nla(V_PORT_NO, u32(10 + i)) + nla(V_TYPE, u32(typ)) + nla(V_NAME, cstr(name)),
                     ifindex=7, seq=3 + i))
main.append(gmsg(FID, 1, nla(V_TYPE, u32(99)) + nla(V_NAME, cstr('weird')), seq=7))      # Unknown (99)
# GET, SET and DEL
main.append(gmsg(FID, 3, nla(V_NAME, cstr('eth1')), pid=1000, seq=8))
main.append(gmsg(FID, 4, nla(V_PORT_NO, u32(2)) + nla(V_UPCALL_PID, u32(77)), pid=1000, seq=9))
main.append(gmsg(FID, 2, nla(V_PORT_NO, u32(2)), pid=1000, seq=10))
main.append(gmsg(FID, 0, b'', ifindex=2))                     # UNSPEC
# GENEVE port options, VXLAN extension variants, unknown tunnel attributes
main.append(gmsg(FID, 1, nest(V_OPTIONS, nla(O_DST_PORT, u16(6081))), seq=11))
main.append(gmsg(FID, 1, nest(V_OPTIONS, nla(O_DST_PORT, b'\1'), nla(O_DST_PORT, u32(1)), nla(0, b'\1'), nla(9, b'\1'),
                              nest(O_EXTENSION, nla(X_GBP, b'\1\2'), nla(X_GBP, b'\1' * 8), nla(0, b'\1'), nla(5, b'\1'))), seq=12))
# wrong sized statistics (63, 65) and upcall counters (7, 9), unknown upcall type
main.append(gmsg(FID, 1, nla(V_STATS, stats[:63]) + nla(V_STATS, stats + b'\0') +
                 nest(V_UPCALL_STATS, nla(U_SUCCESS, b'\1' * 7), nla(U_FAIL, b'\1' * 9), nla(2, b'\1')), seq=13))
# empty name / pid list / options / upcall statistics; PAD, type 0, unknown
main.append(gmsg(FID, 1, nla(V_NAME) + nla(V_UPCALL_PID) + nla(V_UPCALL_PID, u32(1) + b'\1\2') + nest(V_OPTIONS) +
                 nest(V_UPCALL_STATS) + nla(V_PAD, b'\0' * 4) + nla(0, b'\1') + nla(77, b'\1\2\3'), seq=14))
# masked types: NESTED / NET_BYTEORDER on known scalar attributes
main.append(gmsg(FID, 1, nla(V_PORT_NO, u32(5), flags=NLA_F_NESTED) + nla(V_IFINDEX, be32(6), flags=NLA_F_NET_BYTEORDER) +
                 nla(V_NAME, cstr('masked'), flags=NLA_F_NESTED), seq=15))
main.append(rawmsg(FID, 1, b''))
main.append(rawmsg(FID, 1, b'\1\0\0'))

mal = [family(FID, 'ovs_vport')]
for t, p in [(V_PORT_NO, 3), (V_TYPE, 1), (V_IFINDEX, 2), (V_NETNSID, 1)]:
    mal.append(gmsg(FID, 1, raw(t, b'\1' * p)))
mal.append(gmsg(FID, 1, nest(V_OPTIONS, raw(O_DST_PORT, b'\1\2\3'))))
mal.append(gmsg(FID, 1, nest(V_OPTIONS, nest(O_EXTENSION, raw(X_GBP, b'\1\2\3\4')))))
mal.append(gmsg(FID, 1, nest(V_UPCALL_STATS, raw(U_SUCCESS, b'\1' * 8))))
mal.append(gmsg(FID, 1, nla(V_UPCALL_PID, b'\1\2')))
mal.append(gmsg(FID, 1, b''.join(nla(t, b'\1') for t in range(1, 11))))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 3, V_NAME) + b'\0' * 4))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 0x200, V_NAME) + b'eth\0'))
mal.append(sll() + struct.pack(LE + 'IHHII', 300, FID, 0, 1, 0) + genl(1, i32(1) + nla(V_NAME, cstr('x'))))
mal.append(sll() + nlmsg(FID, b'\x01\x01'))

write('ovs_vport', main, mal, sys.argv[1] if len(sys.argv) > 1 else '.')
