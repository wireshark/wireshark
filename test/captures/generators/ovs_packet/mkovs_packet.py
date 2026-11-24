#!/usr/bin/env python3
# Generates test/captures/ovs_packet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Usage: mkovs_packet.py <outdir>
# Synthetic capture for packet-netlink-ovs_packet.c.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ovslib import (
    be16, be32, be64, chain, family, genl, gmsg, i32, LE, nest, nla, NLA_F_NESTED,
    NLA_F_NET_BYTEORDER, nlmsg, raw, rawmsg, sll, struct, u16, u32, u8, write,
)

FID = 0x21
P_PACKET, P_KEY, P_ACTIONS, P_USERDATA, P_EGRESS_TUN_KEY, P_UNUSED1, P_UNUSED2, P_PROBE, P_MRU, P_LEN, P_HASH, P_UPCALL_PID = range(1, 13)
# ovs_flow key / action / tunnel attribute types used inside
K_ENCAP, K_PRIORITY, K_IN_PORT, K_ETHERNET, K_VLAN, K_ETHERTYPE, K_IPV4, K_TCP = 1, 2, 3, 4, 5, 6, 7, 9
A_OUTPUT, A_USERSPACE, A_CLONE = 1, 2, 20
T_ID, T_IPV4_SRC, T_IPV4_DST, T_TTL = 0, 1, 2, 4

mac1, mac2 = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
ip4a, ip4b = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
# an Ethernet/IPv4/UDP frame (the packet data is not dissected further)
frame = mac2 + mac1 + be16(0x0800) + bytes([0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0]) + ip4a + ip4b + \
    be16(1000) + be16(2000) + be16(8) + be16(0)
key = nla(K_PRIORITY, u32(0)) + nla(K_IN_PORT, u32(2)) + nla(K_ETHERNET, mac1 + mac2) + \
    nla(K_ETHERTYPE, be16(0x0800)) + nla(K_IPV4, ip4a + ip4b + bytes([17, 0, 64, 0]))
acts = nla(A_OUTPUT, u32(3)) + nest(A_USERSPACE, nla(1, u32(77)), nla(2, b'\1\2\3\4'))
tun = nla(T_ID, be64(42)) + nla(T_IPV4_SRC, ip4a) + nla(T_IPV4_DST, ip4b) + nla(T_TTL, u8(64))
out = nla(A_OUTPUT, u32(2))

main = [family(FID, 'ovs_packet')]
# MISS upcall: packet, key, userdata, mru, len, hash, upcall pid
main.append(gmsg(FID, 1, nla(P_PACKET, frame) + nest(P_KEY, key) + nla(P_USERDATA, b'\xaa\xbb\xcc\xdd') +
                 nla(P_MRU, u16(1500)) + nla(P_LEN, u32(len(frame))) + nla(P_HASH, u32(0x12345678)) +
                 nla(P_UPCALL_PID, u32(2468)), ifindex=7))
# ACTION upcall: packet, key, userdata (+ egress tunnel key)
main.append(gmsg(FID, 2, nla(P_PACKET, frame) + nest(P_KEY, key) + nla(P_USERDATA, b'\1\2') +
                 nest(P_EGRESS_TUN_KEY, tun), ifindex=7, seq=2))
# EXECUTE from userspace: packet, key, actions, probe, mru
main.append(gmsg(FID, 3, nla(P_PACKET, frame) + nest(P_KEY, key) + nest(P_ACTIONS, acts) + nla(P_PROBE) +
                 nla(P_MRU, u16(9000)), ifindex=7, pid=1000, seq=3))
# UNSPEC command, and unused / unknown / type 0 attributes
main.append(gmsg(FID, 0, b'', ifindex=2))
main.append(gmsg(FID, 1, nla(P_UNUSED1, b'\0' * 4) + nla(P_UNUSED2, b'\0' * 4) + nla(0, b'\1') + nla(40, b'\1\2\3'), seq=4))
# empty packet, userdata and actions
main.append(gmsg(FID, 1, nla(P_PACKET) + nla(P_USERDATA) + nest(P_ACTIONS) + nest(P_KEY), seq=5))
# NESTED / NET_BYTEORDER flags on KEY (already NESTED), scalars and packet
main.append(gmsg(FID, 1, nla(P_MRU, be16(1280), flags=NLA_F_NET_BYTEORDER) + nla(P_LEN, be32(99), flags=NLA_F_NET_BYTEORDER) +
                 nla(P_UPCALL_PID, u32(5), flags=NLA_F_NESTED) + nla(P_HASH, be32(0xdeadbeef), flags=NLA_F_NET_BYTEORDER) +
                 nla(P_PACKET, frame[:20], flags=NLA_F_NESTED), seq=6))
# ENCAP in the key, CLONE in the actions, a few levels
main.append(gmsg(FID, 3, nest(P_KEY, nla(K_ETHERTYPE, be16(0x8100)), nest(K_ENCAP, nla(K_ETHERTYPE, be16(0x0800)))) +
                 nest(P_ACTIONS, nest(A_CLONE, out, nest(A_CLONE, out))), pid=1000, seq=7))
main.append(rawmsg(FID, 1, b''))
main.append(rawmsg(FID, 1, b'\1\0'))
# Recursion into ovs_flow (report-s6 F1; the 16000 deep originals are in
# the malformed capture): OVS_PACKET_ATTR_ACTIONS with CLONE nested 40 deep, and
# OVS_PACKET_ATTR_KEY with ENCAP nested 40 deep. They stop at the
# nesting limit of packet-netlink.c with a warning.
main.append(gmsg(FID, 3, nla(P_ACTIONS, chain(A_CLONE, 40), flags=NLA_F_NESTED), pid=1000, seq=8))
main.append(gmsg(FID, 3, nla(P_KEY, chain(K_ENCAP, 40), flags=NLA_F_NESTED), pid=1000, seq=9))
main.append(gmsg(FID, 3, nla(P_EGRESS_TUN_KEY, nla(T_ID, be64(1)), flags=NLA_F_NESTED), pid=1000, seq=10))

mal = [family(FID, 'ovs_packet')]
mal.append(gmsg(FID, 3, nla(P_ACTIONS, chain(A_CLONE, 16000), flags=NLA_F_NESTED), pid=1000, seq=8))
mal.append(gmsg(FID, 3, nla(P_KEY, chain(K_ENCAP, 16000), flags=NLA_F_NESTED), pid=1000, seq=9))
for t, p in [(P_MRU, 1), (P_LEN, 3), (P_HASH, 2), (P_UPCALL_PID, 1)]:
    mal.append(gmsg(FID, 1, raw(t, b'\1' * p)))
mal.append(gmsg(FID, 1, nest(P_KEY, raw(K_PRIORITY, b'\1\2'))))
mal.append(gmsg(FID, 1, nest(P_EGRESS_TUN_KEY, raw(T_ID, b'\1\2\3'))))
mal.append(gmsg(FID, 1, nest(P_ACTIONS, raw(A_OUTPUT, b'\1'))))
mal.append(gmsg(FID, 1, b''.join(nla(t, b'\1') for t in range(1, 13))))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 3, P_PACKET) + b'\0' * 4))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 0x200, P_PACKET) + frame))
mal.append(sll() + struct.pack(LE + 'IHHII', 300, FID, 0, 1, 0) + genl(1, i32(1) + nla(P_PROBE)))
mal.append(sll() + nlmsg(FID, b'\x01\x01'))

write('ovs_packet', main, mal, sys.argv[1] if len(sys.argv) > 1 else '.')
