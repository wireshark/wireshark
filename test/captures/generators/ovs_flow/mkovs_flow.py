#!/usr/bin/env python3
# Generates test/captures/ovs_flow_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Usage: mkovs_flow.py <outdir>
# Synthetic capture for packet-netlink-ovs_flow.c.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ovslib import (
    be16, be32, be64, chain, cstr, family, genl, gmsg, i32, LE, nest, nla, NLA_F_NESTED,
    NLA_F_NET_BYTEORDER, nlmsg, raw, rawmsg, sll, struct, u16, u32, u64, u8, write,
)

FID = 0x24
# OVS_FLOW_ATTR_*
F_KEY, F_ACTIONS, F_STATS, F_TCP_FLAGS, F_USED, F_CLEAR, F_MASK, F_PROBE, F_UFID, F_UFID_FLAGS, F_PAD = range(1, 12)
# OVS_KEY_ATTR_*
(K_ENCAP, K_PRIORITY, K_IN_PORT, K_ETHERNET, K_VLAN, K_ETHERTYPE, K_IPV4, K_IPV6, K_TCP, K_UDP, K_ICMP,
 K_ICMPV6, K_ARP, K_ND, K_SKB_MARK, K_TUNNEL, K_SCTP, K_TCP_FLAGS, K_DP_HASH, K_RECIRC_ID, K_MPLS,
 K_CT_STATE, K_CT_ZONE, K_CT_MARK, K_CT_LABELS, K_CT_TUPLE4, K_CT_TUPLE6, K_NSH, K_PACKET_TYPE,
 K_ND_EXT, K_TUNNEL_INFO, K_IPV6_EXTHDRS) = range(1, 33)
# OVS_TUNNEL_KEY_ATTR_*
(T_ID, T_IPV4_SRC, T_IPV4_DST, T_TOS, T_TTL, T_DF, T_CSUM, T_OAM, T_GENEVE, T_TP_SRC, T_TP_DST, T_VXLAN,
 T_IPV6_SRC, T_IPV6_DST, T_PAD, T_ERSPAN, T_INFO_BRIDGE) = range(0, 17)
# OVS_ACTION_ATTR_*
(A_OUTPUT, A_USERSPACE, A_SET, A_PUSH_VLAN, A_POP_VLAN, A_SAMPLE, A_RECIRC, A_HASH, A_PUSH_MPLS, A_POP_MPLS,
 A_SET_MASKED, A_CT, A_TRUNC, A_PUSH_ETH, A_POP_ETH, A_CT_CLEAR, A_PUSH_NSH, A_POP_NSH, A_METER, A_CLONE,
 A_CHECK_PKT_LEN, A_ADD_MPLS, A_DEC_TTL, A_DROP, A_PSAMPLE) = range(1, 26)
# userspace / sample / ct / nat
U_PID, U_USERDATA, U_EGRESS, U_ACTIONS = 1, 2, 3, 4
S_PROB, S_ACTIONS = 1, 2
C_COMMIT, C_ZONE, C_MARK, C_LABELS, C_HELPER, C_NAT, C_FORCE, C_EVENTMASK, C_TIMEOUT = range(1, 10)
N_SRC, N_DST, N_IP_MIN, N_IP_MAX, N_PROTO_MIN, N_PROTO_MAX, N_PERSISTENT, N_HASH, N_RANDOM = range(1, 10)

mac1, mac2 = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
ip4a, ip4b = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
ip6a = bytes.fromhex('20010db8000000000000000000000001')
ip6b = bytes.fromhex('20010db8000000000000000000000002')

# ---- key attribute payloads
eth = mac1 + mac2
ipv4 = ip4a + ip4b + bytes([6, 0x10, 64, 0])
ipv6 = ip6a + ip6b + be32(0x12345) + bytes([17, 0, 64, 0])
l4 = be16(1234) + be16(80)
arp = ip4a + ip4b + be16(1) + mac1 + mac2
nd = ip6a + mac1 + mac2
tup4 = ip4a + ip4b + be16(5000) + be16(443) + bytes([6])
tup6 = ip6a + ip6b + be16(5000) + be16(443) + bytes([6])


def key_tcp4():
    return b''.join([
        nla(K_PRIORITY, u32(7)), nla(K_IN_PORT, u32(2)), nla(K_ETHERNET, eth),
        nla(K_VLAN, be16(0x1064)), nla(K_ETHERTYPE, be16(0x0800)), nla(K_IPV4, ipv4),
        nla(K_TCP, l4), nla(K_TCP_FLAGS, be16(0x0012)), nla(K_SKB_MARK, u32(0x55)),
        nla(K_DP_HASH, u32(0xdeadbeef)), nla(K_RECIRC_ID, u32(3))])


def key_udp6():
    return nla(K_ETHERNET, eth) + nla(K_ETHERTYPE, be16(0x86dd)) + nla(K_IPV6, ipv6) + nla(K_UDP, l4)


tunnel = b''.join([
    nla(T_ID, be64(0x1122334455667788)), nla(T_IPV4_SRC, ip4a), nla(T_IPV4_DST, ip4b), nla(T_TOS, u8(0x10)),
    nla(T_TTL, u8(64)), nla(T_DF), nla(T_CSUM), nla(T_OAM), nla(T_GENEVE, bytes.fromhex('0102000411223344')),
    nla(T_TP_SRC, be16(4789)), nla(T_TP_DST, be16(6081)), nla(T_VXLAN, nla(1, u32(0x80))),
    nla(T_IPV6_SRC, ip6a), nla(T_IPV6_DST, ip6b), nla(T_PAD, b'\0' * 4),
    nla(T_ERSPAN, bytes.fromhex('0000000100000000')), nla(T_INFO_BRIDGE)])

key_misc = b''.join([
    nla(K_ICMP, bytes([8, 0])), nla(K_ICMPV6, bytes([135, 0])), nla(K_ARP, arp), nla(K_ND, nd),
    nla(K_SCTP, l4), nla(K_MPLS, be32(0x00012140) + be32(0x00022140)),
    nla(K_CT_STATE, u32(0x21)), nla(K_CT_ZONE, u16(5)), nla(K_CT_MARK, u32(9)), nla(K_CT_LABELS, bytes(range(16))),
    nla(K_CT_TUPLE4, tup4), nla(K_CT_TUPLE6, tup6), nla(K_PACKET_TYPE, be32(0)), nla(K_IPV6_EXTHDRS, u16(0x0c)),
    nla(K_TUNNEL, tunnel)])

# unreachable-by-handler key types fall to raw data: NSH, ND_EXTENSIONS, TUNNEL_INFO, unspecified, unknown
key_raw = nla(K_NSH, b'\1\2\3\4') + nla(K_ND_EXT, b'\1\2\3\4') + nla(K_TUNNEL_INFO, b'\1\2\3\4') + nla(0, b'\1') + nla(99, b'\1\2')

# wrong lengths: the structure subtrees are skipped, no item is added
key_short = b''.join([
    nla(K_ETHERNET, eth[:11]), nla(K_IPV4, ipv4[:11]), nla(K_IPV6, ipv6[:39]), nla(K_TCP, l4[:3]),
    nla(K_UDP, l4[:3]), nla(K_ICMP, b'\x08'), nla(K_ICMPV6, b'\x87'), nla(K_ARP, arp[:21]), nla(K_ND, nd[:27]),
    nla(K_SCTP, l4[:3]), nla(K_CT_TUPLE4, tup4[:12]), nla(K_CT_TUPLE6, tup6[:36])])
# and longer than the structure
key_long = b''.join([
    nla(K_ETHERNET, eth + b'\0' * 4), nla(K_IPV4, ipv4 + b'\0' * 4), nla(K_IPV6, ipv6 + b'\0' * 4),
    nla(K_TCP, l4 + b'\0' * 4), nla(K_UDP, l4 + b'\0' * 4), nla(K_ICMP, bytes([8, 0, 0, 0])),
    nla(K_ICMPV6, bytes([8, 0, 0, 0])), nla(K_ARP, arp + b'\0' * 2), nla(K_ND, nd + b'\0' * 2),
    nla(K_SCTP, l4 + b'\0' * 4), nla(K_CT_TUPLE4, tup4 + b'\0' * 3), nla(K_CT_TUPLE6, tup6 + b'\0' * 3),
    nla(K_MPLS, be32(1) + b'\0' * 2)])

# ---- actions
nat_all = b''.join([nla(N_SRC), nla(N_DST), nla(N_IP_MIN, ip4a), nla(N_IP_MAX, ip4b), nla(N_PROTO_MIN, be16(1024)),
                    nla(N_PROTO_MAX, be16(65535)), nla(N_PERSISTENT), nla(N_HASH), nla(N_RANDOM)])
nat_v6 = nla(N_DST) + nla(N_IP_MIN, ip6a) + nla(N_IP_MAX, ip6b)
ct_all = b''.join([nla(C_COMMIT), nla(C_ZONE, u16(5)), nla(C_MARK, u32(9) + u32(0xff)),
                   nla(C_LABELS, bytes(range(16)) + bytes(range(16))), nla(C_HELPER, cstr('ftp')),
                   nest(C_NAT, nat_all), nla(C_FORCE), nla(C_EVENTMASK, u32(0x6)), nla(C_TIMEOUT, cstr('tcp_deleg'))])
out = nla(A_OUTPUT, u32(2))
acts_a = b''.join([
    out,
    nest(A_USERSPACE, nla(U_PID, u32(1234)), nla(U_USERDATA, b'\x01\x02\x03\x04'), nla(U_EGRESS, u32(6)),
         nla(U_ACTIONS)),
    nest(A_SET, nla(K_ETHERNET, eth), nla(K_IPV4, ipv4)),
    nla(A_PUSH_VLAN, be16(0x8100) + be16(0x1064)), nla(A_POP_VLAN),
    nest(A_SAMPLE, nla(S_PROB, u32(0x7fffffff)), nest(S_ACTIONS, out, nla(A_RECIRC, u32(5)))),
    nla(A_RECIRC, u32(8)), nla(A_HASH, u32(1) + u32(0x1234)),
    nla(A_PUSH_MPLS, be32(0x00012140) + be16(0x8847)), nla(A_POP_MPLS, be16(0x0800)),
    nest(A_SET_MASKED, nla(K_IPV4, ipv4 + ipv4), nla(K_SKB_MARK, u32(1) + u32(0xff))),
    nest(A_CT, ct_all), nest(A_CT, nest(C_NAT, nat_v6)),
    nla(A_TRUNC, u32(128)), nla(A_PUSH_ETH, eth), nla(A_POP_ETH), nla(A_CT_CLEAR), nla(A_POP_NSH),
    nla(A_METER, u32(3)), nest(A_CLONE, out, nla(A_POP_VLAN), nest(A_CLONE, out)), nla(A_DROP, u32(0)),
])
# action types handled as raw data
acts_raw = nla(A_PUSH_NSH, b'\1\2\3\4') + nla(A_CHECK_PKT_LEN, b'\1\2\3\4') + nla(A_ADD_MPLS, b'\1\2\3\4') + \
    nla(A_DEC_TTL, b'\1\2\3\4') + nla(A_PSAMPLE, b'\1\2\3\4') + nla(0, b'\1') + nla(99, b'\1\2')
acts_short = b''.join([
    nla(A_PUSH_VLAN, b'\x81\x00\x10'), nla(A_HASH, b'\0' * 7), nla(A_PUSH_MPLS, b'\0' * 5), nla(A_PUSH_ETH, b'\0' * 11),
    nla(A_PUSH_VLAN, b'\0' * 8), nla(A_HASH, b'\0' * 12), nla(A_PUSH_ETH, b'\0' * 13)])
acts_odd = b''.join([
    nest(A_USERSPACE, nla(0, b'\1'), nla(9, b'\1\2')), nest(A_SAMPLE, nla(0, b'\1'), nla(9, b'\1')),
    nest(A_CT, nla(0, b'\1'), nla(99, b'\1'), nest(C_NAT, nla(0, b'\1'), nla(99, b'\1'))),
    nest(A_SET, nla(K_NSH, b'\1\2\3\4'))])

stats = u64(77) + u64(7700)
flow_attrs = b''.join([nla(F_STATS, stats), nla(F_TCP_FLAGS, u8(0x12)), nla(F_USED, u64(123456789)),
                       nla(F_CLEAR), nla(F_PROBE), nla(F_UFID, bytes(range(16))), nla(F_UFID_FLAGS, u32(3)),
                       nla(F_PAD, b'\0' * 4)])
mask = b''.join([nla(K_PRIORITY, u32(0xffffffff)), nla(K_ETHERNET, b'\xff' * 12), nla(K_ETHERTYPE, be16(0xffff)),
                 nla(K_IPV4, b'\xff' * 12), nla(K_TCP, b'\xff' * 4)])

main = [family(FID, 'ovs_flow')]
# NEW with key, mask, actions (user request; flow add)
main.append(gmsg(FID, 1, nest(F_KEY, key_tcp4()) + nest(F_MASK, mask) + nest(F_ACTIONS, acts_a) +
                 nla(F_UFID, bytes(range(16))) + nla(F_UFID_FLAGS, u32(1)), pid=1000))
# kernel reply with statistics
main.append(gmsg(FID, 1, nest(F_KEY, key_tcp4()) + nest(F_ACTIONS, out) + flow_attrs, seq=2))
# the other key families
main.append(gmsg(FID, 2, nest(F_KEY, key_udp6()), pid=1000, seq=3))
main.append(gmsg(FID, 3, nest(F_KEY, key_misc), pid=1000, seq=4))
main.append(gmsg(FID, 4, nest(F_KEY, key_raw) + nest(F_ACTIONS, acts_raw), pid=1000, seq=5))
# wrong sized structures
main.append(gmsg(FID, 1, nest(F_KEY, key_short) + nest(F_MASK, key_long), seq=6))
main.append(gmsg(FID, 1, nest(F_ACTIONS, acts_short), seq=7))
main.append(gmsg(FID, 1, nest(F_ACTIONS, acts_odd), seq=8))
# ENCAP: the inner key after a VLAN tag
main.append(gmsg(FID, 1, nest(F_KEY, nla(K_ETHERNET, eth), nla(K_ETHERTYPE, be16(0x8100)),
                              nest(K_ENCAP, nla(K_ETHERTYPE, be16(0x0800)), nla(K_IPV4, ipv4), nla(K_TCP, l4))), seq=9))
# NLA_F_NESTED already set by nest(); NET_BYTEORDER on a scalar, a masked
# type on a plain one, flow statistics of the wrong size, UNSPEC command
main.append(gmsg(FID, 1, nla(F_STATS, stats[:8]) + nla(F_STATS, stats + b'\0') +
                 nla(F_USED, be64(5), flags=NLA_F_NET_BYTEORDER) + nla(F_TCP_FLAGS, u8(2), flags=NLA_F_NESTED) +
                 nla(0, b'\1') + nla(77, b'\1\2\3'), seq=10))
main.append(gmsg(FID, 0, b'', ifindex=2))
main.append(rawmsg(FID, 1, b''))
main.append(rawmsg(FID, 1, b'\1\0'))
# Recursion reproducers (stack overflow before the nesting limit in
# packet-netlink.c; the 16000 deep originals are in the malformed capture): 40 levels of CLONE actions and of
# ENCAP keys, and SAMPLE -> ACTIONS chains; the attribute loop stops at
# the limit and adds a warning ("Netlink attributes nested too deeply").
main.append(gmsg(FID, 1, nla(F_ACTIONS, chain(A_CLONE, 40), flags=NLA_F_NESTED), seq=11))
main.append(gmsg(FID, 1, nla(F_KEY, chain(K_ENCAP, 40), flags=NLA_F_NESTED), seq=12))
def sample_chain(pairs):
    sample = b''
    for _ in range(pairs):
        sample = struct.pack(LE + 'HH', 4 + len(sample), S_ACTIONS) + sample
        sample = struct.pack(LE + 'HH', 4 + len(sample), A_SAMPLE) + sample
    return sample


main.append(gmsg(FID, 1, nla(F_ACTIONS, sample_chain(20), flags=NLA_F_NESTED), seq=13))
# just below and at the limit: 20 levels decode completely
main.append(gmsg(FID, 1, nla(F_ACTIONS, chain(A_CLONE, 20, out), flags=NLA_F_NESTED), seq=14))

# ovs_packet upcalls carry the same key, action and tunnel attribute
# streams and hand them to ovs_flow_dissect_key/actions/tunnel_key
PID = 0x21
main.append(family(PID, 'ovs_packet'))
main.append(gmsg(PID, 1, nla(1, bytes(range(60))) + nla(2, key_tcp4(), flags=NLA_F_NESTED) + nla(4, b'\x01\x02'),
                 seq=20))
main.append(gmsg(PID, 2, nla(2, key_udp6() + nla(K_ENCAP, nla(K_ETHERTYPE, be16(0x0800)), flags=NLA_F_NESTED), flags=NLA_F_NESTED) +
                 nla(3, acts_a, flags=NLA_F_NESTED), seq=21))
main.append(gmsg(PID, 3, nla(3, nla(A_OUTPUT, u32(1)), flags=NLA_F_NESTED) + nla(5, tunnel, flags=NLA_F_NESTED), seq=22))

# ---- malformed
mal = [family(FID, 'ovs_flow')]
# ovs_misc.py of the review: 1 octet and empty attributes on every handler
keys = b''.join(nla(t, b'\x01') for t in range(1, 32)) + nla(16, nla(1, b'\x01') + nla(8, b'')) + nla(1, nla(1, nla(2, b'\x01')))
acts = b''.join(nla(t, b'\x01') for t in range(1, 25))
acts += nla(12, nla(4, b'helper') + nla(5, nla(3, b'\x01') + nla(5, b'')) + nla(9, b'tmo'))
acts += nla(6, nla(1, b'\x01') + nla(2, nla(1, b'\x01')))
acts += nla(2, nla(1, b'\x01') + nla(2, b'') + nla(3, b'\x01'))
mal.append(gmsg(FID, 1, nla(1, keys) + nla(2, acts) + nla(3, b'\x01') + nla(5, b'\x01') + nla(9, b'') + nla(10, b'\x01')))
mal.append(gmsg(FID, 1, nla(2, nla(12, nla(4, b'')))))
# the original reproducers: 16000 levels of CLONE, ENCAP, 4000 SAMPLE pairs
mal.append(gmsg(FID, 1, nla(F_ACTIONS, chain(A_CLONE, 16000), flags=NLA_F_NESTED), seq=11))
mal.append(gmsg(FID, 1, nla(F_KEY, chain(K_ENCAP, 16000), flags=NLA_F_NESTED), seq=12))
mal.append(gmsg(FID, 1, nla(F_ACTIONS, sample_chain(4000), flags=NLA_F_NESTED), seq=13))
# one attribute cut at the end of the frame, per handler that reads a field
for t, p in [(F_USED, 4), (F_UFID_FLAGS, 2), (F_TCP_FLAGS, 0)]:
    mal.append(gmsg(FID, 1, raw(t, b'\1' * p)))
for t, p in [(K_PRIORITY, 2), (K_IN_PORT, 3), (K_VLAN, 1), (K_ETHERTYPE, 1), (K_SKB_MARK, 2), (K_TCP_FLAGS, 1),
             (K_DP_HASH, 3), (K_RECIRC_ID, 1), (K_CT_STATE, 3), (K_CT_ZONE, 1), (K_CT_MARK, 1), (K_PACKET_TYPE, 2),
             (K_IPV6_EXTHDRS, 1)]:
    mal.append(gmsg(FID, 1, nest(F_KEY, raw(t, b'\1' * p))))
for t, p in [(T_ID, 4), (T_IPV4_SRC, 2), (T_TOS, 0), (T_TP_SRC, 1), (T_IPV6_SRC, 8)]:
    mal.append(gmsg(FID, 1, nest(F_KEY, nest(K_TUNNEL, raw(t, b'\1' * p)))))
for t, p in [(A_OUTPUT, 2), (A_RECIRC, 1), (A_POP_MPLS, 1), (A_TRUNC, 3), (A_METER, 1), (A_DROP, 2)]:
    mal.append(gmsg(FID, 1, nest(F_ACTIONS, raw(t, b'\1' * p))))
mal.append(gmsg(FID, 1, nest(F_ACTIONS, nest(A_CT, raw(C_ZONE, b'\1')))))
mal.append(gmsg(FID, 1, nest(F_ACTIONS, nest(A_CT, raw(C_EVENTMASK, b'\1\2')))))
mal.append(gmsg(FID, 1, nest(F_ACTIONS, nest(A_CT, nest(C_NAT, raw(N_PROTO_MIN, b'\1'))))))
mal.append(gmsg(FID, 1, nest(F_ACTIONS, nest(A_USERSPACE, raw(U_PID, b'\1\2')))))
mal.append(gmsg(FID, 1, nest(F_ACTIONS, nest(A_SAMPLE, raw(S_PROB, b'\1\2')))))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 3, F_KEY) + b'\0' * 4))
mal.append(rawmsg(FID, 1, i32(1) + struct.pack(LE + 'HH', 0x200, F_KEY) + nla(1, b'\1')))
mal.append(sll() + struct.pack(LE + 'IHHII', 300, FID, 0, 1, 0) + genl(1, i32(1) + nla(F_PROBE)))
mal.append(sll() + nlmsg(FID, b'\x01\x01'))

write('ovs_flow', main, mal, sys.argv[1] if len(sys.argv) > 1 else '.')
