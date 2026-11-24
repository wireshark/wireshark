#!/usr/bin/env python3
# Generates test/captures/netlink_net_dm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the net_dm (network drop monitor, Generic Netlink) coverage captures.

Usage: mknet_dm.py <outdir>
Writes netlink-net_dm-coverage.pcap (LINKTYPE_NETLINK, 253) and
netlink-net_dm-coverage-malformed.pcapng.
Everything is built with struct; nothing comes from a real network.
"""
import os
import struct
import sys

# ---- helpers (pcap/pcapng writers and netlink builders) ----------------
ARPHRD_NETLINK = 824
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_DUMP = 0x300
NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000
FAMILY_ID = 0x22
FAMILY_NAME = b'NET_DM'


def pcap(fn, pkts, linktype=253):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(p), len(p)))
            f.write(p)


def pcapng(fn, pkts):
    """pkts: list of (linktype, bytes); one interface per link type."""
    def blk(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifs = {}
    for lt, _ in pkts:
        if lt not in ifs:
            ifs[lt] = len(ifs)
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, p) in enumerate(pkts):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifs[lt], ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    with open(fn, 'wb') as f:
        f.write(out)


def sll(proto=NETLINK_GENERIC):
    return struct.pack('>HHH8sH', 4, ARPHRD_NETLINK, 0, b'\0' * 8, proto)


class Enc:
    def __init__(self, big=False):
        self.e = '>' if big else '<'

    def attr(self, t, payload=b'', flags=0):
        l = 4 + len(payload)
        return struct.pack(self.e + 'HH', l, t | flags) + payload + b'\0' * ((4 - l % 4) % 4)

    def u8(self, t, v, flags=0):
        return self.attr(t, struct.pack('B', v), flags)

    def u16(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'H', v), flags)

    def u32(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'I', v), flags)

    def u64(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'Q', v), flags)

    def s(self, t, v, flags=0):
        return self.attr(t, v + b'\0', flags)

    def nlmsg(self, mtype, payload, flags=NLM_F_REQUEST, seq=1, pid=0):
        return struct.pack(self.e + 'IHHII', 16 + len(payload), mtype, flags, seq, pid) + payload

    def genl(self, cmd, attrs=b'', version=1):
        return struct.pack(self.e + 'BBH', cmd, version, 0) + attrs

    def frame(self, mtype, cmd, attrs=b'', **kw):
        return sll() + self.nlmsg(mtype, self.genl(cmd, attrs), **kw)


def newfamily(e, fid, name, **kw):
    """CTRL_CMD_NEWFAMILY (1) telling the dissector fid -> name."""
    return e.frame(GENL_ID_CTRL, 1, e.u16(1, fid) + e.s(2, name), **kw)
# ---- end helpers --------------------------------------------------------

LE = Enc()
BE = Enc(True)

(CMD_UNSPEC, CMD_ALERT, CMD_CONFIG, CMD_START, CMD_STOP, CMD_PACKET_ALERT, CMD_CONFIG_GET,
 CMD_CONFIG_NEW, CMD_STATS_GET, CMD_STATS_NEW) = range(10)
(A_UNSPEC, A_ALERT_MODE, A_PC, A_SYMBOL, A_IN_PORT, A_TIMESTAMP, A_PROTO, A_PAYLOAD, A_PAD,
 A_TRUNC_LEN, A_ORIG_LEN, A_QUEUE_LEN, A_STATS, A_HW_STATS, A_ORIGIN, A_HW_TRAP_GROUP_NAME,
 A_HW_TRAP_NAME, A_HW_ENTRIES, A_HW_ENTRY, A_HW_TRAP_COUNT, A_SW_DROPS, A_HW_DROPS,
 A_FLOW_ACTION_COOKIE, A_REASON) = range(24)
PORT_IFINDEX, PORT_NAME = 0, 1
STATS_DROPPED = 0

ETH_P_IP, ETH_P_IPV6, ETH_P_802_2, ETH_P_ALL = 0x0800, 0x86dd, 0x0004, 0x0003
LLC = b'\x0a\x0a\x03\x00'


def csum(b):
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4_udp(sport=5000, dport=5001, data=b'drop-me!'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                    bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + udp


def ipv6_udp(data=b'drop-v6'):
    src, dst = bytes(range(1, 17)), bytes(range(17, 33))
    udp = struct.pack('>HHHH', 5000, 5001, 8 + len(data), 0) + data
    pseudo = src + dst + struct.pack('>IBBBB', len(udp), 0, 0, 0, 17)
    pad = b'\0' if len(udp) % 2 else b''
    udp = udp[:6] + struct.pack('>H', csum(pseudo + udp + pad)) + udp[8:]
    return struct.pack('>IHBB', 0x60000000, len(udp), 17, 64) + src + dst + udp


def eth(ethertype, payload):
    return bytes.fromhex('020000000002020000000001') + struct.pack('>H', ethertype) + payload


def t(cmd, attrs=b'', e=LE, **kw):
    return e.frame(FAMILY_ID, cmd, attrs, **kw)


def nest(e, depth, atype=A_HW_ENTRIES):
    """depth levels of attribute atype, each holding the next; the
    innermost holds a trap name."""
    inner = e.s(A_HW_TRAP_NAME, b'deepest')
    for _ in range(depth):
        inner = e.attr(atype, inner, NLA_F_NESTED)
    return inner


def deep(depth, e=LE):
    """The reproducer of the unbounded recursion: HW_ENTRIES nested
    depth times with 4 byte headers, each header's length covering the rest."""
    total = 4 * depth
    body = b''.join(struct.pack('<HH', min(total - 4 * i, 0xffff), A_HW_ENTRIES) for i in range(depth))
    return t(CMD_ALERT, body)


def main_frames():
    f = []
    f.append(newfamily(LE, FAMILY_ID, FAMILY_NAME))                                # 1
    # 2-6: configuration commands, with and without payload
    f.append(t(CMD_CONFIG, LE.u8(A_ALERT_MODE, 1) + LE.u32(A_TRUNC_LEN, 128) +
               LE.u32(A_QUEUE_LEN, 4096), flags=NLM_F_REQUEST | NLM_F_ACK))
    f.append(t(CMD_START))
    f.append(t(CMD_STOP))
    f.append(t(CMD_CONFIG_GET))
    f.append(t(CMD_CONFIG_NEW, LE.u8(A_ALERT_MODE, 0) + LE.u32(A_TRUNC_LEN, 0) +
               LE.u32(A_QUEUE_LEN, 1000), pid=77))
    # 7: summary alert
    f.append(t(CMD_ALERT, LE.u64(A_PC, 0xffffffff81a3b2c0) + LE.s(A_SYMBOL, b'kfree_skb_reason+0x2c/0x50'),
               pid=77))
    # 8: packet alert, software drop, Ethernet payload (the bytes 12-13 match the protocol)
    f.append(t(CMD_PACKET_ALERT,
               LE.u16(A_ORIGIN, 0) + LE.u64(A_PC, 0xffffffff81a3b2c0) +
               LE.s(A_SYMBOL, b'ip_rcv_finish+0x40') +
               LE.attr(A_IN_PORT, LE.u32(PORT_IFINDEX, 2) + LE.s(PORT_NAME, b'eth0') +
                       LE.u32(7, 1), NLA_F_NESTED) +
               LE.u64(A_TIMESTAMP, 1700000000123456789) + LE.u16(A_PROTO, ETH_P_IP) +
               LE.u32(A_ORIG_LEN, 64) + LE.u32(A_TRUNC_LEN, 64) + LE.u32(A_PAD, 0) +
               LE.s(A_REASON, b'NO_SOCKET') +
               LE.attr(A_PAYLOAD, eth(ETH_P_IP, ipv4_udp())), pid=77))
    # 9: hardware drop with a flow action cookie and a raw IPv4 payload
    # (too short for Ethernet or without matching bytes: the Ethertype table is used)
    f.append(t(CMD_PACKET_ALERT,
               LE.u16(A_ORIGIN, 1) + LE.s(A_HW_TRAP_GROUP_NAME, b'l3_drops') +
               LE.s(A_HW_TRAP_NAME, b'blackhole_route') + LE.u32(A_HW_TRAP_COUNT, 9) +
               LE.attr(A_FLOW_ACTION_COOKIE, bytes(range(12))) + LE.u16(A_PROTO, ETH_P_IP) +
               LE.attr(A_IN_PORT, LE.s(PORT_NAME, b'swp1'), NLA_F_NESTED) +
               LE.attr(A_PAYLOAD, ipv4_udp()), pid=77))
    # 10: raw IPv6 payload
    f.append(t(CMD_PACKET_ALERT, LE.u16(A_PROTO, ETH_P_IPV6) + LE.attr(A_PAYLOAD, ipv6_udp()), pid=77))
    # 11: protocol 802.2 with an 802.3 frame (length 4 and an LLC header)
    f.append(t(CMD_PACKET_ALERT, LE.u16(A_PROTO, ETH_P_802_2) +
               LE.attr(A_PAYLOAD, eth(4, LLC)), pid=77))
    # 12: protocol 802.2 without a matching Ethernet frame; short payload and an unknown Ethertype
    f.append(t(CMD_PACKET_ALERT, LE.u16(A_PROTO, ETH_P_802_2) + LE.attr(A_PAYLOAD, b'\x01\x02\x03\x04'), pid=77))
    f.append(t(CMD_PACKET_ALERT, LE.u16(A_PROTO, 0x9999) + LE.attr(A_PAYLOAD, bytes(range(10))), pid=77))
    # 14: protocol 3 (ETH_P_ALL) goes through the sll.ltype table: Ethernet
    f.append(t(CMD_PACKET_ALERT, LE.u16(A_PROTO, ETH_P_ALL) +
               LE.attr(A_PAYLOAD, eth(ETH_P_IP, ipv4_udp(data=b'ethernet'))), pid=77))
    # 15: payload before the protocol attribute (protocol 0, nothing registered)
    f.append(t(CMD_PACKET_ALERT, LE.attr(A_PAYLOAD, bytes(range(20))) + LE.u16(A_PROTO, ETH_P_IP), pid=77))
    # 17-18: statistics
    f.append(t(CMD_STATS_GET))
    f.append(t(CMD_STATS_NEW,
               LE.attr(A_STATS, LE.u64(STATS_DROPPED, 12345) + LE.u32(5, 1), NLA_F_NESTED) +
               LE.attr(A_HW_STATS, LE.u64(STATS_DROPPED, 6789), NLA_F_NESTED), pid=77))
    # 19: hardware drop summary: entries with entry, count; SW/HW drop flags
    entry1 = LE.attr(A_HW_ENTRY, LE.s(A_HW_TRAP_GROUP_NAME, b'l2_drops') + LE.s(A_HW_TRAP_NAME, b'smac_mc') +
                     LE.u32(A_HW_TRAP_COUNT, 3), NLA_F_NESTED)
    entry2 = LE.attr(A_HW_ENTRY, LE.s(A_HW_TRAP_GROUP_NAME, b'l3_drops') + LE.s(A_HW_TRAP_NAME, b'ttl_value_is_too_small') +
                     LE.u32(A_HW_TRAP_COUNT, 11), NLA_F_NESTED)
    f.append(t(CMD_ALERT, LE.attr(A_HW_ENTRIES, entry1 + entry2, NLA_F_NESTED) +
               LE.attr(A_SW_DROPS) + LE.attr(A_HW_DROPS) + LE.attr(A_UNSPEC, b'\0\0\0\0') +
               LE.attr(99, b'??'), pid=77))
    # 20-22: attribute lengths that do not match (reproducer of "netlink-net_dm: Check
    # attribute lengths"): PC, TIMESTAMP and PROTO are shown as raw data
    f.append(t(CMD_PACKET_ALERT, LE.u32(A_PC, 0x11223344) +
               LE.u32(A_TIMESTAMP, 0xdeadbeef) + LE.u64(A_PROTO, 0x0800) + LE.u32(A_ORIG_LEN, 9), pid=77))
    f.append(t(CMD_PACKET_ALERT, LE.attr(A_PC, b'\x01\x02') + LE.attr(A_TIMESTAMP) + LE.attr(A_PROTO, b'\x08') +
               LE.u32(A_ORIG_LEN, 9), pid=77))
    f.append(t(CMD_PACKET_ALERT, LE.u16(A_PROTO, ETH_P_IP) +
               LE.attr(A_SYMBOL) + LE.attr(A_REASON), pid=77))
    # 23-24: nested HW_ENTRIES 20 levels deep, decoded in full
    # and 40 levels (more than the limit of 32 of packet-netlink.c): a warning expert info
    f.append(t(CMD_ALERT, LE.attr(A_HW_ENTRIES, nest(LE, 19), NLA_F_NESTED), pid=77))
    f.append(t(CMD_ALERT, LE.attr(A_HW_ENTRIES, nest(LE, 39), NLA_F_NESTED), pid=77))
    # 25: attribute flags on net_dm attributes
    f.append(t(CMD_PACKET_ALERT, LE.s(A_SYMBOL, b'flagged', NLA_F_NESTED) +
               LE.attr(A_TRUNC_LEN, struct.pack('>I', 77), NLA_F_NET_BYTEORDER) +
               LE.attr(A_TIMESTAMP, struct.pack('>Q', 5 * 1000000000 + 6), NLA_F_NET_BYTEORDER) +
               LE.attr(A_ORIGIN, struct.pack('>H', 1), NLA_F_NET_BYTEORDER), pid=77))
    # 26: big endian message
    f.append(t(CMD_PACKET_ALERT, BE.u8(A_ALERT_MODE, 1) + BE.u64(A_PC, 0x1000) + BE.s(A_SYMBOL, b'be_symbol') +
               BE.u64(A_TIMESTAMP, 1700000001000000007) + BE.u16(A_PROTO, ETH_P_IP) +
               BE.u32(A_TRUNC_LEN, 99) + BE.u16(A_ORIGIN, 0) +
               BE.attr(A_PAYLOAD, eth(ETH_P_IP, ipv4_udp())), e=BE, pid=77))
    # 27: two messages in one packet
    f.append(sll() + LE.nlmsg(FAMILY_ID, LE.genl(CMD_CONFIG_NEW, LE.u8(A_ALERT_MODE, 1)), seq=5, pid=1) +
             LE.nlmsg(FAMILY_ID, LE.genl(CMD_STOP), seq=6, pid=1))
    # 28: unknown command
    f.append(t(60, LE.u32(A_TRUNC_LEN, 1)))
    return f


def malformed():
    f = [(253, newfamily(LE, FAMILY_ID, FAMILY_NAME))]
    # The reproducer: HW_ENTRIES nested 16383 times (frame 2 of the review's net_dm_recursion.pcap)
    f.append((253, deep(16383)))
    f.append((253, deep(100)))
    # Ethertype table with a payload that is not what the protocol says; empty payload
    f.append((253, t(CMD_PACKET_ALERT, LE.u16(A_PROTO, ETH_P_IP) + LE.attr(A_PAYLOAD, eth(ETH_P_IPV6, ipv6_udp())))))
    f.append((253, t(CMD_PACKET_ALERT, LE.u16(A_PROTO, ETH_P_IP) + LE.attr(A_PAYLOAD))))
    # Fixed width fields with the wrong length: the field type refuses them
    f.append((253, t(CMD_CONFIG, LE.u32(A_ALERT_MODE, 1))))
    f.append((253, t(CMD_PACKET_ALERT, LE.u32(A_ORIGIN, 1))))
    f.append((253, t(CMD_PACKET_ALERT, LE.attr(A_IN_PORT, LE.u16(PORT_IFINDEX, 2), NLA_F_NESTED))))
    f.append((253, t(CMD_PACKET_ALERT, LE.u16(A_TRUNC_LEN, 2))))
    f.append((253, t(CMD_STATS_NEW, LE.attr(A_STATS, LE.u32(STATS_DROPPED, 2), NLA_F_NESTED))))
    # attribute lengths: below the header size, beyond the message, trailing bytes
    f.append((253, t(CMD_ALERT, LE.u32(A_TRUNC_LEN, 1) + struct.pack('<HH', 3, A_SYMBOL) + b'\0\0\0\0')))
    f.append((253, t(CMD_ALERT, LE.u32(A_TRUNC_LEN, 1) + struct.pack('<HH', 400, A_SYMBOL) + b'abcd')))
    f.append((253, t(CMD_ALERT, LE.u32(A_TRUNC_LEN, 1) + b'\0\0')))
    # nested attribute longer than its parent
    f.append((253, t(CMD_ALERT, struct.pack('<HH', 12, A_IN_PORT | NLA_F_NESTED) +
                     struct.pack('<HH', 200, PORT_NAME) + b'eth0')))
    # message length field larger than the data, below the header size, short genl header
    p = LE.genl(CMD_ALERT, LE.u32(A_TRUNC_LEN, 1))
    f.append((253, sll() + struct.pack('<IHHII', 16 + len(p) + 40, FAMILY_ID, 1, 1, 0) + p))
    f.append((253, sll() + struct.pack('<IHHII', 8, FAMILY_ID, 1, 1, 0) + p))
    f.append((253, sll() + struct.pack('<IHHII', 18, FAMILY_ID, 1, 1, 0) + b'\x01\x01'))
    return f


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'netlink-net_dm-coverage.pcap'), main_frames())
    pcapng(os.path.join(out, 'netlink-net_dm-coverage-malformed.pcapng'), malformed())


if __name__ == '__main__':
    main()
