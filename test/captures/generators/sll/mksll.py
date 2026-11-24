#!/usr/bin/env python3
# Generates test/captures/sll_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SLL dissector (packet-sll.c, Linux
cooked capture v1 and v2).

Usage: mksll.py <output directory>

SLL is reached by link-layer type (LINKTYPE_LINUX_SLL 113 and
LINKTYPE_LINUX_SLL2 276), so no port or preference is needed. The pcapng
file has two interfaces, one of each type. Every packet is built with
struct; nothing is captured.

Writes:
  sll-coverage.pcapng            SLL v1 (interface 0) and SLL v2
                                 (interface 1): every packet type, link
                                 layer address lengths 0-10, Ethernet
                                 types, Linux protocol types, GRE, netlink
                                 and radiotap hatypes
  sll-coverage-malformed.pcapng  headers cut short
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pcaplib import csum, eth, ip4, LT_SLL, MAC_A, pcapng

ARPHRD_ETHER, ARPHRD_IPGRE, ARPHRD_IP6GRE, ARPHRD_NETLINK = 1, 778, 823, 824
ARPHRD_IEEE80211_RADIOTAP, ARPHRD_IEEE802154, ARPHRD_PPP, ARPHRD_CAN = 803, 804, 512, 280
ARPHRD_LOOPBACK, ARPHRD_NONE = 772, 0xfffe


def sll1(payload, proto, hatype=ARPHRD_ETHER, pkttype=0, addr=b'\x02\0\0\0\0\x01'):
    return struct.pack('!HHH', pkttype, hatype, len(addr)) + addr[:8].ljust(8, b'\0') + \
        struct.pack('!H', proto) + payload


def sll2(payload, proto, hatype=ARPHRD_ETHER, pkttype=0, addr=b'\x02\0\0\0\0\x01', ifindex=2):
    return struct.pack('!HHIHBB', proto, 0, ifindex, hatype, pkttype, len(addr)) + \
        addr[:8].ljust(8, b'\0') + payload


def ipv4_udp(sport=1000, dport=9, data=b'hello', src='192.0.2.1', dst='192.0.2.2'):
    return ip4(struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data, 17, src, dst)


def ipv6_udp(data=b'hello'):
    s = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [1])
    d = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [2])
    u = struct.pack('!HHHH', 1000, 9, 8 + len(data), 0) + data
    ck = csum(s + d + struct.pack('!II', len(u), 17) + u) or 0xffff
    u = u[:6] + struct.pack('!H', ck) + u[8:]
    return struct.pack('!IHBB', 0x60000000, len(u), 17, 64) + s + d + u


ARP = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC_A, b'\xc0\0\2\1', b'\0' * 6, b'\xc0\0\2\2')


def both(build, payload, proto, **kw):
    return [(0, build[0](payload, proto, **kw)), (1, build[1](payload, proto, **kw))]


def main(out):
    fr = []
    b = (sll1, sll2)
    ip = ipv4_udp()
    # every packet type, including an unknown one
    for pt in range(0, 6):
        fr += both(b, ip, 0x0800, pkttype=pt)
    # link-layer address lengths 0, 4 (IPv4), 6 (Ethernet), 8, 10
    for a in (b'', b'\xc0\0\2\1', b'\x02\0\0\0\0\x01', b'\x01\x02\x03\x04\x05\x06\x07\x08'):
        fr += both(b, ip, 0x0800, addr=a)
    fr.append((0, struct.pack('!HHH', 0, ARPHRD_ETHER, 10) + bytes(range(8)) + struct.pack('!H', 0x0800) + ip))
    fr.append((1, struct.pack('!HHIHBB', 0x0800, 0, 2, ARPHRD_ETHER, 0, 10) + bytes(range(8)) + ip))
    # Ethertypes: IPv4, ARP, IPv6, with trailing padding, unknown
    fr += both(b, ARP, 0x0806)
    fr += both(b, ipv6_udp(), 0x86dd)
    fr += both(b, ip + b'\0' * 6, 0x0800)
    fr += both(b, b'\x01\x02\x03', 0x88b5)
    # Linux protocol types (<= 1536): 802.3, Ethernet, 802.2, PPP HDLC, CAN, CAN FD,
    # IrDA LAP, ISI, 802.15.4, MCTP, unknown 0 and 1536
    llc = bytes([0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]) + ip
    can = struct.pack('>IBBBB', 0x123, 8, 0, 0, 0) + b'\x01\x02\x03\x04\0\0\0\0'
    ipx = struct.pack('>HHBB', 0xffff, 30 + 4, 0, 0) + struct.pack('>I6sH', 1, b'\xff' * 6, 0x4001) + \
        struct.pack('>I6sH', 2, b'\x02\0\0\0\0\1', 0x4000) + b'abcd'
    ack11 = bytes([0xd4, 0, 0, 0]) + MAC_A
    wpan = bytes([0x02, 0x00, 0x01])
    crc = 0
    for x in wpan:                       # CRC-16/KERMIT frame check sequence
        crc ^= x
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    wpan += struct.pack('<H', crc)
    canfd = struct.pack('>IBBBB', 0x123, 4, 0, 0, 0) + b'\x01\x02\x03\x04'
    for proto, pl in ((0x0001, ipx), (0x0003, eth(ip)), (0x0004, llc), (0x0007, b'\xff\x03\x00\x21' + ip),
                      (0x000c, can), (0x000d, canfd), (0x0017, b'\xfe\x01'), (0x00f6, wpan), (0x00fa, b'\x00\x01\x02\x03'), (0x0000, b'\x01'),
                      (0x0600, b'\x02'), (0x0005, b'\x03')):
        fr += both(b, pl, proto)
    # hardware types that are dissected before the protocol type
    radiotap = struct.pack('<BBHI', 0, 0, 8, 0) + ack11
    fr += both(b, radiotap, 0, hatype=ARPHRD_IEEE80211_RADIOTAP)
    fr += both(b, wpan, 0, hatype=ARPHRD_IEEE802154)
    fr += both(b, b'\xff\x03\x00\x21' + ip, 0, hatype=ARPHRD_PPP)
    # GRE and IP6GRE hardware types: protocol is a GRE protocol type
    fr += both(b, ip, 0x0800, hatype=ARPHRD_IPGRE)
    fr += both(b, ipv6_udp(), 0x86dd, hatype=ARPHRD_IP6GRE)
    fr += both(b, ip, 0x0800, hatype=ARPHRD_IP6GRE)
    fr += both(b, ARP, 0x0806, hatype=ARPHRD_IPGRE)
    fr += both(b, ip, 0x1234, hatype=ARPHRD_IPGRE)        # unknown GRE protocol
    # netlink: the whole frame goes to the netlink dissector (16 octets of
    # nlmsghdr: NLMSG_DONE, 20 octets)
    nl = struct.pack('<IHHII', 20, 3, 2, 1, 0) + struct.pack('<i', 0)
    fr += both(b, nl, 0, hatype=ARPHRD_NETLINK)
    fr += both(b, b'', 0x0000, hatype=ARPHRD_LOOPBACK)
    fr += both(b, ip, 0x0800, hatype=ARPHRD_LOOPBACK)
    fr += both(b, ip, 0x0800, hatype=ARPHRD_NONE)
    pcapng(os.path.join(out, 'sll-coverage.pcapng'), fr, (LT_SLL, 276))
    print('%d frames: odd = SLL v1, even = SLL v2 (interface 0 / 1) in pairs of two' % len(fr))

    mal = [(0, sll1(ip, 0x0800)[:15]), (1, sll2(ip, 0x0800)[:19]), (0, sll1(b'', 0x0800)),
           (1, sll2(b'', 0x0800)), (0, sll1(b'\x45', 0x0800)), (0, sll1(b'', 0x0001)),
           (0, sll1(b'', 0, hatype=ARPHRD_NETLINK)), (1, sll2(b'\0' * 4, 0, hatype=ARPHRD_NETLINK)),
           (0, sll1(b'\x01', 0x0800, hatype=ARPHRD_IPGRE)), (0, sll1(b'\x01\x02', 0x00f5)), (1, sll2(b'\x01\x02', 0x00f5)), (0, sll1(b'\x01', 0x0001)), (0, sll1(b'\x01', 0x000c)), (0, sll1(b'\x01', 0x0004)), (0, sll1(b'', 0, hatype=ARPHRD_IEEE80211_RADIOTAP))]
    pcapng(os.path.join(out, 'sll-coverage-malformed.pcapng'), mal, (LT_SLL, 276))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
