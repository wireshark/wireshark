#!/usr/bin/env python3
# AMT coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Automatic Multicast Tunneling (RFC 7450), UDP port 2268, between a
gateway and a relay: Relay Discovery, Relay Advertisement (IPv4, IPv6 and
an address of another length), Request (IPv4 and IPv6 flavour), Membership
Query (with an IGMPv3 or MLDv2 general query, with and without the gateway
port and address of the G flag), Membership Update (an IGMPv3 report and an
MLDv2 report), Multicast Data (UDP/IPv4 and UDP/IPv6), Teardown, and an
unknown message type.

The reproducer of "AMT: Check the gateway address fits in a Membership
Query" (a Membership Query with the G flag and less than 18 octets after
the nonce) is an error expert info and is in the malformed capture. The
AMT/IP/UDP/AMT nesting of that reproducer (62 AMT layers: 61 Multicast Data
around a Relay Discovery) decodes without an error and is in the main
capture.

Usage: mkamt.py [<output directory>]

Writes amt-coverage.pcap and amt-coverage-malformed.pcap. Every packet is
built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, inet_checksum, ip6, ipv4, ipv6, l4_checksum, udp, write_pcap  # noqa: E402

GW = '192.0.2.1'
RELAY = '198.51.100.7'
GW6 = '2001:db8::1'
RELAY6 = '2001:db8:1::7'
GW_MAC = '02:00:00:00:00:01'
RELAY_MAC = '02:00:00:00:00:02'
PORT = 2268
GW_PORT = 40000
MAC6 = bytes.fromhex('a1b2c3d4e5f6')


def to_relay(payload, v6=False):
    if v6:
        return eth(ipv6(udp(payload, GW_PORT, PORT, GW6, RELAY6), 17, src=GW6, dst=RELAY6),
                   0x86dd, dst=RELAY_MAC, src=GW_MAC)
    return eth(ipv4(udp(payload, GW_PORT, PORT, GW, RELAY), 17, src=GW, dst=RELAY), 0x0800,
               dst=RELAY_MAC, src=GW_MAC)


def to_gw(payload, v6=False):
    if v6:
        return eth(ipv6(udp(payload, PORT, GW_PORT, RELAY6, GW6), 17, src=RELAY6, dst=GW6),
                   0x86dd, dst=GW_MAC, src=RELAY_MAC)
    return eth(ipv4(udp(payload, PORT, GW_PORT, RELAY, GW), 17, src=RELAY, dst=GW), 0x0800,
               dst=GW_MAC, src=RELAY_MAC)


def igmp_query():
    """IPv4 packet with an IGMPv3 general query (router alert option)."""
    igmp = struct.pack('!BBHIBBH', 0x11, 100, 0, 0, 0x02, 125, 0)
    igmp = igmp[:2] + struct.pack('!H', inet_checksum(igmp)) + igmp[4:]
    return ipv4(igmp, 2, src='192.0.2.9', dst='224.0.0.1', ttl=1, options=bytes.fromhex('94040000'))


def igmp_report():
    """IPv4 packet with an IGMPv3 membership report (one record)."""
    rec = struct.pack('!BBH4s4s', 2, 0, 1, bytes((232, 1, 1, 1)), bytes((192, 0, 2, 9)))
    igmp = struct.pack('!BBHHH', 0x22, 0, 0, 0, 1) + rec
    igmp = igmp[:2] + struct.pack('!H', inet_checksum(igmp)) + igmp[4:]
    return ipv4(igmp, 2, src='192.0.2.1', dst='224.0.0.22', ttl=1, options=bytes.fromhex('94040000'))


def mld_query():
    """IPv6 packet with an MLDv2 general query (hop-by-hop router alert)."""
    mld = struct.pack('!BBHHH16sBBH', 130, 0, 0, 10000, 0, bytes(16), 2, 125, 0)
    src, dst = 'fe80::1', 'ff02::1'
    mld = mld[:2] + struct.pack('!H', l4_checksum(mld, 58, src, dst)) + mld[4:]
    hbh = bytes.fromhex('3a00 0502 0000 0100'.replace(' ', ''))
    return ipv6(hbh + mld, 0, src=src, dst=dst, hlim=1)


def mld_report():
    rec = struct.pack('!BBH16s', 2, 0, 0, ip6('ff3e::8000:1'))
    mld = struct.pack('!BBHHH', 143, 0, 0, 0, 1) + rec
    src, dst = 'fe80::2', 'ff02::16'
    mld = mld[:2] + struct.pack('!H', l4_checksum(mld, 58, src, dst)) + mld[4:]
    hbh = bytes.fromhex('3a00 0502 0000 0100'.replace(' ', ''))
    return ipv6(hbh + mld, 0, src=src, dst=dst, hlim=1)


def mcast_udp4(payload=b'hello multicast'):
    return ipv4(udp(payload, 5000, 5001, '203.0.113.5', '232.1.1.1'), 17, src='203.0.113.5', dst='232.1.1.1')


def mcast_udp6(payload=b'hello multicast v6'):
    return ipv6(udp(payload, 5000, 5001, '2001:db8:5::5', 'ff3e::8000:1'), 17, src='2001:db8:5::5', dst='ff3e::8000:1')


def hdr(mtype, version=0):
    return bytes([(version << 4) | mtype])


def build():
    f, m = [], []
    nonce = 0x12345678
    gw_addr = ip6('2001:db8:2::99')
    gw_info = struct.pack('!H', 41234) + gw_addr
    # Relay Discovery, Relay Advertisement with an IPv4, an IPv6 and an odd address
    f.append(to_relay(hdr(1) + bytes(3) + struct.pack('!I', nonce)))
    f.append(to_gw(hdr(2) + bytes(3) + struct.pack('!I', nonce) + bytes((198, 51, 100, 7))))
    f.append(to_gw(hdr(2) + bytes(3) + struct.pack('!I', nonce) + ip6('2001:db8:1::7'), v6=True))
    f.append(to_gw(hdr(2) + bytes(3) + struct.pack('!I', nonce) + bytes(6)))
    f.append(to_relay(hdr(1) + bytes([1, 2, 3]) + struct.pack('!I', 0xffffffff), v6=True))
    # Request: IPv4 (P) and IPv6 flavour, reserved bits set
    f.append(to_relay(hdr(3) + b'\x01' + bytes(2) + struct.pack('!I', nonce)))
    f.append(to_relay(hdr(3) + b'\x00' + bytes(2) + struct.pack('!I', nonce), v6=True))
    f.append(to_relay(hdr(3) + b'\xff' + b'\x12\x34' + struct.pack('!I', 1)))
    # Membership Query: IGMPv3, MLDv2, with the L flag, with the G flag and the gateway address
    f.append(to_gw(hdr(4) + b'\x00' + MAC6 + struct.pack('!I', nonce) + igmp_query()))
    f.append(to_gw(hdr(4) + b'\x00' + MAC6 + struct.pack('!I', nonce) + mld_query(), v6=True))
    f.append(to_gw(hdr(4) + b'\x02' + MAC6 + struct.pack('!I', nonce + 1) + igmp_query()))
    f.append(to_gw(hdr(4) + b'\x01' + MAC6 + struct.pack('!I', nonce + 2) + igmp_query() + gw_info))
    f.append(to_gw(hdr(4) + b'\x03' + MAC6 + struct.pack('!I', nonce + 3) + mld_query() + gw_info, v6=True))
    f.append(to_gw(hdr(4) + b'\xfd' + MAC6 + struct.pack('!I', nonce + 4) + igmp_query() + gw_info))
    # Membership Update, Multicast Data, Teardown
    f.append(to_relay(hdr(5) + b'\x00' + MAC6 + struct.pack('!I', nonce) + igmp_report()))
    f.append(to_relay(hdr(5) + b'\x80' + MAC6 + struct.pack('!I', nonce) + mld_report(), v6=True))
    f.append(to_gw(hdr(6) + b'\x00' + mcast_udp4()))
    f.append(to_gw(hdr(6) + b'\x00' + mcast_udp6(), v6=True))
    f.append(to_gw(hdr(6) + b'\x7f' + mcast_udp4(bytes(range(64)))))
    f.append(to_relay(hdr(7) + b'\x00' + MAC6 + struct.pack('!I', nonce) + gw_info))
    f.append(to_relay(hdr(7) + b'\x00' + MAC6 + struct.pack('!I', nonce + 1) + gw_info, v6=True))
    # Unknown types and a version other than 0
    f.append(to_relay(hdr(0) + b'\x01\x02\x03'))
    f.append(to_relay(hdr(8) + b'unknown data'))
    f.append(to_relay(hdr(15, version=1) + bytes(7)))
    f.append(to_relay(hdr(1, version=2) + bytes(3) + struct.pack('!I', nonce)))
    # The nested AMT/IP/UDP/AMT chain of the reproducer, 62 AMT layers, which
    # reaches the layer limit without an error
    inner = hdr(6) + b'\x00' + ipv4(udp(b'\x01\x00\x00\x00\x00\x00\x00\x01', PORT, PORT, GW, RELAY), 17, src=GW, dst=RELAY)
    for _ in range(60):
        inner = hdr(6) + b'\x00' + ipv4(udp(inner, PORT, PORT, GW, RELAY), 17, src=GW, dst=RELAY)
    f.append(to_relay(inner))

    # Malformed: the reproducer (G flag, less than 18 octets after the nonce)
    base = hdr(4) + b'\x01' + MAC6 + struct.pack('!I', nonce)
    m.append(to_gw(base + b'\x41'))
    m.append(to_gw(base + b'\x41' + bytes(9)))
    m.append(to_gw(base))
    m.append(to_gw(base + bytes(17)))
    m.append(to_gw(base + igmp_query()))              # the G flag without the gateway address
    # Truncated messages of every type
    full = {
        1: hdr(1) + bytes(3) + struct.pack('!I', nonce),
        2: hdr(2) + bytes(3) + struct.pack('!I', nonce) + bytes(4),
        3: hdr(3) + bytes(3) + struct.pack('!I', nonce),
        4: hdr(4) + b'\x00' + MAC6 + struct.pack('!I', nonce) + igmp_query(),
        5: hdr(5) + b'\x00' + MAC6 + struct.pack('!I', nonce) + igmp_report(),
        6: hdr(6) + b'\x00' + mcast_udp4(),
        7: hdr(7) + b'\x00' + MAC6 + struct.pack('!I', nonce) + gw_info,
    }
    for mt, pkt in full.items():
        for n in (1, 2, 4, 6, 9, 12, 15, 20, 30):
            if n < len(pkt):
                m.append(to_relay(pkt[:n]))
    # Cut by the capture, not by the sender
    fr = to_relay(full[7])
    m.append((fr[:len(fr) - 10], len(fr)))
    fr = to_gw(full[4])
    m.append((fr[:len(fr) - 8], len(fr)))
    return f, m


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean, malformed = build()
    write_pcap(os.path.join(out, 'amt-coverage.pcap'), clean)
    write_pcap(os.path.join(out, 'amt-coverage-malformed.pcap'), malformed)
    print('%d + %d frames' % (len(clean), len(malformed)), file=sys.stderr)


if __name__ == '__main__':
    main()
