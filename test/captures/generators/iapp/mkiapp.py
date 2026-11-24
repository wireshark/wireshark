#!/usr/bin/env python3
# Generates test/captures/iapp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-iapp.c (IAPP, UDP port 2313).
Usage: mkiapp.py <outdir>"""
import struct
import sys
import os
from pylib import A, B, eth_udp, ip4, Pcap

def pdu(t, v):
    return struct.pack('>BH', t, len(v)) + v

def iapp(typ, pdus, ver=1):
    return bytes([ver, typ]) + b''.join(pdus)

def u16(x): return struct.pack('>H', x)
def u32(x): return struct.pack('>I', x)

BSSID = bytes.fromhex('0200000000a1')
OLD = bytes.fromhex('0200000000a2')
MS = bytes.fromhex('0200000000b1')

def auth_items(user=b'alice'):
    return b''.join([
        pdu(0x01, b'\x01'),                       # status authenticated
        pdu(0x02, user),                          # user name
        pdu(0x03, b'provider.example'),           # provider name
        pdu(0x04, u32(1000)), pdu(0x05, u32(2000)),      # packets
        pdu(0x06, u32(300000)), pdu(0x07, u32(400000)),  # octets
        pdu(0x08, u32(3600)), pdu(0x09, u32(7200)),      # times
        pdu(0x0a, u32(1 << 20)), pdu(0x0b, u32(86400)),  # volume limit, accounting cycle
        pdu(0x0c, u32(1)), pdu(0x0d, u32(2)),            # gigawords
        pdu(0x0e, ip4('192.0.2.77')),                    # client address
        pdu(0x55, b'\x01\x02'),                          # unknown authentication item
        pdu(0xff, bytes([0xaa] * 16)),                   # authenticator (placeholder)
    ])

def f(payload, sport=2313, dport=2313):
    return eth_udp(sport, dport, payload)

def main(out):
    p = Pcap(1)
    # Announce request with the access point's PDUs, DSSS
    p.add(f(iapp(0, [pdu(0, b'ExampleNet'), pdu(1, BSSID), pdu(4, b'\x60'),
                     pdu(5, u16(30)), pdu(6, u16(1000)), pdu(7, u16(42)),
                     pdu(0x10, b'\x02'), pdu(0x11, b'\x30'), pdu(0x12, b'\x06'),
                     pdu(0x13, u16(100)), pdu(0x80, bytes.fromhex('00505a'))])))
    # Announce response, forwarding only, WEP only, neither
    p.add(f(iapp(1, [pdu(0, b'ExampleNet'), pdu(4, b'\x40')])))
    p.add(f(iapp(1, [pdu(4, b'\x20')])))
    p.add(f(iapp(1, [pdu(4, b'\x00')])))
    # Handover request and response with old BSSID and mobile station
    p.add(f(iapp(2, [pdu(2, OLD), pdu(3, MS), pdu(1, BSSID), pdu(7, u16(7)), pdu(6, u16(500))])))
    p.add(f(iapp(3, [pdu(3, MS), pdu(7, u16(7))])))
    # Every PHY type and regulatory domain; FHSS channel as pattern and sequence
    for i, (phy, dom) in enumerate([(0, 0x10), (1, 0x20), (2, 0x31), (3, 0x32), (4, 0x40), (9, 0x99)]):
        p.add(f(iapp(0, [pdu(0x10, bytes([phy])), pdu(0x11, bytes([dom])), pdu(0x12, bytes([0x45 + i])),
                         pdu(0x12, bytes([0x03]))])))
    # ELSA authentication info
    p.add(f(iapp(0, [pdu(0, b'ExampleNet'), pdu(0x81, auth_items())])))
    # Reproducer of the fix: User Name shown with the TLV length
    name = b'alice'
    p.add(f(bytes([1, 0]) + pdu(0x81, struct.pack('>BH', 0x02, len(name)) + name)))
    p.add(f(bytes([1, 0]) + pdu(0x81, struct.pack('>BH', 0x02, 17) + b'a-longer-account!')))
    # No PDUs (note expert info), unknown packet type, other version
    p.add(f(bytes([1, 0])))
    p.add(f(iapp(9, [pdu(0, b'x')], ver=2)))
    # Unknown PDU type, empty SSID
    p.add(f(iapp(0, [pdu(0x42, b'\x01\x02\x03'), pdu(0, b'')])))
    # Responses from the other direction (source port 2313 both ways)
    p.add(eth_udp(2313, 2313, iapp(1, [pdu(0, b'ReplyNet')]), rev=True, src=B, dst=A))
    p.write(os.path.join(out, 'iapp-coverage.pcap'))

    m = Pcap(1)
    # PDU header cut after the type, or after one octet of the length
    m.add(f(bytes([1, 0, 0])))
    m.add(f(bytes([1, 0, 0, 0])))
    # PDU longer than the packet
    m.add(f(iapp(0, [struct.pack('>BH', 0, 200) + b'short'])))
    # Fixed-size values with too little data
    m.add(f(iapp(0, [pdu(5, b'')])))
    m.add(f(iapp(0, [pdu(0x80, b'\x00')])))
    m.add(f(iapp(0, [pdu(4, b'')])))
    # Authentication item with a short value, and a length beyond the PDU
    m.add(f(iapp(0, [pdu(0x81, pdu(0x04, b'\x00\x00'))])))
    m.add(f(iapp(0, [pdu(0x81, struct.pack('>BH', 0x02, 500) + b'abc')])))
    # Header only 1 octet
    m.add(f(bytes([1])))
    m.write(os.path.join(out, 'iapp-coverage-malformed.pcap'))

main(sys.argv[1])
