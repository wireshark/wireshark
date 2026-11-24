#!/usr/bin/env python3
# Generates test/captures/rsip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the RSIP coverage captures: mkrsip.py <outdir>
# Every packet is built with struct; nothing comes from a real network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pk import Cap, ip4, Tcp, udp_frame

def par(ptype, val=b''):
    return struct.pack('!BH', ptype, len(val)) + val

def addr(atype, val=b''):
    return par(1, bytes([atype]) + val)

def ports(number, *plist):
    return par(2, bytes([number]) + b''.join(struct.pack('!H', p) for p in plist))

def lease(n): return par(3, struct.pack('!I', n))
def client(n): return par(4, struct.pack('!I', n))
def bind(n): return par(5, struct.pack('!I', n))
def tunnel(n): return par(6, bytes([n]))
def method(n): return par(7, bytes([n]))
def error(n): return par(8, struct.pack('!H', n))
def flow(l, r): return par(9, bytes([l, r]))
def indicator(n): return par(10, struct.pack('!H', n))
def counter(n): return par(11, struct.pack('!I', n))
def vendor(vid, sub, val): return par(12, struct.pack('!HH', vid, sub) + val)
def spi(number, v): return par(22, struct.pack('!HI', number, v))

def msg(mtype, *params, ver=1):
    body = b''.join(params)
    return struct.pack('!BBH', ver, mtype, 4 + len(body)) + body

V4 = ip4('192.0.2.77')
V4B = ip4('198.51.100.5')
MASK = ip4('255.255.255.0')
V6 = bytes.fromhex('20010db8000000000000000000000001')

def main(out):
    cap = Cap()
    n = [0]
    def u(payload, sport=4555, dport=4555):
        n[0] += 1
        cap.add(udp_frame(sport, dport, payload, ident=n[0]))
    # UDP: client (to port 4555) and server
    u(msg(2, counter(1)), 50000)
    u(msg(3, client(0x1234), lease(3600), flow(1, 3), counter(1), method(1), method(2), tunnel(1)), 4555, 50000)
    u(msg(6, client(0x1234), addr(1, V4), addr(1, V4B), ports(1, 80), counter(2), lease(600), tunnel(2)), 50000)
    u(msg(7, client(0x1234), bind(7), addr(1, V4), addr(1, V4B), ports(1, 80), lease(600), tunnel(3), counter(2), addr(3, V6)), 4555, 50000)
    u(msg(8, client(0x1234), addr(1, V4), ports(1, 5000), addr(2, MASK), ports(2, 1024), counter(3)), 50000)
    u(msg(9, client(0x1234), bind(8), addr(1, V4), ports(3, 2000, 2001, 2002), addr(1, V4B), ports(4, 3000, 3001, 3002, 3003),
          lease(1200), tunnel(1), addr(4, b'rsip.example.test'), counter(3)), 4555, 50000)
    u(msg(10, client(0x1234), bind(8), lease(900), counter(4)), 50000)
    u(msg(11, client(0x1234), bind(8), lease(900), counter(4)), 4555, 50000)
    u(msg(12, client(0x1234), bind(8), counter(5)), 50000)
    u(msg(13, client(0x1234), bind(8), counter(5)), 4555, 50000)
    u(msg(14, client(0x1234), indicator(1), counter(6)), 50000)
    u(msg(15, client(0x1234), indicator(2), counter(6), flow(2, 2)), 4555, 50000)
    u(msg(16, client(0x1234), addr(1, V4), ports(1, 22), counter(7)), 50000)
    u(msg(17, client(0x1234), bind(9), addr(1, V4), ports(1, 22), counter(7)), 4555, 50000)
    u(msg(4, client(0x1234), counter(8)), 50000)
    u(msg(5, client(0x1234), counter(8)), 4555, 50000)
    u(msg(1, error(102), counter(9), client(0x1234), bind(8)), 4555, 50000)
    # RSIPsec
    u(msg(22, client(0x1234), addr(1, V4), spi(1, 0x11223344), addr(1, V4B), spi(1, 0x55667788), counter(10)), 50000)
    u(msg(23, client(0x1234), bind(10), addr(1, V4), spi(1, 0x11223344), addr(1, V4B), spi(1, 0x55667788),
          lease(100), tunnel(1), counter(10)), 4555, 50000)
    # Vendor specific (reproducer of "RSIP: Fix the offset of the vendor
    # specific value"): the value is 6 octets after vendor id and subtype
    u(msg(2, vendor(0x0a0b, 0x0102, b'\xde\xad\xbe\xef\x00\x01'), counter(11)), 50000)
    u(msg(1, vendor(7, 8, b'x')), 4555, 50000)
    # Address variants: reserved, wildcard (no value) of each type, unknown type
    u(msg(6, addr(0), addr(1), addr(2), addr(3), addr(4), addr(5, b'\x01\x02')), 50000)
    u(msg(6, addr(2, MASK), addr(3, V6), addr(4, b'host.example.test'), addr(5)), 50000)
    # Ports variants: unspecified, any port, any N ports, a range, lists
    u(msg(8, ports(0), ports(1), ports(5)), 50000)
    u(msg(8, ports(4, 1000), ports(1, 7), ports(2, 9000, 9001, 9002), ports(8, 1, 2, 3, 4, 5, 6, 7, 8)), 50000)
    # Unknown values: tunnel type, method, error, flow policies, parameter types
    u(msg(3, tunnel(9), method(7), flow(7, 8)), 4555, 50000)
    u(msg(1, error(999), error(401), error(315), error(208)), 4555, 50000)
    u(msg(3, par(77, b'\x01\x02\x03'), par(99), par(1, b'')), 4555, 50000)
    # Unknown message type, version 2, a header-only message and parameters
    # that run to the end
    u(msg(99, counter(1)), 50000)
    u(msg(2, ver=2), 50000)
    u(msg(2, counter(12), client(5)), 50000)
    # Tunnel types, methods and policies for the values tables
    for t in (1, 2, 3):
        u(msg(3, tunnel(t), method(t % 2 + 1), flow(t % 2 + 1, t)), 4555, 50000)
    # TCP: the same protocol on 4555
    tc = Tcp(cap, 50001, 4555)
    tc.handshake()
    tc.c(msg(2))
    tc.s(msg(3, client(0x2222), lease(7200), flow(2, 1), method(1)))
    tc.c(msg(6, client(0x2222), addr(1, V4), addr(1, V4B), ports(1, 443)))
    tc.s(msg(7, client(0x2222), bind(1), addr(1, V4), addr(1, V4B), ports(1, 443), lease(100), tunnel(1)))
    tc.c(msg(4, client(0x2222)))
    tc.s(msg(5, client(0x2222)))
    tc.fin()
    cap.write(os.path.join(out, 'rsip-coverage.pcap'))

    # Malformed: parameters whose length does not fit the type or the
    # message (exceptions and "Trying to fetch" expert infos)
    cap = Cap()
    n[0] = 0
    def m(payload, trunc=None):
        n[0] += 1
        f = udp_frame(50000, 4555, payload, ident=n[0])
        cap.add(f[:len(f) - trunc] if trunc else f, len(f))
    m(msg(6, par(1, b'\x01\x01\x02')))             # IPv4 address of 2 octets
    m(msg(6, par(1, b'\x03\x01\x02\x03\x04')))     # IPv6 address of 4 octets
    m(msg(6, par(3, b'\x00\x01')))                 # lease time of 2 octets
    m(msg(6, par(4, b'\x01')))                     # client id of 1 octet
    m(msg(6, par(5, b'\x01\x02\x03\x04\x05')))     # bind id of 5 octets
    m(msg(6, par(6, b'\x01\x02')))                 # tunnel type of 2 octets
    m(msg(6, par(7, b'\x01\x02\x03')))             # method of 3 octets
    m(msg(6, par(8, b'\x01')))                     # error of 1 octet
    m(msg(6, par(9, b'\x01')))                     # flow policy of 1 octet
    m(msg(6, par(10, b'\x01')))                    # indicator of 1 octet
    m(msg(6, par(11, b'\x01\x02')))                # message counter of 2 octets
    m(msg(6, par(12, b'\x01')))                    # vendor specific of 1 octet
    m(msg(6, par(12, b'\x01\x02\x03\x04')))        # vendor specific, empty value
    m(msg(6, par(22, b'\x00\x01\x02')))            # SPI too short
    m(msg(6, par(2, b'\x02\x01')))                 # ports: range with 1 octet
    m(msg(6, par(2, b'\x03\x01\x02\x03')))         # ports: odd list
    m(msg(6, struct.pack('!BH', 4, 400) + b'\x01\x02'))   # length past the message
    m(msg(6, struct.pack('!BH', 1, 0xffff)))       # huge length
    m(msg(6, b'\x04\x00'))                         # parameter header cut short
    m(b'\x01\x06')                                 # header cut short: no length field
    m(b'\x01')                                     # only the version
    m(msg(2, counter(1)), trunc=3)                 # truncated frame
    cap.write(os.path.join(out, 'rsip-coverage-malformed.pcap'))

main(sys.argv[1])
