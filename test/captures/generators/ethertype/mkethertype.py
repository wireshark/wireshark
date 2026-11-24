#!/usr/bin/env python3
# Generates test/captures/ethertype_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ethertype dispatcher
(packet-ethertype.c).

The dissector has no port or ethertype of its own: Ethernet, VLAN and
Ethernet-in-Ethernet (0x6558) call it. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkethertype.py <output directory>

Writes:
  ethertype-coverage.pcapng            IPv4/ARP/IPv6 with and without
                                       padding trailers, truncated
                                       trailers, FCS (interface with
                                       if_fcslen 4), unknown ethertypes,
                                       Cisco ACI gleaning, VLAN trailer
  ethertype-coverage-malformed.pcapng  payloads that throw, frames
                                       shorter than the FCS, 300 nested
                                       Ethernet headers (nesting limit)
"""
import os
import struct
import sys
import zlib

def mac(x): return bytes([2, 0, 0, 0, 0, x])
ETH = mac(2) + mac(1)

def csum(b):
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(payload, proto=17):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def udp(payload):
    return struct.pack('!HHHH', 40000, 9, 8 + len(payload), 0) + payload

def ipv6(payload):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), 253, 64,
                       b'\x20\x01\x0d\xb8' + bytes(11) + b'\x01',
                       b'\x20\x01\x0d\xb8' + bytes(11) + b'\x02') + payload

def arp():
    return struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, mac(1), bytes([192, 0, 2, 1]),
                       bytes(6), bytes([192, 0, 2, 2]))

def fcs(b): return struct.pack('<I', zlib.crc32(b) & 0xffffffff)
def frame(et, payload): return ETH + struct.pack('!H', et) + payload

def blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(fn, pkts):
    """pkts: (interface, data[, original length]); interface 0 has no
    FCS information, interface 1 has if_fcslen 4."""
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack('<HHI', 1, 0, 65535))
    out += blk(1, struct.pack('<HHI', 1, 0, 65535) +
               struct.pack('<HH', 13, 1) + b'\x04\0\0\0' + struct.pack('<HH', 0, 0))
    for i, p in enumerate(pkts):
        itf, d = p[0], p[1]
        orig = p[2] if len(p) > 2 else len(d)
        pad = (-len(d)) % 4
        out += blk(6, struct.pack('<IIIII', itf, 0, 1000 + i, len(d), orig) + d + b'\0' * pad)
    open(fn, 'wb').write(out)

outdir = sys.argv[1]
body = ipv4(udp(b'hello'))
good, bad = [], []

# 1 plain IPv4, no trailer
good.append((0, frame(0x0800, body)))
# 2 IPv4 padded to 60: Ethernet trailer
good.append((0, frame(0x0800, body + bytes(10))))
# 3 ARP padded to 60
good.append((0, frame(0x0806, arp() + bytes(18))))
# 4 IPv6 with a trailer that is not zero
good.append((0, frame(0x86dd, ipv6(b'six') + b'\xde\xad\xbe\xef')))
# 5 trailer present in the frame, snaplen cut it off: no trailer shown
p = frame(0x0800, body + bytes(30))
good.append((0, p[:14 + len(body)], len(p)))
# 6 unknown ethertype: Data and "0x1234"
good.append((0, frame(0x1234, b'unknown ethertype payload')))
# 7 ethertype with a name but no dissector: Info has the name
good.append((0, frame(0xC0DE, b'xip payload')))
# 8 same for a second name
good.append((0, frame(0x88B5, b'experimental payload')))
# 9 unknown ethertype with no payload at all
good.append((0, frame(0x1235, b'')))
# 10-13 Cisco ACI gleaning: IPv4, IPv6, ARP/other, empty
good.append((0, frame(0xFFF2, body)))
good.append((0, frame(0xFFF2, ipv6(b'six'))))
good.append((0, frame(0xFFF2, arp())))
good.append((0, frame(0xFFF2, b'')))
# 14 VLAN with a padded IPv4: the trailer is added by the VLAN dissector
good.append((0, frame(0x8100, struct.pack('!HH', 5, 0x0800) + body + bytes(10))))
# 15 QinQ: two VLAN tags, second ethertype is an unknown one
good.append((0, frame(0x88a8, struct.pack('!HH', 7, 0x8100) + struct.pack('!HH', 9, 0x1236) + b'qinq')))
# FCS interface (1): 16 IPv4, 17 padded ARP, 18 IPv4 with data trailer, 19 unknown ethertype
for et, pl in ((0x0800, body), (0x0806, arp() + bytes(18)),
               (0x0800, body + b'trailer!'), (0x1234, b'unknown with fcs')):
    f = frame(et, pl)
    good.append((1, f + fcs(f)))
# 20 FCS interface, frame cut by the snaplen after the payload (FCS cut off)
f = frame(0x0800, body)
good.append((1, f, len(f) + 4))
# 21 FCS interface, IPv4 whose captured length reaches into the FCS
f = frame(0x0800, body + bytes(10))
good.append((1, f + fcs(f)))
# 22 ethernet in ethernet, one level
good.append((0, frame(0x6558, frame(0x0800, body))))
# 23 300 nested Ethernet headers: stops at the nesting limit with a warning
good.append((0, b''.join(ETH + b'\x65\x58' for _ in range(300)) + frame(0x0800, body)))
# malformed: IPv4 header cut short (exception in the sub dissector)
bad.append((0, frame(0x0800, body[:10])))
bad.append((0, frame(0x0800, body[:10] + bytes(2)), len(frame(0x0800, body))))
# IPv6 cut short
bad.append((0, frame(0x86dd, ipv6(b'six')[:20])))
# ARP cut short
bad.append((0, frame(0x0806, arp()[:10])))
# FCS interface: payload shorter than the FCS
bad.append((1, frame(0x1234, b'ab')))
bad.append((1, frame(0x1234, b'')))
# unknown ethertype, FCS interface, FCS cut off leaving a short frame
bad.append((1, frame(0x1234, b'abcdefgh'), 14 + 2 + 8 + 4))
# VLAN cut short, then exception in the next dissector
bad.append((0, frame(0x8100, struct.pack('!HH', 5, 0x0800) + body[:12])))
# ACI gleaning with a truncated ARP
bad.append((0, frame(0xFFF2, b'\x10\x00')))
# nested ethernet, nesting exceeded then a cut-off inner frame
bad.append((0, b''.join(ETH + b'\x65\x58' for _ in range(300)) + ETH + b'\x08\x00' + body[:5]))

# 300 nested Ethernet headers with a trailer after the nesting
bad.append((0, b''.join(ETH + b'\x65\x58' for _ in range(300)) + frame(0x0800, body) + bytes(6)))

pcapng(os.path.join(outdir, 'ethertype-coverage.pcapng'), good)
pcapng(os.path.join(outdir, 'ethertype-coverage-malformed.pcapng'), bad)
