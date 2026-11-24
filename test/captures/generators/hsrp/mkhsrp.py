#!/usr/bin/env python3
# Generates test/captures/hsrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-hsrp.c (HSRP v1 to 224.0.0.2 port 1985,
HSRPv2 to 224.0.0.102 port 1985 or IPv6 port 2029).
Usage: mkhsrp.py <outdir>"""
import struct
import sys
import os
from pylib import A, B, eth, H, ip4, ipv4, ipv6, Pcap, S, socket, udp, udp6

V1_DST, V2_DST = '224.0.0.2', '224.0.0.102'
RIP = ip4('192.0.2.254')
MD5_PLACEHOLDER = bytes([0xaa] * 16)

def hsrp1(opcode, state, hello=3, hold=10, prio=100, group=1, auth=b'cisco', vip=RIP):
    return struct.pack('>BBBBBBBB', 0, opcode, state, hello, hold, prio, group, 0) + auth.ljust(8, b'\0') + vip

def hsrp1_adv(typ, length, state, active, passive):
    return struct.pack('>HHBBHHI', typ, length, state, 0, active, passive, 0)

def md5_tlv(key=1):
    # algorithm 1, padding, flags, sender IP, key id, constant placeholder digest
    v = struct.pack('>BBH4sI', 1, 0, 0, ip4('192.0.2.1'), key) + MD5_PLACEHOLDER
    return bytes([4, len(v)]) + v

def group_tlv(opcode=0, state=6, ipver=4, group=1, prio=100, hello=3000, hold=10000, vip=None):
    if vip is None:
        vip = RIP + bytes(12) if ipver == 4 else socket.inet_pton(socket.AF_INET6, '2001:db8::fe')
    v = struct.pack('>BBBB H 6s III', 0, opcode, state, ipver, group, bytes.fromhex('00005e0201') + bytes([group & 0xff]), prio, hello, hold) + vip
    assert len(v) == 40, len(v)
    return bytes([1, 40]) + v

def iface_tlv(active, passive):
    return bytes([2, 4]) + struct.pack('>HH', active, passive)

def text_tlv(auth=b'cisco'):
    return bytes([3, 8]) + auth.ljust(8, b'\0')

def f4(payload, dst=V1_DST, sport=1985, dport=1985, src=A):
    last = int(dst.split('.')[-1])
    return eth('01:00:5e:00:00:%02x' % last, H, 0x0800, ipv4(src, dst, 17, udp(sport, dport, payload), ttl=255 if dst == V2_DST else 1))

def f6(payload, dst='ff02::66', sport=2029, dport=2029, src='fe80::1'):
    return eth('33:33:00:00:00:66', H, 0x86dd, ipv6(src, dst, 17, udp6(src, dst, sport, dport, payload), hlim=1))

def main(out):
    p = Pcap(1)
    # ---- HSRPv1 ----
    for op, st in [(0, 16), (0, 8), (0, 4), (0, 2), (0, 1), (0, 0), (0, 99), (1, 16), (2, 0)]:
        p.add(f4(hsrp1(op, st)))
    # Non-default timers, authentication and priority/group
    p.add(f4(hsrp1(0, 8, hello=5, hold=15, prio=200, group=7, auth=b'secret!')))
    p.add(f4(hsrp1(0, 16, hello=3, hold=10, auth=b'cisco', vip=ip4('198.51.100.1'))))
    # Advertise (opcode 3), interface state and IP redundancy, every state
    for typ, st in [(1, 1), (1, 2), (1, 3), (2, 3), (2, 9)]:
        p.add(f4(bytes([0, 3]) + hsrp1_adv(typ, 8, st, 5, 6)))
    # Unknown opcode: data
    p.add(f4(hsrp1(4, 0)))
    # HSRPv1 with MD5 authentication TLV after the 20 byte message (50 octets), and unknown TLV
    base = hsrp1(0, 16)[:20]
    # offset of the TLV is 16 + 4 = 20: the 20 octet message is followed by the TLV
    p.add(f4(base + md5_tlv()))
    p.add(f4(base + bytes([9, 28]) + bytes(28)))
    # Source port is 1985, destination port is not: not HSRP
    p.add(f4(hsrp1(0, 16), sport=1985, dport=5555))
    # Destination address is neither 224.0.0.2 nor 224.0.0.102: nothing dissected
    p.add(eth(S, H, 0x0800, ipv4(A, B, 17, udp(1985, 1985, hsrp1(0, 16)))))

    # ---- HSRPv2 over IPv4 (port 1985) ----
    p.add(f4(group_tlv(0, 6) + text_tlv(), V2_DST))
    p.add(f4(group_tlv(1, 5) + text_tlv(b'secret'), V2_DST))
    p.add(f4(group_tlv(2, 4) + md5_tlv(), V2_DST))
    p.add(f4(group_tlv(0, 3, hello=1000, hold=3000, prio=255) + iface_tlv(10, 20), V2_DST))
    p.add(f4(group_tlv(0, 2) , V2_DST))
    p.add(f4(group_tlv(0, 1), V2_DST))
    p.add(f4(group_tlv(7, 0), V2_DST))           # unknown opcode, state disabled
    p.add(f4(iface_tlv(1, 2), V2_DST))
    p.add(f4(iface_tlv(1, 2) + group_tlv(0, 6) + md5_tlv() + text_tlv(), V2_DST))
    # Group state TLV with an IPv6 virtual address (IPv4 transport), and unknown IP version
    p.add(f4(group_tlv(0, 6, ipver=6), V2_DST))
    p.add(f4(group_tlv(0, 6, ipver=9, vip=bytes(16)), V2_DST))
    # Undefined TLV types and lengths
    p.add(f4(bytes([9, 4, 1, 2, 3, 4]), V2_DST))
    p.add(f4(group_tlv(0, 6) + bytes([3, 4, 1, 2, 3, 4]), V2_DST))
    p.add(f4(bytes([1, 12]) + bytes(12), V2_DST))

    # ---- HSRPv2 over IPv6 (port 2029) ----
    p.add(f6(group_tlv(0, 6, ipver=6) + text_tlv()))
    p.add(f6(group_tlv(1, 5, ipver=6) + md5_tlv()))
    p.add(f6(group_tlv(0, 6, ipver=4) + iface_tlv(3, 4), dst='ff02::66'))
    # Over IPv4 with destination port 2029 (HSRPv1 destination address)
    p.add(f4(hsrp1(0, 16), sport=2029, dport=2029))
    p.write(os.path.join(out, 'hsrp-coverage.pcap'))

    m = Pcap(1)
    # Packet too short for the header (exceptions)
    m.add(f4(bytes([0, 0, 16])))
    m.add(f4(hsrp1(0, 16)[:12]))
    m.add(f4(bytes([0, 3, 0, 0, 0, 1])))
    # Group state TLV cut short, interface state TLV cut short, MD5 TLV cut short
    m.add(f4(group_tlv()[:20], V2_DST))
    m.add(f4(bytes([2, 4, 0, 1]), V2_DST))
    m.add(f4(bytes([3, 8, 99, 98]), V2_DST))
    m.add(f4(md5_tlv()[:12], V2_DST))
    # TLV type without a length octet
    m.add(f4(bytes([1]), V2_DST))
    # IPv6 packet with an empty UDP payload
    m.add(f6(b''))
    m.write(os.path.join(out, 'hsrp-coverage-malformed.pcap'))

main(sys.argv[1])
