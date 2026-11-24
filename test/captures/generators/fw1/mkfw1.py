#!/usr/bin/env python3
# Generates test/captures/fw1_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the FW-1 coverage captures.
fw1-coverage.pcap            Exported PDU (LINKTYPE_WIRESHARK_UPPER_PDU 252), tag "fw1"
fw1-coverage-malformed.pcap  Ethernet frames of an "fw monitor" file (read with
                             eth.interpret_as_fw1_monitor) plus truncated PDUs
Usage: mkfw1.py <outdir>"""
import os
import struct
import sys

A = bytes([192, 0, 2, 1])
B = bytes([192, 0, 2, 2])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4_udp(sp=1000, dp=2000, data=b'', proto=17):
    u = struct.pack('!HHHH', sp, dp, 8 + len(data), 0) + data
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, proto, 0, A, B)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + u


def arp():
    return struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, bytes.fromhex('020000000001'), A, bytes(6), B)


def ipv6_udp(data=b'x'):
    src = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [1])
    dst = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [2])
    u = struct.pack('!HHHH', 1000, 2000, 8 + len(data), 0) + data
    pseudo = src + dst + struct.pack('!IxxxB', len(u), 17)
    ck = csum(pseudo + u) or 0xffff
    u = u[:6] + struct.pack('!H', ck) + u[8:]
    return struct.pack('!IHBB', 0x60000000, len(u), 17, 64) + src + dst + u


def hdr(direction, iface, etype, chain=b' ', uuid=None):
    """14 octet header: direction, chain position, interface name (10
    octets, or 6 octets and a 4 octet UUID in files written with
    fw monitor -u/-s), Ethernet type"""
    name = iface if isinstance(iface, bytes) else iface.encode()
    if uuid is None:
        nm = name.ljust(10, b'\0')[:10]
    else:
        nm = name.ljust(6, b'\0')[:6] + struct.pack('!I', uuid)
    return direction + chain + nm + struct.pack('!H', etype)


def epdu(p, name=b'fw1'):
    name = name + b'\0' * (-len(name) % 4)      # tag lengths include the padding
    return struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0) + p


def write(fn, recs, lt):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, lt))
        for i, r in enumerate(recs):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(r), len(r)) + r)


out = sys.argv[1]
os.makedirs(out, exist_ok=True)
main = []


def add(p):
    main.append(epdu(p))


# Reproducer of "FW-1: Update the interface list only in the first pass":
# frame 1 must show only the interfaces known at frame 1 in both passes
add(hdr(b'i', 'eth0', 0x0800) + ipv4_udp())
add(hdr(b'O', 'eth1', 0x0800) + ipv4_udp())
add(hdr(b'i', 'eth2', 0x0800) + ipv4_udp())

# All inspection points on a known interface
for d in b'iIoOeE':
    add(hdr(bytes([d]), 'eth0', 0x0800, chain=b'k') + ipv4_udp(data=bytes([d]) * 4))
# Unknown direction characters
add(hdr(b'x', 'eth1', 0x0800) + ipv4_udp())
add(hdr(b'?', 'eth2', 0x0800, chain=b'0') + ipv4_udp())
# Other Ethernet types handed to the ethertype dissector
add(hdr(b'I', 'eth1', 0x0806) + arp())
add(hdr(b'o', 'eth2', 0x86dd) + ipv6_udp())
add(hdr(b'e', 'eth0', 0x8100) + struct.pack('!HH', 5, 0x0800) + ipv4_udp())
add(hdr(b'E', 'eth1', 0x0842) + b'\x01\x02\x03\x04')      # unknown type
# Trailer after the IP packet (the ethertype dissector shows it)
add(hdr(b'i', 'eth0', 0x0800) + ipv4_udp() + bytes(range(1, 7)))
# Interface name that fills all ten octets, no NUL
add(hdr(b'i', 'abcdefghij', 0x0800) + ipv4_udp())
# 6 octet names with a UUID: the 4 octets after a short name are ignored
# at default preferences
add(hdr(b'O', 'eth3', 0x0800, uuid=0x01020304) + ipv4_udp())
add(hdr(b'o', 'eth4', 0x0800, uuid=0) + ipv4_udp())
# more interfaces than the dissector remembers (20)
for n in range(5, 26):
    add(hdr(b'iIoO'[n % 4:n % 4 + 1], 'ge-%d' % n, 0x0800, chain=bytes([0x41 + n % 26])) + ipv4_udp(sp=3000 + n))
# Back to the first interfaces; the list is long now
add(hdr(b'i', 'eth0', 0x0800) + ipv4_udp())
add(hdr(b'I', 'ge-24', 0x0800) + ipv4_udp())
# Another dissector name in the same Exported PDU format is not FW-1
write(os.path.join(out, 'fw1-coverage.pcap'), main, 252)

# --- malformed / other entry point -----------------------------------
mal = []
# Ethernet frames of a monitor file: the destination MAC starts with the
# direction character, so the eth dissector hands them to FW-1 when
# eth.interpret_as_fw1_monitor is set
for d in b'iIoOeE':
    mal.append(hdr(bytes([d]), 'eth0', 0x0800, chain=b'p') + ipv4_udp())
mal.append(hdr(b'i', 'eth9', 0x0806, chain=b'p') + arp())
# not a monitor direction: normal Ethernet II
mal.append(bytes.fromhex('020000000002') + bytes.fromhex('020000000001') + b'\x08\x00' + ipv4_udp())
write(os.path.join(out, 'fw1-coverage-eth.pcap'), mal, 1)

bad = []
for n in (0, 1, 2, 5, 11, 12, 13):
    bad.append(epdu(hdr(b'i', 'eth0', 0x0800)[:n]))
bad.append(epdu(hdr(b'o', 'eth0', 0x0800) + b''))                 # header only
bad.append(epdu(hdr(b'o', 'eth0', 0x0800) + ipv4_udp()[:10]))    # truncated IP
write(os.path.join(out, 'fw1-coverage-malformed.pcap'), bad, 252)
