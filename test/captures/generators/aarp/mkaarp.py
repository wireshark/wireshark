#!/usr/bin/env python3
# Generates test/captures/aarp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic AARP (AppleTalk Address Resolution Protocol)
coverage captures.

Usage: mkaarp.py <outdir> [-v]

  aarp-coverage.pcapng            main capture (Ethernet and Cisco HDLC)
  aarp-coverage-malformed.pcapng  paths only malformed input reaches

Every packet is built with struct; MAC addresses are made up (locally
administered).
"""
import struct
import sys
import os

LT_ETH = 1
LT_CHDLC = 104


def pcapng(path, frames):
    """frames: list of (interface, bytes). Interface 0 is Ethernet,
    interface 1 Cisco HDLC."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', LT_ETH, 0, 65535))
    out += block(1, struct.pack('<HHI', LT_CHDLC, 0, 65535))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


ETH_A = bytes.fromhex('02a000000001')
ETH_B = bytes.fromhex('02a000000002')
BCAST = bytes.fromhex('ffffffffffff')
ATALK = 0x809b
AARP = 0x80f3


def atalk(net, node):
    return struct.pack('>BHB', 0, net, node)


def aarp(op, sha=ETH_A, spa=None, tha=bytes(6), tpa=None, hrd=1, pro=ATALK,
         hln=None, pln=None):
    spa = atalk(1, 10) if spa is None else spa
    tpa = atalk(1, 20) if tpa is None else tpa
    hln = len(sha) if hln is None else hln
    pln = len(spa) if pln is None else pln
    return struct.pack('>HHBBH', hrd, pro, hln, pln, op) + sha + spa + tha + tpa


def eth(payload, dst=BCAST, src=ETH_A, etype=AARP, pad=False):
    f = dst + src + struct.pack('>H', etype) + payload
    if pad and len(f) < 60:
        f += bytes(60 - len(f))
    return (0, f)


def snap(payload, dst=BCAST, src=ETH_A):
    body = bytes([0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]) + struct.pack('>H', AARP) + payload
    return (0, dst + src + struct.pack('>H', len(body)) + body)


def chdlc(payload, addr=0x0f):
    return (1, bytes([addr, 0x00]) + struct.pack('>H', AARP) + payload)


def main_frames():
    F = []
    # 1-3: request, reply, probe on Ethernet
    F.append(eth(aarp(1, tha=bytes(6), tpa=atalk(1, 20))))
    F.append(eth(aarp(2, sha=ETH_B, spa=atalk(1, 20), tha=ETH_A, tpa=atalk(1, 10)), dst=ETH_A, src=ETH_B))
    F.append(eth(aarp(3, spa=atalk(65535, 254), tpa=atalk(65535, 254))))
    # 4-6: opcodes as edited in place by the Linux kernel (byte swapped)
    F.append(eth(aarp(0x0100)))
    F.append(eth(aarp(0x0200, sha=ETH_B, spa=atalk(1, 20)), dst=ETH_A, src=ETH_B))
    F.append(eth(aarp(0x0300)))
    # 7-8: unknown opcodes
    F.append(eth(aarp(0)))
    F.append(eth(aarp(0x1234)))
    # 9-10: Token Ring hardware type, and an unknown hardware type
    F.append(eth(aarp(1, hrd=2)))
    F.append(eth(aarp(2, hrd=0x77)))
    # 11-13: hardware address length other than 6: not an Ethernet address
    F.append(eth(aarp(1, sha=bytes(range(1, 9)), tha=bytes(8))))
    F.append(eth(aarp(2, sha=bytes(range(1, 5)), tha=bytes(4))))
    F.append(eth(aarp(1, hrd=2, sha=bytes(range(1, 21)), tha=bytes(20))))
    # 14-17: protocol type other than AppleTalk, or an address length other than 4
    F.append(eth(aarp(1, pro=0x0800, spa=bytes([192, 0, 2, 1]), tpa=bytes([192, 0, 2, 2]))))
    F.append(eth(aarp(2, spa=bytes([1, 2, 3]), tpa=bytes([4, 5, 6]))))
    F.append(eth(aarp(3, spa=bytes(range(1, 11)), tpa=bytes(range(11, 21)))))
    F.append(eth(aarp(1, pro=0x86dd, spa=bytes(range(16)), tpa=bytes(range(16, 32)))))
    # 18-19: address length 1
    F.append(eth(aarp(1, sha=b'\x01', tha=b'\x02', spa=b'\x03', tpa=b'\x04')))
    F.append(eth(aarp(2, sha=b'\x01', tha=b'\x02', spa=b'\x03', tpa=b'\x04')))
    # 20-23: zero lengths (expert warnings): hardware, protocol, both, probe
    F.append(eth(aarp(2, sha=b'', tha=b'', hln=0), pad=True))
    F.append(eth(aarp(2, spa=b'', tpa=b'', pln=0), pad=True))
    F.append(eth(aarp(1, sha=b'', tha=b'', spa=b'', tpa=b'', hln=0, pln=0), pad=True))
    F.append(eth(aarp(3, sha=b'', tha=b'', spa=b'', tpa=b'', hln=0, pln=0), pad=True))
    # 24: very long addresses
    F.append(eth(aarp(2, sha=bytes(range(200)), tha=bytes(200), spa=bytes(range(55)), tpa=bytes(55))))
    # 25-26: padded to the Ethernet minimum, trailing data after the packet
    F.append(eth(aarp(1), pad=True))
    F.append(eth(aarp(2) + b'\xde\xad\xbe\xef', dst=ETH_A, src=ETH_B))
    # 27-29: the other ways to carry AARP: 802.1Q, LLC SNAP (Apple OUI), Cisco HDLC
    vlan = BCAST + ETH_A + struct.pack('>HHH', 0x8100, 5, AARP) + aarp(1)
    F.append((0, vlan))
    F.append(snap(aarp(1)))
    F.append(snap(aarp(2, sha=ETH_B, spa=atalk(1, 20)), dst=ETH_A, src=ETH_B))
    F.append(chdlc(aarp(1)))
    F.append(chdlc(aarp(2, sha=ETH_B, spa=atalk(1, 20)), addr=0x8f))
    # a conversation: probes, request and reply for the same node
    for i in range(3):
        F.append(eth(aarp(3, spa=atalk(100, 7), tpa=atalk(100, 7))))
    F.append(eth(aarp(1, spa=atalk(100, 7), tpa=atalk(100, 8))))
    F.append(eth(aarp(2, sha=ETH_B, spa=atalk(100, 8), tha=ETH_A, tpa=atalk(100, 7)), dst=ETH_A, src=ETH_B))
    return F


def malformed_frames():
    F = []
    # packets shorter than the 8 octet fixed header
    for n in (0, 1, 2, 4, 5, 6, 7):
        F.append(eth(aarp(1)[:n]))
    # header only, addresses missing; cut inside each address
    pkt = aarp(1)
    for n in (8, 10, 14, 17, 18, 20, 24, 26, 27):
        F.append(eth(pkt[:n]))
    # large lengths with a short packet
    F.append(eth(struct.pack('>HHBBH', 1, ATALK, 255, 255, 1) + bytes(20)))
    F.append(eth(struct.pack('>HHBBH', 1, ATALK, 6, 255, 2) + bytes(20)))
    F.append(eth(struct.pack('>HHBBH', 2, 0x0800, 255, 4, 3) + bytes(100)))
    # zero length hardware address, the rest short
    F.append(eth(struct.pack('>HHBBH', 1, ATALK, 0, 4, 1) + bytes(5)))
    F.append(eth(struct.pack('>HHBBH', 1, ATALK, 6, 0, 3) + bytes(8)))
    # unknown opcode and short
    F.append(eth(struct.pack('>HHBBH', 1, ATALK, 6, 4, 0xffff) + bytes(10)))
    # Cisco HDLC and SNAP with short data
    F.append(chdlc(aarp(1)[:12]))
    F.append(snap(aarp(2)[:20]))
    return F


def main():
    out = sys.argv[1]
    pcapng(os.path.join(out, 'aarp-coverage.pcapng'), main_frames())
    pcapng(os.path.join(out, 'aarp-coverage-malformed.pcapng'), malformed_frames())
    if '-v' in sys.argv:
        print(len(main_frames()), len(malformed_frames()))


main()
