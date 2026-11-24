#!/usr/bin/env python3
# Generates test/captures/dec_bpdu_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DEC Spanning Tree
dissector (packet-dec-bpdu.c, DEC LANbridge 100 BPDUs).

All packets are built from scratch with struct; no captured traffic is
used. The BPDUs are carried the three ways the dissector registers:
Ethernet (ethertype 0x8038, to the LANbridge multicast address
09:00:2b:01:00:01), Cisco HDLC (protocol 0x8038) and PPP (protocol
0x0205). The capture is pcapng with one interface per link type.

Usage: mkdec_bpdu.py <output directory>

Writes:
  dec-bpdu-coverage.pcapng            hello and topology change BPDUs
                                      with every flag, an unknown type,
                                      BPDUs with and without padding
  dec-bpdu-coverage-malformed.pcapng  BPDUs cut short
"""

import os
import struct
import sys

LT_ETHERNET = 1
LT_PPP = 9
LT_CHDLC = 104
INTERFACES = (LT_ETHERNET, LT_CHDLC, LT_PPP)

DEC_MCAST = bytes.fromhex('09002b010001')


def mac(n):
    return bytes([0x02, 0x00, 0x2b, 0x00, 0x00, n])


def bpdu(btype=25, version=1, flags=0, root_pri=128, root=1, cost=10,
         bridge_pri=128, bridge=2, port=3, age=1, hello=1, max_age=20,
         fwd=15):
    return struct.pack('!BBBBH6sHH6sBBBBB', 0xe1, btype, version, flags,
                       root_pri, mac(root), cost, bridge_pri, mac(bridge),
                       port, age, hello, max_age, fwd)


def eth(payload, src=2, pad=True):
    f = DEC_MCAST + mac(src) + struct.pack('!H', 0x8038) + payload
    if pad and len(f) < 60:
        f += bytes(60 - len(f))
    return f


def chdlc(payload, addr=0x8f):
    return struct.pack('!BBH', addr, 0, 0x8038) + payload


def ppp(payload):
    return b'\xff\x03' + struct.pack('!H', 0x0205) + payload


class Pcapng:
    def __init__(self):
        self.packets = []

    def add(self, iface, data, caplen=None):
        self.packets.append((INTERFACES.index(iface), data, caplen))

    @staticmethod
    def block(btype, body):
        body += bytes(-len(body) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)

    def write(self, fn):
        out = self.block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in INTERFACES:
            out += self.block(1, struct.pack('<HHI', lt, 0, 262144))
        for i, (ifn, data, caplen) in enumerate(self.packets):
            ts = (1700000000 + i) * 1000000
            cl = len(data) if caplen is None else caplen
            out += self.block(6, struct.pack('<IIIII', ifn, ts >> 32, ts & 0xffffffff,
                                             cl, len(data)) + data[:cl])
        with open(fn, 'wb') as f:
            f.write(out)


def main(outdir):
    m = Pcapng()
    # Ethernet
    m.add(LT_ETHERNET, eth(bpdu()))                                   # 1: hello, no flags
    m.add(LT_ETHERNET, eth(bpdu(flags=0x83, age=2)))                  # 2: hello, short timers, TCA, TC
    m.add(LT_ETHERNET, eth(bpdu(flags=0x01, root=3, cost=0, bridge=3, port=0, age=0),
                           src=3))                                    # 3: hello from the root bridge, TC
    m.add(LT_ETHERNET, eth(bpdu(btype=2, flags=0x80, version=1)))     # 4: topology change notification
    m.add(LT_ETHERNET, eth(bpdu(btype=7, version=2, flags=0x02,
                                root_pri=65535, cost=65535, bridge_pri=0,
                                port=255, age=255, hello=255, max_age=255,
                                fwd=255)))                            # 5: unknown type 7, maximum values
    # Cisco HDLC
    m.add(LT_CHDLC, chdlc(bpdu(bridge=4, port=1)))                    # 6: hello, exactly 27 octets
    m.add(LT_CHDLC, chdlc(bpdu(btype=2, flags=0x01, bridge=4), addr=0x0f))  # 7: TCN, unicast
    # PPP
    m.add(LT_PPP, ppp(bpdu(bridge=5, port=2, flags=0x02)))            # 8: hello, TCA
    m.add(LT_PPP, ppp(bpdu(btype=2, bridge=5) + b'\x00\x00\x00\x00'))  # 9: TCN with 4 octets after it
    m.write(os.path.join(outdir, 'dec-bpdu-coverage.pcapng'))

    b = Pcapng()
    b.add(LT_PPP, ppp(bpdu()[:10]))                                   # 1: 10 octets
    b.add(LT_CHDLC, chdlc(b'\xe1'))                                   # 2: 1 octet, no type
    b.add(LT_ETHERNET, eth(bpdu(btype=2)), caplen=14 + 20)            # 3: captured length 20 of 46
    b.write(os.path.join(outdir, 'dec-bpdu-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
