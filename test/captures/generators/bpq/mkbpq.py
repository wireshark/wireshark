#!/usr/bin/env python3
# Generates test/captures/bpq_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BPQ dissector (packet-bpq.c).

Amateur Radio BPQ, AX.25 over Ethernet, ethertype 0x08FF. Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkbpq.py <output directory>

Writes:
  bpq-coverage.pcap            BPQ frames with AX.25 UI, I, S and U frames,
                               digipeaters, IPv4 (UDP echo) and ARP carried
                               in AX.25, lengths that set the upper four
                               bits, BPQ in an 802.1Q VLAN
  bpq-coverage-malformed.pcap  BPQ length cut short, no AX.25 frame, a
                               truncated AX.25 address
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
BCAST = b'\xff' * 6
ETH_BPQ = 0x08FF


def eth(dst, src, etype, payload):
    return dst + src + struct.pack('>H', etype) + payload


def call(cs, ssid=0, last=False, c=False):
    '''An AX.25 address: six shifted characters (space padded) and the
    SSID octet with the C (or H) bit and the end-of-address bit.'''
    cs = cs.ljust(6)[:6]
    s = 0x60 | ((ssid & 0xf) << 1) | (0x80 if c else 0) | (1 if last else 0)
    return bytes(ord(ch) << 1 for ch in cs) + bytes([s])


def ax25(ctl, info=b'', pid=None, dst='N0DST', src='N0SRC', src_ssid=0,
         via=(), resp=False):
    dc, sc = (False, True) if resp else (True, False)
    a = call(dst, 0, c=dc) + call(src, src_ssid, last=not via, c=sc)
    for i, (name, ssid, h) in enumerate(via):
        a += call(name, ssid, last=(i == len(via) - 1), c=h)
    p = bytes([ctl])
    if pid is not None:
        p += bytes([pid])
    return a + p + info


def ip_cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src=(44, 0, 0, 1), dst=(44, 0, 0, 2), ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000,
                    64, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', ip_cksum(h)) + h[12:]
    return h + payload


def udp(sport, dport, data):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data


def arp_ax25():
    '''ARP request for 44.0.0.2 with AX.25 hardware addresses (hrd 3).'''
    return (struct.pack('!HHBBH', 3, 0x0800, 7, 4, 1) + call('N0SRC') + bytes([44, 0, 0, 1])
            + bytes(7) + bytes([44, 0, 0, 2]))


def bpq(ax, length=None):
    '''BPQ header: a little endian length (by default the AX.25 frame
    length plus 5, as BPQ32 sends it), then the AX.25 frame.'''
    if length is None:
        length = len(ax) + 5
    return struct.pack('<H', length) + ax


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main_frames():
    F = []
    # 1: UI frame with text (PID 0xF0) to the broadcast address
    F.append(eth(BCAST, MAC_A, ETH_BPQ, bpq(ax25(0x03, b'BPQ beacon', pid=0xF0,
                                                 dst='ID', src='N0SRC', src_ssid=1))))
    # 2: UI response through two digipeaters, one repeated
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, bpq(ax25(0x03, b'via digis', pid=0xF0, resp=True,
                                                 via=[('RELAY', 1, True), ('WIDE2', 2, False)]))))
    # 3: SABM, 4: UA
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, bpq(ax25(0x3F))))
    F.append(eth(MAC_A, MAC_B, ETH_BPQ, bpq(ax25(0x73, dst='N0SRC', src='N0DST', resp=True))))
    # 5: I frame with text, 6: RR response
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, bpq(ax25(0x00, b'hello over BPQ', pid=0xF0))))
    F.append(eth(MAC_A, MAC_B, ETH_BPQ, bpq(ax25(0x21, dst='N0SRC', src='N0DST', resp=True))))
    # 7: I frame carrying IPv4/UDP to the echo port (PID 0xCC)
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, bpq(ax25(0x22, ipv4(17, udp(1024, 7, b'echo me')),
                                                 pid=0xCC))))
    # 8: UI frame carrying ARP (PID 0xCD)
    F.append(eth(BCAST, MAC_A, ETH_BPQ, bpq(ax25(0x03, arp_ax25(), pid=0xCD, dst='QST'))))
    # 9: DISC
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, bpq(ax25(0x53))))
    # 10: a length with the upper four bits set: the tree shows the lower
    # 12 bits (0x234 = 564), the field and Info the whole value (0xF234)
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, bpq(ax25(0x03, b'high bits', pid=0xF0), length=0xF234)))
    # 11: length 0
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, bpq(ax25(0x03, b'zero length', pid=0xF0), length=0)))
    # 12: BPQ in an 802.1Q VLAN (VLAN 7)
    F.append(eth(MAC_B, MAC_A, 0x8100, struct.pack('>HH', 7, ETH_BPQ)
                 + bpq(ax25(0x03, b'vlan', pid=0xF0))))
    return F


def malformed_frames():
    F = []
    # 1: no BPQ header at all
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, b''))
    # 2: one octet of the length
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, b'\x10'))
    # 3: a length but no AX.25 frame
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, struct.pack('<H', 5)))
    # 4: AX.25 address cut short
    F.append(eth(MAC_B, MAC_A, ETH_BPQ, struct.pack('<H', 10) + call('N0DST')[:5]))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bpq-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'bpq-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
