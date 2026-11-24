#!/usr/bin/env python3
# Generates test/captures/cisco_fp_mim_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco FabricPath MiM
dissector (packet-cisco-fp-mim.c).

FabricPath frames run over Ethernet with a 16 octet outer header: a
hierarchical destination MAC (or a multicast/broadcast MAC), a
hierarchical source MAC, the FP tag (ethertype 0x8903, FTAG and TTL), and
optionally an 802.1ad or 802.1Q tag before the FP tag (20 octets). The
dissector is an Ethernet heuristic (fp_eth). The FCS covers the whole
FabricPath frame and is dissected only when Ethernet knows the FCS
length: here from the pcapng if_fcslen option. Every packet is built
from scratch with struct; no captured traffic is used.

Usage: mkcisco-fp-mim.py <output directory>

Writes:
  cisco-fp-mim-coverage.pcapng            unicast, multicast and broadcast
                                          destinations, every HMAC bit,
                                          the 802.1ad and 802.1Q tags,
                                          frames with an FCS, a VLAN frame
                                          that is not FabricPath
  cisco-fp-mim-coverage-malformed.pcapng  bad FCS, frames cut short, the
                                          short frame with FCS reproducer
"""

import os
import struct
import sys
import zlib


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(sport, dport, data, src, dst):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def inner(n):
    """The encapsulated frame: Ethernet, IPv4, UDP to the discard port."""
    a, b = (10, 0, 0, 1), (10, 0, 0, 2)
    ip = ipv4(17, udp(40000 + n, 9, b'fabricpath-%d' % n, a, b), a, b, ident=n)
    return (bytes.fromhex('020000000012') + bytes.fromhex('020000000011')
            + struct.pack('>H', 0x0800) + ip)


def hmac(eid=0, ul=0, ig=0, ooo=0, swid=0, sswid=0, lid=0):
    """Hierarchical MAC: EID bits 47-42 and 39-38, U/L 41, I/G 40,
    reserved 37, OOO/DL 36, switch ID 35-24, sub-switch ID, LID."""
    b = (((eid >> 2) & 0x3f) << 18) | (ul << 17) | (ig << 16) | ((eid & 3) << 14) \
        | (ooo << 12) | swid
    return struct.pack('>I', b)[1:] + struct.pack('>BH', sswid, lid)


def fp(dst, src, ftag=1, ttl=32, tag=None, n=0, payload=None):
    t = b''
    if tag is not None:
        tpid, pcp, dei, vid = tag
        t = struct.pack('>HH', tpid, (pcp << 13) | (dei << 12) | vid)
    return (dst + src + t + struct.pack('>HH', 0x8903, (ftag << 6) | ttl)
            + (inner(n) if payload is None else payload))


def with_fcs(frame):
    return frame + struct.pack('<I', zlib.crc32(frame) & 0xffffffff)


def pcapng_block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)


def write_pcapng(path, frames):
    """frames: (interface, data); interface 0 is Ethernet with an unknown
    FCS length, 1 Ethernet with if_fcslen 4."""
    with open(path, 'wb') as f:
        f.write(pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(pcapng_block(1, struct.pack('<HHI', 1, 0, 262144)))
        opts = struct.pack('<HHB3x', 13, 1, 4) + struct.pack('<HH', 0, 0)
        f.write(pcapng_block(1, struct.pack('<HHI', 1, 0, 262144) + opts))
        for i, (ifc, p) in enumerate(frames):
            ts = (1700000000 + i) * 1000000
            f.write(pcapng_block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                                len(p), len(p)) + p))


FLOOD_VLAN = bytes.fromhex('010fffc101c0')
FLOOD_FABRIC = bytes.fromhex('010fffc102c0')
BROADCAST = bytes.fromhex('ffffffffffff')


def main_frames():
    F = []

    def add(ifc, frame):
        F.append((ifc, frame))

    n = lambda: len(F) + 1
    # 1: unicast destination and source HMACs
    add(0, fp(hmac(swid=5, sswid=0, lid=1), hmac(swid=7, sswid=0, lid=2), ftag=1, ttl=32, n=n()))
    # 2-4: multicast (flood to VLAN, flood to fabric) and broadcast
    add(0, fp(FLOOD_VLAN, hmac(swid=0x123, sswid=0x45, lid=0x6789), ftag=2, ttl=63, n=n()))
    add(0, fp(FLOOD_FABRIC, hmac(swid=0xfff, sswid=0xff, lid=0xffff), ftag=1023, ttl=0, n=n()))
    add(0, fp(BROADCAST, hmac(swid=1, lid=3), ftag=0, ttl=1, n=n()))
    # 5: reproducer cisco-fp-mim_eid_zero: every End Node ID bit set in
    #    the source (EID 255); the destination has EID 0x81
    add(0, fp(hmac(eid=0x81, swid=5, lid=1), hmac(eid=0xff, swid=7, lid=2), ftag=5, ttl=32, n=n()))
    # 6: U/L and OOO/DL set in a unicast destination, U/L, I/G and DL in
    #    the source, EID 0x2a/0x15
    add(0, fp(hmac(eid=0x2a, ul=1, ooo=1, swid=0xabc, sswid=0x12, lid=0x3456),
              hmac(eid=0x15, ul=1, ig=1, ooo=1, swid=0x0de, sswid=0x9a, lid=0xbcde), ftag=100, ttl=10, n=n()))
    # 7: an 802.1ad tag before the FP tag
    add(0, fp(hmac(swid=10, lid=10), hmac(swid=11, lid=11), tag=(0x88a8, 5, 1, 100), ftag=3, ttl=20, n=n()))
    # 8: an 802.1Q tag before the FP tag, multicast destination
    add(0, fp(FLOOD_VLAN, hmac(swid=12, lid=12), tag=(0x8100, 7, 0, 4095), ftag=4, ttl=21, n=n()))
    # 9-11: with an FCS (if_fcslen 4): unicast, 802.1ad, multicast
    add(1, with_fcs(fp(hmac(swid=20, lid=20), hmac(swid=21, lid=21), ftag=6, ttl=30, n=n())))
    add(1, with_fcs(fp(hmac(swid=22, lid=22), hmac(swid=23, lid=23), tag=(0x88a8, 0, 0, 1), ftag=7, ttl=31, n=n())))
    add(1, with_fcs(fp(BROADCAST, hmac(eid=0xff, swid=24, lid=24), ftag=8, ttl=33, n=n())))
    # 12: an 802.1Q frame that is not FabricPath (heuristic rejects it)
    a, b = (10, 0, 0, 5), (10, 0, 0, 6)
    ip = ipv4(17, udp(40012, 9, b'plain-vlan', a, b), a, b, ident=12)
    add(0, bytes.fromhex('020000000002') + bytes.fromhex('020000000001')
        + struct.pack('>HHH', 0x8100, 33, 0x0800) + ip)
    # 13: a plain IPv4 Ethernet frame (heuristic rejects it)
    ip = ipv4(17, udp(40013, 9, b'plain-eth', a, b), a, b, ident=13)
    add(0, bytes.fromhex('020000000002') + bytes.fromhex('020000000001')
        + struct.pack('>H', 0x0800) + ip)
    return F



def malformed_frames():
    F = []
    # 1: bad FCS (with cfp.check_fcs)
    good = with_fcs(fp(hmac(swid=30, lid=30), hmac(swid=31, lid=31), n=1))
    F.append((1, good[:-4] + b'\xde\xad\xbe\xef'))
    # 2: reproducer cisco-fp-mim_short_fcs: header only plus 2 octets
    #    with an FCS length of 4
    F.append((1, hmac(swid=5, lid=1) + hmac(swid=7, lid=2)
              + struct.pack('>HH', 0x8903, (5 << 6) | 32) + b'\x11\x22'))
    # 3: FP header cut in the FP tag
    F.append((0, hmac(swid=5, lid=1) + hmac(swid=7, lid=2) + struct.pack('>HB', 0x8903, 1)))
    # 4: 802.1ad header cut short after the FP ethertype
    F.append((0, hmac(swid=5, lid=1) + hmac(swid=7, lid=2) + struct.pack('>HHH', 0x88a8, 1, 0x8903)))
    # 5: FP header without an encapsulated frame
    F.append((0, fp(hmac(swid=5, lid=1), hmac(swid=7, lid=2), payload=b'')))
    # 6: encapsulated frame cut short
    F.append((0, fp(hmac(swid=5, lid=1), hmac(swid=7, lid=2), payload=inner(6)[:20])))
    # 7: an Ethernet frame of 13 octets
    F.append((0, bytes(13)))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'cisco-fp-mim-coverage.pcapng'), main_frames())
    write_pcapng(os.path.join(out, 'cisco-fp-mim-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
