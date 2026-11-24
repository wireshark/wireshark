#!/usr/bin/env python3
# Generates test/captures/carp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Common Address
Redundancy Protocol dissector (packet-carp.c).

CARP uses IP protocol 112, which it shares with VRRP. The "ip.proto"
table entry for 112 belongs to VRRP (registered after CARP), so CARP is
reached by Decode As (-d ip.proto==112,carp), by the "carp_ip" IPv4
heuristic (enabled by default) when another IP protocol number has no
dissector, or by the heuristic with ip.try_heuristic_first. A CARP
message is 36 octets: version/type, VHID, advskew, authlen (7),
demotion, advbase, checksum, 8 octet counter and 20 octet SHA-1 HMAC.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcarp.py <output directory>

Writes:
  carp-coverage.pcap            advertisements over IP protocol 112 and
                                over an unassigned protocol (heuristic),
                                a truncated frame, a fragmented datagram,
                                VRRP and payloads the heuristic rejects
  carp-coverage-malformed.pcap  bad checksums
"""

import os
import struct
import sys

SRC = (192, 0, 2, 1)
DST = (224, 0, 0, 18)
ETH_DST = bytes.fromhex('01005e000012')
ETH_SRC = bytes.fromhex('00005e000101')


def pcap(path, frames, linktype=1):
    """frames: list of bytes, or (bytes, wire length) for a truncated frame."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(frames):
            if isinstance(p, tuple):
                p, wire = p
            else:
                wire = len(p)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), wire))
            f.write(p)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, ident=1, flags_frag=0, total=None):
    if total is None:
        total = 20 + len(payload)
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0xc0, total, ident, flags_frag,
                      255, proto, 0, bytes(SRC), bytes(DST))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def eth(payload):
    return ETH_DST + ETH_SRC + b'\x08\x00' + payload


def carp(version=2, mtype=1, vhid=1, advskew=0, authlen=7, demotion=0,
         advbase=1, counter=0x0123456789abcdef, hmac=None, trailer=b'',
         bad_cksum=False):
    if hmac is None:
        hmac = bytes(range(0x40, 0x54))
    body = (bytes([(version << 4) | mtype, vhid, advskew, authlen, demotion, advbase])
            + b'\0\0' + struct.pack('>Q', counter) + hmac + trailer)
    c = csum(body)
    if bad_cksum:
        c ^= 0x5a5a
    return body[:6] + struct.pack('>H', c) + body[8:]


def vrrp2(vrid=1, prio=100):
    """A VRRPv2 advertisement with one address (authlen field = count 1)."""
    body = (bytes([0x21, vrid, prio, 1, 0, 1]) + b'\0\0' + bytes([192, 0, 2, 254])
            + b'\0' * 8)
    return body[:6] + struct.pack('>H', csum(body)) + body[8:]


def main_frames():
    f = []
    # 1: version 2 advertisement over IP protocol 112, typical values
    f.append(eth(ipv4(112, carp(), ident=1)))
    # 2: version 2, every one octet field at its maximum, counter 2^64-1
    f.append(eth(ipv4(112, carp(vhid=255, advskew=255, demotion=255, advbase=255,
                                counter=0xffffffffffffffff, hmac=b'\xff' * 20), ident=2)))
    # 3: version 1, VHID 5, advskew 100, demotion 0, counter 0, HMAC 0
    f.append(eth(ipv4(112, carp(version=1, vhid=5, advskew=100, counter=0,
                                hmac=bytes(20)), ident=3)))
    # 4: truncated frame: a 40 octet CARP payload (4 octets after the
    #    HMAC) captured with only the 36 octets of the message, so the
    #    checksum cannot be verified
    full = eth(ipv4(112, carp(vhid=7, trailer=b'\xde\xad\xbe\xef'), ident=4))
    f.append((full[:-4], len(full)))
    # 5-6: one CARP datagram in two IP fragments: 40 octets (more
    #    fragments) and 8 octets; the 48 octet payload is a CARP message
    #    with 12 trailing octets. Reassembled by default; with
    #    ip.defragment off the first fragment is dissected unverified.
    msg = carp(vhid=9, advskew=10, trailer=bytes(range(12)))
    f.append(eth(ipv4(112, msg[:40], ident=5, flags_frag=0x2000, total=60)))
    f.append(eth(ipv4(112, msg[40:], ident=5, flags_frag=40 // 8)))
    # 7: CARP over IP protocol 253 (RFC 3692 experimental, no dissector):
    #    found by the carp_ip heuristic at default preferences
    f.append(eth(ipv4(253, carp(vhid=20, advskew=1, advbase=3), ident=7)))
    # 8: version 1 over IP protocol 254, heuristic
    f.append(eth(ipv4(254, carp(version=1, vhid=21), ident=8)))
    # 9: a VRRPv2 advertisement (IP protocol 112): not CARP (authlen
    #    octet is the address count 1); with -d ip.proto==112,carp the
    #    CARP dissector rejects it and the payload goes to data
    f.append(eth(ipv4(112, vrrp2(), ident=9)))
    # 10-15: payloads over IP protocol 253 the heuristic rejects: 35
    #    octets, version 0, version 3, type 2, authlen 6, authlen 8
    f.append(eth(ipv4(253, carp()[:35], ident=10)))
    f.append(eth(ipv4(253, carp(version=0), ident=11)))
    f.append(eth(ipv4(253, carp(version=3), ident=12)))
    f.append(eth(ipv4(253, carp(mtype=2), ident=13)))
    f.append(eth(ipv4(253, carp(authlen=6), ident=14)))
    f.append(eth(ipv4(253, carp(authlen=8), ident=15)))
    return f


def malformed_frames():
    f = []
    # 1: bad checksum over IP protocol 112
    f.append(eth(ipv4(112, carp(bad_cksum=True), ident=101)))
    # 2: bad checksum over IP protocol 253 (heuristic)
    f.append(eth(ipv4(253, carp(vhid=3, bad_cksum=True), ident=102)))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'carp-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'carp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
