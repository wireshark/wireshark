#!/usr/bin/env python3
# ARCNET coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ARCNET (packet-arcnet.c): BSD-style frames (link type 7,
WTAP_ENCAP_ARCNET: no offset field, exception frames possible) and
Linux-style frames (link type 129, WTAP_ENCAP_ARCNET_LINUX: an offset
field, no exception frames). The two kinds are in one pcapng file with
two interfaces. Every packet is built with struct; nothing comes from a
real network.

Usage: mkarcnet.py [<output directory>]
writes arcnet-coverage.pcapng and arcnet-coverage-malformed.pcapng
"""
import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
import capgen  # noqa: E402

LINKTYPE_ARCNET_BSD = 7
LINKTYPE_ARCNET_LINUX = 129

A4, B4 = '192.0.2.1', '192.0.2.2'
A6, B6 = '2001:db8::1', '2001:db8::2'

# Protocol IDs (packet-arcnet.h)
IP_1051, ARP_1051, IP_1201, ARP_1201, RARP_1201 = 240, 241, 212, 213, 214
IPX, NOVELL_EC, IPV6, ETHERNET = 250, 236, 196, 232
DP_BOOT, DP_MOUNT, POWERLAN, POWERLAN2, LANSOFT = 0, 1, 8, 243, 251
APPLETALK, BANYAN, DIAGNOSE, BACNET = 221, 247, 128, 205
NO_FRAG = (IP_1051, ARP_1051, DIAGNOSE, BACNET)


def ipv4_udp(sport, dport, data):
    return capgen.ipv4(capgen.udp(data, sport, dport, A4, B4), 17, A4, B4, ident=sport)


def arp(op, sha, spa, tha, tpa):
    """ARP for hardware type 7 (ARCNET), one octet hardware addresses"""
    return struct.pack('>HHBBH', 7, 0x0800, 1, 4, op) + bytes([sha]) + capgen.ip4(spa) + \
        bytes([tha]) + capgen.ip4(tpa)


def ipx_packet(data, sock=0x4000):
    return struct.pack('>HHBB', 0xffff, 30 + len(data), 0, 4) + \
        struct.pack('>I6sH', 1, bytes([0, 0, 0, 0, 0, 2]), sock) + \
        struct.pack('>I6sH', 1, bytes([0, 0, 0, 0, 0, 1]), sock) + data


def ddp(data):
    """Extended DDP header: hop count and length, checksum, networks,
    nodes, sockets, type"""
    return struct.pack('>HHHHBBBBB', 13 + len(data), 0, 1, 1, 2, 1, 4, 4, 1) + data


def vines_ip(data):
    return struct.pack('>HHBB', 0, 18 + len(data), 0x01, 5) + \
        struct.pack('>IH', 1, 1) + struct.pack('>IH', 1, 2) + data


def bacnet_who_is():
    # LLC (DSAP/SSAP 0x82) + NPDU version 1, no control + APDU unconfirmed Who-Is
    return bytes([0x82, 0x82, 0x03, 0x01, 0x00, 0x10, 0x08])


def payload(pid, n):
    if pid in (IP_1051, IP_1201):
        return ipv4_udp(41000 + n, 7000, b'arcnet datagram %d' % n)
    if pid in (ARP_1051, ARP_1201):
        return arp(1, 1, A4, 0, B4)
    if pid == RARP_1201:
        return arp(3, 1, A4, 1, B4)
    if pid in (IPX, NOVELL_EC):
        return ipx_packet(b'ipx data')
    if pid == IPV6:
        return capgen.ipv6(capgen.udp(b'v6 over arcnet', 41000 + n, 7001, A6, B6), 17, A6, B6)
    if pid == APPLETALK:
        return ddp(b'ddp data')
    if pid == BANYAN:
        return vines_ip(b'vines data')
    if pid == BACNET:
        return bacnet_who_is()
    if pid == ETHERNET:
        return bytes(range(14)) + b'encapsulated ethernet'
    return b'unclaimed protocol %d' % pid


def bsd_frame(src, dst, pid, body, split=None, seq=0, exception=False):
    """BSD header: source, destination, protocol ID, then for the
    protocols that fragment: split flag and sequence (or, for an
    exception frame, 0xff, two padding octets, the protocol ID again and
    the real split flag and sequence)"""
    h = bytes([src, dst, pid])
    if pid not in NO_FRAG:
        if exception:
            h += bytes([0xff, 0, 0, pid])
        h += struct.pack('>BH', 0 if split is None else split, seq)
    return h + body


def linux_frame(src, dst, pid, body, split=None, seq=0, offset=0x0200):
    """Linux header: source, destination, offset field, protocol ID, ..."""
    h = struct.pack('>BBHB', src, dst, offset, pid)
    if pid not in NO_FRAG:
        h += struct.pack('>BH', 0 if split is None else split, seq)
    return h + body


PIDS = (IP_1051, ARP_1051, IP_1201, ARP_1201, RARP_1201, IPX, NOVELL_EC, IPV6,
        ETHERNET, DP_BOOT, DP_MOUNT, POWERLAN, POWERLAN2, LANSOFT, APPLETALK,
        BANYAN, DIAGNOSE, BACNET, 0x99)

outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
w = capgen.Pcapng()
bsd = w.interface(LINKTYPE_ARCNET_BSD)
lin = w.interface(LINKTYPE_ARCNET_LINUX)
t = [0]


def put(iface, data, orig=None):
    t[0] += 1
    w.packet(iface, data, ts=(capgen.TS_BASE + t[0], 0), orig_len=orig)


# Section A: BSD-style frames, every protocol ID (frames 1-19), then
# fragments and exception frames (20-24)
for n, pid in enumerate(PIDS):
    put(bsd, bsd_frame(0x01 + (n & 1), 0x02 - (n & 1), pid, payload(pid, n),
                       split=n & 7 if pid not in NO_FRAG else None, seq=0x1000 + n))
put(bsd, bsd_frame(0x05, 0x00, IP_1201, payload(IP_1201, 20), split=0x03, seq=0xabcd))
put(bsd, bsd_frame(0x05, 0x00, ARP_1201, payload(ARP_1201, 21), split=0x02, seq=0xabce))
put(bsd, bsd_frame(0x06, 0x07, IP_1201, payload(IP_1201, 22), split=0x04, seq=0x0001,
                   exception=True))
put(bsd, bsd_frame(0x06, 0x07, IPV6, payload(IPV6, 23), split=0x06, seq=0x0002, exception=True))
put(bsd, bsd_frame(0x06, 0x07, IP_1051, payload(IP_1051, 24)))
# Section B: Linux-style frames, every protocol ID (frames 25-43), then
# fragments (44-46); a split flag of 0xff is not an exception here
for n, pid in enumerate(PIDS):
    put(lin, linux_frame(0x11 + (n & 1), 0x12 - (n & 1), pid, payload(pid, n),
                         split=n & 7 if pid not in NO_FRAG else None, seq=0x2000 + n,
                         offset=0x0200 + n))
put(lin, linux_frame(0x15, 0x00, IP_1201, payload(IP_1201, 40), split=0x03, seq=0xbcde))
put(lin, linux_frame(0x15, 0x00, IP_1201, payload(IP_1201, 41), split=0xff, seq=0xbcdf))
put(lin, linux_frame(0x15, 0x00, IPV6, payload(IPV6, 42), split=0xff, seq=0xbce0, offset=0))
n_clean = len(w.blocks) - 3
w.write(os.path.join(outdir, 'arcnet-coverage.pcapng'))

# Malformed capture: truncated headers (and one exception header cut inside)
w = capgen.Pcapng()
bsd = w.interface(LINKTYPE_ARCNET_BSD)
lin = w.interface(LINKTYPE_ARCNET_LINUX)
t[0] = 0
for iface, frm in ((bsd, bsd_frame), (lin, linux_frame)):
    full = frm(1, 2, IP_1201, payload(IP_1201, 1), split=1, seq=5)
    hdr = 6 if iface == bsd else 8
    for cut in (0, 1, 2, 3, 4, hdr - 2, hdr - 1, hdr + 1, hdr + 10):
        put(iface, full[:cut])
put(bsd, bsd_frame(1, 2, IP_1201, b'', split=1, seq=1, exception=True)[:5])
put(bsd, bsd_frame(1, 2, IP_1201, b'', split=1, seq=1, exception=True)[:8])
put(bsd, bsd_frame(1, 2, IPX, b'', split=1, seq=1)[:4])
# A split flag of 0xff in a BSD frame is taken for an exception frame
put(bsd, bsd_frame(0xff, 0xff, IP_1201, payload(IP_1201, 25), split=0xff, seq=0x7777))
put(bsd, bsd_frame(1, 2, ARP_1051, payload(ARP_1051, 1))[:10])
put(lin, linux_frame(1, 2, ARP_1051, payload(ARP_1051, 1))[:12])
put(lin, linux_frame(1, 2, BACNET, bacnet_who_is())[:6])
w.write(os.path.join(outdir, 'arcnet-coverage-malformed.pcapng'))
print('arcnet-coverage.pcapng: %d frames' % n_clean)
