#!/usr/bin/env python3
# Generates test/captures/wfleet_hdlc_coverage.cap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-wfleet-hdlc.c (Wellfleet HDLC).

The dissector is reached through WTAP_ENCAP_WFLEET_HDLC, which only the
Network General Sniffer (ngsniffer) reader produces: an "Internetwork
analyzer" file whose frames start with 07 03.  This writes uncompressed
Sniffer files.
    mkwfleet-hdlc.py <outdir>
Writes wfleet-hdlc-coverage.cap and wfleet-hdlc-coverage-malformed.cap
"""
import struct
import socket
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def udp(sp, dp, payload):
    return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload

MAC_A = b'\x02\0\0\0\0\x01'
MAC_B = b'\x02\0\0\0\0\x02'

def eth(dst, src, etype, payload):
    return dst + src + struct.pack('!H', etype) + payload

def whdlc(addr, cmd, inner):
    return bytes([addr, cmd]) + inner

def sniffer(path, frames, maj=4, min_=33, network=7):
    """Uncompressed Sniffer file: version record, then type 4 frame records."""
    out = b'TRSNIFF data    \x1a'
    vers = struct.pack('<hhhhbBbBbbhh', maj, min_, 0, (26 << 9) | (11 << 5) | 13,
                       0, network, 1, 0, 0, 0, 0, 0)
    out += struct.pack('<HHH', 1, len(vers), 0) + vers
    for i, (fr, fs) in enumerate(frames):
        rec = struct.pack('<HHBBhBBhh', (i * 1000) & 0xffff, 0, 0, 0, len(fr), fs, 0, len(fr), 0) + fr
        out += struct.pack('<HHH', 4, len(rec), 0) + rec
    out += struct.pack('<HHH', 3, 0, 0)
    open(path, 'wb').write(out)

def main(outdir):
    good = []
    ipu = ip(17, udp(1024, 9, b'hello wellfleet'))
    # Ethernet II / IPv4 / UDP, in both directions (DTE and DCE flags)
    good.append((whdlc(7, 3, eth(MAC_B, MAC_A, 0x0800, ipu)), 0x80))
    good.append((whdlc(7, 3, eth(MAC_A, MAC_B, 0x0800, ip(17, udp(9, 1024, b'reply'), '192.0.2.2', '192.0.2.1'))), 0x00))
    # ARP request
    arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC_A, socket.inet_aton('192.0.2.1'),
                      b'\0' * 6, socket.inet_aton('192.0.2.2'))
    good.append((whdlc(7, 3, eth(b'\xff' * 6, MAC_A, 0x0806, arp)), 0x80))
    # ICMP echo
    icmp = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'abcd'
    icmp = icmp[:2] + struct.pack('!H', csum(icmp)) + icmp[4:]
    good.append((whdlc(7, 3, eth(MAC_B, MAC_A, 0x0800, ip(1, icmp))), 0x80))
    # 802.3 length field with LLC/SNAP-less payload (IPX-style 0xffff is not used)
    llc = b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + ipu
    good.append((whdlc(7, 3, eth(MAC_B, MAC_A, len(llc), llc)), 0x80))
    # unknown ethertype
    good.append((whdlc(7, 3, eth(MAC_B, MAC_A, 0x88b5, b'payload' * 4)), 0x80))
    # a padded minimum-size frame
    good.append((whdlc(7, 3, eth(MAC_B, MAC_A, 0x0800, ipu).ljust(60, b'\0')), 0x80))
    sniffer(os.path.join(outdir, 'wfleet-hdlc-coverage.cap'), good)
    bad = list(good[:1])
    # only the 2 header bytes: the Ethernet dissector runs out of data
    bad.append((whdlc(7, 3, b''), 0x80))
    # truncated Ethernet header
    bad.append((whdlc(7, 3, MAC_B + b'\x02\0'), 0x80))
    # truncated IP header
    bad.append((whdlc(7, 3, eth(MAC_B, MAC_A, 0x0800, ipu[:12])), 0x80))
    sniffer(os.path.join(outdir, 'wfleet-hdlc-coverage-malformed.cap'), bad)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
