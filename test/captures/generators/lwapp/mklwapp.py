#!/usr/bin/env python3
# Generates test/captures/lwapp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic LWAPP coverage captures for
epan/dissectors/packet-lwapp.c.  Every packet is built with struct;
nothing comes from a real network.

Usage: mklwapp.py <outdir>
Writes lwapp-coverage.pcap (main) and lwapp-coverage-malformed.pcap
(Ethernet link type).
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def eth(payload, etype=0x0800, n=1):
    return bytes([2, 0, 0, 0, 0, n]) + bytes([2, 0, 0, 0, 0, n + 1]) + struct.pack('>H', etype) + payload


IPID = [0]


def ipudp(dport, payload, sport=40000):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    IPID[0] += 1
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), IPID[0], 0, 64, 17, 0,
                      bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + udp


def lwhdr(flags, length, frag=0, rssi=0x40, snr=0x20):
    return struct.pack('>BBHBB', flags, frag, length, rssi, snr)


def mac(n):
    return bytes([2, 0, 0, 0, 0, n])


ARP_REQUEST = (struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + mac(0x30) + bytes([192, 0, 2, 5])
               + bytes(6) + bytes([192, 0, 2, 6]))


def wlan_data(llc_type=0x0800, payload=None):
    # 802.11 data frame, to DS, with an LLC/SNAP header; the default payload is IPv4/UDP (or ARP)
    if payload is None:
        payload = ARP_REQUEST if llc_type == 0x0806 else ipudp(9999, b'lwapp test data')
    return (bytes([0x08, 0x01, 0, 0]) + mac(0x10) + mac(0x11) + mac(0x12) + b'\x00\x00'
            + b'\xaa\xaa\x03\x00\x00\x00' + struct.pack('>H', llc_type) + payload)


def cntl(mtype, seq=1, body=b'', length=None):
    return struct.pack('>BBH', mtype, seq, len(body) if length is None else length) + body


def nested_lwapp(levels):
    inner = lwhdr(0x04, len(cntl(7))) + cntl(7)
    for _ in range(levels):
        w = wlan_data(0x88bb, inner)
        inner = lwhdr(0x00, len(w)) + w
    return inner


def main_frames():
    F = []
    # 802.11 data over UDP 12222, flag combinations: version, slot id,
    # fragment, fragment type, with RSSI and SNR
    for flags, frag, rssi, snr in ((0x00, 0, 0x40, 0x20), (0x68, 1, 0x30, 0x10),
                                   (0x03, 2, 0x7f, 0x01), (0xc2, 0xff, 0x00, 0xff),
                                   (0x38, 9, 0x11, 0x22)):
        w = wlan_data()
        F.append(eth(ipudp(12222, lwhdr(flags, len(w), frag, rssi, snr) + w)))
    # 802.11 data with a different LLC type and a beacon
    w = wlan_data(0x0806)
    F.append(eth(ipudp(12222, lwhdr(0x00, len(w)) + w)))
    beacon = (bytes([0x80, 0x00, 0, 0]) + b'\xff' * 6 + mac(0x10) + mac(0x10) + b'\x00\x00'
              + bytes(8) + struct.pack('<HH', 100, 0x0401) + b'\x00\x04LWAP' + b'\x01\x04\x82\x84\x8b\x96')
    F.append(eth(ipudp(12222, lwhdr(0x00, len(beacon)) + beacon)))
    # Control packets to UDP 12223 (AP identity first), every message type
    for t in range(1, 36):
        body = bytes(range(t, t + 4))
        F.append(eth(ipudp(12223, mac(0x20 + t) + lwhdr(0x04, len(cntl(t, t, body))) +
                           cntl(t, t, body))))
    # control message types outside the table, no payload
    for t in (0, 36, 255):
        F.append(eth(ipudp(12223, mac(0x20) + lwhdr(0x04, 4) + cntl(t, 7))))
    # control packet to UDP 12222: no AP identity
    F.append(eth(ipudp(12222, lwhdr(0x04, 8) + cntl(5, 3, b'abcd'))))
    # control packet with the fragment flags, from the AP side
    F.append(eth(ipudp(12223, mac(0x30) + lwhdr(0x07, 8, 3) + cntl(2, 9, b'wxyz')), n=5))
    # LWAPP directly over Ethernet, both ethertypes
    F.append(eth(lwhdr(0x04, 8) + cntl(18, 1, b'echo'), etype=0x88bb))
    w = wlan_data()
    F.append(eth(lwhdr(0x00, len(w)) + w, etype=0xbbbb))
    # LWAPP-L3 (UDP 12220): an Ethernet frame inside the datagram, which
    # holds IP/UDP with a control packet, an 802.11 packet, a non-IP frame
    inner = eth(ipudp(12223, mac(0x40) + lwhdr(0x04, 8) + cntl(3, 2, b'join')), n=7)
    F.append(eth(ipudp(12220, inner)))
    inner = eth(ipudp(12222, lwhdr(0x00, len(w)) + w), n=9)
    F.append(eth(ipudp(12220, inner)))
    F.append(eth(ipudp(12220, eth(ARP_REQUEST + bytes(18), etype=0x0806, n=11))))
    # nested encapsulation (10 levels is the limit; 9 are fine)
    F.append(eth(nested_lwapp(9), etype=0x88bb))
    return F


def malformed_frames():
    F = []
    # nesting beyond the limit of 10 levels, expert info
    F.append(eth(nested_lwapp(20), etype=0x88bb))
    F.append(eth(nested_lwapp(11), etype=0x88bb))
    # LWAPP-L3 nested in itself, each level an Ethernet/IP/UDP frame
    inner = eth(ipudp(12223, mac(0x20) + lwhdr(0x04, 4) + cntl(7)))
    for _ in range(600):
        inner = eth(ipudp(12220, inner))
        if len(inner) > 60000:
            break
    F.append(inner)
    # control packet to 12223 cut inside the AP identity / the header
    F.append(eth(ipudp(12223, mac(0x20) + b'\x04')))
    F.append(eth(ipudp(12223, b'\x02\x00\x00')))
    # header cut short on port 12222
    F.append(eth(ipudp(12222, lwhdr(0x04, 0)[:5] + b'')))
    F.append(eth(ipudp(12222, lwhdr(0x04, 0) + b'\x01')))
    # control message with a type but no sequence number or length
    F.append(eth(ipudp(12222, lwhdr(0x04, 1) + b'\x01\x02')))
    # 802.11 payload cut inside the frame control
    F.append(eth(ipudp(12222, lwhdr(0x00, 2) + b'\x08')))
    # a length field that is larger than the payload
    w = wlan_data()
    F.append(eth(ipudp(12222, lwhdr(0x00, 5000) + w)))
    F.append(eth(ipudp(12223, mac(0x20) + lwhdr(0x04, 5000) + cntl(7, 1, b'ab', length=5000))))
    # LWAPP-L3 with a truncated Ethernet header
    F.append(eth(ipudp(12220, b'\x01\x02\x03')))
    # 802.11 frames for the swap-frame-control preference
    F.append(eth(ipudp(12222, lwhdr(0x00, len(w)) + bytes([0x01, 0x08]) + w[2:])))
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'lwapp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'lwapp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
