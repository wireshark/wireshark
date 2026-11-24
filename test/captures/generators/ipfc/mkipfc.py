#!/usr/bin/env python3
# Generates test/captures/ipfc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ipfc.c (IP over Fibre Channel, pcap link
type 122).  Usage: mkipfc.py <outdir> [-v]
Writes ipfc-coverage.pcap (main) and ipfc-coverage-malformed.pcap."""
import struct
import sys
import os

DLT_IP_OVER_FC = 122


def cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(payload, proto, src=bytes([192, 0, 2, 1]), dst=bytes([192, 0, 2, 2])):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64,
                    proto, 0, src, dst)
    h = h[:10] + struct.pack('!H', cksum(h)) + h[12:]
    return h + payload


def icmp_echo(data=b'ipfc'):
    h = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + data
    return h[:2] + struct.pack('!H', cksum(h)) + h[4:]


def udp(sp, dp, data):
    return struct.pack('!HHHH', sp, dp, 8 + len(data), 0) + data


def snap(oui, pid, payload):
    return b'\xaa\xaa\x03' + oui + struct.pack('!H', pid) + payload


def wwn(naa, n):
    """An 8 byte Fibre Channel name: NAA nibble then made-up bytes."""
    return bytes([(naa << 4) | 0, 0, 0, 0xc0, 0xff, 0xee, 0, n])


def frame(da, sa, llc):
    return da + sa + llc


def arp_request():
    return struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1,
                       bytes([2, 0, 0, 0, 0, 1]), bytes([192, 0, 2, 1]),
                       bytes(6), bytes([192, 0, 2, 2]))


class Cap:
    def __init__(self):
        self.frames = []
        self.marks = []

    def add(self, d):
        self.frames.append(d)

    def mark(self, name):
        self.marks.append((len(self.frames) + 1, name))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535,
                                DLT_IP_OVER_FC))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
                f.write(d)


def main_cap():
    c = Cap()
    c.mark('ip_snap')
    # one frame per NAA type of the name format (IEEE 48 bit, extended,
    # registered, ...), carrying IPv4 over LLC/SNAP
    for naa in (0, 1, 2, 5, 6, 12, 15):
        c.add(frame(wwn(naa, 1), wwn(naa, 2),
                    snap(b'\0\0\0', 0x0800, ip4(icmp_echo(), 1))))
    c.mark('other_payloads')
    c.add(frame(wwn(1, 3), wwn(1, 4),
                snap(b'\0\0\0', 0x0800, ip4(udp(40000, 40001, b'fc'), 17))))
    c.add(frame(wwn(1, 3), wwn(1, 4), snap(b'\0\0\0', 0x0806, arp_request())))
    c.add(frame(bytes([0xff] * 8), wwn(1, 4),
                snap(b'\0\0\0', 0x0806, arp_request())))        # broadcast
    c.add(frame(wwn(1, 3), wwn(1, 4), snap(b'\0\0\0', 0x86dd,
                struct.pack('!IHBB16s16s', 0x60000000, 0, 59, 64, bytes(16), bytes(16)))))
    c.add(frame(wwn(1, 3), wwn(1, 4), b'\x06\x06\x03' + ip4(icmp_echo(), 1)))  # LLC SAP IP
    c.add(frame(wwn(1, 3), wwn(1, 4), b'\x04\x04\x03' + b'sna'))
    c.add(frame(wwn(1, 3), wwn(1, 4), b'\x01\x01\x03'))             # LLC, no data
    return c


def malformed_cap():
    c = Cap()
    full = frame(wwn(1, 3), wwn(1, 4),
                 snap(b'\0\0\0', 0x0800, ip4(icmp_echo(), 1)))
    for n in (0, 1, 8, 15, 16, 17, 18, 20):
        c.add(full[:n])
    c.add(frame(wwn(1, 3), wwn(1, 4), snap(b'\0\0\0', 0x0800, b'\x45\0')))
    c.add(frame(wwn(1, 3), wwn(1, 4), snap(b'\0\0\0', 0x0800, b'')))
    # payloads that the LLC sub-dissectors reject
    c.add(frame(wwn(1, 3), wwn(1, 4), snap(b'\0\x00\x0c', 0x2000, b'cdp-ish')))
    c.add(frame(wwn(1, 3), wwn(1, 4), b'\x42\x42\x03' + b'\0' * 12))
    c.add(frame(wwn(1, 3), wwn(1, 4), b'\xe0\xe0\x03' + b'\0' * 4))
    c.add(frame(wwn(1, 3), wwn(1, 4), b'\xf0\xf0\x03' + b'netbios'))
    c.add(frame(wwn(1, 3), wwn(1, 4), b'\xaa\xaa\x03\x08\x00\x07\x80\x9b' + b'appletalk'))
    return c


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_cap()
    m.write(os.path.join(out, 'ipfc-coverage.pcap'))
    x = malformed_cap()
    x.write(os.path.join(out, 'ipfc-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, nm in m.marks:
            print(n, nm)
        print('main frames', len(m.frames), 'malformed', len(x.frames))


main()
