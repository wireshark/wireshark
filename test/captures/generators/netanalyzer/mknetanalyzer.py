#!/usr/bin/env python3
# Generates test/captures/netanalyzer_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the netANALYZER coverage captures.  Usage: mknetanalyzer.py <outdir>
Writes netanalyzer-coverage.pcapng (main) and netanalyzer-coverage-malformed.pcapng.
Interface 0 is LINKTYPE_NETANALYZER (240), interface 1 LINKTYPE_NETANALYZER_TRANSPARENT (241).
Everything is synthetic (192.0.2.0/24, locally administered MAC addresses)."""
import struct
import sys
import os
import zlib
from netlib import csum, ip4, write_pcapng

def hdr(status=0, version=1, port=0, length=64, ptype=0, transparent=False, gpio=False):
    b1 = (1 if gpio else 0) | (2 if transparent else 0) | (version << 2) | (port << 6)
    return bytes([status, b1]) + struct.pack('<H', (length & 0xfff) | (ptype << 12))

def eth(dst, src, etype, payload):
    return dst + src + struct.pack('!H', etype) + payload

def fcs(frame):
    return struct.pack('<I', zlib.crc32(frame) & 0xffffffff)

def udp_frame(sport=1234, dport=5678, data=b'netANALYZER test payload'):
    u = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 7, 0, 64, 17, 0, ip4('192.0.2.1'), ip4('192.0.2.2'))
    iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
    f = eth(b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01', 0x0800, iph + u)
    return f + b'\0' * max(0, 60 - len(f))

def arp_frame():
    a = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, b'\x02\0\0\0\0\x01', ip4('192.0.2.1'), bytes(6), ip4('192.0.2.2'))
    f = eth(b'\xff' * 6, b'\x02\0\0\0\0\x01', 0x0806, a)
    return f + b'\0' * (60 - len(f))

def gpio(number, edge, length=64, port=0, tail=None):
    body = bytes(6) + bytes([0x00, 0x02, 0xa2, 0xff, 0xff, 0xff, 0x88, 0xff, 0x00, number, edge])
    b = hdr(0, 1, port, length, gpio=True) + body
    return b + bytes(max(0, length - len(b)))

def build_main():
    frames = []                      # (interface, bytes)
    # --- Ethernet capture mode (link type 240): the frame ends with its FCS
    for frm in (udp_frame(), arp_frame()):
        frm = frm + fcs(frm)
        for version, ptype in ((1, 0), (2, 0)):
            for port in range(4):
                frames.append((0, hdr(0, version, port, len(frm), ptype) + frm))
    frm = udp_frame(data=b'status bits')
    frm += fcs(frm)
    # every status bit and some combinations (the frame data are unchanged)
    for status in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff, 0x05, 0x24, 0x12, 0x81):
        frames.append((0, hdr(status, 1, status & 3, len(frm)) + frm))
    # lengths: 1 byte and the maximum of 12 bits
    frames.append((0, hdr(0, 1, 0, 1) + frm))
    frames.append((0, hdr(0, 2, 1, 0xfff, 0) + frm))
    # transparent flag in an Ethernet mode record: a note, and with an alignment error a warning
    frames.append((0, hdr(0x00, 2, 0, len(frm), 0, transparent=True) + frm))
    frames.append((0, hdr(0x02, 2, 1, len(frm), 0, transparent=True) + frm))
    frames.append((0, hdr(0x06, 1, 2, len(frm), transparent=True) + frm))
    # buffer state entries: overflow and recovery, every source, every port
    for state in (0, 1):
        for source in range(5):
            frames.append((0, hdr(state | (source << 4), 2, source & 3, 64, 2) + bytes(60)))
    # time ticks
    frames.append((0, hdr(0, 2, 0, 64, 3) + bytes(60)))
    frames.append((0, hdr(0, 2, 3, 64, 3) + bytes(8)))
    # GPIO events
    for number in range(4):
        for edge in (0, 1):
            frames.append((0, gpio(number, edge, port=number)))
    frames.append((0, gpio(1, 0, length=21)))                   # no padding after the event
    # --- transparent mode (link type 241): the payload is shown as data
    for status in (0x00, 0x02, 0x04, 0x82):
        raw = b'\x55' * 7 + b'\xd5' + udp_frame()
        raw += fcs(raw[8:])
        frames.append((1, hdr(status, 1, status & 3, len(raw), transparent=True) + raw))
    raw = b'\x55' * 7 + b'\xd5' + arp_frame()
    frames.append((1, hdr(0, 2, 2, len(raw), 0, transparent=True) + raw + fcs(raw[8:])))
    frames.append((1, hdr(0x01, 2, 0, 64, 2) + bytes(60)))          # buffer state
    frames.append((1, hdr(0x20, 2, 1, 64, 2) + bytes(60)))
    frames.append((1, hdr(0, 2, 0, 64, 3) + bytes(60)))             # time tick
    frames.append((1, gpio(2, 1)))
    frames.append((1, gpio(0, 0, port=1)))
    # the reproducer of "netANALYZER: Do not make decoding depend on the tree": records that
    # must not go to the Ethernet dissector (GPIO, buffer state, time tick), in this order
    frames.append((0, gpio(3, 1)))
    frames.append((0, hdr(0x31, 2, 0, 64, 2) + bytes(60)))
    frames.append((0, hdr(0x00, 2, 0, 64, 3) + bytes(60)))
    return frames

def build_malformed():
    frames = []
    frames.append((0, hdr(0, 2, 0, 64, 1) + bytes(60)))             # PROFIBUS: not implemented
    frames.append((0, hdr(0, 2, 0, 64, 4) + bytes(60)))             # reserved type: wrong header
    frames.append((0, hdr(0, 2, 0, 64, 15) + bytes(60)))
    frames.append((0, hdr(0, 3, 0, 64, 0) + bytes(60)))             # unknown version
    frames.append((0, hdr(0, 0, 0, 64, 0) + bytes(60)))
    frames.append((0, hdr(0, 15, 0, 64, 0) + bytes(60)))
    # GPIO flag with an inconsistent definition
    g = bytearray(gpio(0, 0)); g[10] = 1; frames.append((0, bytes(g)))
    g = bytearray(gpio(0, 0)); g[18] = 1; frames.append((0, bytes(g)))
    # shorter than the header
    frames.append((0, b'\0\0\0'))
    frames.append((0, b''))
    frames.append((1, b'\0\0'))
    # transparent mode: records that are not Ethernet
    frames.append((1, hdr(0, 2, 0, 64, 1) + bytes(60)))
    frames.append((1, hdr(0, 2, 0, 64, 4) + bytes(60)))
    g = bytearray(gpio(0, 0)); g[11] = 1; frames.append((1, bytes(g)))
    # GPIO record too short to hold the definition
    frames.append((0, hdr(0, 1, 0, 8, gpio=True) + bytes(6)))
    frames.append((0, hdr(0, 1, 0, 8, gpio=True) + bytes(8) + b'\0\2\xa2\xff\xff\xff\x88\xff\0'))
    # an Ethernet record whose payload is cut
    frm = udp_frame(); frames.append((0, hdr(0, 1, 0, 60) + frm[:30]))
    frames.append((0, hdr(0, 1, 0, 60)))
    return frames

if __name__ == '__main__':
    out = sys.argv[1]
    m = build_main()
    write_pcapng(os.path.join(out, 'netanalyzer-coverage.pcapng'), m, linktypes=(240, 241))
    x = build_malformed()
    write_pcapng(os.path.join(out, 'netanalyzer-coverage-malformed.pcapng'), x, linktypes=(240, 241))
    print(len(m), len(x))
