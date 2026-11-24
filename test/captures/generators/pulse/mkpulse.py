#!/usr/bin/env python3
# Generates test/captures/pulse_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the PULSE coverage captures. Usage: mkpulse.py <outdir>"""
import struct
import sys
import os

def pcap(fname, pkts):
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
    for i, pkt in enumerate(pkts):
        out.append(struct.pack('<IIII', 1700000000 + i, 0, len(pkt), len(pkt)) + pkt)
    open(fname, 'wb').write(b''.join(out))

def udp(payload, sport=539, dport=539):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    eth = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00'
    return eth + ip + u

RUN, STOP = 0xbdaddbda, 0xadbddabd

def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    main_pkts = [
        udp(struct.pack('<I', RUN)),            # 1 little endian running
        udp(struct.pack('<I', STOP)),           # 2 little endian stopped
        udp(struct.pack('>I', RUN)),            # 3 big endian running
        udp(struct.pack('>I', STOP)),           # 4 big endian stopped
        udp(struct.pack('<I', RUN) + b'trailing padding'),  # 5 extra bytes
        udp(struct.pack('>I', STOP) + b'\0' * 20),          # 6
        udp(b'\x01\x02\x03'),                   # 7 too short: not PULSE
        udp(struct.pack('<I', 0x12345678)),     # 8 unknown magic: not PULSE
    ]
    pcap(os.path.join(out, 'pulse-coverage.pcap'), main_pkts)
    # PULSE has no paths that raise exceptions; keep a small malformed
    # capture with the rejects only, for symmetry with the other directories.
    pcap(os.path.join(out, 'pulse-coverage-malformed.pcap'), [
        udp(b''), udp(b'\xbd\xad'), udp(struct.pack('<I', RUN ^ 1))])

main()
