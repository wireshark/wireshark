#!/usr/bin/env python3
# Generates test/captures/rudp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RUDP coverage captures. Usage: mkrudp.py <outdir>"""
import sys
import os
import struct
from pcaplib import Pcap, udp_frame

PORT = 7000

def rudp(flags, hlen, seq, ack, extra=b'', payload=b''):
    return struct.pack('>BBBB', flags, hlen, seq, ack) + extra + payload

def main(out):
    p = Pcap()
    def f(data, sport=PORT, dport=PORT):
        p.add(udp_frame(data, sport, dport))
    sm = bytes.fromhex('0001000c0000000000000001')   # Cisco SM payload (message type 1)
    # 1: SYN with header length 4 (no checksum)
    f(rudp(0x80, 4, 1, 0))
    # 2: SYN+ACK, header 6 with checksum
    f(rudp(0xc0, 6, 2, 1, b'\x12\x34'))
    # 3: ACK only
    f(rudp(0x40, 4, 3, 2))
    # 4: EAK
    f(rudp(0x20, 6, 4, 3, b'\xab\xcd'))
    # 5: RST
    f(rudp(0x10, 4, 5, 4))
    # 6: NUL
    f(rudp(0x08, 4, 6, 5))
    # 7: CHK with header 6 and SM payload
    f(rudp(0x44, 6, 7, 6, b'\x00\x00', sm))
    # 8: TCS, header 4 with SM payload
    f(rudp(0x42, 4, 8, 7, b'', sm))
    # 9: bit 0 set, header 10: 4 unknown octets after the checksum are shown as data
    f(rudp(0x01, 10, 9, 8, b'\x00\x01\xde\xad\xbe\xef', sm))
    # 10: all flags set, header 8, with payload
    f(rudp(0xff, 8, 10, 9, b'\xff\xff\x01\x02', sm))
    # 11: header only, no checksum field shown for header 4 and nothing after
    f(rudp(0x00, 4, 0, 0))
    # 12: header length 0 (the protocol item has no length)
    f(rudp(0x00, 0, 0, 0, b'', b'\x00\x00'))
    p.write(os.path.join(out, 'rudp-coverage.pcap'))

    m = Pcap()
    # header length 250, truncated: exception at the data subset
    m.add(udp_frame(rudp(0x80, 250, 1, 0, b'\x00' * 6), PORT, PORT))
    # header length beyond the packet with only 3 bytes of header
    m.add(udp_frame(b'\x80\x04\x01', PORT, PORT))
    # one octet only
    m.add(udp_frame(b'\x80', PORT, PORT))
    m.write(os.path.join(out, 'rudp-coverage-malformed.pcap'))

main(sys.argv[1])
