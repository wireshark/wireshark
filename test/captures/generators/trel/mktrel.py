#!/usr/bin/env python3
# Generates test/captures/trel_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds trel-coverage.pcapng and trel-coverage-malformed.pcapng
import struct
import sys
import os
from pcaplib import write_ng, udp, exported_pdu

def hdr(typ=0, ver=0, rsv=0, ack=0, chan=15, pan=0xface, pkt=1, src=0x1122334455667788, dst=0x8877665544332211):
    b0 = (ver << 5) | (rsv << 3) | (ack << 2) | typ
    h = struct.pack('!BBHIQ', b0, chan, pan, pkt, src)
    if typ:
        h += struct.pack('!Q', dst)
    return h

def wpan_data(seq=1, payload=b''):
    # IEEE 802.15.4 data frame, PAN ID compression, short destination and source (no FCS)
    return struct.pack('<HBHHH', 0x8861, seq, 0xface, 0x0001, 0x0002) + payload

def lowpan_udp(sport, dport, data):
    # IPHC: TF elided, NH compressed, HLIM 64, addresses elided; NHC UDP with inline ports
    return b'\x7e\x33\xf0' + struct.pack('!HHH', sport, dport, 0) + data

def beacon(seq=7):
    return struct.pack('<HBH', 0x0000, seq, 0xface)[:0] + struct.pack('<HB', 0x8000, seq) + struct.pack('<HHH', 0xface, 0x0002, 0x0fff) + b'\x00\x00'

def main(out):
    fr = []
    X = lambda p: (1, exported_pdu('trel', p))
    pl = wpan_data(1, lowpan_udp(61631, 61631, b'thread payload'))
    fr.append(X(hdr(0) + pl))                                 # 1 advertisement with a 6LoWPAN UDP frame
    fr.append(X(hdr(1, pkt=2) + wpan_data(2, lowpan_udp(19788, 19788, b'mle'))))   # 2 unicast, destination address
    fr.append(X(hdr(2, ack=1, pkt=3)))                        # 3 ack, no payload (no inner dissection)
    fr.append(X(hdr(2, ack=1, pkt=4) + b''))                  # 4
    fr.append(X(hdr(3, pkt=5) + wpan_data(3)))                # 5 unknown type 3 (dest address too)
    fr.append(X(hdr(0, ver=1, rsv=3, ack=1, chan=26, pan=0xffff, pkt=0xffffffff, src=0) + pl))   # 6 version 1, reserved bits, ack set, extreme values
    fr.append(X(hdr(0, ver=7, pkt=6) + beacon()))             # 7 version 7 with an 802.15.4 beacon frame
    fr.append(X(hdr(0, pkt=8) + wpan_data(4, b'\x00\x01\x02\x03')))   # 9 NALP payload
    # UDP frames to the TREL port: not decoded by default (heuristic off), decoded with
    # --enable-heuristic trel_udp
    fr.append((0, udp(38196, 51234, hdr(0, pkt=9) + pl)))     # 10
    fr.append((0, udp(51234, 38196, hdr(1, pkt=10) + pl)))    # 11
    fr.append((0, udp(38196, 38196, hdr(0, pkt=11) + pl)))    # 12 same ports: heuristic declines
    fr.append((0, udp(38196, 51235, b'\x00' * 15)))           # 13 shorter than 16: declined
    fr.append((0, udp(38196, 51236, b'\xe0' + hdr(0)[1:] + pl)))   # 14 first octet has version bits 7: declined... (E0 mask)
    fr.append((0, udp(38196, 51237, hdr(2, ack=1, pkt=12) + b'')))  # 15 ack, 16 octets exactly? (type 2 is 16 octets)
    write_ng(os.path.join(out, 'trel-coverage.pcapng'), [1, 252], fr)
    print('main frames', len(fr))
    m = []
    m.append(X(hdr(1, pkt=7) + b'\xff\xee\xdd'))             # payload that is not 802.15.4
    m.append(X(hdr(1)[:12]))                                   # header cut inside the source address
    m.append(X(hdr(0)[:5]))                                    # shorter than the fixed fields
    m.append(X(hdr(1, pkt=1)[:20]))                            # destination address cut short
    m.append(X(hdr(0) + wpan_data(9)[:4]))                     # truncated 802.15.4 frame
    write_ng(os.path.join(out, 'trel-coverage-malformed.pcapng'), [1, 252], m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
