#!/usr/bin/env python3
# Generates test/captures/snaeth_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-snaeth.c (SNA over Ethernet, ethertype
# 0x80d5, Ethernet II). Usage: mksnaeth.py <outdir>
import os
import struct
import sys
from pcaplib import Pcap, eth

DLT_EN10MB = 1
ETHERTYPE_SNA = 0x80d5

def snaeth(llc, pad=0, length=None):
    n = len(llc) if length is None else length
    return struct.pack('!HB', n, pad) + llc

def ui(sap, payload):
    return bytes([sap, sap, 0x03]) + payload

def fid2(snf=1, mpf=3):
    return bytes([0x20 | (mpf << 2), 0, 0x12, 0x34]) + struct.pack('!H', snf)

RH = bytes([0x0b, 0x80, 0x00])
DATA = 'SNA OVER ETHERNET'.encode('cp037')

def frame(payload, minimum=60):
    f = eth(payload, ETHERTYPE_SNA)
    return f + b'\0' * max(0, minimum - len(f))

def main(out):
    p = Pcap(DLT_EN10MB)
    # 1: SNA FID2 in an LLC UI frame, length exact
    p.add(frame(snaeth(ui(0x04, fid2() + RH + DATA))))
    # 2: short payload padded by the Ethernet minimum frame size; the
    #    length field cuts the padding off
    p.add(frame(snaeth(ui(0x04, fid2(2) + RH))))
    # 3: non-zero padding octet, SAP 0x08
    p.add(frame(snaeth(ui(0x08, fid2(3) + RH + DATA), pad=0x5a)))
    # 4: LLC I frame with two octet control field
    p.add(frame(snaeth(bytes([0x0c, 0x0c, 0x02, 0x04]) + fid2(4) + RH + DATA)))
    # 5: LLC XID frame with an SNA XID format 0
    p.add(frame(snaeth(bytes([0x04, 0x04, 0xaf]) + bytes([0x02, 0x06, 0x05, 0xd1, 0x23, 0x45]))))
    # 6: LLC to a SAP without a dissector (data)
    p.add(frame(snaeth(ui(0x20, b'\x01\x02\x03\x04'))))
    # 7: length larger than the frame is ignored, the LLC part ends with the frame
    p.add(frame(snaeth(ui(0x04, fid2(5) + RH + DATA), length=0x0400), minimum=0))
    # 8: maximum sized frame with a long SNA payload
    p.add(frame(snaeth(ui(0x04, fid2(6) + RH + DATA * 40))))
    p.write(os.path.join(out, 'snaeth-coverage.pcap'))

    m = Pcap(DLT_EN10MB)
    m.add(eth(b'\x00', ETHERTYPE_SNA))              # header truncated
    m.add(eth(b'\x00\x10\x00' + b'\x04\x04', ETHERTYPE_SNA))   # LLC truncated
    m.add(frame(snaeth(b'', length=0)))               # length zero, no LLC at all
    m.write(os.path.join(out, 'snaeth-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
