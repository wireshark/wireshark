#!/usr/bin/env python3
# Generates test/captures/pagp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the PAgP coverage captures. Usage: mkpagp.py <outdir> [-v]
# PAgP is carried in 802.3/LLC/SNAP frames with the Cisco OUI and PID 0x0104
# to the multicast address 01:00:0c:cc:cc:cc (registered by default).
import os
import struct
import sys
from pcaplib import write_pcap

def mac(n): return bytes([2, 0, 0, 0, 0, n])
def tlv(t, body, length=None): return struct.pack('>HH', t, 4 + len(body) if length is None else length) + body

def info(version=1, flags=0, tlvs=(), ntlvs=None, local=1, partner=2, extra=b''):
    b = bytes([version, flags]) + mac(local) + bytes([1, 128]) + struct.pack('>III', 0x10001, 0x20002, 0x30003)
    b += mac(partner) + bytes([2, 64]) + struct.pack('>III', 0x40004, 0x50005, 0x60006) + struct.pack('>H', 7)
    t = b''.join(tlvs)
    b += struct.pack('>H', len(tlvs) if ntlvs is None else ntlvs) + t
    return b + extra

def flush(local=1, partner=2, trans=0xdeadbeef):
    return bytes([2, 0]) + mac(local) + mac(partner) + struct.pack('>I', trans)

def frame(pdu, src=1):
    llc = bytes([0xaa, 0xaa, 0x03, 0, 0, 0x0c, 0x01, 0x04]) + pdu
    return bytes.fromhex('01000ccccccc') + mac(src) + struct.pack('>H', len(llc)) + llc

def main_frames():
    F, marks = [], []
    def mark(n): marks.append((n, len(F) + 1))
    def add(p, src=1): F.append(frame(p, src))
    mark('Info PDUs: all flags and the TLVs (device name, port name, agport MAC, reserved), no flags and no TLVs, unknown PDU version')
    add(info(flags=7, tlvs=[tlv(1, b'switch-a\0\0\0\0'), tlv(2, b'Gi1/0/1\0'), tlv(3, mac(0x33)), tlv(4, b'\0\0\0\0')]))
    add(info(flags=0, tlvs=[]), src=2)
    add(info(flags=3, tlvs=[tlv(1, b'sw'), tlv(9, b'\x01\x02\x03\x04')]))
    add(info(version=3, flags=1))
    mark('Flush PDU')
    add(flush())
    mark('invalid TLV lengths: 2 (the reproducer, below 4), 0 and past the end of the PDU')
    add(info(flags=1, tlvs=[tlv(1, b'', length=2), tlv(2, b'eth0')], ntlvs=2))
    add(info(flags=1, tlvs=[tlv(1, b'', length=0)], ntlvs=1))
    add(info(flags=1, tlvs=[tlv(2, b'abcd', length=40)], ntlvs=1))
    return F, marks

def malformed_frames():
    F = []
    F.append(frame(info(flags=1)[:30]))                       # Info PDU cut short
    F.append(frame(flush()[:10]))                             # Flush PDU cut short
    F.append(frame(info(flags=1, tlvs=[tlv(1, b'ab')], ntlvs=3)))   # more TLVs than the PDU holds
    F.append(frame(info(flags=1)[:46 - 1]))                   # TLV count cut short
    F.append(frame(info(flags=1, tlvs=[tlv(3, mac(1))[:8]], ntlvs=1)))   # agport MAC cut short
    F.append(frame(b'\x01'))                                  # one octet
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'pagp-coverage.pcap'), F)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'pagp-coverage-malformed.pcap'), M)
    if '-v' in sys.argv:
        for n, s in marks: print(s, n)
        print(len(F), 'frames', len(M), 'malformed frames')
