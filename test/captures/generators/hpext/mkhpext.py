#!/usr/bin/env python3
# Generates test/captures/hpext_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the HPEXT dissector (packet-hpext.c).

HP Extended Local-Link Control is carried over 802.3 + LLC with the
destination SAP 0xF8 (SAP_HPEXT), so a real capture reaches it by
default. A 7 octet header (3 reserved octets, 16 bit DXSAP, 16 bit
SXSAP) selects the payload dissector through the "hpext.dxsap" table:
RMP (0x0608 and 0x0609), the HP Switch Protocol (0x0623) and SNMP
(0x165A). Every packet is built with struct; nothing is captured.

Usage: mkhpext.py <output directory>
Writes hpext-coverage.pcap and hpext-coverage-malformed.pcap.
"""
import struct
import sys
import os

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

def mac(s):
    return bytes.fromhex(s.replace(':', ''))

def frame(payload, dsap=0xF8, ssap=0xF8, ctrl=3, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'):
    llc = struct.pack('!BBB', dsap, ssap, ctrl) + payload
    return mac(dst) + mac(src) + struct.pack('!H', len(llc)) + llc

def hpext(dx, sx, payload=b'', reserved=0):
    return struct.pack('!I', reserved)[1:] + struct.pack('!HH', dx, sx) + payload

def rmp_boot_req():
    return (struct.pack('!BBIHH', 1, 0, 0x01020304, 0x1234, 2) +
            b'HP9000/712'.ljust(20, b' ') + bytes([8]) + b'SYSHPBSD' + b'tail')

def rmp_boot_repl():
    return struct.pack('!BBIHH', 129, 0, 0x01020304, 0x1234, 2) + bytes([4]) + b'BOOT'

def rmp_read_req():
    return struct.pack('!BBIHH', 2, 0, 0x1000, 0x1234, 512)

def rmp_read_repl():
    return struct.pack('!BBIH', 130, 2, 0x1000, 0x1234) + b'\xde\xad' * 8

def rmp_boot_done():
    return struct.pack('!BBIH', 3, 0, 0, 0x1234)

def hpsw_tlv(t, v):
    return bytes([t, len(v)]) + v

def hpsw():
    p = bytes([1, 2])
    p += hpsw_tlv(1, b'switch1')
    p += hpsw_tlv(2, b'K.15.01')
    p += hpsw_tlv(3, b'config')
    p += hpsw_tlv(4, mac('02:00:00:00:00:aa'))
    p += hpsw_tlv(5, bytes([192, 0, 2, 5]))
    p += hpsw_tlv(6, b'\x00\x07')
    p += hpsw_tlv(7, b'domain')
    p += hpsw_tlv(8, b'\x00\x08')
    p += hpsw_tlv(9, b'\x00\x09')
    p += hpsw_tlv(10, b'\x00\x00\x00\x0a')
    p += hpsw_tlv(11, mac('02:00:00:00:00:b1') + mac('02:00:00:00:00:b2'))
    p += hpsw_tlv(12, b'\x01')
    p += hpsw_tlv(13, mac('02:00:00:00:00:cc') + b'idextra')
    p += hpsw_tlv(14, mac('02:00:00:00:00:dd'))
    p += hpsw_tlv(0x20, b'unknown')
    return p

def snmp_get():
    def tlv(t, v): return bytes([t, len(v)]) + v
    vb = tlv(0x30, tlv(0x06, bytes([0x2b, 6, 1, 2, 1, 1, 1, 0])) + tlv(0x05, b''))
    pdu = tlv(0xa0, tlv(2, b'\x01') + tlv(2, b'\x00') + tlv(2, b'\x00') + tlv(0x30, vb))
    return tlv(0x30, tlv(2, b'\x00') + tlv(4, b'public') + pdu)

def main_frames():
    F = []
    # 1-5: RMP behind DXSAP 0x0608 (all five RMP types)
    for p in (rmp_boot_req(), rmp_boot_repl(), rmp_read_req(), rmp_read_repl(), rmp_boot_done()):
        F.append(frame(hpext(0x0608, 0x0609, p)))
    # 6: DXSAP 0x0609 also selects RMP; SXSAP 0x0608
    F.append(frame(hpext(0x0609, 0x0608, rmp_boot_done())))
    # 7: HP Switch Protocol with every TLV type
    F.append(frame(hpext(0x0623, 0x0623, hpsw())))
    # 8: SNMP (the SXSAP shows SNMP too)
    F.append(frame(hpext(0x165A, 0x165A, snmp_get())))
    # 9: unknown DXSAP and SXSAP: payload goes to the data dissector
    F.append(frame(hpext(0x1234, 0xabcd, b'unknown payload')))
    # 10: header only, no payload
    F.append(frame(hpext(0x0608, 0x0609)))
    # 11: non-zero reserved octets, SXSAP is SNMP, DXSAP unknown
    F.append(frame(hpext(0x0001, 0x165A, b'\x01\x02\x03', reserved=0xabcdef)))
    # 12: unknown DXSAP, source SAP also HPSW
    F.append(frame(hpext(0x00ff, 0x0623, b'x')))
    return F

def malformed_frames():
    F = []
    F.append(frame(hpext(0x0608, 0x0609)[:6]))      # header cut inside SXSAP
    F.append(frame(hpext(0x0608, 0x0609)[:3]))      # header cut after reserved
    F.append(frame(hpext(0x0623, 0x0623, bytes([1, 2, 1, 9, 1]))))   # hpsw TLV length past the end
    F.append(frame(hpext(0x0608, 0x0609, b'\x01\x00\x00')))         # RMP boot request cut short
    F.append(frame(hpext(0x165A, 0x165A, b'\x30\x84\xff\xff\xff\xff'))) # SNMP bad length
    return F

if __name__ == '__main__':
    d = sys.argv[1]
    os.makedirs(d, exist_ok=True)
    pcap(os.path.join(d, 'hpext-coverage.pcap'), main_frames())
    pcap(os.path.join(d, 'hpext-coverage-malformed.pcap'), malformed_frames())
