#!/usr/bin/env python3
# Generates test/captures/mndp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MNDP coverage captures.  Usage: mkmndp.py <outdir> [-v]
MNDP is on UDP 5678 by default (frames to the Ethernet broadcast address, as
Mikrotik devices send them); its UDP heuristic is disabled by default, so
two frames on another port are decoded only with --enable-heuristic mndp_udp.
Writes mndp-coverage.pcap and mndp-coverage-malformed.pcap."""
import struct
import sys
import os

def pcap(name, pkts):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            wire = len(p)
            if isinstance(p, tuple):
                p, wire = p
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), wire))
            f.write(p)

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

SRC = bytes([192, 0, 2, 1]); DST = bytes([255, 255, 255, 255])
ipid = [0]
def frame(payload, sport=5678, dport=5678):
    ln = 8 + len(payload)
    ph = SRC + DST + struct.pack('>BBH', 0, 17, ln)
    u = struct.pack('>HHHH', sport, dport, ln, 0)
    u = struct.pack('>HHHH', sport, dport, ln, csum(ph + u + payload) or 0xffff) + payload
    ipid[0] += 1
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ipid[0], 0, 64, 17, 0, SRC, DST)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return b'\xff' * 6 + bytes.fromhex('020000000001') + b'\x08\x00' + h + u

def tlv(t, v): return struct.pack('>HH', t, len(v)) + v
def mndp(seq, *tlvs, unk=b'\x00\x00'):
    return unk + struct.pack('>H', seq) + b''.join(tlvs)

MAC = tlv(1, bytes.fromhex('020000aabbcc'))

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    pk, marks = [], []
    def add(p, label):
        pk.append(p); marks.append((len(pk), label))
    full = mndp(1, MAC, tlv(5, b'MikroTik'), tlv(7, b'6.48.6 (long-term)'), tlv(8, b'MikroTik'),
                tlv(10, struct.pack('<I', 86400 * 3 + 3661)), tlv(11, b'ABCD-1234'), tlv(12, b'RB750Gr3'),
                tlv(14, b'\x01'), tlv(15, bytes.fromhex('fe80000000000000020000fffeaabbcc')),
                tlv(16, b'ether1'), tlv(17, bytes([192, 0, 2, 1])))
    add(frame(full), 'Full neighbor announcement: every known TLV')
    add(frame(mndp(2, MAC)), 'MAC-Address only')
    add(frame(mndp(3, MAC, tlv(5, b'router-2'), tlv(16, b'bridge'), tlv(17, bytes([10, 0, 0, 2])))), 'identity, interface name, IPv4')
    add(frame(mndp(4, MAC, tlv(5, b''), tlv(7, b''))), 'zero length TLVs (identity, version)')
    add(frame(mndp(5, MAC, tlv(99, b'\x01\x02\x03'), tlv(100, b''))), 'unknown TLV types (with data and empty)')
    add(frame(mndp(6, MAC, tlv(10, struct.pack('<I', 0)))), 'uptime 0')
    add(frame(mndp(7, MAC, tlv(14, b'\x02'), tlv(14, b'\x01'))), 'Unpack values: unknown (2) and None (1)')
    add(frame(mndp(0xffff, MAC, tlv(5, b'x' * 200)), 30000, 30000), 'Port 30000: found only with the heuristic enabled')
    add(frame(mndp(8, MAC, unk=b'\xab\xcd'), 30001, 30001), 'Port 30001: heuristic, header bytes 0xabcd')
    add(frame(b'\x00\x00\x00\x01\x00\x02\x00\x06\x01\x02\x03\x04\x05\x06', 5678, 5678), 'MAC TLV with type 2 instead of 1 (not MNDP, shown as data)')
    add(frame(mndp(9, tlv(1, b'\x00' * 5) + b'\x00'), 5678, 5678), 'MAC TLV with length 5 (rejected by the static dissector)')
    add(frame(mndp(10, MAC) + b'\x01\x02\x03', 5678, 5678), 'trailing 3 octets after the TLVs (rejected: neither TLV nor empty)')
    add(frame(b'\x00\x00\x00', 5678, 5678), 'frame shorter than 8 octets (rejected)')
    add(frame(b'\x00\x00\x00\x01\x00\x01\x00\x06\x01\x02\x03', 5678, 5678), 'MAC TLV with length 6 but 3 octets of value (rejected)')
    pcap(os.path.join(out, 'mndp-coverage.pcap'), pk)
    if verbose:
        for n, l in marks:
            print(n, l)
        print(len(pk), 'frames')

    pk, marks = [], []
    add(frame(mndp(1, MAC, tlv(10, b'\x01\x02'))), 'Uptime with length 2')
    add(frame(mndp(2, MAC, tlv(10, b'\x01\x02\x03\x04\x05\x06\x07\x08'))), 'Uptime with length 8')
    add(frame(mndp(3, MAC, tlv(15, b'\x00' * 4))), 'IPv6 address with length 4')
    add(frame(mndp(4, MAC, tlv(17, b'\x00' * 6))), 'IPv4 address with length 6')
    add(frame(mndp(5, MAC, tlv(14, b'\x01\x01'))), 'Unpack with length 2')
    add(frame(mndp(6, MAC, tlv(1, b'\x01\x02\x03\x04\x05\x06\x07'))), 'second MAC TLV with length 7')
    add(frame(mndp(7, MAC, struct.pack('>HH', 5, 100) + b'short')), 'TLV length beyond the end of the frame')
    add(frame(mndp(9, MAC, struct.pack('>HH', 5, 0xffff))), 'TLV length 0xffff')
    pcap(os.path.join(out, 'mndp-coverage-malformed.pcap'), pk)
    if verbose:
        for n, l in marks:
            print('M', n, l)
        print(len(pk), 'malformed frames')

main()
