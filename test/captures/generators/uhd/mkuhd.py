#!/usr/bin/env python3
# Generates test/captures/uhd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the UHD coverage captures. Usage: mkuhd.py <outdir>
# UHD has no default port (UDP 49152 is only a Decode As entry), so the
# frames are Exported PDU (LINKTYPE_WIRESHARK_UPPER_PDU) that name "uhd".
import os
import struct
import sys

def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v

def epdu(payload, proto='uhd'):
    return tlv(12, proto.encode()) + tlv(0, b'') + payload

def write(fn, pkts, t0=1700000000):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', t0 + i, 0, len(p), len(p)))
            f.write(p)

def hdr(ident, seq, rest=b''):
    # proto_ver, id, seq, then the id specific union, padded to 34 bytes
    b = struct.pack('>III', 1, ident, seq) + rest
    return b + bytes(34 - len(b))

def ids():
    seq = [0]
    out = []
    def add(i, rest=b''):
        seq[0] += 1
        out.append(epdu(hdr(i, seq[0], rest)))
    ipa = bytes([192, 168, 10, 2])
    for i in (0x75, 0x55, 0x61, 0x41):                 # UMTRX/WAZZUP: ip_addr
        add(i, ipa)
    for i in (0x73, 0x53):                             # SPI
        add(i, struct.pack('>IIBBBB', 0x10, 0xdeadbeef, 1, 0, 24, 1))
    for i in (0x69, 0x49, 0x68, 0x48):                 # I2C: 0, 1, 5, 20 bytes
        for n in (0, 1, 5, 20):
            add(i, struct.pack('BB', 0x50 + n, n) + bytes(range(0x30, 0x30 + n)))
    for i in (0x72, 0x52):                             # register access
        for act in (1, 2, 3, 4, 5, 6, 0, 99):          # 0 and 99 are unnamed
            add(i, struct.pack('>IIB', 0x1000 + act, 0x11223344 * act & 0xffffffff, act))
    for i in (0x6c, 0x4c, 0x20, 0x7e):                 # echo
        add(i, struct.pack('>I', 64))
    # ids with no body decoding, and the reproducers of "UHD: Print the
    # message id as hex instead of %c": a low byte >= 0x80 and 0x12345678
    for i in (0x00000000, 0x00000041 + 0x100, 0x000000ff, 0x00000080,
              0x12345678, 0xffffffff):
        add(i)
    return out

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    write(os.path.join(outdir, 'uhd-coverage.pcap'), ids())
    # Malformed: truncated headers (the item covers 34 bytes) and an I2C
    # byte count past the end of the packet
    bad = []
    full = hdr(0x69, 1, struct.pack('BB', 0x50, 20) + bytes(20))
    for n in (4, 8, 11, 12, 20, 33):
        bad.append(epdu(full[:n]))
    bad.append(epdu(struct.pack('>III', 1, 0x69, 9) + struct.pack('BB', 0x50, 250) + bytes(20)))
    write(os.path.join(outdir, 'uhd-coverage-malformed.pcap'), bad)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
