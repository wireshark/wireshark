#!/usr/bin/env python3
# Generates test/captures/opa_snc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Omni-Path SnC (Snoop and Capture metadata header) coverage capture.
# ERF records of type 28 (OMNI-PATH SnC) in a pcap file with link type ERF (197).
# All values are synthetic (LIDs, QPs, MAD contents, PBC/RHF words from a seeded PRNG).
# Usage: mkopasnc.py <outdir>
import struct
import random
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

def l2_9b(lnh, plen, dlid=0x0011, slid=0x0022, sl=1):
    return struct.pack('>BBHHH', 0, (sl << 4) | lnh, dlid, (plen // 4) & 0xFFF, slid)

def bth(opcode, dqp, psn=1):
    return struct.pack('>BBHB', opcode, 0, 0xFFFF, 0) + struct.pack('>I', dqp)[1:] + struct.pack('>I', psn)

def deth(sqp, qkey=0x80010000):
    return struct.pack('>IB', qkey, 0) + struct.pack('>I', sqp)[1:]

def ud_packet(payload, dqp, sqp, lnh=2):
    body = bth(0x64, dqp) + deth(sqp) + payload + b'\0\0\0\0'
    return l2_9b(lnh, 8 + len(body)) + body

def mad(cls, method, attr, tid, data=b''):
    return struct.pack('>BBBBHHQHHI', 0x80, cls, 0x80, method, 0, 0, tid, attr, 0, 0) + data

def snc(port, direction, word, pkt):
    return struct.pack('<BBHI', port, direction, 0, 0) + struct.pack('<Q', word) + pkt

def erf(typ, pkt):
    rlen = 16 + len(pkt)
    return struct.pack('<Q', 0) + struct.pack('>BBHHH', typ, 0, rlen, 0, len(pkt)) + pkt

def blk(t, b):
    b += b'\0' * ((4 - len(b) % 4) % 4)
    return struct.pack('<II', t, len(b) + 12) + b + struct.pack('<I', len(b) + 12)

def write_pcapng(path, recs):
    with open(path, 'wb') as f:
        f.write(blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(blk(1, struct.pack('<HHI', 197, 0, 0)))
        for k, d in enumerate(recs):
            ts = 1600000000 * 10**6 + k * 1000
            f.write(blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xFFFFFFFF, len(d), len(d)) + d))

def build(outdir):
    r = random.Random(28)
    recs = []
    # the encapsulated 9B packets: SM ClassPortInfo Get, SA NodeRecord request, PM PortStatus Get,
    # a payload packet to another QP (Ethernet over OPA, IPv4), a raw (LNH 0) packet
    sa = mad(0x03, 0x01, 0x11, 2) + struct.pack('>BBBBII', 1, 0, 0, 0, 0, 0) + struct.pack('>QHHQ', 0, 0, 0, 0)
    pm = mad(0x04, 0x01, 0x40, 3) + struct.pack('>BxxxI', 1, 1)
    pkts = [
        ud_packet(mad(0x01, 0x01, 0x01, 1) + struct.pack('>Q', 0), 0, 2),
        ud_packet(sa, 1, 5),
        ud_packet(pm, 1, 6),
        ud_packet(b'\x08\x06\x00\x00' + bytes(28), 7, 8),
        l2_9b(0, 16) + bytes(8),
    ]
    # Direction 0 (outbound, PBC): bypass bit (bit 28 of the first 32-bit word) clear or set
    for i in range(16):
        lo = r.getrandbits(32) & ~(1 << 28)
        if i in (3, 4):
            lo |= 1 << 28
        hi = r.getrandbits(32)
        recs.append(erf(28, snc(1 + i % 2, 0, (hi << 32) | lo, pkts[i % len(pkts)])))
    # Direction 1 (inbound, RHF): RcvType (bits 12-14) 0-7, error type (bits 60-62 of the high word)
    for rt in range(8):
        for err in (0, 1, 5):
            lo = (r.getrandbits(32) & ~(7 << 12)) | (rt << 12)
            hi = (r.getrandbits(32) & ~(7 << 29)) | (err << 29)
            if rt == 0:
                hi |= 0x80000000 | 0x40000000
            recs.append(erf(28, snc(2, 1, (hi << 32) | lo, pkts[(rt + err) % len(pkts)])))
    # Direction 2 (internal debugging tools) and an unknown direction
    for d in (2, 3, 7):
        recs.append(erf(28, snc(1, d, r.getrandbits(64), pkts[d % len(pkts)])))
    write_pcapng(os.path.join(outdir, 'opa-snc-coverage.pcapng'), recs)
    print(len(recs), 'frames')

def build_malformed(outdir):
    # records cut short: inside the SnC header, right after it (no 9B packet), inside the 9B header
    recs = [erf(28, b'\x01'), erf(28, struct.pack('<BBHI', 1, 0, 0, 0) + b'\0' * 3),
            erf(28, snc(1, 0, 0, b'')), erf(28, snc(1, 1, 0x4000, b'')),
            erf(28, snc(1, 0, 0, b'\0\x12\0\x11')), erf(28, snc(1, 2, 0, b'\0\x12\0\x11\0\x04\0\x22\x64\0')),
            erf(28, snc(1, 0, 0, l2_9b(2, 0x40) + b'\x64\0\xff')), erf(28, snc(1, 1, 0, bytes(10)))]
    write_pcapng(os.path.join(outdir, 'opa-snc-coverage-malformed.pcapng'), recs)
    print(len(recs), 'frames (malformed)')

if __name__ == '__main__':
    build(OUT)
    build_malformed(OUT)
