#!/usr/bin/env python3
# Generates test/captures/gfp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GFP coverage captures. Usage: mkgfp.py <outdir>
# GFP is reached by link-layer type: pcap DLT 171 (GFP-F) and 170 (GFP-T).
# The HEC and FCS values are integrity checks (CRC-16 and CRC-32), not
# keys or authentication.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
import zlib
from common import pcapng, pcap, ip4, udp, eth

def crc16(data):          # CRC-16 CCITT, poly 0x1021, init 0 (G.7041 HEC)
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc

def crc32_mpeg2(data):    # CRC-32/MPEG-2: poly 0x04c11db7, init all ones, no reflection
    crc = 0xffffffff
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04c11db7) & 0xffffffff if crc & 0x80000000 else (crc << 1) & 0xffffffff
    return crc

def hec(b, bad=False):
    return struct.pack('>H', crc16(b) ^ (0x5a5a if bad else 0))

def gfp(pti, upi, payload=b'', pfi=0, exi=0, cid=0, fcs=None, bad_chec=False, bad_thec=False,
        bad_ehec=False, bad_fcs=False, pli=None, ext=True):
    typ = struct.pack('>BB', (pti << 5) | (pfi << 4) | exi, upi)
    area = typ + hec(typ, bad_thec)
    if exi == 1:
        eh = struct.pack('>BB', cid, 0)
        area += eh + hec(eh, bad_ehec)
    elif exi in (2, 3, 5):
        eh = b'\x00\x00'
        area += eh + hec(eh, bad_ehec) if ext else b''
    area += payload
    if pfi and fcs is not False:
        c = crc32_mpeg2(area[len(typ) + 2 + (4 if exi == 1 else 0):])
        area += struct.pack('>I', (~c if not bad_fcs else c) & 0xffffffff)
    length = len(area) if pli is None else pli
    core = struct.pack('>H', length)
    return core + hec(core, bad_chec) + area

def eth_frame(payload=b'ethernet payload'):
    body = eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4('10.0.0.1', '10.0.0.2', 17, udp(1000, 2000, payload)))
    body += b'\0' * max(0, 60 - len(body))
    return body + struct.pack('<I', zlib.crc32(body) & 0xffffffff)

def ipv4(): return ip4('10.0.0.1', '10.0.0.2', 17, udp(1000, 2000, b'ipv4 payload'))
def ipv6():
    pl = b'ipv6 payload'
    return struct.pack('>IHBB', 0x60000000, len(pl), 59, 64) + socket.inet_pton(socket.AF_INET6, '2001:db8::1') + socket.inet_pton(socket.AF_INET6, '2001:db8::2') + pl
def mpls(): return struct.pack('>I', (100 << 12) | (1 << 8) | 64) + ipv4()
def ppp(): return b'\xff\x03\x00\x21' + ipv4()
def ts(): return b'\x47\x1f\xff\x10' + b'\xff' * 184

def build():
    f = []   # (interface, bytes)
    F = lambda b: f.append((0, b))
    # idle frame, with cHEC; core header only
    F(gfp(0, 0, b'')[:0] + struct.pack('>H', 0) + hec(struct.pack('>H', 0)))
    # client data frames, UPI table
    F(gfp(0, 1, eth_frame()))                      # Ethernet (FCS inside the payload)
    F(gfp(0, 1, eth_frame(), pfi=1))               # Ethernet with GFP payload FCS (good)
    F(gfp(0, 1, eth_frame(), pfi=1, bad_fcs=True)) # bad FCS
    F(gfp(0, 2, ppp()))                            # PPP
    F(gfp(0, 9, ts()))                             # MPEG-2 TS
    F(gfp(0, 13, mpls()))                          # MPLS
    F(gfp(0, 14, mpls()))                          # MPLS (multicast), UPI 14 (fixed registration)
    F(gfp(0, 12, mpls()))                          # UPI 12 is asynchronous transparent FC: unsupported
    F(gfp(0, 16, ipv4()))                          # IPv4
    F(gfp(0, 17, ipv6()))                          # IPv6
    for upi in (0, 3, 4, 5, 6, 7, 8, 10, 11, 15, 18, 19, 20, 21, 22, 23, 24, 240, 253, 254, 255):
        F(gfp(0, upi, b'client data ' + bytes([upi])))      # unsupported UPIs: data
    # extension headers
    F(gfp(0, 16, ipv4(), exi=1, cid=7))             # linear frame, CID 7
    F(gfp(0, 16, ipv4(), exi=1, cid=255, pfi=1))    # linear, with FCS
    F(gfp(0, 16, ipv4(), exi=1, cid=1, bad_ehec=True))
    F(gfp(0, 16, ipv4(), exi=2, ext=False))                    # ring frame: undefined
    F(gfp(0, 16, ipv4(), exi=3, ext=False))                    # reserved extension
    # HEC errors
    F(gfp(0, 16, ipv4(), bad_chec=True))
    F(gfp(0, 16, ipv4(), bad_thec=True))
    F(gfp(0, 16, ipv4(), bad_chec=True, bad_thec=True, pfi=1))
    # management
    F(gfp(4, 1, b'\0\0\0\0'))                       # client management: signal fail
    for upi in (2, 3, 4, 5, 0, 6, 224, 255):
        F(gfp(4, upi, b''))
    F(gfp(5, 1, eth_frame()))                       # management communications, same UPI table
    F(gfp(5, 16, ipv4()))
    F(gfp(5, 77, b'mgmt unknown'))
    for pti in (1, 2, 3, 6, 7):
        F(gfp(pti, 1, b'reserved pti %d' % pti))     # reserved PTI
    # control frames (PLI 1..3), PLI 4: shortest client frame (payload header only)
    for p in (1, 2, 3):
        F(struct.pack('>H', p) + hec(struct.pack('>H', p)))
    F(gfp(0, 255, b''))                               # PLI 4, UPI 255, no payload
    F(gfp(0, 16, ipv4(), pfi=1, fcs=None))
    # GFP-T interface
    f.append((1, gfp(0, 3, b'transparent fibre channel')))
    f.append((1, gfp(0, 6, b'transparent gigabit ethernet', pfi=1)))
    f.append((1, struct.pack('>H', 0) + hec(struct.pack('>H', 0))))
    return f

def build_mal():
    f = []
    F = lambda b: f.append(b)
    z = struct.pack('>H', 0) + hec(struct.pack('>H', 0))
    F(b'\x00\x00\x00')                                                 # shorter than the core header
    F(z + b'idle with payload')                                       # idle frame with payload (error)
    # reproducer of the FCS fix: PFI set, payload shorter than 4 octets (error: PFI too short)
    for n in (0, 1, 2, 3):
        F(gfp(0, 255, b'\xaa' * n, pfi=1, fcs=False))
    F(gfp(0, 16, b'', pfi=1, fcs=False, exi=1))                        # linear and PFI, nothing left
    # linear extension with PLI too small for it (EXI short)
    typ = struct.pack('>BB', 0x01, 16)
    area = typ + hec(typ) + b'\x01'
    core = struct.pack('>H', len(area))
    F(core + hec(core) + area)
    # PLI claims more than is present (bogus PLI)
    F(gfp(0, 16, ipv4(), pli=500))
    F(gfp(0, 255, b'abc', pli=9)[:-3])
    F(gfp(0, 1, eth_frame(), pli=0xffff))
    # PLI says 5: payload header is cut off
    F(struct.pack('>H', 5) + hec(struct.pack('>H', 5)) + b'\x00\x10\x00\x00\x00')
    F(struct.pack('>H', 4) + hec(struct.pack('>H', 4)) + b'\x00')       # fewer than 4 octets of payload header
    return f

if __name__ == '__main__':
    out = sys.argv[1]
    pcapng(os.path.join(out, 'gfp-coverage.pcapng'), [171, 170], build())
    pcap(os.path.join(out, 'gfp-coverage-malformed.pcap'), build_mal(), linktype=171)
