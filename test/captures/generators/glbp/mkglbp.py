#!/usr/bin/env python3
# Generates test/captures/glbp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-glbp.c.  Usage: mkglbp.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
import util as u

def hdr(group=1, ver=1, u1=0, owner=b'\x00\x07\xb4\x00\x01\x02', u2=b'\0\0'):
    return bytes([ver, u1]) + struct.pack('>H', group) + u2 + owner

def tlv(t, body, length=None):
    return bytes([t, len(body) + 2 if length is None else length]) + body

def hello(vg=0x20, prio=100, hello_ms=3000, hold_ms=10000, redirect=600,
          timeout=14400, atype=1, alen=None, addr=None, u10=0, u11=1, u12=b'\0\0',
          u13=b'\0\0'):
    if addr is None:
        addr = {1: socket.inet_aton('192.0.2.100'),
                2: socket.inet_pton(socket.AF_INET6, '2001:db8::100')}.get(atype, b'\xde\xad\xbe\xef\x01\x02')
    if alen is None:
        alen = len(addr)
    return (bytes([u10, vg, u11, prio]) + u12 + struct.pack('>IIHH', hello_ms, hold_ms, redirect, timeout)
            + u13 + bytes([atype, alen]) + addr)

def reqresp(fwd=1, vf=0x20, u21=0, prio=100, weight=100, u22=b'\0' * 7,
            mac=b'\x00\x07\xb4\x00\x01\x01'):
    return bytes([fwd, vf, u21, prio, weight]) + u22 + mac

def auth(atype, body, alen=None):
    return bytes([atype, len(body) if alen is None else alen]) + body

def main_frames():
    o = []
    M = dict(dst='224.0.0.102', ttl=64)
    ip = lambda p: o.append(u.udp(3222, 3222, p, **M))
    # Hello: every VG state, IPv4 and IPv6 virtual address
    for i, vg in enumerate((4, 8, 0x10, 0x20, 0x01)):
        ip(hdr(group=i + 1) + tlv(1, hello(vg=vg, prio=50 + i)))
    o.append(u.udp6(3222, 3222, hdr(group=7, u1=0) + tlv(1, hello(atype=2)),
                    src='fe80::1', dst='ff02::66'))
    # unknown address type, with and without data
    ip(hdr(group=8) + tlv(1, hello(atype=3)))
    ip(hdr(group=8) + tlv(1, hello(atype=0, addr=b'')))
    # the "unknown1" header values accepted by the heuristic
    for u1 in range(0, 5):
        ip(hdr(group=9, u1=u1) + tlv(1, hello()))
    # trailing bytes after the Hello (length covers more than was used)
    ip(hdr(group=10) + tlv(1, hello() + b'\x01\x02\x03\x04'))
    # header only, nothing else
    ip(hdr(group=11))
    # Request/Response
    ip(hdr(group=12) + tlv(2, reqresp(fwd=0, vf=4)))
    ip(hdr(group=12) + tlv(2, reqresp(fwd=2, vf=0x20, weight=255)))
    ip(hdr(group=12) + tlv(2, reqresp(fwd=3, vf=9)))
    # Auth: none, plain text, MD5 string, MD5 chain, unknown type
    ip(hdr(group=13) + tlv(3, auth(0, b'')) + tlv(1, hello()))
    ip(hdr(group=13) + tlv(3, auth(1, b'secret12')) + tlv(1, hello()))
    ip(hdr(group=13) + tlv(3, auth(2, bytes(range(16)))) + tlv(1, hello()))
    ip(hdr(group=13) + tlv(3, auth(3, struct.pack('>I', 5) + bytes(range(16, 32)))) + tlv(1, hello()))
    ip(hdr(group=13) + tlv(3, auth(3, struct.pack('>I', 6))))     # chain hash empty
    ip(hdr(group=13) + tlv(3, auth(9, b'\x01\x02\x03')))
    # unknown TLV types
    ip(hdr(group=14) + tlv(7, b'\x11\x22\x33') + tlv(0xff, b'x'))
    # several TLVs in one packet: hello + 2 reqresp (as an AVG sends)
    ip(hdr(group=15) + tlv(1, hello()) + tlv(2, reqresp(fwd=1)) + tlv(2, reqresp(fwd=2, mac=b'\x00\x07\xb4\x00\x01\x02')))
    # the reproducer of "GLBP: Check the MD5 chain authentication length"
    # is the auth type 3 with authlength 2 (malformed capture, expert info)
    # from a unicast source, other group numbers
    o.append(u.udp(3222, 3222, hdr(group=1000) + tlv(1, hello(prio=255)),
                   src='192.0.2.7', dst='192.0.2.8'))
    o.append(u.udp(3222, 3222, hdr(group=65535) + tlv(2, reqresp()), src='192.0.2.8', dst='192.0.2.7'))
    return o

def mal_frames():
    o = []
    ip = lambda p, **k: o.append(u.udp(3222, 3222, p, dst='224.0.0.102', **k))
    # the reproducer: MD5 chain with authlength 2
    ip(hdr() + bytes([3, 6, 3, 2]) + b'\xaa\xbb')
    ip(hdr() + tlv(3, auth(3, b'')))                           # authlength 0
    ip(hdr() + tlv(3, auth(3, b'\1\2\3'), ))                   # authlength 3
    # wrong address lengths
    ip(hdr() + tlv(1, hello(atype=1, alen=5, addr=b'\1\2\3\4\5')))
    ip(hdr() + tlv(1, hello(atype=1, alen=3, addr=b'\1\2\3')))
    ip(hdr() + tlv(1, hello(atype=2, alen=4, addr=b'\1\2\3\4')))
    # TLV length 0 and 1
    ip(hdr() + bytes([1, 0]) + b'\0' * 8)
    ip(hdr() + bytes([2, 1]))
    # an unknown TLV of length 2 uses no bytes
    ip(hdr() + bytes([5, 2]))
    # TLV length longer than the packet (exception)
    ip(hdr() + bytes([1, 60]) + hello()[:10])
    ip(hdr() + tlv(1, hello())[:20])
    # truncated header
    ip(hdr()[:6])
    # truncated plain text password
    ip(hdr() + bytes([3, 12, 1, 20]) + b'abc')
    # a header-only fragment: first octet only (shorter than 2 -> not GLBP)
    ip(b'\x01')
    # not GLBP: wrong version, unknown1 > 4, ports differ
    ip(bytes([2, 0]) + b'\0' * 10)
    ip(bytes([1, 5]) + b'\0' * 10)
    o.append(u.udp(3222, 40000, hdr() + tlv(1, hello()), dst='224.0.0.102'))
    return o

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_frames()
    u.write_pcap(os.path.join(out, 'glbp-coverage.pcap'), m)
    u.gz(os.path.join(out, 'glbp-coverage.pcap'))
    mm = mal_frames()
    u.write_pcap(os.path.join(out, 'glbp-coverage-malformed.pcap'), mm)
    if '-v' in sys.argv:
        print(len(m), len(mm))
