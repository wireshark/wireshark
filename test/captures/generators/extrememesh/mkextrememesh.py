#!/usr/bin/env python3
# Generates test/captures/extrememesh_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Extreme Mesh dissector
(packet-extrememesh.c: Mesh header, MCH, Path Selection frames, L2
update, probe, encapsulated Ethernet).

Extreme Mesh runs over Ethernet with ethertype 0x88A9, registered by
default. Every packet is built with struct; nothing comes from a real
network.

Usage: mkextrememesh.py <output directory>
  extrememesh-coverage.pcap            every next-protocol value, every
                                       path selection frame type with its
                                       options, nested MCH headers
  extrememesh-coverage-malformed.pcap  truncated frames, bad counts and
                                       option lengths
"""
import os
import struct
import sys

A = bytes.fromhex('02000000000a')
B = bytes.fromhex('02000000000b')
C = bytes.fromhex('02000000000c')
D = bytes.fromhex('02000000000d')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, dst=B, src=A, etype=0x88A9):
    return dst + src + struct.pack('>H', etype) + payload


def mesh(nextp, body, ver=1):
    return eth(struct.pack('>BB', ver, nextp) + body)


def mch(nextp, body, ver=1, lq=200, htl=5, prio=3, usr=0x0e, seq=0x1234,
        dst=C, src=D):
    return struct.pack('>BBBBBBH', ver, nextp, lq, htl, prio, usr, seq) + dst + src + body


P_MESH, P_MCH, P_ETH, P_PS, P_HELLO, P_LOC, P_SEC, P_MSH, P_TEST, P_FRAG, \
    P_CFPU, P_EAPOM, P_NULL, P_ETH_NOADDR, P_L2UP, P_PROBE = range(16)


def be(fmt, *a):
    return struct.pack('>' + fmt, *a)


def ps_hdr6(ftype, mpr=C, orig=D, optlen=0):
    return be('BB', 1, ftype) + mpr + orig + be('H', optlen)


# ---------------------------------------------------------------- path selection
def areq(opts=b'', n=None):
    return ps_hdr6(1, optlen=len(opts)) + opts


def arep(opts=b''):
    return ps_hdr6(2, optlen=len(opts)) + opts


def breq(opts=b''):
    return ps_hdr6(3, optlen=len(opts)) + opts


def brep(opts=b''):
    return ps_hdr6(4, optlen=len(opts)) + opts


def bann(opts=b''):
    return ps_hdr6(5, optlen=len(opts)) + opts


def bred(opts=b''):
    return ps_hdr6(6, optlen=len(opts)) + opts


def sreq(opts=b''):
    return be('BBH', 1, 7, 0x0102) + C + D + be('H', len(opts)) + opts


def srep(opts=b''):
    return be('BBH', 1, 8, 0x0304) + A + C + D + be('H', len(opts)) + opts


def preq(opts=b'', flags=0x00, services=0x00):
    return be('BBBBIHBBI', 1, 9, flags, 3, 600, 0x0123, services, 0, 99) + \
        C + D + be('I', 11) + A + be('IH', 22, len(opts)) + opts


def prep(opts=b'', flags=0x00, services=0x00):
    return be('BBBBHBB', 1, 10, flags, 2, 0x0456, services, 0) + \
        C + D + be('I', 33) + A + be('III', 44, 3600, 0)[0:0] + \
        be('I', 44) + be('I', 3600) + be('H', len(opts)) + opts


def perr(n=2, count=None, flags=0x03):
    cnt = n if count is None else count
    return be('BBBB', 1, 11, flags, cnt) + b''.join(
        bytes([2, 0, 0, 0, 0, i]) + be('I', 100 + i) for i in range(n))


def prst():
    return be('BBBBI', 1, 12, 8, 0, 0xcafe) + C + D


def prem(opts=b''):
    return be('BB', 1, 13) + C + D + be('H', len(opts)) + opts


def trace(hops=3, count=None, flags=0x03):
    cnt = hops if count is None else count
    return be('BBB', 1, 14, flags) + C + D + bytes([cnt]) + b''.join(
        bytes([2, 0, 0, 0, 1, i]) for i in range(hops))


def prer(opts=b''):
    return be('BBBB', 1, 15, 1, 0) + C + D + A + be('H', len(opts)) + opts


def o8(typ, val):          # option with 1 octet type and length
    return bytes([typ, len(val)]) + val


def o16(typ, val):         # option with 2 octet type and length
    return be('HH', typ, len(val)) + val


# --------------------------------------------------------------- the capture
main = []

# 1-2: Mesh header with terminating protocols that are ignored
main.append(mesh(P_NULL, b'\0' * 8))
main.append(mesh(P_TEST, b'\0' * 8))
main.append(mesh(P_FRAG, b'\0' * 8))
main.append(mesh(P_LOC, b'\0' * 8))
main.append(mesh(P_MESH, b'\0' * 8))      # mesh in mesh: ends
main.append(mesh(0x30, b'\0' * 8))         # unknown next protocol
# encapsulated Ethernet (with FCS-less frame, ethertype 0x88b5, payload)
main.append(mesh(P_ETH, eth(b'\x01\x02\x03\x04' * 4, dst=D, src=C, etype=0x88b5)))
# MCH -> encapsulated Ethernet
main.append(mesh(P_MCH, mch(P_ETH, eth(b'payload' * 3, dst=D, src=C, etype=0x88b5))))
# MCH with every priority flag bit, other values
main.append(mesh(P_MCH, mch(P_ETH, eth(b'abc', etype=0x88b5), usr=0xff, lq=0, htl=0, prio=7,
                            ver=2)))
main.append(mesh(P_MCH, mch(P_ETH, eth(b'abc', etype=0x88b5), usr=0x00, lq=255, htl=255, prio=0)))
# MCH -> MCH -> Ethernet
main.append(mesh(P_MCH, mch(P_MCH, mch(P_ETH, eth(b'inner', etype=0x88b5)))))
# MCH -> MCH ... 40 levels
n = mch(P_ETH, eth(b'deep', etype=0x88b5))
for _ in range(39):
    n = mch(P_MCH, n)
main.append(mesh(P_MCH, n))
# MCH with terminating ignored types
for p in (P_NULL, P_TEST, P_FRAG, P_LOC, P_MESH, 0x44):
    main.append(mesh(P_MCH, mch(p, b'\0' * 6)))
# no-address protocols: hello, security, secured payload, cfpu, eapom, eth no addr
noaddr = []
for p in (P_HELLO, P_SEC, P_MSH, P_CFPU, P_EAPOM, P_ETH_NOADDR):
    noaddr.append(mesh(p, be('H', 0x88b5) + b'noaddr' * 4))
    noaddr.append(mesh(P_MCH, mch(p, be('H', 0x88b5) + b'noaddr' * 3)))
# L2 update and probe, directly and via MCH
main.append(mesh(P_L2UP, A + b'ballast' * 3))
main.append(mesh(P_MCH, mch(P_L2UP, B + b'xyz')))
main.append(mesh(P_L2UP, A))
main.append(mesh(P_PROBE, be('BBBBHIH', 1, 2, 0x01, 3, 77, 123456, 10) + b'0123456789'))
main.append(mesh(P_MCH, mch(P_PROBE, be('BBBBHIH', 2, 3, 0x00, 7, 78, 1, 0))))
main.append(mesh(P_PROBE, be('BBBBHIH', 2, 3, 0xff, 255, 65535, 0xffffffff, 3) + b'abc'))

# Path selection, directly and via MCH
def ps(body):
    main.append(mesh(P_PS, body))
    main.append(mesh(P_MCH, mch(P_PS, body)))


ps(areq())
ps(areq(o8(2, B) + o8(3, b'\x05')))
ps(areq(o8(0, b'')[0:1] + o8(3, b'\x01')))
ps(areq(o8(9, b'xx')))                      # unknown option: stops
ps(arep())
ps(arep(o8(4, b'\x01') + o8(6, b'\x1e')))
ps(arep(b'\x00' + o8(4, b'\x02')))
ps(arep(o8(7, b'x')))
ps(breq())
ps(breq(o8(1, C + D) + o8(2, A) + o8(5, b'') + o8(7, b'\x09') + o8(8, b'\x01\x02\x03') +
        o8(10, be('H', 100)) + o8(11, be('HH', 5, 6)) + o8(12, be('I', 77))))
ps(breq(b'\x00\x00' + o8(1, C)))
ps(breq(o8(1, b'\0' * 7)))                    # remainder breaks the loop
ps(breq(o8(11, b'\0' * 3)))
ps(breq(o8(42, b'zz')))
ps(brep())
ps(brep(o8(12, be('I', 5))[0:1] + b'\x04' + be('I', 5)))
ps(brep(b'\x00' + b'\x0c\x00' + be('I', 6)))
ps(brep(o8(3, b'q')))
ps(bann())
ps(bann(o8(1, C + D + A) + o8(2, B) + o8(10, be('H', 5)) + o8(12, be('I', 9))))
ps(bann(b'\x00' + o8(1, C)))
ps(bann(o8(77, b'a')))
ps(bred())
ps(bred(o8(12, be('I', 5))))
ps(bred(b'\x00' + o8(12, be('I', 5))))
ps(bred(o8(5, b'')))
ps(sreq())
ps(sreq(o16(10, be('H', 7))))
ps(sreq(be('H', 0) + o16(10, be('H', 8))))
ps(sreq(o16(3, b'')))
ps(srep())
ps(srep(o16(10, be('H', 7))))
ps(srep(be('H', 0) + o16(10, be('H', 9))))
ps(srep(o16(4, b'')))
ps(preq())
ps(preq(o16(1, C + D) + o16(10, be('H', 100)) + o16(14, be('I', 5)), flags=0xff, services=0xff))
ps(preq(be('H', 0) + o16(1, B), flags=0x01, services=0x01))
ps(preq(o16(1, b'\0' * 7) + b'\0', flags=0x10, services=0x10))
ps(preq(o16(77, b'a'), flags=0x40, services=0x40))
ps(prep())
ps(prep(o16(1, C + D) + o16(10, be('H', 100)) + o16(14, be('I', 5)), flags=0xff, services=0xff))
ps(prep(be('H', 0) + o16(1, B), flags=0x01, services=0x80))
ps(prep(o16(1, b'\0' * 7) + b'\0', flags=0x08))
ps(prep(o16(77, b'a')))
ps(perr(0, flags=0))
ps(perr(1, flags=1))
ps(perr(4, flags=2))
ps(prst())
ps(prem())
ps(prem(o8(1, C + D) + o8(11, be('HH', 5, 6))))
ps(prem(b'\x00' + o8(1, C) + o8(11, be('H', 5))))
ps(prem(o8(1, b'\0' * 7) + o8(11, b'\0' * 3)))
ps(prem(o8(99, b'a')))
ps(trace(0, flags=0))
ps(trace(1, flags=1))
ps(trace(4, flags=2))
ps(prer())
ps(prer(o16(11, be('H', 100))))
ps(prer(be('H', 0) + o16(11, be('H', 5))))
ps(prer(o16(5, b'\0\0')))
# undefined path selection frame types
ps(be('BB', 1, 0) + b'\0' * 20)
ps(be('BB', 1, 16) + b'\0' * 20)
# PS with Ethernet addresses beyond the frame: padding to 60 octets is automatic

# wrong header sizes of the Ethernet frame: Ethernet (802.3) length with
# the mesh type shown as a trailer
main.append(eth(be('BB', 1, P_PS) + prst() + b'\xaa' * 4))

malformed = list(noaddr)
M = lambda p, b: malformed.append(mesh(p, b))
M(P_PS, b'')                          # next protocol but nothing follows
malformed.append(eth(b'\x01'))
malformed.append(eth(b''))
M(P_MCH, b'\x01\x02\x03')              # MCH cut
M(P_MCH, mch(P_ETH, b'')[:19])
M(P_PS, ps_hdr6(1)[:5])
for fn in (areq, arep, breq, brep, bann, bred, sreq, srep, preq, prep, prem, prer,
           prst):
    M(P_PS, fn()[:10])
M(P_PS, perr(1)[:6])
M(P_PS, perr(3, count=200))           # destination count beyond the data
M(P_PS, perr(1)[:3])
M(P_PS, trace(2, count=250))          # hop count beyond the data
M(P_PS, trace(1)[:10])
M(P_PS, be('B', 1))                   # no frame type
# option lengths that run past the packet
M(P_PS, breq(b'\x01\x05' + C))
M(P_PS, breq(b'\x08\xff\x01'))
M(P_PS, breq(b'\x01'))
M(P_PS, breq(o8(1, b'\0' * 5)))       # length 5: wraps, runs past the end
M(P_PS, bann(o8(1, b'\0' * 5)))
M(P_PS, preq(o16(1, b'\0' * 5)))
M(P_PS, prep(o16(1, b'\0' * 5)))
M(P_PS, prem(o8(1, b'\0' * 5)))
M(P_PS, areq(b'\x03\x01'))
M(P_PS, arep(b'\x04\x01'))
M(P_PS, preq(be('H', 14) + be('H', 4) + b'\0\0'))
M(P_PS, prep(be('H', 10) + be('H', 2) + b'\0'))
M(P_PS, prer(be('H', 11) + be('H', 2) + b'\0'))
M(P_PS, srep(be('H', 10) + be('H', 2)))
M(P_L2UP, b'\x01\x02')
M(P_PROBE, be('BBBBHI', 1, 2, 0, 0, 1, 1))
M(P_PROBE, be('BBBBHIH', 1, 2, 0, 0, 1, 1, 500) + b'short')
M(P_ETH, b'\x01\x02\x03')
M(P_HELLO, b'')
M(P_HELLO, b'\x08')
malformed.append(mesh(P_HELLO, b'\x88\xb5'))

# nesting deeper than the limit (the fix): 600 MCH headers
n = eth(b'deep', etype=0x88b5)
for _ in range(600):
    n = mch(P_MCH, n)
nested = mesh(P_MCH, n)

if __name__ == '__main__':
    out = sys.argv[1]
    # the deep nesting reproducer is in the main capture (a warning only)
    pcap(os.path.join(out, 'extrememesh-coverage.pcap'), main + [nested])
    pcap(os.path.join(out, 'extrememesh-coverage-malformed.pcap'), malformed)
