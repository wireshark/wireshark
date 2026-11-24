#!/usr/bin/env python3
# Generates test/captures/igap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-igap.c (IGAP, IGMP types 0x40-0x42).
Usage: mkigap.py <outdir>"""
import struct
import sys
import os
from pylib import A, csum, eth, H, ip4, ipv4, Pcap

def igap(typ, subtype, account=b'', password=b'', asize=None, msize=None, tsecs=100,
         group='224.1.2.3', version=0x10, cid=7, cksum=True, bad=False):
    """96 octet IGAP message: 16 octet account field and 64 octet message field."""
    if asize is None: asize = len(account)
    if msize is None: msize = len(password)
    b = struct.pack('>BBH4sBBBBBB2s', typ, tsecs, 0, ip4(group), version, subtype, 0, cid, asize, msize, bytes(2))
    b += account.ljust(16, b'\0')[:16] + password.ljust(64, b'\0')[:64]
    assert len(b) == 96
    c = csum(b)
    if bad: c ^= 0x5a5a
    return b[:2] + struct.pack('>H', c) + b[4:]

def f(payload, src=A, dst='224.1.2.3', trunc=None):
    pkt = ipv4(src, dst, 2, payload, ttl=1)
    fr = eth('01:00:5e:01:02:03', H, 0x0800, pkt)
    return fr

JOIN, QUERY, LEAVE = 0x40, 0x41, 0x42
MD5 = bytes(range(0xa0, 0xb0))     # placeholder, not a real digest
CHAL = bytes(range(0x10, 0x20))

def main(out):
    p = Pcap(1)
    add = lambda *a, **k: p.add(f(igap(*a, **k)))
    # Joins
    add(JOIN, 0x02, b'alice', b'password-text')            # password mechanism
    add(JOIN, 0x03, b'bob')                                 # challenge request, no message
    add(JOIN, 0x04, b'bob', MD5)                            # challenge response (MD5 field)
    # Queries
    add(QUERY, 0x21, b'', b'', group='0.0.0.0')             # basic query
    add(QUERY, 0x23, b'bob', CHAL)                          # challenge
    add(QUERY, 0x24, b'bob', b'\x11')                       # authentication success
    add(QUERY, 0x24, b'bob', b'\x21')                       # authentication failure
    add(QUERY, 0x24, b'bob', b'\x00')                       # other result
    add(QUERY, 0x25, b'bob', b'\x11')                       # accounting start
    add(QUERY, 0x25, b'bob', b'\x21')                       # accounting stop
    # Leaves
    add(LEAVE, 0x41, b'alice')                              # basic leave
    add(LEAVE, 0x42, b'alice', b'password-text')            # password
    add(LEAVE, 0x43, b'alice')                              # challenge request
    add(LEAVE, 0x44, b'alice', MD5)                         # challenge response
    # Subtype with no definition and a message (shown as unknown message)
    add(JOIN, 0x99, b'carol', b'xyz', cid=0xff)
    add(QUERY, 0x21, b'carol', b'basic-query-with-message')
    # Account and message sizes beyond the field sizes are clamped
    add(JOIN, 0x02, b'account-sixteen!', b'P' * 64, asize=40, msize=200)
    add(JOIN, 0x04, b'', MD5, asize=0, msize=64)
    # Other version, max response time 0 and 255, unknown IGAP type
    add(JOIN, 0x02, b'dave', b'pw', version=0x20, tsecs=0)
    add(LEAVE, 0x41, b'dave', tsecs=255, group='239.255.255.250')
    # No account, subtype of a leave under a query
    add(QUERY, 0x41, b'', b'')
    p.write(os.path.join(out, 'igap-coverage.pcap'))

    m = Pcap(1)
    # Bad checksum (error expert info)
    m.add(f(igap(JOIN, 0x02, b'alice', b'pw', bad=True)))
    # Message cut short (inside the account field, and inside the message)
    m.add(f(igap(JOIN, 0x02, b'alice', b'pw')[:20]))
    m.add(f(igap(JOIN, 0x02, b'alice', b'pw')[:50]))
    m.add(f(igap(JOIN, 0x02, b'alice', b'pw')[:95]))
    # Message truncated by the snap length (captured shorter than reported)
    full = f(igap(JOIN, 0x02, b'alice', b'pw'))
    m.add(full[:70]); m.frames[-1] = full[:70]
    m.write(os.path.join(out, 'igap-coverage-malformed.pcap'))

main(sys.argv[1])
