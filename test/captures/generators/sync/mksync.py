#!/usr/bin/env python3
# Generates test/captures/sync_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SYNC (MBMS synchronisation) coverage captures: mksync.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
from c17lib import Cap, ipv4, exppdu

def ipudp(n=1):
    payload = b'mbms user data %d' % n
    u = struct.pack('>HHHH', 4000, 5000, 8 + len(payload), 0) + payload
    return ipv4(17, u)

def head(typ, ts, pktnr, octets, spare=0):
    """octet 1 type/spare, timestamp (x10 ms), packet number minus one, elapsed octet counter."""
    return struct.pack('>BHHI', (typ << 4) | spare, ts, pktnr - 1, octets)

def t0(ts=100, pktnr=1, octets=0, tot=5000, totoct=123456789, crc=0x2a):
    return head(0, ts, pktnr, octets) + struct.pack('>I', tot)[1:] + struct.pack('>Q', totoct)[3:] + bytes([crc << 2])

def t1(payload, crc=0x15, pcrc=0x155):
    return head(1, 200, 7, 4096) + struct.pack('>H', (crc << 10) | pcrc) + payload

def t2(spare, extra=60):
    return head(2, 300, 9, 1000, spare) + b'\xaa' * extra

def t3(pktnr, tot=300, lens=None, tail=True, extra=b''):
    """Type 3: lengths of packets as 12 bit values, two in three octets."""
    b = head(3, 400, pktnr, 77) + struct.pack('>I', tot)[1:] + struct.pack('>Q', 987654321)[3:] + struct.pack('>H', (0x2b << 10) | 0x2aa)
    lens = lens if lens is not None else [(100 + 7 * i) & 0xfff for i in range(pktnr)]
    body = b''
    for i in range(0, len(lens) - 1, 2):
        v = (lens[i] << 12) | lens[i + 1]
        body += struct.pack('>I', v)[1:]
    if len(lens) % 2:
        body += struct.pack('>H', lens[-1] << 4) + (b'\0' if tail else b'')
    return b + body + extra

def main(out, verbose):
    c = Cap(252)
    def add(p):
        c.add(exppdu('sync', p))
    c.mark('Type 0 (synchronisation frame without payload) with several counters')
    add(t0()); add(t0(0, 65535, 0xffffffff, 0xffffff, 0xffffffffff, 0x3f)); add(t0(65535, 1, 0, 0, 0, 0))
    c.mark('Type 1 (user data, uncompressed headers) carrying IPv4/UDP')
    add(t1(ipudp(1))); add(t1(ipudp(2), 0x3f, 0x3ff)); add(t1(ipudp(3), 0, 0))
    c.mark('Type 2 (compressed headers, not decoded): spare bit 0 and 1, expert info')
    add(t2(0)); add(t2(1, 80)); add(t2(2, 20))
    c.mark('Type 3 (lengths of packets): 2, 4 and 8 packets (even, total number of packets set)')
    add(t3(2)); add(t3(4)); add(t3(8))
    c.mark('Type 3 with an odd number of packets (1, 3, 5, 7) and with total number of packets 0')
    add(t3(1)); add(t3(3)); add(t3(5)); add(t3(7))
    add(t3(2, tot=0, extra=b'\x50\x00')); add(t3(6, tot=0, extra=b'\x70\x00'))
    c.mark('Type 3 with the header only, no lengths')
    add(t3(1, lens=[])[:19])
    c.mark('Reserved PDU types 4, 9 and 15 (expert info)')
    for typ in (4, 9, 15):
        add(head(typ, 1, 1, 1) + b'\0' * 10)
    c.mark('Reproducer of the type 3 length fix: 30000 packets, 45 KB, even; and 21847 packets, odd')
    add(t3(30000, lens=[1500] * 30000))
    add(t3(21847, lens=[1400] * 21847))

    m = Cap(252)
    def madd(p):
        m.add(exppdu('sync', p))
    m.mark('Truncated PDUs of every type, type 3 whose list of lengths is cut short, type 1 with a short payload')
    madd(t0()[:5]); madd(t0()[:12]); madd(t0()[:17])
    madd(t1(ipudp(1))[:11]); madd(t1(b''))
    madd(t1(ipudp(4))[:30])
    madd(t2(0)[:9])
    madd(t3(6)[:25]); madd(t3(5)[:22]); madd(t3(7, tail=False)); madd(t3(300)[:100])
    madd(b'\x30'); madd(b'')
    c.write(os.path.join(out, 'sync-coverage.pcap'))
    m.write(os.path.join(out, 'sync-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
