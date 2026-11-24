#!/usr/bin/env python3
# Generates test/captures/kerberos4_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Kerberos v4 coverage captures: mkkerberos4.py <outdir>.

Writes kerberos4-coverage.pcap (all message types, both byte orders, the
Transarc variant) and kerberos4-coverage-malformed.pcap (truncated
messages). All names, tickets, authenticators and encrypted blobs are
made-up placeholder bytes; nothing is encrypted or keyed.
"""
import os
import struct
import sys
from pylib import Pcap, eth_udp

KDC = 750
T0 = 1700000000

def s(x):
    return x.encode() + b'\0'

def fmt(le):
    return '<' if le else '>'

def hdr(ver, mtype, le):
    return struct.pack('BB', ver, (mtype << 1) | (1 if le else 0))

def kdc_request(le=False, ver=4, name='alice', inst='', realm='EXAMPLE.TEST',
                t=T0, life=96, sname='krbtgt', sinst='EXAMPLE.TEST', blob=b''):
    return (hdr(ver, 1, le) + blob + s(name) + s(inst) + s(realm) +
            struct.pack(fmt(le) + 'IB', t, life) + s(sname) + s(sinst))

def kdc_reply(le=False, ver=4, name='alice', inst='', realm='EXAMPLE.TEST',
              t=T0, unk=0, exp=T0 + 28800, kvno=3, enc=bytes(range(64, 104))):
    return (hdr(ver, 2, le) + s(name) + s(inst) + s(realm) +
            struct.pack(fmt(le) + 'IBIB', t, unk, exp, kvno) +
            struct.pack(fmt(le) + 'H', len(enc)) + enc)

def appl_request(le=False, ver=4, mtype=3, kvno=2, realm='EXAMPLE.TEST',
                 ticket=bytes([0xaa] * 20), req=bytes([0xbb] * 12),
                 t=T0, life=255, sname='rcmd', sinst='host1'):
    return (hdr(ver, mtype, le) + struct.pack('B', kvno) + s(realm) +
            struct.pack('BB', len(ticket), len(req)) + ticket + req +
            struct.pack(fmt(le) + 'IB', t, life) + s(sname) + s(sinst))

def simple(mtype, le=False, ver=4, body=b'\x00' * 8):
    return hdr(ver, mtype, le) + body

TRANSARC = 0x63
TBLOB = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])

def main(out):
    p = Pcap()
    def add(data, rev=False):
        sp, dp = (KDC, 40000) if rev else (40000, KDC)
        p.add(eth_udp(sp, dp, data, rev=rev))

    # 1-4 KDC requests: big/little endian, instance set, Transarc
    add(kdc_request())
    add(kdc_request(le=True, name='bob', inst='admin', sname='changepw',
                    sinst='kerberos', life=1))
    add(kdc_request(ver=TRANSARC, blob=TBLOB, realm='AFS.EXAMPLE.TEST'))
    add(kdc_request(le=True, ver=TRANSARC, blob=TBLOB, name='afs', sname='afs'))
    # 5-8 KDC replies
    add(kdc_reply(), rev=True)
    add(kdc_reply(le=True, name='bob', inst='admin', kvno=1,
                  enc=bytes([0x5a] * 33)), rev=True)
    add(kdc_reply(ver=TRANSARC, realm='AFS.EXAMPLE.TEST'), rev=True)
    add(kdc_reply(enc=b''), rev=True)
    # 9-12 application requests
    add(appl_request())
    add(appl_request(le=True, kvno=9, sname='ftp', sinst='ftp.example.test'))
    add(appl_request(ver=TRANSARC, life=0))
    add(appl_request(ticket=b'', req=b'', mtype=3))
    # 13-22 the message types the dissector only names, both byte orders
    for mt in (4, 5, 6, 7, 8, 63):
        add(simple(mt), rev=(mt in (5, 8)))
    add(simple(4, le=True))
    add(simple(5, le=True, ver=TRANSARC), rev=True)
    add(simple(6, le=True))
    add(simple(63, le=True, ver=TRANSARC))
    # 23-25 not Kerberos v4: wrong version, unknown message type
    add(simple(1, ver=5, body=b'\x01' * 20))
    add(simple(9, body=b'\x01' * 20))
    add(simple(100, le=True, body=b'\x02' * 20))
    p.write(os.path.join(out, 'kerberos4-coverage.pcap'))

    m = Pcap()
    def madd(data, rev=False):
        sp, dp = (KDC, 40001) if rev else (40001, KDC)
        m.add(eth_udp(sp, dp, data, rev=rev))
    full = kdc_request()
    madd(full[:2])            # no name
    madd(full[:9])            # name cut
    madd(full[:-3])           # service strings cut
    madd(kdc_request(ver=TRANSARC, blob=TBLOB)[:6])   # short Transarc blob
    r = kdc_reply()
    madd(r[:20], rev=True)
    madd(r[:-10], rev=True)   # encrypted blob longer than the packet
    madd(kdc_reply(enc=b'')[:-1], rev=True)
    a = appl_request()
    madd(a[:12])
    madd(a[:20])              # ticket cut
    madd(a[:38])              # request cut
    madd(a[:-4])
    madd(appl_request(le=True)[:-1])
    madd(b'\x04')             # version only
    m.write(os.path.join(out, 'kerberos4-coverage-malformed.pcap'))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
