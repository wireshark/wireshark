#!/usr/bin/env python3
# Generates test/captures/scsi_smc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic iSCSI/SCSI captures for packet-scsi-smc.c (SCSI medium changer commands).

usage: mksmc.py <outdir>

Writes scsi-smc-coverage.pcap (clean) and scsi-smc-coverage-malformed.pcap.
The commands run over iSCSI (TCP port 3260) to a medium changer (INQUIRY
device type 8, LUN 0).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct

from scsilib import Pcap, rand_cdb  # noqa: E402

R = random.Random(1329)


def rnd(n):
    return bytes(R.randrange(256) for _ in range(n))


def u16(v): return struct.pack('>H', v)
def u24(v): return struct.pack('>I', v)[1:]
def u32(v): return struct.pack('>I', v)


SMC_OPS = (0x07, 0x1b, 0x2b, 0x37, 0xa5, 0xa6, 0xa7, 0xb4, 0xb8)
MT, ST, IE, DT = 1, 2, 3, 4


def volume_tag(ident, seq):
    return ident.ljust(32, b' ') + b'\x00\x00' + u16(seq)


def element(etype, ea, pv=None, av=None, ident=None, svalid=None, flags=None, asc=None, dt=None,
            vendor=b''):
    """One element descriptor in the layout of SMC-3 table 'element descriptor'."""
    fl = flags if flags is not None else R.randrange(256)
    d = u16(ea) + bytes([fl, 0])
    d += bytes(asc) if asc else bytes([0, 0])
    d += bytes(dt) if dt else bytes([R.randrange(256), R.randrange(256), 0])
    if svalid is None:
        d += bytes([0, 0, 0])
    else:
        d += bytes([0x80 | 0x40]) + u16(svalid)
    if pv is not None:
        d += volume_tag(*pv)
    if av is not None:
        d += volume_tag(*av)
    if ident is not None:
        d += bytes([2, 1, 0, len(ident)]) + ident
    return d + vendor


def status_page(etype, descs, pv=False, av=False, desc_len=None):
    n = desc_len if desc_len is not None else max(len(d) for d in descs)
    body = b''.join(d[:n].ljust(n, b'\x00') for d in descs)
    return bytes([etype, (0x80 if pv else 0) | (0x40 if av else 0)]) + u16(n) + b'\x00' + u24(len(body)) + body


def status_report(pages, first=0x10):
    body = b''.join(pages)
    return u16(first) + u16(len(pages)) + b'\x00' + u24(len(body)) + body


def main(out):
    os.makedirs(out, exist_ok=True)
    main_cap(os.path.join(out, 'scsi-smc-coverage.pcap'))
    malformed_cap(os.path.join(out, 'scsi-smc-coverage-malformed.pcap'))


def main_cap(path):
    p = Pcap(path)
    x = p.xchg
    mark = p.mark
    p.inquiry(0, 0x08)
    mark('random')
    for op in SMC_OPS:
        for variant in range(3):
            x(rand_cdb(R, op), 0)
    for op in (0x00, 0x03, 0x1d, 0x1e, 0x3b):
        x(rand_cdb(R, op), 0)
    mark('status')
    pages = [
        status_page(MT, [element(MT, 0x01, flags=0x01), element(MT, 0x02, flags=0x05, asc=(0x15, 0x01))]),
        status_page(ST, [element(ST, 0x10 + i, pv=(b'TAPE%02d' % i, i), svalid=0x10 + i, flags=R.choice((0x01, 0x09, 0x0d, 0x08)))
                         for i in range(4)], pv=True),
        status_page(IE, [element(IE, 0x20, pv=(b'EXPORT', 1), av=(b'ALT001', 2), flags=0x5b),
                         element(IE, 0x21, pv=(b'EXPORT', 2), av=(b'ALT002', 3), flags=0x00)], pv=True, av=True),
        status_page(DT, [element(DT, 0x30, pv=(b'TAPE00', 1), svalid=0x10, dt=(0x20 | 0x10 | 0x08 | 0x03, 5, 0),
                                 ident=b'DRIVE-0001', flags=0x09, vendor=b'\xaa\xbb'),
                         element(DT, 0x31, pv=(b'', 0), dt=(0x00, 7, 0), ident=b'', flags=0x05, asc=(0x04, 0x03))],
                    pv=True),
    ]
    for op, rep in ((0xb8, status_report(pages)), (0xb4, status_report(pages[:2]))):
        x(bytes([op, 0x10 | 0x80, 0, 0x10, 0, 8, 0x03]) + u24(len(rep)) + b'\x00\x00', 0, din=rep)
    # descriptors cut at every length: the decoder stops early without an exception
    base = element(DT, 0x30, pv=(b'TAPE00', 1), av=(b'ALT000', 2), dt=(0x20 | 0x10 | 0x08 | 0x03, 5, 0),
                   svalid=0x10, ident=b'DRIVE-0001', flags=0x0d)
    for n in list(range(2, 12)) + [20, 40, 80, 81, 82, 83, 84, 85, 90]:
        pg = status_page(DT, [base], pv=True, av=True, desc_len=n)
        rep = status_report([pg])
        x(bytes([0xb8, 0x10 | 0x80, 0, 0x10, 0, 8, 0x03]) + u24(len(rep)) + b'\x00\x00', 0, din=rep)
    for et in (MT, ST, IE):
        pg = status_page(et, [element(et, 0x40, pv=(b'X', 1), ident=b'ID', flags=0x85, svalid=3)], pv=True)
        rep = status_report([pg])
        x(bytes([0xb8, et, 0, 0x10, 0, 8, 0]) + u24(len(rep)) + b'\x00\x00', 0, din=rep)
    # descriptors without volume tags cut after the identifier type, the reserved byte and the identifier length
    nov = element(DT, 0x30, dt=(0x20 | 0x10 | 0x08 | 0x03, 5, 0), svalid=0x10, ident=b'DRIVE-0001', flags=0x09)
    for n in (12, 13, 14, 15, 16, 17, 20):
        rep = status_report([status_page(DT, [nov], desc_len=n)])
        x(bytes([0xb8, 0x10, 0, 0x10, 0, 8, 0x03]) + u24(len(rep)) + b'\x00\x00', 0, din=rep)
    # reports whose byte count ends inside the page header, or is shorter than the descriptor data count
    page = bytes([DT, 0]) + u16(24) + b'\x00' + u24(100) + b'\x00' * 24
    for bc in range(1, 10):
        rep = u16(0x10) + u16(1) + b'\x00' + u24(bc) + page
        x(bytes([0xb8, 0x10, 0, 0x10, 0, 8, 0x03]) + u24(len(rep)) + b'\x00\x00', 0, din=rep)
    # element descriptor data of a length smaller than two bytes
    rep = u16(0x10) + u16(1) + b'\x00' + u24(12) + bytes([ST, 0]) + u16(1) + b'\x00' + u24(4) + b'\x00' * 4
    x(bytes([0xb8, 0x10, 0, 0x10, 0, 8, 0x03]) + u24(len(rep)) + b'\x00\x00', 0, din=rep)
    # a report with a zero byte count
    x(bytes([0xb8, 0, 0, 0x10, 0, 8, 0]) + u24(8) + b'\x00\x00', 0, din=u16(0x10) + u16(0) + b'\x00' + u24(0))
    mark('end')
    p.close()


def malformed_cap(path):
    p = Pcap(path)
    x = p.xchg
    p.inquiry(0, 0x08)
    # response cut inside the report header, and inside a page header
    x(bytes([0xb8, 0, 0, 0x10, 0, 8, 0]) + u24(64) + b'\x00\x00', 0, din=rnd(6))
    x(bytes([0xb8, 0, 0, 0x10, 0, 8, 0]) + u24(64) + b'\x00\x00', 0, din=u16(0x10) + u16(1) + b'\x00' + u24(20) + bytes([4, 0x80, 0, 36]))
    p.close()


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
