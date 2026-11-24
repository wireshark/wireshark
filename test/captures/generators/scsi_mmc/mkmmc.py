#!/usr/bin/env python3
# Generates test/captures/scsi_mmc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic iSCSI/SCSI captures for packet-scsi-mmc.c (SCSI multimedia commands).

usage: mkmmc.py <outdir>

Writes scsi-mmc-coverage.pcap (clean) and scsi-mmc-coverage-malformed.pcap.
The commands run over iSCSI (TCP port 3260) to a CD/DVD drive (INQUIRY device
type 5, LUN 0).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct

from scsilib import Pcap, rand_cdb  # noqa: E402

R = random.Random(1330)


def rnd(n):
    return bytes(R.randrange(256) for _ in range(n))


def u16(v): return struct.pack('>H', v)
def u24(v): return struct.pack('>I', v)[1:]
def u32(v): return struct.pack('>I', v)
def u64(v): return struct.pack('>Q', v)


# MMC opcodes with a decoder of their own, with random CDB fields
MMC_OPS = (0x1b, 0x1e, 0x25, 0x28, 0x2a, 0x35, 0x43, 0x46, 0x4a, 0x51, 0x52, 0x53, 0x5b, 0x5c, 0xa4,
           0xa8, 0xaa, 0xac, 0xad, 0xb6, 0xbb)


def feature(code, data, version=1, persistent=1, current=1):
    return u16(code) + bytes([(version << 2) | (persistent << 1) | current, len(data)]) + data


def get_configuration(profile=0x0010, features=()):
    body = b''.join(features)
    return u32(4 + len(body)) + b'\x00\x00' + u16(profile) + body


def main(out):
    os.makedirs(out, exist_ok=True)
    main_cap(os.path.join(out, 'scsi-mmc-coverage.pcap'))
    malformed_cap(os.path.join(out, 'scsi-mmc-coverage-malformed.pcap'))


def toc_cdb(fmt, time=0, track=0, alloc=804):
    return bytes([0x43, time, fmt, 0, 0, 0, track]) + u16(alloc) + b'\x00'


def main_cap(path):
    p = Pcap(path)
    x = p.xchg
    mark = p.mark
    p.inquiry(0, 0x05, removable=True)
    mark('random')
    for op in MMC_OPS:
        for variant in range(3):
            cdb = rand_cdb(R, op)
            if op in (0x28, 0xa8):
                x(cdb, 0, din=rnd(64))
            elif op in (0x2a, 0xaa):
                x(cdb, 0, dout=rnd(64))
            else:
                x(cdb, 0)
    mark('getconf')
    profiles = b''.join(u16(pr) + bytes([c, 0]) for pr, c in ((0x0008, 0), (0x0010, 1), (0x001a, 0), (0x0000, 0xff)))
    feats = (feature(0x0000, profiles), feature(0x001d, b''), feature(0x001f, b''),
             feature(0x001e, bytes([R.randrange(256), 0, 0, 0])),
             feature(0x0021, u16(0x0100) + bytes([0x01, 3, 1, 2, 4])),
             feature(0x002a, bytes([0x07, 0, 0x03, 0x03])), feature(0x002b, bytes([0x07, 0, 0, 0])),
             feature(0x002d, bytes([0x7f, 0, 0x01, 0x00, 0, 0, 0, 0])),
             feature(0x002e, bytes([0xff, 0x00, 0x10, 0x00, 0, 0, 0, 0])),
             feature(0x002f, bytes([0x7f, 0, 0, 0])), feature(0x0108, b'ABC123456789'))
    rep = get_configuration(0x0010, feats)
    x(bytes([0x46, 0x02, 0, 0, 0, 0, 0]) + u16(len(rep)) + b'\x00', 0, din=rep)
    for k in range(len(feats)):
        r = get_configuration(0x0008 + k, (feats[k],))
        x(bytes([0x46, 0x01, 0, k, 0, 0, 0]) + u16(len(r)) + b'\x00', 0, din=r)
    x(bytes([0x46, 0x00, 0, 0, 0, 0, 0]) + u16(8) + b'\x00', 0, din=get_configuration(0x0010, ())[:8])
    mark('toc')
    for fmt, time, track in ((0, 0, 1), (0, 2, 0), (0, 2, 1)):
        n = 3
        d = u16(2 + 8 * n) + bytes([1, n])
        for t in range(n):
            d += bytes([0, 0x14, t + 1, 0]) + u32(0x00000200 * t)
        x(toc_cdb(fmt, time, track), 0, din=d)
    x(toc_cdb(0, 0, 0), 0, din=u16(2) + bytes([1, 1]))
    mark('disc')
    di = u16(32) + bytes([0x1c, 1, 1, 1, 0xe5, 0x00, 0, 0]) + u32(0xdeadbeef) + u32(0x1000) + u32(0x2000) + u64(0)
    x(bytes([0x51, 0, 0, 0, 0, 0, 0]) + u16(34) + b'\x00', 0, din=di)
    x(bytes([0x51, 0, 0, 0, 0, 0, 0]) + u16(34) + b'\x00', 0, din=u16(32) + bytes([0x1c, 1, 1, 1, 0x00, 0x10, 0, 0]) + rnd(24))
    x(bytes([0x51, 0, 0, 0, 0, 0, 0]) + u16(12) + b'\x00', 0, din=di[:12])
    # read track information: with the extra track/session bytes and without
    for alloc, n in ((36, 36), (48, 48), (40, 34)):
        ti = u16(n - 2) + bytes([1, 1, 0, 0x0d, 0x0f, 0xc0]) + u32(0) + u32(0x1000) + u32(0x20) + u32(0x10) + u32(0x4000) + u32(0x3fff) + bytes([2, 3]) + u32(0x100)
        x(bytes([0x52, R.choice((0, 1, 2)), 0, 0, 0, 1, 0]) + u16(alloc) + b'\x00', 0, din=ti[:n].ljust(n, b'\x00'))
    for at in (0, 1, 2):
        x(bytes([0x52, at, 0, 0, 0, 5, 0]) + u16(36) + b'\x00', 0, din=rnd(36))
    mark('struct')
    # READ DISC STRUCTURE: physical format and ADIP, a format without a decoder is in the malformed capture
    for fmt in (0x00, 0x11):
        d = u16(0x22) + b'\x00\x00' + bytes([0x01 | (4 << 4), 0x02, 0x21, 0x10, 0]) + u24(0x30000)[:3] + b'\x00' + u24(0x7fffff)[:3] + b'\x00' + u24(0x30000) + b'\x00' + rnd(16)
        x(bytes([0xad, 0, 0, 0, 0, 0, 0, fmt]) + u16(len(d)) + bytes([0, 0]), 0, din=d.ljust(36, b'\x00'))
    # REPORT KEY, RPC state
    x(bytes([0xa4, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0x08, 0]), 0, din=u16(6) + b'\x00\x00' + bytes([0x40 | 0x10 | 0x03, 0xfe, 1, 0]))
    mark('misc')
    # buffer capacity, with and without the block bit
    for blk in (0, 1):
        x(bytes([0x5c, blk, 0, 0, 0, 0, 0, 0, 12, 0]), 0, din=u16(10) + b'\x00\x00' + u32(0x100000) + u32(0x80000))
    # SET STREAMING: performance descriptor
    pd = bytes([0x07, 0, 0, 0]) + u32(0) + u32(0x1fffff) + u32(0x1000) + u32(1000) + u32(0x1000) + u32(1000)
    x(bytes([0xb6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 0]), 0, dout=pd)
    # GET EVENT STATUS NOTIFICATION, ... responses (no decoder for the data)
    x(bytes([0x4a, 1, 0, 0, 0x7f, 0, 0, 0, 8, 0]), 0, din=rnd(8))
    mark('trackinfo')
    # READ TRACK INFORMATION cut by an allocation length of 32 and 33 bytes
    for alloc in (32, 33):
        x(bytes([0x52, 1, 0, 0, 0, 1, 0]) + u16(alloc) + b'\x00', 0, din=rnd(alloc))
    mark('end')
    p.close()


def malformed_cap(path):
    p = Pcap(path)
    x = p.xchg
    p.inquiry(0, 0x05, removable=True)
    # a feature without a decoder
    r = get_configuration(0x0010, (feature(0x0123, b'\x00' * 8),))
    x(bytes([0x46, 0x02, 0, 0, 0, 0, 0]) + u16(len(r)) + b'\x00', 0, din=r)
    # READ TOC formats without a decoder
    for fmt in (1, 2, 3, 4, 5):
        x(toc_cdb(fmt), 0, din=u16(10) + bytes([1, 1]) + rnd(8))
    # READ DISC STRUCTURE format without decoder
    x(bytes([0xad, 0, 0, 0, 0, 0, 0, 0x04]) + u16(16) + bytes([0, 0]), 0, din=rnd(16))
    # REPORT KEY combinations without a decoder
    x(bytes([0xa4, 0, 0, 0, 0, 0, 0, 1, 0, 8, 0x01, 0]), 0, din=rnd(8))
    # SET STREAMING of an unknown type
    x(bytes([0xb6, 0, 0, 0, 0, 0, 0, 0, 5, 0, 8, 0]), 0, dout=rnd(8))
    p.close()


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
