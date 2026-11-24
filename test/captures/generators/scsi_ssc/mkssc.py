#!/usr/bin/env python3
# Generates test/captures/scsi_ssc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic iSCSI/SCSI captures for packet-scsi-ssc.c (SCSI stream commands).

usage: mkssc.py <outdir>

Writes scsi-ssc-coverage.pcap (clean) and scsi-ssc-coverage-malformed.pcap.
The commands run over iSCSI (TCP port 3260) to a tape drive (INQUIRY device
type 1, LUN 0).  The SSC table also holds the medium changer commands MOVE
MEDIUM and READ ELEMENT STATUS, which are sent too.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct

from scsilib import Pcap, fixed_sense, rand_cdb  # noqa: E402

R = random.Random(1328)


def rnd(n):
    return bytes(R.randrange(256) for _ in range(n))


def u16(v): return struct.pack('>H', v)
def u24(v): return struct.pack('>I', v)[1:]
def u32(v): return struct.pack('>I', v)
def u64(v): return struct.pack('>Q', v)


# opcodes of the SSC table with a decoder of their own
SSC_OPS = (0x01, 0x04, 0x05, 0x08, 0x0a, 0x0b, 0x0f, 0x10, 0x11, 0x13, 0x14, 0x19, 0x1b, 0x2b, 0x34,
           0x44, 0x80, 0x81, 0x88, 0x8a, 0x8f, 0x91, 0x92, 0x93, 0xa5, 0xa7, 0xb4, 0xb8)
DATA_IN = {0x08, 0x0f, 0x14, 0x81, 0x88, 0x05, 0x44}
DATA_OUT = {0x0a, 0x8a, 0x04}


def main(out):
    os.makedirs(out, exist_ok=True)
    main_cap(os.path.join(out, 'scsi-ssc-coverage.pcap'))
    malformed_cap(os.path.join(out, 'scsi-ssc-coverage-malformed.pcap'))


def read_position(p):
    x = p.xchg
    for sa, flagsets in ((0, (0x00, 0x04, 0x20, 0x10, 0x34, 0xc0)), (1, (0x00,)), (6, (0x00, 0x04, 0x08, 0x2c)),
                         (8, (0x00, 0x04, 0x20, 0x10, 0x08, 0x3c, 0x01))):
        for fl in flagsets:
            if sa in (0, 1):
                d = bytes([fl, 1, 0, 0]) + u32(0x10) + u32(0x20) + b'\x00' + u24(5) + u32(0x4000)
                n = 20
            elif sa == 6:
                d = bytes([fl, 0, 0, 0]) + u32(2) + u64(0x1000) + u64(7) + u64(3)
                n = 32
            else:
                d = bytes([fl, 2]) + u16(0x1e) + b'\x00' + u24(9) + u64(0x100) + u64(0x200) + b'\x00' + u64(0x8000)
                n = 33
            x(bytes([0x34, sa, 0, 0, 0, 0, 0, 0, 0, 0]), 0, din=d[:n])
    x(bytes([0x34, 0x03, 0, 0, 0, 0, 0, 0, 20, 0]), 0, din=rnd(20))        # service action without a decoder


def main_cap(path):
    p = Pcap(path)
    x = p.xchg
    mark = p.mark
    p.inquiry(0, 0x01, removable=True)
    mark('random')
    for op in SSC_OPS:
        for variant in range(3):
            cdb = rand_cdb(R, op)
            if op in DATA_IN:
                x(cdb, 0, din=rnd(64))
            elif op in DATA_OUT:
                x(cdb, 0, dout=rnd(32))
            else:
                x(cdb, 0)
    mark('limits')
    x(bytes([0x05, 0, 0, 0, 0, 0]), 0, din=bytes([0x03]) + u24(0x40000) + u16(1))
    x(bytes([0x05, 0, 0, 0, 0, 0]), 0, din=bytes([0x00]) + u24(0x10000) + u16(0x200))
    mark('readpos')
    read_position(p)
    mark('misc')
    # load/unload, locate, space, erase, with the bit variants
    for b1 in (0, 1):
        for b4 in (0, 1, 2, 3, 4, 5, 7, 8, 9, 0x0f):
            x(bytes([0x1b, b1, 0, 0, b4, 0]), 0)
    x(bytes([0x2b, 0x07, 0, 0, 0, 0x10, 0, 0, 0, 0, 0]), 0)
    # reads and writes, variable and fixed
    for fixed in (0, 1):
        for op, ln in ((0x08, 6), (0x0f, 6)):
            x(bytes([op, fixed, 0, 0, 4, 0]), 0, din=rnd(2048))
        x(bytes([0x0a, fixed, 0, 0, 4, 0]), 0, dout=rnd(2048))
    # check conditions on a read: filemark, EOM, ILI with information
    x(bytes([0x08, 0, 0, 0, 4, 0]), 0, status=2, sense=fixed_sense(0x80 | 0, 0, 1, info=0x10))
    x(bytes([0x08, 1, 0, 0, 4, 0]), 0, status=2, sense=bytes([0x70 | 0x80, 0, 0x20, 0, 0, 0, 0x10, 10]) + b'\x00' * 10)
    x(bytes([0x08, 1, 0, 0, 4, 0]), 0, status=2, sense=bytes([0x70 | 0x80, 0, 0x40, 0, 0, 0, 0x10, 10]) + b'\x00' * 10)
    mark('end')
    p.close()


def malformed_cap(path):
    p = Pcap(path)
    x = p.xchg
    p.inquiry(0, 0x01, removable=True)
    for sa, n in ((0, 8), (6, 12), (8, 10), (1, 4)):                  # position data cut short
        x(bytes([0x34, sa, 0, 0, 0, 0, 0, 0, 0, 0]), 0, din=rnd(n))
    x(bytes([0x05, 0, 0, 0, 0, 0]), 0, din=bytes([0x03, 0, 0]))
    p.close()


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
