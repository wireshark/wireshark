#!/usr/bin/env python3
# Generates test/captures/scsi_sbc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic iSCSI/SCSI captures for packet-scsi-sbc.c (SCSI block commands).

usage: mksbc.py <outdir>

Writes scsi-sbc-coverage.pcap (clean) and scsi-sbc-coverage-malformed.pcap.
The commands run over iSCSI (TCP port 3260).  LUN 0 is a disk (INQUIRY device
type 0), LUN 1 a CD/DVD drive: the SBC table is also used for it through the
shared handlers (START STOP UNIT, READ(10) and others).  LUN 2 is never inquired:
it uses the default command set (SBC).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct

from scsilib import Pcap, fixed_sense, rand_cdb  # noqa: E402

R = random.Random(1327)


def rnd(n):
    return bytes(R.randrange(256) for _ in range(n))


def u16(v): return struct.pack('>H', v)
def u32(v): return struct.pack('>I', v)
def u64(v): return struct.pack('>Q', v)


# Opcodes of the SBC table with a decoder of their own (SPC ones are left to the
# scsi-coverage capture); all are exercised with random CDB fields.
SBC_OPS = (0x04, 0x07, 0x08, 0x0a, 0x1b, 0x25, 0x28, 0x2a, 0x2e, 0x2f, 0x34, 0x35, 0x37, 0x3e, 0x3f,
           0x41, 0x42, 0x48, 0x50, 0x51, 0x52, 0x53, 0x88, 0x89, 0x8a, 0x8b, 0x8e, 0x8f, 0x90, 0x91,
           0x93, 0x9c, 0xa8, 0xaa, 0xae, 0xaf, 0xb7)
DATA_IN = {0x08, 0x28, 0x88, 0xa8, 0x3e, 0x52, 0x37, 0xb7}
DATA_OUT = {0x0a, 0x2a, 0x8a, 0xaa, 0x2e, 0x8e, 0xae, 0x3f, 0x41, 0x93, 0x50, 0x51, 0x89, 0x8b, 0x9c, 0x04,
            0x07}


def main(out):
    os.makedirs(out, exist_ok=True)
    main_cap(os.path.join(out, 'scsi-sbc-coverage.pcap'))
    malformed_cap(os.path.join(out, 'scsi-sbc-coverage-malformed.pcap'))


def main_cap(path):
    p = Pcap(path)
    x = p.xchg
    mark = p.mark
    p.inquiry(0, 0x00)
    p.inquiry(1, 0x05, removable=True)
    mark('random')

    # random CDB fields for every SBC opcode, on the disk and (for the shared
    # ones) on the CD drive: the decoders show every bit of the CDB
    for op in SBC_OPS:
        for variant in range(3):
            cdb = rand_cdb(R, op)
            if op in DATA_IN:
                x(cdb, 0, din=rnd(512))
            elif op in DATA_OUT:
                x(cdb, 0, dout=rnd(32))
            else:
                x(cdb, 0)
    for op in (0x1b, 0x25, 0x28, 0x2a, 0x35, 0xa8, 0xaa):
        x(rand_cdb(R, op), 1)

    mark('rc10')
    # READ CAPACITY(10) responses
    for lba, bl in ((0x000fffff, 512), (0xffffffff, 4096), (0, 1), (0x3fffffff, 512), (0x7fffffff, 2048)):
        x(bytes([0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 0, din=u32(lba) + u32(bl))
    mark('rc16')
    # READ CAPACITY(16) responses, with and without protection information
    for prot, big in ((0, 0), (1, 0), (0x0b, 0), (0, 1)):
        d = u64(0xffffffffffffffff if big else 0x1000000) + u32(0xffffffff if big else 512)
        d += bytes([prot, 0x23, 0x80 | 0x40, 0x01]) + b'\x00' * 16
        x(bytes([0x9e, 0x10]) + b'\x00' * 8 + u32(32) + bytes([0, 0]), 0, din=d)
    # READ LONG(16), GET LBA STATUS, REPORT REFERRALS, reserved service action
    x(bytes([0x9e, 0x11]) + u64(0x2000) + b'\x00\x00' + u16(0x208) + bytes([1, 0]), 0, din=rnd(0x208))
    d = u32(8 + 16 * 3) + b'\x00' * 4
    for lba, n, st in ((0, 8, 0), (8, 16, 1), (24, 1, 2)):
        d += u64(lba) + u32(n) + bytes([st, 0, 0, 0])
    x(bytes([0x9e, 0x12]) + u64(0) + u32(len(d)) + bytes([0, 0]), 0, din=d)
    x(bytes([0x9e, 0x13]) + u64(0) + u32(64) + bytes([0, 0]), 0, din=rnd(64))
    x(bytes([0x9e, 0x15]) + u64(0) + u32(64) + bytes([0, 0]), 0)
    # WRITE LONG(16) and a reserved service action out
    x(bytes([0x9f, 0x11]) + u64(0x2000) + b'\x00\x00' + u16(0x208) + bytes([0, 0]), 0, dout=rnd(0x208))
    x(bytes([0x9f, 0x0f]) + u64(0) + b'\x00\x00' + u16(0) + bytes([0, 0]), 0)

    mark('unmap')
    # UNMAP: header and block descriptors
    bd = b''.join(u64(lba) + u32(n) + b'\x00' * 4 for lba, n in ((0, 1), (100, 16), (4096, 1024)))
    pl = u16(6 + len(bd)) + u16(len(bd)) + b'\x00' * 4 + bd
    x(bytes([0x42, 0x01, 0, 0, 0, 0, 0]) + u16(len(pl)) + b'\x00', 0, dout=pl)
    # SANITIZE: overwrite parameter list
    pl = bytes([0x81]) + b'\x00' + u16(4) + b'\xa5\x5a\xa5\x5a'
    x(bytes([0x48, 0x01, 0, 0, 0, 0, 0]) + u16(len(pl)) + b'\x00', 0, dout=pl)
    for sa in (1, 2, 3, 0x1f):
        x(bytes([0x48, 0x80 | sa, 0, 0, 0, 0, 0, 0, 0, 0]), 0)

    mark('writesame')
    # WRITE SAME with a block of data
    x(bytes([0x41, 0x08]) + u32(0x1000) + bytes([0]) + u16(64) + b'\x00', 0, dout=rnd(512))
    x(bytes([0x93, 0x08]) + u64(0x1000) + u32(64) + bytes([0, 0]), 0, dout=rnd(512))

    mark('defect')
    # defect data and reassign blocks
    x(bytes([0x37, 0x1d, 0, 0, 0, 0, 0, 0x01, 0x00, 0]), 0, din=bytes([0, 0x1d, 0, 8]) + rnd(8))
    x(bytes([0xb7, 0x1d, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0]), 0, din=bytes([0, 0x1d, 0, 0, 0, 0, 0, 8]) + rnd(8))
    x(bytes([0x07, 0x03, 0, 0, 0, 0]), 0, dout=bytes([0, 0, 0, 4]) + u32(0x1234))
    x(bytes([0x07, 0x00, 0, 0, 0, 0]), 0, dout=bytes([0, 0, 0, 4]) + u32(0x1234))
    mark('check')
    # a check condition for a read and a write
    x(bytes([0x28, 0, 0, 0, 0x10, 0, 0, 0, 1, 0]), 0, status=2, sense=fixed_sense(3, 0x11, 0x00, info=0x1000))
    x(bytes([0x2a, 0, 0, 0, 0x10, 0, 0, 0, 1, 0]), 0, status=2, sense=fixed_sense(7, 0x27, 0x00))
    mark('end')
    p.close()


def malformed_cap(path):
    p = Pcap(path)
    x = p.xchg
    p.inquiry(0, 0x00)
    x(bytes([0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 0, din=u32(1))               # short response
    x(bytes([0x9e, 0x10]) + b'\x00' * 8 + u32(32) + bytes([0, 0]), 0, din=rnd(12))
    x(bytes([0x42, 0x01, 0, 0, 0, 0, 0, 0, 20, 0]), 0, dout=u16(200) + u16(200) + b'\x00' * 4 + rnd(10))
    p.close()


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
