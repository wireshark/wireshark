#!/usr/bin/env python3
# Generates test/captures/scsi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic iSCSI/SCSI captures for packet-scsi.c (the SPC code).

usage: mkscsi.py <outdir>

Writes scsi-coverage.pcap (clean) and scsi-coverage-malformed.pcap.
Every SCSI exchange runs over iSCSI (TCP port 3260), the way a real capture
reaches the SCSI dissector.  LUN 0 is a disk (SBC), 1 a tape (SSC), 2 a
CD/DVD drive (MMC), 3 a medium changer (SMC), 4 a processor device (no
command set of its own), 5 an unannounced LUN (default command set).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct

from scsilib import Pcap, fixed_sense, desc_sense  # noqa: E402

R = random.Random(34)


def rnd(n):
    return bytes(R.randrange(256) for _ in range(n))


def u16(v): return struct.pack('>H', v)
def u32(v): return struct.pack('>I', v)
def u64(v): return struct.pack('>Q', v)


def cdb6(op, b1=0, b2=0, b3=0, b4=0, ctl=0):
    return bytes([op, b1, b2, b3, b4, ctl])


def cdb10(op, b1=0, b2=0, lba=0, b6=0, ln=0, ctl=0):
    """10 byte CDB: opcode, byte 1, byte 2, bytes 3..6 (lba), byte 6 group, 7..8 length, control"""
    return bytes([op, b1]) + u32(lba) + bytes([b6]) + u16(ln) + bytes([ctl])


def inquiry_data(devtype, version, flags=(0, 0, 0), vendor=b'WSTEST  ',
                 product=b'SYNTHETIC DEVICE', rev=b'0001', rmb=0, qual=0, aca=0):
    d = bytes([(qual << 5) | devtype, rmb << 7, version, aca, 91, flags[0], flags[1], flags[2]])
    d += vendor + product + rev + rnd(20) + b'\x00\x00'
    for i in range(8):
        d += u16(0x0300 + 0x20 * i)
    return d


def tape_alert_page(params):
    body = b''
    for n, flag in params:
        body += u16(n) + bytes([0x43, 1, flag])
    return bytes([0x2e, 0]) + u16(len(body)) + body


def log_page(code, params):
    body = b''
    for n, data in params:
        body += u16(n) + bytes([0x63, len(data)]) + data
    return bytes([code, 0]) + u16(len(body)) + body


def mode_page(code, length, spf=0, sub=0, ps=0, fill=None):
    """Mode page with a page length of `length` bytes after the header."""
    body = fill if fill is not None else rnd(length)
    body = (body + rnd(length))[:length]
    if spf:
        return bytes([(ps << 7) | 0x40 | code, sub]) + u16(length) + body
    return bytes([(ps << 7) | code, length]) + body


def align_pages(pages, hdr):
    """iSCSI pads the data segment to 4 bytes and the MODE SELECT decoder would show the
    padding as one more page: lengthen the last mode page so that the list needs no pad."""
    if not isinstance(pages, (list, tuple)):
        return pages
    pages = list(pages)
    body = b''.join(pages)
    if (hdr + len(body)) % 4 and pages:
        last = pages[-1]
        pad = 4 - (hdr + len(body)) % 4
        if last[0] & 0x40:
            last = last[:2] + u16(struct.unpack('>H', last[2:4])[0] + pad) + last[4:] + b'\x00' * pad
        else:
            last = last[:1] + bytes([last[1] + pad]) + last[2:] + b'\x00' * pad
        pages[-1] = last
    return b''.join(pages)


def mode_hdr6(pages, blockdescs=b'', medium=0, devspec=0):
    pages = align_pages(pages, 4 + len(blockdescs))
    body = bytes([medium, devspec, len(blockdescs)]) + blockdescs + pages
    return bytes([len(body)]) + body


def mode_hdr10(pages, blockdescs=b'', medium=0, devspec=0, longlba=0):
    pages = align_pages(pages, 8 + len(blockdescs))
    body = bytes([medium, devspec, longlba, 0]) + u16(len(blockdescs)) + blockdescs + pages
    return u16(len(body)) + body


def lun_bytes(*units):
    """Hierarchical LUN field from 2-, 4-, 6- or 8-byte units."""
    b = b''.join(units)
    return (b + b'\x00' * 8)[:8]


def main(out):
    os.makedirs(out, exist_ok=True)
    main_cap(os.path.join(out, 'scsi-coverage.pcap'))
    malformed_cap(os.path.join(out, 'scsi-coverage-malformed.pcap'))


def setup_luns(p):
    p.inquiry(0, 0x00)
    p.inquiry(1, 0x01, removable=True)
    p.inquiry(2, 0x05, removable=True)
    p.inquiry(3, 0x08)
    p.inquiry(4, 0x03)


def main_cap(path):
    p = Pcap(path)
    x = p.xchg
    mark = p.mark
    setup_luns(p)

    mark('std inquiry')
    # ---- standard INQUIRY, every version and flag byte layout --------
    for lun, ver in ((6, 3), (6, 4), (6, 5), (6, 6), (6, 0), (6, 2)):
        x(cdb6(0x12, 0, 0, 0, 96), lun,
          din=inquiry_data(0x00, ver, flags=(R.randrange(256), R.randrange(256), R.randrange(256)),
                           aca=R.randrange(256), rmb=ver & 1, qual=ver & 1))
    # allocation length shorter than the data: truncated, not malformed
    x(cdb6(0x12, 0, 0, 0, 36), 6, din=inquiry_data(0x00, 5)[:36])
    x(cdb6(0x12, 0, 0, 0, 60), 1, din=inquiry_data(0x01, 6, rmb=1)[:60])
    p.inquiry(0, 0x00)

    mark('vpd')
    # ---- INQUIRY VPD pages ---------------------------------------------
    x(cdb6(0x12, 1, 0x00, 0, 255), 0, din=bytes([0, 0, 0, 8, 0, 0x80, 0x83, 0xb0, 0xb1, 0xb2, 0x81, 0x82]))
    x(cdb6(0x12, 1, 0x80, 0, 255), 0, din=bytes([0, 0x80, 0, 12]) + b'SN0123456789')
    x(cdb6(0x12, 1, 0x83, 0, 255), 0, din=devid_page())
    x(cdb6(0x12, 1, 0xb0, 0, 255), 0, din=bytes([0, 0xb0, 0, 0x3c]) + rnd(0x3c))
    x(cdb6(0x12, 1, 0xb1, 0, 255), 0, din=bytes([0, 0xb1, 0, 0x3c]) + rnd(0x3c))
    x(cdb6(0x12, 1, 0xb2, 0, 255), 0, din=bytes([0, 0xb2, 0, 4]) + bytes([0x10, 0xe7, 0x02, 0x00]))
    x(cdb6(0x12, 1, 0x81, 0, 255), 0, din=bytes([0, 0x81, 0, 4]) + rnd(4))        # no dissector: header only
    x(cdb6(0x12, 2, 0x28, 0, 255), 0, din=bytes([0, 3, 4, 0, 0, 10]) + rnd(10))   # CMDDT
    p.inquiry(0, 0x00)

    mark('sense')
    # ---- TEST UNIT READY, REQUEST SENSE, sense data -------------------
    x(cdb6(0x00), 0)
    x(cdb6(0x00), 1, status=2, sense=fixed_sense(2, 0x3a, 0x00, info=None))
    x(cdb6(0x03, 0, 0, 0, 252), 0, din=fixed_sense(0, 0, 0))
    x(cdb6(0x03, 0, 0, 0, 252), 0, din=fixed_sense(5, 0x24, 0x00, info=0x12345678, cmd_info=0x55,
                                                   fru=3, sks=(0x08 | 2, 0x00, 0x05)))
    x(cdb6(0x03, 0, 0, 0, 252), 1, din=bytes([0x71]) + fixed_sense(1, 0x00, 0x04)[1:])
    x(cdb6(0x00), 0, status=2, sense=fixed_sense(5, 0x24, 0x00, info=7, sks=(0x04 | 0x08, 0x00, 0x03)))
    x(cdb6(0x00), 0, status=2, sense=fixed_sense(3, 0x11, 0x00, info=0x100, sks=(0, 0x12, 0x34)))
    x(cdb6(0x00), 2, status=2, sense=fixed_sense(6, 0x28, 0x00))
    # descriptor format sense: sense key specific (2), OSD object id (6), OSD attributes (8), others
    d2 = bytes([0x02, 6, 0, 0, 0x80, 0x12, 0x34, 0])
    d6 = bytes([0x06, 0x1e, 0, 0, 0, 0, 0, 0]) + u32(0x8e44c182) + u32(0xc5420081) + u64(0x10000) + u64(0x20001)
    d8 = bytes([0x08, 18, 0, 0]) + u32(0x1) + u32(0x82) + u32(0x30000000) + u32(0x1)
    d0 = bytes([0x00, 6, 0, 0, 0, 0, 0x01, 0x00])
    dx = bytes([0x01, 2, 0, 0])
    x(cdb6(0x00), 0, status=2, sense=desc_sense(5, 0x24, 0x00, d2 + d6 + d8 + d0 + dx))
    x(cdb6(0x03, 0, 0, 0, 252), 0, din=desc_sense(0x0b, 0x00, 0x00, d2 + d8))
    x(cdb6(0x00), 3, status=2, sense=bytes([0x73, 3, 0x04, 0x01, 0, 0, 0, 0]))
    x(cdb6(0x00), 3, status=2, sense=bytes([0x7f]) + b'\x00' * 17)          # unknown response code
    # a long sense buffer (descriptor ends past 255 bytes)
    filler = bytes([0x80, 228]) + b'\x00' * 228
    x(cdb6(0x00), 0, status=2,
      sense=desc_sense(0x05, 0x24, 0x00, filler + bytes([0x08, 18, 0, 0]) + u32(0x1) + u32(0x82) + u32(0x1) + u32(0x83)))

    mark('mode')
    mode_cap(p)
    mark('log')

    # ---- LOG SELECT / LOG SENSE -------------------------------------------
    x(bytes([0x4c, 0x02, 0x6e, 0, 0, 0, 0, 0, 0, 0]), 1)
    x(bytes([0x4c, 0x01, 0x6e, 0, 0, 0, 0, 0, 0x14, 0]), 1, dout=tape_alert_page([(1, 1), (2, 0)]))
    x(bytes([0x4d, 0x02, 0x6e, 0, 0, 0, 0, 0x01, 0x00, 0]), 1,
      din=tape_alert_page([(n, n & 1) for n in list(range(1, 0x28)) + list(range(0x32, 0x3d)) + [0x77]]))
    x(bytes([0x4d, 0x00, 0x03, 0, 0, 0, 0, 0x01, 0x00, 0]), 0, din=log_page(0x03, [(0, b'\x01\x02'), (1, b'')]))
    x(bytes([0x4d, 0x00, 0x00, 0, 0, 0, 0, 0x01, 0x00, 0]), 0, din=bytes([0, 0, 0, 4, 0, 0, 0x40, 0]))

    mark('reserve')
    # ---- RESERVE / RELEASE -------------------------------------------------
    x(cdb6(0x16), 0)
    x(cdb6(0x17), 0)
    x(cdb10(0x56, 0x10, 0x12, 0, 0, 0), 0)
    x(cdb10(0x56, 0x03, 0, 0, 0, 16), 0, dout=rnd(16))
    x(cdb10(0x57, 0x10, 0x34, 0, 0, 0), 0)
    x(cdb10(0x57, 0x02, 0, 0, 0, 0), 0)

    mark('pr')
    # ---- PERSISTENT RESERVE IN / OUT ---------------------------------------
    keys = u64(0x1111111111111111) + u64(0x2222222222222222)
    for sa in (0, 1, 2, 3):
        c = bytes([0x5e, sa, 0, 0, 0, 0, 0, 0x01, 0x00, 0])
        if sa == 0:
            d = u32(5) + u32(len(keys)) + keys
        elif sa == 1:
            d = u32(5) + u32(16) + u64(0x1111111111111111) + u32(0x1000) + b'\x00' + bytes([0x16]) + b'\x00\x00'
        elif sa == 3:
            d = u32(5) + u32(0)
        else:
            d = u32(5) + u32(8) + rnd(8)
        x(c, 0, din=d)
    x(bytes([0x5e, 0, 0, 0, 0, 0, 0, 0x00, 0x08, 0]), 0, din=u32(6) + u32(0))   # empty list
    for sa in (0, 1, 2, 3, 4, 5, 6, 8):
        sc = 0x10 | (sa & 7)
        # CDB: opcode, service action, scope/type, 2 reserved, 4 byte parameter list length at 5..8
        d = u64(0xaaaa0000aaaa0000) + u64(0xbbbb0000bbbb0000) + b'\x00' * 4 + bytes([R.randrange(256) & 0x0b]) + b'\x00' * 3
        x(bytes([0x5f, sa, sc, 0, 0]) + u32(len(d)) + b'\x00', 0, dout=d)
    # REGISTER AND MOVE with a transport id
    tid = bytes([0x05, 0, 0, 0]) + b'\x00' * 16
    pr = u64(0x1) + u64(0x2) + bytes([0, 0x02, 0, 7]) + u32(len(tid)) + tid
    x(bytes([0x5f, 0x07, 0x10, 0, 0]) + u32(len(pr)) + b'\x00', 0, dout=pr)

    mark('reportluns')
    # ---- REPORT LUNS ----------------------------------------------------------
    lunlist = [
        lun_bytes(b'\x00\x00'),                                  # simple, LUN 0
        lun_bytes(b'\x00\x05'),                                  # simple, LUN 5
        lun_bytes(b'\x41\x02'),                                  # flat space
        lun_bytes(b'\x81\x07'),                                  # logical unit addressing
        lun_bytes(b'\x01\x02', b'\x42\x03'),                     # peripheral with bus, then flat
        lun_bytes(b'\xc1\x7f'),                                  # well known logical unit
        lun_bytes(b'\xd2\x01\x02\x03\x04\x05\x06\x07'),          # extended flat space
        lun_bytes(b'\xe2\x01\x02\x03\x04\x05\x06\x07'),          # long extended flat space
        lun_bytes(b'\xfe\x01\x02\x03\x04\x05\x06\x07'),          # reserved for FC-SB-5
        lun_bytes(b'\xff\xff\xff\xff\xff\xff\xff\xff'),          # logical unit not specified
        lun_bytes(b'\xc5\x01\x02\x03\x04\x05\x06\x07'),          # reserved extended method
        lun_bytes(b'\x01\x02', b'\x01\x04', b'\x01\x06', b'\x01\x07'),
        lun_bytes(b'\xcf\x00'),                                  # extended method 15 with a short length
    ]
    luns = b''.join(lunlist)
    x(bytes([0xa0, 0, 0, 0, 0, 0]) + u32(256) + bytes([0, 0]), 0, din=u32(len(luns)) + u32(0) + luns)
    x(bytes([0xa0, 1, 0, 0, 0, 0]) + u32(24) + bytes([0, 0]), 0, din=(u32(len(luns)) + u32(0) + luns)[:24])
    x(bytes([0xa0, 2, 0, 0, 0, 0]) + u32(256) + bytes([0, 0]), 0, din=u32(8) + u32(0) + lun_bytes(b'\x00\x00'))

    # ---- MANAGEMENT PROTOCOL IN (report supported opcodes) ------------------
    all_cmds = b''
    for op, ctdp in ((0x12, 0), (0x28, 1), (0x2a, 0), (0xa0, 1)):
        all_cmds += bytes([op, 0]) + u16(0) + bytes([0, 0x02 if ctdp else 0]) + u16(10)
        if ctdp:
            all_cmds += u16(10) + b'\x00\x00' + u32(30) + u32(60)
    rso = lambda options, alloc=512: bytes([0xa3, 0x0c, options, 0x28, 0, 0]) + u32(alloc) + bytes([0, 0])  # noqa: E731
    for lun in (0, 1, 2, 3):
        x(rso(0), lun, din=u32(len(all_cmds)) + all_cmds)
    one = bytes([0x80, 0x03]) + u16(10) + bytes([0x28, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07]) \
        + u16(0x0a) + u16(0) + u32(30) + u32(60)
    x(rso(1), 0, din=one[:2] + u16(10) + one[4:14] + u16(10) + u16(0) + u32(30) + u32(60))
    one = bytes([0x00, 0x03]) + u16(10) + bytes([0x28, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0, 0])
    x(rso(2), 0, din=one)
    x(rso(0x80 | 2), 0, din=bytes([0x80, 0x83]) + u16(10) + one[4:14] + u16(10) + u16(0) + u32(30) + u32(60))

    mark('xcopy')
    xcopy(p)
    mark('misc')

    # ---- SEND DIAGNOSTIC, WRITE BUFFER, PREVENT/ALLOW, VARLEN CDB, unknown -------
    x(bytes([0x1d, 0x14, 0, 0, 8, 0]), 0, dout=bytes([0x10, 0, 0, 8, 0, 0, 0, 0]))
    x(bytes([0x1d, 0x04, 0, 0, 0, 0]), 0)
    x(bytes([0x3b, 0x02, 0x00, 0, 0, 0, 0, 0, 0x20, 0]), 0, dout=rnd(32))
    x(bytes([0x3b, 0x0e, 0x01, 0, 0x10, 0, 0, 0, 0x00, 0]), 0)
    x(bytes([0x1e, 0, 0, 0, 1, 0]), 2)
    x(bytes([0x1e, 0, 0, 0, 0, 0]), 2)
    for lun in (0, 1, 3):
        x(bytes([0x1e, 0, 0, 0, 1, 0]), lun)
        x(bytes([0x1e, 0, 0, 0, 0, 0]), lun)
    # SEND DIAGNOSTIC and WRITE BUFFER payloads coming from the target
    x(bytes([0x1d, 0x14, 0, 0, 8, 0]), 0, din=bytes([0x10, 0, 0, 8, 0, 0, 0, 0]))
    x(bytes([0x3b, 0x02, 0, 0, 0, 0, 0, 0, 0x10, 0]), 0, din=rnd(16))
    # REPORT DEVICE IDENTIFIER (opcode 0xA3 of the command set-less processor device)
    x(bytes([0xa3, 0x05, 0, 0, 0, 0]) + u32(16) + bytes([0, 0]), 4, din=rnd(16))
    x(bytes([0xd5, 0, 0, 0, 16, 0]), 5, din=rnd(16))        # vendor opcode with data
    x(bytes([0x7f, 0x00, 0, 0, 0, 0, 24, 0x00, 0x09, 0x0b]) + rnd(14), 0)       # 24 byte CDB via AHS
    x(bytes([0xd5, 0, 0, 0, 0, 0]), 5)         # vendor specific opcode, no dissector
    x(bytes([0x00, 0, 0, 0, 0, 0]), 5)         # default command set
    x(bytes([0x12, 0, 0, 0, 36, 0]), 5, din=inquiry_data(0x00, 5)[:36])

    mark('multi')
    # ---- multi-PDU read (reassembly), R2T driven write ------------------------------
    page = mode_hdr10(mode_page(0x08, 0x12) + mode_page(0x0a, 0x0a))
    x(bytes([0x5a, 0x00, 0x3f, 0, 0, 0, 0, 0x02, 0x00, 0]), 0, din=page, split=16)
    # bidirectional command: immediate data out, expected read length in an AHS
    itt = p.command(bytes([0x1d, 0x10, 0, 0, 8, 0]), 0, edtl=8, read=True, write=True,
                    data=bytes([0x10, 0, 0, 8, 0, 0, 0, 0]), bidir=16)
    p.data_in(itt, rnd(16), status=0, lun=0)
    # truncated capture (snaplen): the PDU is cut short
    itt = p.command(bytes([0x5a, 0x00, 0x3f, 0, 0, 0, 0, 0x01, 0xfc, 0]), 0, edtl=252)
    p.data_in(itt, mode_hdr10(mode_page(0x08, 0x12) + mode_page(0x0a, 0x0a)), status=0, snap=124)
    # MODE SELECT(10) data in three Data-Out PDUs, then a single Data-Out
    ms = mode_hdr10(mode_page(0x08, 0x12) + mode_page(0x0a, 0x0a) + mode_page(0x1c, 0x0a), u32(0x1000) + b'\x00' + b'\x00\x02\x00')
    p.write_pieces(bytes([0x55, 0x11, 0, 0, 0, 0, 0]) + u16(len(ms)) + b'\x00', 0, ms, 16)
    itt = p.command(bytes([0x3b, 0x02, 0, 0, 0, 0, 0, 0, 0x20, 0]), 0, edtl=32, read=False, write=True)
    p.r2t(itt, 0, 32)
    p.data_out(itt, rnd(32), 0, 0, 0)
    p.response(itt, 0)
    mark('end')
    p.close()


def devid_page():
    d = b''
    d += bytes([0x02, 0x01, 0, 12]) + b'WSTEST  SN01'          # ASCII vendor specific, >= 8 bytes
    d += bytes([0x02, 0x01, 0, 4]) + b'ABCD'                   # ASCII, shorter than a vendor id
    d += bytes([0x02, 0x00, 0, 6]) + b'T10XYZ'
    for naa in (0x2, 0x3, 0x5, 0x6, 0x1):
        ln = 16 if naa == 6 else 8
        d += bytes([0x01, 0x03, 0, ln]) + bytes([naa << 4 | 0x1]) + rnd(ln - 1)
    d += bytes([0x01, 0x02, 0, 8]) + rnd(8)                    # EUI-64, binary non-NAA
    d += bytes([0x01, 0x08, 0, 0])                             # zero length
    d += bytes([0x03, 0x08, 0, 4]) + b'\xe2\x80\x9d!'          # UTF-8
    return bytes([0, 0x83]) + u16(len(d)) + d


def pages_one():
    return mode_page(0x0a, 0x0a)


def mode_cap(p, bad=False):
    """MODE SENSE and MODE SELECT with every mode page the dissector knows (bad=False)
    or with the pages it has no decoding for (bad=True, malformed capture)."""
    x = p.xchg
    if not bad:
        gen = (mode_page(0x0a, 0x0a), mode_page(0x0a, 0x1c, spf=1, sub=1), mode_page(0x02, 0x0e),
               mode_page(0x1c, 0x0a), mode_page(0x1a, 0x0a),
               mode_page(0x19, 6, fill=bytes([0x00, 0x1f, 0, 0, 0, 0x07]) + b'\x00' * 2),
               mode_page(0x1c, 0x0a, fill=bytes([0x10, 0x0c]) + rnd(8)),
               mode_page(0x1c, 0x0a, fill=bytes([0x08, 0x03]) + rnd(8)),
               mode_page(0x19, 6, fill=bytes([0x00, 0xff, 0, 0, 0, 0, 0, 0])))
        sbc = (mode_page(0x03, 0x16), mode_page(0x04, 0x16), mode_page(0x01, 0x0a), mode_page(0x08, 0x12))
        ssc = (mode_page(0x0f, 0x0e), mode_page(0x10, 0x0e), mode_page(0x11, 0x08))
        mmc = (mode_page(0x03, 6), mode_page(0x05, 0x36), mode_page(0x2a, 0x1e),
               mode_page(0x05, 0x32))
        smc = (mode_page(0x1d, 0x12, fill=u16(1) + u16(1) + u16(0x10) + u16(10) + u16(0x20) + u16(2) + u16(0x30) + u16(4) + b'\x00' * 2),
               mode_page(0x1d, 4, fill=u16(1) + u16(2)),
               mode_page(0x1d, 3, fill=b'\x00\x01\x02'),
               mode_page(0x1d, 0, fill=b''),
               mode_page(0x1f, 0x12), mode_page(0x1d, 6, fill=u16(1) + u16(1) + u16(2)))
    else:
        gen = (mode_page(0x00, 4), mode_page(0x00, 4, ps=1), mode_page(0x09, 0x0e), mode_page(0x18, 6),
               mode_page(0x19, 6, fill=bytes([0x06, 0, 0, 0, 0, 0])), mode_page(0x19, 6, fill=bytes([0x05, 0, 0, 0, 0, 0])),
               mode_page(0x0a, 0x1c, spf=1, sub=2), mode_page(0x20, 4))
        sbc = (mode_page(0x05, 0x1e), mode_page(0x07, 0x0a), mode_page(0x0b, 8), mode_page(0x0c, 0x0e),
               mode_page(0x10, 0x16))
        ssc = (mode_page(0x12, 0x08), mode_page(0x13, 0x08), mode_page(0x14, 0x08), mode_page(0x22, 4))
        mmc = (mode_page(0x01, 6), mode_page(0x07, 6))
        smc = (mode_page(0x1e, 4), mode_page(0x21, 4))
    bd32 = u32(0x100000) + b'\x00' + b'\x00\x02\x00'
    bd24 = bytes([0x30]) + b'\x00\x10\x00' + b'\x00' + b'\x00\x08\x00'
    bd64 = u64(0x1000000) + bytes([0x44]) + b'\x00' * 3 + u32(512)
    for lun, pages in ((0, gen + sbc), (1, gen + ssc), (2, gen + mmc), (3, gen + smc),
                       (4, gen), (5, gen[:3])):
        bd = bd32 if lun in (0, 5) else bd24
        for i, pg in enumerate(pages):
            x(bytes([0x1a, 0x08, 0x3f, 0, 252, 0]), lun,
              din=mode_hdr6(pg, bd if i == 0 else b'', devspec=0x10 if lun == 0 else 0))
            x(bytes([0x5a, 0x18, 0x3f, 0, 0, 0, 0, 0x01, 0xfc, 0]), lun,
              din=mode_hdr10(pg, bd64 if i == len(pages) - 1 else (bd if i == 1 else b''),
                             longlba=1 if i == len(pages) - 1 else 0))
        x(bytes([0x1a, 0x00, 0x3f, 0, 255, 0]), lun, din=mode_hdr6(pages[:5], bd))
        x(bytes([0x5a, 0x00, 0x3f, 0, 0, 0, 0, 0x01, 0xfc, 0]), lun, din=mode_hdr10(pages[:5], bd))
        d6 = mode_hdr6(pages[:4], bd)
        x(bytes([0x15, 0x11, 0, 0, len(d6), 0]), lun, dout=d6)
        d10 = mode_hdr10(pages[:4], bd, longlba=0)
        x(bytes([0x55, 0x11, 0, 0, 0, 0, 0]) + u16(len(d10)) + b'\x00', lun, dout=d10)
        d10 = mode_hdr10(pages[-3:], bd64, longlba=1)
        x(bytes([0x55, 0x10, 0, 0, 0, 0, 0]) + u16(len(d10)) + b'\x00', lun, dout=d10)
    for lun, pc in ((0, 0x08), (0, 0x48), (0, 0x88), (0, 0xc8), (1, 0x0f), (2, 0x2a), (3, 0x1d)):
        x(bytes([0x1a, 0x08, pc, 0, 252, 0]), lun, din=mode_hdr6(b''))
        x(bytes([0x5a, 0x00, pc, 0, 0, 0, 0, 0x01, 0xfc, 0]), lun, din=mode_hdr10(b''))
    if bad:
        return
    # block descriptor lengths that are not a multiple of the descriptor size
    for lun in (0, 1):
        for n in (1, 3, 5, 6, 7, 9, 12, 15, 17, 20):
            x(bytes([0x1a, 0x00, 0x3f, 0, 252, 0]), lun, din=mode_hdr6(pages_one(), rnd(n)))
            x(bytes([0x5a, 0x00, 0x3f, 0, 0, 0, 0, 0x01, 0xfc, 0]), lun, din=mode_hdr10(pages_one(), rnd(n)))
            x(bytes([0x5a, 0x10, 0x3f, 0, 0, 0, 0, 0x01, 0xfc, 0]), lun, din=mode_hdr10(pages_one(), rnd(n), longlba=1))
    # SMC element address assignment pages of every short length
    for n in range(1, 16):
        x(bytes([0x1a, 0x00, 0x1d, 0, 252, 0]), 3, din=mode_hdr6(mode_page(0x1d, n, fill=rnd(n))))
    # a mode data length that is larger than the data returned
    d = bytearray(mode_hdr6(mode_page(0x0a, 0x0a) + mode_page(0x1c, 0x0a)))
    d[0] = 200
    x(bytes([0x1a, 0x00, 0x3f, 0, 252, 0]), 0, din=bytes(d))
    # page codes on a command set without pages of its own (processor device)
    x(bytes([0x1a, 0x00, 0x08, 0, 252, 0]), 4, din=mode_hdr6(mode_page(0x0a, 0x0a)))
    x(bytes([0x5a, 0x00, 0x08, 0, 0, 0, 0, 0x01, 0xfc, 0]), 4, din=mode_hdr10(mode_page(0x0a, 0x0a)))
    # minimal parameter headers
    x(bytes([0x1a, 0x00, 0x3f, 0, 4, 0]), 0, din=bytes([3, 0, 0, 0]))
    x(bytes([0x15, 0x10, 0, 0, 1, 0]), 0, dout=bytes([0]))
    x(bytes([0x15, 0x10, 0, 0, 2, 0]), 0, dout=bytes([1, 0]))
    x(bytes([0x15, 0x10, 0, 0, 3, 0]), 0, dout=bytes([2, 0, 0]))
    x(bytes([0x15, 0x10, 0, 0, 4, 0]), 0, dout=bytes([3, 0, 0, 0]))


def xcopy(p):
    x = p.xchg
    cscd_id = bytes([0xe4, 0x00, 0, 0, 0x01, 0x03, 0, 8]) + bytes([0x31]) + rnd(7) + b'\x00' * 12 + b'\x00\x00\x02\x00'
    cscd_naa = bytes([0xe4, 0x00, 0, 0, 0x01, 0x03, 0, 8]) + bytes([0x61]) + rnd(7) + b'\x00' * 12 + b'\x00\x00\x02\x00'
    cscd_tape = bytes([0xe4, 0x01, 0, 0, 0x01, 0x03, 0, 8]) + bytes([0x61]) + rnd(7) + b'\x00' * 12 + b'\x00\x00\x00\x00'
    cscd_ea = bytes([0xea, 0x00, 0, 0, 0x01, 0x03, 0, 8]) + bytes([0x61]) + rnd(7) + b'\x00' * 12 + b'\x00\x00\x02\x00' + b'\x00' * 32
    seg_b2b = bytes([0x02, 0x00]) + u16(0x18) + u16(0) + u16(1) + b'\x00\x00' + u16(8) + u64(0x1000) + u64(0x2000)
    seg_other = bytes([0x00, 0x00]) + u16(8) + u16(0) + u16(1) + b'\x00' * 4
    for cscds, segs, inline in (((cscd_id, cscd_naa), (seg_b2b,), b'\x00' * 4),
                                ((cscd_tape, cscd_ea, cscd_id), (seg_b2b, seg_other), b''),
                                ((), (), b'')):
        cl = b''.join(cscds)
        sl = b''.join(segs)
        pl = bytes([0, 0x01]) + u16(len(cl)) + b'\x00' * 4 + u32(len(sl)) + u32(len(inline)) + cl + sl + inline
        x(bytes([0x83, 0x00]) + b'\x00' * 8 + u32(len(pl)) + bytes([0, 0]), 0, dout=pl)
    # CSCD list whose length is not a multiple of 32, a zero length segment descriptor
    pl = bytes([0, 0x01]) + u16(16) + b'\x00' * 4 + u32(0) + u32(0) + b'\x00' * 16
    x(bytes([0x83, 0x00]) + b'\x00' * 8 + u32(len(pl)) + bytes([0, 0]), 0, dout=pl)
    pl = bytes([0, 0x01]) + u16(0) + b'\x00' * 4 + u32(8) + u32(0) + bytes([2, 0]) + u16(0) + b'\x00' * 4
    x(bytes([0x83, 0x00]) + b'\x00' * 8 + u32(len(pl)) + bytes([0, 0]), 0, dout=pl)
    pl = bytes([1, 0x10]) + u16(0x20) + bytes([0xe4]) + b'\x00' * 27       # LID4
    x(bytes([0x83, 0x01]) + b'\x00' * 8 + u32(len(pl)) + bytes([0, 0]), 0, dout=pl)
    params = u32(40) + bytes([1]) + b'\x00' * 3 + u16(8) + u16(8) + u32(0x1000) + u32(0x2000) + u32(0x100) \
        + u32(0x10) + u32(0x8000) + b'\x00\x00' + u16(4) + bytes([4, 1, 1, 1]) + b'\x00' * 3 + bytes([3, 0xe0, 0xe4, 0xff])
    x(bytes([0x84, 3]) + b'\x00' * 8 + u32(len(params)) + bytes([0, 0]), 0, din=params)


def malformed_cap(path):
    p = Pcap(path)
    x = p.xchg
    setup_luns(p)
    p.data_in(0x7001, rnd(16), status=0)         # payload of an exchange that was never started
    p.response(0x7002, 0)
    # the page length is shorter than the designator it contains
    for plen, body in ((3, bytes([0x01, 0x03, 0])), (2, bytes([0x01, 0x03])), (1, bytes([0x01])),
                       (4, bytes([0x01, 0x03, 0, 0])),
                       (6, bytes([0x01, 0x03, 0, 20]) + b'ab')):
        x(cdb6(0x12, 1, 0x83, 0, 255), 0, din=bytes([0, 0x83, 0, plen]) + body + b'\x05' * 8)
    # CSCD list with a 64 byte descriptor that has only 32 bytes left in the list
    cs = bytes([0xea, 0x00, 0, 0, 0x01, 0x03, 0, 8]) + b'\x61' + rnd(7) + b'\x00' * 12 + b'\x00\x00\x02\x00'
    pl = bytes([0, 0x01]) + u16(32) + b'\x00' * 4 + u32(0) + u32(0) + cs + b'\x00' * 32
    x(bytes([0x83, 0x00]) + b'\x00' * 8 + u32(len(pl)) + bytes([0, 0]), 0, dout=pl)
    x(bytes([0x5a, 0x00, 0x3f, 0, 0, 0, 0, 0x01, 0xfc, 0]), 0, din=mode_hdr10(bytes([0x08, 0x12]) + b'\x00' * 4))
    mode_cap(p, bad=True)
    x(bytes([0xa0, 0, 0, 0, 0, 0]) + u32(16) + bytes([0, 0]), 0, din=(u32(64) + u32(0) + b'\x00' * 8)[:16])
    for sa in (0, 1, 4, 5, 6, 0x1e):
        x(bytes([0x84, sa]) + b'\x00' * 8 + u32(16) + bytes([0, 0]), 0, din=rnd(16))
    x(bytes([0xa3, 0x10, 0, 0, 0, 0]) + u32(16) + bytes([0, 0]), 0, din=rnd(16))
    x(bytes([0xa3, 0x05, 0, 0, 0, 0]) + u32(16) + bytes([0, 0]), 0, din=rnd(16))
    x(bytes([0x1d, 0x14, 0, 0, 4, 0]), 0, dout=rnd(4))          # data decoded as a CDB: too short
    x(bytes([0x3b, 0x02, 0x00, 0, 0, 0, 0, 0, 0x04, 0]), 0, dout=rnd(4))
    x(bytes([0x4d, 0x00, 0x00, 0, 0, 0, 0, 0x01, 0x00, 0]), 0, din=bytes([0, 0, 0, 3, 0, 2, 3]))
    pr = u64(0x1) + u64(0x2) + bytes([0, 0x02, 0, 7]) + u32(0x10)
    x(bytes([0x5f, 0x07, 0x10, 0, 0]) + u32(len(pr)) + b'\x00', 0, dout=pr)
    x(bytes([0xa3, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0]), 0, din=rnd(16))
    x(cdb6(0x00), 0, status=2, sense=bytes([0x72, 5, 0x24, 0, 0, 0, 0, 20, 0x08, 200, 0, 0, 0, 0, 0, 1]))
    pl = bytes([0, 0x01]) + u16(64) + b'\x00' * 4 + u32(0) + u32(0) + b'\x00' * 8
    x(bytes([0x83, 0x00]) + b'\x00' * 8 + u32(len(pl)) + bytes([0, 0]), 0, dout=pl)
    pl = bytes([0, 0x01]) + u16(0) + b'\x00' * 4 + u32(200) + u32(0) + bytes([2, 0]) + u16(1000)
    x(bytes([0x83, 0x00]) + b'\x00' * 8 + u32(len(pl)) + bytes([0, 0]), 0, dout=pl)
    x(bytes([0x5e, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0]), 0, din=u32(1) + u32(64) + b'\x00' * 8)
    x(bytes([0x4d, 0x00, 0x2e, 0, 0, 0, 0, 0x01, 0x00, 0]), 1, din=bytes([0x2e, 0]) + u16(40) + u16(1) + bytes([3, 1]))
    x(bytes([0x5f, 0x07, 0x10, 0, 0]) + u32(32) + bytes([0]), 0, dout=u64(1) + u64(2) + bytes([0, 2, 0, 7]) + u32(0xfffffff0))
    p.close()


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
