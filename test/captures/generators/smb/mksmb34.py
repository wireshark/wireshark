#!/usr/bin/env python3
# Generates test/captures/smb_coverage.pcap.gz, smb_fixes_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic SMB1 captures for the fixes of batch 34 in packet-smb.c
# ("SMB: Bound export object memory for sparse files").
# Usage: mksmb34.py <outdir>  -> smb_fixes_coverage.pcap (main capture) and
# smb_fixes_coverage-malformed.pcap (paths that need damaged packets).
# Uses the helpers of mksmb.py (same directory).  Everything is built with
# struct, documentation addresses only; no keys, passwords or ciphertext.
import os
import sys
from mksmb import (  # noqa: Cap, Conn, conn_setup, nt_req, nt_resp, secdesc, ...
    Cap, Conn, conn_setup, EALIST, NT, nt_req, nt_resp, secdesc, U16, U32, U64, U8, ustr,
)


def create(c, name, fid, eof=0, isdir=0):
    """NT Create AndX request and response: makes the FID a file (or a directory)."""
    c.nextmid()
    w = U8(0xff, 0) + U16(0) + U8(0) + U16(len(name) + 1) + U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40, 2) + U8(0)
    c.send(True, c.smb(0xa2, False, w, [name]))
    w = U8(0xff, 0) + U16(0) + U8(1) + U16(fid) + U32(1) + U64(NT, NT, NT, NT) + U32(0x10 if isdir else 0x80) + U64(4096, eof) + U16(0, 0) + U8(isdir)
    c.send(False, c.smb(0xa2, True, w, b''))


def wx(c, fid, off, data, tid=None):
    """Write AndX (word count 14, 64 bit offset) with its response."""
    c.nextmid()
    kw = {} if tid is None else {'tid': tid}
    w = U8(0xff, 0) + U16(0) + U16(fid) + U32(off & 0xffffffff, 0) + U16(0, 0, 0, len(data), 64) + U32(off >> 32)
    c.send(True, c.smb(0x2f, False, w, b'\0' + data, **kw))
    c.send(False, c.smb(0x2f, True, U8(0xff, 0) + U16(0, len(data) & 0xffff, 0, 0, 0), b'', **kw))


def rx(c, fid, off, data):
    """Read AndX request and response (the response chunk is exported too)."""
    c.nextmid()
    w = U8(0xff, 0) + U16(0) + U16(fid) + U32(off & 0xffffffff) + U16(len(data), len(data)) + U32(0) + U16(0) + U32(off >> 32)
    c.send(True, c.smb(0x2e, False, w, b'', ))
    w = U8(0xff, 0) + U16(0) + U16(0, 0, 0, len(data), 32 + 1 + 24 + 2 + 1) + U32(0) + bytes(6)
    c.send(False, c.smb(0x2e, True, w, b'\0' + data))


def sparse_files(c):
    """Export Objects: chunks far beyond the data gathered (SMB_EO_MAX_GAP)."""
    # the reproducer: a 1 byte write at 0, then 16 bytes at 0xFFFFFF00 of the
    # same FID (the realloc branch); later chunks of the dropped file
    for i, big in enumerate((0xFFFFFF00, 0x10000000, 0x04000002)):
        f = 0x7500 + i
        create(c, r'\sparse\gap%d.bin' % i, f)
        wx(c, f, 0, b'A')
        wx(c, f, big, b'B' * 16)
        wx(c, f, 1, b'C' * 3)         # dropped: the file is out of memory
        rx(c, f, 4, b'D' * 4)
    # the new-file branch: the very first chunk is beyond the limit
    f = 0x7510
    create(c, r'\sparse\first.bin', f)
    wx(c, f, 0x10000000, b'E' * 8)
    wx(c, f, 0, b'F' * 8)
    # first chunk read, far away
    f = 0x7511
    create(c, r'\sparse\readfar.bin', f)
    rx(c, f, 0x20000000, b'G' * 8)
    # a write at the 4 GiB limit of an existing file, and the next chunk
    f = 0x7512
    create(c, r'\sparse\fourgig.bin', f)
    wx(c, f, 0, b'H' * 4)
    wx(c, f, 0xFFFFFFF0, b'I' * 32)
    wx(c, f, 4, b'J' * 4)
    # a file that stays within the limit: a gap below the limit (zero filled)
    f = 0x7513
    create(c, r'\sparse\small.bin', f)
    wx(c, f, 0, b'K' * 4)
    wx(c, f, 4096, b'L' * 4)
    wx(c, f, 100000, b'M' * 4)
    # several files like the reproducer in the review (3 FIDs, 12 packets)
    for i in range(3):
        f = 0x7520 + i
        create(c, r'\sparse\many%d.bin' % i, f)
        wx(c, f, 0, b'N')
        wx(c, f, 0xFFFFFF00, b'O' * 16)


def pipe_dataoffset(c):
    """Write AndX with MESSAGE_START|RAW: dataoffset += 2 must not wrap."""
    for i, doff in enumerate((59, 0xFFFD, 0xFFFE, 0xFFFF, 0)):
        c.nextmid()
        w = U8(0xff, 0) + U16(0) + U16(0x7600 + i) + U32(0, 0) + U16(0x000c, 0, 0, 8, doff)
        c.send(True, c.smb(0x2f, False, w, U16(6) + b'abcdef', tid=9))
        c.send(False, c.smb(0x2f, True, U8(0xff, 0) + U16(0, 6, 0, 0, 0), b'', tid=9))
    # the same with word count 14 (high offset)
    for doff in (0xFFFF, 0xFFFD):
        c.nextmid()
        w = U8(0xff, 0) + U16(0) + U16(0x7610) + U32(0, 0) + U16(0x000c, 0, 0, 8, doff) + U32(0)
        c.send(True, c.smb(0x2f, False, w, U16(6) + b'abcdef', tid=9))
        c.send(False, c.smb(0x2f, True, U8(0xff, 0) + U16(0, 6, 0, 0, 0), b'', tid=9))


def nt_create_ea(c):
    """NT Transact CREATE with extended attribute lengths: exact, too long, -1, none left."""
    sd = secdesc()
    name = ustr(c, r'\dir\ea.txt')
    cases = [
        ('exact', EALIST, len(EALIST)),
        ('short', EALIST, 4),
        ('toolong', EALIST, len(EALIST) + 1),
        ('minus1', EALIST, 0xFFFFFFFF),
        ('big', EALIST, 0x80000000),
        ('nodata', b'', 0xFFFFFFFF),     # nothing left after the security descriptor
        ('zero', EALIST, 0),
    ]
    for label, ea, ealen in cases:
        for sdx in (sd, b''):
            if label == 'nodata' and not sdx:
                continue
            params = U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40) + U32(len(sdx), ealen, len(name), 2) + U8(0) + name
            c.nextmid()
            c.send(True, nt_req(c, 1, U16(0), params, sdx + ea))
            fid = 0x7700 + c.mid
            rp = U8(1, 0) + U16(fid) + U32(1, 0) + U64(NT, NT, NT, NT) + U32(0x80) + U64(4096, 100) + U16(0, 0) + U8(0)
            c.send(False, nt_resp(c, 1, U16(0), rp, b''))


def sc_main(outdir):
    cap = Cap(os.path.join(outdir, 'smb_fixes_coverage.pcap'))
    c = Conn(cap, 41001)
    conn_setup(c, r'\\SRV\SHARE')
    sparse_files(c)
    pipe_dataoffset(c)
    nt_create_ea(c)
    cap.close()


def sc_malformed(outdir):
    cap = Cap(os.path.join(outdir, 'smb_fixes_coverage-malformed.pcap'))
    c = Conn(cap, 41002)
    conn_setup(c, r'\\SRV\SHARE')
    # NT Transact CREATE whose declared EA list is longer than the data and cut off by the packet
    sd = secdesc()
    name = ustr(c, r'\dir\ea2.txt')
    params = U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40) + U32(len(sd), 0xFFFFFFFF, len(name), 2) + U8(0) + name
    c.nextmid()
    c.send(True, nt_req(c, 1, U16(0), params, sd[:20], tdc=len(sd) + 64))
    c.nextmid()
    c.send(True, nt_req(c, 1, U16(0), params, b'', tdc=0xFFFF))
    # pipe write with the data offset beyond the packet
    for doff in (0xFFFF, 0xFFFE):
        c.nextmid()
        w = U8(0xff, 0) + U16(0) + U16(0x7620) + U32(0, 0) + U16(0x000c, 0, 0, 8, doff)
        c.send(True, c.smb(0x2f, False, w, U16(6) + b'abcdef', tid=9))
    # file write with the data offset beyond the packet (export objects)
    create(c, r'\sparse\bad.bin', 0x7630)
    for doff in (0xFFFF, 2000):
        c.nextmid()
        w = U8(0xff, 0) + U16(0) + U16(0x7630) + U32(0, 0) + U16(0, 0, 0, 4, doff) + U32(0)
        c.send(True, c.smb(0x2f, False, w, b'\0' + b'abcd'))
    cap.close()


if __name__ == '__main__':
    sc_main(sys.argv[1])
    sc_malformed(sys.argv[1])
