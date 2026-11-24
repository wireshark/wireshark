#!/usr/bin/env python3
# Generates test/captures/file_pcapng_darwin_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic pcapng files with Darwin process information blocks.

usage: mkfile-pcapng-darwin.py <outdir>
file-pcapng-darwin-coverage.pcapng: a little endian and a big endian
section, each with Darwin Process Information Blocks (the local block
0x80000001 that file-pcapng-darwin.c registers; the integers are little
endian in both byte orders) and packets with Darwin options. Read with
-X read_format:"MIME Files Format". The coverage of file-pcapng.c is
measured together (see ../file-pcapng-coverage).
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def blk(e, t, body):
    body += b'\0' * ((-len(body)) % 4)
    return struct.pack(e + 'II', t, 12 + len(body)) + body + struct.pack(e + 'I', 12 + len(body))


def opt(e, c, v=b''):
    return struct.pack(e + 'HH', c, len(v)) + v + b'\0' * ((-len(v)) % 4)


def section(e):
    d = blk(e, 0x0A0D0D0A, struct.pack(e + 'IHHq', 0x1A2B3C4D, 1, 0, -1))
    d += blk(e, 1, struct.pack(e + 'HHI', 1, 0, 0) + opt(e, 0))
    d += blk(e, 0x80000001, struct.pack('<I', 501) + opt(e, 1, b'comment') + opt(e, 2, b'mDNSResponder') +
             opt(e, 4, bytes(range(16))) + opt(e, 0xf00, b'??') + opt(e, 0))
    d += blk(e, 0x80000001, struct.pack('<I', 1) + opt(e, 2, b'launchd') + opt(e, 4, bytes(range(16, 32))) + opt(e, 0))
    d += blk(e, 0x80000001, struct.pack('<I', 7))
    frame = bytes(12) + b'\x08\x00' + bytes(20)
    for dpib, edpib in ((0, 1), (1, 1)):
        d += blk(e, 6, struct.pack(e + 'IIIII', 0, 0, 5, len(frame), len(frame)) + frame + b'\0\0' +
                 opt(e, 32769, struct.pack('<I', dpib)) + opt(e, 32771, struct.pack('<I', edpib)) +
                 opt(e, 32770, struct.pack('<I', 300)) + opt(e, 32772, struct.pack('<I', 0x3f)) +
                 opt(e, 32773, struct.pack('<I', 99)) + opt(e, 0))
    return d


def main():
    open(os.path.join(OUT, 'file-pcapng-darwin-coverage.pcapng'), 'wb').write(section('<') + section('>'))
    # a block with a short UUID option: expert info (malformed GUID length)
    d = blk('<', 0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    d += blk('<', 0x80000001, struct.pack('<I', 3) + opt('<', 4, b'\1' * 5) + opt('<', 2, b'') + opt('<', 0))
    open(os.path.join(OUT, 'file-pcapng-darwin-coverage-malformed.pcapng'), 'wb').write(d)


main()
