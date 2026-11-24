#!/usr/bin/env python3
# Generates test/captures/sftp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for the SFTP (packet-sftp.c) dissector.

Usage: mksftp.py <outdir>

SFTP is only called by the SSH dissector after the channel data has been
decrypted, so the captures use Exported PDU frames that name the "sftp"
dissector (one SFTP packet per frame).  Writes sftp-coverage.pcap (clean) and
sftp-coverage-malformed.pcap.  Everything is built with struct; nothing comes
from a real network.
"""
import struct
import sys
import os

P = lambda fmt, *a: struct.pack('>' + fmt, *a)


def s(b):
    b = b if isinstance(b, bytes) else b.encode()
    return P('I', len(b)) + b


def pkt(typ, body):
    return P('IB', 1 + len(body), typ) + body


def attrs(flags=0, size=1234, uid=1000, gid=100, perm=0o100644, at=1700000000, mt=1700000100, ext=0):
    out = P('I', flags)
    if flags & 0x1:
        out += P('Q', size)
    if flags & 0x2:
        out += P('II', uid, gid)
    if flags & 0x4:
        out += P('I', perm)
    if flags & 0x8:
        out += P('II', at, mt)
    if flags & 0x80000000:
        out += P('I', ext)
    return out


def exp_pdu(payload, name='sftp'):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return P('HH', 12, len(n) + pad) + n + b'\0' * pad + P('HH', 0, 0) + payload


def pcap(fname, frames):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        for i, p in enumerate(frames):
            p = exp_pdu(p)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


H = b'\x00\x00\x00\x01\x02\x03\x04\xff'      # an opaque handle


def clean():
    F = []
    F.append(pkt(1, P('I', 3)))                                                   # INIT
    F.append(pkt(2, P('I', 3)))                                                   # VERSION
    F.append(pkt(3, P('I', 1) + s('/home/user/file.txt') + P('I', 0x1a) + attrs(0)))   # OPEN, no attrs
    F.append(pkt(3, P('I', 2) + s('/tmp/new') + P('I', 0x3a) + attrs(0x1 | 0x2 | 0x4 | 0x8)))   # OPEN, all attrs
    F.append(pkt(3, P('I', 3) + s('/tmp/ext') + P('I', 0x01) + attrs(0x80000000 | 0x4, ext=2)))   # OPEN, extended count
    F.append(pkt(4, P('I', 4) + s(H)))                                            # CLOSE
    F.append(pkt(5, P('I', 5) + s(H) + P('QI', 65536, 32768)))                    # READ
    F.append(pkt(6, P('I', 6) + s(H) + P('Q', 0) + s(b'write this data')))        # WRITE
    F.append(pkt(6, P('I', 7) + s(H) + P('Q', 4096) + s(b'')))                    # WRITE, no data
    F.append(pkt(7, P('I', 8) + s('/etc/passwd')))                                # LSTAT
    F.append(pkt(8, P('I', 9) + s(H)))                                            # FSTAT
    F.append(pkt(9, P('I', 10) + s('/tmp/new') + attrs(0x4 | 0x8)))               # SETSTAT
    F.append(pkt(10, P('I', 11) + s(H) + attrs(0x4)))                             # FSETSTAT (not decoded)
    F.append(pkt(11, P('I', 12) + s('/home/user')))                               # OPENDIR
    F.append(pkt(12, P('I', 13) + s(H)))                                          # READDIR
    F.append(pkt(13, P('I', 14) + s('/tmp/old')))                                 # REMOVE
    F.append(pkt(14, P('I', 15) + s('/tmp/dir') + attrs(0)))                      # MKDIR (not decoded)
    F.append(pkt(15, P('I', 16) + s('/tmp/dir')))                                 # RMDIR (not decoded)
    F.append(pkt(16, P('I', 17) + s('.')))                                        # REALPATH
    F.append(pkt(17, P('I', 18) + s('/home/user/file.txt')))                      # STAT
    F.append(pkt(18, P('I', 19) + s('/tmp/a') + s('/tmp/b')))                     # RENAME
    F.append(pkt(19, P('I', 20) + s('/tmp/link')))                                # READLINK (not decoded)
    F.append(pkt(21, P('I', 21) + s('/tmp/l') + s('/tmp/t') + b'\x01'))           # LINK (not decoded)
    F.append(pkt(22, P('I', 22) + s(H) + P('QQI', 0, 100, 0)))                    # BLOCK (not decoded)
    F.append(pkt(23, P('I', 23) + s(H)))                                          # UNBLOCK (not decoded)
    F.append(pkt(101, P('III', 24, 0, 2) + b'OK' + P('I', 2) + b'en'))            # STATUS ok
    F.append(pkt(101, P('I', 25) + P('I', 2) + s('No such file') + s('en-US')))   # STATUS no such file
    F.append(pkt(101, P('III', 26, 4, 0) + P('I', 0)))                            # STATUS, empty strings
    F.append(pkt(102, P('I', 27) + s(H)))                                         # HANDLE
    F.append(pkt(103, P('I', 28) + s(b'file contents\n' * 4)))                    # DATA
    F.append(pkt(103, P('I', 29) + s(b'')))                                       # DATA, empty
    F.append(pkt(104, P('II', 30, 2) + s('file.txt') + s('-rw-r--r--   1 user group 1234 Nov 14 file.txt') +
                 attrs(0x1 | 0x2 | 0x4 | 0x8) + s('dir') + s('drwxr-xr-x   2 user group 4096 Nov 14 dir') + attrs(0x4)))
    F.append(pkt(104, P('II', 31, 0)))                                            # NAME, no entries
    F.append(pkt(105, P('I', 32) + attrs(0x1 | 0x4)))                             # ATTRS
    F.append(pkt(105, P('I', 33) + attrs(0x80000000 | 0x8, ext=3)))               # ATTRS with extended count
    F.append(pkt(200, P('I', 34) + s('statvfs@openssh.com') + s('/')))            # EXTENDED (not decoded)
    F.append(pkt(201, P('I', 35) + b'\0' * 16))                                   # EXTENDED_REPLY (not decoded)
    F.append(pkt(99, b'\x01\x02\x03\x04'))                                        # unknown type
    F.append(pkt(250, b''))                                                       # unknown type, no body
    return F


def malformed():
    F = []
    F.append(P('I', 5))                                                           # length, no type
    F.append(b'\x00\x00\x00')                                                     # fewer than 4 bytes
    F.append(pkt(3, P('I', 1) + P('I', 5000) + b'/tmp'))                          # path longer than the packet
    F.append(pkt(3, P('I', 1) + s('/tmp/f') + P('I', 0x1a)))                      # no attributes
    F.append(pkt(3, P('I', 1) + s('/tmp/f') + P('I', 0x1a) + P('I', 0xffffffff)))  # attributes flags, no data
    F.append(pkt(6, P('I', 6) + s(H) + P('Q', 0) + P('I', 1 << 30) + b'abc'))     # data length past the end
    F.append(pkt(103, P('I', 28) + P('I', 100) + b'abc'))                         # DATA too short
    F.append(pkt(104, P('II', 30, 1000) + s('a')))                                # NAME count larger than the data
    F.append(pkt(104, P('II', 30, 0xffffffff)))                                   # NAME count 2^32-1, no entries
    F.append(pkt(101, P('III', 24, 0, 400) + b'OK'))                              # message longer than the data
    F.append(pkt(105, P('I', 32)))                                                # ATTRS without attributes
    F.append(pkt(18, P('I', 19) + s('/tmp/a')))                                   # RENAME without the new path
    F.append(pkt(1, b''))                                                         # INIT without version
    F.append(pkt(5, P('I', 5) + s(H) + P('Q', 1)))                                # READ without length
    F.append(pkt(99, b'\x01') + b'')                                              # unknown type, length 2 packet
    F.append(P('II', 0xffffff00, 0x02000000))                                     # length larger than the data
    return F


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'sftp-coverage.pcap'), clean())
    pcap(os.path.join(out, 'sftp-coverage-malformed.pcap'), malformed())
