#!/usr/bin/env python3
# Generates test/captures/rdp_cliprdr_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP clipboard channel (MS-RDPECLIP) captures for packet-rdp_cliprdr.c.
# Usage: mkcliprdr.py <outdir> [-v]
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session
from dvclib import create_req, data, data_first

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def cb(t, body=b'', flags=0, length=None):
    return struct.pack('<HHI', t, flags, len(body) if length is None else length) + body


def short_fmt(i, name):
    return struct.pack('<I', i) + name.ljust(32, b'\0')


def long_fmt(i, name):
    return struct.pack('<I', i) + name.encode('utf-16le') + b'\0\0'


def caps(sets):
    body = struct.pack('<HH', len(sets), 0)
    for t, data in sets:
        body += struct.pack('<HH', t, len(data) + 4) + data
    return cb(7, body)


def general(flags, version=2):
    return (1, struct.pack('<II', version, flags))


def build_main():
    cap = Cap()
    # Connection A: the capabilities never announce long format names (short names)
    s = Session(cap, 50000, ['cliprdr', 'drdynvc'])
    S = lambda p: s.chan('cliprdr', p, False)
    C = lambda p: s.chan('cliprdr', p, True)
    S(cb(1))                                                        # monitor ready
    S(caps([general(0x4 | 0x8 | 0x10 | 0x20)]))
    C(caps([general(0)]))
    S(cb(2, short_fmt(13, b'CF_UNICODETEXT') + short_fmt(1, b'') + short_fmt(0xc0ff, b'private format')))
    C(cb(2, short_fmt(1, b'CF_TEXT') + short_fmt(0x8, b'') + short_fmt(0xd, b'x' * 32), flags=4))   # names without a NUL
    C(cb(3, flags=1))                                               # format list response
    S(cb(3, flags=2))
    for f in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x80, 0x81, 0x82, 0x83, 0x8e, 0x1234):
        C(cb(4, struct.pack('<I', f)))                              # format data request, every known format
    S(cb(5, b'clipboard data', flags=1))                            # format data response
    S(cb(5, b'\0', flags=2))
    S(cb(6, 'C:\\tmp\0'.encode('utf-16le') + bytes(500 - 14)))      # temporary directory
    S(caps([(0x7777, b'')]))
    S(caps([]))
    S(cb(8, struct.pack('<IIIIIII', 7, 1, 1, 0, 0, 4096, 99)))      # file contents request
    C(cb(9, struct.pack('<I', 7) + bytes(20), flags=1))             # file contents response
    S(cb(0xa, struct.pack('<I', 99)))
    S(cb(0xb, struct.pack('<I', 99)))
    S(cb(0x7f, bytes(4)))                                           # unknown message
    lst = cb(2, b''.join(short_fmt(0x100 + i, ('format %d' % i).encode()) for i in range(40)))
    s.chunks('cliprdr', lst, False, size=500)                       # reassembled across chunks
    s.chunks('cliprdr', cb(5, bytes(3000), flags=1), True, size=1000)
    # PDUs with a length that wraps the 32 bit PDU length (dataLen + 8)
    S(cb(1, b'', length=0xfffffff8))
    S(cb(2, b'', length=0xfffffffc) + short_fmt(0x42, b''))
    S2 = lambda p: s.chan('drdynvc', p, False)
    S2(create_req(7, 'cliprdr'))
    S2(data(7, cb(1)))
    S2(data(7, cb(2, short_fmt(1, b'CF_TEXT'))))
    S2(data_first(7, len(cb(2, short_fmt(1, b'CF_TEXT'))), cb(2, short_fmt(1, b'CF_TEXT'))[:10]))
    S2(data(7, cb(2, short_fmt(1, b'CF_TEXT'))[10:]))
    # Connection B: both sides announce long format names first
    s = Session(cap, 50001, ['cliprdr'])
    S = lambda p: s.chan('cliprdr', p, False)
    C = lambda p: s.chan('cliprdr', p, True)
    S(caps([general(0x2 | 0x4 | 0x8 | 0x10 | 0x20), (0x7777, struct.pack('<I', 0))]))
    C(caps([general(0x2)]))
    S(cb(2, long_fmt(13, 'CF_UNICODETEXT') + long_fmt(1, '') + long_fmt(0xc0ff, 'private')))
    C(cb(2, long_fmt(0x8, 'CF_DIB') + long_fmt(0xc001, 'Rich Text Format')))
    s.chunks('cliprdr', cb(2, b''.join(long_fmt(0x200 + i, 'long format %d' % i) for i in range(30))), False, size=400)
    cap.write(os.path.join(OUT, 'cliprdr-coverage.pcapng'))
    if VERBOSE:
        print('cliprdr-coverage.pcapng', len(cap.frames), 'frames')


def build_malformed():
    cap = Cap()
    s = Session(cap, 50000, ['cliprdr'])
    s.chan('cliprdr', b'\x01\x00')                                  # cut short
    s.chan('cliprdr', struct.pack('<HHI', 1, 0, 0)[:6])
    s.chan('cliprdr', cb(2, short_fmt(1, b'CF_TEXT')[:20]))         # format list cut in a name
    s.chan('cliprdr', cb(2, struct.pack('<I', 1)))
    s.chan('cliprdr', cb(4))                                        # data request without format id
    s.chan('cliprdr', cb(7, struct.pack('<HH', 5, 0) + struct.pack('<HH', 1, 12)))   # capability set cut short
    s.chan('cliprdr', cb(8, bytes(10)))
    s.chan('cliprdr', cb(0xa))
    s.chan('cliprdr', cb(9))
    s.chan('cliprdr', cb(7, struct.pack('<HH', 1, 0)) + b'')
    # the reproducer of the short-name offset: names of 32 octets that start with a NUL
    s.chan('cliprdr', cb(2, struct.pack('<I', 1) + bytes(32) + struct.pack('<I', 2) + b'A' * 30))
    cap.write(os.path.join(OUT, 'cliprdr-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build_main()
    build_malformed()
