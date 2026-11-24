#!/usr/bin/env python3
# Generates test/captures/moq_lite_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MoQ-Lite datagram coverage captures: mkmoq_lite.py <outdir> [-v]

moq-lite streams are carried in QUIC STREAM frames, which are encrypted;
this generator writes no ciphertext and no keys, so the stream code is
covered only by the existing test captures (moq-lite-05.pcapng.gz and
moq-lite-edge.pcapng.gz, which carry their own TLS secrets). What can be
built here are the group datagrams: Exported PDU records naming the
dissector "moq-lite.datagram" (the same dissector QUIC datagrams reach
through the "quic.proto.datagram" table).

moq-lite-coverage.pcapng            valid datagrams
moq-lite-coverage-malformed.pcapng  truncated varints, oversize datagram
"""
import os
import struct
import sys

def qv(v):
    if v < 1 << 6: return struct.pack('!B', v)
    if v < 1 << 14: return struct.pack('!H', 0x4000 | v)
    if v < 1 << 30: return struct.pack('!I', 0x80000000 | v)
    return struct.pack('!Q', 0xC000000000000000 | v)
def qv_wide(v, size):
    """A varint using more octets than needed (allowed by QUIC)."""
    return {1: struct.pack('!B', v), 2: struct.pack('!H', 0x4000 | v), 4: struct.pack('!I', 0x80000000 | v),
            8: struct.pack('!Q', 0xC000000000000000 | v)}[size]

def blk(t, body):
    body += b'\0' * (-len(body) % 4)
    return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
def write(fn, payloads):
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)) + blk(1, struct.pack('<HHI', 252, 0, 0))
    for i, p in enumerate(payloads):
        n = b'moq-lite.datagram'; n += b'\0' * (-len(n) % 4)
        fr = struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + p
        ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(fn, 'wb').write(out)

def main(outdir, verbose=False):
    os.makedirs(outdir, exist_ok=True)
    good = []
    for sid, grp, ts, body in ((0, 0, 0, b''), (1, 2, 3, b'hello'), (63, 63, 63, b'\x01' * 10),
                               (64, 64, 64, b'\x02' * 20), (16383, 16384, 16385, b'x'),
                               (1 << 30, (1 << 30) + 1, (1 << 30) + 2, b'big ids'),
                               ((1 << 62) - 1, (1 << 62) - 1, (1 << 62) - 1, b'max')):
        good.append(qv(sid) + qv(grp) + qv(ts) + body)
    for size in (2, 4, 8):                                       # non-minimal encodings
        good.append(qv_wide(5, size) + qv_wide(6, size) + qv_wide(7, size) + b'wide%d' % size)
    good.append(qv(9) + qv(1) + qv(1) + b'\0' * (1200 - 3))      # exactly the limit
    good.append(qv(9) + qv(2) + qv(2) + bytes(range(256)) * 4)   # 1024 octets of payload
    write(os.path.join(outdir, 'moq-lite-coverage.pcapng'), good)
    bad = [b'', b'\x40', b'\x80\x00', b'\xc0\x00\x00\x00',            # truncated subscribe ID
           b'\x00\x40', b'\x00\x00\x80\x00',                       # truncated sequence / timestamp
           qv(1) + qv(1) + qv(1) + b'\0' * (1201 - 3),               # one over the limit
           qv(1) + qv(1) + qv(1) + b'\0' * 5000]
    write(os.path.join(outdir, 'moq-lite-coverage-malformed.pcapng'), bad)
    if verbose: print(len(good), 'valid datagrams,', len(bad), 'bad ones')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
