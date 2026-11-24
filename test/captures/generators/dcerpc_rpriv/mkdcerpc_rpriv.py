#!/usr/bin/env python3
# Generates test/captures/dcerpc_rpriv_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DCE/RPC RPRIV dissector
(epan/dissectors/packet-dcerpc-rpriv.c, DCE privilege server interface
b1e338f8-9533-11c9-a34a-08001e019c1e v1).

Connectionless DCE/RPC over UDP (port 135, found by the DCE/RPC
heuristics): a request and response for every opnum, little endian, and
get_eptgt (the only call with a stub dissector) again with other key
sizes and in big endian. The get_eptgt request follows what the
dissector reads: authn and authz service, a 32 bit value, 276 octets it
skips, the cell key (32 bit size and that many octets), 8 octets it
skips and the principal key. Every packet is built from scratch with
struct (dcelib.py); no captured traffic is used.

Usage: mkdcerpc_rpriv.py <output directory>

Writes:
  dcerpc_rpriv-coverage.pcap            (clean, for test/captures)
  dcerpc_rpriv-coverage-malformed.pcap  (key sizes beyond the data)
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from dcelib import CL, pcap  # noqa: E402

RPRIV = 'b1e338f8-9533-11c9-a34a-08001e019c1e'


class W:
    """Stub writer that mirrors the dissector's reads."""
    def __init__(self, le=True):
        self.b = bytearray()
        self.e = '<' if le else '>'

    def u32(self, v):
        self.b += b'\0' * ((-len(self.b)) % 4)
        self.b += struct.pack(self.e + 'I', v)

    def skip(self, n, fill=0):
        self.b += bytes([fill]) * n

    def raw(self, b):
        self.b += b

    def bytes(self):
        return bytes(self.b)


def eptgt(le, cell, princ, authn=2, authz=1, var1=0x10, size1=None, size2=None):
    w = W(le)
    w.u32(authn)
    w.u32(authz)
    w.u32(var1)
    w.skip(276, 0xab)
    c = cell.encode('ascii')
    w.u32(len(c) if size1 is None else size1)
    w.raw(c)
    w.skip(8, 0xcd)
    p = princ.encode('ascii')
    w.u32(len(p) if size2 is None else size2)
    w.raw(p)
    return w.bytes()


def short(le, v):
    w = W(le)
    w.u32(v)
    return w.bytes()


def main_frames():
    F = []
    rpc = CL(F, RPRIV, 1, True, cport=40400)
    for opnum in range(3):
        rpc.call(opnum, short(True, 0x100 + opnum), short(True, 0))
    rpc.call(3, eptgt(True, '/.../cell.example.com', 'alice'), short(True, 0))
    # keys of a length that needs padding before the second size
    rpc.call(3, eptgt(True, '/.../c.example', 'hosts/srv1/self', authn=1, authz=0),
             short(True, 0))
    # empty keys
    rpc.call(3, eptgt(True, '', '', authn=0, authz=2, var1=0), short(True, 0))
    rpc = CL(F, RPRIV, 1, False, cport=40401)
    rpc.call(3, eptgt(False, '/.../be.example.org', 'bob'), short(False, 0))
    rpc.call(0, short(False, 0x100), short(False, 0))
    return F


def malformed_frames():
    F = []
    rpc = CL(F, RPRIV, 1, True, cport=40402)
    # the review's reproducer rpriv_keysize_wrap.py: cell key size
    # 0xffffffff, before the fix taken as "to the end" and the offset
    # moved back one octet
    stub = struct.pack('<III', 1, 2, 3) + b'\0' * 276 + struct.pack('<I', 0xffffffff) \
        + b'CELLNAME' + b'\0' * 12
    rpc.call(3, stub, None)
    # principal key size 0xffffffff
    rpc.call(3, eptgt(True, 'cell', 'princ', size2=0xffffffff), None)
    # key sizes beyond the data
    rpc.call(3, eptgt(True, 'cell', 'princ', size1=100), None)
    rpc.call(3, eptgt(True, 'cell', 'princ', size2=100), None)
    # truncated in the skipped area
    rpc.call(3, struct.pack('<III', 1, 2, 3) + b'\0' * 100, None)
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_rpriv-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_rpriv-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
