#!/usr/bin/env python3
# Generates test/captures/dcerpc_rs_acct_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DCE/RPC RS_ACCT
dissector (epan/dissectors/packet-dcerpc-rs_acct.c, DCE security
registry account interface 4c878280-2000-0000-0d00-028714000000 v1).

Connectionless DCE/RPC over UDP (port 135, found by the DCE/RPC
heuristics): a request and response for every opnum, little endian, and
lookup and get_projlist (the calls with a stub dissector) again with
other keys, a key size of 0 and in big endian. Their requests follow
what the dissector reads: a 32 bit value, a 32 bit key size and that
many octets of key. Every packet is built from scratch with struct
(dcelib.py); no captured traffic is used.

Usage: mkdcerpc_rs_acct.py <output directory>

Writes:
  dcerpc_rs_acct-coverage.pcap            (clean, for test/captures)
  dcerpc_rs_acct-coverage-malformed.pcap  (key sizes beyond the data)
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from dcelib import CL, pcap  # noqa: E402

RS_ACCT = '4c878280-2000-0000-0d00-028714000000'


def keyed(le, var, key, size=None):
    e = '<' if le else '>'
    k = key.encode('ascii')
    return struct.pack(e + 'II', var, len(k) if size is None else size) + k


def short(le, v):
    return struct.pack(('<' if le else '>') + 'I', v)


def main_frames():
    F = []
    rpc = CL(F, RS_ACCT, 1, True, cport=40500)
    for opnum in range(6):
        if opnum in (3, 5):
            req = keyed(True, 7, 'alice\0')
        else:
            req = short(True, 0x100 + opnum)
        rpc.call(opnum, req, short(True, 0))
    rpc.call(3, keyed(True, 1, 'hosts/srv1/self\0'), short(True, 0))
    rpc.call(3, keyed(True, 2, ''), short(True, 0))       # "Request (other)"
    rpc.call(5, keyed(True, 3, 'bob'), short(True, 0))    # no NUL, odd size
    rpc.call(5, keyed(True, 4, ''), short(True, 0))       # empty key
    rpc = CL(F, RS_ACCT, 1, False, cport=40501)
    rpc.call(3, keyed(False, 7, 'carol\0'), short(False, 0))
    rpc.call(5, keyed(False, 7, 'carol\0'), short(False, 0))
    return F


def malformed_frames():
    F = []
    rpc = CL(F, RS_ACCT, 1, True, cport=40502)
    # the review's reproducer rpriv_keysize_wrap.py: key size 0xffffffff,
    # before the fix taken as "to the end" and the offset moved back
    rpc.call(3, struct.pack('<II', 7, 0xffffffff) + b'principal\0', None)
    rpc.call(5, struct.pack('<II', 7, 0xffffffff) + b'principal\0', None)
    # key sizes beyond the data
    rpc.call(3, keyed(True, 7, 'abc', 100), None)
    rpc.call(5, keyed(True, 7, 'abc', 100), None)
    # truncated before the key size
    rpc.call(3, short(True, 7), None)
    rpc.call(5, short(True, 7), None)
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_rs_acct-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_rs_acct-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
