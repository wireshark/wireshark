#!/usr/bin/env python3
# Generates test/captures/dcerpc_rs_misc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DCE/RPC RS_MISC
dissector (epan/dissectors/packet-dcerpc-rs_misc.c, DCE security
registry miscellaneous interface 4c878280-5000-0000-0d00-028714000000
v1).

Connectionless DCE/RPC over UDP (port 135, found by the DCE/RPC
heuristics): a request and response for every opnum, little endian, and
login_get_info (the only call with a stub dissector) again with other
keys, a key size of 0 and in big endian. Its request follows what the
dissector reads: a 32 bit value, a 32 bit key size and that many octets
of key. Every packet is built from scratch with struct (dcelib.py); no
captured traffic is used.

Usage: mkdcerpc_rs_misc.py <output directory>

Writes:
  dcerpc_rs_misc-coverage.pcap            (clean, for test/captures)
  dcerpc_rs_misc-coverage-malformed.pcap  (key sizes beyond the data)
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from dcelib import CL, pcap  # noqa: E402

RS_MISC = '4c878280-5000-0000-0d00-028714000000'


def keyed(le, var, key, size=None):
    e = '<' if le else '>'
    k = key.encode('ascii')
    return struct.pack(e + 'II', var, len(k) if size is None else size) + k


def short(le, v):
    return struct.pack(('<' if le else '>') + 'I', v)


def main_frames():
    F = []
    rpc = CL(F, RS_MISC, 1, True, cport=40600)
    rpc.call(0, keyed(True, 7, 'alice\0'), short(True, 0))
    rpc.call(1, short(True, 0x101), short(True, 0))
    rpc.call(2, short(True, 0x102), short(True, 0))
    rpc.call(0, keyed(True, 1, 'hosts/srv1/self'), short(True, 0))
    rpc.call(0, keyed(True, 2, ''), short(True, 0))       # "Request (other)"
    rpc = CL(F, RS_MISC, 1, False, cport=40601)
    rpc.call(0, keyed(False, 7, 'carol\0'), short(False, 0))
    rpc.call(0, keyed(False, 0, ''), short(False, 0))
    return F


def malformed_frames():
    F = []
    rpc = CL(F, RS_MISC, 1, True, cport=40602)
    # the review's reproducer rpriv_keysize_wrap.py: key size 0xffffffff,
    # before the fix taken as "to the end" and the offset moved back
    rpc.call(0, struct.pack('<II', 7, 0xffffffff) + b'principal\0', None)
    # key size beyond the data, truncated before the key size
    rpc.call(0, keyed(True, 7, 'abc', 100), None)
    rpc.call(0, short(True, 7), None)
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_rs_misc-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_rs_misc-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
