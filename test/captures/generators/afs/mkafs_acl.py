#!/usr/bin/env python3
# AFS Store ACL requests
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AFS (RX over UDP) Store ACL requests (opcode 134) with ACL text for the
ACL scanner of dissect_acl() ("AFS: Fix quadratic time in parsing ACLs").
The text is the number of positive entries, the number of negative ones
and then "name rights" pairs, separated by white space.

Usage: mkafs_acl.py [<output directory>]

Writes afs-acl-entries.pcap, one call per frame (192.0.2.1 -> 192.0.2.2,
server port 7000):
  1  2 positive and 1 negative entry, rights 63, 0 and 127
  2  entities with tabs and newlines between the fields
  3  rights -1 (all bits), 2147483647 and one past INT_MAX, which stops the
     scan
  4  an entity of 127 characters (the longest accepted), then one of 128
  5  a missing rights value, which stops the scan
  6  the counts are larger than the number of entries
  7  a first count that is not a number, which ends the ACL
Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402

SRC = '192.0.2.1'
DST = '192.0.2.2'
EPOCH = 1700000000
STORE_ACL = 134


def rx(call, payload):
    """RX data packet, client initiated, last packet of the call."""
    hdr = struct.pack('>IIIIIBBBBHH', EPOCH, 0x12345600, call, 1, 1, 1, 0x05, 0, 0, 0, 1)
    return hdr + payload


def store_acl(call, text):
    acl = text.encode()
    body = struct.pack('>IIII', STORE_ACL, 1, 2, 3) + struct.pack('>I', len(acl)) + acl
    seg = udp(rx(call, body), 40000, 7000)
    return eth(ipv4(seg, 17, src=SRC, dst=DST, ident=call, flags_frag=0x4000), 0x0800)


TEXTS = [
    '2\n1\nanonymous 63\nalice 0\nbob 127\n',
    '1\t1\nalice\t7\n\n bob \t 2\n',
    '3 0 root -1 max 2147483647 over 2147483648 big 1 ',
    '2 0 ' + 'a' * 127 + ' 1 ' + 'b' * 128 + ' 1 ',
    '2 0 alice 3 bob ',
    '5 5 alice 3 bob 4 ',
    'x 1 alice 1 ',
]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'afs-acl-entries.pcap'),
               [store_acl(i + 1, t) for i, t in enumerate(TEXTS)])


if __name__ == '__main__':
    main()
