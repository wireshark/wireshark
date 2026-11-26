#!/usr/bin/env python3
# AllJoyn nested structure signature
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AllJoyn messages (UDP port 9955) whose body signature is an array of
deeply nested structures, "a" + "(" * k + "y" + ")" * k. Every struct item
shows its whole signature ("AllJoyn: Fix the work per byte of nested
structure signatures"), so the text of the item at depth j is the rest of
the signature from its "(" to its matching ")".

Usage: mkalljoyn_nested.py [<output directory>]

Writes alljoyn-nested-signature.pcap with two frames: k = 4 with 3 array
elements, and k = 12 with 2 elements. Every packet is built here; nothing
comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402


def pad8(b):
    return b + b'\0' * (-len(b) % 8)


def message(sig, body):
    """Little endian method call whose only header field is the signature."""
    s = sig.encode()
    fields = pad8(bytes([8, 1, ord('g'), 0, len(s)]) + s + b'\0')
    hdr = b'l' + bytes([1, 0, 1]) + struct.pack('<III', len(body), 1, len(fields))
    return hdr + fields + body


def nested_body(n):
    """Array of n structs of one byte each; structs are 8 byte aligned."""
    length = 8 * n - 7
    elems = b''.join(bytes([0x41 + i]) + b'\0' * 7 for i in range(n))[:length]
    return struct.pack('<I', length) + b'\0' * 4 + elems


def frame(sig, n):
    seg = udp(message(sig, nested_body(n)), 40000, 9955)
    return eth(ipv4(seg, 17, ident=1), 0x0800)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = [frame('a' + '(' * k + 'y' + ')' * k, n) for k, n in ((4, 3), (12, 2))]
    write_pcap(os.path.join(out, 'alljoyn-nested-signature.pcap'), frames)


if __name__ == '__main__':
    main()
