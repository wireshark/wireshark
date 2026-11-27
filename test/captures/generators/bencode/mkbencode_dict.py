#!/usr/bin/env python3
# Bencode dictionaries nested around a list, and with mixed values
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Exported PDU records for the "bencode" dissector, for "Bencode:
Dissect dictionary values only once":

 1. 9 nested dictionaries ("d1:a" ... "e") around a list of 40 empty
    strings, the deepest nesting the level limit allows. A value used to
    be dissected twice at every level.
 2. a dictionary with an integer, a string, a list and a dictionary
    value, the last of which holds a list with another dictionary
 3. a dictionary whose second value is cut short
 4. a dictionary nested 12 deep, past the level limit

Usage: mkbencode_dict.py [<output directory>]

Writes bencode-dict.pcap (linktype 252, Wireshark Upper PDU). Every packet
is built here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import LINKTYPE_WIRESHARK_UPPER_PDU, exported_pdu, write_pcap  # noqa: E402


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    payloads = [
        b'd1:a' * 9 + b'l' + b'0:' * 40 + b'e' + b'e' * 9,
        b'd1:ai42e1:b2:xy1:cli1ei2ee1:dd1:el1:fd1:gi7eeeee',
        b'd1:ai1e1:b5:ab',
        b'd1:a' * 12 + b'0:' + b'e' * 12,
    ]
    write_pcap(os.path.join(out, 'bencode-dict.pcap'),
               [exported_pdu(p, proto='bencode') for p in payloads],
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU)


if __name__ == '__main__':
    main()
