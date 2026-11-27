#!/usr/bin/env python3
# AT commands in a frame: many one octet commands, hex data parts
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Frames handed to the "at" dissector by Exported PDU records, which have
no direction (so the dissector assumes the DCE role):

 1. 2000 commands of one octet (";"), which the dissector used to handle
    by copying the rest of the frame for every command ("AT: Copy the
    frame once instead of once per command")
 2. +CSIM with 32 octets as hex digits of both cases, converted without
    sscanf ("AT: Parse hex octets without sscanf")
 3. +CSIM with a character that is not a hex digit in the hex string
 4. a lower case +CSIM response, which is matched after upper-casing the
    frame

Usage: mkat_copy.py [<output directory>]

Writes at-copy.pcap (linktype 252, Wireshark Upper PDU). Every packet is
built here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import LINKTYPE_WIRESHARK_UPPER_PDU, exported_pdu, write_pcap  # noqa: E402


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    octets = bytes(range(0x10, 0x30))
    hexstr = ''.join(('%02X' if i % 2 else '%02x') % b for i, b in enumerate(octets))
    payloads = [
        b';' * 2000,
        b'+CSIM: 64,' + hexstr.encode() + b'\r\n',
        b'+CSIM: 8,0102030G\r\n',
        b'+csim: 4,"9f1"\r\n',
    ]
    write_pcap(os.path.join(out, 'at-copy.pcap'),
               [exported_pdu(p, proto='at') for p in payloads],
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU)


if __name__ == '__main__':
    main()
