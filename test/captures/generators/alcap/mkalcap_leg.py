#!/usr/bin/env python3
# ALCAP long leg
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ALCAP (Q.2630) messages of two legs, handed to the ALCAP dissector by
Exported PDU records. A leg is found by the OSAID of its messages and every
packet of a leg lists the messages of the leg in its tree, at most 100 of
them with an expert info for the rest ("ALCAP: Bound the messages listed in
the leg tree").

Usage: mkalcap_leg.py [<output directory>]

Writes alcap-leg-messages.pcap (linktype 252, Wireshark Upper PDU):
  frames 1-150    ERQ messages with the OSAID 0x01020304 (one leg of 150)
  frames 151-155  ERQ messages with the OSAID 0x0a0b0c0d (a leg of 5)
Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import LINKTYPE_WIRESHARK_UPPER_PDU, exported_pdu, write_pcap  # noqa: E402

ERQ = 5
OSAID = 6


def erq(osaid):
    """DSAID 0, message type ERQ, compatibility 0, OSAID parameter."""
    return struct.pack('>IBB', 0, ERQ, 0) + struct.pack('>BBBI', OSAID, 0, 4, osaid)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pdus = [erq(0x01020304)] * 150 + [erq(0x0a0b0c0d)] * 5
    write_pcap(os.path.join(out, 'alcap-leg-messages.pcap'),
               [exported_pdu(p, proto='alcap') for p in pdus],
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU)


if __name__ == '__main__':
    main()
