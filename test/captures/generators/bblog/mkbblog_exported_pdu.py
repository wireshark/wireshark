#!/usr/bin/env python3
# BBLog binary option reached through an Exported PDU record
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Two Exported PDU records for the "pcapng_custom_binary_option"
dissector table with the Netflix enterprise number (10949). The BBLog
binary option dissector is then called without the custom option data that
pcapng reading passes to it ("BBLOG: Fix a NULL pointer dereference in the
binary option dissector"). The first record has a 20 octet payload, the
second 300 octets.

Usage: mkbblog_exported_pdu.py [<output directory>]

Writes bblog-exported-pdu.pcap (linktype 252, Wireshark Upper PDU). Every
packet is built here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import LINKTYPE_WIRESHARK_UPPER_PDU, exported_pdu, write_pcap  # noqa: E402

PEN_NFLX = 10949


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    payloads = [b'\x01\x00\x00\x00' + b'\x00' * 16, b'\x01\x00\x00\x00' + b'\x5a' * 296]
    write_pcap(os.path.join(out, 'bblog-exported-pdu.pcap'),
               [exported_pdu(p, table='pcapng_custom_binary_option', table_value=PEN_NFLX)
                for p in payloads],
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU)


if __name__ == '__main__':
    main()
