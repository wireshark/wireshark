#!/usr/bin/env python3
# AMQP frames reached through the amqp.version dissector table
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AMQP 0-9 method frames handed to the "amqp.version" dissector table by
an Exported PDU record (table value 2 = AMQP 0-9), so that dissect_amqp()
never ran for the conversation and there is no AMQP conversation data.
The method dissectors must cope with that ("AMQP: Fix a NULL dereference
when called through amqp.version"): confirm.select-ok, basic.publish and
basic.ack, each on channel 1.

Usage: mkamqp_exported_pdu.py [<output directory>]

Writes amqp-exported-pdu.pcap (linktype 252, Wireshark Upper PDU). Every
packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import LINKTYPE_WIRESHARK_UPPER_PDU, exported_pdu, write_pcap  # noqa: E402

CONFIRM = 85
BASIC = 60


def frame09(payload, chan=1):
    """AMQP 0-9 method frame (type 1)."""
    return struct.pack('>BHI', 1, chan, len(payload)) + payload + b'\xce'


def shortstr(s):
    return bytes([len(s)]) + s


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = [
        frame09(struct.pack('>HH', CONFIRM, 11)),
        frame09(struct.pack('>HHH', BASIC, 40, 0) + shortstr(b'ex') + shortstr(b'rk') + b'\x00'),
        frame09(struct.pack('>HHQB', BASIC, 80, 1, 0)),
    ]
    write_pcap(os.path.join(out, 'amqp-exported-pdu.pcap'),
               [exported_pdu(f, table='amqp.version', table_value=2) for f in frames],
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU)


if __name__ == '__main__':
    main()
