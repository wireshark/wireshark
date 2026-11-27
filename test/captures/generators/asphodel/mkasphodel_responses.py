#!/usr/bin/env python3
# Many Asphodel responses from one device, then a TCP message
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""An inquiry from 192.0.2.2:50000, 300 responses to it from the device
192.0.2.1 at UDP port 7000, and one TCP segment from the device's port
7000 carrying an Asphodel message. TCP port 7000 is no Asphodel port: the
segment is decoded only through the TCP conversation that the first
response sets up. Responses used to create a new conversation each ("Asphodel:
Do not create a conversation for every response"); conversations are now
created on the first pass only and one is enough for every response.

The UDP heuristic ("asphodel_inquiry") is disabled by default, so
dissect with --enable-heuristic asphodel_inquiry.

Usage: mkasphodel_responses.py [<output directory>]

Writes asphodel-responses.pcap. Every packet is built here; nothing comes
from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, tcp, udp, write_pcap  # noqa: E402

HOST = '192.0.2.2'
DEVICE = '192.0.2.1'
BCAST = '192.0.2.255'
RESPONSES = 300


def cstr(s):
    return s.encode() + b'\0'


def response(n):
    d = struct.pack('>BBHHHB', 1, 0, 402, 402, 40, 0)
    return d + cstr('WM%04d' % n) + bytes([3]) + cstr('WMRTCP') + cstr('build') + \
        cstr('2026-01-02') + cstr('') + cstr('')


def udp_frame(payload, src, sport, dst, dport, ident, mac_src, mac_dst):
    return eth(ipv4(udp(payload, sport, dport, src=src, dst=dst), 17, src=src, dst=dst,
                    ident=ident), 0x0800, dst=mac_dst, src=mac_src)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mac_host, mac_dev = '02:00:00:00:00:02', '02:00:00:00:00:01'
    frames = [udp_frame(struct.pack('>H', 0x0210) + cstr('Asphodel'), HOST, 50000, BCAST, 5760,
                        1, mac_host, 'ff:ff:ff:ff:ff:ff')]
    for n in range(RESPONSES):
        frames.append(udp_frame(response(n), DEVICE, 7000, HOST, 50000, 2 + n, mac_dev, mac_host))
    message = struct.pack('>HB', 3, 0) + bytes([7, 1])   # device command, sequence 7, code 1
    seg = tcp(message, 7000, 40000, seq=1, ack=1, src=DEVICE, dst=HOST)
    frames.append(eth(ipv4(seg, 6, src=DEVICE, dst=HOST, ident=400), 0x0800,
                      dst=mac_host, src=mac_dev))
    write_pcap(os.path.join(out, 'asphodel-responses.pcap'), frames)


if __name__ == '__main__':
    main()
