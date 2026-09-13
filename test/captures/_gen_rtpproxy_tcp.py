#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Generate rtpproxy_tcp.pcap: two single-segment RTPproxy-over-TCP messages,
# the first without a trailing LF (a protocol violation over TCP, which
# requires one to delimit messages) and the second with one. Each uses its
# own source port so it is dissected as an independent segment.

import struct
import sys

DST_PORT = 12222


def frame(sport, payload):
    eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
    # TCP: PSH|ACK, no options, checksum left 0 (not verified on read).
    tcp = struct.pack('!HHIIBBHHH', sport, DST_PORT, 1, 1, (5 << 4), 0x18,
                      65535, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0x4000, 64, 6, 0,
                     bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2)))
    return eth + ip + tcp + payload


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'rtpproxy_tcp.pcap'
    frames = [
        frame(40000, b'24393_4 V'),      # no trailing LF
        frame(40001, b'24393_5 V\n'),     # trailing LF
    ]
    with open(path, 'wb') as f:
        # pcap global header, LINKTYPE_ETHERNET (1)
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for rec in frames:
            f.write(struct.pack('!IIII', 0, 0, len(rec), len(rec)))
            f.write(rec)


if __name__ == '__main__':
    main()
