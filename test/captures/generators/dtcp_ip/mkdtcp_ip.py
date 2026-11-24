#!/usr/bin/env python3
# Generates test/captures/dtcp_ip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DTCP-IP dissector
(packet-dtcp-ip.c, Digital Transmission Content Protection over IP).

DTCP-IP AKE messages run over TCP on a port the source announces, so
the dissector has no default port: it is registered for Decode As with
a "tcp.port" preference. These captures use TCP port 8000; dissect them
with "-d tcp.port==8000,dtcp-ip". A message is a type octet (1), a 16
bit length and an 8 octet control block (ctype, category/AKE_ID,
subfunction, AKE procedure, exchange_key, subfunction dependent,
AKE_label, number/status) and "length - 8" octets of AKE_Info.

The AKE_Info (certificates, nonces, signatures, keys) is random filler:
no keys or authentication are computed. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkdtcp_ip.py <output directory>

Writes:
  dtcp-ip-coverage.pcap            an AKE exchange: challenge, response,
                                   exchange_key for every key, every
                                   status and procedure bit, unknown
                                   subfunction, non-DTCP-IP segments
  dtcp-ip-coverage-malformed.pcap  AKE_Info shorter than the length
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct

from pktlib import TcpConn, pcap

PORT = 8000


def ake(ctype, cat_id, subfct, proc, xkey, dep, label, numstat, info=b'', length=None):
    ctrl = bytes([ctype, cat_id, subfct, proc, xkey, dep, label, numstat])
    return struct.pack('!BH', 1, 8 + len(info) if length is None else length) + ctrl + info


def filler(n, seed):
    return bytes((seed * 37 + i * 11) & 0xff for i in range(n))


def main_frames():
    c = TcpConn(41000, PORT)
    f = []
    # 4-5: CHALLENGE command (ctype 0 control) and accepted response (0x9)
    f.append(c.send(ake(0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x01, 0x0f, filler(40, 1))))
    f.append(c.send(ake(0x09, 0x00, 0x01, 0x04, 0x00, 0x00, 0x01, 0x00), True))
    # 6-7: CHALLENGE the other way with extended full authentication
    f.append(c.send(ake(0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x02, 0x0f, filler(36, 2)), True))
    f.append(c.send(ake(0x09, 0x00, 0x01, 0x0c, 0x00, 0x00, 0x02, 0x00)))
    # 8-9: RESPONSE with both procedure bits
    f.append(c.send(ake(0x00, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x03, 0x0f, filler(48, 3))))
    f.append(c.send(ake(0x09, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x03, 0x00), True))
    # 10-15: EXCHANGE_KEY for K_X, K_S and K_R
    for i, k in enumerate((0x08, 0x20, 0x40)):
        f.append(c.send(ake(0x00, 0x00, 0x03, 0x04, k, 0x00, 0x04 + i, 0x0f, filler(20, 4 + i)), True))
        f.append(c.send(ake(0x09, 0x00, 0x03, 0x04, k, 0x00, 0x04 + i, 0x00)))
    # 16-18: rejected (0xa) with status 1, 7 and an unknown status 3
    for i, st in enumerate((0x01, 0x07, 0x13)):
        f.append(c.send(ake(0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08 + i, st), True))
    # 19: unknown subfunction, unknown exchange_key, category and AKE_ID
    f.append(c.send(ake(0x01, 0x52, 0x80, 0xf3, 0x10, 0xab, 0x0b, 0xf2, filler(4, 9))))
    # 17-19: segments that are not DTCP-IP (wrong type, length below 8,
    # fewer than 11 octets), each on its own connection: shown as data
    for i, data in enumerate((b'\x02\x00\x08' + bytes(8), b'\x01\x00\x07' + bytes(8),
                              b'\x01\x00\x08\x00\x00')):
        f.append(TcpConn(41010 + i, PORT).send(data))
    return f


def malformed_frames():
    c = TcpConn(41001, PORT)
    f = []
    f.append(c.send(ake(0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x01, 0x0f, filler(4, 1), length=40)))
    f.append(c.send(ake(0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x01, 0x0f, b'', length=0xffff), True))
    return f


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dtcp-ip-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dtcp-ip-coverage-malformed.pcap'), malformed_frames())
