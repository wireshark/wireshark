#!/usr/bin/env python3
# Generates test/captures/brp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BRP (Bandwidth
Reservation Protocol) dissector (packet-brp.c).

All packets are built from scratch with struct; no captured traffic is
used. A set top box (BRC, 192.0.2.30) and a bandwidth reservation server
(BRS, 198.51.100.7) exchange BRP over UDP port 4000. BRP has no port of
its own; dissect with "-d udp.port==4000,brp".

Usage: mkbrp.py <output directory>

Writes:
  brp-coverage.pcap            every message type 1-15 and two unknown
                               types (0, 16)
  brp-coverage-malformed.pcap  truncated messages (exceptions)
"""

import struct
import sys

BRC = (192, 0, 2, 30)
BRS = (198, 51, 100, 7)
PORT = 4000
EPOCH = 1700000000
VIDEO_SRC = bytes([198, 51, 100, 50])
VIDEO_PORT = 5004


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def udp4(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(u)) + u) or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]


def hdr(typ, trans):
    """Type (1 octet) and 24 bit transaction ID."""
    return struct.pack('>I', typ << 24 | trans)


def flow_info(stat, rmttl, fltype, bw, life, flid):
    """Body of a Flow Get (Next) Response."""
    return struct.pack('>II', stat, rmttl) + VIDEO_SRC + bytes(BRC) + \
        struct.pack('>HHI', VIDEO_PORT, 0, fltype << 24 | bw) + struct.pack('>II', life, flid)


class Pcap:
    def __init__(self):
        self.frames = []

    def brp(self, payload, to_server=True):
        src, dst = (BRC, BRS) if to_server else (BRS, BRC)
        self.frames.append(b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' +
                           ipv4(src, dst, 17, udp4(src, dst, PORT, PORT, payload),
                                len(self.frames) + 1))

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', EPOCH + i, 0, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def main_capture():
    c = Pcap()
    # 1-2: Setup Request (version 2), Setup Response OK
    c.brp(hdr(1, 1) + struct.pack('>I', 2))
    c.brp(hdr(2, 1) + struct.pack('>I', 0), False)
    # 3-4: Heartbeat Request from the server, Heartbeat Response
    c.brp(hdr(5, 2), False)
    c.brp(hdr(6, 2))
    # 5-6: Unidirectional Flow Create Request (video stream to the STB,
    # 1875 Kbytes/s, lifetime 7200), Flow Create Response OK, flow 77
    c.brp(hdr(7, 3) + VIDEO_SRC + bytes(BRC) + struct.pack('>HHII', VIDEO_PORT, 0, 1875, 7200))
    c.brp(hdr(8, 3) + struct.pack('>II', 0, 77), False)
    # 7-8: Flow Get Request, Flow Get Response
    c.brp(hdr(11, 4) + struct.pack('>I', 77))
    c.brp(hdr(12, 4) + flow_info(0, 7100, 1, 1875, 7200, 77), False)
    # 9-10: Flow Get Next Request, Flow Get Next Response No Such
    c.brp(hdr(13, 5) + struct.pack('>I', 77))
    c.brp(hdr(14, 5) + flow_info(4, 0, 0, 0, 0, 0), False)
    # 11-12: second flow refused for lack of bandwidth
    c.brp(hdr(7, 6) + VIDEO_SRC + bytes(BRC) + struct.pack('>HHII', VIDEO_PORT + 2, 0, 3750, 3600))
    c.brp(hdr(8, 6) + struct.pack('>II', 2, 0), False)
    # 13: Flow Abort of flow 77 (flow removed by the network)
    c.brp(struct.pack('>I', 15 << 24) + struct.pack('>I', 77), False)
    # 14-15: Flow Delete Request, Flow Delete Response No Such
    c.brp(hdr(9, 7) + struct.pack('>I', 77))
    c.brp(hdr(10, 7) + struct.pack('>I', 4), False)
    # 16-17: Teardown Request, Teardown Response
    c.brp(hdr(3, 8))
    c.brp(hdr(4, 8), False)
    # 18: Setup Response with an unsupported version (13)
    c.brp(hdr(2, 9) + struct.pack('>I', 13), False)
    # 19: type 0 ("BRP"), not handled: "Unknown packet type" warning
    c.brp(hdr(0, 10) + b'\0' * 4)
    # 20: type 16, unknown: "Unknown packet type" warning
    c.brp(hdr(16, 11) + b'\0' * 4)
    return c


def malformed_capture():
    c = Pcap()
    # 1: Setup Request cut in the version
    c.brp(hdr(1, 1) + b'\0\0')
    # 2: Flow Create Request cut in the destination port
    c.brp(hdr(7, 3) + VIDEO_SRC + bytes(BRC) + b'\x13')
    # 3: Flow Get Response cut in the lifetime
    c.brp((hdr(12, 4) + flow_info(0, 7100, 1, 1875, 7200, 77))[:30], False)
    # 4: Flow Abort with only the type
    c.brp(b'\x0f', False)
    return c


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(out + '/brp-coverage.pcap')
    malformed_capture().write(out + '/brp-coverage-malformed.pcap')
