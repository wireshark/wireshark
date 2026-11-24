#!/usr/bin/env python3
# Generates test/captures/aruba_adp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Aruba Discovery Protocol
dissector (packet-aruba-adp.c).

All packets are built from scratch with struct; no captured traffic is
used. Access points (10.20.0.x) broadcast ADP requests to UDP port 8200
and a mobility controller (10.20.0.1) answers with its address.

Usage: mkaruba_adp.py <output directory>

Writes:
  aruba_adp-coverage.pcap            requests, responses, unknown types,
                                     versions, trailing data
  aruba_adp-coverage-malformed.pcap  packets cut short
"""

import os
import struct
import sys

ADP_PORT = 8200


def ip_checksum(hdr):
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(src, dst, sport, dport, payload, dmac=b'\xff' * 6, smac=b'\x00\x0b\x86\x00\x00\x01'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
    return dmac + smac + b'\x08\x00' + ip + udp


def write_pcap(path, frames):
    with open(path, 'wb') as fh:
        fh.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            fh.write(struct.pack('<IIII', 1700000000 + i, 0, len(f), len(f)) + f)


def adp(version, typ, tid, body=b''):
    return struct.pack('>HHH', version, typ, tid) + body


def ap_mac(n):
    return bytes([0x00, 0x0b, 0x86, 0x9a, 0x00, n])


BCAST = (255, 255, 255, 255)
CTRL = (10, 20, 0, 1)


def ap(n):
    return (10, 20, 0, 10 + n)


def main(outdir):
    frames = []
    # Requests from three APs and the controller's responses
    for n in range(1, 4):
        frames.append(udp_frame(ap(n), BCAST, ADP_PORT, ADP_PORT,
                                adp(1, 1, n, ap_mac(n)), smac=ap_mac(n)))
        frames.append(udp_frame(CTRL, ap(n), ADP_PORT, ADP_PORT,
                                adp(1, 2, n, bytes(CTRL)), dmac=ap_mac(n)))
    # Request from an AP with no address yet, from an ephemeral port
    frames.append(udp_frame((0, 0, 0, 0), BCAST, 49152, ADP_PORT,
                            adp(1, 1, 0xffff, ap_mac(4)), smac=ap_mac(4)))
    # Response to it, to the ephemeral port, another switch address
    frames.append(udp_frame(CTRL, BCAST, ADP_PORT, 49152,
                            adp(1, 2, 0xffff, bytes((192, 0, 2, 200)))))
    # Version 2 request and response with trailing octets
    frames.append(udp_frame(ap(5), BCAST, ADP_PORT, ADP_PORT,
                            adp(2, 1, 0x1234, ap_mac(5) + b'\x00' * 4), smac=ap_mac(5)))
    frames.append(udp_frame(CTRL, ap(5), ADP_PORT, ADP_PORT,
                            adp(2, 2, 0x1234, bytes(CTRL) + b'\x00' * 8), dmac=ap_mac(5)))
    # Unknown types (0, 3, 0xffff): header only, and with data
    frames.append(udp_frame(ap(6), BCAST, ADP_PORT, ADP_PORT, adp(1, 0, 7), smac=ap_mac(6)))
    frames.append(udp_frame(ap(6), BCAST, ADP_PORT, ADP_PORT,
                            adp(1, 3, 8, b'\xde\xad\xbe\xef'), smac=ap_mac(6)))
    frames.append(udp_frame(ap(6), BCAST, ADP_PORT, ADP_PORT,
                            adp(0, 0xffff, 0, b'\x00' * 6), smac=ap_mac(6)))
    write_pcap(os.path.join(outdir, 'aruba_adp-coverage.pcap'), frames)

    bad = []
    # Shorter than the header
    bad.append(udp_frame(ap(7), BCAST, ADP_PORT, ADP_PORT, b'\x00\x01\x00', smac=ap_mac(7)))
    # Request cut inside the MAC address
    bad.append(udp_frame(ap(7), BCAST, ADP_PORT, ADP_PORT, adp(1, 1, 9, ap_mac(7)[:3]),
                         smac=ap_mac(7)))
    # Response cut inside the switch address
    bad.append(udp_frame(CTRL, ap(7), ADP_PORT, ADP_PORT, adp(1, 2, 9, b'\x0a\x14'),
                         dmac=ap_mac(7)))
    write_pcap(os.path.join(outdir, 'aruba_adp-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
