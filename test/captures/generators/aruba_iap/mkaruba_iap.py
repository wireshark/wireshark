#!/usr/bin/env python3
# Generates test/captures/aruba_iap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Aruba Instant AP
dissector (packet-aruba-iap.c).

All packets are built from scratch with struct; no captured traffic is
used. Instant APs broadcast frames with ethertype 0x8ffd that start
with the magic number 0xbeef.

Usage: mkaruba_iap.py <output directory>

Writes:
  aruba_iap-coverage.pcap            types 3, 4, 5 and 7 with every model
                                     (and an unknown one), other types,
                                     a frame without the magic number
  aruba_iap-coverage-malformed.pcap  frames cut short, frames with nothing
                                     after the fields
"""

import os
import struct
import sys

ETHERTYPE_IAP = 0x8ffd
MODELS = [0x0a, 0x0f, 0x17, 0x19, 0x1a, 0x1e, 0x28, 0x2b, 0x2e, 0x30, 0x37, 0x39, 0x40, 0x47]


def write_pcap(path, frames):
    with open(path, 'wb') as fh:
        fh.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            fh.write(struct.pack('<IIII', 1700000000 + i, 0, len(f), len(f)) + f)


def ap_mac(n):
    return bytes([0x24, 0xde, 0xc6, 0x00, 0x00, n])


def eth(n, payload, pad=True):
    f = b'\xff' * 6 + ap_mac(n) + struct.pack('>H', ETHERTYPE_IAP) + payload
    if pad and len(f) < 60:
        f += b'\0' * (60 - len(f))
    return f


def iap_hdr(typ, length, ident, version=1, magic=0xbeef):
    return struct.pack('>HBBBB', magic, version, typ, length, ident)


def iap_vc(typ, ident, status, uptime, vc_ip, model, pvid, unknown=0x01020304, extra=b''):
    body = struct.pack('>BI4sBHI', status, uptime, bytes(vc_ip), model, pvid, unknown) + extra
    return iap_hdr(typ, 4 + len(body), ident) + body


def main(outdir):
    frames = []
    n = 0
    # Type 3, 4, 5 and 7 announcements from one AP per model
    for i, model in enumerate(MODELS):
        for typ in (3, 4, 5, 7):
            n += 1
            frames.append(eth(i + 1, iap_vc(typ, n & 0xff, i % 3, 1000 * n,
                                            (10, 30, 0, 1 + i), model, 1 + i)))
    # Unknown model, PVID 4094, maximum uptime, trailing octets
    frames.append(eth(20, iap_vc(3, 200, 1, 0xffffffff, (192, 0, 2, 1), 0x7f, 4094,
                                 0xffffffff, b'\x11\x22\x33\x44\x55\x66')))
    # Other types: only the unknown octets after the header
    for typ in (0, 1, 2, 6, 8, 0xff):
        frames.append(eth(22, iap_hdr(typ, 12, typ) + bytes(range(8))))
    # Not 0xbeef: the dissector rejects it, shown as data
    frames.append(eth(24, iap_hdr(3, 20, 1, magic=0xdead) + b'\0' * 16))
    write_pcap(os.path.join(outdir, 'aruba_iap-coverage.pcap'), frames)

    bad = []
    # One octet: too short for the magic number
    bad.append(eth(25, b'\xbe', pad=False))
    # Magic and version only
    bad.append(eth(25, b'\xbe\xef\x01', pad=False))
    # Type 3 cut inside the VC IP address
    bad.append(eth(25, iap_vc(3, 1, 1, 1, (10, 30, 0, 1), 0x0a, 1)[:12], pad=False))
    # Type 5 cut inside the trailing unknown integer
    bad.append(eth(25, iap_vc(5, 1, 1, 1, (10, 30, 0, 1), 0x0a, 1)[:18], pad=False))
    # A frame that ends right after the fields (no Ethernet padding):
    # the trailing "Unknown" item with length -1 throws at the end of the
    # data (observation 1 in the README)
    bad.append(eth(21, iap_vc(7, 201, 2, 42, (10, 30, 1, 1), 0x19, 1), pad=False))
    bad.append(eth(23, iap_hdr(1, 4, 9, version=2), pad=False))
    write_pcap(os.path.join(outdir, 'aruba_iap-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
