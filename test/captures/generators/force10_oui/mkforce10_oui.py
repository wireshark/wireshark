#!/usr/bin/env python3
# Generates test/captures/force10_oui_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Force10 OUI coverage captures (synthetic data only).

usage: mkforce10_oui.py <outdir>

packet-force10-oui.c has no dissector: it registers the LLC "Force10
OUI" (00:01:e8) PID table (llc.force10_pid, PID 0x0111 = FEFD). It is
reached through 802.3 LLC/SNAP frames.

force10-oui-coverage.pcap            LLC/SNAP frames with the Force10 OUI
force10-oui-coverage-malformed.pcap  SNAP headers cut short
"""
import os
import struct
import sys

DST = bytes.fromhex('01000ccccccd')
SRC = bytes.fromhex('0200000000aa')
OUI = bytes.fromhex('0001e8')


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def snap(pid, payload, oui=OUI, dsap=0xaa, ssap=0xaa):
    """802.3 frame, LLC (UI) and SNAP header with the OUI and PID."""
    l = struct.pack('>BBB', dsap, ssap, 3) + oui
    if pid is not None:
        l += struct.pack('>H', pid)
    l += payload
    fr = DST + SRC + struct.pack('>H', len(l)) + l
    return fr + b'\0' * max(0, 60 - len(fr))


def fefd(ver, op, flags, tlvs, csum=0):
    return struct.pack('>BBH', (ver << 5) | op, flags, csum) + b''.join(tlvs)


def tlv(t, data):
    return struct.pack('>HH', t, 4 + len(data)) + data


def main(out):
    fr = [
        # PID 0x0111: FEFD (Far End Failure Detection) hello and echo
        snap(0x0111, fefd(1, 1, 0xc0, [tlv(1, b'switch-1\0'), tlv(2, b'Te0/1\0')], 0x1234)),
        snap(0x0111, fefd(1, 3, 0x00, [tlv(1, b'switch-2\0'), tlv(2, b'Te0/2\0')])),
        # PIDs nothing is registered for: shown as data
        snap(0x0222, b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        snap(0x0000, b'\xff' * 12),
        snap(0xffff, b''),
        # the PID of FEFD under an OUI nothing is registered for: not this table
        snap(0x0111, b'\0' * 8, oui=bytes.fromhex('0001e9')),
    ]
    write_pcap(os.path.join(out, 'force10-oui-coverage.pcap'), fr)
    mal = [
        snap(None, b'')[:14 + 7],        # SNAP header ends inside the PID
        snap(None, b'')[:14 + 5],        # SNAP header ends after the OUI
        snap(0x0111, b'')[:14 + 8],      # FEFD PID without any FEFD data
    ]
    write_pcap(os.path.join(out, 'force10-oui-coverage-malformed.pcap'), mal)
    print('force10-oui-coverage.pcap', len(fr), 'frames')
    print('force10-oui-coverage-malformed.pcap', len(mal), 'frames')


if __name__ == '__main__':
    main(sys.argv[1])
