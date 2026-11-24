#!/usr/bin/env python3
# Generates test/captures/nt_oui_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Nortel OUI coverage captures (synthetic data only).

usage: mknt_oui.py <outdir>

packet-nt-oui.c has no dissector: it registers the LLC "Nortel OUI"
(00:00:81, SONMP) PID table (llc.nortel_pid, PIDs 0x01a1 flatnet hello,
0x01a2 segment hello, 0x01a3 bridge hello). The first two are
dissected by packet-ndp.c. It is reached through 802.3 LLC/SNAP frames.

nt-oui-coverage.pcap            LLC/SNAP frames with the Nortel OUI
nt-oui-coverage-malformed.pcap  SNAP headers cut short
"""
import os
import struct
import sys

SEG = bytes.fromhex('010081000100')     # segment hello multicast
FLAT = bytes.fromhex('010081000101')    # flatnet hello multicast
SRC = bytes.fromhex('0200000000aa')
OUI = bytes.fromhex('000081')


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def snap(pid, payload, dst=SEG, oui=OUI):
    """802.3 frame, LLC (UI) and SNAP header with the OUI and PID."""
    l = struct.pack('>BBB', 0xaa, 0xaa, 3) + oui
    if pid is not None:
        l += struct.pack('>H', pid)
    l += payload
    fr = dst + SRC + struct.pack('>H', len(l)) + l
    return fr + b'\0' * max(0, 60 - len(fr))


def ndp(ip, seg, chassis, backplane, state, links):
    return bytes(ip) + seg.to_bytes(3, 'big') + bytes([chassis, backplane, state, links])


def main(out):
    fr = [
        # PID 0x01a2 segment hello and 0x01a1 flatnet hello: NDP
        snap(0x01a2, ndp([192, 0, 2, 1], 0x000101, 1, 1, 1, 2), SEG),
        snap(0x01a1, ndp([192, 0, 2, 2], 0x000202, 2, 2, 2, 3), FLAT),
        # PID 0x01a3 (bridge hello): nothing registered, shown as data
        snap(0x01a3, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'),
        # a PID that is not in the value string
        snap(0x0abc, b'\xff' * 12),
        snap(0x0000, b''),
        # the NDP PID under another OUI (Cisco): not this table
        snap(0x01a2, ndp([192, 0, 2, 3], 0x000303, 3, 3, 3, 4), SEG, oui=bytes.fromhex('00000c')),
    ]
    write_pcap(os.path.join(out, 'nt-oui-coverage.pcap'), fr)
    mal = [
        snap(None, b'')[:14 + 7],        # SNAP header ends inside the PID
        snap(None, b'')[:14 + 5],        # SNAP header ends after the OUI
        snap(0x01a2, b'')[:14 + 8],      # NDP PID without any NDP data
        snap(0x01a1, b'\x01\x02\x03\x04\x05\x06')[:14 + 8 + 6],   # NDP data cut short
    ]
    write_pcap(os.path.join(out, 'nt-oui-coverage-malformed.pcap'), mal)
    print('nt-oui-coverage.pcap', len(fr), 'frames')
    print('nt-oui-coverage-malformed.pcap', len(mal), 'frames')


if __name__ == '__main__':
    main(sys.argv[1])
