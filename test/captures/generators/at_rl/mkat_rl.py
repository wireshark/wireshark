#!/usr/bin/env python3
# Generates test/captures/at_rl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Allied Telesis Resiliency Link (ethertype 0xFBAC) captures for
# coverage of epan/dissectors/packet-at-rl.c. Every packet is built with
# struct; nothing comes from a real network.
# Usage: mkat_rl.py <outdir>
import os
import struct
import sys

DST = bytes([0x01, 0x00, 0xcd, 0xfa, 0x1b, 0xac])   # AT RL multicast address
SW1 = bytes([0x00, 0x00, 0xcd, 0x00, 0x00, 0x01])
SW2 = bytes([0x00, 0x00, 0xcd, 0x00, 0x00, 0x02])
T0 = 1700000000


def body(seq, master, vcsid, role_change, pad=b'\x00\x00'):
    return struct.pack('>I', seq) + master + pad + struct.pack('>HI', vcsid, role_change)


def eth(src, payload, dst=DST, tags=()):
    h = dst + src
    for tpid, tci in tags:
        h += struct.pack('>HH', tpid, tci)
    return h + struct.pack('>H', 0xfbac) + payload


def pad60(frame, fill=b'\x00'):
    return frame + fill * max(0, 60 - len(frame))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', T0 + 100 + i, 0, len(fr), len(fr)) + fr)


def main_frames():
    fr = []
    # 1-4: switch 1 is master, periodic frames padded to 60 octets
    for seq in range(1, 5):
        fr.append(pad60(eth(SW1, body(seq, SW1, 7, T0))))
    # 5-6: switch 2 sends too, naming switch 1 as master
    fr.append(pad60(eth(SW2, body(1, SW1, 7, T0))))
    fr.append(pad60(eth(SW2, body(2, SW1, 7, T0))))
    # 7-8: role change: switch 2 becomes master
    fr.append(pad60(eth(SW2, body(3, SW2, 7, T0 + 110))))
    fr.append(pad60(eth(SW1, body(5, SW2, 7, T0 + 110))))
    # 9: unpadded, exactly 18 octets of AT RL
    fr.append(eth(SW1, body(6, SW2, 7, T0 + 110)))
    # 10: non-zero Ethernet trailer after the 18 octets
    fr.append(eth(SW1, body(7, SW2, 7, T0 + 110)) + b'\xff' * 10)
    # 11: 802.1Q tagged
    fr.append(pad60(eth(SW1, body(8, SW2, 7, T0 + 110), tags=[(0x8100, 10)])))
    # 12: 802.1ad + 802.1Q (QinQ)
    fr.append(pad60(eth(SW1, body(9, SW2, 7, T0 + 110), tags=[(0x88a8, 100), (0x8100, 10)])))
    # 13: all-zero values
    fr.append(pad60(eth(SW1, body(0, bytes(6), 0, 0))))
    # 14: maximum values, non-zero padding field
    fr.append(pad60(eth(SW1, body(0xffffffff, b'\xff' * 6, 0xffff, 0xffffffff, pad=b'\xde\xad'))))
    # 15: other VCS-ID
    fr.append(pad60(eth(SW2, body(10, SW2, 0x1234, T0 + 110))))
    # 16: not sent to 01:00:cd:fa:1b:ac: the dissector rejects it (data)
    fr.append(pad60(eth(SW1, body(11, SW1, 7, T0), dst=bytes([0x01, 0x00, 0xcd, 0xfa, 0x1b, 0xad]))))
    # 17: unicast destination, also rejected
    fr.append(pad60(eth(SW1, body(12, SW1, 7, T0), dst=SW2)))
    return fr


def malformed_frames():
    full = body(7, SW1, 7, T0)
    fr = []
    for n in (17, 14, 13, 3, 0):          # short: 14-17 throw in the tree,
        fr.append(eth(SW1, full[:n]))     # 0-13 already in the Info column
    fr.append(eth(SW1, full[:15], tags=[(0x8100, 10)]))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'at_rl-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'at_rl-coverage-malformed.pcap'), malformed_frames())
    # Frame cut by the snapshot length (28 of 60 octets captured)
    path = os.path.join(out, 'at_rl-coverage-malformed.pcap')
    fr = pad60(eth(SW1, body(8, SW1, 7, T0)))
    with open(path, 'ab') as f:
        f.write(struct.pack('<IIII', T0 + 200, 0, 28, len(fr)) + fr[:28])


if __name__ == '__main__':
    main()
