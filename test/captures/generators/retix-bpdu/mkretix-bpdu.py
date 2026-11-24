#!/usr/bin/env python3
# Generates test/captures/retix-bpdu_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Retix Spanning Tree (R-STP) captures: 802.3 + LLC (DSAP/SSAP 0x80)
# + 3Com XNS type 0x0004 + R-STP body. Usage: mkretix-bpdu.py <outdir>
import struct
import sys
import os
def mac(n): return bytes([0x02, 0, 0, 0, 0, n])
def body(root, bridge, maxage, hello, fwd, trailer=b'RevC CBPDU', pad=2):
    b = mac(root) + b'\x80\x00\x00\x00' + mac(bridge) + b'\x00\x01\x80\x01'
    b += struct.pack('!HHH', maxage, hello, fwd) + b'\0' * pad + trailer
    return b
def frame(payload, dst=bytes([0x09,0,0x07,0xff,0xff,0xff]), src=mac(1), ctl=3, typ=4):
    llc = bytes([0x80, 0x80, ctl]) + struct.pack('!H', typ)
    p = llc + payload
    return dst + src + struct.pack('!H', len(p)) + p
def write(path, pkts, snap=None):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            cap = p if not isinstance(p, tuple) else p[0][:p[1]]
            full = p if not isinstance(p, tuple) else p[0]
            f.write(struct.pack('<IIII', 1 + i, 0, len(cap), len(full)) + cap)
out = sys.argv[1]
main = [
    frame(body(1, 1, 5120, 512, 3840)),
    frame(body(1, 2, 5120, 512, 3840), src=mac(2)),
    frame(body(2, 3, 0, 0, 0), src=mac(3)),
    frame(body(0xfe, 0xfd, 0xffff, 0xffff, 0xffff), src=mac(0xfd)),
    frame(body(5, 6, 2560, 256, 1920, trailer=b'', pad=0), src=mac(6)),
    frame(body(7, 8, 1280, 128, 960, trailer=b'RevC CBPDU' + b'\0' * 20), src=mac(8)),
]
write(os.path.join(out, 'retix-bpdu-coverage.pcap'), main)
mal = [
    (frame(body(1, 1, 5120, 512, 3840, trailer=b'', pad=0)), 3 + 2 + 2 + 20 + 14),  # cut inside Max Age
    (frame(body(1, 1, 5120, 512, 3840, trailer=b'', pad=0)), 14 + 5 + 12),         # cut before Bridge MAC ends
    (frame(body(1, 1, 5120, 512, 3840, trailer=b'', pad=0)), 14 + 5 + 3),          # cut inside Root MAC
    (frame(body(1, 1, 5120, 512, 3840, trailer=b'', pad=0)), 14 + 5 + 24),         # cut inside Hello
    (frame(body(1, 1, 5120, 512, 3840, trailer=b'', pad=0)), 14 + 5 + 26),         # cut inside Forward Delay
]
full = body(1, 1, 5120, 512, 3840, trailer=b'', pad=0)
for k in (3, 12, 15, 21, 23, 25):   # real short frames (consistent lengths)
    mal.append(frame(full[:k]))
write(os.path.join(out, 'retix-bpdu-coverage-malformed.pcap'), mal)
