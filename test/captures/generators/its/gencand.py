#!/usr/bin/env python3
# Helper module for the its capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Candidate random ITS PDUs (valid header, random PER body) for selectits.py.
# Usage: gencand.py <seed> <count> <out.pcap>   (Exported PDU "its")
import struct
import random
import sys
seed, n, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
r = random.Random(seed)
pairs = [(2,1),(1,1),(2,2),(1,2),(1,4),(2,4),(1,5),(2,5),(1,6),(2,6),(0,7),(1,8),(2,9),(2,10),(0,11),
         (1,13),(2,13),(1,14),(2,14),(2,15),(3,16),(1,18),(1,19),(2,21)]
tags = struct.pack('>HH', 12, 4) + b'its\0' + struct.pack('>HH', 0, 0)
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
    for i in range(n):
        v, m = pairs[i % len(pairs)]
        dens = r.choice([0.02, 0.05, 0.1, 0.2, 0.35, 0.5])
        body = bytes(sum((r.random() < dens) << k for k in range(8)) for _ in range(r.randint(4, 150)))
        fr = tags + struct.pack('>BBI', v, m, 0x01020304) + body
        f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
        f.write(fr)
