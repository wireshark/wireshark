#!/usr/bin/env python3
# Helper module for the dcerpc_rdpdr_smartcard capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# rdpdr smartcard IOCTL request/response pairs with random NDR bodies for
# every IOCTL the dissector handles (robustness smoke test, no finding).
import struct
import random
import sys
from rdpdr_exppdu_common import exp_pdu, write_pcap
random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 1)
codes = [0x00090014,0x00090018,0x0009001C,0x00090020,0x00090024,0x00090028,0x0009002C,0x00090030,0x00090034,0x00090038,0x0009003C,0x00090040,0x00090044,0x00090048,0x0009004C,0x00090050,0x00090054,0x00090058,0x0009005C,0x00090060,0x00090064,0x00090068,0x0009006C,0x00090070,0x00090074,0x00090078,0x0009007C,0x00090080,0x00090084,0x00090088,0x000900A0,0x000900A4,0x000900A8,0x000900AC,0x000900B0,0x000900B4,0x000900B8,0x000900BC,0x000900C0,0x000900C4,0x000900C8,0x000900CC,0x000900D0,0x000900D4,0x000900D8,0x000900DC,0x000900E0,0x000900E4,0x000900E8,0x000900EC,0x000900F0,0x000900F4,0x000900F8,0x000900FC,0x00090100,0x00090104,0x00090108,0x0009010C,0x00090110,0x00090114,0x00090118,0x0009011C,0x00090120,0x00090124,0x00090128,0x0009012C,0x00090130,0x00090134,0x00090138,0x0009013C,0x00090140]
def rnd():
    n = random.choice([8, 32, 64, 200])
    out = bytearray()
    while len(out) < n:
        out += random.choice([struct.pack('<I', random.choice([0, 1, 2, 4, 0x20000, 0xffffffff, 0x7fffffff, random.getrandbits(32)])), bytes([random.getrandbits(8)])])
    return bytes(out)
frames = [exp_pdu('rdpdr', struct.pack('<HHI', 0x4472, 0x4441, 1) + struct.pack('<II', 0x20, 1) + b'SCARD\0\0\0' + struct.pack('<I', 0))]
cid = 0
for rep in range(4):
    for c in codes:
        cid += 1
        body = b'\0' * 16 + rnd()
        req = struct.pack('<HHIIIII', 0x4472, 0x4952, 1, 0, cid, 0x0e, 0) + struct.pack('<III', 0, len(body), c) + b'\0' * 20 + body
        frames.append(exp_pdu('rdpdr', req))
        resp = struct.pack('<HHIII', 0x4472, 0x4943, 1, cid, 0) + b'\0' * 4 + b'\0' * 16 + rnd()
        frames.append(exp_pdu('rdpdr', resp))
write_pcap('rdpdr_smartcard_fuzz.pcap', frames)
