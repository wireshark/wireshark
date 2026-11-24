#!/usr/bin/env python3
# Helper module for the dcerpc_rfr capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# RFR (1544f5e0-613c-11d1-93df-00c04fd7bd09 v1.0) over CO DCE/RPC/TCP:
# well-formed calls for both opnums plus random-bodied ones (smoke test).
import struct
import random
from mapi_common import TCP, RPC, pcap
random.seed(1)
def cvs(s):
    s = s.encode() + b'\0'
    d = struct.pack('<III', len(s), 0, len(s)) + s
    return d + b'\0' * ((4 - len(d) % 4) % 4)
frames = []
t = TCP(frames, 50001)
r = RPC(t, uuid="1544f5e0-613c-11d1-93df-00c04fd7bd09", ver=(1, 0))
r.bind()
req0 = struct.pack('<I', 0) + cvs('/o=Example/ou=Admin') + struct.pack('<I', 0x20000) + struct.pack('<I', 0) + struct.pack('<I', 0x20004) + struct.pack('<I', 0x20008) + cvs('srv.example.test')
resp0 = struct.pack('<I', 0) + struct.pack('<I', 0x20000) + struct.pack('<I', 0x20004) + cvs('dc1.example.test') + struct.pack('<I', 0)
r.call(0, req0, resp0)
req1 = struct.pack('<II', 0, 20) + cvs('/o=Example/cn=Server')
resp1 = struct.pack('<I', 0x20000) + cvs('mbx.example.test') + struct.pack('<I', 0x8004010f)
r.call(1, req1, resp1)
for i in range(60):
    body = bytes(random.choice([0, 1, 2, 0xff, 0x80, random.getrandbits(8)]) for _ in range(random.choice([4, 16, 48])))
    body2 = bytes(random.choice([0, 1, 2, 0xff, random.getrandbits(8)]) for _ in range(random.choice([4, 16, 48])))
    r.call(i % 2, body, body2)
pcap('rfr_smoke.pcap', frames)
