#!/usr/bin/env python3
# Helper module for the c1222 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# C12.22 over TCP/1153 with BER message lengths near 2^32 so that
# get_c1222_message_len() returns length + header which wraps.
import struct
import sys
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
seq = 1000
def tcp4(payload, sport=50000, dport=1153):
    global seq
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, 0x18, 65535, 0, 0) + payload
    seq += len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(tcp), 1, 0, 64, 6, 0,
                     bytes([192,0,2,1]), bytes([192,0,2,2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + tcp
pkts = []
for l in (0xfffffffa, 0xfffffffb, 0xfffffffc, 0xffffffff, 0x7ffffffe):
    pkts.append(tcp4(b'\x60\x84' + struct.pack('!I', l) + b'\xa2\x04\x80\x02\x7b\x04' + b'\0'*20))
pkts.append(tcp4(b'\x60\x00' * 30))
out = sys.argv[1] if len(sys.argv) > 1 else 'c1222_tcp_pdu_len.pcap'
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for i, p in enumerate(pkts):
        f.write(struct.pack('<IIII', i+1, 0, len(p), len(p)) + p)
