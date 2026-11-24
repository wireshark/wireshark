#!/usr/bin/env python3
# Helper module for the bittorrent capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# BitTorrent edge cases over TCP port 6881: handshake, AMP messages with
# wrapping type lengths, JPC hello with huge address length, short
# extended/piece messages, continuation data.
import struct
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
def tcp(src, dst, sport, dport, seq, payload, flags=0x18):
    th = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 5 << 4, flags, 65535, 0, 0)
    ph = struct.pack('!4s4sBBH', src, dst, 0, 6, len(th) + len(payload))
    c = csum(ph + th + payload)
    th = th[:16] + struct.pack('!H', c) + th[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(th) + len(payload), 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00'
    return eth + ip + th + payload
A = bytes([192,0,2,1]); B = bytes([192,0,2,2])
def msg(t, body): return struct.pack('!IB', 1 + len(body), t) + body
def amp(name, prio, body):
    n = name.encode()
    return struct.pack('!IBI', 1 + 4 + len(n) + 1 + len(body) - 1, 0, 0)[:4] + struct.pack('!I', len(n)) + n + bytes([prio]) + body
def amp2(name, prio, body):
    n = name.encode(); inner = struct.pack('!I', len(n)) + n + bytes([prio]) + body
    return struct.pack('!I', len(inner)) + inner
segs = []
segs.append(bytes([19]) + b'BitTorrent protocol' + b'\0'*5 + b'\x10\0\x05' + b'\x11'*20 + b'-TR2940-' + b'x'*12)
segs.append(msg(5, b'\xff' * 8))
segs.append(msg(7, b''))
segs.append(msg(7, b'\0\0\0\1'))
segs.append(msg(20, b''))
segs.append(msg(20, b'\0d1:ai1ee'))
segs.append(amp2('JPC_HELLO', 1, struct.pack('!I', 0xfffffff0) + b'abc'))
segs.append(amp2('JPC_HELLO', 1, struct.pack('!I', 3) + b'abc' + struct.pack('!II', 6881, 0x1234)))
segs.append(amp2('AZ_HANDSHAKE', 2, b'd1:ai1ee'))
segs.append(amp2('BT_PIECE', 0, struct.pack('!II', 1, 2) + b'data'))
segs.append(amp2('BT_HAVE', 0, struct.pack('!I', 1)))
segs.append(struct.pack('!IB', 12, 0) + struct.pack('!I', 0xfffffffb) + b'\0' * 7)
segs.append(struct.pack('!IB', 12, 0) + struct.pack('!I', 0x7ffffffe) + b'\0' * 7)
segs.append(struct.pack('!I', 0))
segs.append(b'\x00\x00\x40\x0a\x07' + b'z' * 30)
pk = []
seq = 1000
for s in segs:
    pk.append(tcp(A, B, 51413, 6881, seq, s)); seq += len(s)
with open('bittorrent_mix.pcap', 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, p in enumerate(pk):
        f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)
