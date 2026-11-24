# Helper module for the ieee8021ah capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import zlib
def pcap(name, frames, linktype=1, t0=1700000000):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            if isinstance(fr, tuple):
                fr, olen = fr
            else:
                olen = len(fr)
            f.write(struct.pack('<IIII', t0 + i, 0, len(fr), olen))
            f.write(fr)
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def ip4(src, dst, proto, payload, ttl=64, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0,
                    bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload
def udp(sp, dp, payload):
    return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
def mac(s): return bytes.fromhex(s.replace(':', ''))
def eth(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack('!H', etype) + payload
