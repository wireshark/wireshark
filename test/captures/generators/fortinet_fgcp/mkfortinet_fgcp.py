#!/usr/bin/env python3
# Generates test/captures/fortinet_fgcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic FGCP (FortiGate Cluster Protocol) captures.

Usage: mkfortinet_fgcp.py <outdir>
Writes fortinet-fgcp-coverage.pcap and fortinet-fgcp-coverage-malformed.pcap.
Everything is built with struct and zlib; the authentication and the
encrypted payload are opaque filler bytes, nothing is computed from keys.
"""
import struct
import sys
import os
import zlib

out = sys.argv[1] if len(sys.argv) > 1 else '.'

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(et, payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('>H', et) + payload

def ipv4(proto, payload, src=(10, 0, 0, 1), dst=(10, 0, 0, 2)):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 7, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload

def pad(s, n):
    return s.encode().ljust(n, b'\0')

def hb_header(mode=2, flags=0, group='cluster-1', gid=7, port='ha1', rev=3,
              sn='FGT60E0000000001', magic=0x2a2a, u=0x1000):
    h = struct.pack('<H', magic) + bytes([mode, flags]) + pad(group, 32)
    h += struct.pack('<H', u)              # unknown
    h += struct.pack('<H', gid)            # group id
    h += b''.join(struct.pack('<H', u + i + 1) for i in range(6))
    h += pad(port, 16)
    h += struct.pack('<HH', rev, 0xbeef)   # revision, unknown
    h += pad(sn, 16)
    assert len(h) == 88
    return h

def tlv(t, v, l=None):
    return struct.pack('<HH', t, len(v) if l is None else l) + v

def inventory(ifs, count=None, raw=None):
    """ifs: list of (name, mac, flags)"""
    body = b''.join(pad(n, 16) + m + bytes([f]) for n, m, f in ifs)
    comp = zlib.compress(body) if raw is None else raw
    n = len(ifs) if count is None else count
    return tlv(0x2a, struct.pack('<H', n) + comp)

AUTH = bytes(range(0xa0, 0xc0))        # opaque 32 octets
OPAQUE = bytes((i * 7 + 3) & 0xff for i in range(64))  # opaque, shown as bytes only

IFS = [('port1', b'\x00\x09\x0f\x01\x02\x03', 0x0f),
       ('port2', b'\x00\x09\x0f\x01\x02\x04', 0x03),
       ('wan1', b'\x00\x09\x0f\x01\x02\x05', 0x05),
       ('ha1', b'\x00\x09\x0f\x01\x02\x06', 0x00),
       ('mgmt', b'\x00\x09\x0f\x01\x02\x07', 0x08)]

main, mal = [], []
HB = 0x8890
SESS = 0x8893

# ---- main capture: heartbeat frames
# 1 mode 1 (A/A), no flags, no TLVs at all
main.append(eth(HB, hb_header(mode=1)))
# 2 each simple TLV: vcluster, priority, override true, override false
main.append(eth(HB, hb_header(mode=2) + tlv(0x0b, b'\x01') + tlv(0x0c, b'\x80')
                + tlv(0x0d, b'\x01') + tlv(0x0d, b'\x00')))
# 3 HA checksum (3 x 16 octets) and an End of TLV entry
main.append(eth(HB, hb_header(mode=2, port='ha2', rev=4)
                + tlv(0x3c, bytes(range(16)) + bytes(range(16, 32)) + bytes(range(32, 48)))
                + tlv(0x00, b'')))
# 4 interface inventory with five interfaces covering every flag
main.append(eth(HB, hb_header(mode=1, group='inventory', port='ha1') + inventory(IFS)))
# 5 interface inventory with zero interfaces, then an unknown TLV type
main.append(eth(HB, hb_header() + inventory([]) + tlv(0x99, b'\x01\x02\x03\x04\x05')))
# 6 inventory whose payload is not a zlib stream (nothing to decompress)
main.append(eth(HB, hb_header() + inventory([], count=3, raw=b'\x01\x02\x03\x04\x05\x06')))
# 7 unknown flag bits 7-4, 3 and 2 set, all TLVs together
main.append(eth(HB, hb_header(mode=2, flags=0xfc, group='flags')
                + tlv(0x0b, b'\x02') + tlv(0x0c, b'\x10') + tlv(0x0d, b'\x00')
                + inventory(IFS[:2])))
# 8 authentication flag: TLVs then 32 octets of authentication data
main.append(eth(HB, hb_header(mode=2, flags=0x02) + tlv(0x0c, b'\x64') + AUTH))
# 9 authentication flag, no TLVs at all (exactly 32 octets follow)
main.append(eth(HB, hb_header(mode=1, flags=0x02) + AUTH))
# 10 encrypted flag: the payload is shown as opaque bytes
main.append(eth(HB, hb_header(mode=2, flags=0x01) + OPAQUE))
# 11 encrypted and authentication flags
main.append(eth(HB, hb_header(mode=2, flags=0x03) + OPAQUE + AUTH))
# 12 encrypted flag, empty payload
main.append(eth(HB, hb_header(mode=1, flags=0x01)))
# 13 TLV that is exactly the last 4 octets (zero length End of TLV) with auth
main.append(eth(HB, hb_header(mode=2, flags=0x02) + tlv(0x00, b'') + AUTH))
# 14 odd mode value (neither A/A nor A/P), different magic number
main.append(eth(HB, hb_header(mode=9, magic=0x1111, group='odd')))

# ---- main capture: session frames (FGCP session sync carrying IPv4)
udp = struct.pack('>HHHH', 4000, 4001, 8 + 6, 0) + b'syncit'
udp2 = struct.pack('>HHHH', 4002, 4003, 8 + 4, 0) + b'sync'
main.append(eth(SESS, struct.pack('<HH', 0x2a2a, 1) + ipv4(17, udp2)))
main.append(eth(SESS, struct.pack('<HH', 0x2a2b, 2) + ipv4(17, udp)))
# session frame with nothing after the 4 octet header (IP is malformed)
mal.append(eth(SESS, struct.pack('<HH', 0x2a2a, 0)))

# ---- malformed capture
# fix: payload too short for the authentication field (4 octets only)
mal.append(eth(HB, hb_header(flags=0x02) + b'\x01\x02\x03\x04'))
# fix: authentication flag, nothing after the header
mal.append(eth(HB, hb_header(flags=0x02)))
# fix: TLV length exceeds the remaining payload
mal.append(eth(HB, hb_header() + tlv(0x0c, b'\x01', l=500)))
# fix: TLV length exceeds the payload before the authentication field
mal.append(eth(HB, hb_header(flags=0x02) + tlv(0x0c, b'\x01', l=40) + AUTH))
# fix: inventory TLV shorter than its 2 octet count
mal.append(eth(HB, hb_header() + tlv(0x2a, b'\x05', l=1)))
mal.append(eth(HB, hb_header() + tlv(0x2a, b'', l=0)))
# inventory announces more interfaces than the decompressed data holds
mal.append(eth(HB, hb_header() + inventory(IFS[:2], count=9)))
# a partial TLV header at the end of the payload (3 octets)
mal.append(eth(HB, hb_header() + b'\x0c\x00\x01'))
# vcluster TLV with a length of 0 followed by a truncated one: the value
# is read as one octet whatever the length says
mal.append(eth(HB, hb_header() + tlv(0x0b, b'', l=0) + tlv(0x0c, b'\x01', l=1)))
# HA checksum TLV with a short length (48 octets are read anyway)
mal.append(eth(HB, hb_header() + tlv(0x3c, b'\x01\x02', l=2)))
# shorter than the 88 octet header: exception while building the Info text
mal.append(eth(HB, hb_header()[:60]))
mal.append(eth(HB, hb_header()[:20]))
mal.append(eth(HB, hb_header()[:80]))
# the header is complete but nothing else (flags byte only, then truncated)
mal.append(eth(HB, hb_header()[:87]))
# session frame shorter than its header
mal.append(eth(SESS, b'\x2a\x2a\x01'))
mal.append(eth(SESS, b''))
# session frame carrying a truncated IP header
mal.append(eth(SESS, struct.pack('<HH', 0x2a2a, 1) + b'\x45\x00\x00'))

write_pcap(os.path.join(out, 'fortinet-fgcp-coverage.pcap'), main)
write_pcap(os.path.join(out, 'fortinet-fgcp-coverage-malformed.pcap'), mal)
print(len(main), len(mal))
