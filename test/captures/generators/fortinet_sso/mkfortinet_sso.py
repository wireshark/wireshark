#!/usr/bin/env python3
# Generates test/captures/fortinet_sso_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Fortinet Single Sign-On (FSSO) captures.

Usage: mkfortinet_sso.py <outdir>
Writes fortinet-sso-coverage.pcap and fortinet-sso-coverage-malformed.pcap.
FSSO is a UDP datagram to port 8002 whose first two octets give the datagram
length, found by the (default enabled) heuristic.
"""
import struct
import sys
import os

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

def frame(payload, dport=8002, sport=40000):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 9, 0, 64, 17, 0,
                    bytes((192, 0, 2, 10)), bytes((192, 0, 2, 20)))
    ip = h[:10] + struct.pack('>H', csum(h)) + h[12:] + udp
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip

TS = 1700000000
def msg(ip, s, tail=b'', length=None, plen=None, ts=TS):
    """ip: 4 octets, s: str (NUL terminated here), tail: after the string"""
    body = s if isinstance(s, bytes) else s.encode() + b'\0'
    rest = struct.pack('>I', ts) + bytes(ip) + struct.pack('>H', len(body) if plen is None else plen) + body + tail
    n = 2 + len(rest) if length is None else length
    return struct.pack('>H', n) + rest

CLIENT = (192, 0, 2, 77)
KA = (255, 255, 255, 255)
EXTRA = bytes((10, 1, 2, 3))

def tsagent(ranges, count=None):
    t = bytes(range(0x30, 0x30 + 15)) + bytes(range(0x50, 0x55)) + bytes(range(0x60, 0x66))
    t += struct.pack('>H', len(ranges) if count is None else count)
    for lo, hi in ranges:
        t += struct.pack('>HH', lo, hi)
    return t

main, mal = [], []
# 1 login: host / domain / user, then an extra IPv4 address
main.append(frame(msg(CLIENT, 'WS-01/CORP/alice', EXTRA)))
# 2 login without anything after the string
main.append(frame(msg((192, 0, 2, 78), 'WS-02/CORP/bob')))
# 3 keep alive (client ip 255.255.255.255): domain / KeepAlive / version
main.append(frame(msg(KA, 'CORP/KeepAlive/1.0')))
# 4 keep alive with an extra IPv4 address
main.append(frame(msg(KA, 'CORP/KeepAlive/2.1', EXTRA)))
# 5 tail starting with 0x2002 (17 octets)
main.append(frame(msg(CLIENT, 'WS-03/CORP/carol', b'\x20\x02' + bytes((10, 9, 8, 7)) + bytes(range(6)) + bytes((10, 9, 8, 6)) + b'\x01')))
# 6 TS Agent: 15 + 5 + 6 octets, two port ranges
main.append(frame(msg(CLIENT, 'TS-01/CORP/dave', tsagent([(1024, 1999), (2000, 2999)]))))
# 7 TS Agent with no port range
main.append(frame(msg(CLIENT, 'TS-02/CORP/erin', tsagent([]))))
# 8 TS Agent with many port ranges
main.append(frame(msg(CLIENT, 'TS-03/CORP/frank', tsagent([(5000 + 100 * i, 5099 + 100 * i) for i in range(8)]))))
# 9 fix: no '/' at all: the whole string is the host
main.append(frame(msg(CLIENT, 'nouser')))
# 10 fix: one '/': host and domain only
main.append(frame(msg(CLIENT, 'host/domain')))
# 11 fix: keep alive without separators and with one
main.append(frame(msg(KA, 'domainonly')))
main.append(frame(msg(KA, 'dom/user')))
# 13 empty fields
main.append(frame(msg(CLIENT, '//')))
main.append(frame(msg(KA, '/')))
# 15 empty string (just the NUL)
main.append(frame(msg(CLIENT, '')))
# heuristic rejects: wrong length field, other port, one octet datagram
main.append(frame(msg(CLIENT, 'WS-01/CORP/alice', length=9)))
main.append(frame(msg(CLIENT, 'WS-01/CORP/alice'), dport=9999))
main.append(frame(b'\x01'))

# ---- malformed
# more than three fields: the user ends at the third '/' and the rest of
# the string is taken for the fixed part that follows
mal.append(frame(msg(CLIENT, 'h/d/u/x/y/z')))
# string with no terminating NUL up to the end of the datagram
mal.append(frame(msg(CLIENT, b'WS-01/CORP/alice')))
# only the first 8 octets of the header
mal.append(frame(msg(CLIENT, 'a/b/c')[:8]))
mal.append(frame(struct.pack('>H', 2)))
mal.append(frame(struct.pack('>HI', 6, TS)))
# one stray octet after the string: the 0x2002 test needs two
mal.append(frame(msg(CLIENT, 'a/b/c', b'\x20')))
# 0x2002 tail cut short
mal.append(frame(msg(CLIENT, 'a/b/c', b'\x20\x02\x01\x02\x03\x04\x05\x06')))
# TS Agent data cut short in the fixed part
mal.append(frame(msg(CLIENT, 'a/b/c', b'\x30' * 12)))
# TS Agent announcing more port ranges than there are
mal.append(frame(msg(CLIENT, 'a/b/c', tsagent([(1, 2)], count=60000))))
mal.append(frame(msg(KA, 'a/b/c', tsagent([], count=3))))
# payload length field larger than the string (not used for decoding)
mal.append(frame(msg(CLIENT, 'a/b/c', plen=5000)))

write_pcap(os.path.join(out, 'fortinet-sso-coverage.pcap'), main)
write_pcap(os.path.join(out, 'fortinet-sso-coverage-malformed.pcap'), mal)
print(len(main), len(mal))
