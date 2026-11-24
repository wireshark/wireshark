#!/usr/bin/env python3
# Generates test/captures/raw_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Raw (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6) coverage captures.
The pcapng files have three interfaces: 101 (raw IP, version from the first
nibble, with the old Linux/Irix PPP quirks), 228 (IPv4) and 229 (IPv6).
Usage: mkraw.py <outdir> [-v]"""
import struct
import sys
import os
import socket

def pcapng_write(path, frames):
    """frames: list of (interface, bytes)"""
    def blk(t, body):
        pad = (-len(body)) % 4
        n = 12 + len(body) + pad
        return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (101, 228, 229):
        out += blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def ip6(nxt, payload, src='2001:db8::1', dst='2001:db8::2'):
    if nxt in (17, 58):
        ph = (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
              + struct.pack('!IBBBB', len(payload), 0, 0, 0, nxt))
        off = 6 if nxt == 17 else 2
        c = csum(ph + payload[:off] + b'\0\0' + payload[off + 2:]) or 0xffff
        payload = payload[:off] + struct.pack('!H', c) + payload[off + 2:]
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), nxt, 64,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + payload

def udp(sp, dp, data):
    return struct.pack('!HHHH', sp, dp, 8 + len(data), 0) + data

def icmp_unreach():
    inner = ip4(17, udp(5001, 5000, b''), src='192.0.2.1', dst='192.0.2.2')[:28]
    b = struct.pack('!BBHI', 3, 3, 0, 0) + inner
    return b[:2] + struct.pack('!H', csum(b)) + b[4:]

def icmp6_ns():
    return struct.pack('!BBHI16s', 135, 0, 0, 0, socket.inet_pton(socket.AF_INET6, '2001:db8::2'))

def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    verbose = '-v' in sys.argv
    m = []; bad = []
    U4 = ip4(17, udp(5000, 5001, b'hello'))
    U6 = ip6(17, udp(5000, 5001, b'hello'))
    # LINKTYPE_RAW (101): the version is taken from the first nibble
    m.append((0, U4))                                                    # IPv4
    m.append((0, U6))                                                    # IPv6
    m.append((0, ip4(1, icmp_unreach())))                                # IPv4 ICMP port unreachable (stateless)
    m.append((0, ip4(17, udp(53, 5002, b'\x12\x34\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00'), src='192.0.2.2', dst='192.0.2.1')))   # UDP from port 53 (DNS)
    m.append((0, U4 + b'\x00' * 6))                                      # IPv4 with trailing padding
    m.append((0, b'\xff\x03\x00\x21' + U4))                              # PPP in HDLC framing (Linux PPP driver sends the header)
    m.append((0, b'\xff\x03\xc0\x21\x01\x01\x00\x04'))                   # PPP LCP Configure-Request
    m.append((0, bytes.fromhex('020000000001') + b'\xff\x03\x00\x21' + U4))   # ISDN fake MAC address before the PPP header
    m.append((0, b'\x00\xff\x03\x00\x21' + U4))                          # one byte before the PPP header
    m.append((0, b'\x00' * 10 + U4))                                     # connection down: 10 zero octets, then IPv4
    m.append((0, b'\x00' * 10 + U6))                                     # ... then IPv6
    m.append((0, b' unknown data starting with a space'))                # neither IP nor PPP: data
    m.append((0, b'\x00' * 9 + b'\x01' + U4))                            # nine zero octets: not the down marker
    m.append((0, b'\x8f' * 12))                                          # version nibble 8: data
    # LINKTYPE_IPV4 (228) and LINKTYPE_IPV6 (229)
    m.append((1, U4))                                                    #
    m.append((1, ip4(1, icmp_unreach())))                                # ICMP
    m.append((2, U6))                                                    #
    m.append((2, ip6(58, icmp6_ns())))                                   # ICMPv6 neighbour solicitation
    m.append((1, U4 + b'\xaa' * 4))                                      # trailing octets after the datagram
    n = len(m)
    # Malformed: frames too short for the checks of dissect_raw()
    bad.append((0, b'\x45'))
    bad.append((0, b'\x00' * 10 + b'xyz'))                              # zero octets followed by bogus IP version 7 (error expert info)
    bad.append((0, b'\x45\x00\x00\x14'))                                 # fewer than 8 octets
    bad.append((0, b'\x60' * 9))                                         # fewer than 10 octets, version 6
    bad.append((0, b'\x00' * 9))
    bad.append((0, U4[:12]))                                             # IPv4 header cut short
    bad.append((0, U6[:30]))                                             # IPv6 header cut short
    bad.append((1, b'\x45\x00'))
    bad.append((2, b'\x60\x00\x00'))
    bad.append((0, b'\xff\x03\x00'))                                     # PPP cut short
    pcapng_write(os.path.join(out, 'raw-coverage.pcapng'), m)
    pcapng_write(os.path.join(out, 'raw-coverage-malformed.pcapng'), bad)
    if verbose:
        print('main frames', n, 'malformed frames', len(bad))

main()
