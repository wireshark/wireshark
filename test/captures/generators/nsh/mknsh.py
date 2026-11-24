#!/usr/bin/env python3
# Generates test/captures/nsh_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Network Service Header (NSH) coverage captures (synthetic, struct only).

Usage: mknsh.py <outdir> [-v]

Writes, into <outdir>:
  nsh-coverage.pcap            main capture: NSH over Ethernet (ethertype 0x894F),
                               GRE, IP protocol 145, VXLAN-GPE and GTP-U (heuristic)
  nsh-coverage-malformed.pcap  invalid lengths (warnings), TLVs cut short or longer
                               than their dissector, truncated headers
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def eth(payload, etype=0x0800, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'):
    mac = lambda m: bytes(int(x, 16) for x in m.split(':'))
    return mac(dst) + mac(src) + struct.pack('!H', etype) + payload


def inner_ipv4(n=0):
    return ipv4(17, udp(40000 + n, 5000, b'payload%d' % n), src=(10, 0, 0, 1), dst=(10, 0, 0, 2), ident=100 + n)


def inner_ipv6(n=0):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    u = udp(40000 + n, 5000, b'v6payload')
    pseudo = src + dst + struct.pack('!IBBBB', len(u), 0, 0, 0, 17)
    u = u[:6] + struct.pack('!H', csum(pseudo + u) or 0xffff) + u[8:]
    return struct.pack('!IHBB', 0x60000000, len(u), 17, 64) + src + dst + u


def inner_eth(n=0):
    return eth(inner_ipv4(n), dst='02:00:00:00:00:12', src='02:00:00:00:00:11')


def nsh(nextp, body, mdtype=1, spi=0x123456, si=255, ttl=63, oam=0, crit=0, ver=0, length=None,
        unassigned=0, payload=b''):
    """body: the context headers (MD type 1: 16 octets) or the TLVs. The
    length field counts 4 octet words of the whole header; override with
    length=."""
    words = 2 + (len(body) + 3) // 4
    n = words if length is None else length
    b0 = (ver << 6) | (oam << 5) | (crit << 4) | (ttl >> 2)
    b1 = ((ttl & 3) << 6) | (n & 0x3f)
    md = (unassigned << 4) | (mdtype & 0xf)
    return struct.pack('!BBBB', b0, b1, md, nextp) + struct.pack('!I', (spi << 8) | si) + body + b'\0' * (-len(body) % 4) + payload


def ctx(*words):
    return b''.join(struct.pack('!I', w) for w in words)


def tlv(cls, typ, data, rbit=0, length=None):
    n = len(data) if length is None else length
    return struct.pack('!HBB', cls, typ, (rbit << 7) | n) + data + b'\0' * (-len(data) % 4)


def fwd(ct, rest=b'\0\0\0'):
    return tlv(0, 4, bytes([ct << 4]) + rest)


RANGES = []


class Cap:
    def __init__(self, name):
        self.name, self.frames = name, []

    def add(self, fr):
        self.frames.append(fr)
        return len(self.frames)

    def group(self, text):
        first = len(self.frames) + 1
        return lambda: RANGES.append((self.name, first, len(self.frames), text))

    def save(self):
        with open(os.path.join(OUT, self.name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)


def on_eth(n):
    return eth(n, 0x894F)


def main():
    os.makedirs(OUT, exist_ok=True)
    c = Cap('nsh-coverage.pcap')
    CTX = ctx(0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10)

    g = c.group('MD type 1 over Ethernet: IPv4, IPv6, Ethernet, MPLS, none, experiments (data), flags (OAM, critical), TTL, SPI/SI')
    c.add(on_eth(nsh(1, CTX, payload=inner_ipv4(1))))
    c.add(on_eth(nsh(2, CTX, payload=inner_ipv6(2), ttl=1, spi=0xffffff, si=0)))
    c.add(on_eth(nsh(3, CTX, payload=inner_eth(3), oam=1, crit=1, ttl=0)))
    c.add(on_eth(nsh(5, CTX, payload=b'\x00\x01\x01\x40' + inner_ipv4(3))))
    c.add(on_eth(nsh(0, CTX, payload=b'')))
    c.add(on_eth(nsh(0, CTX, payload=b'\xde\xad\xbe\xef')))
    c.add(on_eth(nsh(0xfe, CTX, payload=b'experiment 1')))
    c.add(on_eth(nsh(0xff, CTX, payload=b'experiment 2')))
    c.add(on_eth(nsh(1, CTX, payload=inner_ipv4(4), ttl=63, spi=1, si=1)))
    g()
    g = c.group('MD type: unassigned high bits (the MD type is the low 4 bits), unknown MD types 0, 3 and 15, MD type 2 without TLVs')
    c.add(on_eth(nsh(1, CTX, payload=inner_ipv4(5), unassigned=0xa)))
    c.add(on_eth(nsh(1, tlv(0, 5, b'ten1'), mdtype=2, payload=inner_ipv4(6), unassigned=0x5)))
    c.add(on_eth(nsh(1, b'', mdtype=0, payload=inner_ipv4(7))))
    c.add(on_eth(nsh(1, b'\x11\x22\x33\x44', mdtype=3, payload=inner_ipv4(8))))
    c.add(on_eth(nsh(1, b'\x11\x22\x33\x44' * 3, mdtype=15, payload=inner_ipv4(9))))
    c.add(on_eth(nsh(1, b'', mdtype=2, payload=inner_ipv4(10))))      # length 2: no TLVs
    g()
    g = c.group('MD type 2 TLVs (RFC 9263): forwarding context types 0-5, tenant id, ingress node info and source interface, flow id types 0-2, groups, policy id')
    for ct in range(6):
        c.add(on_eth(nsh(1, (tlv(0, 4, bytes([4 << 4, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd])) if ct == 4 else fwd(ct, b'\x00\x0a\x0b')),
                         mdtype=2, payload=inner_ipv4(11 + ct))))
    c.add(on_eth(nsh(1, tlv(0, 5, b'tenant-01'), mdtype=2, payload=inner_ipv4(20))))
    c.add(on_eth(nsh(1, tlv(0, 6, bytes(range(8))) + tlv(0, 7, bytes(range(16, 20))), mdtype=2, payload=inner_ipv4(21))))
    for ft in range(3):
        c.add(on_eth(nsh(1, tlv(0, 8, bytes([ft << 4, 0x0a, 0xbc, 0xde])), mdtype=2, payload=inner_ipv4(22 + ft))))
    c.add(on_eth(nsh(1, tlv(0, 9, bytes(range(1, 9))) + tlv(0, 10, b'policy-17'), mdtype=2, payload=inner_ipv4(25))))
    g()
    g = c.group('MD type 2 TLVs (BBF TR-459i2): logical port (printable and binary), MAC, network instance, interface identifier; unknown class and type; empty TLV; several TLVs; R bit in the length')
    c.add(on_eth(nsh(1, tlv(0x0200, 0, b'eth0/1'), mdtype=2, payload=inner_ipv4(26))))
    c.add(on_eth(nsh(1, tlv(0x0200, 0, b'\x01\x02\x03\xff'), mdtype=2, payload=inner_ipv4(27))))
    c.add(on_eth(nsh(1, tlv(0x0200, 1, b'\x02\x00\x00\x00\x00\x99') + tlv(0x0200, 2, b'vrf-blue')
                     + tlv(0x0200, 3, bytes(range(8))), mdtype=2, payload=inner_ipv4(28))))
    c.add(on_eth(nsh(1, tlv(0x1234, 0x56, b'unknown tlv data') + tlv(0x1234, 0x57, b'') + tlv(0x1234, 0x58, b'abc'),
                     mdtype=2, payload=inner_ipv4(29))))
    c.add(on_eth(nsh(1, tlv(0, 5, b'tenant', rbit=1), mdtype=2, payload=inner_ipv4(30))))
    c.add(on_eth(nsh(1, fwd(3, b'\x00\x00\x2a') + tlv(0, 5, b'abcd') + tlv(0, 10, b'x') + tlv(0x0200, 0, b'p'),
                     mdtype=2, payload=inner_ipv4(31))))
    g()
    g = c.group('NSH carried by GRE (0x894F), IP protocol 145, VXLAN-GPE (UDP 4790), GTP-U (heuristic), NSH in NSH; ethertype in a second frame')
    GRE = lambda p: struct.pack('!HH', 0, 0x894F) + p
    c.add(eth(ipv4(47, GRE(nsh(1, CTX, payload=inner_ipv4(40))))))
    c.add(eth(ipv4(145, nsh(1, CTX, payload=inner_ipv4(41)))))
    gpe = lambda nxt, p: bytes([0x0c, 0, 0, nxt]) + b'\x00\x00\x2a\x00' + p
    c.add(eth(ipv4(17, udp(40000, 4790, gpe(4, nsh(3, CTX, payload=inner_eth(42)))))))
    c.add(eth(ipv4(17, udp(40000, 4790, gpe(4, nsh(1, tlv(0, 5, b'abcd'), mdtype=2, payload=inner_ipv4(43)))))))
    gtp = lambda p: struct.pack('!BBHI', 0x30, 0xff, len(p), 0x1000) + p
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(nsh(1, CTX, payload=inner_ipv4(44)))))))
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(nsh(1, tlv(0, 5, b'abcd'), mdtype=2, payload=inner_ipv6(45)))))))
    c.add(on_eth(nsh(4, CTX, payload=nsh(1, CTX, payload=inner_ipv4(46)))))     # NSH in NSH
    c.add(on_eth(nsh(4, CTX, payload=nsh(4, CTX, payload=nsh(1, CTX, payload=inner_ipv4(47))))))
    g()
    g = c.group('GTP-U payloads the heuristic rejects: IPv4 data, too short, version 1, MD type 3, MD type 1 with the wrong length, MD type 2 with length 1, length longer than the payload, next protocol 0 and above 5')
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(inner_ipv4(50))))))
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(b'\x00\x02\x01\x01\x00\x00\x01')))))
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(b'\x40' + nsh(1, CTX, payload=inner_ipv4(51))[1:])))))
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(nsh(1, CTX, mdtype=3, payload=inner_ipv4(52)))))))
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(nsh(1, CTX, length=5, payload=inner_ipv4(53)))))))
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(nsh(1, tlv(0, 5, b'abcd'), mdtype=2, length=1, payload=inner_ipv4(54)))))))
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(nsh(1, CTX, length=63, payload=inner_ipv4(55)))))))
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(nsh(0, CTX, payload=inner_ipv4(56)))))))
    c.add(eth(ipv4(17, udp(2152, 2152, gtp(nsh(6, CTX, payload=inner_ipv4(57)))))))
    g()
    c.save()

    m = Cap('nsh-coverage-malformed.pcap')
    g = m.group('invalid lengths (warnings): MD type 1 with length 5 and 7, MD type 2 with length 1, unknown MD type with length 0')
    m.add(on_eth(nsh(1, CTX, length=5, payload=inner_ipv4(60))))
    m.add(on_eth(nsh(1, CTX, length=7, payload=inner_ipv4(61))))
    m.add(on_eth(nsh(1, b'', mdtype=2, length=1, payload=inner_ipv4(62))))
    m.add(on_eth(nsh(1, b'', mdtype=0, length=0, payload=inner_ipv4(63))))
    m.add(on_eth(nsh(1, b'', mdtype=2, length=0, payload=inner_ipv4(64))))
    g()
    g = m.group('TLVs the TLV dissector does not consume fully (incomplete dissection warnings), TLVs longer than the header, truncated headers')
    m.add(on_eth(nsh(1, tlv(0, 4, bytes([0, 0, 1, 0, 0, 0, 0, 0])), mdtype=2, payload=inner_ipv4(65))))   # VLAN context in 8 octets
    m.add(on_eth(nsh(1, tlv(0, 9, bytes(range(12))), mdtype=2, payload=inner_ipv4(66))))                  # groups: 12 octets, 8 used
    m.add(on_eth(nsh(1, tlv(0, 5, b'abcd', length=100), mdtype=2, payload=inner_ipv4(67))))               # TLV longer than the header
    m.add(on_eth(nsh(1, tlv(0x0200, 1, b'\x02\x00\x00'), mdtype=2, payload=inner_ipv4(68))))              # MAC in 3 octets
    m.add(on_eth(nsh(1, tlv(0, 4, b''), mdtype=2, payload=inner_ipv4(69))))                               # empty forwarding context
    m.add(on_eth(nsh(1, tlv(0, 4, bytes([4 << 4, 0, 0, 0])), mdtype=2, payload=inner_ipv4(70))))          # session id context in 4 octets
    m.add(on_eth(nsh(1, tlv(0, 8, b'\x00'), mdtype=2, payload=inner_ipv4(71))))                           # flow id in 1 octet
    m.add(on_eth(nsh(1, tlv(0x0200, 3, b'\x01\x02\x03'), mdtype=2, payload=inner_ipv4(72))))              # interface id in 3 octets
    m.add(on_eth(nsh(1, CTX)[:6]))                                                                        # cut in the base header
    m.add(on_eth(nsh(1, CTX)[:12]))                                                                       # cut in the context headers
    m.add(on_eth(nsh(1, tlv(0, 5, b'abcdefgh'), mdtype=2)[:10]))
    m.add(on_eth(nsh(1, tlv(0, 5, b'abcdefgh'), mdtype=2)[:14]))
    m.add(on_eth(nsh(1, tlv(0, 5, b'abcdefgh'), mdtype=2)[:18]))
    g()
    m.save()
    if VERBOSE:
        for r in RANGES:
            print(*r)
        print(len(c.frames), len(m.frames))


main()
