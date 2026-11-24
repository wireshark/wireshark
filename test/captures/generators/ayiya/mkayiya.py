#!/usr/bin/env python3
# Generates test/captures/ayiya_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the AYIYA (Anything In
Anything) dissector (packet-ayiya.c).

All packets are built from scratch with struct; no captured traffic is
used. A tunnel client (192.0.2.10) and a tunnel server (198.51.100.1)
exchange AYIYA on UDP port 5072; forwarded packets carry IPv6 (and IPv4)
between 2001:db8::2 and 2001:db8::1.

Usage: mkayiya.py <output directory>

Writes:
  ayiya-coverage.pcap            every operation code, identity type, hash
                                 and authentication method, identity and
                                 signature lengths, forwarded IPv6, IPv4
                                 and nested AYIYA payloads, and (last
                                 frame) the nesting reproducer that stops
                                 with the "ayiya.expert.too_deep" warning
  ayiya-coverage-malformed.pcap  truncated packets (exceptions)
"""

import struct
import sys

PORT = 5072
CLIENT = (192, 0, 2, 10)
SERVER = (198, 51, 100, 1)
V6_CLIENT = bytes.fromhex('20010db8000000000000000000000002')
V6_SERVER = bytes.fromhex('20010db8000000000000000000000001')
EPOCH = 1700000000


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def udp4(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(u)) + u) or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]


def ipv6(src, dst, nh, payload):
    return struct.pack('>IHBB16s16s', 0x60000000, len(payload), nh, 64, src, dst) + payload


def l4_6(src, dst, nh, l4, cs_off):
    pseudo = struct.pack('>16s16sIxxxB', src, dst, len(l4), nh)
    c = csum(pseudo + l4) or 0xffff
    return l4[:cs_off] + struct.pack('>H', c) + l4[cs_off + 2:]


def icmp6_echo(src, dst, typ, ident, seq, data):
    return ipv6(src, dst, 58, l4_6(src, dst, 58, struct.pack('>BBHHH', typ, 0, 0, ident, seq) + data, 2))


def udp6(src, dst, sport, dport, data):
    return ipv6(src, dst, 17, l4_6(src, dst, 17, struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data, 6))


def icmp4_echo(src, dst, typ, ident, seq, data):
    m = struct.pack('>BBHHH', typ, 0, 0, ident, seq) + data
    return ipv4(src, dst, 1, m[:2] + struct.pack('>H', csum(m)) + m[4:])


def ayiya(opcode, nh, payload=b'', idlen_exp=4, idtype=1, identity=None,
          siglen_words=5, hash_method=2, auth=1, signature=None, epoch=EPOCH):
    idlen = 1 << idlen_exp
    if identity is None:
        identity = V6_CLIENT
    identity = (identity + b'\0' * idlen)[:idlen]
    siglen = siglen_words * 4
    if signature is None:
        signature = bytes((0x11 * (i + 1)) & 0xff for i in range(siglen))
    return struct.pack('>BBBBI', idlen_exp << 4 | idtype, siglen_words << 4 | hash_method,
                       auth << 4 | opcode, nh, epoch) + identity + signature[:siglen] + payload


class Pcap:
    def __init__(self):
        self.frames = []

    def ayiya(self, payload, to_server=True):
        src, dst = (CLIENT, SERVER) if to_server else (SERVER, CLIENT)
        self.ip(ipv4(src, dst, 17, udp4(src, dst, PORT, PORT, payload), len(self.frames) + 1))

    def ip(self, ip):
        eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
        self.frames.append(eth + ip)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', EPOCH + i, 0, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def nested(levels):
    """The reproducer from ayiya_nested.py: AYIYA forwarding IPv4
    with UDP to port 5072 carrying AYIYA again, levels deep."""
    def ayiya0(inner):
        # idlen 1, idtype none, siglen 0, no hash, no auth, forward IPv4
        return bytes([0x00, 0x00, 0x01, 4]) + struct.pack('>I', 0) + b'\0' + inner

    def ip0(payload):
        return ipv4((192, 0, 2, 1), (198, 51, 100, 1), 17, payload)

    def udp0(payload, sport, dport):
        return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    inner = udp0(b'', 1234, 9)
    for _ in range(levels):
        inner = udp0(ayiya0(ip0(inner)), PORT, PORT)
    return ip0(inner)


def main_capture():
    c = Pcap()
    data = bytes(range(32))
    # 1-2: heartbeat both ways: 16 octet integer identity, SHA1 shared secret
    c.ayiya(ayiya(0, 59))
    c.ayiya(ayiya(0, 59, identity=V6_SERVER), to_server=False)
    # 3-4: forward IPv6 ICMPv6 echo request and reply
    c.ayiya(ayiya(1, 41, icmp6_echo(V6_CLIENT, V6_SERVER, 128, 0x1234, 1, data)))
    c.ayiya(ayiya(1, 41, icmp6_echo(V6_SERVER, V6_CLIENT, 129, 0x1234, 1, data), identity=V6_SERVER),
            to_server=False)
    # 5: forward IPv6 UDP (DNS port, but not a DNS message: use port 9, discard)
    c.ayiya(ayiya(1, 41, udp6(V6_CLIENT, V6_SERVER, 40000, 9, b'discard me')))
    # 6-7: forward IPv4 ICMP echo request and reply, MD5 signature, 4 octet identity
    c.ayiya(ayiya(1, 4, icmp4_echo((10, 0, 0, 2), (10, 0, 0, 1), 8, 7, 1, data),
                  idlen_exp=2, identity=bytes([10, 0, 0, 2]), siglen_words=4, hash_method=1))
    c.ayiya(ayiya(1, 4, icmp4_echo((10, 0, 0, 1), (10, 0, 0, 2), 0, 7, 1, data),
                  idlen_exp=2, identity=bytes([10, 0, 0, 1]), siglen_words=4, hash_method=1),
            to_server=False)
    # 8: forward with an unregistered next header (253, experimentation)
    c.ayiya(ayiya(1, 253, b'\x01\x02\x03\x04'))
    # 9-10: echo request, echo request and forward (payload not dissected)
    c.ayiya(ayiya(2, 59))
    c.ayiya(ayiya(3, 41, icmp6_echo(V6_CLIENT, V6_SERVER, 128, 0x1234, 2, data)))
    # 11: echo response
    c.ayiya(ayiya(4, 59, identity=V6_SERVER), to_server=False)
    # 12: MOTD, ASCII string identity, public key authentication
    c.ayiya(ayiya(5, 59, b'Welcome to the synthetic tunnel broker\n', idlen_exp=3, idtype=2,
                  identity=b'T12345\0\0', auth=2), to_server=False)
    # 13-14: query request and response
    c.ayiya(ayiya(6, 59, b'\x00\x01'))
    c.ayiya(ayiya(7, 59, b'\x00\x01ok', identity=V6_SERVER), to_server=False)
    # 15: no identity type, no hash, no authentication, no signature
    c.ayiya(ayiya(0, 59, idlen_exp=0, idtype=0, identity=b'\0', siglen_words=0, hash_method=0, auth=0))
    # 16: unknown identity type, hash and authentication methods, opcode 8
    c.ayiya(ayiya(8, 59, idtype=3, hash_method=3, auth=3))
    # 17: opcode 15, a 256 octet identity and the largest signature (60)
    c.ayiya(ayiya(15, 59, idlen_exp=8, identity=b'big identity', siglen_words=15))
    # 18-19: AYIYA forwarding IPv4/UDP to port 5072 carrying AYIYA
    # forwarding IPv6 ICMPv6 echo request and reply
    inner = ayiya(1, 41, icmp6_echo(V6_CLIENT, V6_SERVER, 128, 0x1234, 3, data))
    c.ayiya(ayiya(1, 4, ipv4((10, 0, 0, 2), (10, 0, 0, 1), 17, udp4((10, 0, 0, 2), (10, 0, 0, 1),
                                                                       PORT, PORT, inner))))
    inner = ayiya(1, 41, icmp6_echo(V6_SERVER, V6_CLIENT, 129, 0x1234, 3, data), identity=V6_SERVER)
    c.ayiya(ayiya(1, 4, ipv4((10, 0, 0, 1), (10, 0, 0, 2), 17, udp4((10, 0, 0, 1), (10, 0, 0, 2),
                                                                       PORT, PORT, inner))),
            to_server=False)
    # 20: the nesting reproducer, 200 levels: stops after 160 with the
    # "Payload nested too deep" warning (used to fail DISSECTOR_ASSERT in
    # call_dissector_work)
    c.ip(nested(200))
    return c


def malformed_capture():
    c = Pcap()
    # 1: identity length 32768 (exponent 15) and a 60 octet signature, short
    #    (from ayiya_nested.py)
    c.ayiya(bytes([0xf2, 0xf1, 0x01, 4]) + b'\0' * 8 + b'A' * 100)
    # 2: three octets, no next header
    c.ayiya(b'\x41\x52\x01')
    # 3: header cut in the epoch
    c.ayiya(b'\x41\x52\x01\x29\x00\x00')
    # 4: identity cut short
    c.ayiya(ayiya(0, 59)[:16])
    # 5: forward of a truncated IPv6 header
    c.ayiya(ayiya(1, 41, icmp6_echo(V6_CLIENT, V6_SERVER, 128, 1, 1, b'')[:20]))
    return c


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(out + '/ayiya-coverage.pcap')
    malformed_capture().write(out + '/ayiya-coverage-malformed.pcap')
