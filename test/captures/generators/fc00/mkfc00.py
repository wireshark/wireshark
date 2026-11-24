#!/usr/bin/env python3
# Generates test/captures/fc00_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Fc00 CryptoAuth (cjdns)
dissector (packet-fc00.c).

The dissector has no default port: it is only registered for Decode As
on UDP ports (and its udp.port preference), so the captures use UDP
port 5555 and are dissected with -d udp.port==5555,fc00. Only the
CryptoAuth header is dissected; the keys, nonce and payload octets are
made-up bytes (no real keys, no ciphertext is produced).

Usage: mkfc00.py <output directory>
  fc00-coverage.pcap            handshake headers (session state 0-3 and
                                0xffffffff), data packets (nonce >= 4),
                                all challenge fields
  fc00-coverage-malformed.pcap  packets shorter than the header
"""
import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
PORT = 5555


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ipsum(h):
    s = sum(struct.unpack('>10H', h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp(payload, sport=PORT + 1, dport=PORT, a_to_b=True):
    ulen = 8 + len(payload)
    u = struct.pack('>HHHH', sport, dport, ulen, 0) + payload
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + ulen, 1, 0x4000, 64, 17, 0) + \
        bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2])
    ip = ip[:10] + struct.pack('>H', ipsum(ip)) + ip[12:]
    return MAC_B + MAC_A + b'\x08\x00' + ip + u


def header(state, auth_type=1, hashcode=b'\x11' * 7, poly=0, deriv=0, additional=0,
           nonce=None, key=None, auth=None, temp=None, payload=b'', plbyte=0x80):
    """The 120 octet CryptoAuth header plus payload. Octet 12 of the
    challenge: bit 7 poly1305 flag, low 15 bits (with the next octet) the
    derivation count."""
    chal = bytes([auth_type]) + hashcode + struct.pack('>H', (plbyte if poly else 0) << 8 & 0x8000 | deriv) + \
        struct.pack('>H', additional)
    return struct.pack('>I', state) + chal + (nonce or bytes(range(24))) + \
        (key or bytes(range(32, 64))) + (auth or bytes(range(100, 116))) + \
        (temp or bytes(range(200, 232))) + payload


main = [
    # 1-5: session states Hello, Hello, repeated Hello, Key, repeated Key, Connect To Me
    udp(header(0, payload=b'\xaa' * 16)),
    udp(header(1, payload=b'\xbb' * 8), a_to_b=False),
    udp(header(2)),
    udp(header(3, payload=b'\xcc' * 40), a_to_b=False),
    udp(header(0xffffffff, payload=b'\xdd' * 4)),
    # derivations 127 and below, and 128 and above (fixed mask 0x7FFF)
    udp(header(1, deriv=5, additional=7)),
    udp(header(1, deriv=127)),
    udp(header(1, deriv=128)),
    udp(header(1, deriv=0x1234, additional=0xffff)),
    udp(header(1, deriv=0x7fff, poly=1)),
    udp(header(1, auth_type=0, poly=1)),
    # data packets: nonce (session state) > 3 and below 0xffffffff
    udp(header(4)[:4] + b'\xee' * 30),
    udp(header(0x12345678)[:4] + b'\x01\x02\x03\x04'),
    udp(header(0xfffffffe)[:4] + b'\x00' * 100, a_to_b=False),
    # 4 octets only (empty payload)
    udp(struct.pack('>I', 99)),
    # exactly the header, payload of one octet
    udp(header(0, payload=b'\x42')),
    # no payload
    udp(header(1)),
    # other source port (reply)
    udp(header(3, payload=b'reply'), sport=PORT, dport=PORT + 1, a_to_b=False),
]

malformed = [
    # shorter than the 4 octet session state
    udp(b'\x00\x00'),
    # handshake state with a header cut at the challenge
    udp(struct.pack('>I', 0) + bytes(6)),
    # cut in the nonce
    udp(header(0)[:30]),
    # cut in the public key
    udp(header(1)[:60]),
    # cut before the temporary key
    udp(header(2)[:100]),
    # header cut in the temporary public key
    udp(header(3)[:110]),
]

if __name__ == '__main__':
    out = sys.argv[1]
    pcap(os.path.join(out, 'fc00-coverage.pcap'), main)
    pcap(os.path.join(out, 'fc00-coverage-malformed.pcap'), malformed)
