#!/usr/bin/env python3
# Generates test/captures/teredo_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Teredo coverage captures. Usage: mkteredo.py <outdir>
All packets are built with struct; nothing comes from a real network."""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip6(src, dst, nh, payload, hlim=64):
    return struct.pack('!IHBB', 0x60000000, len(payload), nh, hlim) + src + dst + payload

def udp6(src, dst, sport, dport, payload):
    ln = 8 + len(payload)
    pseudo = src + dst + struct.pack('!IHBB', ln, 0, 0, 17)
    c = csum(pseudo + struct.pack('!HHHH', sport, dport, ln, 0) + payload) or 0xffff
    return struct.pack('!HHHH', sport, dport, ln, c) + payload

def icmp6_echo(src, dst, typ=128, ident=1, seq=1, data=b'teredo'):
    body = struct.pack('!BBHHH', typ, 0, 0, ident, seq) + data
    pseudo = src + dst + struct.pack('!IHBB', len(body), 0, 0, 58)
    c = csum(pseudo + body)
    return body[:2] + struct.pack('!H', c) + body[4:]

def udp4(sport, dport, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    ln = 8 + len(payload)
    s, d = bytes(src), bytes(dst)
    pseudo = s + d + struct.pack('!BBH', 0, 17, ln)
    c = csum(pseudo + struct.pack('!HHHH', sport, dport, ln, 0) + payload) or 0xffff
    return struct.pack('!HHHH', sport, dport, ln, c) + payload

def ip4(payload, proto=17, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

ETH4 = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
ETH6 = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x86\xdd'

def eth_udp4(sport, dport, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    return ETH4 + ip4(udp4(sport, dport, payload, src, dst), 17, src, dst)

def write(fn, frames, linktype=1):
    with open(os.path.join(OUT, fn), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# Teredo client addresses: 2001:0:c000:201:... (server 192.0.2.1)
CL = bytes.fromhex('20010000c0000201000000000a0b0c0d')
PEER = bytes.fromhex('20010db8000000000000000000000002')
PEER2 = bytes.fromhex('fe80000000000000000000000a0b0c0d')

def echo(src=CL, dst=PEER, typ=128, seq=1):
    return ip6(src, dst, 58, icmp6_echo(src, dst, typ, seq=seq))

def auth(idlen=0, aulen=0, conf=0, nonce=b'\x01\x02\x03\x04\x05\x06\x07\x08'):
    return (struct.pack('!HBB', 1, idlen, aulen) + bytes(range(0x40, 0x40 + idlen)) +
            bytes(range(0x80, 0x80 + aulen)) + nonce + bytes([conf]))

def orig(port=40000, addr=(198, 51, 100, 7)):
    return struct.pack('!HH', 0, port ^ 0xffff) + bytes(b ^ 0xff for b in addr)

def nested(levels, inner):
    """IPv6 / UDP 3544 / Teredo / IPv6 ... 'levels' times."""
    pkt = inner
    for _ in range(levels):
        u = udp6(CL, PEER, 3544, 3544, pkt)
        pkt = ip6(CL, PEER, 17, u)
    return pkt

main = []
# 1-2: plain IPv6 in Teredo, echo request and reply
main.append(eth_udp4(3544, 3544, echo(CL, PEER, 128, 1)))
main.append(eth_udp4(3544, 3544, echo(PEER, CL, 129, 1)))
# 3: authentication header, no client id, no value (nonce + confirmation 0)
main.append(eth_udp4(3544, 3544, auth() + echo(CL, PEER2, 128, 2)))
# 4: authentication header with a client id and an authentication value, conf 1
main.append(eth_udp4(3544, 3544, auth(4, 8, 1) + echo(PEER2, CL, 129, 2)))
# 5: origin indication
main.append(eth_udp4(3544, 3544, orig() + echo(PEER, CL, 129, 3)))
# 6: authentication header and origin indication
main.append(eth_udp4(3544, 3544, auth(2, 0) + orig(1234, (203, 0, 113, 9)) + echo(PEER, CL, 129, 4)))
# 7: bubble: IPv6 header with next header "no next header" and no payload
main.append(eth_udp4(3544, 3544, ip6(CL, PEER, 59, b'')))
# 8: Teredo carrying a UDP datagram that is itself Teredo (one level)
main.append(eth_udp4(3544, 3544, nested(1, echo(CL, PEER, 128, 5))))
# 9: Teredo over IPv6 (an IPv6 packet with UDP 3544)
main.append(ETH6 + ip6(PEER, CL, 17, udp6(PEER, CL, 3544, 3544, echo(PEER, CL, 129, 6))))
# 10: source port other than 3544, destination 3544
main.append(eth_udp4(50000, 3544, echo(CL, PEER, 128, 7)))
# 11-13: the heuristic (disabled by default; "teredo_udp"), a port with no dissector
main.append(eth_udp4(4000, 4001, echo(CL, PEER, 128, 8)))
main.append(eth_udp4(4000, 4001, auth(1, 1) + orig() + echo(CL, PEER, 128, 9)))
main.append(eth_udp4(4000, 4001, orig() + echo(PEER, CL, 129, 10)))
# 14-19: payloads the heuristic rejects (plain UDP data):
#   shorter than 40, not IPv6 (first nibble), IPv6 length mismatch,
#   IPv6 length too big, auth header too short for its lengths, origin
#   indication too short
main.append(eth_udp4(4000, 4001, b'\x60' + b'\0' * 38))
main.append(eth_udp4(4000, 4001, b'\x45' + b'\0' * 59))
bad = bytearray(echo()); bad[4:6] = struct.pack('!H', 99)
main.append(eth_udp4(4000, 4001, bytes(bad)))
big = bytearray(echo()); big[4:6] = struct.pack('!H', 65500)
main.append(eth_udp4(4000, 4001, bytes(big)))
main.append(eth_udp4(4000, 4001, struct.pack('!HBB', 1, 40, 40) + b'\0' * 40))
main.append(eth_udp4(4000, 4001, orig() + b'\x60' + b'\0' * 31))
# 20: reproducer of the nesting bug: 12 levels (the limit is 8); the
# fixed dissector stops with the "Too many nested Teredo headers" expert info
main.append(eth_udp4(3544, 3544, nested(12, echo(CL, PEER, 128, 11))))
# 21: nesting exactly at the limit (8 Teredo layers), no expert info
main.append(eth_udp4(3544, 3544, nested(7, echo(CL, PEER, 128, 12))))
write('teredo-coverage.pcap', main)

mal = []
# 1: Teredo with a single octet
mal.append(eth_udp4(3544, 3544, b'\x60'))
# 2: authentication header cut off after the lengths
mal.append(eth_udp4(3544, 3544, struct.pack('!HBB', 1, 0, 0) + b'\x01\x02'))
# 3: authentication header whose lengths run past the packet
mal.append(eth_udp4(3544, 3544, struct.pack('!HBB', 1, 200, 200) + b'\x01' * 20))
# 4: origin indication cut off
mal.append(eth_udp4(3544, 3544, struct.pack('!HH', 0, 5)))
# 5: authentication header, then nothing for the next header
mal.append(eth_udp4(3544, 3544, auth()))
# 6: Teredo whose IPv6 payload is truncated
mal.append(eth_udp4(3544, 3544, echo()[:30]))
# 7: nested far past the limit, 40 levels
mal.append(eth_udp4(3544, 3544, nested(40, echo())))
write('teredo-coverage-malformed.pcap', mal)
print(len(main), len(mal))
