#!/usr/bin/env python3
# Generates test/captures/bt_dht_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BitTorrent DHT dissector
(packet-bt-dht.c).

All packets are built from scratch with struct; no captured traffic is
used. DHT nodes 192.0.2.10:6881, 198.51.100.20:51413 and
203.0.113.30:6889 exchange KRPC messages (BEP 5, BEP 32 nodes6, BEP 42
"ip", BEP 51 sample_infohashes) over UDP. BT-DHT has no default port and
its heuristic is disabled by default: dissect with
"--enable-heuristic bittorrent_dht_udp" (or Decode As with
"-d udp.port==6881,bt-dht").

Usage: mkbt_dht.py <output directory>

Writes:
  bt_dht-coverage.pcap            every message type and special key, the
                                  client version table, sub-lists and
                                  sub-dictionaries, the dictionary key order
                                  checks, non-DHT data in a DHT conversation,
                                  and the "unterminated dictionary"
                                  reproducer (bt_dht_small.py)
  bt_dht-coverage-malformed.pcap  error paths (bad lengths, truncation, the
                                  error list terminator reproducer and the
                                  length wrap reproducers)
"""

import struct
import sys

EPOCH = 1700000000
A = ((192, 0, 2, 10), 6881)
B = ((198, 51, 100, 20), 51413)
C = ((203, 0, 113, 30), 6889)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def udp4(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(u)) + u) or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]


def benc(v):
    """Bencode; dicts keep insertion order (so unsorted keys are possible),
    a list of (key, value) tuples wrapped in Raw gives duplicate keys."""
    if isinstance(v, int):
        return b'i%de' % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b'%d:' % len(v) + v
    if isinstance(v, list):
        return b'l' + b''.join(benc(x) for x in v) + b'e'
    if isinstance(v, dict):
        return b'd' + b''.join(benc(k) + benc(x) for k, x in v.items()) + b'e'
    if isinstance(v, Pairs):
        return b'd' + b''.join(benc(k) + benc(x) for k, x in v.pairs) + b'e'
    raise TypeError(v)


class Pairs:
    def __init__(self, *pairs):
        self.pairs = pairs


def nid(n):
    return bytes((n * 17 + i) & 0xff for i in range(20))


def compact4(ip, port):
    return bytes(ip) + struct.pack('>H', port)


V6A = bytes.fromhex('20010db8000000000000000000000010')
V6B = bytes.fromhex('20010db8000000000000000000000020')


def compact6(ip6, port):
    return ip6 + struct.pack('>H', port)


INFO = bytes.fromhex('0123456789abcdef0123456789abcdef01234567')


class Pcap:
    def __init__(self):
        self.frames = []

    def udp(self, src, dst, payload):
        ip = ipv4(src[0], dst[0], 17, udp4(src[0], dst[0], src[1], dst[1], payload),
                  len(self.frames) + 1)
        eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
        self.frames.append(eth + ip)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', EPOCH + i, 0, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def main_capture():
    c = Pcap()
    # 1-2: ping query and response, uTorrent and libtorrent versions
    c.udp(A, B, benc({'a': {'id': nid(1)}, 'q': 'ping', 't': b'aa', 'v': b'UT\x0b\x22', 'y': 'q'}))
    c.udp(B, A, benc({'ip': compact4(A[0], A[1]), 'r': {'id': nid(2)}, 't': b'aa',
                      'v': b'LT\x01\x23', 'y': 'r'}))
    # 3-4: find_node with "want"; response with 2 IPv4 nodes and 2 IPv6 nodes
    # (BEP 32), rTorrent version
    c.udp(A, B, benc({'a': {'id': nid(1), 'target': nid(9), 'want': ['n4', 'n6']},
                      'q': 'find_node', 't': b'ab', 'v': b'lt\x0d\x60', 'y': 'q'}))
    c.udp(B, A, benc({'r': {'id': nid(2),
                            'nodes': nid(3) + compact4((203, 0, 113, 1), 6881)
                            + nid(4) + compact4((203, 0, 113, 2), 6882),
                            'nodes6': nid(5) + compact6(V6A, 6881) + nid(6) + compact6(V6B, 6883)},
                      't': b'ab', 'y': 'r'}))
    # 5-6: get_peers; response with a token and IPv4 and IPv6 peers and one
    # value of another length; Monotorrent version (6 octets)
    c.udp(A, B, benc({'a': {'id': nid(1), 'info_hash': INFO}, 'q': 'get_peers', 't': b'ac',
                      'v': b'MO1234', 'y': 'q'}))
    c.udp(B, A, benc({'r': {'id': nid(2), 'token': b'\xde\xad\xbe\xef',
                            'values': [compact4((198, 51, 100, 7), 6881),
                                       compact4((198, 51, 100, 8), 51413),
                                       compact6(V6A, 6890), b'odd']},
                      't': b'ac', 'y': 'r'}))
    # 7-8: get_peers response with nodes (no peers) and a trailing partial
    # node; the BEP 42 "ip" as IPv6 (18 octets); XDHT version
    c.udp(A, B, benc({'a': {'id': nid(1), 'info_hash': INFO}, 'q': 'get_peers', 't': b'ad',
                      'v': b'XDHT', 'y': 'q'}))
    c.udp(B, A, benc({'ip': compact6(V6A, 6881),
                      'r': {'id': nid(2), 'nodes': nid(7) + compact4((203, 0, 113, 3), 6881)
                            + b'\x01\x02\x03', 'token': b'tok1'},
                      't': b'ad', 'y': 'r'}))
    # 9-10: announce_peer with implied_port; response with an empty values list
    c.udp(A, B, benc({'a': {'id': nid(1), 'implied_port': 1, 'info_hash': INFO, 'port': 6881,
                            'token': b'\xde\xad\xbe\xef'},
                      'q': 'announce_peer', 't': b'ae', 'y': 'q'}))
    c.udp(B, A, benc({'r': {'id': nid(2), 'values': []}, 't': b'ae', 'y': 'r'}))
    # 11-12: error messages (Generic Error, Protocol Error), unknown version
    # and a known client name with the wrong length
    c.udp(B, A, benc({'e': [201, 'A Generic Error Ocurred'], 't': b'af', 'v': b'ZZ\x00\x01',
                      'y': 'e'}))
    c.udp(C, A, benc({'e': [203, 'Protocol Error, such as a malformed packet'], 't': b'ag',
                      'v': b'LT\x01\x02\x03\x04', 'y': 'e'}))
    # 13: error 204 with an empty message
    c.udp(C, A, benc({'e': [204, ''], 't': b'ah', 'y': 'e'}))
    # 14-15: BEP 51 sample_infohashes query and response; the response has
    # an "ip" of another length (shown as hex)
    c.udp(A, C, benc({'a': {'id': nid(1), 'target': nid(10)}, 'q': 'sample_infohashes',
                      't': b'ai', 'y': 'q'}))
    c.udp(C, A, benc({'ip': b'\x01\x02\x03\x04', 'r': {'id': nid(11), 'interval': 21600,
                                                        'nodes': b'', 'num': 2,
                                                        'samples': INFO + nid(12)},
                      't': b'ai', 'y': 'r'}))
    # 16: a query with a one letter name, empty and nested lists and
    # dictionaries, integers and strings in lists
    c.udp(A, C, benc({'a': {'id': nid(1), 'list': [1, -2, 'str', [], ['x', [3]], {},
                                                   {'k': 'v', 'n': 0}],
                            'sub': {'deeper': {'z': 'end'}}, 'zero': b''},
                      'q': 'x', 't': b'aj', 'y': 'q'}))
    # 17: keys out of order (chat), 18: duplicate key (warning)
    c.udp(A, C, benc({'a': {'target': nid(9), 'id': nid(1)}, 'q': 'find_node', 't': b'ak',
                      'y': 'q'}))
    c.udp(A, C, benc(Pairs(('a', {'id': nid(1)}), ('q', 'ping'), ('t', b'al'), ('t', b'al'),
                           ('y', 'q'))))
    # 19: not DHT (uTP-like data) in the A<->B conversation: the dissector
    # set for the conversation rejects it, so it is Data
    c.udp(A, B, struct.pack('>BBHIII', 0x41, 0, 0x1234, 1, 2, 3))
    # 20: shorter than DHT_MIN_LEN
    c.udp(A, B, b'd1:a')
    # 21: the reproducer from bt_dht_small.py: a response
    # whose top level dictionary has no terminator. The tree shows it once
    # (no Data item, and with Decode As no second BT-DHT tree)
    c.udp(B, A, b'd1:rd2:id20:' + b'A' * 20 + b'e')
    # 22: a top level dictionary with only the BEP 42 "ip" key (the "d2:ip"
    # heuristic pattern)
    c.udp(C, B, benc({'ip': compact4(B[0], B[1])}))
    return c


def malformed_capture():
    c = Pcap()
    frames = [
        # bt_dht_small.py: 'X' where the error list 'e' belongs
        b'd1:eli201e5:helloX1:t2:aa1:y1:ee',
        # error list: bad error number, bad message length, message too long
        b'd1:el5:helloee',
        b'd1:eli201ex:helloee',
        b'd1:eli201e99:hiee',
        # error list ending after the error number
        b'd1:eli201e',
        # values: not a string inside
        b'd1:rd6:valueslxxee',
        # values truncated (runs off the end)
        b'd1:rd6:valuesl6:abcdef',
        # nodes / ip / v with no valid length
        b'd1:rd5:nodesxxe',
        b'd1:rd2:ipxxe',
        b'd1:rd1:vxxe',
        # v longer than the packet
        b'd1:rd1:v99:LTee',
        # key with a bad length, key that is not a string, key at the end
        b'd1:ad5x:abcee',
        b'd1:adi3e1:xee',
        b'd1:ad2:id',
        # string value longer than the packet
        b'd1:ad2:id99:abee',
        # int value without terminator; int too short
        b'd1:ad1:ni42',
        b'd1:ad1:ni',
        # list: too short, item fails, unterminated, sub-list fails
        b'd1:ad1:ll',
        b'd1:ad1:ll5:abee',
        b'd1:ad1:lli1e',
        b'd1:ad1:llixee',
        b'd1:ad1:lld1:xee',
        # sub-dictionary too short, entry fails, unterminated
        b'd1:ad1:dd',
        b'd1:ad1:dd1:xee',
        b'd1:ad1:dd1:x1:y',
    ]
    # bt_dht_lenwrap.py: lengths that would wrap the offset
    W = b'4294967285:'
    frames += [
        b'd1:rd6:values' + b'l' + W + b'eee',
        b'd1:rd2:id20:' + b'A' * 20 + b'e1:v' + W + b'e',
        b'd1:rd5:nodes' + W + b'ee',
        b'd1:ad1:xl' + W + b'eee',
        b'd1:rd5:token' + W + b'ee',
        b'd1:el' + b'i201e' + W + b'ee',
        b'd1:rd2:ip' + W + b'ee',
    ]
    for f in frames:
        c.udp(A, B, f)
    return c


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(out + '/bt_dht-coverage.pcap')
    malformed_capture().write(out + '/bt_dht-coverage-malformed.pcap')
