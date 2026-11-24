#!/usr/bin/env python3
# Generates test/captures/banana_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Twisted Banana dissector
(packet-banana.c).

All packets are built from scratch with struct; no captured traffic is
used. A client (192.0.2.10:50001) talks to a Perspective Broker server
(198.51.100.1:8787) over one TCP connection with a three-way handshake.
Banana has no default port: dissect with -d tcp.port==8787,banana (or
-o banana.tcp.port:8787).

The dissector reads the value/length octets before a type tag as
val = val * 129 + octet (first octet most significant), so enc() below
writes a number in base 129 with digits 0..127.

Usage: mkbanana.py <output directory>

Writes:
  banana-coverage.pcap            every element type, nested and short
                                  lists, the Info column cases, pb tokens
                                  (also one at the start of the data),
                                  large integers
  banana-coverage-malformed.pcap  more than 8 value octets, values and
                                  lengths too large (negative integer
                                  2147483648), unknown type, pb error,
                                  truncated string and float, nesting
                                  past the tree depth limit
"""

import struct
import sys

PORT = 8787
CPORT = 50001
CLIENT = (192, 0, 2, 10)
SERVER = (198, 51, 100, 1)
EPOCH = 1700000000

LIST, INT, STRING, NEG, FLOAT, LGINT, LGNEG, PB = range(0x80, 0x88)


def enc(v):
    """Value octets the dissector reads back as v (base 129, digits <= 127)."""
    if v == 0:
        return b'\x00'
    d = []
    while v:
        d.append(v % 129)
        v //= 129
    assert max(d) <= 127, 'not representable'
    return bytes(reversed(d))


def el(tag, v=None, data=b''):
    return (b'' if v is None else enc(v)) + bytes([tag]) + data


def string(s):
    return el(STRING, len(s), s)


def lst(*items):
    return el(LIST, len(items)) + b''.join(items)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000,
                    64, proto, 0, bytes(src), bytes(dst))
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload):
    opts = struct.pack('>BBH', 2, 4, 1460) if flags & 0x02 else b''   # MSS on SYN
    h = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                    flags, 65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(h) + len(payload))
    c = csum(pseudo + h + payload)
    return h[:16] + struct.pack('>H', c) + h[18:] + payload


class Capture:
    def __init__(self):
        self.frames = []
        self.cseq = 1000
        self.sseq = 5000
        self.ident = 1
        syn, ack, psh = 0x02, 0x10, 0x08
        self.seg(True, syn, b'')
        self.cseq += 1
        self.seg(False, syn | ack, b'')
        self.sseq += 1
        self.seg(True, ack, b'')

    def seg(self, to_server, flags, payload):
        if to_server:
            t = tcp(CLIENT, SERVER, CPORT, PORT, self.cseq,
                    self.sseq if flags & 0x10 else 0, flags, payload)
            ip = ipv4(CLIENT, SERVER, 6, t, self.ident)
            self.cseq += len(payload)
        else:
            t = tcp(SERVER, CLIENT, PORT, CPORT, self.sseq, self.cseq, flags, payload)
            ip = ipv4(SERVER, CLIENT, 6, t, self.ident)
            self.sseq += len(payload)
        self.ident += 1
        eth = bytes.fromhex('020000000002020000000001') + b'\x08\x00'
        self.frames.append(eth + ip)

    def banana(self, payload, to_server=True):
        self.seg(to_server, 0x18, payload)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', EPOCH + i, 0, len(fr), len(fr)))
                f.write(fr)


def main_capture():
    c = Capture()                                       # 1-3 handshake
    # 4: a list of every scalar type
    c.banana(lst(el(INT, 5), string(b'hello'), el(NEG, 7),
                 el(FLOAT, data=struct.pack('>d', 1.5)),
                 el(LGINT, 1234567), el(LGNEG, 89)))
    # 5: a PB call as Twisted writes it: pb tokens before 0x87
    c.banana(lst(el(PB, 0x1a), el(INT, 1), string(b'root'), string(b'echo'),
                 lst(el(PB, 0x0b), string(b'hi')), lst(el(PB, 0x05)),
                 el(INT, 0)), to_server=True)
    # 6: answer (server -> client)
    c.banana(lst(el(PB, 0x1b), el(INT, 1), string(b'hi')), to_server=False)
    # 7: a pb token at the very start of the data (no value octet), then a
    #    pb token with one: only the second has a pb Profile Value
    c.banana(el(PB) + el(PB, 0x01) + el(INT, 3))
    # 8: integer and negative integer limits (2147483647), zero, multi-octet
    c.banana(el(INT, 2147483647) + el(NEG, 2147483647) + el(INT, 0) +
             el(NEG, 0) + el(INT, 300) + el(NEG, 16641))
    # 9: large integers of 8 and 1 value octets (Info "Unknown type: 8") and without value octets
    c.banana(b'\x01\x02\x03\x04\x05\x06\x07\x08' + bytes([LGINT]) +
             el(LGNEG, 2) + bytes([LGINT]) + bytes([LGNEG]))
    # 10: floats (integral, negative, zero) and a float without value octets
    c.banana(el(FLOAT, data=struct.pack('>d', -1024.0)) +
             el(FLOAT, data=struct.pack('>d', 0.0)) +
             el(FLOAT, data=struct.pack('>d', 1e100)))
    # 11: nested lists, empty lists, an empty string, a string without
    #     length octets
    c.banana(lst(lst(), lst(lst(el(INT, 9))), string(b''), bytes([STRING])))
    # 12: a list that claims more items than present (stops at the end)
    c.banana(el(LIST, 5) + el(INT, 1) + string(b'x'))
    # 13: value octets after the last element without a type tag
    c.banana(el(INT, 42) + b'\x05\x06')
    # 14: no type tag in the first 8 octets: Info shows "Unknown type: 1"
    #     (8 value octets, the most allowed: integer 1)
    c.banana(b'\x00' * 7 + b'\x01' + bytes([INT]))
    # 15: only value octets, shorter than 8: Info "Unknown type: 6"
    c.banana(b'\x05\x06')
    # 16: one octet: too short, not Banana
    c.banana(b'\x01')
    # 17: a type tag after up to 7 value octets: Info from the scan
    c.banana(b'\x01\x02\x03\x04\x05\x06\x07' + bytes([LGINT]) + string(b'tail'))
    # 18: a longer string and a list of many integers
    c.banana(string(b'Perspective Broker ' * 10) +
             lst(*[el(INT, i) for i in range(50)]), to_server=False)
    return c


def malformed_capture():
    c = Capture()                                       # 1-3 handshake
    nine = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09'
    # 4-11: 9 or more value octets before each type (too_many_value_bytes);
    #       before the fix the value kept shifting (signed overflow)
    c.banana(nine + bytes([INT]))
    c.banana(b'\x7f' * 20 + bytes([NEG]))
    c.banana(nine + bytes([LGINT]))
    c.banana(b'\x7f' * 12 + bytes([LGNEG]))
    c.banana(b'\x00' * 9 + b'\x01' + bytes([LIST]) + el(INT, 1))
    c.banana(b'\x00' * 9 + b'\x02' + bytes([STRING]) + b'ab')
    c.banana(b'\x00' * 9 + bytes([FLOAT]) + struct.pack('>d', 2.0))
    c.banana(b'\x00' * 9 + bytes([PB]))
    # 12: negative integer 2147483648 (negated in 64 bits) and
    #     integer 2147483648 (value_too_large)
    c.banana(el(NEG, 2147483648) + el(INT, 2147483648))
    # 13: string and list length too large
    c.banana(el(STRING, 2147483648) + b'abc')
    c.banana(el(LIST, 2147483648) + el(INT, 1))
    # 15: unknown type octets
    c.banana(b'\x01\x90' + el(INT, 2) + b'\xff\xff')
    # 16: pb token with two value octets (pb_error)
    c.banana(b'\x01\x02' + bytes([PB]) + el(INT, 1))
    # 17: string longer than the data
    c.banana(string(b'abcdef')[:-3])
    # 18: float cut short
    c.banana(bytes([FLOAT]) + b'\x40\x00')
    # 19: lists nested past the tree depth limit
    c.banana(el(LIST, 1) * 600 + el(INT, 1))
    return c


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(out + '/banana-coverage.pcap')
    malformed_capture().write(out + '/banana-coverage-malformed.pcap')
