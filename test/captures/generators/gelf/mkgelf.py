#!/usr/bin/env python3
# Generates test/captures/gelf_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GELF coverage captures. Usage: mkgelf.py <outdir>
# gelf-coverage.pcapng has two interfaces: 0 = Ethernet with UDP datagrams
# (reached with the "gelf_udp" heuristic dissector, which is disabled by
# default) and 1 = Exported PDU naming the "gelf-udp" dissector (reached
# without any preference).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import zlib
import json
from common import pcapng, pcap, ip4, udp, eth

def msg(host, text, level=6, **extra):
    d = {"version": "1.1", "host": host, "short_message": text, "level": level,
         "timestamp": 1700000000.5, "_facility": "coverage"}
    d.update(extra)
    return json.dumps(d, separators=(',', ':')).encode()

def zl(data, level):
    return zlib.compress(data, level)

def gz(data):
    c = zlib.compressobj(9, zlib.DEFLATED, 31)
    return c.compress(data) + c.flush()

def chunks(mid, data, n, order=None):
    size = (len(data) + n - 1) // n
    parts = [data[i * size:(i + 1) * size] for i in range(n)]
    out = [b'\x1e\x0f' + mid + bytes([i, n]) + p for i, p in enumerate(parts)]
    return out if order is None else [out[i] for i in order]

def expdu(payload, name=b'gelf-udp'):
    pad = (4 - len(name) % 4) % 4
    return struct.pack('>HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

ETH_DST = bytes.fromhex('020000000002'); ETH_SRC = bytes.fromhex('020000000001')
def dgram(payload, sport=50000, src='10.0.0.1'):
    return eth(ETH_DST, ETH_SRC, 0x0800, ip4(src, '10.0.0.2', 17, udp(sport, 12201, payload)))

def build():
    A = 'example.org'
    plain = msg(A, 'A plain JSON message')
    big = msg(A, 'x' * 600 + ' a long message that is split in chunks', 4, _user='ronnie', _n=12345)
    frames = []   # (interface, bytes)
    U = lambda p, **k: frames.append((0, dgram(p, **k)))
    X = lambda p: frames.append((1, expdu(p)))

    # ---- UDP datagrams (heuristic)
    U(plain)                                              # 0x7b22 plain JSON
    U(b'\x1f\x3c' + msg(A, 'uncompressed with header'))   # 0x1f3c
    U(zl(plain, 1)); U(zl(plain, 3)); U(zl(plain, 6)); U(zl(plain, 9))   # 7801 785e 789c 78da
    U(gz(plain))                                          # gzip
    # chunked, in order, 3 chunks, zlib compressed
    cz = zl(big, 6)
    for c in chunks(bytes.fromhex('0102030405060708'), cz, 3):
        U(c)
    # chunked, out of order, uncompressed JSON (0x7b22 after reassembly), 4 chunks
    for c in chunks(bytes.fromhex('a1a2a3a4a5a6a7a8'), big, 4, order=[2, 0, 3, 1]):
        U(c, sport=50001)
    # chunked gzip, 2 chunks, duplicated first chunk, two messages interleaved
    g1 = chunks(bytes.fromhex('1111111122222222'), gz(big), 2)
    g2 = chunks(bytes.fromhex('3333333344444444'), zl(big, 9), 2)
    U(g1[0], sport=50002); U(g2[0], sport=50002); U(g1[0], sport=50002)
    U(g2[1], sport=50002); U(g1[1], sport=50002)
    # chunked with the "uncompressed" 0x1f3c header after reassembly
    for c in chunks(bytes.fromhex('5555555566666666'), b'\x1f\x3c' + big, 2):
        U(c, sport=50003)
    # datagrams the heuristic rejects: unknown header, too short, chunk number >= count
    U(b'\x00\x01' + plain)
    U(b'\x7b\x22' + b'short')
    U(b'\x1f\x8b' + b'x' * 10)
    U(b'\x1f\x3c' + b'short json')
    U(b'\x1e\x0f' + b'12345678' + bytes([5, 3]) + b'abcdef')       # number >= count
    U(b'\x1e\x0f' + b'1234567')                                     # shorter than 12
    U(b'\x78\x9c' + b'x' * 10)                                      # zlib too short
    U(b'\x1e')                                                      # 1 byte: less than 2

    # ---- Exported PDU (no preference needed)
    X(plain)
    X(b'\x1f\x3c' + msg(A, 'exported uncompressed'))
    for lv in (1, 3, 6, 9):
        X(zl(msg(A, 'exported zlib %d' % lv), lv))
    X(gz(msg(A, 'exported gzip')))
    for c in chunks(bytes.fromhex('0f0e0d0c0b0a0908'), zl(big, 6), 3):
        X(c)
    for c in chunks(bytes.fromhex('f1f2f3f4f5f6f7f8'), gz(big), 2, order=[1, 0]):
        X(c)
    # a single chunk message (count 1)
    for c in chunks(bytes.fromhex('0011223344556677'), zl(plain, 6), 1):
        X(c)
    # UDP not accepted by the heuristic but through Exported PDU: invalid number >= count
    # ends up in the reassembly with an odd count
    X(b'\x1e\x0f' + bytes.fromhex('9988776655443322') + bytes([0, 2]) + zl(big, 6)[:50])
    X(b'\x1e\x0f' + bytes.fromhex('9988776655443322') + bytes([1, 2]) + zl(big, 6)[50:])
    return frames

def build_mal():
    frames = []
    X = lambda p: frames.append((0, expdu(p)))
    plain = msg('example.org', 'plain')
    # the reproducer of the fixed leak: chunked packets shorter than the chunk header
    for i in range(3):
        X(b'\x1e\x0f' + bytes([i, 1, 2, 3, 4, 5, 6, 7]))     # 10 bytes: throws at the chunk number
        X(b'\x1e\x0f' + bytes([i, 1, 2]))                    # 5 bytes: throws adding the message id
    X(b'\x1e\x0f' + bytes(8) + b'\x00')                       # 11 bytes: throws at the chunk count
    X(b'\x1e')                                                 # one octet: not GELF
    X(b'\x12\x34' + plain)                                     # invalid header magic
    X(b'\x78\x9c' + b'this is not zlib data at all, not even close.....')   # broken compression
    X(b'\x1f\x8b' + b'this is not gzip data at all, not even close.....')
    X(zl(plain, 6)[:20])                                       # truncated zlib stream
    X(b'\x1f\x3c')                                             # uncompressed header, no payload
    X(b'\x7b\x22')                                             # plain JSON header only
    X(b'\x7b\x22' + b'this is not json {{{ at all, but starts like it')  # JSON dissector rejects it
    # a chunked message whose reassembly is not valid GELF
    for c in chunks(bytes.fromhex('abababababababab'), b'garbage garbage garbage garbage', 2):
        X(c)
    # chunk number 7 of 3 (never completes), and count 0
    X(b'\x1e\x0f' + bytes.fromhex('cdcdcdcdcdcdcdcd') + bytes([7, 3]) + b'tail')
    X(b'\x1e\x0f' + bytes.fromhex('cecececececececece'[:16]) + bytes([0, 0]) + b'head')
    # first chunk of a chunked message that is never completed
    X(b'\x1e\x0f' + bytes.fromhex('dededededededede') + bytes([0, 5]) + zl(plain, 6))
    # chunk reassembly conflicts: same chunk number twice with different data
    mid = bytes.fromhex('0a0b0c0d0e0f1011')
    X(b'\x1e\x0f' + mid + bytes([0, 3]) + b'AAAAAAAA')
    X(b'\x1e\x0f' + mid + bytes([0, 3]) + b'BBBBBBBB')
    X(b'\x1e\x0f' + mid + bytes([2, 3]) + b'CC')
    X(b'\x1e\x0f' + mid + bytes([1, 3]) + b'DDDD')
    return frames

if __name__ == '__main__':
    out = sys.argv[1]
    pcapng(os.path.join(out, 'gelf-coverage.pcapng'), [1, 252], build())
    pcap(os.path.join(out, 'gelf-coverage-malformed.pcap'), [f for _, f in build_mal()], linktype=252)
