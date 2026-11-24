#!/usr/bin/env python3
# Generates test/captures/olsr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the OLSR dissector
(packet-olsr.c, OLSR v1, RFC 3626 plus the olsr.org and NRL extensions).

OLSR runs over UDP port 698, IPv4 or IPv6. Every packet is built with
struct; nothing comes from a real network.

Usage: mkolsr.py <output directory>

Writes:
  olsr-coverage.pcap            HELLO, TC, MID, HNA, olsr.org LQ-HELLO,
                                LQ-TC and Nameservice, NRL TC and unknown
                                message types over IPv4 and IPv6, with
                                several messages per packet
  olsr-coverage-malformed.pcap  truncated packets and messages, bad lengths
"""
import os
import struct
import sys

IP4 = {'a': bytes((10, 0, 0, 1)), 'b': bytes((10, 0, 0, 255))}
IP6 = {'a': bytes.fromhex('20010db8000000000000000000000001'),
       'b': bytes.fromhex('ff020000000000000000000000000002')}
N4 = [bytes((10, 1, 0, i)) for i in range(1, 8)]
N6 = [bytes.fromhex('20010db8000100000000000000000%03x' % i) for i in range(1, 8)]


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_pkt(payload, v6, sport=698, dport=698):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if v6:
        ph = IP6['a'] + IP6['b'] + struct.pack('>IBBBB', len(u), 0, 0, 0, 17)
        u = u[:6] + struct.pack('>H', csum(ph + u) or 0xffff) + u[8:]
        ip = struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + IP6['a'] + IP6['b']
        return bytes.fromhex('333300000002020000000001') + b'\x86\xdd' + ip + u
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, IP4['a'], IP4['b'])
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return bytes.fromhex('ffffffffffff020000000001') + b'\x08\x00' + h + u


def msg(mtype, vtime, body, v6=False, ttl=255, hops=0, seq=1, size=None, origin=None):
    o = origin or (IP6['a'] if v6 else IP4['a'])
    hdr = struct.pack('>BBH', mtype, vtime, (4 + len(o) + 4 + len(body)) if size is None else size)
    return hdr + o + struct.pack('>BBH', ttl, hops, seq) + body


def packet(msgs, seq=1, plen=None):
    body = b''.join(msgs)
    return struct.pack('>HH', (4 + len(body)) if plen is None else plen, seq) + body


def hello(links, htime=0x86, will=3):
    """links: list of (link code, [neighbour addresses] or raw bytes)."""
    b = struct.pack('>HBB', 0, htime, will)
    for code, nb in links:
        raw = nb if isinstance(nb, bytes) else b''.join(nb)
        b += struct.pack('>BBH', code, 0, 4 + len(raw)) + raw
    return b


def tc(ansn, nbs):
    return struct.pack('>HH', ansn, 0) + b''.join(nbs)


def lq_entries(nbs, lqs):
    return b''.join(a + bytes((lq, nlq, 0, 0)) for a, (lq, nlq) in zip(nbs, lqs))


def ns_entry(typ, ip, content, v6=False, length=None):
    """Nameservice entry: type, length, address, content padded to 4."""
    ln = len(content) if length is None else length
    pad = (-len(content)) % 4
    return struct.pack('>HH', typ, ln) + ip.ljust(16, b'\0') + content + bytes(pad)


def nameservice(entries, version=1, count=None):
    return struct.pack('>HH', version, len(entries) if count is None else count) + b''.join(entries)


class Cap:
    def __init__(self):
        self.frames = []

    def add(self, payload, v6=False, **kw):
        self.frames.append(udp_pkt(payload, v6, **kw))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)


def main_capture(path):
    c = Cap()
    for v6 in (False, True):
        N = N6 if v6 else N4
        # RFC HELLO: no links, links of every named type, an unnamed type
        c.add(packet([msg(1, 0x86, hello([]), v6)]), v6)
        c.add(packet([msg(1, 0x86, hello([(0x06, N[:2]), (0x0a, N[2:4]), (0x01, N[4:5])], htime=0x45, will=7), v6, seq=2)], 2), v6)
        c.add(packet([msg(1, 0x86, hello([(0x00, N[:1]), (0x03, N[1:2]), (0x05, N[2:3]), (0x66, N[3:4]), (0x0a, [])], htime=0xff, will=0), v6, seq=3)], 3), v6)
        # TC: with and without neighbours
        c.add(packet([msg(2, 0xc5, tc(0x1234, N[:3]), v6, hops=2)], 4), v6)
        c.add(packet([msg(2, 0x00, tc(7, []), v6)], 5), v6)
        # MID
        c.add(packet([msg(3, 0x86, b''.join(N[:4]), v6, ttl=1)], 6), v6)
        # HNA (IPv6 HNA is the reproducer of the length fix)
        if v6:
            h = (bytes.fromhex('20010db8aaaa00000000000000000000') + bytes.fromhex('ffffffffffffffff0000000000000000')
                 + bytes.fromhex('20010db8bbbb00000000000000000000') + bytes.fromhex('ffffffffffffffffffff000000000000'))
        else:
            h = bytes((192, 168, 1, 0, 255, 255, 255, 0, 10, 20, 0, 0, 255, 255, 0, 0))
        c.add(packet([msg(4, 0x86, h, v6)], 7), v6)
        # olsr.org LQ HELLO / LQ TC
        c.add(packet([msg(201, 0x86, hello([(0x06, lq_entries(N[:3], [(255, 255), (200, 100), (0, 1)])),
                                            (0x0a, lq_entries(N[3:4], [(128, 64)]))]), v6, seq=8)], 8), v6)
        c.add(packet([msg(202, 0x86, tc(9, []) , v6)], 9), v6)
        c.add(packet([msg(202, 0x86, struct.pack('>HH', 9, 0) + lq_entries(N[:3], [(255, 255), (200, 100), (1, 2)]), v6)], 10), v6)
        # olsr.org nameservice: every entry type, padding, empty content
        ip = N[0]
        e = [ns_entry(0, ip, b'host.mesh\0'), ns_entry(1, ip, b'fwd\0'), ns_entry(2, ip, b'http://10.1.0.1:80|tcp|web\0'),
             ns_entry(3, ip, b'52.5|13.4\0'), ns_entry(9, ip, b'abcd'), ns_entry(0, ip, b'x')]
        c.add(packet([msg(130, 0x86, nameservice(e), v6, seq=11)], 11), v6)
        c.add(packet([msg(130, 0x86, nameservice([]), v6)], 12), v6)
        # NRL TC: neighbours followed by two field arrays
        nb = N[:3]
        c.add(packet([msg(241, 0x86, struct.pack('>HH', 3, 0) + b''.join(nb) + bytes((1, 2, 3)) + bytes((4, 5, 6)), v6)], 13), v6)
        c.add(packet([msg(241, 0x86, struct.pack('>HH', 3, 0) + b'', v6)], 14), v6)
        # an unknown message type (the reproducer of the length fix), 4 and 8 octets of data
        c.add(packet([msg(0x99, 0x86, b'ABCD', v6)], 15), v6)
        c.add(packet([msg(0x99, 0x86, b'ABCDEFGH', v6, seq=16)], 16), v6)
        c.add(packet([msg(0x99, 0x86, b'', v6)], 17), v6)
        # several messages in one packet, each of a different type
        c.add(packet([msg(1, 0x86, hello([(6, N[:2])]), v6), msg(2, 0x86, tc(1, N[:2]), v6),
                      msg(3, 0x86, b''.join(N[:2]), v6), msg(0x99, 0x86, b'abcd', v6), msg(4, 0x86, h, v6)], 18), v6)
        # message with a different originator and ttl / hop count
        c.add(packet([msg(3, 0x86, N[0], v6, ttl=7, hops=9, seq=0xffff, origin=N[5])], 19), v6)
        # trailing data after the packet length (ignored)
        c.add(packet([msg(3, 0x86, N[0], v6)], 20) + b'\xde\xad\xbe\xef', v6)
    c.write(path)


def malformed_capture(path):
    c = Cap()
    for v6 in (False, True):
        N = N6 if v6 else N4
        alen = 16 if v6 else 4
        c.add(b'\x00\x08')                                   # packet shorter than 4 octets
        c.add(b'\x00\x00\x00', v6)
        c.add(struct.pack('>HH', 200, 1), v6)                # packet length larger than the data
        c.add(struct.pack('>HH', 6, 1) + b'\x01\x86', v6)    # message header cut short ("Message too short")
        c.add(packet([msg(1, 0x86, hello([]), v6, size=8 + alen - 1)]), v6)   # size below the minimum
        c.add(packet([msg(1, 0x86, hello([]), v6, size=400)]), v6)           # size beyond the data: exception
        # size beyond the OLSR packet length but inside the UDP payload ("not enough data for message")
        c.add(packet([msg(1, 0x86, hello([]), v6, size=8 + alen + 40)]) + bytes(100), v6)
        # HELLO: too short for the header, truncated entries
        c.add(packet([msg(1, 0x86, b'\x00\x00\x86', v6)]), v6)
        c.add(packet([msg(1, 0x86, struct.pack('>HBB', 0, 0x86, 3) + b'\x06\x00\x00', v6)]), v6)    # entry < 4 octets
        c.add(packet([msg(1, 0x86, struct.pack('>HBBBBH', 0, 0x86, 3, 6, 0, 3), v6)]), v6)          # link size < 4
        c.add(packet([msg(1, 0x86, struct.pack('>HBBBBH', 0, 0x86, 3, 6, 0, 4 + alen - 2) + bytes(alen - 2), v6)]), v6)  # partial neighbour
        # TC
        c.add(packet([msg(2, 0x86, b'\x00\x01\x00', v6)]), v6)                                       # < 4 octets
        c.add(packet([msg(2, 0x86, tc(1, [N[0]]) + b'\x01\x02', v6)]), v6)                           # partial neighbour
        # MID, HNA
        c.add(packet([msg(3, 0x86, N[0] + b'\x01\x02', v6)]), v6)
        c.add(packet([msg(4, 0x86, bytes(alen + 1), v6)]), v6)
        # LQ HELLO / LQ TC
        c.add(packet([msg(201, 0x86, b'\x00\x00', v6)]), v6)
        c.add(packet([msg(201, 0x86, struct.pack('>HBBBBH', 0, 0x86, 3, 6, 0, 4 + alen) + bytes(alen), v6)]), v6)  # too short for LQ entry
        c.add(packet([msg(202, 0x86, b'\x00\x01', v6)]), v6)
        c.add(packet([msg(202, 0x86, tc(1, []) + bytes(alen + 2), v6)]), v6)
        # nameservice: < 4 octets, wrong version, truncated entries
        c.add(packet([msg(130, 0x86, b'\x00\x01', v6)]), v6)
        c.add(packet([msg(130, 0x86, nameservice([], version=2) + b'1234', v6)]), v6)
        c.add(packet([msg(130, 0x86, nameservice([], count=1) + bytes(10), v6)]), v6)
        c.add(packet([msg(130, 0x86, nameservice([ns_entry(0, N[0], b'abc')], count=1)[:-2], v6)]), v6)
        c.add(packet([msg(130, 0x86, nameservice([ns_entry(0, N[0], b'abcdefgh', length=40)], count=1), v6)]), v6)
        # NRL TC < 4 octets
        c.add(packet([msg(241, 0x86, b'\x00', v6)]), v6)
        # unknown type with data that is not a multiple of four
        c.add(packet([msg(0x99, 0x86, b'ABC', v6)]), v6)
        c.add(packet([msg(0x99, 0x86, b'ABCDEF', v6), msg(3, 0x86, N[0], v6)]), v6)
    c.write(path)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_capture(os.path.join(out, 'olsr-coverage.pcap'))
    malformed_capture(os.path.join(out, 'olsr-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
