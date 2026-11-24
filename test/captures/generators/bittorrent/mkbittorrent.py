#!/usr/bin/env python3
# Generates test/captures/bittorrent_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BitTorrent dissector
(packet-bittorrent.c).

All packets are built from scratch with struct; no captured traffic is
used. Peers are 192.0.2.1 (A) and 192.0.2.2 (B).

Usage: mkbittorrent.py <output directory>

Writes:
  bittorrent-coverage.pcap            handshakes, every message type, the
                                      Fast extension, extended (LTEP)
                                      messages, Azureus Messaging Protocol
                                      messages, keepalives, reassembly,
                                      continuation data, the heuristic,
                                      and BitTorrent over uTP (frames noted
                                      in the README)
  bittorrent-coverage-malformed.pcap  paths that end in an exception, and
                                      the bittorrent_mix.py edge cases

TCP 6881-6889 is registered by default and the heuristic is enabled by
default. The uTP stream (UDP 50001/50002) needs
-d udp.port==50001,bt-utp (or --enable-heuristic bt_utp_udp).
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))









import struct
from repro import reproducer_dir

A = (192, 0, 2, 1)
B = (192, 0, 2, 2)
MAC_A = b'\x02\x00\x00\x00\x00\x01'
MAC_B = b'\x02\x00\x00\x00\x00\x02'


# --------------------------------------------------------------------------
# pcap writer (Ethernet / IPv4 / TCP or UDP)

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []    # (frame bytes, captured length)

    def ip(self, proto, l4, src, dst, caplen=None):
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, proto, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        if src == A:
            eth = MAC_B + MAC_A + b'\x08\x00'
        else:
            eth = MAC_A + MAC_B + b'\x08\x00'
        f = eth + ip + l4
        self.frames.append((f, len(f) if caplen is None else 14 + 20 + caplen))

    def tcp(self, src, dst, sport, dport, seq, ack, flags, payload=b'', caplen=None):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', csum(pseudo + hdr + payload)) + hdr[18:]
        # caplen counts the TCP header too
        self.ip(6, hdr + payload, src, dst,
                None if caplen is None else len(hdr) + caplen)

    def udp(self, src, dst, sport, dport, payload):
        hdr = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(payload))
        c = csum(pseudo + hdr + payload) or 0xffff
        self.ip(17, hdr[:6] + struct.pack('>H', c) + payload, src, dst)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
        t = 1700000000
        for i, (f, cap) in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, cap, len(f)) + f[:cap])
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class TcpStream:
    """A TCP connection from A (client) to B (server) with correct sequence
    numbers."""
    def __init__(self, cap, cport, sport, handshake=True):
        self.cap, self.cport, self.sport = cap, cport, sport
        self.seq = {A: 1000 + cport, B: 5000 + sport}
        if handshake:
            self.cap.tcp(A, B, cport, sport, self.seq[A], 0, 0x02)
            self.seq[A] += 1
            self.cap.tcp(B, A, sport, cport, self.seq[B], self.seq[A], 0x12)
            self.seq[B] += 1
            self.cap.tcp(A, B, cport, sport, self.seq[A], self.seq[B], 0x10)

    def send(self, src, data, split=None, caplen=None):
        """Send data from src (A or B), cut into segments at the offsets
        in split, or in segments of at most 1400 octets."""
        dst = B if src == A else A
        sp, dp = (self.cport, self.sport) if src == A else (self.sport, self.cport)
        if split is None:
            split = list(range(1400, len(data), 1400))
        cuts = [0] + list(split) + [len(data)]
        for a, b in zip(cuts, cuts[1:]):
            self.cap.tcp(src, dst, sp, dp, self.seq[src], self.seq[dst], 0x18, data[a:b], caplen)
            self.seq[src] += b - a

    def fin(self):
        self.cap.tcp(A, B, self.cport, self.sport, self.seq[A], self.seq[B], 0x11)
        self.seq[A] += 1
        self.cap.tcp(B, A, self.sport, self.cport, self.seq[B], self.seq[A], 0x11)
        self.seq[B] += 1
        self.cap.tcp(A, B, self.cport, self.sport, self.seq[A], self.seq[B], 0x10)


# --------------------------------------------------------------------------
# BitTorrent messages

ALL_EXTENSIONS = 0xffffffffffffffff
INFO_HASH = bytes(range(0x10, 0x24))


def handshake(peer_id, reserved=0x0000000000100005, info_hash=INFO_HASH):
    assert len(peer_id) == 20
    return (bytes([19]) + b'BitTorrent protocol' + struct.pack('>Q', reserved) +
            info_hash + peer_id)


def msg(t, body=b''):
    return struct.pack('>IB', 1 + len(body), t) + body


def keepalive():
    return struct.pack('>I', 0)


def amp(name, prio, body=b''):
    n = name.encode()
    inner = struct.pack('>I', len(n)) + n + bytes([prio]) + body
    return struct.pack('>I', len(inner)) + inner


def benc(v):
    if isinstance(v, int):
        return b'i%de' % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b'%d:' % len(v) + v
    if isinstance(v, list):
        return b'l' + b''.join(benc(x) for x in v) + b'e'
    if isinstance(v, dict):
        return b'd' + b''.join(benc(k) + benc(v[k]) for k in sorted(v)) + b'e'
    raise TypeError(v)


def piece_req(index, begin, length):
    return struct.pack('>III', index, begin, length)


def piece_data(n, seed):
    return bytes((seed + i * 7) & 0xff for i in range(n))


HAVE, BITFIELD, REQUEST, PIECE, CANCEL, PORT = 4, 5, 6, 7, 8, 9
CHOKE, UNCHOKE, INTERESTED, NOT_INTERESTED = 0, 1, 2, 3
SUGGEST, HAVE_ALL, HAVE_NONE, REJECT, ALLOWED_FAST, EXTENDED = 13, 14, 15, 16, 17, 20


def utp(typ, conn, seq, ack, payload=b'', wnd=0x100000):
    return struct.pack('>BBHIIIHH', (typ << 4) | 1, 0, conn, 0x11223344 + seq,
                       1000, wnd, seq, ack) + payload


# --------------------------------------------------------------------------

def main_capture():
    cap = Pcap()

    # ---- Stream 1: plain BitTorrent on 6881 --------------------------------
    s = TcpStream(cap, 51413, 6881)
    s.send(A, handshake(b'-TR2940-' + b'abcdefghijkl', reserved=ALL_EXTENSIONS))
    s.send(B, handshake(b'-qB4250-' + b'mnopqrstuvwx', reserved=0x0000000000100005))
    # extended handshakes (extended id 0, bencoded)
    s.send(A, msg(EXTENDED, b'\x00' + benc({'m': {'ut_metadata': 3, 'ut_pex': 1},
                                            'p': 51413, 'reqq': 250,
                                            'v': 'Transmission 2.94'})))
    s.send(B, msg(EXTENDED, b'\x00' + benc({'m': {'ut_pex': 2}, 'v': 'qBittorrent/4.2.5',
                                            'yourip': b'\xc0\x00\x02\x01'})))
    # extended message with another id: raw bytes
    s.send(B, msg(EXTENDED, b'\x01' + benc({'added': b'\xc0\x00\x02\x03\x1a\xe1',
                                            'added.f': b'\x00'})))
    # empty extended message body (just the id)
    s.send(A, msg(EXTENDED, b'\x03'))
    s.send(A, msg(BITFIELD, b'\xff\xff\xfe'))
    s.send(B, msg(HAVE_ALL))
    s.send(B, msg(HAVE_NONE))
    s.send(A, msg(INTERESTED))
    s.send(A, msg(NOT_INTERESTED))
    s.send(B, msg(UNCHOKE))
    s.send(B, msg(CHOKE))
    s.send(B, msg(UNCHOKE))
    s.send(A, msg(INTERESTED))
    s.send(A, msg(HAVE, struct.pack('>I', 0x17)))
    s.send(A, msg(REQUEST, piece_req(1, 0, 0x4000)))
    s.send(A, msg(CANCEL, piece_req(1, 0, 0x4000)))
    s.send(A, msg(PORT, struct.pack('>H', 6881)))
    s.send(B, msg(SUGGEST, struct.pack('>I', 5)))
    s.send(B, msg(REJECT, piece_req(1, 0, 0x4000)))
    s.send(B, msg(ALLOWED_FAST, struct.pack('>I', 6)))
    s.send(A, keepalive())
    # several messages in one segment
    s.send(A, msg(REQUEST, piece_req(2, 0, 0x4000)) + msg(REQUEST, piece_req(2, 0x4000, 0x10))
           + keepalive() + msg(HAVE, struct.pack('>I', 3)))
    # a small piece
    s.send(B, msg(PIECE, struct.pack('>II', 2, 0x4000) + piece_data(16, 1)))
    # a full 0x4000 piece over 12 segments, the last one followed by a Have
    big = msg(PIECE, struct.pack('>II', 2, 0) + piece_data(0x4000, 2))
    s.send(B, big + msg(HAVE, struct.pack('>I', 2)))
    # a Request whose length field is alone in the first segment, then two
    # octets, then the rest
    r = msg(REQUEST, piece_req(4, 0, 0x4000))
    s.send(A, r, split=[4, 6])
    # a segment of just two octets of a header
    s.send(A, msg(HAVE, struct.pack('>I', 4)), split=[2])
    # a message that starts in the middle of one segment and ends in the next
    s.send(B, msg(UNCHOKE) + msg(PIECE, struct.pack('>II', 4, 0) + piece_data(40, 3)), split=[20])
    # continuation data: an unknown type, a Have with the wrong length,
    # a Piece and a Choke longer than any real one
    s.send(B, struct.pack('>IB', 0x30, 0x63) + piece_data(60, 4))
    s.send(B, struct.pack('>IB', 6, HAVE) + piece_data(40, 5))
    s.send(B, struct.pack('>IB', 0x4100, PIECE) + piece_data(40, 6))
    s.send(B, struct.pack('>IB', 2, INTERESTED) + piece_data(40, 13))
    s.send(B, struct.pack('>IB', 4, PORT) + piece_data(40, 14))
    s.send(B, struct.pack('>IB', 12, REQUEST) + piece_data(40, 15))
    s.send(B, struct.pack('>IB', 0x30000, CHOKE) + piece_data(40, 7))
    # back in step
    s.send(B, msg(HAVE, struct.pack('>I', 4)))
    s.send(A, msg(CHOKE, b'\x00\x00'))   # Choke with a short payload
    s.fin()

    # ---- Stream 2: Azureus Messaging Protocol on 6882 ----------------------
    s = TcpStream(cap, 51414, 6882)
    s.send(A, handshake(b'-AZ4004-' + b'0123456789ab', reserved=0x8000000000000000))
    s.send(B, handshake(b'-AZ5770-' + b'cdefghijklmn', reserved=0x8000000000000001))
    s.send(A, amp('AZ_HANDSHAKE', 1, benc({'client': 'Azureus', 'version': '4.0.0.4',
                                           'messages': [{'id': 'BT_HAVE', 'ver': b'\x01'}],
                                           'tcp_port': 6882})))
    s.send(B, amp('AZ_HANDSHAKE', 2, benc({'client': 'Vuze', 'version': '5.7.7.0'})))
    s.send(A, amp('BT_HANDSHAKE', 1, handshake(b'-AZ4004-' + b'0123456789ab')))
    s.send(A, amp('BT_KEEP_ALIVE', 0))
    s.send(B, amp('BT_BITFIELD', 1, b'\xf0\x0f'))
    s.send(B, amp('BT_HAVE_ALL', 1))
    s.send(B, amp('BT_HAVE_NONE', 1))
    s.send(A, amp('BT_INTERESTED', 1))
    s.send(A, amp('BT_UNINTERESTED', 0))
    s.send(B, amp('BT_UNCHOKE', 2))
    s.send(B, amp('BT_CHOKE', 2))
    s.send(B, amp('BT_UNCHOKE', 2))
    # the reproducer of bittorrent_mix.py frame 11
    s.send(A, amp('BT_HAVE', 0, struct.pack('>I', 1)))
    s.send(A, amp('BT_REQUEST', 1, piece_req(7, 0x100, 0x200)))
    s.send(A, amp('BT_CANCEL', 1, piece_req(7, 0x100, 0x200)))
    s.send(A, amp('BT_PORT', 1, struct.pack('>H', 6882)))
    s.send(B, amp('BT_SUGGEST', 1, struct.pack('>I', 8)))
    s.send(B, amp('BT_REJECT_REQUEST', 1, piece_req(7, 0x100, 0x200)))
    s.send(B, amp('BT_ALLOWED_FAST', 1, struct.pack('>I', 9)))
    s.send(B, amp('BT_PIECE', 0, struct.pack('>II', 7, 0x100) + piece_data(0x200, 8)))
    s.send(A, amp('BT_EXTENDED', 1, b'\x00' + benc({'m': {'ut_pex': 1}})))
    s.send(A, amp('BT_EXTENDED', 1, b'\x05' + b'raw-ext'))
    s.send(B, amp('AZ_PEER_EXCHANGE', 0, benc({'infohash': INFO_HASH,
                                               'added': [b'\xc0\x00\x02\x05\x1a\xe2']})))
    s.send(A, amp('JPC_HELLO', 1, struct.pack('>I', 9) + b'10.0.0.99' +
                  struct.pack('>II', 6881, 0x12345678)))
    s.send(B, amp('JPC_REPLY', 1, struct.pack('>I', 0x12345678)))
    # AMP-shaped messages that fall back to Choke: unknown name, a known
    # name with an invalid priority, and a name longer than the message
    s.send(A, amp('BT_FOO', 1, b'xx'))
    s.send(A, amp('BT_HAVE', 3, struct.pack('>I', 1)))
    s.send(A, struct.pack('>IB', 8, 0) + struct.pack('>I', 20) + b'BT_'
           )
    # an AMP fixed length message with the wrong length: continuation data
    s.send(A, amp('BT_HAVE', 1, struct.pack('>II', 1, 2)))
    s.send(A, amp('BT_UNCHOKE', 1))
    s.fin()

    # ---- Stream 3: found by the heuristic (ports 40001/40002) --------------
    s = TcpStream(cap, 40001, 40002)
    h = handshake(b'-UT3530-' + b'opqrstuvwxyz', reserved=0x0000000000000004)
    s.send(A, h, split=[20])      # handshake split after the protocol name
    s.send(B, handshake(b'-LT1100-' + b'zyxwvutsrqpo', reserved=0x0000000000000004))
    s.send(B, msg(HAVE_ALL))
    s.send(A, msg(INTERESTED))
    s.send(B, msg(UNCHOKE))
    s.send(A, msg(REQUEST, piece_req(0, 0, 0x20)))
    s.send(B, msg(PIECE, struct.pack('>II', 0, 0) + piece_data(0x20, 9)))
    s.fin()

    # ---- Not BitTorrent: the heuristic rejects it (ports 40003/40004) ------
    s = TcpStream(cap, 40003, 40004, handshake=False)
    s.send(A, b'This is not a BitTorrent handshake.\r\n')
    s.send(B, b'short\r\n')

    # ---- Streams 4-7: peer IDs for the decode_client preference ------------
    ids = [
        (b'exbc\x00\x30' + b'LORDabcdefghij', b'XBT054d-' + b'abcdefghijkl'),
        (b'T03I-----' + b'abcdefghijk', b'-BOW0A0-' + b'abcdefghijkl'),
        (b'-AZ\x01\x02\x03\x04-' + b'abcdefghijkl', b'M4-3-6--' + b'abcdefghijkl'),
        (b'OP7685' + b'abcdefghijklmn', b'\x00' * 20),
    ]
    for i, (ia, ib) in enumerate(ids):
        s = TcpStream(cap, 51420 + i, 6883 + i, handshake=False)
        s.send(A, handshake(ia))
        s.send(B, handshake(ib))
        s.send(A, keepalive())

    # ---- Stream 8: frames cut short by the capture length (6887) -----------
    # tcp_dissect_pdus cannot reassemble a cut frame, so the message
    # dissector sees less than the whole message
    s = TcpStream(cap, 51430, 6887, handshake=False)
    s.send(A, handshake(b'-DE13F0-' + b'abcdefghijkl'))
    s.send(A, amp('BT_PIECE', 1, struct.pack('>II', 1, 2) + piece_data(100, 10)), caplen=6)
    s.send(A, amp('BT_PIECE', 1, struct.pack('>II', 1, 2) + piece_data(100, 10)), caplen=10)

    # ---- uTP (UDP 50001/50002), needs -d udp.port==50001,bt-utp ------------
    u = lambda src, p: cap.udp(src, B if src == A else A,
                               50001 if src == A else 50002,
                               50002 if src == A else 50001, p)
    u(A, utp(4, 0x1000, 1, 0))                                   # ST_SYN
    u(B, utp(2, 0x1000, 100, 1))                                 # ST_STATE
    u(A, utp(0, 0x1001, 2, 100, handshake(b'-UT3530-' + b'utputputputp')))
    u(B, utp(0, 0x1000, 101, 2, handshake(b'-UT3530-' + b'ptuptuptuptu')))
    u(A, utp(0, 0x1001, 3, 101, msg(INTERESTED) + msg(HAVE, struct.pack('>I', 1))))
    u(B, utp(0, 0x1000, 102, 3, msg(UNCHOKE)))
    u(A, utp(0, 0x1001, 4, 102, msg(REQUEST, piece_req(1, 0, 0x40))))
    u(B, utp(0, 0x1000, 103, 4, msg(PIECE, struct.pack('>II', 1, 0) + piece_data(0x40, 12))))
    u(A, utp(0, 0x1001, 5, 103, keepalive()))
    u(A, utp(1, 0x1001, 6, 103))                                 # ST_FIN
    return cap


def malformed_capture(mixdir):
    cap = Pcap()
    s = TcpStream(cap, 51500, 6881, handshake=False)
    s.send(A, handshake(b'-TR2940-' + b'abcdefghijkl'))
    # extended message without its id
    s.send(A, msg(EXTENDED))
    # piece shorter than its index and begin
    s.send(A, msg(PIECE, b'\x00\x00\x00\x01\x00'))
    # JPC hello with an address length past the end, and too short
    s.send(A, amp('JPC_HELLO', 1, struct.pack('>I', 0xfffffff0) + b'abc'))
    s.send(A, amp('JPC_HELLO', 1, struct.pack('>I', 3) + b'abc'))
    # JPC reply without its session
    s.send(A, amp('JPC_REPLY', 1, b'\x01'))
    # AMP piece too short
    s.send(A, amp('BT_PIECE', 1, b'\x00\x00'))
    # bad bencode in an extended handshake
    s.send(A, msg(EXTENDED, b'\x00' + b'd3:abc'))
    s.send(A, msg(UNCHOKE))
    # a frame cut after the length field: the type cannot be read
    s.send(A, msg(PIECE, struct.pack('>II', 1, 2) + piece_data(100, 11)), caplen=4)
    # the bittorrent_mix.py reproducer capture, re-sent as is
    mix = os.path.join(mixdir, 'bittorrent_mix.pcap')
    if os.path.exists(mix):
        with open(mix, 'rb') as fh:
            d = fh.read()
        off = 24
        while off < len(d):
            _, _, incl, _ = struct.unpack('<IIII', d[off:off + 16])
            f = d[off + 16:off + 16 + incl]
            cap.frames.append((f, len(f)))
            off += 16 + incl
    return cap


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'bittorrent-coverage.pcap'))
    malformed_capture(reproducer_dir(os.path.dirname(os.path.abspath(__file__)), ['bittorrent_mix.py'])).write(
        os.path.join(out, 'bittorrent-coverage-malformed.pcap'))
