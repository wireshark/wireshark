#!/usr/bin/env python3
# Generates test/captures/nmf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the NMF (.NET Message
Framing, [MC-NMF]) dissector (packet-nmf.c) on TCP port 9389.

Every packet is built from scratch with struct. TCP streams carry
consistent sequence numbers. Upgrade negotiation and protected packets
use placeholder bytes only: no keys, no real security tokens.

Usage: mknmf.py <output directory>

  nmf-coverage.pcap            valid streams (no malformed frames)
  nmf-coverage-malformed.pcap  invalid record sizes (the reproducer of
                               the Sized Envelope assertion), truncated
                               records, bad varints
"""
import os
import struct
import sys

T0 = 1700000000


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def tcp_pkt(src, dst, sport, dport, seq, ack, payload, flags=0x18):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00'
    if src > dst:
        pass
    return eth + ip + tcp + payload


class Flow:
    """One TCP connection to the server port 9389."""
    CLI = bytes([192, 0, 2, 1])
    SRV = bytes([192, 0, 2, 2])

    def __init__(self, out, port, sport=9389):
        self.out = out
        self.cport = port
        self.sport = sport
        self.cseq = 1000
        self.sseq = 5000

    def c(self, data):
        self.out.append(tcp_pkt(self.CLI, self.SRV, self.cport, self.sport, self.cseq, self.sseq, data))
        self.cseq += len(data)

    def s(self, data):
        self.out.append(tcp_pkt(self.SRV, self.CLI, self.sport, self.cport, self.sseq, self.cseq, data))
        self.sseq += len(data)

    def csplit(self, data, *cuts):
        """Client data in several segments, cut at the given offsets."""
        last = 0
        for c in cuts + (len(data),):
            self.c(data[last:c])
            last = c

    def ssplit(self, data, *cuts):
        last = 0
        for c in cuts + (len(data),):
            self.s(data[last:c])
            last = c


def write(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', T0 + i, 0, len(p), len(p)))
            f.write(p)


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def rec_version(major=1, minor=0): return bytes([0x00, major, minor])
def rec_mode(m): return bytes([0x01, m])
def rec_via(uri): return b'\x02' + varint(len(uri)) + uri.encode()
def rec_known(e): return bytes([0x03, e])
def rec_sized(payload): return b'\x06' + varint(len(payload)) + payload
def rec_upgrade(p): return b'\x09' + varint(len(p)) + p.encode()


VIA = 'net.tcp://server.example.test:9389/Service'


def negotiate(typ, data):
    """Upgraded negotiation message: type, two octets, big endian length."""
    return bytes([typ, 0, 0]) + struct.pack('>H', len(data)) + data


# Placeholder GSS-API token: a SPNEGO-looking wrapper without any key
# material or ciphertext.
TOKEN_INIT = (b'\x60\x1c\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x12\x30\x10\xa0\x0e\x30\x0c'
              b'\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a')


# SPNEGO NegTokenResp: accept-completed
TOKEN_SHORT = b'\xa1\x07\x30\x05\xa0\x03\x0a\x01\x00'


def wrap_token(sealed, payload):
    """Placeholder RFC 4121 wrap token header; the checksum is 12 filler octets."""
    flags = 0x02 if sealed else 0x00
    return (struct.pack('>HBBHH', 0x0504, 0x00 | flags, 0xff, 12 if not sealed else 0, 0)
            + struct.pack('>Q', 1) + payload + b'\xaa' * 12)


def protected(data):
    return struct.pack('<I', len(data)) + data


def build_main():
    p = []
    port = [40000]

    def flow():
        port[0] += 1
        return Flow(p, port[0])

    # 1: preamble records, one per segment, with the records of the
    # preamble end; sizes of one, two and three octets; every simple record
    f = flow()
    f.c(rec_version())
    f.c(rec_mode(2))
    f.c(rec_via(VIA))
    f.c(rec_known(8))
    f.c(rec_upgrade('application/x-other'))
    f.s(b'\x0b')                                     # preamble ack
    f.c(b'\x0c')                                     # preamble end
    f.c(rec_sized(b'<s:Envelope/>' * 3))
    f.s(rec_sized(b'x' * 200))                       # two octet size
    f.c(rec_sized(b'y' * 20000))                     # three octet size
    f.s(rec_sized(b''))
    f.c(b'\x04' + b'\x05')                           # extensible encoding, unsized envelope
    f.c(b'\x07')                                     # end
    f.c(b'\x08')                                     # fault
    f.c(b'\xff')                                     # unknown record type
    # 2: several records in one segment, modes and encodings
    f = flow()
    f.c(rec_version(1, 0) + rec_mode(1) + rec_via('net.tcp://h/x') + rec_known(0)
        + rec_sized(b'one') + rec_sized(b'two'))
    for m in (2, 3, 9):
        f.c(rec_mode(m))
    for e in range(1, 10):
        f.s(rec_known(e))
    f.c(rec_version(2, 1))
    f.c(rec_via(''))                                 # empty Via
    # 3: reassembly: records split over segments (size varint, string,
    # sized envelope payload); next record in the same segment as a tail
    f = flow()
    f.csplit(rec_via(VIA), 1)                        # type only
    f.csplit(rec_via(VIA), 2, 10)
    f.csplit(rec_sized(b'z' * 300), 1, 2, 100)       # two octet size split
    f.csplit(rec_sized(b'a' * 50) + rec_sized(b'b' * 60), 30)
    f.ssplit(rec_upgrade('application/x-other') + rec_known(7), 5)
    f.csplit(rec_sized(b'tail'), 3)
    # 4: upgrade to application/negotiate, negotiation messages in both
    # directions (GSS-API), then protected packets
    f = flow()
    f.c(rec_version() + rec_mode(2) + rec_via(VIA) + rec_known(8) + rec_upgrade('application/negotiate'))
    f.s(b'\x0a')                                     # upgrade response
    f.c(negotiate(0x10, TOKEN_INIT))
    f.s(negotiate(0x11, TOKEN_SHORT))
    f.c(negotiate(0x11, TOKEN_SHORT))
    f.csplit(negotiate(0x12, TOKEN_INIT), 3)         # split negotiate message
    f.s(negotiate(0x14, TOKEN_SHORT))                # last message: switches to protected
    # protected packets: integrity (readable), privacy (flag set), one
    # one with two records, one split over segments
    f.c(protected(wrap_token(False, rec_version() + rec_mode(2))))
    f.s(protected(wrap_token(False, rec_sized(b'<s:Envelope>' + b'q' * 40))))
    f.c(protected(wrap_token(False, rec_via(VIA) + rec_known(8) + rec_sized(b'two records'))))
    f.c(protected(wrap_token(True, b'\x55' * 24)))
    f.csplit(protected(wrap_token(False, rec_sized(b'split ' * 10))), 2, 20)
    f.s(protected(wrap_token(False, rec_mode(3))))
    # 5: a stream where the upgrade response is not followed by anything
    f = flow()
    f.c(rec_version() + rec_mode(2) + rec_upgrade('application/ssl-tls'))
    f.s(b'\x0a')
    f.c(negotiate(0x00, TOKEN_INIT))
    f.c(negotiate(0x13, TOKEN_SHORT))                # not 0x14: stays in the upgrade phase
    f.s(negotiate(0x14, TOKEN_SHORT))
    return p


def build_malformed():
    p = []
    port = [41000]

    def flow():
        port[0] += 1
        return Flow(p, port[0])

    # The reproducer of "NMF: Bound the record size and fix the record
    # offsets": record sizes that exceed the data
    f = flow()
    f.c(b'\x06\xfe\xff\xff\xff\x0f' + b'A' * 16)     # sized envelope, size 0xFFFFFFFE
    f = flow()
    f.c(b'\x02\xff\xff\xff\xff\x0f' + b'net.tcp://x/')   # via, size 0xFFFFFFFF
    f = flow()
    f.c(b'\x09\x10abc')                              # upgrade, size 16 > 3
    f = flow()
    f.c(b'\x02\x80\x80\x80\x80\x80\x01abc')          # varint longer than 5 octets
    f = flow()
    f.c(b'\x06\xff\xff\xff\xff\xff\x01' + b'x' * 20)
    f = flow()
    f.c(b'\x02\x80\x80\x80\x80\x10zzzzzzzz')         # size above UINT32_MAX
    f = flow()
    f.c(b'\x06\x80\x80\x80\x80\x10zzzzzzzz')
    f = flow()
    f.c(b'\x09\x85\x80\x80\x80\x80\x00abcde')      # upgrade: six octet varint holding 5
    f = flow()
    f.c(b'\x09' + b'\xff' * 8)                      # varint that never ends
    f = flow()
    f.c(b'\x02' + b'\xff' * 6)
    f = flow()
    f.c(b'\x06')                                     # type only, left incomplete
    f = flow()
    f.c(b'\x00\x01')                                 # truncated version record
    f = flow()
    f.c(b'\x01')                                     # truncated mode record
    f = flow()
    f.c(b'\x03')                                     # truncated known encoding
    # protected phase: length wrap, and a protected packet with a wrong length
    f = flow()
    f.c(rec_version() + rec_upgrade('application/negotiate'))
    f.s(b'\x0a')
    f.c(negotiate(0x14, TOKEN_INIT))
    f.c(b'\xfc\xff\xff\xff' + b'\x00' * 8)           # 4 + len wraps
    f.c(b'\xff\xff\xff\xff' + b'\x00' * 8)
    f.c(b'\x20\x00\x00\x00' + wrap_token(False, rec_sized(b'short')))
    f.c(protected(wrap_token(False, b'\x06\xff\xff\xff\x0f' + b'x' * 8)))   # bad size inside
    f.c(protected(wrap_token(False, b'\x06')))       # truncated record inside
    f.c(protected(wrap_token(False, b'\x01')))
    # upgrade phase: truncated and wrong lengths
    f = flow()
    f.c(rec_version() + rec_upgrade('application/negotiate'))
    f.s(b'\x0a')
    f.c(negotiate(0x10, b'abcd')[:-2])               # length longer than the data
    f.c(b'\x10\x00\x00\x00')                         # too short
    f.c(b'\x10\x00\x00\xff\xff' + b'abc')
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    write(os.path.join(out, 'nmf-coverage.pcap'), build_main())
    write(os.path.join(out, 'nmf-coverage-malformed.pcap'), build_malformed())


main()
