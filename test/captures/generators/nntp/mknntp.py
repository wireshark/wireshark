#!/usr/bin/env python3
# Generates test/captures/nntp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the NNTP dissector
(packet-nntp.c) on TCP port 119.

Every packet is built from scratch with struct. The TLS records that
follow an accepted STARTTLS are a ClientHello and a ServerHello with made
up random values; no keys and no ciphertext.

Usage: mknntp.py <output directory>

  nntp-coverage.pcap            valid sessions (no malformed frames)
  nntp-coverage-malformed.pcap  short lines that match the prefix of
                                STARTTLS or 382 (the reproducer of the
                                over-read), data without line ends and
                                other odd packets
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
    """One TCP connection to the server port 119."""
    CLI = bytes([192, 0, 2, 1])
    SRV = bytes([192, 0, 2, 2])

    def __init__(self, out, port, sport=119):
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




def tls_hello(server):
    exts = b''
    if not server:
        name = b'news.example.test'
        sni = struct.pack('>HBH', len(name) + 3, 0, len(name)) + name
        exts = struct.pack('>HH', 0, len(sni)) + sni
    body = struct.pack('>H', 0x0303) + bytes(range(32 if not server else 64, 64 if not server else 96)) + b'\x00'
    if server:
        body += struct.pack('>HB', 0xc02f, 0) + struct.pack('>H', len(exts)) + exts
        hs = b'\x02' + struct.pack('>I', len(body))[1:] + body
    else:
        body += struct.pack('>HHH', 4, 0xc02f, 0x1301) + b'\x01\x00' + struct.pack('>H', len(exts)) + exts
        hs = b'\x01' + struct.pack('>I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs


def build_main():
    p = []
    port = [40000]

    def flow():
        port[0] += 1
        return Flow(p, port[0], 119)

    # 1: a reader session: greeting, capabilities, group, listing, article
    # (multi-line responses), posting, quit
    f = flow()
    f.s(b'200 news.example.test InterNetNews NNRP server ready (posting ok)\r\n')
    f.c(b'CAPABILITIES\r\n')
    f.s(b'101 Capability list:\r\nVERSION 2\r\nREADER\r\nSTARTTLS\r\nLIST ACTIVE NEWSGROUPS\r\n.\r\n')
    f.c(b'MODE READER\r\n')
    f.s(b'200 Posting allowed\r\n')
    f.c(b'GROUP comp.test\r\n')
    f.s(b'211 3 1 3 comp.test\r\n')
    f.c(b'LIST ACTIVE\r\n')
    f.s(b'215 list follows\r\ncomp.test 3 1 y\r\nmisc.test 0 1 n\r\n.\r\n')
    f.c(b'ARTICLE 2\r\n')
    f.s(b'220 2 <2@example.test> article\r\nFrom: a@example.test\r\nSubject: Hello\r\n\r\nBody line\r\n..a dot line\r\n.\r\n')
    f.c(b'POST\r\n')
    f.s(b'340 Send article to be posted\r\n')
    f.c(b'From: a@example.test\r\nNewsgroups: comp.test\r\nSubject: x\r\n\r\nText\r\n.\r\n')
    f.s(b'240 Article received OK\r\n')
    f.c(b'QUIT\r\n')
    f.s(b'205 Bye\r\n')
    # 2: STARTTLS accepted: the 382 response starts TLS
    f = flow()
    f.s(b'200 ready\r\n')
    f.c(b'STARTTLS\r\n')
    f.s(b'382 Continue with TLS negotiation\r\n')
    f.c(tls_hello(False))
    f.s(tls_hello(True))
    # 3: lower case starttls, rejected with 502; a later request
    f = flow()
    f.s(b'200 ready\r\n')
    f.c(b'starttls\r\n')
    f.s(b'502 Command unavailable\r\n')
    f.c(b'GROUP misc.test\r\n')
    f.s(b'382 not a STARTTLS answer any more\r\n')
    f.c(b'DATE\r\n')
    f.s(b'111 20231115000000\r\n')
    # 4: STARTTLS with trailing text, mixed case, accepted with a response
    # that has more lines
    f = flow()
    f.c(b'StartTLS extra\r\n')
    f.s(b'382 go ahead\r\nsecond line\r\n')
    f.c(tls_hello(False))
    # 5: line endings: bare LF, no line terminator, empty lines, a
    # request without a terminator, a long line, non-ASCII bytes
    f = flow()
    f.s(b'200 lf only\n')
    f.c(b'HELP\n')
    f.s(b'100 Help text follows\nline one\nline two\n.\n')
    f.c(b'\r\n')
    f.s(b'500 What?')
    f.c(b'XOVER 1-3')
    f.s(b'224 overview\r\n1\tSubject \xe9\xff\tfrom\r\n' + b'x' * 1500 + b'\r\n.\r\n')
    f.c(b'LAST\r\nNEXT\r\n')                       # two requests in one segment
    f.s(b'223 1 <1@example.test>\r\n223 2 <2@example.test>\r\n')
    # 6: STARTTLS split over segments and a short "382"
    f = flow()
    f.csplit(b'STARTTLS\r\n', 4)
    f.s(b'38')
    f.s(b'2 split code\r\n')
    # 7: a response that is the exact keyword length: "STARTTLS" as response text
    f = flow()
    f.s(b'STARTTLS offered\r\n')
    f.c(b'STARTTLS\r\n')
    f.s(b'382\r\n')
    f.c(tls_hello(False))
    return p


def build_malformed():
    p = []
    port = [41000]

    def flow():
        port[0] += 1
        return Flow(p, port[0], 119)

    # The reproducer of "NNTP: Do not read past the line when matching
    # STARTTLS": lines that are shorter prefixes of the keyword at the end
    # of the packet
    f = flow()
    f.c(b'STARTTL')
    f.s(b'38')
    f = flow()
    f.c(b'STARTTLS')                                 # exactly the keyword, no terminator
    f.s(b'38')                                       # short response while TLS is requested
    f.c(b'S')
    f.s(b'3')
    f.s(b'')                                         # empty segment
    f = flow()
    f.c(b'STARTTLS\r\n')
    f.s(b'382')                                      # no terminator
    f.c(b'\x16\x03\x01\x00')                         # truncated TLS record
    f = flow()
    f.c(b'\x00' * 20)
    f.s(bytes(range(256)))
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    write(os.path.join(out, 'nntp-coverage.pcap'), build_main())
    write(os.path.join(out, 'nntp-coverage-malformed.pcap'), build_malformed())


main()
