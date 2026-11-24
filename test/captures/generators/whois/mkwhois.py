#!/usr/bin/env python3
# Generates test/captures/whois_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-whois.c (WHOIS, TCP port 43).
    mkwhois.py <outdir>
Writes whois-coverage.pcap and whois-coverage-malformed.pcap
"""
import struct
import socket
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

MAC_C = b'\x02\0\0\0\0\x01'
MAC_S = b'\x02\0\0\0\0\x02'
CLI = '192.0.2.1'
SRV = '192.0.2.2'

def ipv4(proto, payload, src, dst, ident=1, frag=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, frag, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def eth_ip(ip, from_client):
    d, s = (MAC_S, MAC_C) if from_client else (MAC_C, MAC_S)
    return d + s + b'\x08\x00' + ip

def udp(sp, dp, payload, from_client=True):
    src, dst = (CLI, SRV) if from_client else (SRV, CLI)
    u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    return eth_ip(ipv4(17, u, src, dst), from_client)

class Tcp:
    """One TCP connection, client port cp to server port sp."""
    def __init__(self, cp, sp):
        self.cp, self.sp = cp, sp
        self.cseq, self.sseq = 1000, 5000
    def seg(self, payload, from_client=True, flags=0x18):
        if from_client:
            sport, dport, seq, ack = self.cp, self.sp, self.cseq, self.sseq
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            sport, dport, seq, ack = self.sp, self.cp, self.sseq, self.cseq
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        src, dst = (CLI, SRV) if from_client else (SRV, CLI)
        if flags == 0x02: ack = 0
        opts = b'\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02\x01\x01' if flags & 2 else b''
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return eth_ip(ipv4(6, t, src, dst), from_client)
    def handshake(self):
        return [self.seg(b'', True, 0x02), self.seg(b'', False, 0x12), self.seg(b'', True, 0x10)]
    def close(self):
        return [self.seg(b'', False, 0x11), self.seg(b'', True, 0x11), self.seg(b'', False, 0x10)]

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000, len(fr), len(fr)))
            f.write(fr)

def conn(cp, query_parts, answer_parts, fin_with_last=False, qfin=False):
    """A client query in one or more segments, then the server answer in one
    or more segments, closed by the server's FIN."""
    t = Tcp(cp, 43)
    f = t.handshake()
    for q in query_parts:
        f.append(t.seg(q, True))
        f.append(t.seg(b'', False, 0x10))
    for i, a in enumerate(answer_parts):
        last = i == len(answer_parts) - 1
        f.append(t.seg(a, False, 0x19 if (last and fin_with_last) else 0x18))
        f.append(t.seg(b'', True, 0x10))
    if not fin_with_last:
        f.append(t.seg(b'', False, 0x11))
    f.append(t.seg(b'', True, 0x11))
    f.append(t.seg(b'', False, 0x10))
    return f

def main(outdir):
    f = []
    # 1. query and an answer over three segments, FIN after them
    f += conn(40001, [b'example.com\r\n'],
              [b'Domain Name: EXAMPLE.COM\r\n', b'Registrar: Example Registrar, Inc.\r\n',
               b'Status: ok\r\n\r\n>>> Last update <<<\r\n'])
    # 2. query split in two segments; the first has no CR LF
    f += conn(40002, [b'exam', b'ple.net\r\n'],
              [b'Domain Name: EXAMPLE.NET\n', b'Name Server: NS1.EXAMPLE.NET\n'])
    # 3. LF only line ends, a UTF-8 and a Latin-1 line, the answer with the FIN
    f += conn(40003, [b'-h whois.example.org nic\xc3\xa9.fr\r\n'],
              ['Nom: Café Été\r\n'.encode(), b'Org: caf\xe9 (latin-1)\n',
               b'last line without a line end'], fin_with_last=True)
    # 4. empty query (just CR LF) and a one-segment answer with the FIN
    f += conn(40004, [b'\r\n'], [b'% No query given\r\n'], fin_with_last=True)
    # 5. the answer first in two segments, the second sent before the first
    #    (out of order, so the answer is reassembled when the FIN arrives)
    t = Tcp(40005, 43)
    f += t.handshake()
    f.append(t.seg(b'192.0.2.0/24\r\n', True))
    f.append(t.seg(b'', False, 0x10))
    a1, a2, a3 = b'inetnum: 192.0.2.0 - 192.0.2.255\r\n', b'netname: TEST-NET-1\r\n', b'descr: documentation\r\n'
    s1 = t.seg(a1, False, 0x18)
    s2 = t.seg(a2, False, 0x18)
    s3 = t.seg(a3, False, 0x19)
    f += [s2, s1, s3, t.seg(b'', True, 0x10), t.seg(b'', True, 0x11), t.seg(b'', False, 0x10)]
    # 6. a long answer over many segments
    f += conn(40006, [b'big.example\r\n'], [b'remarks: line %03d of the long answer\r\n' % i for i in range(30)])
    # 7. a second query on a new connection from the same client, answer is one LF-separated block
    f += conn(40007, [b'example.com\r\n'], [b'a\nb\nc\n'], fin_with_last=True)
    write_pcap(os.path.join(outdir, 'whois-coverage.pcap'), f)

    m = []
    # query without CR LF, ended by the client's FIN: Missing <CR><LF>
    t = Tcp(41001, 43)
    m += t.handshake()
    m.append(t.seg(b'noeol', True, 0x19))
    m.append(t.seg(b'', False, 0x10))
    m.append(t.seg(b'Answer for noeol\r\n', False, 0x19))
    m.append(t.seg(b'', True, 0x10))
    # a 1 byte query
    t = Tcp(41002, 43)
    m += t.handshake()
    m.append(t.seg(b'x', True, 0x19))
    m.append(t.seg(b'', False, 0x19))
    # the server speaks first: the conversation's query is taken from its answer
    t = Tcp(41003, 43)
    m += t.handshake()
    m.append(t.seg(b'Welcome\r\n', False, 0x18))
    m.append(t.seg(b'q\r\n', True, 0x18))
    m.append(t.seg(b'ans\r\n', False, 0x19))
    # a query whose destination is not port 43 but the source is (answer only)
    write_pcap(os.path.join(outdir, 'whois-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
