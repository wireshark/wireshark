#!/usr/bin/env python3
# Generates test/captures/proxy_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the PROXY protocol
dissector (packet-proxy.c).

The HAProxy PROXY protocol (v1 text line, v2 binary header with TLVs)
precedes the proxied data on a TCP connection (and, in v2, in every UDP
datagram). The dissector is a heuristic dissector on TCP and UDP (both
enabled by default), so the connections use an unregistered port 9999;
on TCP the conversation is then handed to the PROXY v1/v2 handle for the
following segments, and the proxied payload (HTTP, TCP port 80) is
dissected by the proxied ports. Over UDP the proxied payload is
dissected with the outer ports through the UDP heuristics (STUN here).
Everything is built with struct; nothing is captured traffic.

Usage: mkproxy.py <output directory>

Writes:
  proxy-coverage.pcap            v1 (TCP4, TCP6, UNKNOWN) and v2 (TCP,
                                 UDP, IPv4/IPv6/UNIX/UNSPEC, LOCAL, every
                                 TLV type, SSL sub-TLVs, desegmentation of
                                 the proxied HTTP) over TCP, v2 over UDP
  proxy-coverage-malformed.pcap  bad v1 lines, v2 length errors, nested
                                 PROXY headers over UDP (limit 4)
"""
import os
import struct
import sys

MAGIC = bytes([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a])
MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
LB4 = bytes([192, 0, 2, 1])
CL4 = bytes([192, 0, 2, 10])
LB6 = bytes.fromhex('20010db8000000000000000000000001')
CL6 = bytes.fromhex('20010db800000000000000000000000a')

frames = []
mframes = []


def pcap(path, frs):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frs):
            f.write(struct.pack('<IIII', 1700000000 + i // 100, 10000 * (i % 100), len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip_frame(proto, payload, v6, c2s):
    if v6:
        src, dst = (CL6, LB6) if c2s else (LB6, CL6)
        ip = struct.pack('>IHBB', 0x60000000, len(payload), proto, 64) + src + dst
        et = b'\x86\xdd'
    else:
        src, dst = (CL4, LB4) if c2s else (LB4, CL4)
        ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0) + src + dst
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        et = b'\x08\x00'
    mac = (MAC_S + MAC_C) if c2s else (MAC_C + MAC_S)
    return mac + et + ip + payload


class Tcp:
    """One TCP connection to the PROXY port 9999."""

    def __init__(self, cport, v6=False, out=None):
        self.cport, self.v6 = cport, v6
        self.cseq, self.sseq = 1000, 5000
        self.out = frames if out is None else out
        self.seg(True, 0x02, b'')
        self.cseq += 1
        self.seg(False, 0x12, b'')
        self.sseq += 1
        self.seg(True, 0x10, b'')

    def seg(self, c2s, flags, data):
        sp, dp = (self.cport, 9999) if c2s else (9999, self.cport)
        seq, ack = (self.cseq, self.sseq) if c2s else (self.sseq, self.cseq)
        if flags == 0x02:
            ack = 0
        if flags & 0x02:
            hdr = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x70, flags, 65535, 0, 0) \
                + struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1)
        else:
            hdr = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
        self.out.append(ip_frame(6, hdr + data, self.v6, c2s))

    def send(self, c2s, data):
        self.seg(c2s, 0x18, data)
        if c2s:
            self.cseq += len(data)
        else:
            self.sseq += len(data)
        self.seg(not c2s, 0x10, b'')


def http_get(path):
    return b'GET ' + path + b' HTTP/1.1\r\nHost: example.com\r\n\r\n'


HTTP_OK = b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'


def tlv(t, v):
    return struct.pack('>BH', t, len(v)) + v


def v2(cmd, fam, addrs, tlvs=b'', length=None):
    n = len(addrs) + len(tlvs) if length is None else length
    return MAGIC + bytes([0x20 | cmd, fam]) + struct.pack('>H', n) + addrs + tlvs


def a4(sip, dip, sp, dp):
    return bytes(sip) + bytes(dip) + struct.pack('>HH', sp, dp)


A4 = a4([198, 51, 100, 7], [203, 0, 113, 9], 51234, 80)
A6 = (bytes.fromhex('20010db8000000000000000000000007') + bytes.fromhex('20010db8000000000000000000000009')
      + struct.pack('>HH', 51235, 80))
UNIX = b'/run/client.sock'.ljust(108, b'\0') + b'/run/server.sock'.ljust(108, b'\0')

SSL_SUB = (tlv(0x21, b'TLSv1.3') + tlv(0x22, b'client.example') + tlv(0x23, b'TLS_AES_256_GCM_SHA384')
           + tlv(0x24, b'RSA-SHA256') + tlv(0x25, b'RSA2048'))
TLVS = (tlv(0x01, b'h2') + tlv(0x02, b'example.com') + tlv(0x03, b'\x01\x02\x03\x04') + tlv(0x04, b'\0\0\0')
        + tlv(0x05, b'unique-id-1') + tlv(0x20, b'\x01' + struct.pack('>I', 0) + SSL_SUB)
        + tlv(0x30, b'ns1') + tlv(0xEA, b'\x01vpce-0123') + tlv(0x99, b'??') + tlv(0x00, b''))


def stun():
    # With a SOFTWARE attribute: an attribute-less 20 octet message makes the
    # STUN dissector read past its end (tvb_get_ntohs at the first attribute).
    return struct.pack('>HHI', 0x0001, 8, 0x2112A442) + bytes(range(12)) \
        + struct.pack('>HH', 0x8022, 4) + b'test'


def udp_frame(payload, v6=False, sport=40000, dport=9999, c2s=True, out=None):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if v6:
        # the UDP checksum is mandatory over IPv6
        src, dst = (CL6, LB6) if c2s else (LB6, CL6)
        ck = csum(src + dst + struct.pack('>IBBBB', len(u), 0, 0, 0, 17) + u) or 0xffff
        u = u[:6] + struct.pack('>H', ck) + u[8:]
    (frames if out is None else out).append(ip_frame(17, u, v6, c2s))


def main(outdir):
    os.makedirs(outdir, exist_ok=True)

    # ---- v1
    t = Tcp(40001)
    t.send(True, b'PROXY TCP4 198.51.100.7 203.0.113.9 51234 80\r\n' + http_get(b'/one'))
    t.send(False, HTTP_OK)
    t.send(True, http_get(b'/two'))
    t.send(False, HTTP_OK)
    t = Tcp(40002, v6=True)
    t.send(True, b'PROXY TCP6 2001:db8::7 2001:db8::9 51235 80\r\n' + http_get(b'/six'))
    t.send(False, HTTP_OK)
    t = Tcp(40003)
    t.send(True, b'PROXY UNKNOWN 1.2.3.4 5.6.7.8 11 22\r\nunknown payload')
    t.send(False, b'reply')
    t = Tcp(40004)   # only the header, the data follows in the next segment
    t.send(True, b'PROXY TCP4 198.51.100.8 203.0.113.9 51236 80\r\n')
    t.send(True, http_get(b'/later'))

    # ---- v2 over TCP
    t = Tcp(40010)
    post = b'POST /up HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20\r\n\r\n'
    t.send(True, v2(1, 0x11, A4, TLVS) + post + b'01234')   # needs reassembly
    t.send(True, b'56789ABCDEFGHIJ')
    t.send(False, HTTP_OK)
    t.send(True, http_get(b'/after'))
    t = Tcp(40011, v6=True)
    t.send(True, v2(1, 0x21, A6) + http_get(b'/v6'))
    t.send(False, HTTP_OK)
    t = Tcp(40012)
    t.send(True, v2(1, 0x31, UNIX) + b'unix stream data')
    t = Tcp(40013)
    t.send(True, v2(1, 0x32, UNIX, tlv(0x02, b'unix.example')) + b'unix dgram data')
    t = Tcp(40014)
    t.send(True, v2(0, 0x11, A4) + b'local command data')            # LOCAL
    t = Tcp(40015)
    t.send(True, v2(0, 0x00, b'') + http_get(b'/local'))             # LOCAL, UNSPEC
    t = Tcp(40016)
    t.send(True, v2(1, 0x00, b'\xde\xad\xbe\xef') + b'unspec data')   # unknown family, with data
    t = Tcp(40017)
    t.send(True, v2(1, 0x00, b'') + b'unspec empty')
    t = Tcp(40018)
    t.send(True, v2(1, 0x12, A4) + http_get(b'/udp4'))               # UDP over IPv4 declared on TCP
    t = Tcp(40019, v6=True)
    t.send(True, v2(1, 0x22, A6) + http_get(b'/udp6'))               # UDP over IPv6 declared on TCP
    t = Tcp(40020)
    # SSL TLV followed by another TLV; an SSL TLV shorter than 5 octets
    t.send(True, v2(1, 0x11, A4, tlv(0x20, b'\x00' + struct.pack('>I', 7) + tlv(0x22, b'cn')) + tlv(0x02, b'after.example')
                    + tlv(0x20, b'\x01\x02')) + http_get(b'/ssl'))
    t = Tcp(40021)
    t.send(True, v2(1, 0x11, A4, b'', length=12) + b'')               # header only, no data
    t.send(True, http_get(b'/second'))

    # ---- v2 over UDP: the proxied payload is a STUN message
    udp_frame(v2(1, 0x12, A4) + stun())
    udp_frame(v2(1, 0x22, A6) + stun(), v6=True)
    udp_frame(v2(1, 0x12, A4, TLVS) + stun())
    udp_frame(v2(0, 0x12, A4) + stun())                               # LOCAL
    udp_frame(v2(1, 0x32, UNIX) + stun())
    udp_frame(v2(1, 0x00, b'') + b'plain data after header')
    udp_frame(v2(1, 0x12, A4))                                        # header only
    udp_frame(v2(1, 0x12, A4) + v2(1, 0x12, A4) + stun())             # two nested headers
    udp_frame(stun(), c2s=False, sport=9999, dport=40000)             # reply without header
    pcap(os.path.join(outdir, 'proxy-coverage.pcap'), frames)

    # ================= malformed
    n = 41000

    def one(data, v6=False):
        nonlocal n
        n += 1
        t = Tcp(n, v6=v6, out=mframes)
        t.send(True, data)

    for line in (
        b'PROXY TCP4 1.2.3.4\r\n',
        b'PROXY TCP4 999.1.1.1 1.1.1.1 1 2\r\n',
        b'PROXY TCP4 1.1.1.1 999.1.1.1 1 2\r\n',
        b'PROXY TCP4 1.1.1.1 2.2.2.2 99999 80\r\n',
        b'PROXY TCP4 1.1.1.1 2.2.2.2 80\r\n',
        b'PROXY TCP4 1.1.1.1 2.2.2.2 80 \r\n',
        b'PROXY TCP4 1.1.1.1 2.2.2.2 80 xx\r\n',
        b'PROXY TCP4 1.1.1.1 2.2.2.2 80 99999\r\n',
        b'PROXY TCP4 1.1.1.1\r\n',
        b'PROXY TCP4 1.1.1.1 2.2.2.2\r\n',
        b'PROXY  TCP4 1.1.1.1 2.2.2.2 1 2\r\n',
        b'PROXY UNKNOWN\r\n',
        b'PROXY TCP6 zz::q 2001:db8::9 1 2\r\n',
        b'PROXY TCP6 2001:db8::7 zz::q 1 2\r\n',
        b'PROXY TCP6 2001:db8::7\r\n',
        b'PROXY TCP6 2001:db8::7 2001:db8::9\r\n',
        b'PROXY TCP6 2001:db8::7 2001:db8::9 5 xx\r\n',
        b'PROXY TCP6 2001:db8::7 2001:db8::9 99999 5\r\n',
        b'PROXY TCP4 1.1.1.1 2.2.2.2 80 90\n',      # LF only: not PROXY
        b'PROXY TCP4 ' + b'1' * 120 + b'\r\n',       # longer than 107: not PROXY
    ):
        one(line)
    # v2: length too small for the addresses, TLV past the header, TLV
    # length past the data, cut-off headers
    one(v2(1, 0x11, A4, length=4))
    one(v2(1, 0x21, A6, length=10))
    one(v2(1, 0x31, UNIX, length=100))
    one(v2(1, 0x11, A4, b'\x01\xff\xffxx'))                    # TLV length past the data
    one(v2(1, 0x11, A4, b'\x01\x00'))                          # TLV header cut off
    one(v2(1, 0x11, A4, tlv(0x20, b'\x01' + struct.pack('>I', 0) + b'\x21\x00\x50ab')))   # sub-TLV too long
    one(v2(1, 0x11, A4)[:20])
    one(v2(1, 0x00, b'abcd', length=40))                      # unknown family, length past the data
    one((MAGIC + b'\x21\x11\x00')[:15])                       # shorter than 16: not PROXY
    # nested PROXY v2 headers over UDP: the fifth is refused (limit 4)
    for depth in (5, 6, 8):
        udp_frame(v2(1, 0x00, b'') * depth + stun(), out=mframes)
    udp_frame(v2(1, 0x12, A4)[:18], out=mframes)
    pcap(os.path.join(outdir, 'proxy-coverage-malformed.pcap'), mframes)


if __name__ == '__main__':
    main(sys.argv[1])
