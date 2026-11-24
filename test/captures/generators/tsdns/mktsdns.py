#!/usr/bin/env python3
# Generates test/captures/tsdns_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: pcap writer and Ethernet / MPLS / IPv4 / UDP builders.
import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def eth(payload, etype, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4(payload, proto=17, src=IP_A, dst=IP_B, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                    64, proto, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def ipv6(payload, nh=17):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + src + dst + payload


def udp(payload, sport, dport, src=IP_A, dst=IP_B):
    n = 8 + len(payload)
    pseudo = src + dst + struct.pack('>BBH', 0, 17, n)
    h = struct.pack('>HHHH', sport, dport, n, 0)
    c = csum(pseudo + h + payload) or 0xffff
    return struct.pack('>HHHH', sport, dport, n, c) + payload


def udp_frame(payload, sport, dport, ident=1):
    return eth(ipv4(udp(payload, sport, dport), ident=ident), 0x0800)


def mpls(label, payload, ttl=64, tc=0, bos=1):
    return struct.pack('>I', (label << 12) | (tc << 9) | (bos << 8) | ttl) + payload


def mpls_frame(label, payload, **kw):
    return eth(mpls(label, payload, **kw), 0x8847)


class Pcap:
    def __init__(self):
        self.frames = []

    def add(self, data, snap=None):
        # snap: captured length smaller than the original length
        self.frames.append((data, snap))
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, (d, snap) in enumerate(self.frames):
                t = 1700000000 + i
                cap = d if snap is None else d[:snap]
                f.write(struct.pack('<IIII', t, 1000 * i, len(cap), len(d)))
                f.write(cap)
        return len(self.frames)


def tcp(payload, sport, dport, seq=1, ack=1, flags=0x18, src=IP_A, dst=IP_B):
    h = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(pseudo + h + payload)
    return h[:16] + struct.pack('>H', c) + h[18:] + payload


def tcp_frame(payload, sport, dport, seq=1, ack=1, flags=0x18, down=False, ident=1):
    if down:
        return eth(ipv4(tcp(payload, sport, dport, seq, ack, flags, src=IP_B, dst=IP_A), 6, src=IP_B, dst=IP_A, ident=ident), 0x0800, dst=MAC_A, src=MAC_B)
    return eth(ipv4(tcp(payload, sport, dport, seq, ack, flags), 6, ident=ident), 0x0800)


class Tcp:
    """One TCP connection with consistent sequence numbers (client = IP_A)."""
    def __init__(self, cport, sport, ident=1):
        self.cport, self.sport, self.ident = cport, sport, ident
        self.cseq, self.sseq = 1000, 5000

    def c(self, payload):
        self.ident += 1
        f = tcp_frame(payload, self.cport, self.sport, self.cseq, self.sseq, 0x18, False, self.ident)
        self.cseq += len(payload)
        return f

    def s(self, payload):
        self.ident += 1
        f = tcp_frame(payload, self.sport, self.cport, self.sseq, self.cseq, 0x18, True, self.ident)
        self.sseq += len(payload)
        return f

# ---- tsdns ----
# TSDNS (TeamSpeak 3 DNS) over TCP port 41144; the port has no default
# registration, so the captures need Decode As tcp.port 41144 -> tsdns.
CLIENT = 50000
SERVER = 41144


def build(out):
    main = Pcap()
    t = Tcp(CLIENT, SERVER)
    req = lambda n, i: t.c(n + b'\n\r\r\r\n')
    resp = lambda x, i: t.s(x)
    main.add(req(b'ts.example.com', 1))                         # 1 request
    main.add(resp(b'192.0.2.9:9987', 2))                        # 2 response, address and port
    main.add(req(b'a', 3))                                     # 3 shortest request with a domain
    main.add(resp(b'192.0.2.10:65535', 4))                     # 4 port 65535 (largest that fits)
    main.add(resp(b'[2001:db8::1]:9987', 5))                   # 5 IPv6 style address: the first ':' splits
    main.add(resp(b'192.0.2.11:abc', 6))                       # 6 port not a number: IP only, no port item
    main.add(resp(b'192.0.2.12:99999', 7))                     # 7 port too large for 16 bits (the case of the fix)
    main.add(resp(b'noport.example.net:0', 8))                 # 8 host name and port 0
    main.add(req(b'', 10))                                     # 9 request with an empty domain (5 octets)
    main.write(os.path.join(out, 'tsdns-coverage.pcap'))
    bad = Pcap()
    t = Tcp(CLIENT, SERVER)
    bad.add(t.s(b'1234'))                                   # 1 under 5 octets: TSDNS declines
    bad.add(t.c(b'\n\r\r\r'))                                  # 2 four octets, request direction
    bad.add(t.s(b'1.2.3.4'))                                       # 3 no port: malformed address (error expert info)
    bad.add(resp(b'no colon here', 3))                          # 4 response without a colon (error)
    bad.add(resp(b'::', 4))                                     # 5 empty parts
    bad.add(resp(b'192.0.2.13:99999999999', 5))                 # 6 port beyond 32 bits
    bad.add(resp(b'host:80:81', 6))                             # 7 more than one colon
    bad.write(os.path.join(out, 'tsdns-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
