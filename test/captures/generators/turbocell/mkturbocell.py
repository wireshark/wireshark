#!/usr/bin/env python3
# Generates test/captures/turbocell_coverage.pcap.gz
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
    def __init__(self, linktype=1):
        self.frames = []
        self.linktype = linktype

    def add(self, data, snap=None):
        # snap: captured length smaller than the original length
        self.frames.append((data, snap))
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
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


def raw_eth(dst, src, etype, payload):
    return dst + src + struct.pack('>H', etype) + payload

# ---- turbocell ----
# Turbocell (KarlNet): LLC/SNAP with OUI 00:20:f6 on an 802.3 frame, reached by
# default. Beacons carry the network name and the list of stations, data and
# management packets carry either that or aggregated Ethernet frames.
BASE = bytes.fromhex('02aa00000001')
MAGIC = bytes.fromhex('01fe23dc45ba')


def header(typ, satnw=0x12, counter=0x1234, dst=bytes.fromhex('ffffffffffff'), ts=0x00abcd,
           unknown=0, ip=bytes([192, 0, 2, 100]), alt=False):
    if alt:
        return (bytes([typ, satnw]) + struct.pack('>I', ts)[1:] + struct.pack('>I', counter)[1:] + MAGIC +
                struct.pack('>H', unknown) + ip)
    return (bytes([typ, satnw]) + struct.pack('>H', counter) + dst + struct.pack('>I', ts)[1:] + b'\0' +
            struct.pack('>H', unknown) + ip)


def netinfo(name, stations=(), tail=b'\x5a\xa5\x01\x02\x03\x04\x05\x06\x07\x08'):
    p = name.ljust(30, b'\0') + b'\0\0'
    for s in stations:
        p += b'\0' + s + b'\0'
    return p + tail


def sta(n):
    return bytes([0x11, 0x22, 0x33, 0x44, 0x55, n])


def agg(frames, unknown1=0x7856, trailer=b'', hdr=(0x4, 0xc, 0x8)):
    body = b''
    for i, f in enumerate(frames):
        body += struct.pack('<H', (len(f) & 0x0fff) | (hdr[i % 3] << 12)) + f
    p = struct.pack('>HH', 4 + len(body) + len(trailer), unknown1) + body + trailer
    return p


def frame(tc):
    llc = b'\xaa\xaa\x03\x00\x20\xf6' + tc
    return raw_eth(BASE, MAC_A, len(llc), llc)


def eth_ip(n):
    return raw_eth(MAC_B, MAC_A, 0x0800, ipv4(udp(b"x" * n, 45000, 45001)))


def build(out):
    main = Pcap()
    main.add(frame(header(0x40, 0x11) + netinfo(b'TestNet', [sta(1), sta(2), sta(3)])))        # 1 beacon, normal base station, three stations
    main.add(frame(header(0x00, 0x22, counter=1) + netinfo(b'NonPolling')))                   # 2 beacon, non-polling base station, no station
    main.add(frame(header(0x80, 0x31) + netinfo(b'Polling', [sta(9)])))                       # 3 beacon, polling base station
    main.add(frame(header(0xa0, 0x00) + netinfo(b'ISP net')))                                 # 4 beacon, ISP base station, satellite mode 0
    main.add(frame(header(0x40, 0x15, alt=True) + netinfo(b'AltHeader', [sta(4)])))           # 5 alternate header (magic number)
    main.add(frame(header(0x01, 0x23) + agg([eth_ip(10), eth_ip(30)])))                      # 6 data packet with two aggregated Ethernet frames
    main.add(frame(header(0x11, 0x24) + netinfo(b'MgmtNet', [sta(5), sta(6)])))               # 7 management packet with network info
    main.add(frame(header(0x05, 0x00)))                                                       # 8 unknown type 5, header only
    main.add(frame(header(0x21, 0x00) + b'\x01' * 6))                                         # 9 unknown type 0x21, exactly 6 octets after the header
    main.add(frame(header(0x01, 0x25) + agg([eth_ip(5), eth_ip(6), eth_ip(7)])))              # 10 data packet with three aggregated frames
    main.add(frame(header(0x01, 0x25) + agg([])))                                             # 11 aggregate with no subframe (length 0 ends the loop)
    main.add(frame(header(0x01, 0x25) + agg([eth_ip(20)], trailer=b'\xde\xad\xbe\xef\x01')))  # 12 aggregate with trailing data after the subframes
    main.add(frame(header(0x01, 0x26) + agg([eth_ip(8)], unknown1=0x0000)))                   # 13 aggregate with another "unknown" value
    inner = frame(header(0x40, 0x11) + netinfo(b'Inner', [sta(7)]))
    main.add(frame(header(0x01, 0x27) + agg([inner[0:]])))                                    # 14 an aggregated frame that is itself a Turbocell beacon
    main.add(frame(header(0x40, 0x11) + netinfo(b'MaxStations', [sta(i) for i in range(32)], tail=b'\x77' * 9)))   # 15 32 stations (the limit)
    main.add(frame(header(0x40, 0x11) + netinfo(b'ManyStations', [sta(i) for i in range(40)])))                   # 16 40 candidate stations: stops at 32
    main.add(frame(header(0x40, 0x11) + netinfo(b'N' * 29 + b'x', [], tail=b'\x77' * 9)))     # 17 network name of 30 characters without NUL (truncated)
    main.add(frame(header(0x01, 0x28) + agg([eth_ip(1)] * 6)))                                # 18 six subframes
    main.add(frame(header(0x40, 0x11) + netinfo(b'A\x01\x02 ctrl\x7f chars', [sta(1)])))    # 19 name with control characters (escaped in Info)
    main.write(os.path.join(out, 'turbocell-coverage.pcap'))
    bad = Pcap()
    bad.add(frame(header(0x40, 0x11) + b'N' * 7))                                             # 1 network name cut (30 octets expected)
    bad.add(frame(header(0x40, 0x11) + netinfo(b'Net', [sta(1)], tail=b'')))                   # 2 stations up to the end: next octet read fails
    bad.add(frame(header(0x01, 0x11) + struct.pack('>HH', 40, 0x7856) + struct.pack('<H', 100) + b'x' * 10))   # 3 subframe length beyond the aggregate
    bad.add(frame(header(0x01, 0x11) + struct.pack('>HH', 10, 0x7856) + struct.pack('<H', 4) + b'ab'))         # 4 aggregate length 10 but frame shorter
    bad.add(frame(header(0x01, 0x11) + b'\x00\x05\x78'))                                       # 5 aggregate header cut after three octets
    bad.add(frame(header(0x01, 0x11) + struct.pack('>HH', 0x0fff, 0x7856) + struct.pack('<H', 0x0123) + b'y' * 50))   # 6 subframe of 291 octets, 50 present
    bad.add(frame(header(0x40, 0x11)[:12]))                                                   # 7 header cut in the timestamp
    bad.add(frame(header(0x40, 0x11)[:3]))                                                    # 8 header cut after the counter
    bad.add(raw_eth(BASE, MAC_A, 8, b'\xaa\xaa\x03\x00\x20\xf6\x40\x11'))                     # 9 only two octets of Turbocell
    nest = frame(header(0x01, 0x11) + agg([eth_ip(4)]))
    for i in range(5):
        nest = frame(header(0x01, 0x11) + agg([nest]))
    bad.add(nest)                                                                             # 10 Turbocell aggregates nested five levels deep
    bad.write(os.path.join(out, 'turbocell-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
