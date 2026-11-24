#!/usr/bin/env python3
# Generates test/captures/tte_coverage.pcap.gz
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

# ---- tte ----
# TTEthernet: a heuristic dissector on Ethernet. Protocol Control Frames
# (ethertype 0x891d) are always accepted; critical traffic frames are
# found by the preferences "CT Mask" and "CT Marker" (tte.ct_mask_value
# and tte.ct_marker_value), so the captures are decoded with
# -o tte.ct_mask_value:ffff0000 -o tte.ct_marker_value:aabb0000
SRC = bytes.fromhex('020000000001')


def pcf(ic, mn, sp, sd, typ, tc, res=0):
    return (struct.pack('>III', ic, mn, res) + bytes([sp, sd, typ]) + bytes([0, 0, 0, 0, 0]) +
            struct.pack('>Q', tc))


def ct(cf, ctid):
    return struct.pack('>IH', cf, ctid)


ARP = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + SRC + bytes([192, 0, 2, 1]) + bytes(6) + bytes([192, 0, 2, 2])


def udp_payload(n):
    return ipv4(udp(b'tte' * n, 5000, 5001))


def build(out):
    main = Pcap()
    main.add(raw_eth(ct(0x01aabb00, 0x0001), SRC, 0x891d, pcf(1, 0xff, 2, 1, 2, 0x1122334455667788)))   # 1 PCF, integration frame
    main.add(raw_eth(ct(0x01aabb00, 0x0001), SRC, 0x891d, pcf(2, 0xf0f0, 7, 3, 4, 5)))                  # 2 PCF, coldstart frame
    main.add(raw_eth(ct(0x01aabb00, 0x0001), SRC, 0x891d, pcf(3, 1, 0, 0, 8, 0)))                       # 3 PCF, coldstart ack frame
    main.add(raw_eth(ct(0x01aabb00, 0x0001), SRC, 0x891d, pcf(4, 1, 255, 255, 0x1f, 2**64 - 1)))        # 4 PCF, unknown type with the high nibble set
    main.add(raw_eth(bytes.fromhex('0180c2000000'), SRC, 0x891d, pcf(5, 9, 1, 2, 2, 7)))                # 5 PCF to a destination that is no CT marker
    main.add(raw_eth(ct(0xaabb0001, 0x1234), SRC, 0x0800, udp_payload(3)))                              # 6 CT frame (marker aabb0001 matches the mask), IPv4: "TTEthernet Frame"
    main.add(raw_eth(ct(0xaabbffff, 0x0002), SRC, 0x0800, udp_payload(5)))                              # 7 CT frame, other low bits
    main.add(raw_eth(ct(0xaabb0001, 0x0003), SRC, 0x0020, bytes(range(32))))                            # 8 CT frame with an 802.3 length: "Bogus TTEthernet Frame"
    main.add(raw_eth(ct(0xaabb0001, 0x0004), SRC, 0x05dc, b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + bytes(1492 - 8)))  # 9 length 1500 (largest "bogus"), LLC/SNAP
    main.add(raw_eth(ct(0xaabb0001, 0x0005), SRC, 0x05dd, bytes(40)))                                   # 10 ethertype 1501: first "TTEthernet Frame"
    main.add(raw_eth(ct(0xaabb0001, 0x0006), SRC, 0x88b5, bytes(40)))                                   # 11 CT frame with an ethertype that has no dissector (data)
    main.add(raw_eth(ct(0xccdd0001, 0x0001), SRC, 0x0800, udp_payload(2)))                              # 12 not CT (marker mismatch): plain Ethernet
    main.add(raw_eth(ct(0xaabb0001, 0x0007), SRC, 0x891d, pcf(6, 1, 1, 1, 2, 1)))                       # 13 PCF whose destination is also a CT marker
    main.add(raw_eth(ct(0xaabb0001, 0x0008), SRC, 0x0806, ARP))                                       # 14 CT frame carrying ARP
    main.add(raw_eth(ct(0xaabb0001, 0x0009), SRC, 0x0806, struct.pack('>HHBBH', 1, 0x0800, 0, 0, 1) + bytes(20)))   # 15 ARP with address lengths 0: a long Ethernet trailer (the field id 0 assertion before the fix)
    main.write(os.path.join(out, 'tte-coverage.pcap'))
    bad = Pcap()
    bad.add(raw_eth(ct(0x01aabb00, 1), SRC, 0x891d, pcf(1, 1, 1, 1, 2, 1)[:20]))                        # 1 PCF shorter than 28 octets: PCF declines
    bad.add(raw_eth(ct(0x01aabb00, 1), SRC, 0x891d, b''))                                               # 2 PCF header with no payload
    bad.add(raw_eth(ct(0xaabb0001, 1), SRC, 0x0800, b'\x45'))                                           # 3 CT frame with a truncated IPv4 header
    bad.add(raw_eth(ct(0xaabb0001, 1), SRC, 0x0800, udp_payload(3)), snap=14 + 10)                      # 4 CT frame cut off in the IPv4 header
    bad.add(raw_eth(ct(0xaabb0001, 1), SRC, 0x891d, pcf(1, 1, 1, 1, 2, 1)), snap=14 + 12)               # 5 PCF cut off inside the payload
    bad.add(raw_eth(ct(0xaabb0001, 1), SRC, 0x0000, b''))                                               # 6 CT frame with ethertype 0 and no payload
    bad.add(raw_eth(ct(0xaabb0001, 1), SRC, 0x0800, udp_payload(3) + bytes(9)))                         # 7 IPv4 in a CT frame padded to 60 octets: the Ethernet trailer asserts (trailer id 0)
    bad.add(raw_eth(ct(0xaabb0001, 1), SRC, 0x0806, struct.pack('>HHBBH', 1, 0x0800, 0, 0, 1) + bytes(20)))  # 8 ARP with address lengths 0: a long trailer, the same assertion
    bad.write(os.path.join(out, 'tte-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
