#!/usr/bin/env python3
# Generates test/captures/pathport_coverage.pcap.gz
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

    def add(self, data, comment=None):
        self.frames.append(data)
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, d in enumerate(self.frames):
                t = 1700000000 + i
                f.write(struct.pack('<IIII', t, 1000 * i, len(d), len(d)))
                f.write(d)
        return len(self.frames)

# ---- pathport ----
# Pathport (ETC / Pathway Connectivity): UDP port 3792 (the default port
# of the dissector) and the UDP heuristic on other ports.
PP_PORT = 3792
BCAST = 0xffffffff
MCAST_ALL = 0xefffedff
MCAST_DATA = 0xefffed01
MCAST_MANAGE = 0xefffed02
PADS = [0, 3, 2, 1]


def pad4(b):
    return b + bytes(PADS[len(b) % 4])


def header(src, dst, seq=1, magic=0xed01, version=0x0002):
    return struct.pack('>HHH', magic, version, seq) + bytes(6) + struct.pack('>II', src, dst)


def pdu(ptype, payload, plen=None):
    # PDU header, payload padded to a multiple of 4 octets
    return struct.pack('>HH', ptype, len(payload) if plen is None else plen) + pad4(payload)


def tlv(ptype, value):
    return struct.pack('>HH', ptype, len(value)) + pad4(value)


def data_block(enc, start_code, dst, levels):
    return (struct.pack('>HHBBH', enc, len(levels), 0, start_code, dst) + pad4(levels))


def pkt(hdr, *pdus):
    return hdr + b''.join(pdus)


def f(p, sport=40001, dport=PP_PORT, ident=1):
    return udp_frame(p, sport, dport, ident)


def build(out):
    main = Pcap()
    h = header(MCAST_MANAGE, BCAST)
    main.add(f(pkt(h, pdu(0x0301, b'')), ident=1))                                   # 1 ARP request, known IDs
    main.add(f(pkt(header(0x0a000001, 0x0a000002), pdu(0x0301, b'')), ident=2))      # 2 ARP request, unknown IDs
    arp = struct.pack('>I4sBBBB', 0x0a000001, IP_A, 0x20, 0x01, 0x02, 0x08)
    main.add(f(pkt(header(0x0a000001, MCAST_MANAGE), pdu(0x0302, arp)), ident=3))    # 3 ARP reply
    arp2 = struct.pack('>I4sBBBB', MCAST_DATA, IP_B, 0x20, 0x01, 0x02, 0x08)
    main.add(f(pkt(header(0x0a000001, MCAST_ALL), pdu(0x0302, arp2)), ident=4))      # 4 ARP reply, a well known ID
    pids = [0x0401, 0x0411, 0x0413, 0x0482, 0x0461, 0x04dd, 0x0702, 0x0000, 0xffff, 0x1101, 0x7777]
    main.add(f(pkt(h, pdu(0x0222, b''.join(struct.pack('>H', p) for p in pids))), ident=5))  # 5 Get, 11 PIDs (padding)
    main.add(f(pkt(h, pdu(0x0222, struct.pack('>HH', 0x0401, 0x0482))), ident=6))    # 6 Get, 2 PIDs
    reply = (tlv(0x0401, b'pathport-node') + tlv(0x0413, struct.pack('>I', 100))
             + tlv(0x0421, bytes.fromhex('00000c000102')) + tlv(0x0422, IP_A)
             + tlv(0x0000, b'') + tlv(0x04e1, b'notes') + tlv(0x3333, b'\1\2\3') + tlv(0xffff, b''))
    main.add(f(pkt(h, pdu(0x0223, reply)), ident=7))                                  # 7 Get reply, TLVs
    main.add(f(pkt(h, pdu(0x0400, tlv(0x0401, b'new name') + tlv(0x0414, b'\1') + tlv(0x04a1, b''))), ident=8))  # 8 Set
    main.add(f(pkt(h, pdu(0x0303, tlv(0x04dd, b'Model') + tlv(0x04de, b'Maker') + tlv(0x04df, b'1.2.3'))), ident=9))  # 9 ARP extend info
    lv = bytes(range(10))
    main.add(f(pkt(header(0x0a000001, MCAST_DATA), pdu(0x0100, data_block(0x0101, 0, 0x0200, lv))), ident=10))  # 10 flat, 10 channels at xDMX 512
    two = data_block(0x0101, 0, 0x0000, bytes(8)) + data_block(0x0103, 0xdd, 0x0400, b'')
    main.add(f(pkt(header(0x0a000001, MCAST_DATA), pdu(0x0100, two)), ident=11))     # 11 two blocks (flat and release)
    main.add(f(pkt(h, pdu(0x0999, b'unknown')), ident=12))                           # 12 unknown PDU type
    main.add(f(pkt(header(0x0a000001, MCAST_MANAGE), pdu(0x0302, arp), pdu(0x0222, struct.pack('>HH', 0x0401, 0x0411))), ident=13))  # 13 two PDUs
    main.add(f(pkt(h, pdu(0x0301, b'')), sport=3792, dport=3792, ident=14))           # 14 both ports
    main.add(f(pkt(h, pdu(0x0301, b''), pdu(0x0301, b'')), sport=50000, dport=50001, ident=15))  # 15 heuristic, two ARP requests
    main.add(f(b'\xed\x01' + bytes(10), dport=PP_PORT, ident=16))                    # 16 shorter than the minimum: plain UDP
    n = main.write(os.path.join(out, 'pathport-coverage.pcap'))

    bad = Pcap()
    bad.add(f(pkt(h, struct.pack('>HH', 0x0301, 4)), ident=1))                       # 1 PDU length beyond the packet (ARP request)
    bad.add(f(pkt(h, struct.pack('>HH', 0x0302, 12) + bytes(6)), ident=2))           # 2 ARP reply cut short
    bad.add(f(pkt(h, struct.pack('>HH', 0x0222, 20) + bytes(6)), ident=3))           # 3 Get cut short
    bad.add(f(pkt(h, struct.pack('>HH', 0x0223, 12) + struct.pack('>HH', 0x0401, 40) + bytes(4)), ident=4))  # 4 TLV beyond the PDU
    bad.add(f(pkt(h, struct.pack('>HH', 0x0223, 6) + struct.pack('>HH', 0x0401, 2) + bytes(2)), ident=5))    # 5 TLV, PDU ends mid-TLV header
    bad.add(f(pkt(h, struct.pack('>HH', 0x0100, 16) + struct.pack('>HHBBH', 0x0101, 400, 0, 0, 0) + bytes(4)), ident=6))  # 6 data block beyond the packet
    bad.add(f(pkt(h, struct.pack('>HH', 0x0100, 3) + bytes(4)), ident=7))            # 7 data PDU shorter than a block header
    bad.add(f(pkt(h, struct.pack('>HH', 0x0999, 400) + bytes(4)), ident=8))          # 8 unknown PDU, length beyond the packet
    bad.add(f(pkt(h, pdu(0x0301, b''), struct.pack('>H', 0x0301)), ident=9))        # 9 second PDU header cut
    bad.add(f(h + struct.pack('>H', 0x0301) + bytes(2), ident=10))                   # 10 24 octets, PDU length 0
    bad.add(f(pkt(header(0x0a000001, MCAST_DATA, magic=0x7e01), pdu(0x0301, b'')), dport=PP_PORT, ident=11))  # 11 wrong magic number (heuristics try other dissectors)
    nb = bad.write(os.path.join(out, 'pathport-coverage-malformed.pcap'))
    print('main', n, 'malformed', nb)


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
