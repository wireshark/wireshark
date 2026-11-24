#!/usr/bin/env python3
# Generates test/captures/ttl_coverage.pcap.gz
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

# ---- ttl ----
# TTL (TTX Logger) entries in Ethernet frames, ethertype 0x4040 (registered by
# default). The file format reader is not covered: it needs a TTL file with
# the logger header (wiretap/ttl.c). The "dissect next layer" preference
# (ttl.dissect_next_layer) makes the dissector hand the Ethernet, CAN, LIN and
# FlexRay payloads on; the captures are made to decode with it enabled.
BUS, CMD, RSV, JRN, SEG, SENDF, PAD, SWD, DROP = 0, 1, 2, 3, 4, 5, 6, 7, 8
FPGA, ATOM, TC1, TC2, TC3, TDA, FPGAA, FPGAB = range(8)


def addr(cascade, device, function):
    return (cascade << 10) | (device << 6) | function


ETH1 = addr(0, FPGA, 3)       # ETH A (CH1)
CAN1 = addr(0, FPGA, 11)
LIN1 = addr(0, FPGA, 29)
FR1A = addr(0, FPGA, 5)
FR1B = addr(0, FPGA, 6)
MOST = addr(0, FPGA, 1)
TAPETH = addr(1, 0, 3)        # TAP 1, PT-15 FPGA, 100BASE-T1 1a
TS = 1700000000 * 1000000


def entry(typ, dst, src, status, payload=b'', meta1=0, ack=0, ts=TS, size=None):
    n = 16 + len(payload) if size is None else size
    return (struct.pack('<HHHH', (typ << 12) | n, (meta1 << 13) | dst, (ack << 13) | src, status) +
            struct.pack('<Q', ts) + payload)


def frame(e):
    return raw_eth(MAC_B, MAC_A, 0x4040, e)


def eth_payload(n=20):
    return b'\0\0' + raw_eth(MAC_B, MAC_A, 0x0800, ipv4(udp(b'ttl!' * (n // 4), 45000, 45001)))


def can_payload(cid, data):
    return struct.pack('<I', cid) + data


def can_status(dlc, valid=1, rtr=0, busoff=0, matched=0, err=0, ide=0, edl=0, brs=0, esi=0):
    return (valid | rtr << 1 | busoff << 2 | matched << 3 | err << 4 | dlc << 8 | ide << 12 |
            edl << 13 | brs << 14 | esi << 15)


def fr_frame(fid, data, cyc=1, sync=1):
    plen = len(data) // 2
    h = (sync << 36) | (1 << 35) | (fid << 24) | (plen << 17) | (0x123 << 6) | cyc
    return struct.pack('>Q', h)[3:] + data + b'\x01\x02\x03'


def segment(src, fid, num, data, total=None, typ=3, dst=0, status=None):
    st = (fid << 4) | num if status is None else status
    if num == 0:
        data = struct.pack('<II', len(data) if total is None else total, typ) + data
    return entry(SEG, dst, src, st, data)


def nest(levels, inner, src=0x0031, fid=3):
    for i in range(levels):
        inner = segment(src, fid, 0, inner)
    return inner


def build(out):
    main = Pcap()
    add = lambda e: main.add(frame(e))
    # bus data: Ethernet
    add(entry(BUS, addr(0, FPGA, 0), ETH1, 0x0001, eth_payload()))                  # 1 valid Ethernet frame
    for st in (0x0002, 0x0004, 0x0008, 0x0010, 0x2000, 0x4000, 0x0100):            # 2-8 CRC error, length error, PHY error, TX error, TX FreeMem, TX frame, unknown status
        add(entry(BUS, 0, ETH1, st, eth_payload(8)))
    add(entry(BUS, 0, ETH1, 0x8000, struct.pack('<HBB', 0x1234, 0x01, 0x80) + struct.pack('<HBB', 0x00ff, 0xe5, 0x6a) + b'\x01\x02'))   # 9 PHY status (cascade 0): two entries and a short rest
    add(entry(BUS, 0, TAPETH, 0x8000, struct.pack('<HBB', 0x1234, 0x01, 0x82) + struct.pack('<HBB', 0x0001, 0x02, 0x8d)))             # 10 PHY status from a TAP (cascade 1): PHY addresses
    add(entry(BUS, 0, TAPETH, 0x0001, eth_payload(12)))                              # 11 Ethernet frame from a TAP
    # CAN
    add(entry(BUS, 0, CAN1, can_status(8), can_payload(0x123, bytes(range(8)))))                                                     # 12 CAN standard frame, 8 bytes
    add(entry(BUS, 0, CAN1, can_status(4, ide=1), can_payload(0x1abcdef, bytes(4))))                                                 # 13 CAN extended frame
    add(entry(BUS, 0, CAN1, can_status(15, edl=1, brs=1, esi=1), can_payload(0x77, bytes(range(64)))))                                # 14 CAN FD frame with BRS and ESI
    add(entry(BUS, 0, CAN1, can_status(0, rtr=1, busoff=1, matched=1, err=3), can_payload(0x55, b'')))                                # 15 remote frame, bus off, matched, error code 3
    # LIN
    add(entry(BUS, 0, LIN1, 0x01c2 | (0 << 8), bytes([1, 2, 3, 4, 0xaa])))                                                          # 16 LIN frame (PID 0xc2), checksum 0xaa
    add(entry(BUS, 0, LIN1, 0x3f80 | 0x2d, bytes([0x55])))                                                                          # 17 LIN with only the checksum octet (size 1), error flags
    add(entry(BUS, 0, LIN1, 0xffc1, bytes([9, 8, 7]) + b'\x11'))                                                                      # 18 LIN with every error flag
    # FlexRay
    add(entry(BUS, 0, FR1A, 0x0000 | 0x7f00, fr_frame(5, bytes(range(8)))))                                                          # 19 FlexRay regular frame (channel A), every error flag clear
    add(entry(BUS, 0, FR1B, 0x0001 | 0x7e00, fr_frame(6, bytes(range(4)), cyc=2, sync=1)))                                            # 20 aborted frame, channel B
    add(entry(BUS, 0, FR1A, 0x0002, struct.pack('<HH', 7, 0)))                                                                       # 21 0 pulse
    add(entry(BUS, 0, FR1A, 0x0003 | 0x00f8, struct.pack('<HH', 3, 0) + b'\xaa\xbb'))                                                 # 22 1 pulse with trailing data
    add(entry(BUS, 0, FR1A, 0x0004, struct.pack('<7I', *range(1, 8)) + b'\x99'))                                                     # 23 error information (seven registers) and an octet
    add(entry(BUS, 0, FR1A, 0x0007, b'xyz'))                                                                                          # 24 FlexRay with an unknown item type
    add(entry(BUS, 0, MOST, 0x0000, b'most data'))                                                                                   # 25 unsupported interface (MOST)
    # other entry types
    for t, p in ((CMD, b'cmd'), (RSV, b''), (JRN, b'journal entry'), (SENDF, b'send'), (PAD, b''), (SWD, b'sw data'), (DROP, struct.pack('<I', 5)), (9, b'x'), (15, b'')):
        add(entry(t, addr(0, ATOM, 2), CAN1, 0x1234, p))                             # 26-34 command, reserved, journal, send frame, padding, software data, dropped frames, types 9 and 15
    # addresses: every logger device and every TAP device in destination and source
    dsts = [addr(0, d, 1) for d in range(8)] + [addr(0, 8, 1), addr(0, 15, 63)]
    srcs = [addr(1 + (i % 7), d, (i * 5) % 40 + 1) for i, d in enumerate((0, 1, 2, 3, 4, 5, 6, 7, 8, 9))]
    for i in range(10):                                                                # 35-44 padding entries: destination devices 0-7, 8, 15 with TAP source devices
        add(entry(PAD, dsts[i], srcs[i], 0, b'', meta1=i & 7, ack=i % 8))
    srcs2 = [addr(0, d, 2) for d in range(8)] + [addr(0, 8, 0), addr(0, 15, 1)]
    dsts2 = [addr(1 + (i % 7), d, (i * 3) % 30 + 1) for i, d in enumerate((0, 1, 2, 3, 4, 5, 6, 7, 8, 9))]
    for i in range(10):                                                                # 45-54 padding entries: TAP destinations, logger source devices 0-7, 8, 15
        add(entry(PAD, dsts2[i], srcs2[i], 0, b'', meta1=7 - (i & 7), ack=(i + 3) % 8))
    # segmented messages
    fw = bytes(range(100))
    add(segment(0x0011, 1, 0, fw[:40], total=100, typ=1))                              # 55 firmware, header and the first 40 octets
    add(segment(0x0011, 1, 1, fw[40:80]))                                              # 56 second fragment
    add(segment(0x0011, 1, 2, fw[80:]))                                                # 57 third fragment: reassembled
    add(segment(0x0012, 2, 0, b'configuration', typ=2))                                # 58 configuration in one fragment
    e1 = entry(BUS, 0, ETH1, 0x0001, eth_payload(16))
    add(segment(0x0013, 4, 0, e1[:20], total=len(e1), typ=3))                          # 59 nested frame, first fragment
    add(segment(0x0013, 4, 1, e1[20:]))                                                # 60 second fragment: the nested entry is dissected
    add(segment(0x0014, 5, 3, b'orphan fragment'))                                     # 61 fragment 3 without a header (nothing in progress)
    add(segment(0x0016, 7, 0, b'invalid type', typ=0))                                 # 65 type 0 (invalid), complete
    add(segment(0x0017, 8, 0, b'unknown type', typ=77))                                # 66 unknown segment type
    frame_nest = entry(BUS, 0, ETH1, 0x0001, eth_payload(8))
    add(nest(1, e1))                                                                   # 67 nested frame in one fragment (one level)
    add(nest(4, e1))                                                                   # 68 four levels of nested segmented entries with one key (the limit)
    add(nest(3, e1, src=0x0032, fid=4))                                                # 69 three levels, another key
    add(nest(5, e1))                                                                   # 70 five levels: the fifth is refused (warning, the nesting limit)
    add(entry(SEG, 0, 0x0020, 0xffff, b'xxxx'))                                        # 71 segmented entry with the reserved status 0xffff (warning)
    add(segment(0x0015, 6, 0, fw[:10], total=500, typ=1))                              # 69 header of a message that never completes
    add(segment(0x0015, 6, 0, fw[:10], total=50, typ=1))                               # 70 new header for the same key while one is in progress (tvb_free(NULL) assertion before the fix)
    main.write(os.path.join(out, 'ttl-coverage.pcap'))

    fw = bytes(range(100))
    bad = Pcap()
    addb = lambda e, **kw: bad.add(frame(e), **kw)
    addb(segment(0x0015, 6, 0, fw[:10], total=500, typ=1))                             # 1 header of a message that never completes
    addb(segment(0x0015, 6, 0, fw[:10], total=50, typ=1))                              # 2 new header for the same key while one is in progress: tvb_free(NULL) assertion
    addb(nest(6, e1))                                                                  # 1 six levels: "nested segmented messages too deep" warning (past the limit of four)

    addb(entry(BUS, 0, ETH1, 0x0001, b'', size=10))                                    # 4 entry size 10 (below the 16 byte header): the reproducer of the size fix
    addb(entry(BUS, 0, ETH1, 0x0001, b'', size=3))                                     # 5 entry size 3
    addb(entry(BUS, 0, ETH1, 0x0001, b'', size=0))                                     # 6 entry size 0
    e = entry(BUS, 0, ETH1, 0x0001, eth_payload(8))
    for n in (1, 3, 5, 7, 9, 11, 13, 15):
        addb(e[:n])                                                                    # 7-14 entry cut after 1, 3, 5, 7, 9, 11, 13, 15 octets
    addb(e[:20])                                                                       # 15 cut inside the timestamp
    addb(e[:16])                                                                       # 16 header only, payload missing (size says more)
    addb(entry(BUS, 0, CAN1, can_status(8), can_payload(1, b'')[:2]))                  # 17 CAN entry with two octets (no CAN id)
    addb(entry(BUS, 0, ETH1, 0x8000, b'\x01'))                                         # 18 PHY status with one octet
    addb(entry(BUS, 0, ETH1, 0x0001, b'\x00'))                                         # 19 Ethernet entry with one octet
    addb(entry(BUS, 0, LIN1, 0x01c2, b''))                                             # 20 LIN entry without data
    addb(entry(BUS, 0, FR1A, 0x0004, b'\x01\x02'))                                     # 21 FlexRay error information with two octets
    addb(entry(BUS, 0, FR1A, 0x0002, b'\x01'))                                         # 22 FlexRay pulse with one octet
    addb(entry(SEG, 0, 0x0021, 0x0010, b'\x05\x00'))                                   # 23 segmented header cut in the size
    addb(entry(SEG, 0, 0x0021, 0x0010, struct.pack('<I', 5)))                          # 24 segmented header without the type
    addb(entry(SEG, 0, 0x0022, 0x0021, b''))                                           # 25 fragment 1 without data and without a header
    addb(segment(0x0023, 9, 0, b'nested garbage', typ=3))                              # 26 nested frame that is not a TTL entry
    addb(segment(0x0024, 10, 0, b'\x01', typ=3))                                       # 27 nested frame of one octet
    addb(segment(0x0025, 11, 0, entry(SEG, 0, 0x0025, 0x00b0, b'\x00\x00\x00\x00'), typ=3))   # 28 nested segmented entry with the same key, truncated header
    addb(entry(BUS, 0, ETH1, 0x0001, eth_payload(8)), snap=14 + 6)                     # 29 captured length stops inside the header
    addb(frame_nest, snap=14 + 24)                                                     # 30 captured length stops in the middle of the entry
    bad.write(os.path.join(out, 'ttl-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
