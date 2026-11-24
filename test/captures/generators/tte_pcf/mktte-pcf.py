#!/usr/bin/env python3
# Generates test/captures/tte_pcf_coverage.pcap.gz
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

# ---- tte-pcf ----
# TTEthernet Protocol Control Frames: ethertype 0x891d (registered by default).
# The TTE heuristic also accepts every PCF on Ethernet; PCFs behind a VLAN tag
# reach only this dissector.
SRC = bytes.fromhex('020000000001')
DST = bytes.fromhex('01aabb000001')


def pcf(ic, mn, sp, sd, typ, tc, res0=0, res1=bytes(5)):
    return (struct.pack('>III', ic, mn, res0) + bytes([sp, sd, typ]) + res1 + struct.pack('>Q', tc))


def f(p, dst=DST):
    return raw_eth(dst, SRC, 0x891d, p)


def build(out):
    main = Pcap()
    main.add(f(pcf(1, 0xff, 2, 1, 2, 0x1122334455667788)))                  # 1 integration frame
    main.add(f(pcf(2, 0xf0f0, 7, 3, 4, 5)))                                 # 2 coldstart frame
    main.add(f(pcf(3, 1, 0, 0, 8, 0)))                                      # 3 coldstart ack frame
    main.add(f(pcf(4, 0xffffffff, 255, 255, 0x0f, 2**64 - 1)))              # 4 unknown type 0x0f, every field at its maximum
    main.add(f(pcf(5, 0, 0x10, 0x20, 0xf2, 7)))                             # 5 type 0xf2: only the low nibble (2) is the type
    main.add(f(pcf(6, 9, 1, 2, 2, 1, res0=0xdeadbeef, res1=b'\xff' * 5)))   # 6 reserved fields not zero (not shown)
    main.add(f(pcf(7, 1, 1, 1, 2, 1) + bytes(18)))                          # 7 PCF padded to the 60 octet minimum
    main.add(f(pcf(8, 1, 1, 1, 8, 1), dst=bytes.fromhex('0180c2000000')))   # 8 other destination address
    main.add(f(pcf(0, 0, 0, 0, 0, 0)))                                      # 9 everything zero (type 0 is unknown)
    vlan = struct.pack('>HH', 0x0064, 0x891d) + pcf(9, 3, 4, 5, 4, 6)
    main.add(raw_eth(DST, SRC, 0x8100, vlan))                               # 10 PCF behind a VLAN tag (not seen by the TTE heuristic)
    main.write(os.path.join(out, 'tte-pcf-coverage.pcap'))
    bad = Pcap()
    bad.add(f(pcf(1, 1, 1, 1, 2, 1)[:27]))                                  # 1 27 octets: one short, PCF declines
    bad.add(f(b''))                                                         # 2 no payload
    bad.add(f(pcf(1, 1, 1, 1, 2, 1)[:10]))                                  # 3 10 octets
    bad.add(f(pcf(1, 1, 1, 1, 2, 1)))                                       # 4 control: a complete PCF
    bad.add(f(pcf(1, 1, 1, 1, 2, 1)), snap=14 + 20)                       # 5 capture cut inside the payload (reported length is complete)
    bad.add(raw_eth(DST, SRC, 0x8100, struct.pack('>HH', 1, 0x891d) + pcf(1, 1, 1, 1, 2, 1)[:20]))   # 6 short PCF behind a VLAN tag
    bad.write(os.path.join(out, 'tte-pcf-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
