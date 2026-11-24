#!/usr/bin/env python3
# Generates test/captures/pw_oam_coverage.pcap.gz
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

# ---- pw-oam ----
# PW OAM (RFC 6478): PW ACH with channel type 0x0027, reached by default
# through the MPLS first nibble (1) and through the generic label 13.


def ach(chan=0x0027):
    return struct.pack('>BBH', 0x10, 0, chan)


def oam(timer=0x0258, total=8, flags=0, code=0x2, tlv_type=0x096a, tlv_len=4, rsv=0):
    return (struct.pack('>HBB', timer, total, flags)
            + struct.pack('>HHI', (rsv << 14) | tlv_type, tlv_len, code))


def m(label, p, bos=1):
    return mpls_frame(label, p, bos=bos)


def build(out):
    main = Pcap()
    main.add(m(100, ach() + oam()))                             # 1 PW status, AC ingress receive fault
    main.add(m(100, ach() + oam(flags=0x80, code=0x4)))         # 2 ACK flag, egress transmit fault
    main.add(m(100, ach() + oam(code=0x20)))                    # 3 forwarding standby
    main.add(m(100, ach() + oam(code=0x40, timer=0)))           # 4 request switchover, refresh timer 0
    main.add(m(100, ach() + oam(code=0x6)))                     # 5 combination not in the table
    main.add(m(100, ach() + oam(rsv=3, code=0)))                # 6 reserved bits set: TLV type 0xc96a is not recognised
    main.add(m(13, ach() + oam(code=0x2)))                      # 7 generic label 13 (GACH), PW OAM
    main.add(m(100, ach() + oam(tlv_type=0x0001, tlv_len=4)))   # 8 TLV type not handled
    main.add(m(100, ach() + oam(total=12, code=2) + b'\0' * 4)) # 9 trailing octets after the TLV
    n = main.write(os.path.join(out, 'pw-oam-coverage.pcap'))

    bad = Pcap()
    bad.add(m(100, ach() + b'\x00\x10'))                        # 1 header cut after the refresh timer
    bad.add(m(100, ach() + b'\x00\x10\x08\x00'))                # 2 no TLV type
    bad.add(m(100, ach() + b'\x00\x10\x08\x00\x09\x6a\x00\x04'))  # 3 TLV cut before the status code
    bad.add(m(100, ach() + b'\x00\x10\x08\x00\x09\x6a'))        # 4 TLV cut after the type
    bad.add(m(100, ach() + struct.pack('>HBBHH', 5, 4, 0, 0x096a, 0)))   # 5 PW status TLV without a status code
    nb = bad.write(os.path.join(out, 'pw-oam-coverage-malformed.pcap'))
    print('main', n, 'malformed', nb)


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
