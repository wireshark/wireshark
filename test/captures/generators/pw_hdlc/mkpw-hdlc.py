#!/usr/bin/env python3
# Generates test/captures/pw_hdlc_coverage.pcap.gz
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

# ---- pw-hdlc ----
# HDLC pseudowires, no CW: Frame Relay port mode and PPP (Decode As mpls.label).
L_FR, L_PPP = 4001, 4002


def ip_udp(n=0, ident=1):
    return ipv4(udp(bytes((i & 0xff) for i in range(n)), 6000, 6001), ident=ident)


def ppp_ip(ident=1):
    return struct.pack('>H', 0x0021) + ip_udp(4, ident)


def ppp_lcp(code=9, ident=1):
    # LCP Echo-Request: code, identifier, length 8, magic number
    return struct.pack('>HBBHI', 0xc021, code, ident, 8, 0x01020304)


def hdlc(addr, ctl, ppp):
    return bytes([addr, ctl]) + ppp


def fr(addr, p, ctl=0x03, nlpid=0xcc):
    return addr + bytes([ctl, nlpid]) + p


def m(label, p):
    return mpls_frame(label, p)


# control byte values: (control, name)
UFRAMES = [0x03, 0x23, 0x43, 0x63, 0x83, 0xe3, 0x07, 0x87, 0x0f, 0x2f, 0x4f,
           0x6f, 0x8f, 0xaf, 0xcf]


def build(out):
    main = Pcap()
    # PPP in HDLC: all stations address, UI
    main.add(m(L_PPP, hdlc(0xff, 0x03, ppp_ip(1))))               # 1
    main.add(m(L_PPP, hdlc(0x05, 0x03, ppp_lcp())))               # 2 other address, C/R bit clear
    main.add(m(L_PPP, hdlc(0x06, 0x03, ppp_lcp(9, 2))))           # 3 C/R bit set
    main.add(m(L_PPP, hdlc(0xff, 0x00, ppp_ip(3))))               # 4 I frame
    main.add(m(L_PPP, hdlc(0xff, 0x01, ppp_lcp(9, 3))))           # 5 S frame
    for i, c in enumerate(UFRAMES):                               # 6-20 U frames, every modifier
        main.add(m(L_PPP, hdlc(0xff, c, ppp_lcp(9, 10 + i))))
    main.add(m(L_PPP, hdlc(0xff, 0x13, ppp_lcp(9, 30))))          # 21 UI with the poll/final bit
    main.add(m(L_PPP, hdlc(0xff, 0x5b, ppp_lcp(9, 31))))          # 22 U frame, unknown modifier
    # Frame Relay port mode
    main.add(m(L_FR, fr(bytes([0x04, 0x01]), ip_udp(4, 40))))     # 23 DLCI 16, two octet address
    main.add(m(L_FR, fr(bytes([0x1c, 0x2f]), ip_udp(4, 41))))     # 24 FECN/BECN/DE and C/R bits
    main.add(m(L_FR, fr(bytes([0x04, 0x00, 0x21]), ip_udp(4, 42))))  # 25 three octet address
    main.add(m(L_FR, fr(bytes([0x08, 0x01]), bytes([0, 0, 0, 0x08, 0x00]) + ip_udp(4, 43), nlpid=0x80)))  # 26 SNAP
    # first nibble 4 / 6 / 1 are not special here: the handlers take every payload
    n = main.write(os.path.join(out, 'pw-hdlc-coverage.pcap'))

    bad = Pcap()
    bad.add(m(L_PPP, b'\xff'))                                     # 1 shorter than the HDLC header
    bad.add(m(L_PPP, hdlc(0xff, 0x03, b'')))                       # 2 no PPP payload
    bad.add(m(L_PPP, hdlc(0xff, 0x03, b'\x00')))                   # 3 truncated PPP protocol field
    bad.add(m(L_FR, b'\x04'))                                      # 4 truncated FR address
    bad.add(m(L_FR, bytes([0x04, 0x01, 0x03])))                    # 5 no NLPID
    nb = bad.write(os.path.join(out, 'pw-hdlc-coverage-malformed.pcap'))
    print('main', n, 'malformed', nb)


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
