#!/usr/bin/env python3
# Generates test/captures/tzsp_coverage.pcap.gz
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

# ---- tzsp ----
# TZSP (Tazmen Sniffer Protocol) on UDP port 37008 (default) and, in the extra
# capture tzsp-coverage-wtap.pcap, as link type 128 (WTAP_ENCAP_TZSP).
PORT = 37008
END = b'\x01'


def opt(tag, data):
    return bytes([tag, len(data)]) + data


def tz(typ, encap, opts=b'', payload=b'', ver=1, end=True):
    return struct.pack('>BBH', ver, typ, encap) + opts + (END if end else b'') + payload


def inner_ip(n=10):
    return ipv4(udp(b'tzsp' * n, 45000, 45001))


def inner_eth(n=10):
    return raw_eth(MAC_B, MAC_A, 0x0800, inner_ip(n))


def dot11():
    return struct.pack('<HH', 0x0148, 0) + MAC_B + MAC_A + MAC_B + struct.pack('<H', 0x10)   # null data frame, to DS


def f(p, ident):
    return udp_frame(p, 50000, PORT, ident)


def wrap(n, payload, start_ident=1000):
    """n levels of TZSP-in-UDP-in-IP (encapsulation 7, raw IP) around payload."""
    for i in range(n):
        payload = ipv4(udp(tz(0, 7, payload=payload), 50000, PORT), ident=start_ident + i)
    return payload


def build(out):
    main = Pcap()
    n = [0]

    def add(p):
        n[0] += 1
        main.add(f(p, n[0]))
    wlan = (opt(10, b'\xc4') + opt(11, b'\xa6') + opt(12, b'\x6e') + opt(13, struct.pack('>I', 123456)) +
            opt(14, b'\x00') + opt(15, b'\x00') + opt(16, b'\x00') + opt(17, b'\x00') + opt(18, b'\x06') +
            opt(60, MAC_A) + opt(40, struct.pack('>I', 77)) + opt(41, struct.pack('>H', 1514)))
    add(tz(0, 1, wlan, inner_eth()))                                        # 1 received packet, Ethernet, every WLAN option, FCS good
    add(tz(1, 1, b'\x00\x00\x00', inner_eth()))                             # 2 packet for transmit, three Pad options
    add(tz(3, 1, opt(99, b'cfg'), inner_eth()))                             # 3 configuration with an unknown option
    add(tz(4, 1))                                                           # 4 keepalive (no options, no payload)
    add(tz(5, 1))                                                           # 5 port opener
    tr = b'\x10\x40' + MAC_B + MAC_A + b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + inner_ip()
    add(tz(0, 2, b'', tr))                                                  # 6 Token Ring
    add(tz(0, 3, b'', b'slip data'))                                        # 7 SLIP: no dissector, shown as UNKNOWN
    add(tz(0, 4, b'', b'\xff\x03\x00\x21' + inner_ip()))                    # 8 PPP
    fddi = b'\x50' + MAC_B + MAC_A + b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + inner_ip()
    add(tz(0, 5, b'', fddi))                                                # 9 FDDI
    add(tz(0, 7, b'', inner_ip()))                                          # 10 raw IP
    add(tz(0, 18, b'', dot11()))                                            # 11 IEEE 802.11
    prism = struct.pack('<II', 0x44, 144) + b'wlan0'.ljust(16, b'\0') + b''.join(
        struct.pack('<IHHI', 0x1000 + i, 0, 4, 0) for i in range(10))
    add(tz(0, 119, b'', prism + dot11()))                                   # 12 Prism
    add(tz(0, 126, b'', struct.pack('<BBHI', 0, 0, 8, 0) + dot11()))        # 13 radiotap
    avs = struct.pack('>II', 0x80211001, 64) + bytes(16) + struct.pack('>IIIIIIIIII', 8, 36, 6000000, 0, 0, 0, 0, 0, 2, 0)
    add(tz(0, 127, b'', avs + dot11()))                                     # 14 AVS
    add(tz(0, 99, b'', b'unknown encapsulation'))                           # 15 unknown encapsulation 99
    add(tz(0, 1, opt(18, struct.pack('>H', 191)) + opt(12, b'\x14'), inner_eth()))         # 16 two octet channel (191 = 6 GHz), rate 2 Mbit/s
    add(tz(0, 1, opt(18, b'\x24') + opt(12, b'\x0a') + opt(14, b'\x01') + opt(15, b'\x01'), inner_eth()))   # 17 channel 36, rate 0x0a, message type 1, PCF set
    add(tz(0, 1, opt(80, b'sensor-1') + opt(81, b'lab') + opt(82, struct.pack('>II', 1700000000, 5000)) +
           opt(83, b'info text') + opt(84, struct.pack('>I', 99)) + opt(99, b'\x01\x02\x03'), inner_eth()))   # 18 device name, location, time stamp, info, capture id, unknown tag
    add(tz(0, 1, opt(17, b'\x01') + opt(16, b'\x00'), inner_eth()))         # 19 FCS error
    add(tz(0, 1, opt(17, b'\x00') + opt(16, b'\x01'), inner_eth()))         # 20 not decrypted: "Encrypted"
    add(tz(0, 1, opt(82, struct.pack('>I', 1700000001)) + opt(12, b'\x07') + opt(14, b'\x04'), inner_eth()))   # 21 four octet time stamp, unknown rate, 802.11 management type
    add(tz(0, 7, b'', wrap(3, inner_ip())))                                 # 22 TZSP nested three levels deep (UDP port 37008 inside raw IP)
    add(tz(0, 1, opt(40, struct.pack('>I', 1)) + opt(41, struct.pack('>H', 60)) + opt(60, MAC_B), inner_eth(0)))   # 23 minimal payload
    add(tz(2, 1, b'', inner_eth()))                                         # 24 unknown packet type 2
    add(tz(0, 1, ver=2, opts=b'', payload=inner_eth()))                     # 25 version 2
    main.write(os.path.join(out, 'tzsp-coverage.pcap'))

    wt = Pcap(128)
    wt.add(tz(0, 1, opt(18, b'\x01'), inner_eth()))                         # link type 128: TZSP directly
    wt.add(tz(4, 1))
    wt.write(os.path.join(out, 'tzsp-coverage-wtap.pcap'))

    bad = Pcap()
    m = [0]

    def addb(p, snap=None):
        m[0] += 1
        bad.add(f(p, m[0]), snap=snap)
    deep = tz(0, 7, b'', wrap(130, inner_ip()))
    addb(deep)                                                              # 1 TZSP nested 131 levels: "Maximum protocol layer depth" exception item (no abort)
    addb(tz(0, 1, b'', b'', end=False))                                     # 2 options missing: no END tag
    addb(b'\x01\x00\x00')                                                   # 3 header cut in the encapsulation
    addb(b'\x01\x00')                                                       # 4 header of two octets
    addb(struct.pack('>BBH', 1, 0, 1) + b'\x0a')                            # 5 option without a length octet
    addb(struct.pack('>BBH', 1, 0, 1) + b'\x0a\x20' + b'\xc4')              # 6 option length beyond the packet
    addb(struct.pack('>BBH', 1, 0, 1) + b'\x12\x02\x01')                    # 7 channel option, length 2 with one octet
    addb(struct.pack('>BBH', 1, 0, 1) + opt(18, b'\x01\x02\x03\x04') + END + inner_eth())    # 8 channel option with four octets
    addb(struct.pack('>BBH', 1, 0, 1) + b'\x28\x02\x00\x01' + END)          # 9 packet id with length 2 (reads four octets)
    addb(struct.pack('>BBH', 1, 0, 1) + b'\x3c\x02\x00\x01' + END)          # 10 sensor MAC with length 2 (reads six)
    addb(struct.pack('>BBH', 1, 0, 1) + b'\x52\x03\x00\x00\x01' + END)      # 11 time stamp with length 3
    addb(struct.pack('>BBH', 1, 0, 1) + b'\x52\x00' + END)                  # 12 time stamp with length 0
    addb(struct.pack('>BBH', 1, 0, 1) + b'\x0d\x01\x00' + END)              # 13 time option with length 1 (reads four)
    addb(struct.pack('>BBH', 1, 0, 1) + b'\x29\x01\x00' + END)              # 14 original length with length 1
    addb(struct.pack('>BBH', 1, 4, 1) + b'\x01')                            # 15 keepalive with trailing octet
    addb(tz(0, 1, b'', inner_eth()), snap=14 + 20 + 8 + 4)                  # 16 captured length stops after the TZSP header
    addb(tz(0, 1, opt(99, b'x' * 200), inner_eth()))                        # 17 long unknown option
    addb(tz(0, 1, b'', b''))                                                # 18 received packet without payload (empty Ethernet)
    bad.write(os.path.join(out, 'tzsp-coverage-malformed.pcap'))
    print('main', len(main.frames), 'wtap', len(wt.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
