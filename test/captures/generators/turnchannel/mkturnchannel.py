#!/usr/bin/env python3
# Generates test/captures/turnchannel_coverage.pcap.gz
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


def raw_eth(dst, src, etype, payload):
    return dst + src + struct.pack('>H', etype) + payload

# ---- turnchannel ----
# TURN ChannelData messages. There is no port or heuristic of its own (STUN
# has its own copy of the code), so the captures need Decode As:
#   -d udp.port==40000,turnchannel -d tcp.port==40001,turnchannel
UPORT = 40000
TPORT = 40001


def pdu(chan, data, length=None):
    return struct.pack('>HH', chan, len(data) if length is None else length) + data


def u(p, ident, down=False):
    if down:
        return eth(ipv4(udp(p, UPORT, 51000, src=IP_B, dst=IP_A), src=IP_B, dst=IP_A, ident=ident),
                   0x0800, dst=MAC_A, src=MAC_B)
    return udp_frame(p, 51000, UPORT, ident)


def build(out):
    main = Pcap()
    main.add(u(pdu(0x4000, b'hello turn'), 1))                         # 1 UDP, channel 0x4000
    main.add(u(pdu(0x4001, bytes(range(100))), 2, down=True))          # 2 channel 0x4001, 100 octets
    main.add(u(pdu(0x7fff, b'\x01'), 3))                               # 3 highest channel in the range
    main.add(u(pdu(0xff10, b'ms-turn multiplex'), 4))                  # 4 the MS-TURN multiplex channel number
    main.add(u(pdu(0x4010, b''), 5))                                   # 5 header only, no data
    main.add(u(pdu(0xc000, b'abcd'), 6))                               # 6 0xc000 has bit 0x4000 set: accepted
    main.add(u(pdu(0x3fff, b'rejected'), 7))                           # 7 channel number below 0x4000: not TURN
    main.add(u(pdu(0x4000, b'wrong length', length=3), 8))             # 8 length field does not match the datagram
    main.add(u(b'\x40\x00\x00', 9))                                    # 9 three octets, shorter than the header
    t = Tcp(51001, TPORT)
    main.add(t.c(pdu(0x4000, b'tcp one')))                             # 10 TCP, one message
    main.add(t.s(pdu(0x4001, b'x' * 20)))                              # 11 reply
    main.add(t.c(pdu(0x4000, b'first') + pdu(0x4002, b'second one') + pdu(0x4003, b'3')))     # 12 three messages in one segment (the second and third use their own channel ids)
    a = pdu(0x4004, bytes(range(60)))
    main.add(t.c(a[:30]))                                              # 13 message split: first part
    main.add(t.c(a[30:] + pdu(0x4005, b'next')))                       # 14 rest and the next message
    main.add(t.c(pdu(0x4006, b'ok') + pdu(0x1234, bytes(8)) + pdu(0x4007, b'after')))         # 15 a bad channel id as second message: it and everything after it is not TURN
    main.add(t.s(pdu(0xff10, b'ms') + pdu(0x4008, b'')))               # 16 MS multiplex channel, then an empty message
    main.write(os.path.join(out, 'turnchannel-coverage.pcap'))
    bad = Pcap()
    bad.add(u(pdu(0x4000, b'abcdefghij') + b'0123456789', 1), )        # 1 whole datagram (control)
    p = udp(pdu(0x4000, b'abcdefgh') + b'padding-beyond!', 51000, UPORT)
    fr = eth(ipv4(p), 0x0800)
    bad.add(fr, snap=14 + 20 + 8 + 4 + 8)                              # 2 captured length stops after the data, reported longer
    t = Tcp(51002, TPORT)
    bad.add(t.c(pdu(0x4000, b'abcd')[:3]))                             # 3 TCP segment of three octets
    bad.add(t.c(pdu(0x2000, b'zz')))                                   # 4 TCP segment starting with a bad channel id
    bad.add(t.c(pdu(0x4001, b'0123456789', length=500)))               # 5 TCP message that claims 500 octets (waits for more)
    bad.write(os.path.join(out, 'turnchannel-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
