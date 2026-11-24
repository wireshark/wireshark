#!/usr/bin/env python3
# Generates test/captures/tsp_coverage.pcap.gz
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

# ---- tsp ----
# TSP (BSD timed) over UDP port 525, registered by default.
PORT = 525


def msg(t, seq, body=bytes(8), name=b'host1', ver=1, pad=0):
    return struct.pack('>BBH', t, ver, seq) + body + name + b'\0' * (1 + pad)


def tm(sec, usec):
    return struct.pack('>II', sec, usec)


def f(p, ident, down=False):
    if down:
        return eth(ipv4(udp(p, PORT, PORT, src=IP_B, dst=IP_A), src=IP_B, dst=IP_A, ident=ident),
                   0x0800, dst=MAC_A, src=MAC_B)
    return udp_frame(p, PORT, PORT, ident)


def build(out):
    main = Pcap()
    n = 0
    for t in range(0, 25):                       # frames 1-25: every defined type
        n += 1
        if t == 24:
            body = bytes([3]) + bytes(7)         # loop: hop count 3
        elif t in (1, 5, 22, 23):
            body = tm(1700000000 + t, 123456 + t)    # adjtime, settime, setdate, setdatereq
        else:
            body = bytes(8)
        main.add(f(msg(t, 100 + t, body, name=b'host%d' % t), n, down=bool(t & 1)))
    main.add(f(msg(25, 200, name=b'unknown'), 26))                    # 26 unknown type 25
    main.add(f(msg(255, 201, name=b'x'), 27))                         # 27 type 255
    main.add(f(msg(14, 202, ver=2, name=b'c' * 200), 28))             # 28 version 2, a 200 character name
    main.add(f(struct.pack('>BBH', 2, 1, 203) + bytes(8) + b'\0' * 256, 29))   # 29 full size timed packet, empty name
    main.write(os.path.join(out, 'tsp-coverage.pcap'))
    bad = Pcap()
    bad.add(f(struct.pack('>BBH', 3, 1, 204) + bytes(8) + b'noterm', 8))   # 8 name without a terminating NUL
    bad.add(f(b'', 1))                                                # 1 empty UDP payload (no TSP type)
    bad.add(f(b'\x02\x01', 2))                                        # 2 type and version only (sequence cut off)
    bad.add(f(struct.pack('>BBH', 5, 1, 1) + bytes(4), 3))            # 3 settime cut in the seconds
    bad.add(f(struct.pack('>BBH', 5, 1, 1) + bytes(6), 4))            # 4 settime cut in the microseconds
    bad.add(f(struct.pack('>BBH', 24, 1, 1), 5))                      # 5 loop without the hop count
    bad.add(f(struct.pack('>BBH', 2, 1, 1) + bytes(6), 6))            # 6 ack with the name offset beyond the end
    bad.add(f(struct.pack('>BBH', 2, 1, 1) + bytes(8), 7))            # 7 name offset at the end (empty)
    bad.write(os.path.join(out, 'tsp-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
