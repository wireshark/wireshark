#!/usr/bin/env python3
# Generates test/captures/nsip_coverage.pcap.gz, nsip_reproducers.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the GPRS-NS over IP (NSIP) coverage captures (synthetic, struct only).

Usage: mknsip.py <outdir> [-v]

Writes, into <outdir>:
  nsip-coverage.pcap            main capture (Ethernet, UDP 2157 and 19999)
  nsip-coverage-malformed.pcap  too deep NS PDU nesting, truncated PDUs, bad IEs
  nsip-reproducers.pcap         the reproducers of fd54660f2b (IPv6 address IE,
                                600 nested NS PDUs, then a plain NS-ALIVE)
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def frame(payload, sport=2157, dport=2157, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + ip + udp


def tlv(iei, val, two=False):
    """TLV information element: one octet length (bit 8 set) or, with
    two=True or for long values, two octets."""
    if len(val) < 128 and not two:
        return bytes([iei, 0x80 | len(val)]) + val
    return bytes([iei]) + struct.pack('!H', len(val)) + val


def cause(c, two=False):
    return tlv(0x00, bytes([c]), two)


def nsvci(v, two=False):
    return tlv(0x01, struct.pack('!H', v), two)


def nsei(v, two=False):
    return tlv(0x04, struct.pack('!H', v), two)


def bvci(v):
    return tlv(0x03, struct.pack('!H', v))


def ns_pdu(inner):
    return tlv(0x02, inner)


def ip4_elem(addr, port, sw, dw):
    return bytes(addr) + struct.pack('!HBB', port, sw, dw)


def ip6_elem(addr, port, sw, dw):
    return bytes.fromhex(addr) + struct.pack('!HBB', port, sw, dw)


IP4 = lambda *els: tlv(0x05, b''.join(els))
IP6 = lambda *els: tlv(0x06, b''.join(els))
V6A = '20010db8000000000000000000000001'
V6B = '20010db8000000000000000000000002'
# TV information elements
ipaddr4 = bytes([0x0b, 1, 192, 0, 2, 9])
ipaddr6 = bytes([0x0b, 2]) + bytes.fromhex(V6A)
BSSGP = bytes([0x21, 0x04, 0x82, 0x00, 0x01])       # BVC-BLOCK-ACK with BVCI 1


def status(inner, c=1):
    return bytes([0x08]) + cause(c) + nsvci(1) + ns_pdu(inner)


def write_pcap(name, frames):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


RANGES = []


class Cap:
    def __init__(self, name):
        self.name, self.frames = name, []

    def add(self, payload, **kw):
        self.frames.append(frame(payload, **kw))
        return len(self.frames)

    def group(self, text):
        first = len(self.frames) + 1
        return lambda: RANGES.append((self.name, first, len(self.frames), text))

    def save(self):
        write_pcap(self.name, self.frames)


def main():
    os.makedirs(OUT, exist_ok=True)
    c = Cap('nsip-coverage.pcap')

    g = c.group('NS_UNITDATA to BSSGP (control bits none, R, C, both), ports 2157 and 19999, other direction')
    for cb in (0x00, 0x01, 0x02, 0x03, 0xfc):
        c.add(bytes([0x00, cb]) + struct.pack('!H', 7) + BSSGP)
    c.add(bytes([0x00, 0x00]) + struct.pack('!H', 7) + BSSGP, sport=19999, dport=19999)
    c.add(bytes([0x00, 0x00]) + struct.pack('!H', 8) + BSSGP, sport=40000, dport=2157, src=(192, 0, 2, 2), dst=(192, 0, 2, 1))
    g()
    g = c.group('NS_RESET, NS_RESET_ACK, NS_BLOCK (causes), NS_BLOCK_ACK, NS_UNBLOCK, NS_UNBLOCK_ACK, NS_ALIVE, NS_ALIVE_ACK')
    c.add(bytes([0x02]) + cause(0x00) + nsvci(0x1234) + nsei(100))
    c.add(bytes([0x02]) + cause(0x01, two=True) + nsvci(0x1234, two=True) + nsei(100, two=True))
    c.add(bytes([0x03]) + nsvci(0x1234) + nsei(100))
    for ca in (0x03, 0x04, 0x05, 0x08, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x02, 0x99):
        c.add(bytes([0x04]) + cause(ca) + nsvci(0x0102))
    c.add(bytes([0x05]) + nsvci(0x0102))
    c.add(bytes([0x06]))
    c.add(bytes([0x07]))
    c.add(bytes([0x0a]))
    c.add(bytes([0x0b]))
    g()
    g = c.group('NS_STATUS: cause only, with BVCI, with IP4 and IP6 element lists, nested NS PDUs (1 to 4 levels)')
    c.add(bytes([0x08]) + cause(0x03) + nsvci(7))
    c.add(bytes([0x08]) + cause(0x05) + nsvci(7) + bvci(9))
    c.add(bytes([0x08]) + cause(0x13) + nsvci(7) + bvci(9) + IP4(ip4_elem((192, 0, 2, 1), 2157, 10, 20),
                                                              ip4_elem((192, 0, 2, 2), 19999, 1, 2)))
    c.add(bytes([0x08]) + cause(0x13) + nsvci(7) + IP6(ip6_elem(V6A, 2157, 10, 20), ip6_elem(V6B, 19999, 3, 4)))
    c.add(bytes([0x08]) + cause(0x13) + nsvci(7) + IP4() + IP6())
    inner = bytes([0x0a])
    for lvl in range(4):
        inner = status(inner, 0x0a)
        c.add(inner)
    c.add(status(bytes([0x00, 0x00]) + struct.pack('!H', 7) + BSSGP))     # NS_UNITDATA inside NS_STATUS
    g()
    g = c.group('SNS_ACK (IPv4 and IPv6 address IE, elements, cause) - IPv6 is the reproducer of the field type fix')
    c.add(bytes([0x0c]) + nsei(5) + b'\x01')
    c.add(bytes([0x0c]) + nsei(5) + b'\x02' + cause(0x08))
    c.add(bytes([0x0c]) + nsei(5) + b'\x03' + ipaddr4)
    c.add(bytes([0x0c]) + nsei(5) + b'\x04' + ipaddr6)
    c.add(bytes([0x0c]) + nsei(5) + b'\x05' + cause(0x09) + ipaddr6 + IP4(ip4_elem((10, 0, 0, 1), 2157, 1, 1)))
    c.add(bytes([0x0c]) + nsei(5) + b'\x06' + IP4(ip4_elem((10, 0, 0, 1), 2157, 1, 1)) + IP6(ip6_elem(V6A, 2157, 1, 1)))
    c.add(bytes([0x0c]) + nsei(5) + b'\x07' + bytes([0x0b, 0x00, 1, 2, 3, 4]))      # reserved address type
    g()
    g = c.group('SNS_ADD, SNS_CHANGEWEIGHT, SNS_CONFIG (end flag), SNS_CONFIG_ACK, SNS_DELETE')
    els4 = IP4(ip4_elem((192, 0, 2, 10), 2157, 5, 5), ip4_elem((192, 0, 2, 11), 2158, 6, 6), ip4_elem((192, 0, 2, 12), 2159, 7, 7))
    els6 = IP6(ip6_elem(V6A, 2157, 5, 5))
    c.add(bytes([0x0d]) + nsei(5) + b'\x10' + els4)
    c.add(bytes([0x0d]) + nsei(5) + b'\x11' + els6)
    c.add(bytes([0x0d]) + nsei(5) + b'\x12' + els4 + els6)
    c.add(bytes([0x0e]) + nsei(5) + b'\x20' + els4)
    c.add(bytes([0x0e]) + nsei(5) + b'\x21' + els6)
    for flag in (0, 1, 0xfe):
        c.add(bytes([0x0f, flag]) + nsei(5) + els4 + els6)
    c.add(bytes([0x0f, 1]) + nsei(5))
    c.add(bytes([0x10]) + nsei(5))
    c.add(bytes([0x10]) + nsei(5) + cause(0x14))
    c.add(bytes([0x11]) + nsei(5) + b'\x30' + ipaddr4)
    c.add(bytes([0x11]) + nsei(5) + b'\x31' + ipaddr6)
    c.add(bytes([0x11]) + nsei(5) + b'\x32' + els4)
    c.add(bytes([0x11]) + nsei(5) + b'\x33' + els6)
    c.add(bytes([0x11]) + nsei(5) + b'\x34')
    g()
    g = c.group('SNS_SIZE (reset flag, max NS-VCs, endpoint counts), SNS_SIZE_ACK, unknown PDU types')
    c.add(bytes([0x12]) + nsei(5) + bytes([0x0a, 0x01]) + bytes([0x07, 0x00, 0x08]) + bytes([0x08, 0x00, 0x02]) + bytes([0x09, 0x00, 0x03]))
    c.add(bytes([0x12]) + nsei(5) + bytes([0x0a, 0x00]) + bytes([0x07, 0x00, 0x10]))
    c.add(bytes([0x13]) + nsei(5))
    c.add(bytes([0x13]) + nsei(5) + cause(0x10))
    c.add(bytes([0x01, 0xaa, 0xbb]))
    c.add(bytes([0x30]))
    c.add(bytes([0x09, 0x01]), sport=19999, dport=2157)
    g()
    c.save()

    # ---- malformed / warnings
    m = Cap('nsip-coverage-malformed.pcap')
    g = m.group('NS PDU IE nested 5 and 6 levels deep (too deep warning), then a plain NS_ALIVE')
    inner = bytes([0x0a])
    for lvl in range(6):
        inner = status(inner, 0x0a)
        if lvl >= 4:
            m.add(inner)
    m.add(bytes([0x0a]))
    g()
    g = m.group('truncated PDUs and information elements (exceptions)')
    full = bytes([0x02]) + cause(0x00) + nsvci(0x1234) + nsei(100)
    for n in (1, 2, 3, 5, 7, 9):
        m.add(full[:n])
    m.add(bytes([0x00]))                                  # NS_UNITDATA without control bits
    m.add(bytes([0x00, 0x00, 0x00]))                      # NS_UNITDATA with a short BVCI
    m.add(bytes([0x0c]) + nsei(5) + b'\x01' + bytes([0x0b, 0x01, 1, 2]))             # IPv4 address cut short
    m.add(bytes([0x0c]) + nsei(5) + b'\x01' + bytes([0x0b, 0x02, 1, 2, 3, 4, 5]))    # IPv6 address cut short
    m.add(bytes([0x08]) + cause(0x03) + nsvci(7) + bytes([0x02, 0x7f, 1]))           # NS PDU IE longer than the packet
    m.add(bytes([0x08]) + cause(0x03) + nsvci(7) + bytes([0x05, 0x00]))              # two octet length cut short
    m.add(bytes([0x08]) + cause(0x03) + nsvci(7) + bytes([0x05, 0x81, 1]))           # element list cut short
    m.add(bytes([0x08]) + cause(0x03) + nsvci(7) + bytes([0x05, 0x84, 1, 2, 3, 4]))  # 4 octets: less than one element
    m.add(bytes([0x12]) + nsei(5) + bytes([0x0a]))                                   # SNS_SIZE cut short
    m.add(bytes([0x12]) + nsei(5) + bytes([0x0a, 0x01, 0x07, 0x00]))
    g()
    m.save()

    # ---- reproducers of fd54660f2b
    r = Cap('nsip-reproducers.pcap')
    r.add(bytes([0x0c]) + nsei(1) + b'\x05' + ipaddr6)
    inner = bytes([0x0a])
    for _ in range(600):
        inner = status(inner)
    r.add(inner)
    r.add(bytes([0x0a]))
    r.save()
    if VERBOSE:
        for x in RANGES:
            print(*x)
        print(len(c.frames), len(m.frames), len(r.frames))


main()
