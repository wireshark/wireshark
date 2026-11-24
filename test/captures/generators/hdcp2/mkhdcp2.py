#!/usr/bin/env python3
# Generates test/captures/hdcp2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the HDCP2 coverage captures.  Usage: mkhdcp2.py <outdir>

HDCP 2.x authentication messages over TCP.  The dissector is a heuristic
TCP dissector that is disabled by default (hdcp2_tcp).  Every field that
would carry key material, a certificate or a signature holds constant
placeholder bytes; nothing comes from a real network."""
import struct
import sys
import os

TX = bytes([192, 0, 2, 1])
RX = bytes([192, 0, 2, 2])
MAC_T = bytes.fromhex('020000000001')
MAC_R = bytes.fromhex('020000000002')
TXP, RXP = 40000, 53000


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Flow:
    """A TCP connection between transmitter and receiver."""

    def __init__(self, cap, sport=TXP, dport=RXP):
        self.cap = cap
        self.sport, self.dport = sport, dport
        self.seq = {True: 1000, False: 5000}
        self.ipid = 1

    def seg(self, to_rx, payload, flags=0x18):
        src, dst = (TX, RX) if to_rx else (RX, TX)
        ms, md = (MAC_T, MAC_R) if to_rx else (MAC_R, MAC_T)
        sp, dp = (self.sport, self.dport) if to_rx else (self.dport, self.sport)
        seq, ack = self.seq[to_rx], self.seq[not to_rx]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.ipid, 0, 64, 6, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        self.cap.add(md + ms + b'\x08\x00' + ip + tcp + payload)
        self.seq[to_rx] += len(payload) + (1 if flags & 3 else 0)

    def handshake(self):
        self.seg(True, b'', 0x02)
        self.seg(False, b'', 0x12)
        self.seg(True, b'', 0x10)


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000

    def add(self, fr):
        self.frames.append((self.t, fr))
        self.t += 1

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


def fill(n, v):
    return bytes([v]) * n


def ake_init(rtx=0x0102030405060708):
    return b'\x02' + struct.pack('>Q', rtx)


def tx_info(length=6, version=2, caps=0x0001):
    return b'\x13' + struct.pack('>HBH', length, version, caps)


def send_cert(repeater=0, reserved=0):
    return (b'\x03' + bytes([repeater]) + fill(5, 0x11) + fill(128, 0xa5) +
            b'\x01\x00\x01' + struct.pack('>H', reserved) + fill(384, 0x5a))


def rx_info(length=6, version=2, caps=0x0000):
    return b'\x14' + struct.pack('>HBH', length, version, caps)


def no_stored_km():
    return b'\x04' + fill(128, 0xc3)


def stored_km():
    return b'\x05' + fill(16, 0x21) + fill(16, 0x22)


def send_rrx():
    return b'\x06' + struct.pack('>Q', 0x1112131415161718)


def send_h_prime():
    return b'\x07' + fill(32, 0x33)


def pairing_info():
    return b'\x08' + fill(16, 0x44)


def lc_init():
    return b'\x09' + struct.pack('>Q', 0x2122232425262728)


def l_prime():
    return b'\x0a' + fill(32, 0x55)


def send_eks():
    return b'\x0b' + fill(16, 0x66) + struct.pack('>Q', 0x3132333435363738)


def main(out):
    c = Cap()
    f = Flow(c)
    f.handshake()                                    # 1-3
    # session 1: no stored km, locality precompute
    f.seg(True, ake_init())                          # 4
    f.seg(False, send_cert(0))                       # 5
    f.seg(True, tx_info(6, 2, 0x0001))               # 6 locality precompute
    f.seg(False, rx_info(6, 2, 0x0000))              # 7 no locality precompute
    f.seg(True, no_stored_km())                      # 8
    f.seg(False, send_rrx())                         # 9
    f.seg(False, send_h_prime())                     # 10
    f.seg(False, pairing_info())                     # 11
    f.seg(True, lc_init())                           # 12
    f.seg(False, l_prime())                          # 13
    f.seg(True, send_eks())                          # 14
    # session 2: stored km, repeater
    f.seg(True, ake_init(0x0807060504030201))        # 15
    f.seg(False, send_cert(1))                       # 16 repeater
    f.seg(True, stored_km())                         # 17
    f.seg(False, send_rrx())                         # 18
    f.seg(False, send_h_prime())                     # 19
    f.seg(True, lc_init())                           # 20
    f.seg(False, l_prime())                          # 21
    f.seg(True, send_eks())                          # 22
    # warnings: version, length, reserved
    f.seg(True, tx_info(5, 1, 0x0000))               # 23 short length, version 1
    f.seg(False, rx_info(4, 3, 0x0001))              # 24
    f.seg(False, send_cert(0, 0x0001))               # 25 reserved not 0
    f.seg(False, send_cert(0, 0x1000))               # 26 reserved bit 12 (see README)
    f.seg(True, tx_info(0x0100, 2, 0x0003))          # 27
    # segments that are not HDCP2: wrong length, unknown id, id > 31
    f.seg(True, b'\x02' + fill(7, 0x77))             # 28
    f.seg(True, b'\x0c' + fill(8, 0x77))             # 29
    f.seg(True, b'\x40' + fill(8, 0x77))             # 30
    f.seg(True, b'\x00' + b'')                       # 31 (empty after id)
    f.seg(True, b'', 0x11)                           # 32 FIN
    c.write(os.path.join(out, 'hdcp2-coverage.pcap'))

    # malformed capture: heuristic with truncated or odd segments; the
    # header checks reject them, so these only add to the not-HDCP2 paths
    m = Cap()
    g = Flow(m, 40001, 53001)
    g.seg(True, ake_init()[:5])
    g.seg(True, send_cert(0)[:100])
    g.seg(True, send_eks() + b'\0')
    g.seg(True, tx_info() + tx_info())               # two messages in one segment
    g.seg(True, b'\xff\xff\xff')
    m.write(os.path.join(out, 'hdcp2-coverage-malformed.pcap'))


main(sys.argv[1])
