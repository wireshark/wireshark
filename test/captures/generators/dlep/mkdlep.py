#!/usr/bin/env python3
# Generates test/captures/dlep_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic DLEP (RFC 8175) coverage captures: signals over
UDP 854, messages over TCP 854. Usage: mkdlep.py <outdir>"""
import os
import socket
import struct
import sys
from pcaplib import udp, Tcp, write_pcap

def di(t, v):
    return struct.pack('!HH', t, len(v)) + v

def signal(t, items, length=None):
    body = b''.join(items)
    return b'DLEP' + struct.pack('!HH', t, len(body) if length is None else length) + body

def message(t, items, length=None):
    body = b''.join(items)
    return struct.pack('!HH', t, len(body) if length is None else length) + body

V6A = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
V6B = socket.inet_pton(socket.AF_INET6, '2001:db8:1::')

STATUS = lambda code, text=b'': di(1, bytes([code]) + text)
V4CONN = lambda flags, port=None: di(2, bytes([flags]) + bytes([192, 0, 2, 2]) + (struct.pack('!H', port) if port is not None else b''))
V6CONN = lambda flags, port=None: di(3, bytes([flags]) + V6A + (struct.pack('!H', port) if port is not None else b''))
PEERTYPE = lambda flags, desc: di(4, bytes([flags]) + desc)
HEARTBEAT = lambda ms: di(5, struct.pack('!I', ms))
EXTSUPP = lambda *codes: di(6, b''.join(struct.pack('!H', c) for c in codes))
MAC48 = di(7, bytes.fromhex('02000000aa01'))
MAC64 = di(7, bytes.fromhex('02000000aa01bb02'))
V4ADDR = lambda f: di(8, bytes([f, 192, 0, 2, 50]))
V6ADDR = lambda f: di(9, bytes([f]) + V6A)
V4SUB = lambda f: di(10, bytes([f, 198, 51, 100, 0, 24]))
V6SUB = lambda f: di(11, bytes([f]) + V6B + bytes([48]))
U64 = lambda t, v: di(t, struct.pack('!Q', v))
MDRR, MDRT, CDRR, CDRT, LAT = (lambda v: U64(12, v)), (lambda v: U64(13, v)), (lambda v: U64(14, v)), (lambda v: U64(15, v)), (lambda v: U64(16, v))
RES = lambda v: di(17, bytes([v]))
RLQR = lambda v: di(18, bytes([v]))
RLQT = lambda v: di(19, bytes([v]))
MTU = lambda v: di(20, struct.pack('!H', v))
HOPCNT = lambda p, n: di(21, bytes([(0x80 if p else 0), n]))
HOPCNTRL = lambda a: di(22, struct.pack('!H', a))
LILEN = lambda v: di(26, struct.pack('!H', v))
LI = lambda v: di(27, v)
LATRANGE = lambda mx, mn: di(28, struct.pack('!QQ', mx, mn))

def destination_metrics():
    return [MDRR(100000000), MDRT(50000000), CDRR(80000000), CDRT(40000000),
            LAT(2500), RES(75), RLQR(90), RLQT(85), MTU(1500)]

def main_frames():
    f = []
    # --- UDP 854: discovery ---
    f.append(udp(854, 854, signal(1, [PEERTYPE(0, b'router')]), src='192.0.2.1', dst='192.0.2.2'))  # 1 (unicast: the helper sets TTL 64)
    f.append(udp(854, 854, signal(2, [PEERTYPE(1, b'modem one'), V4CONN(0, 854), V4CONN(1),
                                      V6CONN(0, 854), V6CONN(1), STATUS(0, b'ok')]),
                 src='192.0.2.2', dst='192.0.2.1'))                                         # 2
    f.append(udp(854, 854, signal(0, [HEARTBEAT(1000)])))                                  # 3 reserved signal
    f.append(udp(854, 854, signal(9, [])))                                                 # 4 unknown, empty
    # --- TCP 854: session ---
    t = Tcp(40000, 854)
    f.append(t.c2s(message(1, [HEARTBEAT(1000), PEERTYPE(0, b'router'),
                               EXTSUPP(0, 1, 2, 3, 4, 5, 65520, 65535)])))                 # 5 session init
    f.append(t.s2c(message(2, [STATUS(0), HEARTBEAT(1000), PEERTYPE(1, b''), EXTSUPP(1, 3, 4)]
                           + destination_metrics() + [V4ADDR(1), V6ADDR(1), V4SUB(1), V6SUB(1)])))  # 6
    f.append(t.s2c(message(3, [V4ADDR(0), V6ADDR(0), V4SUB(0), V6SUB(0)] + destination_metrics()))) # 7
    f.append(t.c2s(message(4, [STATUS(1, b'not interested')])))                            # 8
    f.append(t.s2c(message(7, [MAC48] + destination_metrics() + [V4ADDR(1), V6SUB(1),
                               HOPCNT(True, 3), LILEN(4), LI(b'\x00\x00\x00\x07'), LATRANGE(5000, 1000)])))  # 9 dest up
    f.append(t.c2s(message(8, [MAC48, STATUS(2, b'denied')])))                             # 10
    f.append(t.c2s(message(9, [MAC64, V4ADDR(1), LI(b'')])))                               # 11 dest announce, EUI-64
    f.append(t.s2c(message(10, [MAC64, STATUS(3)] + destination_metrics())))               # 12
    f.append(t.s2c(message(13, [MAC48, HOPCNT(False, 1), LAT(3000), RLQR(10)])))           # 13 dest update
    f.append(t.c2s(message(14, [MAC48, CDRR(1000), LAT(100)])))                            # 14 link char request
    f.append(t.s2c(message(15, [MAC48, STATUS(0)] + destination_metrics())))               # 15
    # 16: heartbeat, a hop control message and a destination down in one segment
    f.append(t.s2c(message(16, []) + message(13, [MAC48, HOPCNTRL(0), HOPCNTRL(1)])
                   + message(11, [MAC48])))
    f.append(t.c2s(message(12, [MAC48, STATUS(0)])))                                       # 17
    f.append(t.c2s(message(13, [MAC48, HOPCNTRL(2), HOPCNTRL(3), HOPCNTRL(100),
                                HOPCNTRL(65520), HOPCNTRL(65535)])))                       # 18
    # 19: data items without a decoder (queue parameters, pause, restart, unknown)
    f.append(t.s2c(message(13, [MAC48, di(23, b'\x01\x02\x03\x04'), di(24, b'\x00\x05'),
                                di(25, b''), di(0, b'\x00'), di(200, b'\xab\xcd')])))
    # 20-21: a destination update split over two segments
    big = message(13, [MAC48] + destination_metrics() * 3)
    f.append(t.s2c(big[:40]))
    f.append(t.s2c(big[40:]))
    # 22-27: every status code, then the session ends
    f.append(t.s2c(message(13, [MAC48, STATUS(128, b'u'), STATUS(129), STATUS(130), STATUS(131),
                                STATUS(132), STATUS(200)])))
    f.append(t.c2s(message(5, [STATUS(255, b'Shutting down')])))                           # 23 session term
    f.append(t.s2c(message(6, [])))                                                        # 24 term response
    f.append(t.s2c(message(0, [])))                                                        # 25 reserved
    f.append(t.s2c(message(99, [di(1, b''), di(4, b'')])))                                 # 26 unknown, empty status and peer type
    return f

def malformed_frames():
    f = []
    # 1: signal length larger than the data.
    f.append(udp(854, 854, signal(1, [PEERTYPE(0, b'x')], length=40)))
    # 2: MAC address of 5 octets.
    t = Tcp(40001, 854)
    f.append(t.c2s(message(7, [di(7, b'\x01\x02\x03\x04\x05')])))
    # 3: data items of the wrong length (heartbeat 2, v4 address 3, MTU 4).
    f.append(t.c2s(message(13, [di(5, b'\0\0'), di(8, b'\0\0\0'), di(20, b'\0\0\0\0')])))
    # 4: data item length past the end of the message.
    f.append(t.c2s(message(13, [struct.pack('!HH', 5, 40) + b'\0\0\0\0'])))
    # 5: extensions supported with an odd length; v4 connection point of 6 octets.
    f.append(t.c2s(message(1, [di(6, b'\0\1\0'), di(2, b'\0\1\2\3\4\5')])))
    # 6: signal shorter than its header.
    f.append(udp(854, 854, b'DLEP\0'))
    # 7: data item header cut short.
    f.append(udp(854, 854, signal(1, []) + b'\0\4'))
    return f

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dlep-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dlep-coverage-malformed.pcap'), malformed_frames())
