#!/usr/bin/env python3
# Generates test/captures/doip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DoIP dissector
(packet-doip.c, Diagnostics over IP, ISO 13400-2).

DoIP runs over UDP and TCP port 13400 (registered by default). Each
message has an 8 octet header (version, inverse version, payload type,
length) and a payload; TCP messages go through tcp_dissect_pdus(), so
several messages can share a segment and one message can span segments.
Diagnostic messages carry UDS, which the dissector hands to the
"uds_over_doip" dissector. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkdoip.py <output directory>

Writes:
  doip-coverage.pcap            vehicle identification (plain, EID, VIN)
                                and announcements, entity status, power
                                mode, generic NACK, unknown payload types
                                and versions over UDP; routing activation
                                of every protocol version, alive check,
                                diagnostic messages with UDS, ACK and NACK
                                over TCP, several messages per segment and
                                messages split across segments
  doip-coverage-malformed.pcap  reproducer doip_pdulen_offset.pcap (a
                                second message with a wrong inverse
                                version), length fields beyond the data,
                                messages cut short
"""

import os
import socket
import struct
import sys

PORT = 13400
TESTER = '192.0.2.10'
ENTITY = '192.0.2.20'


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def mac(ip):
    return bytes([2, 0, 0, 0, 0, int(ip.split('.')[-1])])


def ip4(src, dst, proto, payload):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    eth = mac(dst) + mac(src) + b'\x08\x00'
    return eth + h + payload


def udp(src, sport, dst, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    return ip4(src, dst, 17, u)


class Tcp:
    """One TCP connection with sequence numbers in both directions."""

    def __init__(self, cport, frames):
        self.cport = cport
        self.frames = frames
        self.seq = {True: 1000, False: 5000}
        self.seg(True, 0x02, b'')
        self.seq[True] += 1
        self.seg(False, 0x12, b'')
        self.seq[False] += 1
        self.seg(True, 0x10, b'')

    def seg(self, c2s, flags, payload):
        src, dst = (TESTER, ENTITY) if c2s else (ENTITY, TESTER)
        sport, dport = (self.cport, PORT) if c2s else (PORT, self.cport)
        ack = self.seq[not c2s] if flags & 0x10 else 0
        # SYN and SYN/ACK carry an MSS option
        opts = b'\x02\x04\x05\xb4\x01\x01\x04\x02' if flags & 0x02 else b''
        t = struct.pack('>HHIIBBHHH', sport, dport, self.seq[c2s], ack,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        self.frames.append(ip4(src, dst, 6, t))
        self.seq[c2s] += len(payload)

    def send(self, c2s, payload):
        self.seg(c2s, 0x18, payload)


def doip(ptype, payload=b'', version=2, inv=None, length=None):
    if inv is None:
        inv = version ^ 0xff
    if length is None:
        length = len(payload)
    return struct.pack('>BBHI', version, inv, ptype, length) + payload


VIN = b'WDB1234567X890123'
EID = bytes.fromhex('020000000014')
GID = bytes.fromhex('0200000000aa')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    f = []
    T, E = TESTER, ENTITY
    # --- UDP, frames 1-22 ---
    # 1: vehicle identification request, default version 0xff
    f.append(udp(T, 50000, '192.0.2.255', PORT, doip(0x0001, version=0xff)))
    # 2: announcement / identification response with sync status (version 2)
    f.append(udp(E, PORT, T, 50000, doip(0x0004, VIN + b'\x10\x01' + EID + GID + b'\x00\x00')))
    # 3: vehicle identification request with EID (version 0xff)
    f.append(udp(T, 50000, E, PORT, doip(0x0002, EID, version=0xff)))
    # 4: announcement without sync status (version 1), further action 0x10
    f.append(udp(E, PORT, T, 50000, doip(0x0004, VIN + b'\x10\x01' + EID + GID + b'\x10', version=1)))
    # 5: vehicle identification request with VIN (version 3)
    f.append(udp(T, 50000, E, PORT, doip(0x0003, VIN, version=3)))
    # 6: announcement, version 3, sync status 0x10 (not synchronized)
    f.append(udp(E, PORT, T, 50000, doip(0x0004, VIN + b'\x10\x02' + EID + GID + b'\x00\x10', version=3)))
    # 7-8: entity status request and response with max data size
    f.append(udp(T, 50000, E, PORT, doip(0x4001)))
    f.append(udp(E, PORT, T, 50000, doip(0x4002, b'\x00\x10\x02' + struct.pack('>I', 4096))))
    # 9: entity status response without max data size (node type 1)
    f.append(udp(E, PORT, T, 50000, doip(0x4002, b'\x01\x04\x00', version=1)))
    # 10-11: diagnostic power mode request and response
    f.append(udp(T, 50000, E, PORT, doip(0x4003)))
    f.append(udp(E, PORT, T, 50000, doip(0x4004, b'\x01')))
    # 12: power mode response, not supported (2)
    f.append(udp(E, PORT, T, 50000, doip(0x4004, b'\x02', version=4)))
    # 13-17: generic NACK with each code 0-4
    for code in range(5):
        f.append(udp(E, PORT, T, 50000, doip(0x0000, bytes([code]))))
    # 18: unknown payload type 0x9000
    f.append(udp(T, 50000, E, PORT, doip(0x9000, b'\x01\x02')))
    # 19: reserved version 0 (invalid/unsupported)
    f.append(udp(T, 50000, E, PORT, doip(0x0001, version=0)))
    # 20: default version 0xff with a payload type other than identification
    f.append(udp(T, 50000, E, PORT, doip(0x4001, version=0xff)))
    # 21: two messages in one UDP datagram
    f.append(udp(T, 50000, E, PORT, doip(0x4001) + doip(0x4003)))
    # 22: default version 0xff with payload type 0 (generic NACK)
    f.append(udp(E, PORT, T, 50000, doip(0x0000, b'\x00', version=0xff)))

    # --- TCP connection 1 (version 2) ---
    c = Tcp(40001, f)
    # routing activation request, version 2, with OEM data, and response with OEM
    c.send(True, doip(0x0005, b'\x0e\x00\x00' + bytes(4) + b'\x11\x22\x33\x44'))
    c.send(False, doip(0x0006, b'\x0e\x00\x10\x01\x10' + bytes(4) + b'\x55\x66\x77\x88'))
    # diagnostic session control and its positive response (UDS)
    c.send(True, doip(0x8001, b'\x0e\x00\x10\x01' + b'\x10\x03'))
    c.send(False, doip(0x8002, b'\x10\x01\x0e\x00\x00' + b'\x10\x03'))
    c.send(False, doip(0x8001, b'\x10\x01\x0e\x00' + b'\x50\x03\x00\x32\x01\xf4'))
    # read data by identifier VIN, ACK without previous message, response
    c.send(True, doip(0x8001, b'\x0e\x00\x10\x01' + b'\x22\xf1\x90'))
    c.send(False, doip(0x8002, b'\x10\x01\x0e\x00\x00'))
    c.send(False, doip(0x8001, b'\x10\x01\x0e\x00' + b'\x62\xf1\x90' + VIN))
    # NACK with previous message and without
    c.send(True, doip(0x8001, b'\x0e\x00\x10\x02' + b'\x11\x01'))
    c.send(False, doip(0x8003, b'\x10\x02\x0e\x00\x03' + b'\x11\x01'))
    c.send(True, doip(0x8001, b'\x0e\x00\x10\x03' + b'\x3e\x00'))
    c.send(False, doip(0x8003, b'\x10\x03\x0e\x00\x06'))
    # alive check request and response
    c.send(False, doip(0x0007))
    c.send(True, doip(0x0008, b'\x0e\x00'))
    # three messages in one segment: tester present, alive check response,
    # read DTC information
    c.send(True, doip(0x8001, b'\x0e\x00\x10\x01' + b'\x3e\x80') + doip(0x0008, b'\x0e\x00') +
           doip(0x8001, b'\x0e\x00\x10\x01' + b'\x19\x02\xff'))
    # a diagnostic message split over three segments (header split too)
    big = doip(0x8001, b'\x10\x01\x0e\x00' + b'\x59\x02\xff' + bytes(range(64)))
    c.send(False, big[:5])
    c.send(False, big[5:40])
    c.send(False, big[40:])
    # one message completed in a segment that also starts the next
    m1 = doip(0x8001, b'\x0e\x00\x10\x01' + b'\x22\xf1\x86')
    m2 = doip(0x8001, b'\x0e\x00\x10\x01' + b'\x22\xf1\x87')
    c.send(True, m1[:10])
    c.send(True, m1[10:] + m2[:6])
    c.send(True, m2[6:])
    # unknown payload type on TCP
    c.send(True, doip(0x7000, b'\xaa'))

    # --- TCP connection 2: routing activation for the other versions ---
    c = Tcp(40002, f)
    # version 1 (2010): 2 octet activation type, ISO reserved, OEM
    c.send(True, doip(0x0005, b'\x0e\x01\x00\x00' + bytes(4) + b'\x01\x02\x03\x04', version=1))
    # version 1 without OEM data
    c.send(True, doip(0x0005, b'\x0e\x01\x00\x01' + bytes(4), version=1))
    # version 3 (2019) without OEM, activation type central security
    c.send(True, doip(0x0005, b'\x0e\x02\xe0' + bytes(4), version=3))
    # version 4 (2019 Amd1): only the source address is decoded
    c.send(True, doip(0x0005, b'\x0e\x03\x01' + bytes(4), version=4))
    # routing activation responses without OEM, denied codes
    c.send(False, doip(0x0006, b'\x0e\x02\x10\x01\x00' + bytes(4), version=3))
    c.send(False, doip(0x0006, b'\x0e\x03\x10\x01\x06' + bytes(4), version=4))
    # vehicle identification on TCP with VIN, version 1
    c.send(True, doip(0x0003, VIN, version=1))
    # diagnostic message, negative UDS response, version 3
    c.send(False, doip(0x8001, b'\x10\x01\x0e\x02' + b'\x7f\x22\x31', version=3))

    pcap(os.path.join(out, 'doip-coverage.pcap'), f)

    # --- malformed ---
    m = []
    # reproducer doip_pdulen_offset.pcap: the second message of the first
    # segment has a wrong inverse version, as does the message alone in the
    # next segment
    good = doip(0x0007)
    bad = doip(0x0008, b'\x0e\x00', inv=0x02)
    c = Tcp(40003, m)
    c.send(True, good + bad)
    c.send(True, bad)
    # UDP: length field beyond the data (illegal length expert)
    m.append(udp(T, 50000, E, PORT, doip(0x0004, VIN, length=100)))
    # UDP: routing activation request cut short
    m.append(udp(T, 50000, E, PORT, doip(0x0005, b'\x0e')))
    # UDP: announcement cut short
    m.append(udp(E, PORT, T, 50000, doip(0x0004, VIN[:10])))
    # UDP: header only 5 octets
    m.append(udp(T, 50000, E, PORT, doip(0x0001, version=0xff)[:5]))
    # UDP: length 0xffffffff (overflow)
    m.append(udp(T, 50000, E, PORT, doip(0x0001, version=0xff, length=0xffffffff)))
    # UDP: a diagnostic ACK, NACK, entity status and VIN request cut short
    m.append(udp(E, PORT, T, 50000, doip(0x8002, b'\x10\x01')))
    m.append(udp(E, PORT, T, 50000, doip(0x8003, b'\x10\x01\x0e')))
    m.append(udp(E, PORT, T, 50000, doip(0x4002, b'\x00')))
    m.append(udp(T, 50000, E, PORT, doip(0x0003, VIN[:4])))
    m.append(udp(T, 50000, E, PORT, doip(0x8001, b'\x0e')))
    # UDP: diagnostic message without UDS data
    m.append(udp(T, 50000, E, PORT, doip(0x8001, b'\x0e\x00\x10\x01')))
    m.append(udp(E, PORT, T, 50000, doip(0x0000)))
    m.append(udp(E, PORT, T, 50000, doip(0x0006, b'\x0e\x00')))
    m.append(udp(T, 50000, E, PORT, doip(0x0005, b'\x0e\x00\x00', version=1)))
    pcap(os.path.join(out, 'doip-coverage-malformed.pcap'), m)


if __name__ == '__main__':
    main()
