#!/usr/bin/env python3
# Generates test/captures/egd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EGD dissector
(packet-egd.c, GE Fanuc Ethernet Global Data).

EGD data messages (PDU type 13, version 1) go to UDP port 18246. The
32 octet header holds the type, version, a little endian request ID,
the producer ID as an IPv4 address, a little endian exchange ID, an 8
octet timestamp (seconds and nanoseconds, or 0 for "no timestamp"), a
status, a configuration signature and a reserved word; the rest is
handed to the data dissector. Every packet is built from scratch with
struct; no captured traffic is used. Addresses are from 192.0.2.0/24.

Usage: mkegd.py <output directory>

Writes:
  egd-coverage.pcap            data messages with and without a
                               timestamp, every status value and an
                               unknown one, with and without data, to a
                               unicast and a broadcast address; two
                               packets on the port that are not EGD data
                               messages (other PDU type, other version)
  egd-coverage-malformed.pcap  a header cut short after 8, 1 and 20
                               octets
"""

import os
import struct
import sys

EGD_PORT = 18246
STATUSES = [0, 1, 2, 3, 4, 6, 7, 10, 12, 16, 18, 22, 26, 28, 30]


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


IDENT = [0]


def udp_frame(src, dst, sport, dport, payload):
    IDENT[0] += 1
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), IDENT[0], 0x4000, 64, 17, 0,
                    ip4(src), ip4(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    if dst.endswith('.255'):
        dmac = b'\xff' * 6
    else:
        dmac = bytes([2, 0]) + ip4(dst)
    return dmac + bytes([2, 0]) + ip4(src) + b'\x08\x00' + h + u


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def egd(rid, producer, exid, secs, nsecs, status, csig=0, resv=0, data=b'',
        typ=13, ver=1):
    return (struct.pack('<BBH', typ, ver, rid) + ip4(producer) +
            struct.pack('<IIIIII', exid, secs, nsecs, status, csig, resv) + data)


PLC1 = '192.0.2.10'
PLC2 = '192.0.2.11'
HMI = '192.0.2.20'


def main_frames():
    f = []
    # 1-15: PLC1 produces exchange 0x00000001 with every status value;
    # request IDs count up, the timestamp advances by 10 ms
    for i, st in enumerate(STATUSES):
        data = struct.pack('<8H', *range(i, i + 8))
        f.append(udp_frame(PLC1, HMI, EGD_PORT, EGD_PORT,
                           egd(i + 1, PLC1, 1, 1700000000, 10000000 * i, st, csig=0x10001,
                               data=data)))
    # 16: no timestamp (seconds 0), an unknown status (5), no data
    f.append(udp_frame(PLC1, HMI, EGD_PORT, EGD_PORT,
                       egd(16, PLC1, 1, 0, 0, 5)))
    # 17: PLC2 broadcasts exchange 0xDEADBEEF, request ID 65535,
    # seconds 0 with nanoseconds set (still "no timestamp"), large data
    f.append(udp_frame(PLC2, '192.0.2.255', EGD_PORT, EGD_PORT,
                       egd(65535, PLC2, 0xDEADBEEF, 0, 123, 1, csig=0xffffffff,
                           resv=7, data=bytes(range(256)) * 4)))
    # 18: producer ID other than the sender, a single data octet
    f.append(udp_frame(PLC2, HMI, 40000, EGD_PORT,
                       egd(2, '10.0.0.1', 2, 1700000123, 999999999, 1, data=b'\x5a')))
    # 19: PDU type 14 (a control message): not dissected as EGD
    f.append(udp_frame(PLC1, HMI, EGD_PORT, EGD_PORT,
                       egd(1, PLC1, 1, 0, 0, 1, typ=14)))
    # 20: version 2: not dissected as EGD
    f.append(udp_frame(PLC1, HMI, EGD_PORT, EGD_PORT,
                       egd(1, PLC1, 1, 0, 0, 1, ver=2)))
    return f


def malformed_frames():
    full = egd(1, PLC1, 1, 1700000000, 0, 1)
    return [
        # 1: header up to the producer ID only
        udp_frame(PLC1, HMI, EGD_PORT, EGD_PORT, full[:8]),
        # 2: one octet
        udp_frame(PLC1, HMI, EGD_PORT, EGD_PORT, full[:1]),
        # 3: cut short in the timestamp
        udp_frame(PLC1, HMI, EGD_PORT, EGD_PORT, full[:20]),
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'egd-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'egd-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
