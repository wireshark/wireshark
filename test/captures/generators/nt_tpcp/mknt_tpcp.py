#!/usr/bin/env python3
# Generates test/captures/nt_tpcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the TPCP coverage captures (synthetic data only).

usage: mknt_tpcp.py <outdir> [-v]

packet-nt-tpcp.c: Alteon WebSystems Transparent Proxy Cache Protocol,
UDP port 3121 (registered by default). Versions 1 (16 octets) and 2
(28 octets, with virtual server, RAS server and signature).

nt-tpcp-coverage.pcap            valid PDUs of both versions
nt-tpcp-coverage-malformed.pcap  truncated PDUs
"""
import os
import struct
import sys

CLI = bytes([192, 0, 2, 10])
SRV = bytes([192, 0, 2, 20])
VIP = bytes([192, 0, 2, 80])
RAS = bytes([192, 0, 2, 90])
MAC_A = b'\x02\0\0\0\0\x0a'
MAC_B = b'\x02\0\0\0\0\x14'
SIG = 0x74706370      # "tpcp"


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


ipid = [0]


def udp(payload, sport=3121, dport=3121, to=True):
    ipid[0] += 1
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    src, dst = (CLI, SRV) if to else (SRV, CLI)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ipid[0], 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    macs = (MAC_B + MAC_A) if to else (MAC_A + MAC_B)
    return macs + b'\x08\x00' + ip + u


def pdu(ver, typ, flags, cid, cport, caddr=CLI, saddr=SRV, extra=b'', v2=None):
    p = struct.pack('!BBHHH', ver, typ, flags, cid, cport) + caddr + saddr
    if ver == 2:
        p += (v2 or (VIP, RAS, SIG))[0] + (v2 or (VIP, RAS, SIG))[1] \
            + struct.pack('!I', (v2 or (VIP, RAS, SIG))[2])
    return p + extra


def main(out, verbose=False):
    fr = []
    marks = []

    def mark(name):
        marks.append((len(fr) + 1, name))
    mark('Version 1: every type')
    for typ, cid, cport in ((1, 1, 49152), (2, 1, 49152), (3, 2, 80), (4, 2, 80)):
        fr.append(udp(pdu(1, typ, 0x0000, cid, cport), to=typ % 2 == 1))
    mark('Version 1: every flag, UDP/TCP, other ports')
    for flags in (0x0001, 0x0002, 0x0004, 0x0008, 0x000f, 0x0100, 0xff00, 0xffff):
        fr.append(udp(pdu(1, 3, flags, 100 + (flags & 0xff), 8080)))
    fr.append(udp(pdu(1, 1, 0, 65535, 0)))
    fr.append(udp(pdu(1, 1, 0, 0, 65535)))
    mark('Version 2: types 1-6, signature, addresses')
    for typ in (1, 2, 3, 4, 5, 6):
        fr.append(udp(pdu(2, typ, 0x0001 if typ & 1 else 0x0000, 200 + typ, 3128), to=typ % 2 == 1))
    fr.append(udp(pdu(2, 5, 0x0003, 300, 443, v2=(bytes([203, 0, 113, 1]), bytes([203, 0, 113, 2]), SIG))))
    fr.append(udp(pdu(2, 6, 0x000c, 301, 21, v2=(bytes(4), bytes(4), 0))))
    fr.append(udp(pdu(2, 5, 0x0000, 302, 25, v2=(VIP, RAS, 0xdeadbeef))))
    mark('Unknown type, trailing data, other direction')
    fr.append(udp(pdu(1, 0, 0, 1, 1)))
    fr.append(udp(pdu(1, 7, 0, 1, 1)))
    fr.append(udp(pdu(1, 255, 0, 1, 1)))
    fr.append(udp(pdu(2, 99, 0, 1, 1)))
    fr.append(udp(pdu(1, 1, 0, 9, 9, extra=b'\x01\x02\x03\x04\x05\x06')))
    fr.append(udp(pdu(2, 1, 0, 9, 9, extra=b'\x01\x02\x03')))
    fr.append(udp(pdu(1, 2, 0x0001, 10, 49153), sport=3121, dport=49153, to=False))
    mark('Another version: not TPCP')
    fr.append(udp(pdu(3, 1, 0, 1, 1)))
    fr.append(udp(pdu(0, 1, 0, 1, 1)))
    fr.append(udp(pdu(255, 1, 0, 1, 1)))
    mark('End')
    write_pcap(os.path.join(out, 'nt-tpcp-coverage.pcap'), fr)
    mal = [
        udp(pdu(1, 1, 0, 1, 1)[:15]),          # version 1 one octet short
        udp(pdu(1, 1, 0, 1, 1)[:12]),          # cut inside the client address
        udp(pdu(1, 1, 0, 1, 1)[:6]),           # cut after the id
        udp(pdu(1, 1, 0, 1, 1)[:1]),           # version only
        udp(pdu(2, 5, 0, 1, 1)[:27]),          # version 2 one octet short
        udp(pdu(2, 5, 0, 1, 1)[:24]),          # version 2 without signature
        udp(pdu(2, 5, 0, 1, 1)[:16]),          # version 2 as version 1 length only
    ]
    write_pcap(os.path.join(out, 'nt-tpcp-coverage-malformed.pcap'), mal)
    if verbose:
        for (n, name), nxt in zip(marks, marks[1:]):
            print('%d-%d: %s' % (n, nxt[0] - 1, name))
    print('nt-tpcp-coverage.pcap', len(fr), 'frames')
    print('nt-tpcp-coverage-malformed.pcap', len(mal), 'frames')


if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
