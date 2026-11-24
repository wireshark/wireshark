#!/usr/bin/env python3
# Generates test/captures/cnip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CN/IP dissector
(packet-cnip.c, Component Network over IP, EIA-852).

All packets are built from scratch with struct; no captured traffic is
used. Two CN/IP devices (10.0.0.1, 10.0.0.2) and a configuration server
(10.0.0.3) exchange UDP datagrams on the CN/IP ports 1628 (normal
priority) and 1629 (urgent), which are registered by default.

The 20 octet header holds a length, version, packet type, the size of the
extension header in 32 bit words, protocol flags (security bit and a 5
bit protocol code), a vendor code, session ID, sequence number and time
stamp. Data packets (type 1) are handed to the "cnip.protocol" table by
protocol code: 0 is LonTalk (packet-lon.c), anything else is data.

Usage: mkcnip.py <output directory>

Writes:
  cnip-coverage.pcap            data packets with LonTalk and unknown
                                protocol codes, extension headers, the
                                security flag, both priorities, every
                                other packet type and an unknown one
  cnip-coverage-malformed.pcap  headers cut short, an extension header
                                past the end of the datagram
"""

import os
import struct
import sys

DEV1 = (10, 0, 0, 1)
DEV2 = (10, 0, 0, 2)
CS = (10, 0, 0, 3)


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def udp(self, src, dst, sport, dport, payload):
        udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(udp))
        c = ip_checksum(pseudo + udp) or 0xffff
        udp = udp[:6] + struct.pack('>H', c) + udp[8:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), len(self.frames) & 0xffff,
                         0x4000, 64, 17, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        eth = b'\x02\x00\x00\x00\x00' + bytes([dst[3]]) + b'\x02\x00\x00\x00\x00' + \
            bytes([src[3]]) + b'\x08\x00'
        self.frames.append(eth + ip + udp)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def cnip(ptype, payload=b'', pcode=0, sec=False, vendor=0, sessid=0x11223344, seqno=1,
         tstamp=0, ext=b'', version=1, length=None):
    """CN/IP header, extension header (whole 32 bit words) and payload."""
    assert len(ext) % 4 == 0
    if length is None:
        length = 20 + len(ext) + len(payload)
    hdr = struct.pack('>HBBBBHIII', length, version, ptype, len(ext) // 4,
                      (0x20 if sec else 0) | pcode, vendor, sessid, seqno, tstamp)
    return hdr + ext + payload


# LonTalk payloads for protocol code 0
# Broadcast, domain length 1, TPDU ACK
LON_ACK = bytes([0x85, 0x01, 0x01, 0x82, 0x00, 0x42, 0x20])
# Unicast 2a, domain length 3, priority, TPDU ACK
LON_UNICAST = bytes([0x81, 0x0a, 0x01, 0x85, 0x02, 0x07, 0x12, 0x34, 0x56, 0x21])

TYPES = (0x63, 0x03, 0x71, 0x64, 0x04, 0x66, 0x06, 0x68, 0x08, 0x07, 0x7f, 0x60, 0x70)


def main_capture():
    cap = Pcap()
    seq = 1
    # 1-2: data packets carrying LonTalk, normal priority and urgent
    cap.udp(DEV1, DEV2, 1628, 1628, cnip(0x01, LON_ACK, seqno=seq, tstamp=1000))
    seq += 1
    cap.udp(DEV2, DEV1, 1628, 1629, cnip(0x01, LON_UNICAST, seqno=seq, tstamp=1010))
    seq += 1
    # 3: LonTalk after a two word extension header, security flag set,
    #    vendor code
    cap.udp(DEV1, DEV2, 1628, 1628, cnip(0x01, LON_ACK, sec=True, vendor=0x1234,
                                         ext=b'EXT1EXT2', seqno=seq, tstamp=1020))
    seq += 1
    # 4: data packet with a protocol code nobody registered (shown as data)
    cap.udp(DEV1, DEV2, 1628, 1628, cnip(0x01, b'\xde\xad\xbe\xef', pcode=5, seqno=seq))
    seq += 1
    # 5: protocol code 31 with the security flag, urgent, empty payload
    cap.udp(DEV2, DEV1, 1628, 1629, cnip(0x01, b'', pcode=31, sec=True, seqno=seq,
                                         sessid=0xffffffff, tstamp=0xffffffff))
    seq += 1
    # 6-18: every other packet type (not decoded: a warning, then data)
    for t in TYPES:
        src, dst = (DEV1, CS) if t >= 0x60 else (CS, DEV1)
        body = b'' if t in (0x07, 0x60) else struct.pack('>I', 0x01000000 | t) + b'\0' * 8
        cap.udp(src, dst, 1628, 1628, cnip(t, body, seqno=seq, tstamp=2000 + seq))
        seq += 1
    # 19: unknown packet type, version 2, an extension header and payload
    cap.udp(DEV1, CS, 1628, 1629, cnip(0x55, b'\x01\x02', version=2, ext=b'\0\0\0\1',
                                       seqno=seq))
    seq += 1
    # 20: a data packet with only the header and the whole datagram as
    #     extension header (nothing left for LonTalk would throw, so
    #     protocol code 1)
    cap.udp(DEV1, DEV2, 1628, 1628, cnip(0x01, b'', pcode=1, ext=b'\xaa' * 12, seqno=seq))
    return cap


def malformed_capture():
    cap = Pcap()
    # 1: only the length, version and type
    cap.udp(DEV1, DEV2, 1628, 1628, cnip(0x01, LON_ACK)[:4])
    # 2: header cut short in the session ID
    cap.udp(DEV1, DEV2, 1628, 1628, cnip(0x01, LON_ACK)[:10])
    # 3: extension header of 255 words, not present
    h = bytearray(cnip(0x01, LON_ACK))
    h[4] = 0xff
    cap.udp(DEV1, DEV2, 1628, 1628, bytes(h))
    # 4: a data packet with no LonTalk payload
    cap.udp(DEV1, DEV2, 1628, 1629, cnip(0x01, b''))
    # 5: a status request cut short
    cap.udp(DEV1, CS, 1628, 1628, cnip(0x60)[:19])
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'cnip-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'cnip-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
