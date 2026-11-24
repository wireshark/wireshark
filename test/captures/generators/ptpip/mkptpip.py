#!/usr/bin/env python3
# Generates test/captures/ptpip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the PTP/IP dissector
(packet-ptpip.c), Picture Transfer Protocol over IP, TCP port 15740.

PTP/IP packets have a little endian length and packet type; the
initiator opens a command connection (Init Command Request/ACK) and an
event connection (Init Event Request/ACK), then sends operation requests
and gets data and responses. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkptpip.py <output directory>

Writes:
  ptpip-coverage.pcap            both connections of a session: every
                                 packet type the dissector handles, the
                                 packet types it only names, operation
                                 codes of the standard and of each vendor
                                 range, response codes, events, a data
                                 transfer with known and unknown length
  ptpip-coverage-malformed.pcap  packets cut short
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Conv:
    """One TCP connection, camera 10.0.0.2:15740, initiator 10.0.0.1."""

    def __init__(self, frames, cport):
        self.frames = frames
        self.c = (bytes([10, 0, 0, 1]), cport)
        self.s = (bytes([10, 0, 0, 2]), 15740)
        self.seq = [1000, 5000]

    def send(self, d, payload):
        src, dst = (self.c, self.s) if d == 0 else (self.s, self.c)
        t = struct.pack('!HHIIBBHHH', src[1], dst[1], self.seq[d],
                        self.seq[1 - d], 0x50, 0x18, 65535, 0, 0) + payload
        self.seq[d] += len(payload)
        iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t), 1, 0, 64, 6,
                          0, src[0], dst[0])
        iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
        mac = (b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01') if d == 0 else \
              (b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02')
        self.frames.append(mac[0] + mac[1] + b'\x08\x00' + iph + t)


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def pkt(ptype, body=b''):
    return struct.pack('<II', 8 + len(body), ptype) + body


GUID = bytes(range(0x10, 0x20))


def name(s):
    return s.encode('utf-16-le') + b'\0\0'


def cmd(opcode, tid, phase=1, params=b''):
    return pkt(6, struct.pack('<IHI', phase, opcode, tid) + params)


def resp(code, tid, params=b''):
    return pkt(7, struct.pack('<HI', code, tid) + params)


def main(outdir):
    frames = []
    c = Conv(frames, 50101)
    c.send(0, pkt(1, GUID + name('Initiator') + struct.pack('<I', 0x00010000)))
    c.send(1, pkt(2, struct.pack('<I', 7) + GUID + name('Camera') + struct.pack('<I', 0x00010001)))
    e = Conv(frames, 50102)
    e.send(0, pkt(3, struct.pack('<I', 7)))
    e.send(1, pkt(4))
    # Operations with their own dissection or name
    c.send(0, cmd(0x1001, 1))                                   # GetDeviceInfo
    c.send(1, pkt(9, struct.pack('<IQ', 1, 12)))                # Start Data
    c.send(1, pkt(10, struct.pack('<I', 1) + b'0123'))          # Data
    c.send(1, pkt(12, struct.pack('<I', 1) + b'4567'))          # End Data
    c.send(1, resp(0x2001, 1))
    c.send(0, cmd(0x1002, 2, params=struct.pack('<I', 0x1234))) # OpenSession
    c.send(1, resp(0x2001, 2))
    c.send(0, cmd(0x1004, 3))                                   # GetStorageIDs
    c.send(1, pkt(9, struct.pack('<IQ', 3, 0xFFFFFFFFFFFFFFFF)))  # unknown length
    c.send(1, pkt(12, struct.pack('<I', 3) + b'\0' * 8))
    c.send(1, resp(0x2002, 3))
    c.send(0, cmd(0x1003, 4))                                   # CloseSession
    c.send(0, cmd(0x1007, 5, params=struct.pack('<III', 0xffffffff, 0, 0)))  # not parsed
    c.send(1, resp(0x2019, 5))
    c.send(0, cmd(0x100c, 6, phase=2, params=b'\0' * 4))        # standard, no param decode
    c.send(1, resp(0x201d, 6, struct.pack('<I', 9)))
    # Vendor ranges (0x9xxx operations, 0xAxxx responses, 0xCxxx events)
    c.send(0, cmd(0x9001, 7))
    c.send(0, cmd(0x9801, 8))
    c.send(1, resp(0xA001, 7))
    c.send(1, resp(0xA801, 8))
    c.send(0, cmd(0x9101, 12))
    c.send(0, cmd(0xB001, 9))
    c.send(1, resp(0xB002, 9))
    # Codes below 0x1000 take the non-vendor path
    c.send(0, cmd(0x0001, 11))
    c.send(1, resp(0x0001, 11))
    # A response code outside the table
    c.send(1, resp(0x2fff, 10))
    # Events on the event connection
    e.send(1, pkt(8, struct.pack('<HI', 0x4002, 0) + b'\0' * 12))
    e.send(1, pkt(8, struct.pack('<HI', 0xC001, 5) + b'\0' * 12))
    # Packet types the dissector only names
    c.send(1, pkt(5, struct.pack('<I', 1)))                     # Init Fail
    c.send(0, pkt(11, struct.pack('<I', 2)))                    # Cancel
    c.send(0, pkt(13))                                          # Probe Request
    c.send(1, pkt(14))                                          # Probe Response
    c.send(0, pkt(0))                                           # Invalid
    c.send(0, pkt(99, b'\0' * 4))                               # unknown type
    # Unicode names: empty, and with characters outside ASCII
    c2 = Conv(frames, 50103)
    c2.send(0, pkt(1, GUID + name('') + struct.pack('<I', 0x00020003)))
    c2.send(1, pkt(2, struct.pack('<I', 8) + GUID + name('Kämera €') + struct.pack('<I', 0x00000000)))
    pcap(os.path.join(outdir, 'ptpip-coverage.pcap'), frames)

    bad = []
    c = Conv(bad, 50110)
    c.send(0, b'\x08\x00\x00')                                   # under 8 octets: not dissected
    c.send(0, struct.pack('<II', 16, 1) + GUID[:8])               # GUID cut short
    c.send(0, struct.pack('<II', 30, 1) + GUID + b'A\0B\0')       # name without terminator
    c.send(0, struct.pack('<II', 12, 6) + b'\0\0')                # request cut short
    c.send(0, struct.pack('<II', 14, 7) + b'\x01')                # response cut short
    c.send(0, struct.pack('<II', 12, 9) + b'\0\0')                # start data cut short
    c.send(0, struct.pack('<II', 12, 2) + b'\0\0')                # connection number cut short
    pcap(os.path.join(outdir, 'ptpip-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1])
