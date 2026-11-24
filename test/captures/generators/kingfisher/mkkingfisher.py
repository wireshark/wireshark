#!/usr/bin/env python3
# Generates test/captures/kingfisher_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Kingfisher coverage captures.

Usage: mkkingfisher.py <outdir>

  kingfisher-coverage.pcap            version 2 and 3 messages (every
                                      function code) over UDP and TCP,
                                      one byte acknowledgements through
                                      the conversation dissector,
                                      packets the heuristic rejects
  kingfisher-coverage-malformed.pcap  packets cut short
Synthetic: built with struct only.
"""
import os
import struct
import sys

CMAC = bytes.fromhex('020000000002')
SMAC = bytes.fromhex('020000000001')

FUNCTIONS = [0x00, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
             0x14, 0x15, 0x16, 0x17, 0x18, 0x1a, 0x1b, 0x1e, 0x1f, 0x21, 0x22, 0x23, 0x24, 0x25,
             0x26, 0x28, 0x29, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x33, 0x34, 0x35, 0x36,
             0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x41, 0x42, 0x46, 0x47, 0x50, 0x51, 0x80, 0x81,
             0x84, 0x85, 0x87, 0x88, 0x89, 0x8a, 0x9e, 0x9f, 0xa2, 0xa3, 0xa4, 0xa8, 0xa9, 0xd1,
             0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xe0, 0xe1, 0xe2, 0xe3]


def csum(b):
    if len(b) & 1:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def kf_crc(msg):
    """The checksum of the dissector: over bytes 1 .. len-3."""
    crc = 0
    for c in msg[1:len(msg) - 2]:
        for _ in range(8):
            c <<= 1
            top = crc & 0x8000
            crc = (crc << 1) & 0xffff
            crc = (crc + ((c & 0x100) != 0)) & 0xffff
            if top:
                crc ^= 0x1021
    return crc


def kf(function, target=1, frm=2, via=0, message=0x00, system=7, data=b'', hi=(0, 0, 0), good=True):
    """A Kingfisher message. Version 3 (function >= 0x80) has the high
    bytes of target, from and via after the function code."""
    v3 = function & 0x80
    hdr = bytes([system, target & 0xff, 0, frm & 0xff, via & 0xff, message, function])
    if v3:
        hdr += bytes([(target >> 8) & 0xff, (frm >> 8) & 0xff, (via >> 8) & 0xff])
    m = hdr + data + b'\0\0'
    m = m[:2] + bytes([len(m) - 1]) + m[3:]
    c = kf_crc(m)
    if not good:
        c ^= 0x00ff
    return m[:-2] + struct.pack('!H', c)


def ip(l4, proto, ident, to_server=True):
    a, b = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0,
                    *((a, b) if to_server else (b, a)))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + l4


class Net:
    def __init__(self):
        self.out = []
        self.seq = {}

    def _frame(self, l4, proto, to_server):
        macs = (CMAC + SMAC) if to_server else (SMAC + CMAC)
        pkt = macs + b'\x08\x00' + ip(l4, proto, len(self.out) + 1, to_server)
        self.out.append(pkt)

    def udp(self, payload, to_server=True, cport=40000, sport=4058):
        sp, dp = (cport, sport) if to_server else (sport, cport)
        self._frame(struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload, 17, to_server)

    def tcp(self, payload, to_server=True, cport=41000, sport=4058, flags=0x18):
        k = (cport, sport, to_server)
        seq = self.seq.get(k, 1000 if to_server else 5000)
        ack = self.seq.get((cport, sport, not to_server), 5000 if to_server else 1000)
        sp, dp = (cport, sport) if to_server else (sport, cport)
        opts = struct.pack('!BBH', 2, 4, 1460) + b'\x04\x02\x01\x03\x03\x07\x01\x01' if flags & 0x02 else b''
        t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        src, dst = (bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) if to_server else (bytes([192, 0, 2, 2]), bytes([192, 0, 2, 1]))
        t = t[:16] + struct.pack('!H', csum(src + dst + struct.pack('!BBH', 0, 6, len(t)) + t)) + t[18:]
        self._frame(t, 6, to_server)
        self.seq[k] = seq + len(payload) + (1 if flags & 3 else 0)


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main(out):
    n = Net()
    # A first one byte datagram: no conversation yet, so not Kingfisher
    n.udp(b'\x00', cport=39999)
    # Every function code (version 2 below 0x80, version 3 from it), each on
    # its own port pair so that the heuristic runs for each
    for i, fn in enumerate(FUNCTIONS):
        data = bytes(range(i % 5)) if i % 3 == 0 else b''
        n.udp(kf(fn, target=10 + i, frm=20 + i, via=i & 3, message=(0x00 if i % 2 else 0x10), data=data,
                 hi=(0, 0, 0)), cport=30000 + i, sport=4058 if i % 4 else 473)
    # Version 3 with 16 bit RTU addresses
    n.udp(kf(0x85, target=0x1234, frm=0x0102, via=0x0304, message=0x21, data=b'named variable'),
          cport=40001)
    # Version 2 with a longer data part
    n.udp(kf(0x0a, target=5, frm=6, message=0x03, data=bytes(range(60))), cport=40002)
    # One byte replies through the conversation dissector, every kind
    for k, b in enumerate((0x00, 0x01, 0x80, 0x81)):
        n.udp(kf(0x0a, target=5, frm=6, message=0x03), cport=40010 + k)
        n.udp(bytes([b]), to_server=False, cport=40010 + k)
    # A one byte datagram that is not an acknowledgement
    n.udp(kf(0x0b, target=5, frm=6), cport=40020)
    n.udp(b'\x55', to_server=False, cport=40020)
    # A second full message on a conversation (conversation dissector path)
    n.udp(kf(0x0b, target=6, frm=5, data=b'\x01\x02'), to_server=False, cport=40020)
    # Garbage on the conversation
    n.udp(bytes(range(40, 60)), to_server=True, cport=40020)
    # Packets the heuristic rejects
    n.udp(kf(0x0a) [:8], cport=40030)                                # shorter than 9 bytes
    n.udp(kf(0x7e, target=5), cport=40031)                            # unknown function code
    n.udp(kf(0x0a, target=5) + b'\0', cport=40032)                    # length byte does not fit the datagram
    n.udp(kf(0x0a, target=5, good=False), cport=40033)                # bad checksum
    # TCP: a request, a one byte reply, another request on the stream
    n.tcp(b'', flags=0x02)
    n.tcp(b'', to_server=False, flags=0x12)
    n.tcp(b'', flags=0x10)
    n.tcp(kf(0x85, target=300, frm=2, message=0x11, data=b'tcp data'))
    n.tcp(b'\x80', to_server=False)
    n.tcp(kf(0x0a, target=9, frm=1, message=0x02))
    n.tcp(b'\x01', to_server=False)
    n.tcp(kf(0x0a, target=9, frm=1, message=0x02), to_server=False, flags=0x18)
    # TCP, port 473 and a first segment that is not Kingfisher
    n.tcp(b'\x01\x02\x03', cport=41001, sport=473)
    pcap(os.path.join(out, 'kingfisher-coverage.pcap'), n.out)

    m = Net()
    # a message cut by the snap length: heuristic returns 0 (fully reported)
    # the conversation dissector gets 9 bytes of a 12 byte message
    m.udp(kf(0x0a, target=5), cport=40100)
    full = kf(0x0a, target=5, data=b'xyz')
    m.udp(full, to_server=False, cport=40100)
    pcap(os.path.join(out, 'kingfisher-coverage-malformed.pcap'), m.out)
    # cut the second packet's capture length (reported length stays)
    with open(os.path.join(out, 'kingfisher-coverage-malformed.pcap'), 'r+b') as f:
        d = bytearray(f.read())
        # second record header: after 24 + 16 + len(first)
        off = 24 + 16 + len(m.out[0])
        caplen = struct.unpack('<I', d[off + 8:off + 12])[0]
        d[off + 8:off + 12] = struct.pack('<I', caplen - 3)
        d = d[:off + 16 + caplen - 3]
        f.seek(0); f.truncate(); f.write(d)


if __name__ == '__main__':
    main(sys.argv[1])
