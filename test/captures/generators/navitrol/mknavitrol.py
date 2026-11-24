#!/usr/bin/env python3
# Generates test/captures/navitrol_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Navitrol (Navitec Systems) coverage captures.

    mknavitrol.py <outdir>

writes navitrol-coverage.pcap (every message of protocol versions 1 and 3,
little endian, TCP port 5000; decodes cleanly when TCP port 5000 is
decoded as Navitrol, there is no default port) and
navitrol-coverage-malformed.pcap (unknown message ids, short PDUs, and a
stream in big endian that needs navitrol.endian:big_endian).
Nothing is captured from a real network.
"""
import os
import struct
import sys

CL = bytes([10, 0, 0, 2])
SV = bytes([10, 0, 0, 1])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


class Flow:
    def __init__(self, cport, sport=5000, mss=1400):
        self.cport, self.sport, self.mss = cport, sport, mss
        self.cseq, self.sseq = 1000, 5000
        self.frames = []

    def _seg(self, to_server, payload, flags):
        if to_server:
            src, dst, sp, dp, seq, ack = CL, SV, self.cport, self.sport, self.cseq, self.sseq
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            src, dst, sp, dp, seq, ack = SV, CL, self.sport, self.cport, self.sseq, self.cseq
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        opts = bytes.fromhex('020405b4010303070402') if flags & 2 else b''
        opts += b'\x01' * (-len(opts) % 4)
        th = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        c = csum(src + dst + struct.pack('!BBH', 0, 6, len(th) + len(payload)) + th + payload)
        th = th[:16] + struct.pack('!H', c) + th[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(th) + len(payload), len(self.frames) + 1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        a, b = bytes.fromhex('020000000002'), bytes.fromhex('020000000001')
        self.frames.append((a + b if to_server else b + a) + b'\x08\x00' + ip + th + payload)

    def handshake(self):
        self._seg(True, b'', 0x02)
        self._seg(False, b'', 0x12)
        self._seg(True, b'', 0x10)

    def send(self, to_server, payload, split=None):
        """one segment, or segments of at most `split` octets"""
        if split is None:
            self._seg(to_server, payload, 0x18)
            return
        for i in range(0, len(payload), split):
            self._seg(to_server, payload[i:i + split], 0x18)

    def c(self, p, split=None):
        self.send(True, p, split)

    def s(self, p, split=None):
        self.send(False, p, split)


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
            f.write(fr)


def v1(mid, body=b'', length=None):
    """protocol version 1: 32-bit little endian message id, 32-bit total length"""
    return struct.pack('<II', mid, 8 + len(body) if length is None else length) + body


def v3(mid, body=b'', length=None, endian='<', version=3):
    """protocol version 3: 16-bit version and message id"""
    return struct.pack(endian + 'HHI', version, mid, 8 + len(body) if length is None else length) + body


DD = struct.pack('<dd', 12.5, -3.25)


def desc(s):
    return s.encode().ljust(200, b'\0')


def main_frames():
    f = Flow(40000)
    f.handshake()
    # --- version 1 requests (client to server)
    f.c(v1(1, DD + struct.pack('<ii', 900, 2)))
    f.c(v1(2, struct.pack('<I', 17) + DD + struct.pack('<ii', 1800, 1)))
    f.c(v1(14, struct.pack('<I', 18) + DD + struct.pack('<ii', 2700, 1) + struct.pack('<ii', 55, -4)))
    f.c(v1(3, struct.pack('<i', 4)))
    f.c(v1(4, struct.pack('<H', 1)))
    f.c(v1(5, struct.pack('<I', 1234)))
    f.c(v1(6))
    f.c(v1(7, struct.pack('<BBI', 1, 1, 100000)))
    f.c(v1(7, struct.pack('<BBI', 0, 0, 0)))
    f.c(v1(8))
    for mode in (0, 1, 2, 3):
        f.c(v1(9, struct.pack('<B', mode) + bytes([192, 168, 1, 50]) + struct.pack('<II', 5100, 5101)))
    f.c(v1(10))
    f.c(v1(11))
    f.c(v1(12))
    f.c(v1(4242, b'\x01\x02'))                    # unknown message id (expert warning)
    f.c(v1(13, bytes([30, 15, 12, 7, 10]) + struct.pack('<I', 2024)))
    # --- version 1 responses (server to client)
    f.s(v1(101, struct.pack('<B', 1) + DD + struct.pack('<ii', 900, 2) + struct.pack('<f', 0.75)))
    f.s(v1(101, struct.pack('<B', 0) + DD + struct.pack('<ii', 0, 0) + struct.pack('<f', 0.0)))
    f.s(v1(102, struct.pack('<IB', 17, 1) + DD + struct.pack('<ii', 1800, 1) + struct.pack('<f', 0.5)))
    f.s(v1(114, struct.pack('<IB', 18, 2) + DD + struct.pack('<ii', 1800, 1) + struct.pack('<f', 0.25)))
    f.s(v1(114, struct.pack('<IB', 19, 0) + DD + struct.pack('<ii', 1800, 1) + struct.pack('<f', 1.0)))
    f.s(v1(103, struct.pack('<BI', 1, 5)))
    f.s(v1(104, struct.pack('<B', 2)))
    f.s(v1(109, struct.pack('<B', 1)))
    f.s(v1(110))
    # --- version 3 requests
    f.c(v3(1001, struct.pack('<iiii', 1000, -2000, 450, 3)))
    f.c(v3(1004, struct.pack('<H', 1)))
    f.c(v3(1005, struct.pack('<I', 77)))
    f.c(v3(1006))
    f.c(v3(1007))
    f.c(v3(1008))
    f.c(v3(1011))
    f.c(v3(1012))
    f.c(v3(1013, struct.pack('<IHHHHH', 2024, 10, 7, 12, 15, 30)))
    f.c(v3(1016, struct.pack('<IiiHI', 5, 1000, 1010, 1, 123456)))
    # --- version 3 responses
    f.s(v3(1101, struct.pack('<iiiiHH', 1000, -2000, 450, 3, 1, 90)))
    f.s(v3(1104, struct.pack('<H', 2)))
    f.s(v3(1105, struct.pack('<I', 77) + desc('No reflectors in sight')))
    f.s(v3(1106, struct.pack('<I', 3) + struct.pack('<III', 1, 2, 3) + desc('first') + desc('second') + desc('third')))
    f.s(v3(1106, struct.pack('<I', 0)))
    f.s(v3(1107, struct.pack('<I', 42)))
    f.s(v3(1108, struct.pack('<H', 1)))
    f.s(v3(1111, struct.pack('<II', 20301, 30000)))
    f.s(v3(1112))
    f.s(v3(1113, struct.pack('<H', 1)))
    f.s(v3(1114, struct.pack('<IiiiiHH', 6, 1, 2, 3, 4, 2, 80)))
    f.s(v3(1116, struct.pack('<IiiH', 9, -500, 500, 1)))
    f.s(v3(201, struct.pack('<I', 2) + struct.pack('<II', 11, 12)))
    f.s(v3(201, struct.pack('<I', 0)))
    # position correction cumulative/velocity (1014/1015 as sent by the Navitrol client with data)
    f.c(v3(1014, struct.pack('<IiiiiIIII', 7, 100, 200, 300, 1, 11, 12, 13, 14)))
    f.c(v3(1015, struct.pack('<IiiiiIIII', 8, 100, 200, 300, 1, 21, 22, 23, 24)))
    # --- several PDUs in one segment, and PDUs split across segments
    f.c(v1(11) + v1(10) + v3(1011))
    f.s(v3(1111, struct.pack('<II', 20400, 30000))[:7])
    f.s(v3(1111, struct.pack('<II', 20400, 30000))[7:] + v3(1112))
    big = v3(1106, struct.pack('<I', 3) + struct.pack('<III', 1, 2, 3) + desc('split a') + desc('split b') + desc('split c'))
    f.s(big, split=100)
    # --- the reproducer of "Navitrol: Do not truncate the PDU length": an error
    #     description list of 330 entries, 67 KB; the 32-bit length no longer fits 16 bits
    n = 330
    codes = b''.join(struct.pack('<I', 5000 + i) for i in range(n))
    descs = b''.join(desc('Error number %d' % i) for i in range(n))
    huge = v3(1106, struct.pack('<I', n) + codes + descs)
    f.s(huge, split=1400)
    f.c(v1(11))           # the next PDU must be found right after the long one
    return f.frames


def malformed_frames():
    f = Flow(40100)
    f.handshake()
    f.c(v1(4242, b'\x01\x02'))                    # unknown version 1 id
    f.c(v3(2999, b'\x01\x02\x03\x04'))             # unknown version 3 id
    f.c(v3(1001, b'\x01\x02'))                     # truncated bodies
    f.c(v1(1, b'\x01\x02\x03'))
    f.c(v3(1105, struct.pack('<I', 5) + b'short'))
    f.c(v3(1106, struct.pack('<I', 1000)))         # error count far beyond the PDU
    f.c(v3(201, struct.pack('<I', 0xffffffff)))
    f.c(v3(1013, b'\x01'))
    f.c(v1(13, b'\x01'))
    f.c(v3(1014))                                  # cumulative / velocity without data
    f.c(v3(1015, struct.pack('<I', 0)))
    f.c(v1(1, length=4))                           # length shorter than the header
    f.c(v3(1011, length=0))
    f.c(struct.pack('<HHI', 3, 1111, 8 + 6) + b'\x01\x02')   # length 14 but 2 octets of body
    f.c(v1(11)[:5])
    g = Flow(40101, sport=5001)
    g.handshake()
    # big endian stream (decode with navitrol.endian:big_endian on port 5001): the version is
    # taken for the message id
    be = lambda mid, body=b'': struct.pack('>HHI', 3, mid, 8 + len(body)) + body
    g.c(be(1001, struct.pack('>iiii', 1, 2, 3, 4)))
    g.c(be(1011))
    g.c(be(1013, struct.pack('>IHHHHH', 2024, 10, 7, 12, 15, 30)))
    g.c(be(1106, struct.pack('>I', 2) + struct.pack('>II', 1, 2) + desc('a') + desc('b')))
    g.c(be(1111, struct.pack('>II', 20301, 30000)))
    g.c(be(201, struct.pack('>I', 1) + struct.pack('>I', 9)))
    g.c(struct.pack('>HHI', 1001, 3, 8 + 16) + struct.pack('>iiii', 1, 2, 3, 4))   # version 1001: as id 1001 for BE
    g.c(struct.pack('>HHI', 1111, 1, 8 + 8) + struct.pack('>II', 20301, 30000))
    g.c(struct.pack('>HHI', 1004, 1, 8 + 2) + struct.pack('>H', 1))
    # a v1 message in big endian: the id word has no upper half in either order
    g.c(struct.pack('>II', 11, 8))
    return f.frames + g.frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = main_frames()
    write_pcap(os.path.join(out, 'navitrol-coverage.pcap'), m)
    x = malformed_frames()
    write_pcap(os.path.join(out, 'navitrol-coverage-malformed.pcap'), x)
    print(len(m), 'frames,', len(x), 'malformed-capture frames')


if __name__ == '__main__':
    main()
