#!/usr/bin/env python3
# Generates test/captures/rtitcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the RTI-TCP (RTITCP) coverage captures.
# Usage: mkrtitcp.py <outdir>   (writes rtitcp-coverage.pcap and
# rtitcp-coverage-malformed.pcap)
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

class Cap:
    def __init__(self):
        self.pkts = []
        self.seq = {}
        self.t = 0
    def tcp(self, src, dst, sport, dport, payload, seq=None, flags=0x18):
        key = (src, dst, sport, dport)
        if seq is None:
            seq = self.seq.get(key, 1000)
        self.seq[key] = seq + len(payload)
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 5 << 4, flags,
                          65535, 0, 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         len(self.pkts) + 1, 0, 64, 6, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
        self.pkts.append(eth + ip + tcp + payload)
    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1000 + i // 4, (i % 4) * 250000,
                                    len(p), len(p)))
                f.write(p)

A = (192, 0, 2, 1)
B = (192, 0, 2, 2)
COOKIE = 0x2112A442
CRC_MAGIC = 0x43524332

def attr(t, body):
    pad = (-len(body)) % 4
    return struct.pack('!HH', t, len(body)) + body + b'\0' * pad

def locator4(ip, port):
    return attr(0x3D01, b'\0' * 8 + b'\xff\xff' + struct.pack('!H', port) + bytes(ip))
def locator6(addr16):
    # bytes 8-9 must not be 0xffff for the IPv6 branch
    return attr(0x3D01, addr16)
def port_attr(p):
    return attr(0x3D02, struct.pack('!I', p))
def ctype_attr(v):
    return attr(0x3D03, bytes([v]))
def cookie_attr(c):
    return attr(0x3D04, c)
def session_attr(s):
    return attr(0x3D07, s)
def error_attr(code, desc=b''):
    return attr(0x0009, struct.pack('!I', code) + desc)

def ctrl(kind, attrs=b'', tid=b'\x01' * 12, crc=False, cookie=COOKIE,
         alen=None, mlen=None, trailing=b''):
    if alen is None:
        alen = len(attrs)
    body = struct.pack('!HHI', kind, alen, cookie) + tid + attrs
    if mlen is None:
        mlen = len(body)
    hdr = struct.pack('!HHI', 0, mlen, 0xdd54dd55)
    if crc:
        hdr += struct.pack('!II', CRC_MAGIC, 0x12345678)
    return hdr + body + trailing

def rtps_msg(extra=b''):
    # RTPS header (version 2.1, vendor RTI 0x0101, GUID prefix) + INFO_TS
    hdr = b'RTPS' + bytes([2, 1]) + b'\x01\x01' + bytes(range(1, 13))
    ts = struct.pack('<BBHII', 0x09, 0x01, 8, 0x1000, 0x2000)
    return hdr + ts + extra

def data(rtps, crc=False, ctrl_byte=0x00):
    hdr = struct.pack('!I', (ctrl_byte << 24) | len(rtps)) + struct.pack('!I', 0xdd54dd55)
    if crc:
        hdr += struct.pack('!II', CRC_MAGIC, 0x9abcdef0)
    return hdr + rtps

def main(outd):
    c = Cap()
    # ---- Stream 1: identity bind etc. between A:50001 -> B:7400
    s = (A, B, 50001, 7400)
    r = (B, A, 7400, 50001)
    tid = lambda n: bytes([n]) * 12
    c.tcp(*s, ctrl(0x0C01, session_attr(b'\xde\xad\xbe\xef\x00\x01\x02\x03'), tid(1)))   # identity bind req
    c.tcp(*r, ctrl(0x0D01, b'', tid(1)))                                                  # response
    c.tcp(*s, ctrl(0x0C02, port_attr(7411), tid(2)))                                      # server logical port req
    c.tcp(*r, ctrl(0x0D02, port_attr(7411) + ctype_attr(0x00), tid(2)))
    c.tcp(*s, ctrl(0x0C03, port_attr(7412) + ctype_attr(0x40), tid(3)))                   # client logical port req
    c.tcp(*r, ctrl(0x0D03, ctype_attr(0x80), tid(3)))
    c.tcp(*s, ctrl(0x0C04, locator4((10, 1, 2, 3), 7400) + ctype_attr(0xC0)
                   + cookie_attr(bytes(range(16))), tid(4)))                              # connection bind
    c.tcp(*r, ctrl(0x0D04, cookie_attr(bytes(range(16, 32))) + ctype_attr(0x55), tid(4)))
    c.tcp(*s, ctrl(0x0C05, session_attr(b'\x01\x02\x03\x04'), tid(5)))
    c.tcp(*r, ctrl(0x0D05, session_attr(b'\x01\x02\x03\x04\x05\x06\x07\x08'), tid(5)))
    c.tcp(*s, ctrl(0x0C06, b'', tid(6)))                                                  # liveliness
    c.tcp(*r, ctrl(0x0D06, b'', tid(6)))
    c.tcp(*s, ctrl(0x0C1F, b'', tid(7)))                                                  # finalize ind
    # IPv4 and IPv6 locators; multiple attributes (", " separators in Info)
    c.tcp(*s, ctrl(0x0C02, locator4((172, 16, 0, 9), 9000) + locator4((172, 16, 0, 10), 9001)
                   + port_attr(1) + cookie_attr(b'\xaa' * 16), tid(8)))
    c.tcp(*s, ctrl(0x0C02, locator6(bytes(range(0x20, 0x30))) + locator4((1, 2, 3, 4), 5)
                   + locator6(b'\x20\x01\x0d\xb8' + b'\0' * 11 + b'\x01'), tid(9)))
    # Error responses with and without description; error attr before others
    for i, (code, desc) in enumerate([(0, b''), (1, b'transport class mismatch'),
                                      (2, b'\0'), (6, b'retry'), (0x1000, b''),
                                      (0x1001, b'xyz'), (0x1005, b'srv'), (0x1fff, b'q')]):
        c.tcp(*r, ctrl(0x0D11 if i % 2 else 0x0D14, error_attr(code, desc), tid(10 + i)))
    # Other attribute types the dissector only labels
    c.tcp(*s, ctrl(0x0C12, attr(0x3D05, b'\0\0\0\x01') + attr(0x3D06, b'\0\0\0\x02')
                   + attr(0x0001, b'\0' * 8) + attr(0x0020, b'\0' * 8)
                   + attr(0x000A, b'\0\x01\0\x02') + attr(0x8022, b'RTI Connext')
                   + attr(0x8023, b'\0' * 8) + attr(0x1234, b'ab'), tid(20)))
    # Unknown control message kind; a kind with the response flag, no request
    c.tcp(*s, ctrl(0x0EEE, b'', tid(21)))
    c.tcp(*r, ctrl(0x0D12, b'', tid(22)))          # response without a request
    c.tcp(*r, ctrl(0x0D13, b'', tid(23)))
    c.tcp(*s, ctrl(0x0C13, b'', tid(24)))
    c.tcp(*s, ctrl(0x0C15, b'', tid(25)))
    c.tcp(*r, ctrl(0x0D15, b'', tid(26)))
    # CRC variants
    c.tcp(*s, ctrl(0x0C01, port_attr(7), tid(30), crc=True))
    c.tcp(*r, ctrl(0x0D01, ctype_attr(0), tid(30), crc=True))
    # Not the control cookie: only the header and the kind decode
    c.tcp(*s, ctrl(0x0C01, b'\0' * 16, tid(31), cookie=0x11223344))
    # Several control messages in one segment (Info joined with ", ")
    c.tcp(*s, ctrl(0x0C06, b'', tid(40)) + ctrl(0x0C06, b'', tid(41)) + ctrl(0x0C1F, b'', tid(42), crc=True))
    # PDU split over two TCP segments (reassembly), and over three
    m = ctrl(0x0C04, locator4((10, 9, 8, 7), 1234) + cookie_attr(b'\x5a' * 16) + session_attr(b'\x11' * 8), tid(43))
    c.tcp(*s, m[:11])
    c.tcp(*s, m[11:])
    m = ctrl(0x0C02, port_attr(77) + ctype_attr(0x40) + session_attr(b'\x22' * 12), tid(44), crc=True)
    c.tcp(*s, m[:9])
    c.tcp(*s, m[9:30])
    c.tcp(*s, m[30:])
    # ---- Stream 2: RTPS data messages
    s2 = (A, B, 50002, 7400)
    r2 = (B, A, 7400, 50002)
    c.tcp(*s2, ctrl(0x0C01, b'', tid(50)))
    c.tcp(*r2, ctrl(0x0D01, b'', tid(50)))
    c.tcp(*s2, data(rtps_msg()))
    c.tcp(*r2, data(rtps_msg(), crc=True))
    c.tcp(*s2, data(rtps_msg(b'\0' * 12), ctrl_byte=0x40))     # control byte bits set (2^30 modulo)
    # data message followed by garbage in the same TCP segment is split by tcp_dissect_pdus
    c.tcp(*s2, data(rtps_msg()) + data(rtps_msg(b'\0' * 4)))
    d = data(rtps_msg(b'\0' * 100))
    c.tcp(*s2, d[:30])
    c.tcp(*s2, d[30:])
    # data message with a payload that is not a valid RTPS heuristically
    # (magic RTPS but body too short)
    c.tcp(*s2, data(b'RTPS\x02\x01\x01\x01' + b'\0' * 12))
    # Control message after data on the same stream
    c.tcp(*s2, ctrl(0x0C06, b'', tid(51)))
    c.tcp(*r2, ctrl(0x0D06, b'', tid(51)))
    # A new stream starts with a 5 byte segment (too short for the
    # heuristic), then a complete message
    s4 = (A, B, 50005, 7400)
    c.tcp(*s4, b'\0\0\0\0\0')
    c.tcp(*s4, ctrl(0x0C06, b'', tid(52)))
    # ---- Reproducers (rtitcp_wraploop*.py, rtitcp_errattr.py)
    # 1. msg_length 0xfff0 + CRC header 16 = 0x10000 wrapped uint16 to 0
    def wrap(withcookie):
        msg = struct.pack('!HH', 0, 0xfff0) + struct.pack('!I', 0xdd54dd55)
        msg += struct.pack('!II', CRC_MAGIC, 0)
        msg += struct.pack('!HH', 0x0C01, 0)
        if withcookie:
            msg += struct.pack('!I', COOKIE) + b'\x01' * 12
        msg += b'\0' * (0x10000 - len(msg))
        return msg
    for i, wc in enumerate((False, True)):
        m = wrap(wc)
        s3 = (A, B, 50100 + i, 50300)
        c.tcp(*s3, m[:40000])
        c.tcp(*s3, m[40000:])
    # 2. ERROR_CODE attribute shorter than 4, port/type attributes with other lengths
    for i, a in enumerate([struct.pack('!HH', 0x0009, 0) + b'\0' * 8,
                           struct.pack('!HH', 0x0009, 2) + b'\0' * 8,
                           struct.pack('!HH', 0x3D02, 8) + b'\0' * 8,
                           struct.pack('!HH', 0x3D03, 3) + b'\0' * 4]):
        c.tcp(A, B, 50200 + i, 50300, ctrl(0x0C01, a, b'\x02' * 12), seq=1)
    c.write(os.path.join(outd, 'rtitcp-coverage.pcap'))

    # ---- Malformed capture
    m = Cap()
    # truncated attribute (length beyond end), truncated header fields
    m.tcp(*s, ctrl(0x0C01, struct.pack('!HH', 0x3D01, 16) + b'\0' * 4, tid(60)))
    m.tcp(*s, ctrl(0x0C01, struct.pack('!HH', 0x3D02, 4) + b'\0\0', tid(61), alen=8))
    m.tcp(*s, ctrl(0x0C01, struct.pack('!HH', 0x3D04, 40) + b'\0' * 40, tid(62)))   # cookie longer than 16
    m.tcp(*s, ctrl(0x0C01, struct.pack('!HH', 0x3D03, 1), tid(63)))
    m.tcp(*s, ctrl(0x0C01, b'', tid(64), alen=100))
    m.tcp(*s, ctrl(0x0C01, b'', tid(65), mlen=5))
    m.tcp(*s, ctrl(0x0C01, b'', tid(66), mlen=2000))      # PDU never completes
    # RTPS-magic data with a length far beyond the segment
    m.tcp(A, B, 50003, 7400, struct.pack('!II', 3000, 0xdd54dd55) + rtps_msg())
    # control PDU with mlen 0xfff8 (get_pdu_len returns 1)
    m.tcp(A, B, 50004, 7400, struct.pack('!HHI', 0, 0xfff8, 0xdd54dd55) + b'\0' * 40)
    m.write(os.path.join(outd, 'rtitcp-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
