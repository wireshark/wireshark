#!/usr/bin/env python3
# Generates test/captures/opsi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OPSI coverage captures: mkopsi.py <outdir>. OPSI is on TCP 4002."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from wslib import pcap, TCP, gz, ip4

def attr(t, val=b'', length=None):
    return struct.pack('!HH', t, 4 + len(val) if length is None else length) + val

def s(t, text):
    return attr(t, text.encode())

def u32(t, v):
    return attr(t, struct.pack('!I', v))

def ipa(t, a):
    return attr(t, ip4(a))

def pdu(code, attrs=b'', session=1, hook=2, major=1, minor=0, length=None):
    return struct.pack('!BBBBHH', major, minor, code,
                       hook, 8 + len(attrs) if length is None else length, session) + attrs

def all_attrs():
    a = [s(1, 'alice'), s(2, 'secret'), s(3, '\x01' + 'c' * 16), ipa(4, '192.0.2.10'), u32(5, 0x1234),
         u32(6, 2), u32(7, 1), ipa(8, '198.51.100.7'), ipa(9, '255.255.255.0'), u32(10, 3),
         s(11, 'filter 1'), u32(12, 1500), u32(13, 1), s(30, '5551234'), s(31, '5554321'),
         s(32, 'nas-1')]
    a += [s(t, 'acct%d' % t) for t in (40, 41, 42, 43, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59)]
    a += [s(44, 'sess-0001'), s(60, 'challenge'), u32(61, 19), s(77, '5559999'), s(87, 'port-7')]
    a += [u32(651, 11), u32(652, 12), s(653, 'vpn'), u32(654, 13), ipa(655, '203.0.113.5'), s(656, 'ran'),
          u32(657, 14), s(658, 'pop'), u32(659, 15), u32(660, 1700000000), u32(661, 1700000100),
          u32(674, 3), s(675, 'app')]
    return a

def frames():
    f = []
    c = TCP('192.0.2.1', 40100, '192.0.2.2', 4002)
    f += c.handshake()
    f.append(c.c2s(pdu(1, hook=1)))                                   # Discover Request, no attributes
    f.append(c.s2c(pdu(2, s(1, 'srv') + u32(674, 1))))                # Discover Response
    at = all_attrs()
    f.append(c.c2s(pdu(3, b''.join(at[:20]), session=7)))             # Service Request, many attributes
    f.append(c.c2s(pdu(3, b''.join(at[20:40]), session=7)))
    f.append(c.c2s(pdu(3, b''.join(at[40:]), session=7)))
    for t, code in enumerate((4, 5, 6)):                              # accept, reject, terminate
        f.append(c.s2c(pdu(code, u32(5, t) + s(1, 'bob'), session=7)))
    f.append(c.s2c(pdu(9, s(1, 'x'))))                                # unknown opcode
    f.append(c.s2c(pdu(4, attr(9999, b'\x00\x00\x00\x01') + u32(6, 1))))   # unknown attribute
    # PDU split over three TCP segments (reassembly)
    big = pdu(3, s(1, 'u' * 100) + s(2, 'p' * 100) + s(32, 'n' * 50), session=9)
    f.append(c.c2s(big[:5]))
    f.append(c.c2s(big[5:120]))
    f.append(c.c2s(big[120:]))
    # two PDUs in one segment
    f.append(c.s2c(pdu(4, u32(5, 1), session=9) + pdu(6, u32(5, 2), session=9)))
    # an attribute with length 4 (empty string value) and a zero-length string
    f.append(c.c2s(pdu(3, attr(1, b'') + attr(11, b''))))
    # Message length that ends exactly on an attribute boundary, extra attribute beyond it ignored
    f.append(c.c2s(pdu(3, s(1, 'abc') + s(2, 'def'), length=8 + 7)))
    return f

def malformed():
    f = []
    c = TCP('192.0.2.3', 40101, '192.0.2.2', 4002)
    f += c.handshake()
    for t in (4, 5, 6, 7, 8, 12, 60, 61, 651, 660, 674):               # too-short value attributes
        f.append(c.c2s(pdu(3, attr(t, b'\x00\x01') if t in (1,) else attr(t, b'', length=4))))
    f.append(c.c2s(pdu(3, attr(1, b'', length=0))))                    # length 0
    f.append(c.c2s(pdu(3, attr(1, b'ab', length=2))))                  # length 2 (< 4)
    f.append(c.c2s(pdu(3, s(1, 'ok') + b'\x00\x01\x00')))             # trailing junk
    f.append(c.c2s(pdu(3, s(1, 'ok') + attr(2, b'xx', length=100)))) # attribute longer than PDU
    f.append(c.c2s(pdu(3, attr(30, b'\xff\xfe\x80'))))                 # non-ASCII string
    f.append(c.c2s(pdu(3, s(1, 'abc') + s(2, 'def'), length=8 + 7 + 4)))   # length ends inside an attribute
    return f

def main(out):
    pcap(os.path.join(out, 'opsi-coverage.pcap'), frames())
    gz(os.path.join(out, 'opsi-coverage.pcap'))
    pcap(os.path.join(out, 'opsi-coverage-malformed.pcap'), malformed())

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
