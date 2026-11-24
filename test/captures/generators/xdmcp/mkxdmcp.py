#!/usr/bin/env python3
# Generates test/captures/xdmcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the XDMCP dissector (packet-xdmcp.c).

XDMCP (X Display Manager Control Protocol) runs over UDP port 177. Every
message is: version (16 bit, 1), opcode (16 bit), length of the rest (16
bit), then fields built from counted strings (16 bit length + text),
byte arrays (16 bit length + data), arrays of strings (8 bit count) and
the connection type/address arrays of the Request.

Usage: mkxdmcp.py <outdir>
Writes xdmcp-coverage.pcap and xdmcp-coverage-malformed.pcap.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from util import udp, write_pcap

DM = '192.0.2.1'
XS = '192.0.2.2'

def s(t):      # counted string
    t = t.encode() if isinstance(t, str) else t
    return struct.pack('>H', len(t)) + t

def arr(*strs):   # ARRAY8 of strings: 8 bit count
    return bytes([len(strs)]) + b''.join(s(x) for x in strs)

def msg(op, body, length=None, version=1):
    return struct.pack('>HHH', version, op, len(body) if length is None else length) + body

def to_dm(m, sport=40177):
    return udp(sport, 177, m, src=XS, dst=DM)

def to_xs(m, dport=40177):
    return udp(177, dport, m, src=DM, dst=XS)

ADDR4 = bytes([192, 0, 2, 2])
ADDR6 = bytes.fromhex('20010db8000000000000000000000002')

def request(dn, ctypes, caddrs, aname, adata, anames, mfr):
    b = struct.pack('>H', dn)
    b += bytes([len(ctypes)]) + b''.join(struct.pack('>H', t) for t in ctypes)
    b += bytes([len(caddrs)]) + b''.join(s(a) for a in caddrs)
    b += s(aname) + s(adata) + arr(*anames) + s(mfr)
    return msg(7, b)

main = []
# Queries: broadcast, query, indirect, with 0, 1 and several authentication names
main.append(to_dm(msg(1, arr())))
main.append(to_dm(msg(2, arr(''))))
main.append(to_dm(msg(2, arr('MIT-MAGIC-COOKIE-1', 'XDM-AUTHENTICATION-1'))))
main.append(to_dm(msg(3, arr('MIT-MAGIC-COOKIE-1'))))
# Forward_query with an IPv4 client address and a 2 octet port, an IPv6
# address, and other lengths of address and port
main.append(to_dm(msg(4, s(ADDR4) + s(struct.pack('>H', 6000)) + arr('MIT-MAGIC-COOKIE-1'))))
main.append(to_dm(msg(4, s(ADDR6) + s(struct.pack('>H', 6001)) + arr())))
main.append(to_dm(msg(4, s(b'\x01\x02\x03') + s(b'\x17\x70\x00\x01') + arr('a', 'bb'))))
main.append(to_dm(msg(4, s(b'') + s(b'') + arr())))
# Willing, Unwilling
main.append(to_xs(msg(5, s('MIT-MAGIC-COOKIE-1') + s('xdm.example.net') + s('Willing to manage'))))
main.append(to_xs(msg(5, s('') + s('') + s(''))))
main.append(to_xs(msg(6, s('xdm.example.net') + s('Too many sessions'))))
# Requests with IPv4, IPv6 and other connection types, unknown type,
# address of the wrong length for its type, authentication data, authorization names
main.append(to_dm(request(0, [0], [ADDR4], 'MIT-MAGIC-COOKIE-1', b'\x01\x02\x03\x04\x05\x06\x07\x08',
                          ['MIT-MAGIC-COOKIE-1', 'XDM-AUTHORIZATION-1'], b'X-Terminal 1.0')))
main.append(to_dm(request(1, [0, 6], [ADDR4, ADDR6], '', b'', [], b'')))
main.append(to_dm(request(2, [1, 2, 0, 6, 0], [b'\x01\x02', b'\x00\x01\x02\x03', b'\x01\x02\x03', ADDR6, ADDR4],
                          'XDM-AUTHENTICATION-1', b'\xaa' * 8, ['XDM-AUTHORIZATION-1'], b'NCD-19')))
main.append(to_dm(request(3, [], [], 'x', b'y', [], b'z')))
# Accept, Decline, Manage, Refuse, Failed
main.append(to_xs(msg(8, struct.pack('>I', 0x12345678) + s('MIT-MAGIC-COOKIE-1') + s(b'\x11' * 8)
                      + s('MIT-MAGIC-COOKIE-1') + s(b'\x22' * 16))))
main.append(to_xs(msg(8, struct.pack('>I', 1) + s('') + s(b'') + s('') + s(b''))))
main.append(to_xs(msg(9, s('No such display') + s('XDM-AUTHENTICATION-1') + s(b'\x33' * 8))))
main.append(to_xs(msg(9, s('') + s('') + s(b''))))
main.append(to_dm(msg(10, struct.pack('>IH', 0x12345678, 0) + s(b'MIT'))))
main.append(to_dm(msg(10, struct.pack('>IH', 0x9abcdef0, 15) + s(b''))))
main.append(to_xs(msg(11, struct.pack('>I', 0xdeadbeef))))
main.append(to_xs(msg(12, struct.pack('>I', 0x12345678) + s('Server is going down'))))
main.append(to_xs(msg(12, struct.pack('>I', 0) + s(''))))
# Keepalive and Alive, session running and not
main.append(to_dm(msg(13, struct.pack('>HI', 0, 0x12345678))))
main.append(to_xs(msg(14, b'\x01' + struct.pack('>I', 0x12345678))))
main.append(to_xs(msg(14, b'\x00' + struct.pack('>I', 0x12345678))))
# Unknown opcodes, one with data, and a message with trailing data
main.append(to_dm(msg(0, b'')))
main.append(to_dm(msg(0x00ff, b'\x01\x02\x03\x04')))
main.append(to_xs(msg(11, struct.pack('>I', 7) + b'trailing')))
# Not XDMCP: another version number (the dissector declines, UDP shows data)
main.append(to_dm(msg(1, arr(), version=2)))
# IPv6 transport of one message over a different client port
main.append(to_dm(msg(2, arr('MIT-MAGIC-COOKIE-1')), sport=1024))

bad = []
# Request whose connection type and address counts differ (expert info)
b = struct.pack('>H', 0) + bytes([2]) + struct.pack('>HH', 0, 6) + bytes([1]) + s(ADDR4) + s('') + s(b'') + arr() + s(b'')
bad.append(to_dm(msg(7, b)))
b = struct.pack('>H', 0) + bytes([0]) + bytes([1]) + s(ADDR4)
bad.append(to_dm(msg(7, b)))
# Truncated messages and strings or arrays longer than the message
bad.append(to_dm(b'\x00\x01'))
bad.append(to_dm(b'\x00\x01\x00\x02'))
bad.append(to_dm(b'\x00\x01\x00\x02\x00'))
bad.append(to_dm(msg(2, b'\x02\x00\x05abc')))                      # string past the end
bad.append(to_dm(msg(2, b'\x05\x00\x01a')))                        # fewer strings than counted
bad.append(to_dm(msg(4, b'\x00\x04\xc0\x00')))                     # address cut
bad.append(to_dm(msg(4, s(ADDR4) + b'\x00\x02\x17')))              # port cut
bad.append(to_dm(msg(4, s(ADDR6) + s(b'\x17\x70') )))              # no names array
bad.append(to_dm(msg(4, b'\x00\x10\x01\x02')))                     # IPv6 address cut
bad.append(to_xs(msg(5, s('MIT') + s('host'))))                    # status missing
bad.append(to_xs(msg(5, b'\xff\xff' + b'abc')))                    # string length 65535
bad.append(to_xs(msg(6, b'\x00\x05ab')))
bad.append(to_dm(msg(7, b'\x00')))                                 # Request cut after display
bad.append(to_dm(msg(7, struct.pack('>H', 0) + bytes([1]) + struct.pack('>H', 0))))   # type array cut
bad.append(to_dm(msg(7, struct.pack('>H', 0) + bytes([1]) + struct.pack('>H', 0) + bytes([1]) + b'\x00\x04\xc0')))
bad.append(to_dm(msg(7, struct.pack('>H', 0) + bytes([1]) + struct.pack('>H', 6) + bytes([1]) + s(ADDR6[:8]))))
bad.append(to_dm(msg(7, struct.pack('>H', 0) + bytes([1]) + struct.pack('>H', 0) + bytes([1]) + s(ADDR4))))   # no auth fields
bad.append(to_xs(msg(8, b'\x00\x00')))
bad.append(to_xs(msg(8, struct.pack('>I', 1) + s('a') + b'\x00\x09ab')))
bad.append(to_xs(msg(9, s('x'))))
bad.append(to_dm(msg(10, b'\x00\x00\x00\x01\x00')))
bad.append(to_dm(msg(10, struct.pack('>IH', 1, 0) + b'\x00\x08ab')))
bad.append(to_xs(msg(11, b'\x00\x00')))
bad.append(to_xs(msg(12, struct.pack('>I', 1))))
bad.append(to_dm(msg(13, b'\x00\x00\x00')))
bad.append(to_xs(msg(14, b'')))
bad.append(to_xs(msg(14, b'\x01\x00\x00')))
# Declared length larger than the data
bad.append(to_xs(msg(11, struct.pack('>I', 7), length=0x7fff)))

out = sys.argv[1]
write_pcap(os.path.join(out, 'xdmcp-coverage.pcap'), main)
write_pcap(os.path.join(out, 'xdmcp-coverage-malformed.pcap'), bad)
print(len(main), len(bad))
