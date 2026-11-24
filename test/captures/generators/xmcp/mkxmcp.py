#!/usr/bin/env python3
# Generates test/captures/xmcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the XMCP dissector (packet-xmcp.c).

XMCP (XML Media Control/Service Advertisement Framework, STUN-like) runs
over TCP port 4788 (and a TCP heuristic): a 20 octet header (message
type with class and method bits, length, magic cookie 0x7f5a9bc7, 96 bit
transaction ID) and attributes (type, length, value, padded to 4
octets). Requests and responses are matched by transaction ID. Every
packet is built from scratch with struct.

Usage: mkxmcp.py <outdir>
Writes xmcp-coverage.pcap and xmcp-coverage-malformed.pcap.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from util import Conn, write_pcap

COOKIE = 0x7f5a9bc7
(REG, UNREG, REGREV, PUB, UNPUB, PUBREV, SUB, UNSUB, WITHDRAW, NOTIFY, KEEPALIVE) = range(1, 12)
REQ, RESV, OK, ERR = 0x0000, 0x0010, 0x0100, 0x0110
USERNAME, INTEGRITY, ERRCODE, REALM, NONCE = 0x0006, 0x0008, 0x0009, 0x0014, 0x0015
CNAME, CHANDLE, PROTVER, PAGESIZE, CLABEL, KEEP, SIDENT, STRANS, SPROTO, FLAGS, SVER, SDATA, SUBID, SREMOVED, DOMAIN = (
    0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007, 0x1008, 0x1009, 0x100a, 0x100b, 0x100c, 0x100e, 0x100f, 0x1011)

def attr(t, v):
    v = v if isinstance(v, bytes) else v.encode()
    return struct.pack('>HH', t, len(v)) + v + b'\0' * ((-len(v)) % 4)

def u32(n): return struct.pack('>I', n)

def tid(n):
    return struct.pack('>III', 0x01020304, 0x05060708, n)

def msg(method, cls, n, *attrs, length=None, cookie=COOKIE, rawtype=None):
    body = b''.join(attrs)
    t = (method | cls) if rawtype is None else rawtype
    return struct.pack('>HHI', t, len(body) if length is None else length, cookie) + tid(n) + body

def guid(n): return struct.pack('>HH', 1, 2) + bytes((n + i) & 0xff for i in range(16))
def trans4(port, ip=b'\xc0\x00\x02\x09', fam=1): return struct.pack('>BBH', 0, fam, port) + ip
def trans6(port): return struct.pack('>BBH', 0, 2, port) + bytes(range(16))

main, mal = [], []

def session(out, ctr=[0]):
    ctr[0] += 1
    return Conn(out, 40000 + ctr[0], 4788, cisn=1000 * ctr[0], sisn=7000 * ctr[0])

c = session(main)
mac = bytes(range(20))
# Register / response (success) with handle, Username in the Info, Realm, Nonce, Client-Name ...
c.send(msg(REG, REQ, 1, attr(USERNAME, 'alice'), attr(REALM, '"SAF"'), attr(NONCE, 'abcdef0123'),
           attr(CNAME, 'client one'), attr(PROTVER, struct.pack('>HH', 1, 0)), attr(PAGESIZE, u32(50)),
           attr(CLABEL, 'label-1'), attr(DOMAIN, u32(7)), attr(KEEP, u32(300)), attr(INTEGRITY, mac)))
c.recv(msg(REG, OK, 1, attr(CHANDLE, u32(0xcafe)), attr(KEEP, u32(300)), attr(DOMAIN, u32(7)), attr(INTEGRITY, bytes(range(32)))))
# a Register with a client handle is a Keepalive; Keepalive method
c.send(msg(REG, REQ, 2, attr(CHANDLE, u32(0xcafe))))
c.recv(msg(REG, OK, 2))
c.send(msg(KEEPALIVE, REQ, 3, attr(CHANDLE, u32(0xcafe))))
c.recv(msg(KEEPALIVE, OK, 3))
# Publish: service identity, transport IPv4 and IPv6, protocols, flags, version, data
xml = b'<service><name>test</name></service>'
c.send(msg(PUB, REQ, 4, attr(CHANDLE, u32(0xcafe)), attr(SIDENT, guid(1)), attr(SPROTO, bytes([0, 0, 0, 6])),
           attr(STRANS, trans4(8080)), attr(SVER, u32(3)), attr(SDATA, xml),
           attr(FLAGS, struct.pack('>HHHHHH', 1, 1, 2, 1, 3, 1))))
c.recv(msg(PUB, OK, 4))
c.send(msg(PUB, REQ, 5, attr(SIDENT, guid(2)), attr(STRANS, trans6(5060)), attr(SPROTO, bytes([0, 0, 0, 17])),
           attr(SDATA, b'  \n  <?xml version="1.0"?><a/>'), attr(FLAGS, struct.pack('>HHHHHH', 1, 0, 2, 0, 3, 0))))
c.recv(msg(PUB, OK, 5))
for n, proto in enumerate((33, 132, 1, 253)):    # DCCP, SCTP, ICMP, other
    c.send(msg(PUB, REQ, 10 + n, attr(SIDENT, guid(3 + n)), attr(STRANS, trans4(1000 + n)), attr(SPROTO, bytes([0, 0, 0, proto])),
               attr(SDATA, b'plain text service data'), attr(FLAGS, struct.pack('>HHHH', 0x7777, 5, 1, 2))))
    c.recv(msg(PUB, OK, 10 + n))
# Service Data empty, protocol after transport, port name for TCP
c.send(msg(PUB, REQ, 20, attr(SPROTO, bytes([0, 0, 0, 6])), attr(STRANS, trans4(80)), attr(SIDENT, guid(9)), attr(SDATA, b'')))
c.recv(msg(PUB, OK, 20))
# an unknown transport family; an attribute of unknown type (note)
c.send(msg(PUB, REQ, 21, attr(STRANS, trans4(80, fam=9)), attr(0x7777, b'unknown attr'), attr(0x2000, b'')))
c.recv(msg(PUB, OK, 21))
# Subscribe, notify, unsubscribe, withdraw, unpublish
c.send(msg(SUB, REQ, 30, attr(SIDENT, guid(1)), attr(DOMAIN, u32(1))))
c.recv(msg(SUB, OK, 30, attr(SUBID, u32(55)), attr(SIDENT, guid(1)), attr(SDATA, xml)))
c.recv(msg(NOTIFY, REQ, 31, attr(SUBID, u32(55)), attr(SIDENT, guid(1)), attr(SDATA, xml)))
c.send(msg(NOTIFY, OK, 31))
c.send(msg(UNSUB, REQ, 32, attr(SUBID, u32(55))))
c.recv(msg(UNSUB, OK, 32))
for n, reason in enumerate((0, 1, 7)):
    c.recv(msg(WITHDRAW, REQ, 40 + n, attr(SIDENT, guid(1)), attr(SREMOVED, u32(reason))))
    c.send(msg(WITHDRAW, OK, 40 + n))
c.send(msg(UNPUB, REQ, 50, attr(SIDENT, guid(1))))
c.recv(msg(UNPUB, OK, 50))
c.recv(msg(PUBREV, REQ, 51, attr(SIDENT, guid(2))))
c.send(msg(PUBREV, OK, 51))
# Error responses: every unusual code, plain codes, an error with no reason text
for n, (cls_, num, text) in enumerate(((4, 0, 'Bad Request'), (4, 1, 'Unauthorized'), (4, 31, 'Integrity'), (4, 35, 'Nonce'),
                                       (4, 73, 'Unknown Service'), (4, 76, ''), (4, 77, 'Already'), (4, 99, 'Misc'),
                                       (5, 0, 'Responder'), (5, 1, 'Not impl'), (4, 13, 'RequestTooLarge'), (6, 6, 'x'))):
    c.send(msg(REG, REQ, 60 + n, attr(USERNAME, 'bob')))
    c.recv(msg(REG, ERR, 60 + n, attr(ERRCODE, struct.pack('>HBB', 0, cls_, num) + text.encode())))
# incorrect realm (warning), Message-Integrity of the 20 octet SHA1 and 32 octet SHA-256 sizes
c.send(msg(REG, REQ, 80, attr(REALM, 'SAF'), attr(USERNAME, 'carol'), attr(INTEGRITY, mac)))
c.recv(msg(REG, OK, 80, attr(REALM, '"SAF"'), attr(INTEGRITY, bytes(32))))
c.send(msg(UNREG, REQ, 81, attr(CHANDLE, u32(0xcafe))))
c.recv(msg(UNREG, OK, 81))
c.recv(msg(REGREV, REQ, 82))
c.send(msg(REGREV, OK, 82))
# a response without a request (note), reserved class, reserved methods (warnings), the keepalive of an unknown method
c.recv(msg(PUB, OK, 90))
c.recv(msg(PUB, RESV, 91))
c.send(msg(0x00c, REQ, 92))
c.send(msg(0x000, REQ, 93))
c.send(msg(0x3eef, REQ, 94))
# several messages in one segment, and one message over two segments
a = msg(KEEPALIVE, REQ, 100, attr(CHANDLE, u32(1)))
b = msg(KEEPALIVE, REQ, 101, attr(CHANDLE, u32(2)))
c.send(a + b)
c.recv(msg(KEEPALIVE, OK, 100) + msg(KEEPALIVE, OK, 101))
big = msg(PUB, REQ, 102, attr(SIDENT, guid(5)), attr(SDATA, b'<x>' + b'a' * 400 + b'</x>'), attr(CNAME, 'c' * 255))
c.csegs(big, 100)
c.recv(msg(PUB, OK, 102))
# the same transaction ID again after the response
c.send(msg(KEEPALIVE, REQ, 3, attr(CHANDLE, u32(1))))
c.fin()

# The 65532 octet message of the reproducer: attributes up to offset 65532, then one whose
# header ends at 65536 (where the 16 bit offset wrapped) and whose 16 octet value ends
# exactly at the end of the message (65532 + 20)
d = session(main)
attrs = [attr(0x7777, b'A' * 1020) for _ in range(63)] + [attr(0x7777, b'B' * 996)]
body = b''.join(attrs) + struct.pack('>HH', 0x7777, 16) + b'C' * 16
assert len(body) == 65532
big = struct.pack('>HHI', PUB | REQ, 65532, COOKIE) + tid(200) + body
d.csegs(big, 1400)
d.recv(msg(PUB, OK, 200))
d.fin()

# The heuristic: XMCP on another port (needs tcp heuristic, enabled by default)
h = Conn(main, 40100, 5555, cisn=1, sisn=1)
h.send(msg(KEEPALIVE, REQ, 300, attr(CHANDLE, u32(7))))
h.recv(msg(KEEPALIVE, OK, 300))
h.send(b'\x00\x01\x00\x00' + b'\x11' * 20)         # reserved bits clear but wrong cookie: not XMCP
h.send(b'\xc0\x01\x00\x00\x7f\x5a\x9b\xc7' + bytes(12))   # reserved bits set: not XMCP
h.send(b'\x00\x01')
h.fin()

# ---------------------------------------------------------------------------
# Malformed: lengths past the packet, attribute lengths past the message, minimum and maximum
# lengths, cookie, truncated attributes, wrong IPv4/IPv6 transport lengths
def S(m, ctr=[0]):
    ctr[0] += 1
    Conn(mal, 41000 + ctr[0], 4788, cisn=1, sisn=1, handshake=False).send(m)
S(msg(REG, REQ, 1, attr(USERNAME, 'x'), length=500))
S(msg(REG, REQ, 2, attr(USERNAME, 'x'), length=0xffff))
S(msg(REG, REQ, 3) + b'')
S(struct.pack('>HHI', REG, 8, COOKIE) + tid(4) + struct.pack('>HH', USERNAME, 40) + b'abcd')    # attribute past the message
S(struct.pack('>HHI', REG, 4, COOKIE) + tid(5) + struct.pack('>HH', 0x7777, 0xffff))
S(msg(REG, REQ, 6, attr(USERNAME, b'')))                                   # below the minimum
S(msg(REG, REQ, 7, attr(NONCE, b'')))
S(msg(REG, REQ, 8, attr(CNAME, b'')))
S(msg(REG, REQ, 9, attr(CLABEL, b'')))
S(msg(REG, REQ, 10, attr(NONCE, b'n' * 256)))                              # above the maximum
S(msg(REG, REQ, 11, attr(CNAME, b'n' * 300)))
S(msg(REG, REQ, 12, attr(INTEGRITY, bytes(10))))
S(msg(REG, REQ, 13, attr(INTEGRITY, bytes(33))))
S(msg(REG, REQ, 14, attr(INTEGRITY, bytes(20)), attr(NONCE, 'after integrity')))   # data after message-integrity
S(msg(REG, REQ, 15, attr(CHANDLE, b'\x01\x02')))                            # fixed-length attributes too short
S(msg(REG, REQ, 16, attr(CHANDLE, bytes(8))))                               # and too long
S(msg(REG, REQ, 17, attr(PROTVER, b'\x00\x01')))
S(msg(REG, REQ, 18, attr(PROTVER, b'\x00')))
S(msg(REG, REQ, 19, attr(PROTVER, b'')))
for k, t in enumerate((PAGESIZE, KEEP, SVER, SUBID, SREMOVED, DOMAIN, SPROTO)):
    S(msg(REG, REQ, 20 + k, attr(t, b'\x01')))
S(msg(PUB, REQ, 30, attr(SIDENT, b'')))
S(msg(PUB, REQ, 31, attr(SIDENT, b'\x00\x01')))
S(msg(PUB, REQ, 32, attr(SIDENT, b'\x00\x01\x00\x02')))
S(msg(PUB, REQ, 33, attr(SIDENT, bytes(19))))
S(msg(PUB, REQ, 34, attr(SIDENT, bytes(24))))
S(msg(PUB, REQ, 35, attr(STRANS, b'')))
S(msg(PUB, REQ, 36, attr(STRANS, b'\x00')))
S(msg(PUB, REQ, 37, attr(STRANS, b'\x00\x01')))
S(msg(PUB, REQ, 38, attr(STRANS, b'\x00\x01\x00')))
S(msg(PUB, REQ, 39, attr(STRANS, struct.pack('>BBH', 0, 1, 80) + bytes(8))))      # IPv4 with an IPv6-sized address
S(msg(PUB, REQ, 40, attr(STRANS, struct.pack('>BBH', 0, 2, 80) + bytes(4))))
S(msg(PUB, REQ, 41, attr(STRANS, struct.pack('>BBH', 0, 1, 80) + bytes(4) + bytes(20))))
S(msg(PUB, REQ, 42, attr(STRANS, struct.pack('>BBH', 0, 2, 80) + bytes(40))))
S(msg(PUB, REQ, 43, attr(SPROTO, b'\x00\x00\x00')))
S(msg(PUB, REQ, 44, attr(FLAGS, b'\x00\x01\x00')))                          # flags length not divisible by 4
S(msg(PUB, REQ, 45, attr(FLAGS, b'')))
S(msg(PUB, REQ, 46, attr(FLAGS, struct.pack('>HHHHH', 1, 1, 2, 1, 3))))
S(msg(PUB, REQ, 47, attr(ERRCODE, b'\x00\x00\x04')))
S(msg(PUB, REQ, 48, attr(ERRCODE, b'')))
S(msg(PUB, REQ, 49, attr(ERRCODE, struct.pack('>HBB', 0, 4, 100) + b'num out of range')))
S(msg(PUB, REQ, 50, attr(ERRCODE, struct.pack('>HBB', 0, 7, 255))))
S(msg(PUB, REQ, 51, attr(ERRCODE, struct.pack('>HBB', 0, 4, 1))))
S(msg(PUB, REQ, 52, attr(SDATA, b'<' + bytes(600))))
S(msg(PUB, REQ, 53, attr(REALM, b'')))
S(msg(PUB, REQ, 54, attr(REALM, b'"SAF"x')))
# unknown or wrong header: reserved type bits and cookie (not dissected as XMCP), shorter than 20
S(struct.pack('>HHI', 0xc001, 0, COOKIE) + tid(60))
S(struct.pack('>HHI', REG, 0, 0x12345678) + tid(61))
S(b'\x00\x01\x00\x00\x7f\x5a\x9b\xc7')
S(msg(REG, REQ, 62, attr(USERNAME, 'cut'))[:25])
# bytes after the message in the same segment
S(msg(REG, REQ, 63) + b'\x00\x01\x00')

out = sys.argv[1]
write_pcap(os.path.join(out, 'xmcp-coverage.pcap'), main)
write_pcap(os.path.join(out, 'xmcp-coverage-malformed.pcap'), mal)
print(len(main), len(mal))
