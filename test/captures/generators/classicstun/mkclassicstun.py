#!/usr/bin/env python3
# Generates test/captures/classicstun_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the classic STUN dissector
(packet-classicstun.c, RFC 3489 and draft-ietf-behave-rfc3489bis-00).

Classic STUN is a heuristic UDP and TCP dissector (enabled by default).
It takes a message whose type is one of its 16 known types, whose
transaction ID does not start with the RFC 5389 magic cookie (or the
XMCP one) and whose length field matches the payload exactly. The STUN
dissector on UDP port 3478 rejects such messages, so the heuristic runs
for them. Requests and responses are matched by transaction ID within
the conversation. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkclassicstun.py <output directory>

Writes:
  classicstun-coverage.pcap            every message type and attribute,
                                       request/response matching, IPv4 and
                                       IPv6 addresses (plain and XOR-d),
                                       short attributes, RFC 5389 style
                                       padding, a DATA attribute carrying an
                                       RFC 5389 STUN message
  classicstun-coverage-malformed.pcap  attribute lengths past the end of the
                                       message, attributes cut short, and
                                       messages the heuristic rejects
"""

import os
import struct
import sys

CLIENT = (192, 0, 2, 1)
SERVER = (198, 51, 100, 2)
CPORT = 40000
SPORT = 3478


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []
        self.t = 0

    def udp(self, payload, to_server=True, gap_ms=10):
        src, dst = (CLIENT, SERVER) if to_server else (SERVER, CLIENT)
        sp, dp = (CPORT, SPORT) if to_server else (SPORT, CPORT)
        hdr = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0)
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(payload))
        c = csum(pseudo + hdr + payload) or 0xffff
        l4 = hdr[:6] + struct.pack('>H', c) + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) + 1, 0x4000,
                         64, 17, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        macs = (bytes.fromhex('020000000002') + bytes.fromhex('020000000001')) if to_server \
            else (bytes.fromhex('020000000001') + bytes.fromhex('020000000002'))
        self.t += gap_ms
        self.frames.append((self.t, macs + b'\x08\x00' + ip + l4))

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        for t, f in self.frames:
            out.append(struct.pack('<IIII', 1792000000 + t // 1000, (t % 1000) * 1000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


_tid = [0]


def tid():
    """A new 16 octet transaction ID (never starting with a magic cookie)."""
    _tid[0] += 1
    return struct.pack('>I', 0xa1b2c300 + _tid[0]) + bytes(range(_tid[0], _tid[0] + 12))


def msg(mtype, t, attrs=b''):
    return struct.pack('>HH', mtype, len(attrs)) + t + attrs


def attr(atype, value, length=None):
    return struct.pack('>HH', atype, len(value) if length is None else length) + value


def addr4(ip, port, family=1):
    return struct.pack('>BBH', 0, family, port) + bytes(ip)


def addr6(ip, port):
    return struct.pack('>BBH', 0, 2, port) + bytes(ip)


def xaddr4(t, ip, port):
    w = struct.unpack('>I', t[:4])[0]
    return struct.pack('>BBHI', 0, 1, port ^ (w >> 16), struct.unpack('>I', bytes(ip))[0] ^ w)


def error_code(cls, num, reason):
    return struct.pack('>HBB', 0, cls, num) + reason


IPV6_A = bytes.fromhex('20010db8000000000000000000000001')
IPV6_B = bytes.fromhex('20010db8000000000000000000000002')
RELAY = (203, 0, 113, 5)

# Attribute types
MAPPED, RESPONSE, CHANGE, SOURCE, CHANGED, USERNAME, PASSWORD, INTEGRITY, \
    ERROR, UNKNOWN, REFLECTED = range(1, 12)
LIFETIME, ALTERNATE, COOKIE, BANDWIDTH, DEST, REMOTE, DATA, NONCE, REALM, REQTYPE = range(0x0d, 0x17)
XOR_MAPPED, XOR_ONLY, SERVER_ATTR, CONN_REQ_BINDING, BINDING_CHANGE = 0x8020, 0x0021, 0x8022, 0xc001, 0xc002


def rfc5389_binding_request():
    """An RFC 5389 STUN Binding Request (magic cookie) with a SOFTWARE
    attribute for the DATA attribute; with --enable-heuristic
    stun_classicstun it is dissected as STUN. (Without any attribute the
    STUN dissector throws, a packet-stun.c matter.)"""
    return struct.pack('>HHI', 0x0001, 8, 0x2112a442) + bytes(range(0x40, 0x4c)) \
        + struct.pack('>HH', 0x8022, 4) + b'peer'


def main_capture():
    c = Pcap()
    # 1-2: Binding Request and Response
    t = tid()
    c.udp(msg(0x0001, t, attr(RESPONSE, addr4(CLIENT, CPORT)) + attr(CHANGE, struct.pack('>I', 0x06))
              + attr(USERNAME, b'user0001') + attr(INTEGRITY, bytes(range(20)))))
    c.udp(msg(0x0101, t, attr(MAPPED, addr4((203, 0, 113, 10), 61000))
              + attr(SOURCE, addr4(SERVER, SPORT)) + attr(CHANGED, addr4((198, 51, 100, 3), 3479))
              + attr(REFLECTED, addr4(CLIENT, CPORT))
              + attr(XOR_MAPPED, xaddr4(t, (203, 0, 113, 10), 61000))
              + attr(SERVER_ATTR, b'classicstun-test 1.0')
              + attr(INTEGRITY, bytes(range(20, 40)))), False)
    # 3-4: Binding Request and Error Response
    t = tid()
    c.udp(msg(0x0001, t, attr(0x0025, b'\0\0\0\0') + attr(0x0026, b'\0\0\0\0')))
    c.udp(msg(0x0111, t, attr(ERROR, error_code(4, 20, b'Unknown Attr'))
              + attr(UNKNOWN, struct.pack('>HH', 0x0025, 0x0026))
              + attr(UNKNOWN, struct.pack('>HHHH', 0x0027, 0x0028, 0x0029, 0x0029))), False)
    # 5-6: Shared Secret Request and Response; 7-8: and an Error Response
    t = tid()
    c.udp(msg(0x0002, t))
    c.udp(msg(0x0102, t, attr(USERNAME, b'tempuser0001') + attr(PASSWORD, b'secretpw')), False)
    t = tid()
    c.udp(msg(0x0002, t))
    c.udp(msg(0x1112, t, attr(ERROR, error_code(4, 33, b'Need TLS'))), False)
    # 9-10: Allocate Request and Response (IPv6, XOR-d IPv6)
    t = tid()
    c.udp(msg(0x0003, t, attr(LIFETIME, struct.pack('>I', 600)) + attr(BANDWIDTH, struct.pack('>I', 64))
              + attr(REQTYPE, struct.pack('>BBH', 0, 2, 0)) + attr(COOKIE, struct.pack('>I', 0x72c64bc6))
              + attr(NONCE, b'nonce-0123456789') + attr(REALM, b'example.org\0')
              + attr(USERNAME, b'user0001')))
    c.udp(msg(0x0103, t, attr(MAPPED, addr6(IPV6_A, 5000))
              + attr(XOR_MAPPED, addr6(IPV6_B, 5001)) + attr(LIFETIME, struct.pack('>I', 0xffffffff))
              + attr(BANDWIDTH, struct.pack('>I', 0)) + attr(ALTERNATE, addr4((198, 51, 100, 9), 3478))), False)
    # 11-12: Allocate Request and Error Response
    t = tid()
    c.udp(msg(0x0003, t, attr(LIFETIME, struct.pack('>I', 0))))
    c.udp(msg(0x0113, t, attr(ERROR, error_code(4, 1, b'Unauthorized')) + attr(NONCE, b'nonce-01')
              + attr(REALM, b'example.org\0')), False)
    # 13-14: Send Request with data and Send Response
    t = tid()
    c.udp(msg(0x0004, t, attr(DEST, addr4(RELAY, 9000)) + attr(DATA, b'hello peer!\n')))
    c.udp(msg(0x0104, t), False)
    # 15-16: Send Request and Send Error Response
    t = tid()
    c.udp(msg(0x0004, t, attr(DEST, addr6(IPV6_B, 9001)) + attr(DATA, b'')))
    c.udp(msg(0x0114, t, attr(ERROR, error_code(4, 37, b'No Binding'))), False)
    # 17: Data Indication carrying an RFC 5389 STUN message
    c.udp(msg(0x0115, tid(), attr(REMOTE, addr4(RELAY, 9000)) + attr(DATA, rfc5389_binding_request())), False)
    # 18-21: Set Active Destination Request, Response, Request, Error Response
    t = tid()
    c.udp(msg(0x0006, t, attr(DEST, addr4(RELAY, 9000))))
    c.udp(msg(0x0106, t), False)
    t = tid()
    c.udp(msg(0x0006, t, attr(DEST, addr4(RELAY, 9002))))
    c.udp(msg(0x0116, t, attr(ERROR, error_code(4, 39, b'Bad Dest'))), False)
    # 22: TR-111 attributes and attributes with no specific dissection
    c.udp(msg(0x0001, tid(), attr(CONN_REQ_BINDING, b'dslforum.org/TR-111 ')
              + attr(BINDING_CHANGE, b'') + attr(XOR_ONLY, b'') + attr(0x7777, b'\x01\x02\x03\x04')))
    # 23: a response without a request
    c.udp(msg(0x0101, tid(), attr(MAPPED, addr4(CLIENT, CPORT))), False)
    # 24: attributes too short for their fields (each field is skipped)
    c.udp(msg(0x0001, tid(),
              attr(MAPPED, b'')
              + attr(RESPONSE, struct.pack('>BBH', 0, 1, 1234))          # IPv4, port only
              + attr(SOURCE, struct.pack('>BBH', 0, 2, 1234) + b'\0' * 4)  # IPv6, 8 octets
              + attr(CHANGED, struct.pack('>BBH', 0, 3, 1234) + b'\0' * 4)  # unknown family
              + attr(CHANGE, b'') + attr(USERNAME, b'') + attr(ERROR, b'')
              + attr(ERROR, struct.pack('>HBB', 0, 5, 0))                  # no reason
              + attr(LIFETIME, b'') + attr(COOKIE, b'') + attr(BANDWIDTH, b'')
              + attr(XOR_MAPPED, b'')
              + attr(XOR_MAPPED, struct.pack('>BBH', 0, 1, 1234))
              + attr(XOR_MAPPED, struct.pack('>BBH', 0, 2, 1234) + b'\0' * 4)
              + attr(XOR_MAPPED, struct.pack('>BBH', 0, 3, 1234) + b'\0' * 4)
              + attr(REQTYPE, b'')))
    # 25: unpadded attributes: RFC 5389 style padding before a known
    # attribute (assumed), no padding where the next attribute is known
    # without it, two octet attributes (family only), and padding at the end (assumed)
    c.udp(msg(0x0001, tid(),
              attr(USERNAME, b'alice') + b'\0\0\0'
              + attr(PASSWORD, b'secret') + attr(REALM, b'example.org\0')
              + attr(MAPPED, b'\x00\x01') + b'\0\0'
              + attr(REQTYPE, b'\x00\x01') + b'\0\0'
              + attr(XOR_MAPPED, b'\x00\x01') + b'\0\0'
              + attr(ERROR, b'\x00\x00\x04') + attr(NONCE, b'abcd')
              + attr(REALM, b'org') + b'\0'))
    return c


def malformed_capture():
    c = Pcap()
    # 1: an attribute length past the end of the message (shown as bogus)
    c.udp(msg(0x0001, tid(), attr(USERNAME, b'abcd', length=40)))
    # 2: only two octets left for an attribute header
    c.udp(msg(0x0001, tid(), attr(USERNAME, b'abcd') + b'\x00\x06'))
    # 3: UNKNOWN-ATTRIBUTES with an odd number of two octet values at the
    # end of the message (reads past the end)
    c.udp(msg(0x0111, tid(), attr(UNKNOWN, b'\x00\x25\x00\x26\x00\x27', length=6)))
    # 4-9: rejected by the heuristic: shorter than the header, a type with
    # the top bits set, the RFC 5389 magic cookie (STUN), the XMCP magic
    # cookie, an unknown type, a length that does not match
    c.udp(msg(0x0001, tid())[:16])
    c.udp(msg(0xc001, tid()))
    c.udp(struct.pack('>HHI', 0x0001, 0, 0x2112a442) + b'\x01' * 12)
    c.udp(struct.pack('>HHI', 0x0001, 0, 0x7f5a9bc7) + b'\x02' * 12)
    c.udp(msg(0x0005, tid()))
    c.udp(msg(0x0001, tid(), attr(USERNAME, b'abcd')) + b'\0\0\0\0')
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'classicstun-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'classicstun-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
