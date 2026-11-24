#!/usr/bin/env python3
# Generates test/captures/sstp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the SSTP dissector
(packet-sstp.c, MS-SSTP). Nothing comes from a real network.

SSTP is reached through HTTP: a request with the method SSTP_DUPLEX_POST
answered by status 200 makes the HTTP dissector hand the rest of the TCP
stream to SSTP (HTTP is on TCP port 80 by default).

Usage: mksstp.py <output directory>

Writes:
  sstp-coverage.pcap            HTTP handshake and every SSTP message type
                                and attribute, data PDUs (PPP), PDUs split
                                over segments and several in one segment,
                                the length field with reserved bits,
                                unknown attributes and extra bytes
  sstp-coverage-malformed.pcap  too short STATUS_INFO attributes, an
                                attribute length below 4, cut-off PDUs
"""
import os
import struct
import sys

CLI = ("192.0.2.1", 49152)
SRV = ("192.0.2.2", 80)
CMAC = bytes.fromhex("020000000001")
SMAC = bytes.fromhex("020000000002")


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(a):
    return bytes(int(x) for x in a.split("."))


class Stream:
    def __init__(self, cli=CLI, srv=SRV):
        self.cli, self.srv = cli, srv
        self.seq = {0: 1000, 1: 50000}
        self.frames = []

    def seg(self, from_server, payload=b"", flags=0x18):
        src, dst = (self.srv, self.cli) if from_server else (self.cli, self.srv)
        d = 1 if from_server else 0
        seq = self.seq[d]
        ack = self.seq[1 - d] if flags & 0x10 else 0
        self.seq[d] += len(payload) + (1 if flags & 0x02 else 0)
        tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, ip4(src[0]), ip4(dst[0]))
        iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
        pseudo = ip4(src[0]) + ip4(dst[0]) + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
        eth = (SMAC if from_server else CMAC) + (CMAC if from_server else SMAC) + b"\x08\x00"
        self.frames.append(eth + iph + tcp)

    def handshake(self):
        self.seg(False, b"", 0x02)
        self.seg(True, b"", 0x12)
        self.seg(False, b"", 0x10)


def attr(aid, body, length=None, reserved=0):
    """Attribute: reserved octet, id, 4 reserved bits + 12 bit length (the
    length includes the 4 octet header)."""
    if length is None:
        length = 4 + len(body)
    return struct.pack("!BBH", reserved, aid, length) + body


def ctrl(msgtype, attrs=(), extra=b"", numattrib=None, lenbits=0, ver=0x10, total=None):
    body = struct.pack("!HH", msgtype, len(attrs) if numattrib is None else numattrib)
    body += b"".join(attrs) + extra
    length = 4 + len(body) if total is None else total
    return struct.pack("!BBH", ver, 1, lenbits | length) + body


def data(ppp, lenbits=0):
    return struct.pack("!BBH", 0x10, 0, lenbits | (4 + len(ppp))) + ppp


def lcp_echo(code, ident):
    return b"\xff\x03\xc0\x21" + struct.pack("!BBHI", code, ident, 8, 0x12345678)


NONCE = bytes(range(0x40, 0x60))
H1 = bytes(range(0xa0, 0xb4))
H256 = bytes(range(0xc0, 0xe0))
MAC1 = bytes(range(0x10, 0x24))


def encap(extra=b"", length=None, proto=1):
    return attr(1, struct.pack("!H", proto) + extra, length)


def status(code, atid=1, value=b"", reserved=b"\0\0\0"):
    return attr(2, reserved + bytes([atid]) + struct.pack("!I", code) + value)


def cb(hashproto):
    """Crypto Binding attribute (SHA1 or SHA256 variant)."""
    if hashproto == 1:
        body = b"\0\0\0" + bytes([1]) + NONCE + H1 + b"\0" * 12 + MAC1 + b"\0" * 12
    else:
        body = b"\0\0\0" + bytes([2]) + NONCE + H256 + H256
    return attr(3, body)


def cbreq(hashbits=3):
    return attr(4, b"\0\0\0" + bytes([hashbits]) + NONCE)


def build(outdir):
    s = Stream()
    s.handshake()                                                     # 1-3
    s.seg(False, (b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
                  b"Host: vpn.example.com\r\n"
                  b"SSTPCORRELATIONID: {11111111-2222-3333-4444-555555555555}\r\n\r\n"))   # 4
    s.seg(True, (b"HTTP/1.1 200 OK\r\n"
                 b"Server: Microsoft-HTTPAPI/2.0\r\n\r\n"))                             # 5
    # 6: connect request with the encapsulated protocol attribute
    s.seg(False, ctrl(1, [encap()]))
    # 7: connect ACK with a crypto binding request attribute
    s.seg(True, ctrl(2, [cbreq(3)]))
    # 8: connect NAK with a status info attribute (no value)
    s.seg(True, ctrl(3, [status(4, 1)]))
    # 9: connect request again; two PDUs in one segment (data + echo)
    s.seg(False, ctrl(1, [encap()]) + ctrl(8))
    # 10: echo response and a data PDU (PPP LCP echo request) in one segment
    s.seg(True, ctrl(9) + data(lcp_echo(9, 1)))
    # 11: connected, crypto binding with SHA1
    s.seg(False, ctrl(4, [cb(1)]))
    # 12: crypto binding with SHA256
    s.seg(False, ctrl(4, [cb(2)]))
    # 13: crypto binding with an unknown hash protocol (neither branch)
    s.seg(False, ctrl(4, [attr(3, b"\0\0\0" + bytes([9]) + NONCE + b"\xee" * 8)]))
    # 14: abort with a status info attribute carrying an attribute value
    s.seg(True, ctrl(5, [status(7, 3, b"\xde\xad\xbe\xef")]))
    # 15-16: disconnect, disconnect ACK
    s.seg(False, ctrl(6, [status(0, 0)]))
    s.seg(True, ctrl(7))
    # 17: unknown message type, no attributes
    s.seg(False, ctrl(0x00ff))
    # 18: data PDUs, PPP LCP echo reply, and the PDU split over two segments
    s.seg(True, data(lcp_echo(10, 1)))
    p = data(lcp_echo(9, 2))
    s.seg(False, p[:5])                                               # 19
    s.seg(False, p[5:])                                               # 20
    # 21: control PDU split over two segments in the middle of an attribute
    p = ctrl(1, [encap()])
    s.seg(False, p[:10])
    s.seg(False, p[10:])                                              # 22
    # The reserved bits in the 16 bit length field (fixed: masked)
    s.seg(False, ctrl(1, [encap()], lenbits=0x8000))                  # 23
    s.seg(True, data(lcp_echo(10, 2), lenbits=0x4000))                # 24
    s.seg(False, ctrl(8, lenbits=0xf000) + ctrl(9, lenbits=0x1000))   # 25
    # Unknown attributes are skipped (fixed): unknown id 9 with 4 bytes of
    # value before a known attribute, and id 0 (no error) with a value
    s.seg(False, ctrl(1, [attr(9, b"\x01\x02\x03\x04"), encap(),
                          attr(0, b"\x00" * 8), attr(7, b"")]))       # 26
    # Extra bytes after the value of a known attribute are skipped (fixed)
    s.seg(False, ctrl(1, [encap(b"\xaa\xbb\xcc\xdd"), cbreq(1)]))     # 27
    # Attribute with reserved bits in the attribute length set
    s.seg(True, ctrl(2, [attr(1, struct.pack("!H", 1), length=0x9006, reserved=0x80)]))  # 28
    # Status info exactly 12 octets long, and 12 + value with the maximum id
    s.seg(True, ctrl(3, [status(0x0b, 0xff, b"", b"\x01\x02\x03"),
                         status(0x0a, 2, b"x" * 9)]))                # 29
    # Every status value, one attribute each
    st = [status(c, 1) for c in (0, 1, 2, 3, 5, 6, 8, 9)]
    s.seg(True, ctrl(3, st))                                         # 30
    # Trailing bytes after the attributes ("Unknown Data") and after
    # a message without attributes
    s.seg(False, ctrl(1, [encap()], extra=b"\x01\x02\x03\x04\x05"))   # 31
    s.seg(False, ctrl(8, extra=b"\xaa\xbb"))                          # 32
    # ACK from the server and FIN
    s.seg(True, b"", 0x10)
    s.seg(False, b"", 0x11)
    s.seg(True, b"", 0x11)
    pcap(os.path.join(outdir, "sstp-coverage.pcap"), s.frames)

    m = Stream(("192.0.2.3", 49153), SRV)
    m.handshake()
    m.seg(False, (b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
                  b"Content-Length: 18446744073709551615\r\nHost: vpn.example.com\r\n\r\n"))
    m.seg(True, b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
    # STATUS_INFO attribute shorter than 12 octets (expert info)
    m.seg(True, ctrl(3, [attr(2, b"\0\0\0\1")]))
    m.seg(True, ctrl(3, [attr(2, b"", length=4)]))
    # attribute length below 4 (stays as it is), then another attribute
    m.seg(False, ctrl(1, [attr(1, struct.pack("!H", 1), length=2), encap()]))
    # more attributes announced than present
    m.seg(False, ctrl(1, [encap()], numattrib=5))
    # crypto binding cut off
    m.seg(True, ctrl(4, [attr(3, b"\0\0\0\1" + NONCE[:10])]))
    # data PDU with only the 4 octet header (empty PPP)
    m.seg(False, struct.pack("!BBH", 0x10, 0, 4))
    # length field smaller than the header
    m.seg(True, struct.pack("!BBHHH", 0x10, 1, 2, 8, 0))
    pcap(os.path.join(outdir, "sstp-coverage-malformed.pcap"), m.frames)


if __name__ == "__main__":
    build(sys.argv[1])
