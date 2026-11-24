#!/usr/bin/env python3
# Generates test/captures/sap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP (Session Announcement Protocol, RFC 2974) coverage
# captures.  Usage: mksap.py <outdir>
# Nothing is captured from a network; every packet is built here.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from sapcov_lib import Cap

SDP = (b'v=0\r\no=jdoe 2890844526 2890842807 IN IP4 192.0.2.10\r\n'
       b's=Coverage session\r\nc=IN IP4 224.2.17.12/127\r\nt=0 0\r\n'
       b'm=audio 49170 RTP/AVP 0\r\n')
GRP = '224.2.127.254'
SRC = '192.0.2.10'


def sap(flags, authlen, msgid, origin, auth=b'', body=b''):
    return struct.pack('!BBH', flags, authlen, msgid) + origin + auth + body


def build_main(out):
    c = Cap()
    o4 = bytes([192, 0, 2, 10])
    o6 = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [10])
    # 1 announcement, IPv4, no auth, no payload type: SDP follows
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 0, 0x1234, o4, body=SDP))
    # 2 deletion, IPv4
    c.udp(SRC, GRP, 9875, 9875, sap(0x24, 0, 0x1234, o4, body=SDP))
    # 3 announcement, IPv6 originating source
    c.udp(SRC, GRP, 9875, 9875, sap(0x30, 0, 0x4321, o6, body=SDP))
    # 4 optional payload type (MIME) string, NUL terminated
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 0, 0x0001, o4, body=b'application/sdp\0' + SDP))
    # 5 authentication data (2 words), PGP, no padding
    auth = bytes([0x20]) + bytes(range(1, 8))
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 2, 0x0002, o4, auth=auth, body=SDP))
    # 6 authentication data, CMS, padded (3 pad bytes, last byte is the count)
    auth = bytes([0x31]) + b'\xaa\xbb\xcc\xdd' + b'\0\0\x03'
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 2, 0x0003, o4, auth=auth, body=b'application/sdp\0' + SDP))
    # 7 encrypted payload
    c.udp(SRC, GRP, 9875, 9875, sap(0x22, 0, 0x0004, o4, body=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
    # 8 compressed payload (the bytes are not interpreted)
    c.udp(SRC, GRP, 9875, 9875, sap(0x21, 0, 0x0005, o4, body=b'\x78\x9c\x01\x02'))
    # 9 compressed and encrypted
    c.udp(SRC, GRP, 9875, 9875, sap(0x23, 0, 0x0006, o4, body=b'\x09\x08\x07\x06'))
    # 10 payload type string without terminating NUL, up to the end
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 0, 0x0007, o4, body=b'text/plain'))
    # 11 version 0 style header (flags 0x00), reserved bit set
    c.udp(SRC, GRP, 9875, 9875, sap(0x08, 0, 0x0008, o4, body=SDP))
    # 12 padded auth with pad count 0 (hits the "no padding bytes" item)
    auth = bytes([0x30]) + b'\x11\x22\x33' + b'\x44\x55\x66\x00'
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 2, 0x0009, o4, auth=auth, body=SDP))
    # 13 announcement of an RTSP stream: the SDP has a=control, and an RTSP
    # SETUP for that control URL follows (SDP / RTSP interplay, run under ASAN with
    # WIRESHARK_DEBUG_WMEM_OVERRIDE=simple in the README)
    sdp2 = (b'v=0\r\no=jdoe 2890844527 2890842808 IN IP4 192.0.2.10\r\ns=RTSP stream\r\n'
            b'c=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 0 RTP/AVP 0\r\n'
            b'a=control:rtsp://192.0.2.10/stream/audio\r\n')
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 0, 0x000a, o4, body=b'application/sdp\0' + sdp2))
    # 14-15 RTSP SETUP and its reply (TCP 554, no handshake)
    req = (b'SETUP rtsp://192.0.2.10/stream/audio RTSP/1.0\r\nCSeq: 3\r\n'
           b'Transport: RTP/AVP;unicast;client_port=4588-4589\r\n\r\n')
    rep = (b'RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 12345678\r\n'
           b'Transport: RTP/AVP;unicast;client_port=4588-4589;server_port=6256-6257\r\n\r\n')
    c.tcp('192.0.2.20', '192.0.2.10', 50554, 554, 1000, 1, req)
    c.tcp('192.0.2.10', '192.0.2.20', 554, 50554, 1, 1000 + len(req), rep)
    c.write(os.path.join(out, 'sap-coverage.pcap'))


def build_malformed(out):
    c = Cap()
    o4 = bytes([192, 0, 2, 10])
    # auth length 1 with the padding bit set and a pad count larger than
    # the authentication data: "Bogus authentication length"
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 1, 0x0a01, o4, auth=bytes([0x30, 0, 0, 0xff]), body=SDP))
    # payload type search with nothing left (empty body after the header)
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 0, 0x0a02, o4))
    # packet ends in the originating source
    c.udp(SRC, GRP, 9875, 9875, sap(0x30, 0, 0x0a03, o4[:2]))
    # authentication data longer than the packet
    c.udp(SRC, GRP, 9875, 9875, sap(0x20, 40, 0x0a04, o4, auth=bytes([0x20]) + b'\1\2'))
    # encrypted with nothing after the header
    c.udp(SRC, GRP, 9875, 9875, sap(0x22, 0, 0x0a05, o4))
    c.write(os.path.join(out, 'sap-coverage-malformed.pcap'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)
