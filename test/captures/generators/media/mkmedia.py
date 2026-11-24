#!/usr/bin/env python3
# Generates test/captures/media_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Media Type dissector
(packet-media.c: the fallback for HTTP bodies whose media type has no
dissector of its own, with structured suffix and heuristic handling).

HTTP on TCP port 80 is registered by default.  Every packet is built with
struct; nothing comes from a real network.

Usage: mkmedia.py <output directory>
  media-coverage.pcap  HTTP exchanges with unknown media types (with and
                       without parameters), structured suffixes (json,
                       xml, cbor, unknown), upper case suffix, request
                       bodies, XML text under an unknown type (reached
                       by the heuristic when it is enabled)
"""
import os
import struct
import sys

CMAC = bytes.fromhex('020000000001')
SMAC = bytes.fromhex('020000000002')
CIP = bytes([192, 0, 2, 10])
SIP = bytes([192, 0, 2, 20])


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Conn:
    def __init__(self, frames, cport, sport=80):
        self.f = frames
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.ipid = 1

    def _tcp(self, c2s, flags, payload=b''):
        if c2s:
            sip, dip, sp, dp, seq, ack = CIP, SIP, self.cport, self.sport, self.cseq, self.sseq
            smac, dmac = CMAC, SMAC
        else:
            sip, dip, sp, dp, seq, ack = SIP, CIP, self.sport, self.cport, self.sseq, self.cseq
            smac, dmac = SMAC, CMAC
        opts = b''
        if flags & 2:
            opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1)
            if not flags & 0x10:
                ack = 0
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = sip + dip + struct.pack('>BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(tcp), self.ipid, 0x4000, 64, 6, 0) + sip + dip
        self.ipid += 1
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        self.f.append(dmac + smac + b'\x08\x00' + ip + tcp)
        if c2s:
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            self.sseq += len(payload) + (1 if flags & 3 else 0)

    def handshake(self):
        self._tcp(True, 0x02)
        self._tcp(False, 0x12)
        self._tcp(True, 0x10)

    def send(self, c2s, payload):
        self._tcp(c2s, 0x18, payload)
        self._tcp(not c2s, 0x10)

    def exchange(self, path, ctype, body, method='GET', req_ctype=None, req_body=b''):
        req = '%s %s HTTP/1.1\r\nHost: media.example\r\n' % (method, path)
        if req_ctype:
            req += 'Content-Type: %s\r\nContent-Length: %d\r\n' % (req_ctype, len(req_body))
        req += '\r\n'
        self.send(True, req.encode() + req_body)
        rsp = 'HTTP/1.1 200 OK\r\n'
        if ctype:
            rsp += 'Content-Type: %s\r\n' % ctype
        rsp += 'Content-Length: %d\r\n\r\n' % len(body)
        self.send(False, rsp.encode() + body)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    frames = []
    c = Conn(frames, 40001)
    c.handshake()
    # unknown media type without parameters, with one and several parameters
    c.exchange('/a', 'application/x-unknown', bytes(range(32)))
    c.exchange('/b', 'application/x-unknown; charset=utf-8', b'plain bytes here\n')
    c.exchange('/c', 'application/x-unknown; version=2; profile="x y"; q=0.5', b'\x00\x01\x02\x03' * 5)
    c.exchange('/c2', 'text/x-unknown', b'some text of an unknown type\n')
    # structured suffixes: the suffix dissector gets the body
    c.exchange('/d', 'application/vnd.example+json', b'{"name": "media", "n": [1, 2, 3]}')
    c.exchange('/e', 'application/vnd.example+xml', b'<?xml version="1.0"?><root><a>1</a></root>')
    c.exchange('/f', 'application/vnd.example+cbor', bytes.fromhex('a2 01 02 03 63 61 62 63'))
    c.exchange('/g', 'application/Vnd.Example+JSON; charset=utf-8', b'{"upper": true}')
    # last plus decides: a+b+json
    c.exchange('/h', 'application/vnd.a+b+json', b'[1, 2]')
    # suffix without a dissector
    c.exchange('/i', 'application/vnd.example+nosuchsuffix', bytes(range(40, 70)))
    # a trailing plus (empty suffix)
    c.exchange('/j', 'application/vnd.example+', b'empty suffix\n')
    # XML under an unknown type: the heuristic (disabled by default) finds it
    c.exchange('/k', 'application/x-unknown-xml', b'<?xml version="1.0" encoding="UTF-8"?>\n<doc><item id="1"/></doc>')
    c.exchange('/k2', 'text/x-unknown-xml; charset=utf-8', b'<?xml version="1.0"?><p:doc xmlns:p="urn:example:p"><p:i/></p:doc>')
    # request bodies
    c.exchange('/l', 'application/x-unknown', b'reply', method='POST',
               req_ctype='application/x-unknown-request; charset=ascii', req_body=b'request body bytes')
    c.exchange('/m', 'application/x-unknown', b'reply', method='PUT',
               req_ctype='application/vnd.example.req+json', req_body=b'{"k": "v"}')
    # a one octet body
    c.exchange('/n', 'application/x-unknown', b'Z')
    # no Content-Type: not the media dissector
    c.exchange('/o', None, b'no content type header\n')
    pcap(os.path.join(out, 'media-coverage.pcap'), frames)


main()
