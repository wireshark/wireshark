#!/usr/bin/env python3
# Generates test/captures/media_type_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the "media_type" dissector table
(packet-media-type.c: registers the table that HTTP and other protocols
use to dispatch a body by its Internet media type; case insensitive).

HTTP on TCP port 80 is registered by default.  Every packet is built with
struct; nothing comes from a real network.

Usage: mkmedia_type.py <output directory>
  media-type-coverage.pcap  HTTP exchanges whose Content-Type is found in
                            the table (JSON, XML, PNG,
                            plain, HTML, in lower, upper and mixed case,
                            with parameters) or is not
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
    c = Conn(frames, 40002)
    c.handshake()
    png = bytes.fromhex('89504e470d0a1a0a') + struct.pack('>I', 13) + b'IHDR' + \
        struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0) + b'\x00\x00\x00\x00' + \
        struct.pack('>I', 0) + b'IEND' + b'\xae\x42\x60\x82'
    c.exchange('/a', 'application/json', b'{"table": "media_type", "hit": true}')
    c.exchange('/b', 'Application/JSON', b'{"case": "upper"}')
    c.exchange('/c', 'application/json; charset=utf-8', b'[1, 2, 3]')
    c.exchange('/d', 'text/xml', b'<?xml version="1.0"?><a><b>text</b></a>')
    c.exchange('/e', 'APPLICATION/XML; charset=UTF-8', b'<?xml version="1.0"?><a/>')
    c.exchange('/f', 'image/png', png)
    c.exchange('/h', 'text/plain', b'plain text body\n')
    c.exchange('/i', 'text/html', b'<html><body>hello</body></html>\n')
    c.exchange('/j', 'application/x-www-form-urlencoded', b'a=1&b=two')
    # not in the table: falls back to the media dissector
    c.exchange('/k', 'application/x-not-registered', b'\x00\x01\x02\x03')
    c.exchange('/l', 'x-unregistered/type', b'unregistered')
    # a request body dispatched by the table
    c.exchange('/m', 'application/json', b'{"ok": 1}', method='POST',
               req_ctype='application/json', req_body=b'{"request": 1}')
    pcap(os.path.join(out, 'media-type-coverage.pcap'), frames)


main()
