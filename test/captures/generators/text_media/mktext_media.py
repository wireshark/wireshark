#!/usr/bin/env python3
# Generates test/captures/text_media_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the text-media coverage captures. Usage: mktext_media.py <outdir>
All packets are built with struct; nothing comes from a real network."""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

CIP, SIP_ = (192, 0, 2, 1), (192, 0, 2, 2)
ETH = lambda a, b: bytes(b) + bytes(a) + b'\x08\x00'
CM = (2, 0, 0, 0, 0, 1); SM = (2, 0, 0, 0, 0, 2)

def ip4(payload, proto, src, dst, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(t))
    t = t[:16] + struct.pack('!H', csum(pseudo + t)) + t[18:]
    return t

def udp(src, dst, sport, dport, payload):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(pseudo + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

class Flow:
    """One TCP connection (no handshake), request then response."""
    n = 0
    def __init__(self):
        Flow.n += 1
        self.port = 40000 + Flow.n
        self.cseq = 1000; self.sseq = 5000
    def c2s(self, data):
        f = ETH(CM, SM) + ip4(tcp(CIP, SIP_, self.port, 80, self.cseq, self.sseq, data), 6, CIP, SIP_)
        self.cseq += len(data); return f
    def s2c(self, data):
        f = ETH(SM, CM) + ip4(tcp(SIP_, CIP, 80, self.port, self.sseq, self.cseq, data), 6, SIP_, CIP)
        self.sseq += len(data); return f

def exchange(ctype, body, path=b'/x', extra=b''):
    fl = Flow()
    req = b'GET ' + path + b' HTTP/1.1\r\nHost: example.test\r\n\r\n'
    hdr = (b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype + b'\r\n' + extra +
           b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n')
    return [fl.c2s(req), fl.s2c(hdr + body)]

def exppdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    hdr = struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0)
    return hdr + payload

def write(fn, frames, linktype=1):
    with open(os.path.join(OUT, fn), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def write_ng(fn, frames):
    """pcapng with interface 0 Ethernet and interface 1 Exported PDU."""
    def blk(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (1, 252):
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(os.path.join(OUT, fn), 'wb') as f:
        f.write(out)

LINES = b'first line\r\nsecond line\r\n\r\nfourth after an empty line\r\n'
TYPES = [b'text/plain', b'text/richtext', b'text/enriched', b'text/parameters',
         b'text/html', b'text/xml-external-parsed-entity', b'text/css',
         b'application/xml-external-parsed-entity', b'text/javascript',
         b'application/x-javascript', b'application/x-tia-p25-issi',
         b'application/x-tia-p25-sndcp', b'application/x-ns-proxy-autoconfig',
         b'text/vnd.sun.j2me.app-descriptor', b'application/vnd.poc.refer-to',
         b'application/vnd.drm.message', b'application/x-wms-logplaystats',
         b'application/x-rtsp-udp-packetpair']
main = []
# 1-36: every media type registered by the dissector, a few lines each
for t in TYPES:
    main += exchange(t, LINES + b'last line of ' + t + b' without a terminator')
# Line endings: CRLF, LF only, CR only, mixed, a lone terminator
main += exchange(b'text/plain', b'unix one\nunix two\n\nunix four\n')
main += exchange(b'text/plain; charset=utf-8', b'old mac one\rold mac two\r\rold mac four\r')
main += exchange(b'text/plain', b'mixed\r\nlf\ncr\rend\n\r\n\n')
main += exchange(b'text/plain', b'\n')
main += exchange(b'text/plain', b'x')
# Content type parameters and upper case
main += exchange(b'TEXT/HTML; charset=iso-8859-1', b'<html>\r\n<body>hello</body>\r\n</html>\r\n')
# XML detection: more than 38 octets starting with "<?xml" go to the XML
# dissector; 38 octets or fewer (and non-XML text) stay line based
xml = b'<?xml version="1.0" encoding="UTF-8"?>\r\n<a><b>text</b></a>\r\n'
main += exchange(b'text/html', xml)
main += exchange(b'text/plain', b'<?XML version="1.0"?>\r\n<r/>\r\n' + b' ' * 20)
main += exchange(b'text/html', b'<?xml version="1.0"?>\r\n<r/>\r\n')
main += exchange(b'text/html', b'<?xml version="1.0" encoding="UTF-8"?>')   # exactly 38
main += exchange(b'text/css', b'<?xm' + b'x' * 60)
# A large body with many lines
main += exchange(b'text/plain', b''.join(b'line %d\r\n' % i for i in range(300)))
# Reassembled over several TCP segments (Content-Length body split)
fl = Flow()
body = b''.join(b'segment line %d\r\n' % i for i in range(200))
hdr = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n' % len(body)
main.append(fl.c2s(b'GET /big HTTP/1.1\r\nHost: example.test\r\n\r\n'))
whole = hdr + body
for i in range(0, len(whole), 1000):
    main.append(fl.s2c(whole[i:i + 1000]))
# SIP MESSAGE with a text/plain body over UDP
sipmsg = (b'MESSAGE sip:bob@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n'
          b'Max-Forwards: 70\r\nFrom: <sip:alice@example.test>;tag=1\r\nTo: <sip:bob@example.test>\r\n'
          b'Call-ID: textmedia1@192.0.2.1\r\nCSeq: 1 MESSAGE\r\nContent-Type: text/plain\r\n'
          b'Content-Length: 21\r\n\r\nhello bob\r\nhow are you')
sipmsg = sipmsg.replace(b'Content-Length: 21', b'Content-Length: %d' % len(b'hello bob\r\nhow are you'))
main.append(ETH(CM, SM) + ip4(udp(CIP, SIP_, 5060, 5060, sipmsg), 17, CIP, SIP_))
n_main = len(main)

# Exported PDU naming the dissector (no match string, no content info)
exp = []
exp.append(exppdu('data-text-lines', LINES))
exp.append(exppdu('data-text-lines', b'one line'))
exp.append(exppdu('data-text-lines', xml))
write_ng('text_media-coverage.pcapng', [(0, f) for f in main] + [(1, f) for f in exp])

# Malformed capture: truncated bodies and a short-xml frame cut inside
mal = []
fl = Flow()
mal.append(fl.c2s(b'GET /t HTTP/1.1\r\nHost: example.test\r\n\r\n'))
mal.append(fl.s2c(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 500\r\n\r\ntruncated body line one\r\nline two'))
write('text_media-coverage-malformed.pcap', mal)
print(n_main, len(exp), len(mal))
