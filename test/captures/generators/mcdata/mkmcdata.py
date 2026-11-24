#!/usr/bin/env python3
# Generates test/captures/mcdata_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the MCData dissector
(packet-mcdata.c, Mission Critical Data, 3GPP TS 24.282). MCData is
reached by default through the media types
application/vnd.3gpp.mcdata-signalling and application/vnd.3gpp.mcdata-payload,
here as HTTP bodies (TCP port 80). UDP needs Decode As (the malformed
capture, -d udp.port==40000,mcdata).

Usage: mkmcdata.py <output directory> [-v]
Writes mcdata-coverage.pcapng (main, default prefs) and
mcdata-coverage-malformed.pcapng.
"""
import struct
import sys

LT_ETH = 1
LT_EXPPDU = 252


def pcapng(path, frames, extra_lt=()):
    """frames: list of (interface, bytes). Interface 0 is Ethernet, 1 is
    Exported PDU, 2.. the link types in extra_lt. 10 ms per frame."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (LT_ETH, LT_EXPPDU) + tuple(extra_lt):
        out += block(1, struct.pack('<HHI', lt, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def mac(addr):
    return bytes([2, 0]) + ip4(addr)


IDENT = [0]


def ipv4(proto, payload, src, dst):
    IDENT[0] += 1
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0] & 0xffff,
                      0x4000, 64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + hdr + payload


def udp(payload, src, sport, dst, dport):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return (0, ipv4(17, u, src, dst))


class TCP:
    """A TCP connection; c2s()/s2c() return frames carrying data."""

    def __init__(self, cli, cport, srv, sport):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def seg(self, payload, to_server, flags=0x18, seq=None):
        if to_server:
            src, sp, dst, dp = self.cli, self.cport, self.srv, self.sport
            s, a = self.cseq, self.sseq
        else:
            src, sp, dst, dp = self.srv, self.sport, self.cli, self.cport
            s, a = self.sseq, self.cseq
        if seq is not None:
            s = seq
        opts = b''
        if flags & 0x02:
            opts = b'\x02\x04\x05\xb4'
            if not flags & 0x10:
                a = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, s & 0xffffffff, a & 0xffffffff,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return (0, ipv4(6, t, src, dst))

    def handshake(self):
        f = [self.seg(b'', True, 0x02)]
        self.cseq += 1
        f.append(self.seg(b'', False, 0x12))
        self.sseq += 1
        f.append(self.seg(b'', True, 0x10))
        return f

    def c2s(self, payload):
        f = self.seg(payload, True)
        self.cseq += len(payload)
        return f

    def s2c(self, payload):
        f = self.seg(payload, False)
        self.sseq += len(payload)
        return f


def exported_pdu(proto_name, payload):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


def u16(v): return struct.pack('<H', v)
def u32(v): return struct.pack('<I', v)
def u64(v): return struct.pack('<Q', v)
def b16(v): return struct.pack('>H', v)
def b32(v): return struct.pack('>I', v)
# ---- end of prelude ----

# ------------------------------------------------------------ MCData

TS = (1700000000).to_bytes(5, 'big')
CONV = bytes(range(0x10, 0x20))
MSGID = bytes(range(0x30, 0x40))
REPLY = bytes(range(0x50, 0x60))

SIG = 'application/vnd.3gpp.mcdata-signalling'
PAY = 'application/vnd.3gpp.mcdata-payload'

CLI, SRV = '192.0.2.21', '192.0.2.22'


def first(mtype, auth=0, prot=0):
    return bytes([(0x80 if auth else 0) | (0x40 if prot else 0) | mtype])


def lv(data):
    return struct.pack('>H', len(data)) + data


def payload(ctype, data):
    """Payload: 16 bit length (content type + data), content type, data."""
    return lv(bytes([ctype]) + data)


def sigmsg(mtype, ies=b'', sub=None, auth=0, prot=0):
    b = first(mtype, auth, prot)
    if sub is not None:
        b += bytes([sub])
    if mtype != 13:
        b += TS
    b += CONV + MSGID
    if mtype == 13:
        b += bytes([sub if sub is not None else 1])
    return b + ies


def sigmsg13(term, ies=b''):
    return first(13) + CONV + MSGID + bytes([term]) + ies


def http(body, ctype, request=True, path='/mcdata', ):
    if request:
        h = ('POST %s HTTP/1.1\r\nHost: mcdata.example.org\r\nContent-Type: %s\r\n'
             'Content-Length: %d\r\n\r\n' % (path, ctype, len(body))).encode()
    else:
        h = ('HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n'
             % (ctype, len(body))).encode()
    return h + body


def main_frames():
    f = []
    port = [49300]

    def conn():
        port[0] += 1
        c = TCP(CLI, port[0], SRV, 80)
        f.extend(c.handshake())
        return c

    def post(c, body, ctype=SIG):
        f.append(c.c2s(http(body, ctype)))

    def reply(c, body, ctype=SIG):
        f.append(c.s2c(http(body, ctype, False)))

    c = conn()
    # SDS signalling payload with every information element
    ies = (bytes([0x21]) + REPLY + bytes([0x22, 0x01]) + bytes([0x51]) + lv(b'user@example.org')
           + bytes([0x52]) + lv(b'\xde\xad\xbe\xef') + bytes([0x53]) + lv(b'{"app":1}')
           + bytes([0x78]) + payload(1, b'Hello MCData')
           + bytes([0x79]) + lv(b'{"meta":true}') + bytes([0x7B]) + lv(b'\x01\x02\x03\x04')
           + bytes([0x7C]) + lv(b'bob@example.org') + bytes([0x7E]) + lv(b'\x00\x01\x02')
           + bytes([0x7F]) + lv(b'Example Org')
           + bytes([0x7D]) + struct.pack('>H', 5) + bytes([1]) + b'app-1')
    post(c, sigmsg(1, ies, auth=1, prot=1))
    reply(c, sigmsg(5, bytes([0x81]), sub=2))
    # the disposition and request IEs: SDS (0x8n), FD (0x9n), mandatory (0xAn), ext
    # response (0xCn), release response (0xDn)
    post(c, sigmsg(1, bytes([0x81, 0x82, 0x83]) + bytes([0xA1]) + bytes([0xC1, 0xC2, 0xD1, 0xD2])))
    post(c, sigmsg(2, bytes([0x91, 0xA1, 0x22, 0x01]) + bytes([0x7D]) + struct.pack('>H', 2) + bytes([2]) + b'ur'))
    # notifications with their type byte: SDS 1-5, FD 1-4, FD network 1-2
    for st in range(1, 6):
        post(c, sigmsg(5, b'', sub=st))
    for st in range(1, 5):
        post(c, sigmsg(6, b'', sub=st))
    for st in range(1, 3):
        post(c, sigmsg(9, b'', sub=st))
    # FD HTTP termination, all information types
    for t in range(1, 8):
        post(c, sigmsg13(t))
    post(c, sigmsg13(1, bytes([0x21]) + REPLY))
    # message types without a body and an unknown one
    for t in (7, 8, 10, 11, 12, 17, 18, 19, 20, 4, 30, 63):
        post(c, first(t) + b'\x00')
    c = conn()
    # data payloads: every payload content type
    plds = [
        (1, b'text payload'), (2, b'\x00\x01\x02\x03'), (3, b'https://example.org/'),
        (4, b'https://example.org/f.bin'),
        (5, bytes([0x40, 0x00, 0x00, 0x10, 0x00, 0x00])),        # North, ~45 degrees
        (5, bytes([0xC0, 0x00, 0x00, 0x90, 0x00, 0x00])),        # South, west
        (5, bytes([0x00, 0x00, 0x01, 0x7f, 0xff, 0xff])),
        (6, b'\x12\x34'), (7, b'\xca\xfe'),
        (8, struct.pack('>H', 1200)), (8, struct.pack('>H', 0x8000 | 50)),
        (9, bytes([25]) + b'2026-11-07 09:30:00.12345'),
        (10, b'coded text'),
        (0, b'x'), (11, b'unknown type'),
    ]
    for ct, d in plds:
        post(c, first(3) + bytes([1, 0x78]) + payload(ct, d), PAY)
    # several payloads in one message
    body = first(3, 1, 1) + bytes([3])
    for ct, d in plds[:3]:
        body += bytes([0x78]) + payload(ct, d)
    post(c, body, PAY)
    reply(c, first(3) + bytes([0]), PAY)
    # body split over two segments (HTTP reassembly)
    big = first(3) + bytes([1, 0x78]) + payload(1, b'long text ' * 40)
    hb = http(big, PAY)
    f.append(c.c2s(hb[:150]))
    f.append(c.c2s(hb[150:]))
    return f, c


def udp_pkt(body, sport=40000, dport=40000):
    return udp(body, CLI, sport, SRV, dport)


def malformed_frames():
    f = []
    c = TCP(CLI, 49400, SRV, 80)
    f += c.handshake()

    def post(body, ctype=SIG):
        f.append(c.c2s(http(body, ctype)))

    # payload length of 0, longer than the message
    post(first(3) + bytes([1, 0x78]) + struct.pack('>H', 0), PAY)
    post(first(3) + bytes([1, 0x78]) + struct.pack('>H', 500) + b'\x01abc', PAY)
    post(first(3) + bytes([2, 0x78]) + payload(1, b'one') + bytes([0x78]) + struct.pack('>H', 9) + b'\x01', PAY)
    # information elements with a length longer than the message
    for iei in (0x51, 0x52, 0x53, 0x79, 0x7B, 0x7C, 0x7E, 0x7F):
        post(sigmsg(1, bytes([iei]) + struct.pack('>H', 300) + b'abc'))
    post(sigmsg(1, bytes([0x7D]) + struct.pack('>H', 300) + b'\x01abc'))
    post(sigmsg(1, bytes([0x78]) + struct.pack('>H', 300) + b'\x01abc'))
    post(sigmsg(1, bytes([0x78]) + struct.pack('>H', 0)))
    # truncated header parts and IEs
    post(first(1) + TS[:3])
    post(first(1) + TS + CONV[:5])
    post(first(5))
    post(first(13) + CONV)
    post(first(3))
    post(first(3) + bytes([5]))
    post(sigmsg(1, bytes([0x21]) + REPLY[:4]))
    post(sigmsg(1, bytes([0x22])))
    post(sigmsg(1, bytes([0x51])))
    post(sigmsg(1, bytes([0x51, 0x00])))
    # unknown IEIs, which are skipped one octet at a time
    post(sigmsg(1, bytes([0x30, 0x31, 0x32, 0x00, 0xff])))
    # payload bodies shorter than their content type needs
    for ct, d in [(5, b'\x01\x02'), (6, b'\x01'), (8, b'\x01'), (9, bytes([25]) + b'2026'), (9, b'')]:
        post(first(3) + bytes([1, 0x78]) + payload(ct, d), PAY)
    # UDP (Decode As mcdata): the reproducer of "MCData: Fix masks, latitude sign
    # and payload return value", an empty message, nothing after the first octet
    loc = b'\x05' + bytes([0x80 | 0x40, 0, 0]) + bytes([0x10, 0, 0])
    pl = b'\x78' + struct.pack('>H', len(loc)) + loc
    msg = b'\x01' + TS + b'\x11' * 16 + b'\x22' * 16 + pl + b'\xc1' + b'\xd2'
    f.append(udp_pkt(msg))
    f.append(udp_pkt(b'\x03'))
    f.append(udp_pkt(first(3) + bytes([2, 0x78]) + struct.pack('>H', 3) + b'\x01a'))
    f.append(udp_pkt(first(13) + CONV + MSGID + b'\x01'))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf, _ = main_frames()
    pcapng(out + '/mcdata-coverage.pcapng', mf)
    xf = malformed_frames()
    pcapng(out + '/mcdata-coverage-malformed.pcapng', xf)
    if '-v' in sys.argv:
        print('main', len(mf), 'malformed', len(xf))


main()
