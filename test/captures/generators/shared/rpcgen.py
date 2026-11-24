# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small helpers shared by the mkdcerpc_*.py coverage generators: pcap
writer, a TCP connection with handshake, connection-oriented DCE/RPC
(bind, request/response) and a minimal NDR / NDR64 encoder. Every packet
is built with struct; addresses are from the documentation ranges."""

import struct
import uuid as _uuid

UUID_NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
UUID_NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


class TCP:
    """One TCP connection with a handshake; seq/ack kept per side."""
    def __init__(self, frames, cport, sport=49155,
                 cip=(192, 0, 2, 50), sip=(192, 0, 2, 60)):
        self.frames = frames
        self.c = (bytes(cip), cport, 0x10000000 + cport * 7)
        self.s = (bytes(sip), sport, 0x20000000 + cport * 11)
        self.cseq, self.sseq = self.c[2], self.s[2]
        self.seg(True, b'', 0x02)
        self.cseq += 1
        self.seg(False, b'', 0x12)
        self.sseq += 1
        self.seg(True, b'', 0x10)

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.cseq if from_client else self.sseq
        ack = self.sseq if from_client else self.cseq
        if flags == 0x02:
            ack = 0
        opts = struct.pack('>BBH', 2, 4, 1460) if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', src[1], dst[1], seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        ph = src[0] + dst[0] + struct.pack('>BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000, 64, 6, 0, src[0], dst[0])
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        mc, ms = bytes.fromhex('020000000050'), bytes.fromhex('020000000060')
        eth = (ms + mc) if from_client else (mc + ms)
        self.frames.append(eth + b'\x08\x00' + ip + tcp + payload)
        if from_client:
            self.cseq += len(payload)
        else:
            self.sseq += len(payload)

    def fin(self):
        self.seg(True, b'', 0x11)
        self.cseq += 1
        self.seg(False, b'', 0x11)
        self.sseq += 1
        self.seg(True, b'', 0x10)


def uuid_bytes(u, le=True):
    h = u.replace('-', '')
    a, b, c = int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)
    return struct.pack(('<' if le else '>') + 'IHH', a, b, c) + bytes.fromhex(h[16:])


class RPC:
    """Connection-oriented DCE/RPC on one TCP connection."""
    def __init__(self, tcp, uuid, ver, le=True, ndr64=False):
        self.tcp, self.le, self.ndr64 = tcp, le, ndr64
        self.e = '<' if le else '>'
        self.call_id = 0
        self.uuid, self.ver = uuid, ver

    def pdu(self, ptype, body, call_id, flags=0x03):
        drep = bytes([0x10 if self.le else 0x00, 0, 0, 0])
        hdr = struct.pack(self.e + 'BBBB', 5, 0, ptype, flags) + drep
        hdr += struct.pack(self.e + 'HHI', 16 + len(body), 0, call_id)
        return hdr + body

    def bind(self, port=b'49155\0'):
        self.call_id += 1
        ts = (UUID_NDR64, 1) if self.ndr64 else (UUID_NDR, 2)
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0) + struct.pack(self.e + 'B3x', 1)
        body += struct.pack(self.e + 'HBx', 0, 1) + uuid_bytes(self.uuid, self.le)
        body += struct.pack(self.e + 'I', self.ver[0] | (self.ver[1] << 16))
        body += uuid_bytes(ts[0], self.le) + struct.pack(self.e + 'I', ts[1])
        self.tcp.seg(True, self.pdu(11, body, self.call_id))
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0x12345) + struct.pack(self.e + 'H', len(port)) + port
        body += b'\0' * ((-(16 + len(body))) % 4)
        body += struct.pack(self.e + 'B3x', 1) + struct.pack(self.e + 'HH', 0, 0)
        body += uuid_bytes(ts[0], self.le) + struct.pack(self.e + 'I', ts[1])
        self.tcp.seg(False, self.pdu(12, body, self.call_id))

    def request(self, opnum, req, obj=None):
        self.call_id += 1
        flags = 0x83 if obj else 0x03
        body = struct.pack(self.e + 'IHH', len(req), 0, opnum)
        if obj:
            body += uuid_bytes(obj, self.le)
        self.tcp.seg(True, self.pdu(0, body + req, self.call_id, flags))

    def response(self, resp):
        body = struct.pack(self.e + 'IHBB', len(resp), 0, 0, 0) + resp
        self.tcp.seg(False, self.pdu(2, body, self.call_id))

    def call(self, opnum, req, resp, obj=None):
        self.request(opnum, req, obj)
        if resp is not None:
            self.response(resp)


class NDR:
    """Minimal NDR / NDR64 encoder (offsets relative to the stub start,
    which is 8-aligned in the PDU: 16 header + 8 request/response)."""
    def __init__(self, le=True, ndr64=False, base=0):
        self.b = bytearray()
        self.e = '<' if le else '>'
        self.le = le
        self.ndr64 = ndr64
        self.ref = 0x00020000
        self.base = base

    def align(self, n):
        self.b += b'\0' * ((-(len(self.b) + self.base)) % n)

    def raw(self, data):
        self.b += data

    def u8(self, v):
        self.b += bytes([v])

    def u16(self, v):
        self.align(2)
        self.b += struct.pack(self.e + 'H', v)

    def u32(self, v):
        self.align(4)
        self.b += struct.pack(self.e + 'I', v)

    def u64(self, v):
        self.align(8)
        self.b += struct.pack(self.e + 'Q', v)

    def enum16(self, v):
        """enum without v1_enum: 2 octets, 4 in NDR64"""
        if self.ndr64:
            self.u32(v)
        else:
            self.u16(v)

    def u3264(self, v):
        if self.ndr64:
            self.u64(v)
        else:
            self.u32(v)

    def count(self, v):
        """conformance / variance counts: 4 octets, 8 in NDR64"""
        if self.ndr64:
            self.u64(v)
        else:
            self.u32(v)

    def ptr(self, present):
        if present:
            self.ref += 4
            v = self.ref
        else:
            v = 0
        if self.ndr64:
            self.u64(v)
        else:
            self.u32(v)

    def guid(self, u):
        self.align(4)
        self.b += uuid_bytes(u, self.le)

    def nttime(self, v):
        """NTTIME as dissect_nttime() reads it: low, then high 32 bits"""
        self.align(4)
        self.b += struct.pack(self.e + 'II', v & 0xffffffff, v >> 32)

    def handle(self, h):
        self.align(4)
        self.b += h

    def wstr(self, s, nul=True):
        """conformant varying UTF-16 string"""
        n = len(s) + (1 if nul else 0)
        self.count(n)
        self.count(0)
        self.count(n)
        self.b += (s + ('\0' if nul else '')).encode('utf-16-le' if self.le else 'utf-16-be')

    def astr(self, s, nul=True):
        """conformant varying 8 bit string"""
        n = len(s) + (1 if nul else 0)
        self.count(n)
        self.count(0)
        self.count(n)
        self.b += s.encode() + (b'\0' if nul else b'')

    def vwstr(self, s, nul=True):
        """varying (not conformant) UTF-16 string"""
        n = len(s) + (1 if nul else 0)
        self.count(0)
        self.count(n)
        self.b += (s + ('\0' if nul else '')).encode('utf-16-le' if self.le else 'utf-16-be')

    def bytes(self):
        return bytes(self.b)
