# Helper module for the dcerpc_epm capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic DCE/RPC packet builder shared by the small DCE/RPC coverage
generators: Ethernet/IPv4 with TCP (connection-oriented DCE/RPC, with
bind/bind_ack) or UDP (connectionless DCE/RPC), and a small NDR encoder.
Every packet is built with struct; nothing comes from a real network.
Addresses are from 192.0.2.0/24 (TEST-NET-1)."""

import struct
import uuid as _uuid

UUID_NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
UUID_NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'
CIP = (192, 0, 2, 50)
SIP = (192, 0, 2, 60)


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


def ipv4(src, dst, proto, l4):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0, 0x4000, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ip + l4


def eth(from_client, payload):
    mc, ms = bytes.fromhex('020000000050'), bytes.fromhex('020000000060')
    return ((ms + mc) if from_client else (mc + ms)) + b'\x08\x00' + payload


def uuid_bytes(u, le=True):
    return _uuid.UUID(u).bytes_le if le else _uuid.UUID(u).bytes


class TCP:
    """One TCP connection with a handshake; seq/ack kept per side."""
    def __init__(self, frames, cport, sport=49155, cip=CIP, sip=SIP):
        self.frames = frames
        self.c = (bytes(cip), cport)
        self.s = (bytes(sip), sport)
        self.cseq, self.sseq = 0x10000000 + cport * 7, 0x20000000 + cport * 11
        self.seg(True, b'', 0x02)
        self.cseq += 1
        self.seg(False, b'', 0x12)
        self.sseq += 1
        self.seg(True, b'', 0x10)

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.cseq if from_client else self.sseq
        ack = 0 if flags == 0x02 else (self.sseq if from_client else self.cseq)
        opts = struct.pack('>BBH', 2, 4, 1460) if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', src[1], dst[1], seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        ph = src[0] + dst[0] + struct.pack('>BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp + payload)) + tcp[18:]
        self.frames.append(eth(from_client, ipv4(src[0], dst[0], 6, tcp + payload)))
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


class CO:
    """Connection-oriented DCE/RPC on one TCP connection."""
    def __init__(self, tcp, uuid, ver, le=True, ndr64=False):
        self.tcp, self.le, self.ndr64 = tcp, le, ndr64
        self.e = '<' if le else '>'
        self.call_id = 0
        self.uuid, self.ver = uuid, ver

    def pdu(self, ptype, body, call_id, flags=0x03):
        drep = bytes([0x10 if self.le else 0x00, 0, 0, 0])
        hdr = struct.pack('BBBB', 5, 0, ptype, flags) + drep
        hdr += struct.pack(self.e + 'HHI', 16 + len(body), 0, call_id)
        return hdr + body

    def bind(self):
        self.call_id += 1
        ts = (UUID_NDR64, 1) if self.ndr64 else (UUID_NDR, 2)
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0) + struct.pack(self.e + 'B3x', 1)
        body += struct.pack(self.e + 'HBx', 0, 1) + uuid_bytes(self.uuid, self.le)
        body += struct.pack(self.e + 'I', self.ver[0] | (self.ver[1] << 16))
        body += uuid_bytes(ts[0], self.le) + struct.pack(self.e + 'I', ts[1])
        self.tcp.seg(True, self.pdu(11, body, self.call_id))
        sec = b'%d\0' % self.tcp.s[1]
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0x12345) + struct.pack(self.e + 'H', len(sec)) + sec
        body += b'\0' * ((-(16 + len(body))) % 4)
        body += struct.pack(self.e + 'B3x', 1) + struct.pack(self.e + 'HH', 0, 0)
        body += uuid_bytes(ts[0], self.le) + struct.pack(self.e + 'I', ts[1])
        self.tcp.seg(False, self.pdu(12, body, self.call_id))

    def request(self, opnum, req, obj=None):
        self.call_id += 1
        flags = 0x03 | (0x80 if obj else 0)
        body = struct.pack(self.e + 'IHH', len(req), 0, opnum)
        if obj:
            body += uuid_bytes(obj, self.le)
        self.tcp.seg(True, self.pdu(0, body + req, self.call_id, flags))

    def response(self, resp):
        body = struct.pack(self.e + 'IHBB', len(resp), 0, 0, 0) + resp
        self.tcp.seg(False, self.pdu(2, body, self.call_id))

    def fault(self, status):
        body = struct.pack(self.e + 'IHBBI', 0, 0, 0, 0, status) + b'\0' * 4
        self.tcp.seg(False, self.pdu(3, body, self.call_id))

    def call(self, opnum, req, resp, obj=None):
        self.request(opnum, req, obj)
        if resp is not None:
            self.response(resp)


class CL:
    """Connectionless DCE/RPC over UDP. Each call gets its own activity
    and sequence number; the response repeats them."""
    def __init__(self, frames, uuid, ver, le=True, cport=40000, sport=135, obj=None):
        self.frames, self.uuid, self.ver, self.le = frames, uuid, ver, le
        self.cport, self.sport = cport, sport
        self.obj = obj
        self.seq = 0
        self.act = None

    def pkt(self, ptype, opnum, stub, flags1, seq, act):
        e = '<' if self.le else '>'
        drep = bytes([0x10 if self.le else 0x00, 0, 0])
        obj = uuid_bytes(self.obj, self.le) if self.obj else b'\0' * 16
        hdr = struct.pack('BBBB', 4, ptype, flags1, 0) + drep + b'\x00'
        hdr += obj + uuid_bytes(self.uuid, self.le) + uuid_bytes(act, self.le)
        hdr += struct.pack(e + 'IIIHHHHHBB', 1, self.ver, seq, opnum, 0xffff, 0xffff,
                           len(stub), 0, 0, 0)
        assert len(hdr) == 80
        return hdr + stub

    def udp(self, from_client, payload):
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        src, dst = (CIP, SIP) if from_client else (SIP, CIP)
        u = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
        self.frames.append(eth(from_client, ipv4(src, dst, 17, u)))

    def request(self, opnum, stub):
        self.seq += 1
        self.act = '6b8c%04x-0000-4000-8000-%012x' % (self.cport & 0xffff, self.seq)
        self.opnum = opnum
        self.udp(True, self.pkt(0, opnum, stub, 0x28, self.seq, self.act))

    def response(self, stub):
        self.udp(False, self.pkt(2, self.opnum, stub, 0x0a, self.seq, self.act))

    def call(self, opnum, req, resp):
        self.request(opnum, req)
        if resp is not None:
            self.response(resp)


class NDR:
    """Minimal NDR / NDR64 encoder (offsets relative to the stub start,
    which is 8-aligned in the PDU)."""
    def __init__(self, le=True, ndr64=False, ref=0x00020000):
        self.b = bytearray()
        self.e = '<' if le else '>'
        self.le = le
        self.ndr64 = ndr64
        # full pointers: a response must use referent IDs above those of
        # its request, or they count as already sent (pass ref=...)
        self.ref = ref

    def align(self, n):
        self.b += b'\0' * ((-len(self.b)) % n)

    def raw(self, b):
        self.b += b

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

    def uuid(self, u):
        self.align(4)
        self.b += uuid_bytes(u, self.le)

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

    def wstr(self, s, nul=True):
        """conformant varying UTF-16 string"""
        n = len(s) + (1 if nul else 0)
        self.count(n)
        self.count(0)
        self.count(n)
        self.b += (s + ('\0' if nul else '')).encode('utf-16-le' if self.le else 'utf-16-be')

    def cstr(self, s, nul=True):
        """conformant varying 8-bit string"""
        n = len(s) + (1 if nul else 0)
        self.count(n)
        self.count(0)
        self.count(n)
        self.b += s.encode('latin-1') + (b'\0' if nul else b'')

    def bytes(self):
        return bytes(self.b)
