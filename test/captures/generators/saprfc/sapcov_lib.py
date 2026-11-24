#!/usr/bin/env python3
# Helper module for the saprfc capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers shared by the SAP coverage generators: pcap writer, Ethernet /
# IPv4 / TCP / UDP framing with per-direction TCP sequence numbers, SAP NI
# framing.  Nothing here is crypto.
import struct
import zlib


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000
        self.ipid = 1

    def add(self, fr, lt=1):
        self.frames.append((self.t, fr, lt))
        self.t += 1

    def exp_pdu(self, name, payload):
        '''An Exported PDU frame (link type 252) naming a dissector.'''
        def tag(t, v):
            pad = (-len(v)) % 4
            return struct.pack('!HH', t, len(v) + pad) + v + b'\0' * pad
        self.add(tag(12, name.encode()) + tag(0, b'') + payload, 252)

    def eth_ip(self, src, dst, proto, l4, sm=1, dm=2):
        src, dst = ip4(src), ip4(dst)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), self.ipid, 0, 64,
                         proto, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = bytes([2, 0, 0, 0, 0, dm]) + bytes([2, 0, 0, 0, 0, sm]) + b'\x08\x00'
        return eth + ip + l4, src, dst

    def tcp(self, src, dst, sport, dport, seq, ack, payload, flags=0x18, opts=b''):
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        s, d = ip4(src), ip4(dst)
        ph = s + d + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        c = csum(ph + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        fr, _, _ = self.eth_ip(src, dst, 6, tcp + payload,
                               1 if sport > dport else 2, 2 if sport > dport else 1)
        self.add(fr)

    def udp(self, src, dst, sport, dport, payload):
        u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        fr, _, _ = self.eth_ip(src, dst, 17, u)
        self.add(fr)

    def write(self, path, linktype=1):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
            for t, fr, lt in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)))
                f.write(fr)

    def write_ng(self, path):
        '''pcapng, one interface per link type (Ethernet and Exported PDU).'''
        def blk(typ, body):
            body += b'\0' * ((-len(body)) % 4)
            n = 12 + len(body)
            return struct.pack('<II', typ, n) + body + struct.pack('<I', n)
        lts = []
        for _, _, lt in self.frames:
            if lt not in lts:
                lts.append(lt)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in lts:
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
        for t, fr, lt in self.frames:
            ts = t * 1000000
            out += blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32, ts & 0xffffffff,
                                      len(fr), len(fr)) + fr)
        open(path, 'wb').write(out)


MSS = bytes([2, 4, 5, 0xb4, 4, 2, 1, 1])


class Flow:
    """One TCP connection: client -> server and back, with sequence numbers."""
    def __init__(self, cap, client, server, cport, sport):
        self.cap, self.c, self.s, self.cp, self.sp = cap, client, server, cport, sport
        self.cseq, self.sseq = 1000, 5000

    def syn(self):
        cap = self.cap
        cap.tcp(self.c, self.s, self.cp, self.sp, self.cseq, 0, b'', 0x02, MSS)
        self.cseq += 1
        cap.tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, b'', 0x12, MSS)
        self.sseq += 1
        cap.tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, b'', 0x10)

    def send(self, data, to_server=True):
        if to_server:
            self.cap.tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, data)
            self.cseq += len(data)
        else:
            self.cap.tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, data)
            self.sseq += len(data)

    def split(self, data, parts, to_server=True):
        n = len(data)
        cuts = [0] + [n * (i + 1) // parts for i in range(parts - 1)] + [n]
        for a, b in zip(cuts, cuts[1:]):
            self.send(data[a:b], to_server)


def ni(payload):
    return struct.pack('!I', len(payload)) + payload


# ---- SAP Router (NI_ROUTE, NI_PONG, NI_RTERR, ROUTER_ADM) -------------------

def route_string(hops):
    '''hops: list of (host, service, password) -> route string bytes.'''
    return b''.join(h.encode() + b'\0' + s.encode() + b'\0' + p.encode() + b'\0'
                    for h, s, p in hops)


def ni_route(hops, entries=None, talk=2, rest=0, version=2, ni_version=39, route=None,
             route_len=None, route_off=0):
    r = route_string(hops) if route is None else route
    return (b'NI_ROUTE\0' + bytes([version, ni_version,
                                   len(hops) if entries is None else entries, talk, 0, 0, rest]) +
            struct.pack('!II', len(r) if route_len is None else route_len, route_off) + r)


def rterr_ctl(opcode, rc=0, text=b'', tail=b'', ni_version=39, text_len=None):
    '''NI_RTERR control message (opcode != 0); text_len defaults to len(text).'''
    return (b'NI_RTERR\0' + bytes([ni_version, opcode, 0]) + struct.pack('!i', rc) +
            struct.pack('!I', len(text) if text_len is None else text_len) + text + tail)


def rterr_err(rc, fields, ni_version=39, tail=b'', text_len=None):
    '''NI_RTERR error information (opcode 0); fields is a list of strings that
    are NUL terminated and sent as the error text.'''
    text = b''.join(f.encode() + b'\0' for f in fields)
    return (b'NI_RTERR\0' + bytes([ni_version, 0, 0]) + struct.pack('!i', rc) +
            struct.pack('!I', len(text) if text_len is None else text_len) + text + tail)


def snc_frame(ftype, token=b'', data=b'', ext=None, hl=None, version=2, mech=2,
              flags=0x0001, qop=0x48, tok_len=None, data_len=None, eye=b'SNCFRAME'):
    '''SNC frame: 24 byte header, optional extension (flags, field), token, data.'''
    e = b''
    if ext is not None:
        e = struct.pack('!IH', 0x01020304, len(ext[0]) if ext[1] is None else ext[1]) + ext[0]
    if hl is None:
        hl = 24 + len(e)
    return (eye + bytes([ftype, version]) + struct.pack('!H', hl) +
            struct.pack('!II', len(token) if tok_len is None else tok_len,
                        len(data) if data_len is None else data_len) +
            struct.pack('!HH', mech, flags) [:3] + bytes([qop]) + e + token + data)


# ---- LZC (compress(1) style) compressor for the SAP LZC payload header ------

def lzc_compress(data, maxbits=13, alg=0x11):
    '''SAP LZC: uncompressed length (LE), algorithm, 1f 9d, flags, then an LZW
    stream as written by compress(1) in block mode.  Not crypto.'''
    maxmax = 1 << maxbits
    n_bits = 9
    maxcode = (1 << n_bits) - 1
    free_ent = 257
    out = bytearray(struct.pack('<I', len(data)) + bytes([alg, 0x1f, 0x9d, 0x80 | maxbits]))
    buf = bytearray(n_bits)
    off = 0

    def put(code):
        nonlocal buf, off, n_bits, maxcode
        for i in range(n_bits):
            if (code >> i) & 1:
                buf[(off + i) >> 3] |= 1 << ((off + i) & 7)
        off += n_bits
        if off == n_bits * 8:
            out.extend(buf)
            buf = bytearray(n_bits)
            off = 0
        if free_ent > maxcode:
            if off > 0:
                out.extend(buf)
            off = 0
            n_bits += 1
            maxcode = (1 << n_bits) - 1
            buf = bytearray(n_bits)

    table = {}
    if not data:
        return bytes(out)
    ent = data[0]
    for c in data[1:]:
        key = (ent, c)
        if key in table:
            ent = table[key]
            continue
        put(ent)
        if free_ent < maxmax:
            table[key] = free_ent
            free_ent += 1
        ent = c
    put(ent)
    if off > 0:
        out.extend(buf[:(off + 7) // 8])
    return bytes(out)
