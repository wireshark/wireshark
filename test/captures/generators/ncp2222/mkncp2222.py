#!/usr/bin/env python3
# Generates test/captures/ncp2222_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
# Synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())

# ---- NCP function and subfunction tables (packet-ncp2222.c) ----
# packet-ncp2222.c is generated at build time from
# tools/dissector_generators/generate-ncp2222.py. This script loads that
# generator (pass its path as the second argument), walks its packet
# definitions and builds, for every NCP function and subfunction, a request
# and a reply whose fields follow the definition (made-up values). The
# frames are NCP over UDP 524. Records that the generator marks as
# depending on a request field (req_cond) are left out of the reply.
import importlib.util

GEN = os.path.join(SRCDIR, 'tools/dissector_generators/generate-ncp2222.py')

def load_generator(path):
    spec = importlib.util.spec_from_file_location('gen_ncp2222', path)
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    g.msg = open(os.devnull, 'w')
    g.compcode_lists = g.UniqueCollection('Completion Code Lists')
    g.ptvc_lists = g.UniqueCollection('PTVC Lists')
    g.define_errors()
    g.define_groups()
    g.define_ncp2222()
    return g

class Filler:
    def __init__(self, g, seed, mode=0):
        self.g = g
        self.seed = seed
        self.mode = mode          # 0: small values, 1: any value, 2: all bits set
    def rnd(self, n):
        self.seed = (self.seed * 1103515245 + 12345) & 0x7fffffff
        return (self.seed >> 8) % n

    def num(self, nbytes, endian, small):
        if self.mode == 2:
            return b'\xff' * nbytes
        if self.mode == 1:
            return bytes(self.rnd(256) for _ in range(nbytes))
        v = self.rnd(small)
        order = 'little' if endian == 1 else 'big'
        return v.to_bytes(nbytes, order)

    def build(self, records, vars_):
        '''records: generator record lists or PTVCRecord objects.'''
        g = self.g
        out = b''
        for r in records:
            if isinstance(r, list):
                field, length, endian, var, repeat, cond = r[2], r[1], r[3], r[4], r[5], r[6]
            else:
                field, length, endian, var, repeat, cond = r.field, r.length, r.endianness, r.var, r.repeat, r.req_cond
            if cond not in (None, -1, g.NO_REQ_COND):
                continue
            count = 1
            if repeat not in (None, -1):
                count = vars_.get(repeat, 1)
            for _ in range(count):
                out += self.one(field, length, endian, var, vars_)
        return out

    def one(self, field, length, endian, var, vars_):
        g = self.g
        if isinstance(field, g.struct):
            return self.build(field.list, vars_)
        if isinstance(field, g.nstring):
            n = 3 + self.rnd(5)
            n = min(n, 255 if field.Length() == 1 else 1000)
            s = (b'abcdefgh' * 3)[:n]
            return n.to_bytes(field.Length(), 'little' if endian == 1 else 'big') + s
        if isinstance(field, g.nbytes):
            n = 2 + self.rnd(5)
            return n.to_bytes(field.Length(), 'little' if endian == 1 else 'big') + bytes(self.rnd(256) for _ in range(n))
        if isinstance(field, g.stringz):
            n = length if isinstance(length, int) else (length[0] if isinstance(length, tuple) else 4)
            n = max(2, min(n, 6))
            return (b'name'[:n - 1] + b'x' * max(0, n - 5))[:n - 1] + b'\0'
        if isinstance(length, tuple):
            n = max(length[0], 1)
            if isinstance(field, g.fw_string):
                return (b'str' * 100)[:n]
            return bytes(self.rnd(4) for _ in range(n))
        if var not in (None, -1):
            vars_[var] = 1 + (self.mode == 1)
            return (vars_[var]).to_bytes(length, 'little' if endian == 1 else 'big')
        if isinstance(field, g.fw_string):
            return (b'file name ' * 40)[:length]
        if isinstance(field, g.CountingNumber) and length in (1, 2, 3, 4, 8):
            return self.num(length, endian, 4 if length > 1 else 3)
        if isinstance(field, g.bf_uint) or length in (1, 2, 3, 4, 8):
            return self.num(length, endian, 8)
        return bytes(self.rnd(3) for _ in range(length))

def ncp_request(conn, seq, task, func, sub, has_len, data):
    h = struct.pack('!HBBBB', 0x2222, seq, conn & 0xff, task, conn >> 8) + bytes([func])
    if sub is not None:
        h += (struct.pack('!H', len(data) + 1) if has_len else b'') + bytes([sub])
    return h + data

def ncp_reply(conn, seq, task, code, status, data):
    return struct.pack('!HBBBB', 0x3333, seq, conn & 0xff, task, conn >> 8) + bytes([code, status]) + data

def generate(g, mode=0):
    '''Returns [(code, name, pkt, func, sub, request data, reply data)].'''
    out = []
    n = 0
    for pkt in g.packets:
        code = pkt.FunctionCode()
        func = pkt.FunctionCode('high')
        sub = pkt.FunctionCode('low') if pkt.HasSubFunction() else None
        f = Filler(g, code * 7 + 1 + mode * 977, mode)
        req = f.build(pkt.request_records or [], {})
        rep = f.build(pkt.reply_records or [], {})
        out.append((code, pkt.Description(), pkt, func, sub, req, rep))
    return out

# Definitions whose generated request or reply the dissector reports as malformed
# (the generated values do not satisfy a length or condition); they go to the
# malformed capture instead of the main one. Keys are (variant, function code).
BAD = set()
for _mode, _codes in {
    0: [
        0x3f, 0x1625, 0x1633, 0x1634, 0x1635, 0x5701, 0x5703, 0x5706, 0x570c, 0x5710,
        0x5713, 0x5714, 0x5719, 0x571d, 0x571e, 0x571f, 0x5720, 0x5721, 0x5728, 0x5729,
        0x5747, 0x5901, 0x5903, 0x5906, 0x590c, 0x5910, 0x5913, 0x5914, 0x5919, 0x591d,
        0x591e, 0x5920, 0x5921, 0x5928, 0x5c01, 0x5c02, 0x5e01, 0x5e02, 0x6801, 0x6802,
        0x7b0b, 0x7b0e, 0x7b11, 0x7b23, 0x7b3e,
    ],
    1: [
        0x3f, 0x1625, 0x1633, 0x1635, 0x1720, 0x5701, 0x5703, 0x5706, 0x570c, 0x5710,
        0x5713, 0x5714, 0x5719, 0x571d, 0x571e, 0x5720, 0x5721, 0x5728, 0x5901, 0x5903,
        0x5906, 0x590c, 0x5910, 0x5913, 0x5914, 0x5919, 0x591d, 0x591e, 0x5920, 0x5921,
        0x5928, 0x5c01, 0x5c02, 0x5e01, 0x5e02, 0x6801, 0x6802, 0x7b0b, 0x7b0e, 0x7b10,
        0x7b11, 0x7b23,
    ],
    2: [
        0x3f, 0x1625, 0x1633, 0x1635, 0x1720, 0x5701, 0x5703, 0x5706, 0x570c, 0x5710,
        0x5713, 0x5714, 0x5719, 0x571d, 0x571e, 0x5720, 0x5721, 0x5728, 0x5901, 0x5903,
        0x5906, 0x590c, 0x5910, 0x5913, 0x5914, 0x5919, 0x591d, 0x591e, 0x5920, 0x5921,
        0x5928, 0x5c01, 0x5c02, 0x5e01, 0x5e02, 0x6801, 0x6802, 0x7b0b, 0x7b0e, 0x7b10,
        0x7b11, 0x7b23,
    ],
    3: [
        0x1, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0x12, 0x13,
        0x14, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x21, 0x25, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
        0x4f, 0x54, 0x55, 0x5b, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x69, 0x6a,
        0x6b, 0x6c, 0x6d, 0x6e, 0x70, 0x1100, 0x1101, 0x1102, 0x1103, 0x1106, 0x1109,
        0x110a, 0x1500, 0x1501, 0x1502, 0x1503, 0x1509, 0x150a, 0x150b, 0x1601, 0x1602,
        0x1603, 0x1605, 0x1606, 0x160c, 0x1611, 0x1612, 0x1613, 0x1614, 0x1615, 0x1616,
        0x1617, 0x1618, 0x1619, 0x161a, 0x161b, 0x161c, 0x161d, 0x161e, 0x161f, 0x1620,
        0x1622, 0x1623, 0x1625, 0x1626, 0x1628, 0x1629, 0x162a, 0x162b, 0x162c, 0x162d,
        0x162e, 0x162f, 0x1630, 0x1631, 0x1632, 0x1633, 0x1634, 0x1635, 0x1637, 0x1638,
        0x163a, 0x1702, 0x1703, 0x1705, 0x1707, 0x170e, 0x170f, 0x1710, 0x1711, 0x1712,
        0x1713, 0x1715, 0x1716, 0x1717, 0x171a, 0x171b, 0x171c, 0x171e, 0x171f, 0x1720,
        0x1721, 0x1722, 0x1735, 0x1736, 0x1737, 0x173c, 0x173d, 0x1746, 0x1747, 0x1748,
        0x1749, 0x174a, 0x174b, 0x174c, 0x1764, 0x1766, 0x1768, 0x176b, 0x176c, 0x176d,
        0x176e, 0x1771, 0x1773, 0x1774, 0x1776, 0x1778, 0x1779, 0x177a, 0x177c, 0x177d,
        0x1781, 0x1784, 0x1785, 0x1786, 0x1787, 0x1788, 0x1789, 0x178a, 0x1796, 0x17c8,
        0x17c9, 0x17ca, 0x17cb, 0x17cc, 0x17cd, 0x17cf, 0x17d0, 0x17d4, 0x17d5, 0x17d6,
        0x17d7, 0x17d8, 0x17d9, 0x17db, 0x17dc, 0x17dd, 0x17de, 0x17df, 0x17e0, 0x17e1,
        0x17e2, 0x17e3, 0x17e5, 0x17e6, 0x17e7, 0x17e8, 0x17e9, 0x17ea, 0x17eb, 0x17ec,
        0x17ed, 0x17ee, 0x17ef, 0x17f0, 0x17f1, 0x17f2, 0x17f3, 0x17f4, 0x2000, 0x2001,
        0x2002, 0x2003, 0x2004, 0x2200, 0x2201, 0x2202, 0x2203, 0x2204, 0x2205, 0x2207,
        0x2208, 0x2209, 0x220a, 0x2301, 0x2302, 0x2303, 0x2304, 0x2305, 0x2306, 0x2307,
        0x2308, 0x2309, 0x230a, 0x230b, 0x230c, 0x230d, 0x230e, 0x230f, 0x2310, 0x2311,
        0x2312, 0x2313, 0x2400, 0x2401, 0x2402, 0x2403, 0x2404, 0x2405, 0x2406, 0x5601,
        0x5602, 0x5603, 0x5604, 0x5605, 0x5701, 0x5702, 0x5703, 0x5704, 0x5705, 0x5706,
        0x5707, 0x5708, 0x5709, 0x570a, 0x570b, 0x570c, 0x5710, 0x5711, 0x5712, 0x5713,
        0x5714, 0x5715, 0x5716, 0x5717, 0x5718, 0x5719, 0x571a, 0x571b, 0x571c, 0x571d,
        0x571e, 0x571f, 0x5720, 0x5721, 0x5722, 0x5723, 0x5724, 0x5725, 0x5726, 0x5727,
        0x5728, 0x5729, 0x572a, 0x572b, 0x572c, 0x5740, 0x5741, 0x5742, 0x5743, 0x5744,
        0x5745, 0x5746, 0x5747, 0x5748, 0x5749, 0x5801, 0x5802, 0x5803, 0x5804, 0x5805,
        0x5806, 0x5807, 0x5808, 0x5809, 0x580a, 0x580b, 0x580d, 0x580e, 0x580f, 0x5810,
        0x5811, 0x5812, 0x5813, 0x5814, 0x5816, 0x5817, 0x5818, 0x5819, 0x581a, 0x581e,
        0x581f, 0x5901, 0x5902, 0x5903, 0x5904, 0x5905, 0x5906, 0x5907, 0x5908, 0x5909,
        0x590a, 0x590b, 0x590c, 0x5910, 0x5911, 0x5913, 0x5914, 0x5916, 0x5919, 0x591c,
        0x591d, 0x591e, 0x5920, 0x5921, 0x5923, 0x5927, 0x5928, 0x5929, 0x5932, 0x5934,
        0x5935, 0x5936, 0x5947, 0x5a00, 0x5a0a, 0x5a0b, 0x5a0c, 0x5a80, 0x5a81, 0x5a82,
        0x5a83, 0x5a84, 0x5a85, 0x5a86, 0x5a87, 0x5a88, 0x5a96, 0x5c01, 0x5c02, 0x5c03,
        0x5c04, 0x5c05, 0x5c06, 0x5c07, 0x5c08, 0x5c09, 0x5c0a, 0x5e01, 0x5e02, 0x5e03,
        0x6801, 0x6802, 0x6804, 0x6808, 0x68c8, 0x6f00, 0x6f01, 0x6f02, 0x6f03, 0x6f04,
        0x7201, 0x7202, 0x7205, 0x7206, 0x720c, 0x7b01, 0x7b02, 0x7b03, 0x7b04, 0x7b05,
        0x7b06, 0x7b07, 0x7b08, 0x7b09, 0x7b0a, 0x7b0b, 0x7b0c, 0x7b0d, 0x7b0e, 0x7b0f,
        0x7b10, 0x7b11, 0x7b14, 0x7b15, 0x7b16, 0x7b17, 0x7b18, 0x7b19, 0x7b1a, 0x7b1b,
        0x7b1e, 0x7b1f, 0x7b20, 0x7b21, 0x7b22, 0x7b23, 0x7b28, 0x7b29, 0x7b2a, 0x7b2b,
        0x7b2c, 0x7b2d, 0x7b2e, 0x7b2f, 0x7b32, 0x7b33, 0x7b34, 0x7b35, 0x7b36, 0x7b37,
        0x7b38, 0x7b3c, 0x7b3d, 0x7b3e, 0x7b46, 0x7b47, 0x7b48, 0x8301, 0x8302, 0x8303,
        0x8304, 0x8305, 0x8306, 0x8307,
    ],
}.items():
    BAD.update((_mode, _c) for _c in _codes)

def frames_for(items, mode, want_bad=False):
    frames = []
    conn, seq = 3 + mode, 0
    for code, name, pkt, func, sub, req, rep in items:
        if ((mode, code) in BAD) != want_bad:
            continue
        seq = (seq + 1) & 0xff
        sport = 1024 + (code & 0x3ff)
        cc = 0
        if mode == 3:
            # error reply: the completion code is the last one the definition lists
            codes = [c for c in (pkt.codes.list if pkt.codes else []) if c != 0]
            cc = (codes[-1] & 0xff) if codes else 0xff
            rep = b''
        frames.append(udp(A, B, sport, 524, ncp_request(conn, seq, 1, func, sub, pkt.HasLength(), req)))
        frames.append(udp(B, A, 524, sport, ncp_reply(conn, seq, 1, cc, 0, rep), 1, 2))
    return frames

# ---- NDS over NCP (func 0x68): ping and fragmented requests of every verb ----
# Each verb gets a request with the given protocol version in its first
# dword and zeros after, and a reply that is zeros after a tag dword. The
# decoding is driven by the verb remembered from the request, so every
# verb's decoding runs on the minimal data. Frames the dissector reports as
# malformed (a count or length that is zero where a field must be non-zero)
# go to the malformed capture (NDS_BAD).
def nds_request(verb, body, flags=0, seq=1, conn=40, version_byte=0):
    pre = struct.pack('<IIIHHII', 0xffffffff, 0, 0, 0, flags, verb, 0x10000)
    data = bytes([0x68, 2]) + pre + body
    data = data[:2] + struct.pack('<III', 0xffffffff, len(data) - 6, len(data) - 6) + data[14:]
    return struct.pack('!HBBBB', 0x2222, seq, conn & 0xff, 1, conn >> 8) + data

def nds_reply(body, code=0, seq=1, conn=40, handle=0xffffffff):
    data = struct.pack('<IIi', len(body) + 8, handle, code) + body
    return struct.pack('!HBBBB', 0x3333, seq, conn & 0xff, 1, conn >> 8) + bytes([0, 0]) + data

def nds_frames(want_bad):
    frames = []
    conn = 40
    seq = 0
    def pair(req, rep, sport):
        nonlocal seq
        frames.append(udp(A, B, sport, 524, req))
        frames.append(udp(B, A, 524, sport, rep, 1, 2))
    def key_ok(key):
        return (key in NDS_BAD) == want_bad
    # ping for NDS: version, flags; reply with the tree name (version 9) or flags
    for n, (flags, rver) in enumerate([(1, 8), (0xffff, 8), (0, 8), (0x0f, 9)]):
        key = ('ping', n)
        if not key_ok(key):
            continue
        seq = (seq + 1) & 0xff
        req = struct.pack('!HBBBB', 0x2222, seq, conn & 0xff, 1, 0) + bytes([0x68, 1]) + struct.pack('<II', 1, flags)
        if rver == 9:
            name = b'TREE_NAME'
            body = bytes([9]) + struct.pack('!I', len(name)) + b'\0' * 3 + name + struct.pack('!II', 3, 4) + struct.pack('<I', 5)
        else:
            body = bytes([rver, 0, 0, 0]) + struct.pack('<IIHH', 0, 0, 0xffff, 0xffff)
        rep = struct.pack('!HBBBB', 0x3333, seq, conn & 0xff, 1, 0) + bytes([0, 0]) + body
        pair(req, rep, 3000 + n)
    def fill(pattern, n):
        if pattern == 'zero':
            return bytes(n)
        if pattern == 'one':
            return struct.pack('<I', 1) * (n // 4)
        return b''.join(struct.pack('<I', i & 3) for i in range(n // 4))
    for verb in range(1, 112):
        for pattern, version, tag in [('zero', 0, 0), ('zero', 1, 1), ('zero', 2, 2), ('zero', 0, 3),
                                     ('zero', 0, 4), ('zero', 0, 6)] + [(p, v, v) for p in ('one', 'seq') for v in (0, 1, 2)]:
            if verb != 1 and pattern == 'zero' and tag > 2:
                continue
            key = (verb, version, tag) if pattern == 'zero' else (verb, version, tag, pattern)
            if not key_ok(key):
                continue
            seq = (seq + 1) & 0xff
            body = struct.pack('<I', version) + fill(pattern, 120)
            req = nds_request(verb, body, 0, seq, conn)
            rep = nds_reply(struct.pack('<I', tag) + fill(pattern, 120), 0, seq, conn)
            pair(req, rep, 4000 + verb)
    return frames

NDS_BAD = {
    (1, 0, 0, 'one'), (1, 1, 1, 'one'), (1, 2, 2, 'one'), (1, 2, 2, 'seq'), (3, 0, 0, 'one'),
    (3, 1, 1, 'one'), (3, 2, 2, 'one'), (4, 0, 0, 'one'), (4, 1, 1, 'one'), (4, 1, 1, 'seq'),
    (4, 2, 2, 'one'), (5, 1, 1, 'one'), (5, 2, 2, 'one'), (5, 2, 2, 'seq'), (7, 0, 0, 'one'),
    (7, 1, 1, 'one'), (7, 1, 1, 'seq'), (7, 2, 2, 'one'), (7, 2, 2, 'seq'), (9, 0, 0, 'seq'),
    (9, 1, 1, 'seq'), (9, 2, 2, 'seq'), (11, 0, 0, 'one'), (11, 0, 0, 'seq'), (11, 1, 1, 'one'),
    (11, 1, 1, 'seq'), (11, 2, 2, 'one'), (11, 2, 2, 'seq'), (15, 0, 0, 'seq'),
    (15, 1, 1, 'seq'), (15, 2, 2, 'seq'), (19, 0, 0, 'one'), (19, 0, 0, 'seq'),
    (19, 1, 1, 'one'), (19, 1, 1, 'seq'), (19, 2, 2, 'one'), (19, 2, 2, 'seq'),
    (42, 0, 0, 'one'), (42, 1, 1, 'one'), (42, 2, 2, 'one'), (43, 0, 0, 'one'),
    (43, 0, 0, 'seq'), (43, 1, 1, 'one'), (43, 1, 1, 'seq'), (43, 2, 2, 'one'),
    (43, 2, 2, 'seq'), (53, 1, 1, 'one'), (53, 1, 1, 'seq'), (110, 0, 0, 'one'),
    (110, 0, 0, 'seq'), (110, 1, 1, 'one'), (110, 1, 1, 'seq'), (110, 2, 2, 'one'),
    (110, 2, 2, 'seq'), ('ping', 1),
}

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    g = load_generator(sys.argv[2] if len(sys.argv) > 2 else GEN)
    main, bad = [], []
    for mode in (0, 1, 2, 3):
        items = generate(g, mode if mode < 3 else 0)
        main += frames_for(items, mode)
        bad += frames_for(items, mode, True)
    main += nds_frames(False)
    bad += nds_frames(True)
    print(len(main), 'frames,', len(bad), 'malformed frames')
    write_pcap(os.path.join(out, 'ncp2222-coverage.pcap'), main)
    write_pcap(os.path.join(out, 'ncp2222-coverage-malformed.pcap'), bad)
    gz(os.path.join(out, 'ncp2222-coverage.pcap'))
    os.rename(os.path.join(out, 'ncp2222-coverage.pcap.gz'), os.path.join(out, 'ncp2222_coverage.pcap.gz'))
