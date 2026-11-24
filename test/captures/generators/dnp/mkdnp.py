#!/usr/bin/env python3
# Generates test/captures/dnp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build synthetic DNP 3.0 captures for the packet-dnp.c coverage test.

Usage: mkdnp.py <outdir>

Writes dnp-coverage.pcap (clean) and dnp-coverage-malformed.pcap.
Every packet is built with struct; nothing comes from a real network.
Addresses are from 192.0.2.0/24 (TEST-NET-1) and 02:00:00:... MACs.
"""
import os
import struct
import sys

# ---------------------------------------------------------------- framing

def dnp_crc(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xffff


def dnp_link(dl_dst, dl_src, user, ctl, length=None, bad_crc=False):
    """One DNP3 link frame; user = transport byte + AL bytes (<= 250)."""
    assert len(user) <= 250
    if length is None:
        length = 5 + len(user)
    hdr = struct.pack('<BBBBHH', 0x05, 0x64, length, ctl, dl_dst, dl_src)
    out = hdr + struct.pack('<H', dnp_crc(hdr))
    for i in range(0, len(user), 16):
        chunk = user[i:i + 16]
        crc = dnp_crc(chunk) ^ (0x5555 if bad_crc else 0)
        out += chunk + struct.pack('<H', crc)
    return out


def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


MAC = {1: bytes.fromhex('020000000001'), 2: bytes.fromhex('020000000002'),
       3: bytes.fromhex('020000000003')}


def ip_frame(proto, payload, src, dst):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64,
                     proto, 0, bytes([192, 0, 2, src]), bytes([192, 0, 2, dst]))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return MAC[dst] + MAC[src] + b'\x08\x00' + ip + payload


def udp_frame(payload, src=1, dst=2, sport=20000, dport=20000):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ip_frame(17, udp, src, dst)


class Tcp:
    """A TCP connection between 192.0.2.<c> and 192.0.2.<s>."""

    def __init__(self, frames, c, s, cport, sport=20000):
        self.frames = frames
        self.c, self.s, self.cport, self.sport = c, s, cport, sport
        self.seq = {c: 1000, s: 5000}
        self.seg(c, b'', 0x02)
        self.seq[c] += 1
        self.seg(s, b'', 0x12)
        self.seq[s] += 1
        self.seg(c, b'', 0x10)

    def seg(self, frm, data, flags=0x18):
        to = self.s if frm == self.c else self.c
        sp, dp = (self.cport, self.sport) if frm == self.c else (self.sport, self.cport)
        ack = self.seq[to] if flags != 0x02 else 0
        opts = struct.pack('!BBH', 2, 4, 1460) if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[frm], ack,
                          (5 + len(opts) // 4) << 4, flags, 8192, 0, 0) + opts
        pseudo = struct.pack('!4s4sBBH', bytes([192, 0, 2, frm]),
                             bytes([192, 0, 2, to]), 0, 6, len(tcp) + len(data))
        cs = _csum(pseudo + tcp + data)
        tcp = tcp[:16] + struct.pack('!H', cs) + tcp[18:]
        self.frames.append(ip_frame(6, tcp + data, frm, to))
        self.seq[frm] += len(data)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ------------------------------------------------------------ app layer

FIR, FIN, CON, UNS = 0x80, 0x40, 0x20, 0x10
MASTER, OUTST, OUTST2, OUTST3 = 1, 1024, 1025, 1026
TS = 1700000000123          # milliseconds since 1970, 48 bits


def ts48(ms=TS):
    return struct.pack('<Q', ms)[:6]


def obj(g, v, qual, rng=b'', data=b''):
    return bytes([g, v, qual]) + rng + data


def u8(*v):
    return bytes(v)


def le16(*v):
    return b''.join(struct.pack('<H', x) for x in v)


def le32(*v):
    return b''.join(struct.pack('<I', x & 0xffffffff) for x in v)


def i32(v):
    return struct.pack('<i', v)


def i16(v):
    return struct.pack('<h', v)


def flt(v):
    return struct.pack('<f', v)


def dbl(v):
    return struct.pack('<d', v)


def req(func, objs=b'', seq=0, ctl=FIR | FIN):
    return bytes([ctl | (seq & 0x0f), func]) + objs


def rsp(objs=b'', seq=0, iin=0x0000, func=0x81, ctl=FIR | FIN):
    return bytes([ctl | (seq & 0x0f), func]) + struct.pack('>H', iin) + objs


class Link:
    """Sends AL messages over DNP3 link frames, one UDP datagram per frame
    (or appended to a list of link frames for TCP)."""

    def __init__(self):
        self.tr_seq = {}

    def segments(self, al, dl_dst, dl_src, ctl, seq=None, seg_size=249):
        key = (dl_dst, dl_src)
        s = self.tr_seq.get(key, 0) if seq is None else seq
        out = []
        parts = [al[i:i + seg_size] for i in range(0, len(al), seg_size)] or [b'']
        for n, part in enumerate(parts):
            tr = (s & 0x3f) | (0x40 if n == 0 else 0) | (0x80 if n == len(parts) - 1 else 0)
            out.append(dnp_link(dl_dst, dl_src, bytes([tr]) + part, ctl))
            s += 1
        self.tr_seq[key] = s & 0x3f
        return out


# ---------------------------------------------------------- the capture

def build_main():
    frames = []
    L = Link()
    names = []          # (frame number, description) for the README

    def note(text):
        names.append((len(frames) + 1, text))

    def m2o(al, ctl=0xC4, dst=OUTST, seq=None, src_ip=1, dst_ip=2):
        for f in L.segments(al, dst, MASTER, ctl, seq):
            frames.append(udp_frame(f, src_ip, dst_ip))

    def o2m(al, ctl=0x44, src=OUTST, seq=None, src_ip=2, dst_ip=1, seg_size=249):
        for f in L.segments(al, MASTER, src, ctl, seq, seg_size):
            frames.append(udp_frame(f, src_ip, dst_ip))

    def link_only(ctl, dst, src, frm=1, to=2):
        frames.append(udp_frame(dnp_link(dst, src, b'', ctl), frm, to))

    # --- Link layer only (no transport/application data)
    note('link layer: request link status, status of link, reset link, ACK')
    link_only(0xC9, OUTST, MASTER)                  # PRM DIR request link status
    link_only(0x0B, MASTER, OUTST, 2, 1)            # secondary status of link
    link_only(0xC0, OUTST, MASTER)                  # reset link states
    link_only(0x30, MASTER, OUTST, 2, 1)            # secondary ACK with RES and DFC
    # Link functions that carry user data
    note('link layer: test link (FCB, FCV), confirmed user data, unknown primary function, '
         'NACK, no function, not implemented, unknown secondary function, each with a CONFIRM')
    m2o(req(0x00), ctl=0xF2)                        # test link function, FCB FCV
    m2o(req(0x00), ctl=0xD3)                        # confirmed user data, FCV
    m2o(req(0x00), ctl=0xC5)                        # unknown primary function 5
    o2m(req(0x00), ctl=0x21)                        # NACK, RES
    o2m(req(0x00), ctl=0x1E)                        # no function, DFC
    o2m(req(0x00), ctl=0x0F)                        # not implemented
    o2m(req(0x00), ctl=0x07)                        # unknown secondary function

    # --- READ requests
    note('READ: class 0-3, class 1 and 3 only, specific objects by every range type, '
         'prefixed indices, device attributes, octet strings')
    m2o(req(0x01, obj(60, 1, 0x06) + obj(60, 2, 0x06) + obj(60, 3, 0x06) + obj(60, 4, 0x06), 1))
    m2o(req(0x01, obj(60, 2, 0x06) + obj(60, 4, 0x07, u8(5)), 2))
    m2o(req(0x01, obj(1, 0, 0x06) + obj(2, 0, 0x07, u8(10)) + obj(3, 0, 0x08, le16(10))
            + obj(4, 0, 0x09, le32(10)) + obj(10, 0, 0x00, u8(0, 7))
            + obj(20, 0, 0x01, le16(0, 3)) + obj(30, 0, 0x02, le32(0, 3))
            + obj(40, 0, 0x03, u8(2)) + obj(21, 0, 0x04, le16(2))
            + obj(22, 0, 0x05, le32(2)) + obj(32, 0, 0x0B, u8(1)), 3))
    m2o(req(0x01, obj(1, 2, 0x17, u8(2), u8(3, 5)) + obj(30, 1, 0x28, le16(2), le16(1, 260))
            + obj(20, 1, 0x39, le32(1), le32(70000)) + obj(0, 254, 0x06)
            + obj(110, 0, 0x06) + obj(111, 0, 0x07, u8(2)) + obj(50, 1, 0x07, u8(1))
            + obj(34, 0, 0x06) + obj(42, 0, 0x06) + obj(11, 0, 0x06), 4))
    # header only, but with object size prefixes: the objects are dissected
    m2o(req(0x01, obj(70, 5, 0x5B, u8(1), le16(8) + le32(0x11223344) + le32(1)), 5))
    note('READ of an object the read value string does not know (warning)')
    m2o(req(0x01, obj(85, 1, 0x06), 6))

    # --- WRITE
    note('WRITE: clear the restart IIN, set time and date, IIN bits 8-15, '
         'octet strings with index prefixes, file transport')
    m2o(req(0x02, obj(80, 1, 0x00, u8(7, 7), u8(0)), 7))
    m2o(req(0x02, obj(50, 1, 0x07, u8(1), ts48()), 8))
    m2o(req(0x02, obj(80, 1, 0x00, u8(8, 15), u8(0x5a)), 9))
    m2o(req(0x02, obj(110, 4, 0x17, u8(2), u8(1) + b'ABCD' + u8(2) + b'WXYZ')
            + obj(70, 5, 0x5B, u8(1), le16(12) + le32(0x01020304) + le32(0x80000000) + b'data'), 10))

    # --- control: SELECT, OPERATE, DIRECT OPERATE, DIRECT OPERATE NO ACK
    note('SELECT/OPERATE/DIRECT OPERATE (NO ACK): CROBs with every operation and '
         'trip/close code, pattern control block and mask, analog output blocks')
    crob = (le16(0) + u8(0x41, 1) + le32(100, 200) + u8(0)
            + le16(1) + u8(0x81, 2) + le32(300, 400) + u8(0)
            + le16(2) + u8(0x03, 1) + le32(0, 0) + u8(0)
            + le16(3) + u8(0x04, 1) + le32(0, 0) + u8(0)
            + le16(4) + u8(0x20, 1) + le32(0, 0) + u8(0)
            + le16(5) + u8(0xCF, 1) + le32(0, 0) + u8(0))
    m2o(req(0x03, obj(12, 1, 0x28, le16(6), crob), 11))
    m2o(req(0x04, obj(12, 1, 0x28, le16(6), crob), 12))
    m2o(req(0x05, obj(12, 2, 0x07, u8(1), u8(0x11, 1) + le32(10, 20) + u8(0))
            + obj(12, 3, 0x00, u8(0, 9), u8(0xA5, 0x02)), 13))
    m2o(req(0x06, obj(41, 1, 0x17, u8(1), u8(0) + i32(-123456) + u8(0))
            + obj(41, 2, 0x17, u8(1), u8(1) + i16(-1234) + u8(0))
            + obj(41, 3, 0x28, le16(1), le16(2) + flt(1.5) + u8(0))
            + obj(41, 4, 0x39, le32(1), le32(3) + dbl(-2.25) + u8(0)), 14))

    # --- freeze and other requests without objects
    note('freeze requests, restarts and other functions without object dissection, '
         'spontaneous message enable/disable, delay measurement, unknown function')
    for n, fc in enumerate((0x07, 0x08, 0x09, 0x0A)):
        m2o(req(fc, obj(20, 0, 0x06) + obj(21, 0, 0x00, u8(0, 3)), n))
    m2o(req(0x0B, obj(50, 2, 0x07, u8(1), ts48() + le32(1000)) + obj(20, 0, 0x06), 4))
    for n, fc in enumerate((0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x16, 0x18,
                            0x1C, 0x1D, 0x1E, 0x1F)):
        m2o(req(fc, b'', 5 + n))
    m2o(req(0x14, obj(60, 2, 0x06) + obj(60, 3, 0x06) + obj(60, 4, 0x06), 3))
    m2o(req(0x15, obj(60, 2, 0x06), 4))
    m2o(req(0x17, b'', 5))
    m2o(req(0x50, u8(1, 2, 3), 6))

    # --- file functions
    note('OPEN FILE (write, read, append modes), CLOSE FILE, DELETE FILE')
    def fcmd(mode, name, perms=0x01ff, size=1024):
        body = (le16(26) + le16(len(name)) + ts48() + le16(perms) + le32(0xdeadbeef)
                + le32(size) + le16(mode) + le16(512) + le16(7) + name)
        return obj(70, 3, 0x5B, u8(1), le16(len(body)) + body)
    m2o(req(0x19, fcmd(2, b'/tmp/cfg.txt'), 7))
    m2o(req(0x19, fcmd(1, b'/tmp/log.txt'), 8))
    m2o(req(0x19, fcmd(3, b''), 9))
    m2o(req(0x1A, obj(70, 4, 0x5B, u8(1), le16(13) + le32(0x01020304) + le32(0)
                      + le16(512) + le16(7) + u8(0)), 10))
    m2o(req(0x1B, fcmd(0, b'/tmp/old.txt'), 11))

    # --- CONFIRM with an object, authentication functions (error object only)
    note('CONFIRM with an object; Authentication Request/Error with an Authentication '
         'Error object (no key or MAC data)')
    m2o(req(0x00, obj(60, 1, 0x06), 12))
    autherr = le32(1) + le16(1) + le16(2) + u8(5) + ts48()
    m2o(req(0x20, obj(120, 7, 0x5B, u8(1), le16(len(autherr)) + autherr), 13))
    m2o(req(0x21, obj(120, 7, 0x5B, u8(1), le16(len(autherr)) + autherr), 14))

    # --- responses
    note('RESPONSE without objects, all IIN bits, Authentication Response without objects')
    o2m(rsp(b'', 0, 0x0000))
    o2m(rsp(b'', 1, 0xFF3F))           # all IIN bits (abnormal IIN: warning)
    o2m(rsp(b'', 2, 0x9000, func=0x83))

    note('RESPONSE: binary and double-bit inputs and events, every quality flag, CTO and '
         'relative time')
    bi = (obj(1, 1, 0x00, u8(0, 9), u8(0xA5, 0x02))                   # packed bits
          + obj(1, 1, 0x17, u8(2), u8(3, 1, 9, 0))                    # bits with indices
          + obj(1, 2, 0x01, le16(0, 1), u8(0x81, 0x7E))
          + obj(2, 1, 0x17, u8(2), u8(3, 0xA1, 4, 0x00))
          + obj(2, 2, 0x28, le16(1), le16(5) + u8(0x81) + ts48())
          + obj(51, 1, 0x07, u8(1), ts48())
          + obj(2, 3, 0x17, u8(1), u8(6, 0x81) + le16(1500))
          + obj(3, 1, 0x00, u8(0, 4), u8(0xE4, 0x03))
          + obj(3, 2, 0x00, u8(0, 3), u8(0x01, 0x41, 0x81, 0xFF))
          + obj(4, 1, 0x17, u8(1), u8(1, 0x41))
          + obj(4, 2, 0x17, u8(1), u8(2, 0x81) + ts48())
          + obj(51, 2, 0x07, u8(1), ts48(TS + 1000))
          + obj(4, 3, 0x17, u8(1), u8(3, 0xC1) + le16(25)))
    o2m(rsp(bi, 3))

    note('RESPONSE: binary outputs, output events, command events, CROB echo')
    bo = (obj(10, 1, 0x00, u8(0, 7), u8(0x96))
          + obj(10, 2, 0x00, u8(0, 1), u8(0x81, 0x7F))
          + obj(11, 1, 0x17, u8(1), u8(0, 0x81))
          + obj(11, 2, 0x17, u8(1), u8(1, 0x01) + ts48())
          + obj(13, 1, 0x17, u8(1), u8(0, 0x80))
          + obj(13, 2, 0x17, u8(1), u8(1, 0x04) + ts48())
          + obj(12, 1, 0x28, le16(1), le16(0) + u8(0x41, 1) + le32(100, 200) + u8(4)))
    o2m(rsp(bo, 4))

    note('RESPONSE: every counter and frozen counter variation and their events '
         '(multi-segment, reassembled)')
    ctr = b''
    for v in range(1, 9):              # g20
        flags = v in (1, 2, 3, 4)
        val = le32(70000 + v) if v % 2 else le16(v)
        ctr += obj(20, v, 0x00, u8(0, 0), (u8(0xFF) if flags else b'') + val)
    for v in range(1, 13):             # g21
        flags = v <= 8
        val = le32(80000 + v) if v % 2 else le16(v)
        t = ts48() if 5 <= v <= 8 else b''
        ctr += obj(21, v, 0x00, u8(1, 1), (u8(0x61) if flags else b'') + val + t)
    for g in (22, 23):
        for v in range(1, 9):
            val = le32(90000 + v) if v % 2 else le16(v)
            t = ts48() if v >= 5 else b''
            ctr += obj(g, v, 0x28, le16(1), le16(v) + u8(0x01) + val + t)
    o2m(rsp(ctr, 5))

    note('RESPONSE: every analog input, frozen analog, analog event and deadband variation '
         '(multi-segment, reassembled)')
    ai = b''
    def aval(v32, v16, kind):
        return {'32': i32(v32), '16': i16(v16), 'f': flt(2.5), 'd': dbl(-0.125)}[kind]
    g30 = {1: ('32', 1), 2: ('16', 1), 3: ('32', 0), 4: ('16', 0), 5: ('f', 1), 6: ('d', 1)}
    for v, (k, fl) in g30.items():
        ai += obj(30, v, 0x00, u8(0, 0), (u8(0x7F) if fl else b'') + aval(-5, -6, k))
    g31 = {1: ('32', 1, 0), 2: ('16', 1, 0), 3: ('32', 1, 1), 4: ('16', 1, 1),
           5: ('32', 0, 0), 6: ('16', 0, 0), 7: ('f', 1, 0), 8: ('d', 1, 0)}
    for v, (k, fl, t) in g31.items():
        ai += obj(31, v, 0x00, u8(2, 2), (u8(0x01) if fl else b'') + aval(7, 8, k)
                  + (ts48() if t else b''))
    gev = {1: ('32', 0), 2: ('16', 0), 3: ('32', 1), 4: ('16', 1),
           5: ('f', 0), 6: ('d', 0), 7: ('f', 1), 8: ('d', 1)}
    for g in (32, 33):
        for v, (k, t) in gev.items():
            ai += obj(g, v, 0x17, u8(1), u8(v) + u8(0x21) + aval(9, 10, k) + (ts48() if t else b''))
    ai += obj(34, 1, 0x00, u8(0, 0), le16(5))
    ai += obj(34, 2, 0x00, u8(0, 0), le32(6))
    ai += obj(34, 3, 0x00, u8(0, 0), flt(0.5))
    # every other range type: 32-bit start/stop, absolute addresses
    ai += obj(30, 2, 0x02, le32(10, 11), u8(1) + i16(1) + u8(1) + i16(2))
    ai += obj(30, 4, 0x03, u8(12), i16(3))
    ai += obj(30, 4, 0x04, le16(13), i16(4))
    ai += obj(30, 4, 0x05, le32(14), i16(5))
    o2m(rsp(ai, 6))

    note('RESPONSE: analog output status, output blocks, output events, '
         'command events')
    ao = b''
    for v, k in {1: '32', 2: '16', 3: 'f', 4: 'd'}.items():
        ao += obj(40, v, 0x00, u8(0, 0), u8(0xFF) + aval(-100, -200, k))
    for v, k in {1: '32', 2: '16', 3: 'f', 4: 'd'}.items():
        ao += obj(41, v, 0x17, u8(1), u8(v) + aval(300, 400, k) + u8(0))
    for v, (k, t) in gev.items():
        ao += obj(42, v, 0x28, le16(1), le16(v) + u8(0x01) + aval(11, 12, k) + (ts48() if t else b''))
    # g43: v1 and v3 have a 32-bit value (the dissector did not step past
    # it before "DNP3: Fix a loop on empty octet strings and two-pass
    # reassembly", see README)
    g43 = {1: u8(0) + i32(-100000), 2: u8(1) + i16(-2), 3: u8(2) + i32(300000) + ts48(), 4: u8(3) + i16(4) + ts48(),
           5: u8(4) + flt(5.5), 6: u8(5) + dbl(6.5), 7: u8(6) + flt(7.5) + ts48(),
           8: u8(7) + dbl(8.5) + ts48()}
    for v, body in g43.items():
        ao += obj(43, v, 0x17, u8(1), u8(v) + body)
    o2m(rsp(ao, 7))

    note('RESPONSE: time objects, IIN bits, octet strings, security statistics, '
         'authentication error')
    misc = (obj(50, 1, 0x07, u8(1), ts48())
            + obj(50, 3, 0x07, u8(1), ts48())
            + obj(52, 2, 0x07, u8(1), le16(250))
            + obj(80, 1, 0x00, u8(0, 15), u8(0x81, 0x40))
            + obj(110, 5, 0x00, u8(0, 1), b'hello' + b'world')
            + obj(111, 3, 0x28, le16(1), le16(4) + b'abc')
            + obj(121, 1, 0x00, u8(0, 1), u8(0x01) + le16(1) + le32(5) + u8(0x01) + le16(1) + le32(6))
            + obj(122, 1, 0x17, u8(1), u8(18, 0x01) + le16(1) + le32(7))
            + obj(122, 2, 0x28, le16(1), le16(30) + u8(0x01) + le16(1) + le32(8) + ts48())
            + obj(120, 7, 0x5B, u8(1), le16(len(autherr)) + autherr))
    o2m(rsp(misc, 8))
    o2m(rsp(obj(52, 2, 0x07, u8(1), le16(33)), 9))  # delay measurement reply

    note('RESPONSE: file status, file transport and transport status, with and '
         'without data; size prefixes of 1, 2 and 4 octets')
    fs = (obj(70, 4, 0x5B, u8(1), le16(18) + le32(0x01020304) + le32(4096) + le16(512)
              + le16(7) + u8(0) + b'ok!!!')
          + obj(70, 4, 0x4B, u8(1), u8(13) + le32(0x01020304) + le32(0) + le16(512)
                + le16(8) + u8(1))
          + obj(70, 5, 0x6B, u8(1), le32(13) + le32(0x01020304) + le32(0x80000001) + b'abcde')
          + obj(70, 5, 0x5B, u8(1), le16(8) + le32(0x01020304) + le32(2))
          + obj(70, 6, 0x5B, u8(1), le16(12) + le32(0x01020304) + le32(3) + u8(0) + b'end')
          + obj(70, 6, 0x5B, u8(1), le16(9) + le32(0x01020304) + le32(4) + u8(5)))
    o2m(rsp(fs, 10))

    note('RESPONSE: device attributes of every data type and length')
    def da(var, body):
        return obj(0, var, 0x00, u8(0, 0), body)
    dattr = (da(252, u8(1, 7) + b'Example')
             + da(250, u8(1, 4) + b'Unit')
             + da(239, u8(2, 1, 16))
             + da(238, u8(2, 2) + le16(1000))
             + da(240, u8(2, 4) + le32(2048))
             + da(204, u8(3, 1, 0xFE))
             + da(205, u8(3, 2) + i16(-300))
             + da(203, u8(3, 4) + i32(-70000))
             + da(206, u8(4, 4) + flt(12.75))
             + da(207, u8(4, 8) + dbl(-3.5))
             + da(201, u8(0))
             + da(200, u8(5))
             + da(199, u8(6))
             + da(198, u8(7))
             + da(197, u8(8))
             + da(196, u8(0xFE))
             + da(211, u8(0xFF))
             + da(249, u8(0x20))           # not a data type
             + da(248, u8(2, 3))           # UINT of length 3: only the length is taken
             + da(247, u8(3, 3))
             + da(246, u8(4, 2)))
    o2m(rsp(dattr, 11))
    note('RESPONSE: unknown group 0 variation (warning)')
    o2m(rsp(da(1, u8(1, 2) + b'xy'), 12))

    note('RESPONSE: objects that are named but not decoded, and an unknown object '
         '(warning): the rest of the message is shown as data')
    for n, (g, v) in enumerate(((50, 2), (52, 1), (85, 1), (86, 1), (86, 2), (86, 3),
                                (87, 1), (88, 1), (112, 4), (113, 4), (99, 9))):
        o2m(rsp(obj(g, v, 0x07, u8(1), b'\x01\x02\x03\x04'), 13 + n))

    note('UNSOLICITED RESPONSE with CON and UNS; CONFIRM with UNS')
    o2m(rsp(obj(2, 1, 0x17, u8(1), u8(0, 0x81)), 0, 0x0000, func=0x82,
            ctl=FIR | FIN | CON | UNS))
    m2o(req(0x00, b'', 0, ctl=FIR | FIN | UNS))

    note('READ with a 16-bit index prefix and 1-octet size prefix as a header only: '
         'no point values')
    m2o(req(0x01, obj(30, 1, 0x28, le16(1), le16(9)) + obj(110, 2, 0x17, u8(1), u8(4)), 15))

    # --- transport sequence numbers wrapping 62, 63, 0
    note('RESPONSE in three transport segments with sequence numbers 62, 63, 0 '
         '(reassembled across the wrap)')
    big = b''.join(obj(30, 5, 0x00, u8(i, i), u8(1) + flt(float(i))) for i in range(60))
    o2m(rsp(big, 0), seq=62)

    # --- interleaved multi-segment responses from two outstations behind one IP
    note('two new outstations (1026 and 1025) behind 192.0.2.2 send three-segment '
         'responses with the same transport sequence numbers, interleaved')
    r1 = rsp(b''.join(obj(20, 1, 0x00, u8(i, i), u8(1) + le32(1000 + i)) for i in range(60)), 1)
    r2 = rsp(b''.join(obj(20, 2, 0x00, u8(i, i), u8(1) + le16(2000 + i)) for i in range(90)), 1)
    s1 = L.segments(r1, MASTER, OUTST3, 0x44, 10)
    s2 = L.segments(r2, MASTER, OUTST2, 0x44, 10)
    for a, b in zip(s1, s2):
        frames.append(udp_frame(a, 2, 1))
        frames.append(udp_frame(b, 2, 1))

    # --- a series restarted by a new FIR, and an out of order segment
    note('a first segment whose series is never finished, a segment that goes back over '
         'the sequence wrap, then a complete message')
    part = rsp(big, 2)
    segs = L.segments(part, MASTER, OUTST, 0x44, 5)
    frames.append(udp_frame(segs[0], 2, 1))          # FIR, seq 5, never completed
    frames.append(udp_frame(dnp_link(MASTER, OUTST, bytes([40]) + part[249:300], 0x44), 2, 1))
    o2m(rsp(b'', 3), seq=6)

    # --- the two-pass reproducer: two messages, same TL seq, one datagram
    note('reproducer dnp_same_seq_2pdu: two messages from two masters with the same '
         'transport sequence number in one datagram')
    a = dnp_link(10, 1, bytes([0xC5]) + bytes([0xC0, 0x01, 0x3C, 0x02, 0x06]), 0xC4)
    b = dnp_link(20, 2, bytes([0xC5]) + bytes([0xC0, 0x0D]), 0xC4)
    frames.append(udp_frame(a + b))

    # --- several link frames in one datagram
    note('three link frames in one datagram: a CONFIRM, a status of link, a READ')
    frames.append(udp_frame(dnp_link(OUTST, MASTER, u8(0xC0) + req(0x00, b'', 1), 0xC4)
                            + dnp_link(MASTER, OUTST, b'', 0x0B)
                            + dnp_link(OUTST, MASTER, u8(0xC1) + req(0x01, obj(60, 1, 0x06), 2), 0xC4),
                            1, 2))

    # --- DNP3 over TCP: one message in two segments, two messages in one segment
    note('TCP port 20000: handshake, a READ split over two segments, two responses '
         'in one segment, a two-segment response')
    t = Tcp(frames, 3, 2, 40000)
    rd = L.segments(req(0x01, obj(60, 1, 0x06) + obj(1, 2, 0x00, u8(0, 7)), 3), OUTST, MASTER, 0xC4)[0]
    t.seg(3, rd[:7])
    t.seg(3, rd[7:])
    r_a = L.segments(rsp(obj(1, 2, 0x00, u8(0, 1), u8(0x81, 0x01)), 3), MASTER, OUTST, 0x44)[0]
    r_b = L.segments(rsp(b'', 4, 0x0100, func=0x82, ctl=FIR | FIN | UNS), MASTER, OUTST, 0x44)[0]
    t.seg(2, r_a + r_b)
    long = L.segments(rsp(big, 5), MASTER, OUTST, 0x44)
    for seg in long:
        t.seg(2, seg)
    t.seg(3, b'', 0x10)

    # --- the zero-length octet string reproducer (last frame)
    note('reproducer dnp_oct0_loop: g110v0 without a prefix and 2^31-1 items '
         '(Expert Info error "Zero-length octet string objects without a prefix")')
    al = bytes([0xC0, 0x81, 0x00, 0x00])
    al += bytes([0x6E, 0x00, 0x09]) + struct.pack('<I', 0x7FFFFFFF)
    frames.append(udp_frame(dnp_link(1, 1024, bytes([0xC0]) + al, 0xC4)))
    return frames, names


def build_malformed():
    frames = []
    L = Link()

    def m2o(al, ctl=0xC4, seq=None):
        for f in L.segments(al, OUTST, MASTER, ctl, seq):
            frames.append(udp_frame(f))

    def o2m(al, seq=None):
        for f in L.segments(al, MASTER, OUTST, 0x44, seq):
            frames.append(udp_frame(f, 2, 1))

    # reproducer dnp_file_size_wrap: g70v5 size 7 < fixed 8
    item = bytes([0x07]) + bytes.fromhex('11223344') + bytes.fromhex('01000080')
    o2m(rsp(bytes([0x46, 0x05, 0x47, 0x02]) + item + item))
    # g70v4 and g70v6 with sizes below the fixed part
    o2m(rsp(obj(70, 4, 0x4B, u8(1), u8(5) + bytes(13))))
    o2m(rsp(obj(70, 6, 0x4B, u8(1), u8(5) + bytes(9))))
    # negative number of items
    o2m(rsp(obj(30, 1, 0x00, u8(5, 2))))
    # items for an object that should be empty
    o2m(rsp(obj(1, 0, 0x07, u8(2))))
    # items that do not advance: g1v1 with no data and many items
    o2m(rsp(obj(1, 1, 0x08, le16(1000))))
    # octet string without data
    o2m(rsp(obj(110, 0, 0x07, u8(3))))
    # truncated objects (exceptions)
    o2m(rsp(obj(20, 1, 0x00, u8(0, 5), u8(1, 2))))
    o2m(rsp(obj(12, 1, 0x28, le16(1), le16(0) + u8(3))))
    o2m(rsp(obj(0, 252, 0x00, u8(0, 0), u8(1, 40) + b'short')))
    # bad data chunk CRC
    frames.append(udp_frame(dnp_link(OUTST, MASTER, u8(0xC0) + req(0x01, obj(60, 1, 0x06)), 0xC4,
                                     bad_crc=True)))
    # bad header CRC (not DNP3 by the port check)
    f = bytearray(dnp_link(OUTST, MASTER, u8(0xC0) + req(0x00), 0xC4))
    f[8] ^= 0xff
    frames.append(udp_frame(bytes(f)))
    # length below 5
    hdr = struct.pack('<BBBBHH', 0x05, 0x64, 4, 0xC4, OUTST, MASTER)
    frames.append(udp_frame(hdr + struct.pack('<H', dnp_crc(hdr))))
    # length 5 with a function that expects data
    frames.append(udp_frame(dnp_link(OUTST, MASTER, b'', 0xC3)))
    # length longer than the datagram
    frames.append(udp_frame(dnp_link(OUTST, MASTER, u8(0xC0) + req(0x01, obj(60, 1, 0x06)),
                                     0xC4, length=40)))
    # application layer of one octet
    frames.append(udp_frame(dnp_link(OUTST, MASTER, u8(0xC0, 0xC0), 0xC4)))
    # a response with an object header cut short
    o2m(rsp(u8(30, 1)))
    # file command cut short and a VSTR longer than the data
    o2m(rsp(obj(70, 3, 0x5B, u8(1), le16(40) + bytes(10))))
    # an unknown function with IIN-like data and a READ of a truncated range
    m2o(req(0x01, obj(30, 1, 0x01, u8(1))))
    # an unknown object with two items: the first takes the rest of the
    # message, the second throws
    o2m(rsp(obj(99, 9, 0x07, u8(2), b'\x01\x02\x03\x04')))
    # UDP and TCP port 20000 payloads that are not DNP3
    frames.append(udp_frame(b'\x06\x64\x05\xc4'))
    frames.append(udp_frame(b'\x05\x65\x05\xc4'))
    t = Tcp(frames, 3, 2, 40001)
    t.seg(3, b'GET / HTTP/1.0\r\n\r\n')
    # a non-FIR segment that matches no series, then FIN
    frames.append(udp_frame(dnp_link(OUTST, MASTER, u8(0x83) + req(0x00), 0xC4)))
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames, names = build_main()
    write_pcap(os.path.join(out, 'dnp-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'dnp-coverage-malformed.pcap'), build_malformed())
    if os.environ.get('DNP_LIST'):
        for n, text in names:
            print(n, text)
    print('main: %d frames, malformed: %d frames' % (len(frames), len(build_malformed())))


if __name__ == '__main__':
    main()
