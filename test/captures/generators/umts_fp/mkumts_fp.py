#!/usr/bin/env python3
# Generates the umts_fp captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic UMTS FP (packet-umts_fp.c) coverage captures.

Usage: mkumts_fp.py <outdir>
Writes umts_fp-coverage.pcapng (+ -malformed), umts_fp-pi-coverage.pcapng and
the DCT2000 logs umts_fp-dct2000-coverage.out (+ -malformed).

Everything is built with struct; nothing comes from a real network.  The
captures have two interfaces: link type 252 (Exported PDU: carries the
records that name "dct2000", "fp_hint" and "fp_mux", which hand FP its
per-frame information) and Ethernet (UDP datagrams that the FP heuristics
"fp_udp" frame without any help).
"""
import struct
import sys
import json
import random
import os
import zlib

import types

out = sys.argv[1] if len(sys.argv) > 1 else '.'

# ------------------------------------------------------------------ CRCs
def crc7(data):
    r = 0
    for b in data:
        for i in range(7, -1, -1):
            top = ((r >> 6) & 1) ^ ((b >> i) & 1)
            r = (r << 1) & 0x7f
            if top:
                r ^= 0x45
    return r

def crc16(data):
    r = 0
    for b in data:
        r ^= b << 8
        for _ in range(8):
            r = ((r << 1) ^ 0x8005) & 0xffff if r & 0x8000 else (r << 1) & 0xffff
    return r

def crc11(data):
    r = 0
    for b in data:
        for i in range(7, -1, -1):
            top = ((r >> 10) & 1) ^ ((b >> i) & 1)
            r = (r << 1) & 0x7ff
            if top:
                r ^= 0x307
    return r

# ------------------------------------------------------------------ FP frames
def fp_data(hdr, payload=b'', crc=True):
    """data frame: byte 0 = CRC7 of hdr << 1 | FT 0; payload CRC16 appended"""
    f = bytes([crc7(hdr) << 1]) + hdr + payload
    if crc:
        f += struct.pack('>H', crc16(payload))
    return f

def fp_ctl(ftype, body=b''):
    rest = bytes([ftype]) + body
    return bytes([(crc7(bytes([1]) + rest) << 1) | 1]) + rest

def fp_edch(hdr, payload):
    """E-DCH type 1 data frame: 11 bit header CRC split over bytes 0 and 1.
    hdr = bytes after byte 0, the low nibble of hdr[0] is part of the header"""
    h = bytes([hdr[0] & 0x0f]) + hdr[1:]
    c = crc11(h)
    b0 = (c >> 4) << 1
    b1 = ((c & 0xf) << 4) | (hdr[0] & 0x0f)
    return bytes([b0, b1]) + hdr[1:] + payload + struct.pack('>H', crc16(payload))

def am_pdu(sn, data, poll=0):
    """RLC AM data PDU without length indicators"""
    return bytes([0x80 | (sn >> 5), ((sn & 0x1f) << 3) | (poll << 2)]) + data

# ------------------------------------------------------------------ capture records
IDB_EXP, IDB_ETH = 0, 1

def exp_pdu(proto, payload, ipsrc=None, ipdst=None, sport=None, dport=None):
    def tag(t, v):
        return struct.pack('>HH', t, len(v)) + v
    name = proto.encode()
    name += b'\0' * (-len(name) % 4)
    p = tag(12, name)
    if ipsrc:
        p += tag(20, bytes(map(int, ipsrc.split('.'))))
        p += tag(21, bytes(map(int, ipdst.split('.'))))
        p += tag(24, struct.pack('>I', 3))
        p += tag(25, struct.pack('>I', sport))
        p += tag(26, struct.pack('>I', dport))
    p += struct.pack('>HH', 0, 0)
    return p + payload

def ipv4_udp(src, dst, sport, dport, payload):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                      bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    s = sum(struct.unpack('>10H', hdr))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    hdr = hdr[:10] + struct.pack('>H', ~s & 0xffff) + hdr[12:]
    return hdr + udp

def eth_udp(src, dst, sport, dport, payload):
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ipv4_udp(src, dst, sport, dport, payload)

def write_pcapng(path, frames):
    def block(btype, body):
        body += b'\0' * (-len(body) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    f = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    f += block(1, struct.pack('<HHI', 252, 0, 262144))
    f += block(1, struct.pack('<HHI', 1, 0, 262144))
    for i, rec in enumerate(frames):
        idb, data = rec[0], rec[1]
        orig = rec[2] if len(rec) > 2 else len(data)
        ts = 1793440800 * 1000000 + i * 1000
        f += block(6, struct.pack('<IIIII', idb, ts >> 32, ts & 0xffffffff, len(data), orig) + data)
    open(path, 'wb').write(f)

main, mal, pi = [], [], []     # lists of (idb, bytes)
dmain, dmal = [], []   # DCT2000 frames: (proto, variant, outhdr, direction, fp)
notes = {'main': [], 'mal': [], 'dmain': [], 'dmal': [], 'pi': []}

def note(lst, text):
    k = 'main' if lst is main else 'mal' if lst is mal else 'pi' if lst is pi else 'dmain' if lst is dmain else 'dmal'
    notes[k].append((len(lst) + 1, text))

def add_exp(lst, rec):
    lst.append((IDB_EXP, rec))

def add_udp(lst, payload, src='10.1.0.1', dst='10.1.0.2', sport=3000, dport=3001):
    lst.append((IDB_ETH, eth_udp(src, dst, sport, dport, payload)))

# ------------------------------------------------------------------ DCT2000 records
def dct(proto, fp, outhdr, direction=0, variant=b'1', ctx=b'ctx', port=1):
    """Exported PDU record naming dct2000: stub + 4 octet AAL2 prefix + FP frame"""
    oh = ','.join(str(v) for v in outhdr).encode()
    stub = (ctx + b'\0' + bytes([port]) + b'0.0010' + b'\0' + proto.encode() + b'\0' + variant + b'\0' +
            oh + b'\0' + bytes([direction, 14]) + bytes([0, len(fp) & 0xff, 0, 0]) + fp)
    name = b'dct2000'
    return struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0) + stub

def write_dct(path, frames):
    """DCT2000 text log ("Session Transcript (format 5)"): FP over AAL2, the wiretap reader
    turns the outhdr into the per-frame information that the FP dissector needs"""
    lines = ['Session Transcript (format 5)', 'October 31, 2026     10:00:00.0000']
    t = 0
    for proto, var, ohv, direction, fp in frames:
        t += 10
        data = bytes([0, len(fp) & 0xff, 0, 0]) + fp
        head = 'ctx.1/%s/%s' % (proto, var.decode())
        if ohv:
            head += ',' + ','.join(str(v) for v in ohv)
        head += '$001002000008/'
        lines.append('%s %s tm %d.%04d l $%s' % (head, 's' if direction == 0 else 'r', t // 10000, t % 10000, data.hex()))
    open(path, 'w').write('\n'.join(lines) + '\n')

def bitpack(fields):
    """fields: list of (nbits, value) -> bytes, MSB first, zero padded"""
    acc, n = 0, 0
    for nb, v in fields:
        acc = (acc << nb) | (v & ((1 << nb) - 1))
        n += nb
    pad = -n % 8
    acc <<= pad
    return acc.to_bytes((n + pad) // 8, 'big')


HINT_SRC = r'''import struct, sys, os, json
def exp_pdu(proto, payload):
    # EXP_PDU_TAG_DISSECTOR_NAME = 12, then the end-of-options tag
    name = proto.encode()
    name += b'\0' * (-len(name) % 4)
    return struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0) + payload

def crc7(data):
    r = 0
    for b in data:
        for i in range(7, -1, -1):
            top = ((r >> 6) & 1) ^ ((b >> i) & 1)
            r = (r << 1) & 0x7f
            if top:
                r ^= 0x45
    return r

def crc16(data):
    r = 0
    for b in data:
        r ^= b << 8
        for _ in range(8):
            r = ((r << 1) ^ 0x8005) & 0xffff if r & 0x8000 else (r << 1) & 0xffff
    return r

def fp_frame(hdr, payload=b'', tail=b'', pcrc=True):
    """FP data frame: byte 0 = header CRC (7 bits) + frame type 0, then hdr
    (covered by the CRC), the transport block payload, an optional trailer
    and the payload CRC."""
    b0 = crc7(hdr) << 1
    f = bytes([b0]) + hdr + payload + tail
    if pcrc:
        f += struct.pack('>H', crc16(payload))
    return f

def fp_control(ftype, body=b''):
    """UMTS FP control frame: the header CRC covers the whole frame with
    the first octet reduced to the frame type bit"""
    rest = bytes([ftype]) + body
    return bytes([(crc7(bytes([1]) + rest) << 1) | 1]) + rest

# ---- hint header builders
UOFF = 0

def rb_entry(urnti, rlc=0, content=0, rbid=0, ctmux=0, ciph=0, deciph=0):
    urnti = urnti + UOFF if urnti else 0
    b4 = (rlc & 3) | ((content & 3) << 2) | ((rbid & 0xf) << 4)
    b5 = ((rbid >> 4) & 1) | (ctmux << 1) | (ciph << 2) | (deciph << 3)
    return struct.pack('<IBBH', urnti, b4, b5, 0)

def blk(count, size, extra=0):
    """4 octet transport format as used by PCH, RACH and FACH: block
    count (9 bits), block size (13 bits) and the PICH length (3 bits)"""
    v = (count & 0x1ff) | ((size & 0x1fff) << 9) | ((extra & 7) << 22)
    return struct.pack('<I', v)

def tf4(dch_id, n, size):
    """DCH transport format: DCH id (5 bits), N (9 bits), size (13+ bits)"""
    v = (dch_id - 1) & 0x1f
    v |= (n & 0x1ff) << 5
    v |= (size & 0x1fff) << 14
    return struct.pack('<I', v)

ATM, ETH = 0, 1
PCH, RACH, FACH, DCH, HSDSCH, EDCH = range(6)

def hint(frame_type, channel, body, pdu, cid=5, vpi=1, vci=33, hdrlen=None):
    """hint header + AAL2/ATM header or nothing + pdu"""
    hl = 4 + len(body) if hdrlen is None else hdrlen
    h = struct.pack('<HBB', hl, frame_type, channel) + body
    if frame_type == ATM:
        h += struct.pack('>II', cid, (vpi << 20) | (vci << 4))
    return h + pdu

def eth_frame(payload=b'\x01\x02\x03\x04'):
    udp = struct.pack('>HHHH', 3000, 3001, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2)))
    s = sum(struct.unpack('>10H', ip))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', (~s) & 0xffff) + ip[12:] + udp
    f = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip
    import zlib
    return f + struct.pack('<I', zlib.crc32(f))

def data(n, seed=0):
    return bytes((seed + 7 * i + 1) & 0xff for i in range(n))

P = lambda h: exp_pdu('fp_hint', h)
SEEDS = {"fach1": 2, "fach2": 2, "rach1": 63, "rach2": 63}
names = []
main, mal = [], []
BUILDERS = []
def add(lst, name, fn):
    """fn(seed) -> exported PDU record"""
    if lst is main:
        names.append(name)
        BUILDERS.append((name, fn))
    lst.append(P(fn(SEEDS.get(name, 0))))

def tbdata(n, seed):
    return data(n, seed)

# ---- PCH.  The first frame carries the paging indication bitmap, which
# the following frames with transport blocks refer to.
def pch_fp(pi, tfi, bitmap, tbs):
    return fp_frame(bytes([0x11, pi & 1, tfi]), bitmap + tbs)

add(main, 'pch_bm0', lambda sd: hint(ATM, PCH, blk(0, 0, 0), pch_fp(1, 0, b'\xa5' * 3, b'')))
add(mal, 'pch_tb0', lambda sd: hint(ATM, PCH, blk(1, 64, 0), pch_fp(0, 1, b'', tbdata(8, sd))))
add(main, 'pch_bm1', lambda sd: hint(ATM, PCH, blk(0, 0, 1), pch_fp(1, 0, b'\x5a' * 5, b'')))
add(mal, 'pch_tb1', lambda sd: hint(ATM, PCH, blk(1, 64, 1), pch_fp(1, 1, b'\x5a' * 5, tbdata(8, sd))))
add(main, 'pch_bm2', lambda sd: hint(ATM, PCH, blk(0, 0, 2), pch_fp(1, 0, b'\x3c' * 9, b'')))
add(main, 'pch_bm3', lambda sd: hint(ATM, PCH, blk(0, 0, 3), pch_fp(1, 0, b'\xc3' * 18, b'')))
add(main, 'pch_nopi', lambda sd: hint(ATM, PCH, blk(0, 0, 4), pch_fp(0, 0, b'', b'')))   # PICH value 4: unknown

# ---- RACH / FACH / DCH with radio bearers
def rach_fp(cfn, tb):
    return fp_frame(bytes([cfn, 0, 4]), tb + b'\x00')
def fach_fp(cfn, tb):
    return fp_frame(bytes([cfn, 0, 20]), tb)
def dch_fp(cfn, tfis, tbs):
    return fp_frame(bytes([cfn]) + bytes(tfis), tbs)

R = rb_entry
add(main, 'rach1', lambda sd: hint(ATM, RACH, blk(1, 64) + b'\x01' + R(0x1001, 2, 1, 3, 0, 0, 0),
                                   rach_fp(10, tbdata(8, sd))))
add(main, 'rach2', lambda sd: hint(ATM, RACH, blk(1, 64) + b'\x02' + R(0x1002, 3, 2, 4, 1, 1, 1)
                                   + R(0, 1, 3, 17, 0, 0, 1), rach_fp(11, tbdata(8, sd))))
add(main, 'fach1', lambda sd: hint(ATM, FACH, blk(1, 64) + b'\x01' + R(0x2001, 2, 1, 3, 0, 0, 0),
                                   fach_fp(12, tbdata(8, sd))))
add(main, 'fach2', lambda sd: hint(ATM, FACH, blk(1, 64) + b'\x03' + R(0x2002, 3, 2, 31, 1, 0, 1)
                                   + R(0x2003, 1, 3, 5, 0, 1, 1) + R(0x2004, 0, 0, 0, 1, 0, 0),
                                   fach_fp(13, tbdata(8, sd))))
add(main, 'dch1', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 64) + b'\x01' + R(0x3001, 2, 1, 3, 1, 0, 0),
                                  dch_fp(20, [0], tbdata(8, sd))))
add(main, 'dch2', lambda sd: hint(ATM, DCH, b'\x02' + tf4(1, 1, 40) + tf4(5, 1, 24) + b'\x01'
                                  + R(0x3002, 3, 1, 1, 0, 1, 1), dch_fp(21, [0, 0], tbdata(8, sd))))
add(main, 'dch3', lambda sd: hint(ATM, DCH, b'\x01' + tf4(2, 1, 64) + b'\x02' + R(0x3003, 3, 3, 2, 1, 0, 0)
                                  + R(0x3004, 0, 1, 6, 0, 0, 0), dch_fp(22, [0], tbdata(8, sd))))
# size 0x1fff means no transport block data: the size is not shown
add(main, 'dch_empty', lambda sd: hint(ATM, DCH, b'\x01' + tf4(2, 0, 0x1fff) + b'\x01' + R(0x3005, 3, 1, 3, 0, 0, 0),
                                       dch_fp(23, [0], b'')))
# three channels, one with two transport blocks
add(main, 'dch_multi', lambda sd: hint(ATM, DCH, b'\x03' + tf4(1, 2, 32) + tf4(3, 0, 0) + tf4(7, 1, 16) + b'\x01'
                                       + R(0x3006, 0, 1, 3, 1, 0, 0), dch_fp(24, [0, 0, 0], tbdata(10, sd))))
# a content value of 0 (unknown)
add(main, 'dch_unknown', lambda sd: hint(ATM, DCH, b'\x01' + tf4(3, 1, 64) + b'\x01' + R(0x3007, 0, 0, 0, 0, 0, 0),
                                         dch_fp(25, [0], tbdata(8, sd))))

# ---- HS-DSCH and E-DCH: the hint attaches the info, and control frames
# (valid header CRC) are decoded by FP
add(main, 'hs_ctl1', lambda sd: hint(ATM, HSDSCH, b'\x01\x00', fp_control(3, b'\x00')))
add(main, 'hs_ctl2', lambda sd: hint(ATM, HSDSCH, b'\x09\x01' + R(0x4001, 2, 1, 3, 0, 0, 0), fp_control(1, b'\x05')))
add(main, 'hs_ctl3', lambda sd: hint(ATM, HSDSCH, b'\x0b\x02' + R(0x4002, 3, 2, 4, 1, 0, 0) + R(0x4003, 3, 1, 1, 0, 1, 1),
                                     fp_control(6, b'\x01\x02\x03')))
add(main, 'ed_ctl1', lambda sd: hint(ATM, EDCH, b'\x01\x00\x00', fp_control(3, b'\x00')))
add(main, 'ed_ctl2', lambda sd: hint(ATM, EDCH, b'\x02\x02' + bytes([1, 3]) + struct.pack('<H', 336)
                                     + bytes([2, 4]) + struct.pack('<H', 144) + b'\x01' + R(0x5001, 2, 1, 3, 0, 0, 0),
                                     fp_control(1, b'\x05')))
add(main, 'ed_ctl3', lambda sd: hint(ATM, EDCH, b'\x03\x03' + bytes([1, 3]) + struct.pack('<H', 336) * 1
                                     + bytes([2, 4]) + struct.pack('<H', 144) + bytes([3, 5]) + struct.pack('<H', 0)
                                     + b'\x00', fp_control(6, b'\x01\x02\x03')))
# control frames on the other channel types
add(main, 'pch_ctl', lambda sd: hint(ATM, PCH, blk(0, 0, 0), fp_control(1, b'\x05')))
add(main, 'dch_ctl', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 64) + b'\x00', fp_control(1, b'\x05')))

# ---- unknown channel type, unknown frame type
add(main, 'chan_unknown', lambda sd: hint(ATM, 9, b'', fp_control(1, b'\x05')))
add(main, 'frame_unknown', lambda sd: hint(7, DCH, b'\x01' + tf4(1, 1, 8) + b'\x00', data(8, 0)))
# ---- Ethernet frame type: the Ethernet frame (with FCS) holds a UDP datagram
add(main, 'eth_dch', lambda sd: hint(ETH, DCH, b'\x01' + tf4(1, 1, 8) + b'\x00', eth_frame()))
add(main, 'eth_pch', lambda sd: hint(ETH, PCH, blk(0, 0), eth_frame(b'\x10\x20\x30')))

# ---- malformed / unsupported
# no radio bearer info: MAC and RLC miss their per-frame info
add(mal, 'rach_norb', lambda sd: hint(ATM, RACH, blk(1, 64) + b'\x00', rach_fp(10, tbdata(8, 0))))
add(mal, 'fach_norb', lambda sd: hint(ATM, FACH, blk(1, 64) + b'\x00', fach_fp(10, tbdata(8, 0))))
add(mal, 'dch_norb', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 64) + b'\x00', dch_fp(10, [0], tbdata(8, 0))))
add(mal, 'hs_norb', lambda sd: hint(ATM, HSDSCH, b'\x01\x00', data(8)))
add(mal, 'ed_norb', lambda sd: hint(ATM, EDCH, b'\x01\x00\x00', data(8)))
# more radio bearers than supported (64) -> warning, in all channel types
rbs = b''.join(R(0x6000 + i, 2, 1, i & 31, 0, 0, 0) for i in range(65))
add(mal, 'rach_many_rb', lambda sd: hint(ATM, RACH, blk(1, 64) + b'\x41' + rbs, rach_fp(10, tbdata(8, 0))))
add(mal, 'dch_many_rb', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 64) + b'\x41' + rbs, dch_fp(10, [0], tbdata(8, 0))))
# more FP channels than supported (65) -> warning
tfs = b''.join(tf4((i % 31) + 1, 0, 0) for i in range(65))
add(mal, 'dch_many_ch', lambda sd: hint(ATM, DCH, b'\x41' + tfs + b'\x00', dch_fp(10, [0] * 65, b'')))
# more E-DCH DDIs than supported (17)
ddis = b''.join(bytes([i, 3]) + struct.pack('<H', 336) for i in range(17))
add(mal, 'ed_many_ddi', lambda sd: hint(ATM, EDCH, b'\x01\x11' + ddis + b'\x00', fp_control(1, b'\x05')))
# truncated hints and headers
add(mal, 'short1', lambda sd: struct.pack('<H', 4))
add(mal, 'short2', lambda sd: struct.pack('<HBB', 4, 0, DCH))
add(mal, 'short_dch', lambda sd: struct.pack('<HBB', 8, 0, DCH) + b'\x03\x00\x00')
add(mal, 'short_ed', lambda sd: struct.pack('<HBB', 8, 0, EDCH) + b'\x03\x05\x01\x02')
add(mal, 'short_rb', lambda sd: struct.pack('<HBB', 12, 0, RACH) + blk(1, 64) + b'\x01' + b'\x01\x02')
add(mal, 'short_pch', lambda sd: struct.pack('<HBB', 6, 0, PCH) + b'\x01\x02')
# header length beyond the packet, and too short for the ATM header
add(mal, 'hdrlen_big', lambda sd: struct.pack('<HBB', 0xfff0, 0, 9) + b'\x00' * 8)
add(mal, 'no_atm', lambda sd: struct.pack('<HBB', 4, 0, 9) + b'\x00\x00')
add(mal, 'eth_short', lambda sd: struct.pack('<HBB', 4, 1, 9) + b'\x00\x00')

'''
FLOWS_SRC = r'''# Flow generators for the FP-over-UDP heuristics.  Each generator takes a
# seed (the synthetic transport block bytes depend on it: MAC, RLC and RRC
# decode them) and returns a list of (payload, reverse) UDP datagrams of one
# flow.  search.py picks seeds for which the whole stack decodes cleanly.

FLOWS = {}
ONEPASS = set()      # flows whose first datagram is only framed by a later one: -2 differs by design

def flow_gen(fn):
    FLOWS[fn.__name__] = fn
    return fn

def onepass(fn):
    ONEPASS.add(fn.__name__)
    return fn

def um_pdu(sn, sdu, size):
    """RLC UM PDU of 'size' octets holding one complete SDU: E=1, LI = SDU length (E=1), LI 0x7f
    (padding), SDU, padding"""
    pdu = bytes([((sn & 0x7f) << 1) | 1, (len(sdu) << 1) | 1, 0x7f << 1]) + sdu
    assert len(pdu) <= size
    return pdu + bytes(size - len(pdu))

def am_sdu_pdu(sn, sdu, size, poll=0):
    """RLC AM PDU of 'size' octets holding one complete SDU (HE=01, LI, LI padding)"""
    pdu = bytes([0x80 | (sn >> 5), ((sn & 0x1f) << 3) | (poll << 2) | 1, (len(sdu) << 1) | 1, 0x7f << 1]) + sdu
    assert len(pdu) <= size
    return pdu + bytes(size - len(pdu))

def rb(rnd, n):
    return bytes(rnd.randrange(256) for _ in range(n))

def tb148(rnd, sn, ct=1):
    """4 bit C/T + 18 octet RLC UM PDU = 148 bits (19 octets)"""
    return bitpack([(4, ct), (144, int.from_bytes(um_pdu(sn, rb(rnd, rnd.randrange(3, 12)), 18), 'big'))])

@flow_gen
def dch(seed):
    rnd = random.Random(seed)
    out = []
    # DL data (24 octets): framed as DCH
    out.append((fp_data(bytes([1, 0x01]), tb148(rnd, 0)), False))
    # UL data (26): TB, QE, CRCI byte
    out.append((fp_data(bytes([2, 0x01]), tb148(rnd, 0) + bytes([0x55, 0x00])), True))
    out.append((fp_data(bytes([3, 0x01]), tb148(rnd, 1)), False))
    # control frames on the framed flow: DL sync, timing adjustment, UL sync
    out.append((fp_ctl(1, bytes([4])), False))
    out.append((fp_ctl(2, bytes([5, 0x01, 0x23])), True))
    out.append((fp_data(bytes([4, 0x00])), False))        # DL, no TB
    out.append((fp_data(bytes([5, 0x00]), b'\x00\x00'), True))   # UL, no TB: QE + CRCI
    return out

@flow_gen
def fach1(seed):
    rnd = random.Random(seed)
    tctf = rnd.choice([0x40, 0x50, 0x5f, 0x80, 0x60, 0x6a, 0x00, 0x11, 0xc0, 0xd5, 0x00, 0x00])
    tb = bytes([tctf]) + rb(rnd, 44)
    out = [(fp_data(bytes([7, 0x01, 0x00]), tb), False)]
    return out

@flow_gen
def fach2(seed):
    rnd = random.Random(seed)
    out = []
    tb = bytes([0x40]) + rb(rnd, 20)
    out.append((fp_data(bytes([9, 0x01, 0x00]), bytes([0x00]) + rb(rnd, 20)), False))          # 4 + 21 + 2 = 27
    tb2 = (bytes([0x00]) + rb(rnd, 20)) + (bytes([0x00]) + rb(rnd, 20))
    out.append((fp_data(bytes([10, 0x02, 0x00]), tb2), False))        # 4 + 42 + 2 = 48
    return out

@flow_gen
def rach(seed):
    rnd = random.Random(seed)
    out = []
    # 28 octets: 4 + 21 (168 bits) + CRCI byte + 2; TCTF 00 = CCCH
    tb = bytes([rnd.choice([0x00, 0x10, 0x20]) | (rnd.randrange(16))]) + rb(rnd, 20)
    out.append((fp_data(bytes([11, 0x00, 0x00]), tb + b'\x00'), True))
    # 52 octets: 4 + 45 (360 bits) + CRCI + 2; TCTF 01 = DCCH over RACH
    tb = bytes([0x40 | rnd.randrange(64)]) + rb(rnd, 44)
    out.append((fp_data(bytes([12, 0x01, 0x00]), tb + b'\x00'), True))
    return out

@flow_gen
@onepass
def pch_pi_tb(seed):
    """PI bitmap of 18 bits first, then a TB-only frame and frames with both"""
    rnd = random.Random(seed)
    out = []
    out.append((fp_data(bytes([0x00, 0x21, 0x00]), bytes([0xa0, 0x41, 0xc0])), False))
    out.append((fp_data(bytes([0x01, 0x20, 0x01]), bytes([0x40]) + rb(rnd, 9)), False))
    out.append((fp_data(bytes([0x02, 0x21, 0x01]), bytes([0xa0, 0x41, 0xc0, 0x40]) + rb(rnd, 9)), False))
    return out

@flow_gen
@onepass
def pch_tb_pi(seed):
    """TB first (10 octets, no PI), then 36 bit PI bitmap"""
    rnd = random.Random(seed)
    out = []
    out.append((fp_data(bytes([0x00, 0x20, 0x01]), bytes([0x40]) + rb(rnd, 9)), False))
    out.append((fp_data(bytes([0x01, 0x21, 0x00]), bytes([0xa0, 0x41, 0xc0, 0x11, 0x22])), False))
    out.append((fp_data(bytes([0x02, 0x20, 0x00]), b''), False))
    return out

@flow_gen
@onepass
def pch_pi72(seed):
    """72 bit bitmap, TB of 30 octets in the same frame as a bitmap"""
    rnd = random.Random(seed)
    out = []
    out.append((fp_data(bytes([0x00, 0x21, 0x00]), bytes(range(0xa0, 0xa9))), False))
    out.append((fp_data(bytes([0x01, 0x21, 0x01]), bytes(range(0xa0, 0xa9)) + bytes([0x40]) + rb(rnd, 29)), False))
    out.append((fp_data(bytes([0x02, 0x20, 0x01]), bytes([0x40]) + rb(rnd, 29)), False))
    return out

@flow_gen
@onepass
def pch_pi144(seed):
    """144 bit bitmap with the low CFN bits set (PCH, not DCH)"""
    rnd = random.Random(seed)
    out = []
    out.append((fp_data(bytes([0x00, 0x31, 0x00]), bytes([0x80 | i for i in range(18)])), False))
    out.append((fp_data(bytes([0x01, 0x20, 0x01]), bytes([0x40]) + rb(rnd, 9)), False))
    return out

def hs1_hdr(seq, pdulen_bits, npdus, buf, flags=0):
    return bytes([(seq << 4) | 3, (pdulen_bits >> 5) & 0xff, ((pdulen_bits & 0x1f) << 3) | flags, npdus]) + struct.pack('>H', buf)

@flow_gen
def hsdsch1(seed):
    rnd = random.Random(seed)
    out = []
    sn = list(range(100))
    for k, (plen, n) in enumerate([(336, 2), (656, 1)]):
        pdus = b''
        for i in range(n):
            # 4 bit padding + the MAC-d PDU (an RLC AM PDU), byte padded
            am = am_sdu_pdu(sn.pop(0), rb(rnd, rnd.randrange(3, plen // 8 - 5)), plen // 8)
            pdus += bitpack([(4, 0), (plen, int.from_bytes(am, 'big'))])
        out.append((fp_data(hs1_hdr(k, plen, n, 100 + k), pdus), False))
    return out

def hs2_blocks(blocks):
    """HS-DSCH type 2 PDU block headers; blocks = [(pdu_len, n, lchid)]"""
    f = []
    for i, (ln, n, lch) in enumerate(blocks):
        if i % 2 == 0:
            f += [(11, ln), (1, 0), (4, n)]
            if i == len(blocks) - 1:
                f += [(4, lch), (4, 0)]
            else:
                f += [(4, lch)]
        else:
            f += [(11, ln), (1, 0), (4, n), (4, lch)]
    return bitpack(f)

@flow_gen
def hsdsch2(seed):
    rnd = random.Random(seed)
    out = []
    sn = {}
    # LCHID field 8 and 10 are lchid 9 and 11: PS DTCH over AM (clean IPv4 SDUs)
    for k, blocks in enumerate([[(42, 1, 8)], [(40, 2, 8), (36, 1, 10)], [(38, 1, 10), (38, 1, 8), (40, 1, 10)]]):
        hdr = bytes([(k << 4) | 2, len(blocks) << 3, 0x00]) + struct.pack('>H', 50) + hs2_blocks(blocks)
        pl = b''
        for ln, n, lch in blocks:
            for i in range(n):
                s_ = sn.setdefault(lch, [])
                pl += am_sdu_pdu(len(s_), icmp_sdu(rnd), ln)
                s_.append(1)
        out.append((fp_data(hdr, pl), False))
    return out

@flow_gen
def unknown_ctl(seed):
    """control frame first: the flow is framed with an unknown channel"""
    rnd = random.Random(seed)
    out = [(fp_ctl(1, bytes([3])), False), (fp_ctl(2, bytes([4, 0, 5])), True)]
    return out

def icmp_sdu(rnd):
    """IPv4 + ICMP echo request (28 octets): a clean SDU for a PS DTCH"""
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28, rnd.randrange(65536), 0, 64, 1, 0, bytes([10, 9, 0, 1]), bytes([10, 9, 0, 2]))
    k = sum(struct.unpack('>10H', ip))
    while k >> 16:
        k = (k & 0xffff) + (k >> 16)
    ip = ip[:10] + struct.pack('>H', ~k & 0xffff) + ip[12:]
    icmp = struct.pack('>BBHHH', 0, 0, 0, 1, rnd.randrange(65536))
    k = sum(struct.unpack('>4H', icmp))
    while k >> 16:
        k = (k & 0xffff) + (k >> 16)
    return ip + icmp[:2] + struct.pack('>H', ~k & 0xffff) + icmp[4:]

def edch_frame(fsn, cfn, subframes, rnd, sn, size=42, ddi_ok=True):
    """subframes: list of (subframe number, [(ddi, n_macd)]); one TSN octet and n MAC-d PDUs
    per MAC-es PDU"""
    hdr = bytes([fsn & 0xf, len(subframes) - 1, cfn])
    pl = b''
    for sfn, pdus in subframes:
        fields = [(8, sfn & 7), (4, len(pdus))]
        for ddi, n in pdus:
            fields += [(6, ddi), (6, n)]
        hdr += bitpack(fields) if (4 + 12 * len(pdus)) % 8 == 0 else bitpack(fields)
    for sfn, pdus in subframes:
        for ddi, n in pdus:
            pl += bytes([rnd.randrange(64)])
            for i in range(n):
                pl += am_sdu_pdu(sn.pop(0), icmp_sdu(rnd), size)
    return fp_edch(hdr, pl)

@flow_gen
def edch1(seed):
    rnd = random.Random(seed)
    out = []
    sn = list(range(100))
    out.append((edch_frame(1, 10, [(0, [(1, 1)])], rnd, sn), True))            # 1 subframe, 1 MAC-es PDU, 1 MAC-d
    out.append((edch_frame(2, 11, [(1, [(2, 2)])], rnd, sn), True))
    out.append((edch_frame(3, 12, [(2, [(3, 1), (4, 1)]), (3, [(5, 1)])], rnd, sn), True))
    out.append((fp_ctl(1, bytes([4])), False))
    return out
'''
hintmod = types.SimpleNamespace()
exec(HINT_SRC, hintmod.__dict__)
_fns = dict(globals())
exec(FLOWS_SRC, _fns)
flows = types.SimpleNamespace(**_fns)
SEEDS = {"edch1": [0, 1, 2, 3], "dch": [2, 6, 8, 9], "fach1": [0, 1, 5, 7], "fach2": [0, 1, 2, 3], "rach": [2, 3, 4, 5], "pch_pi_tb": [0, 1, 4, 5], "pch_tb_pi": [0, 1, 2, 3], "pch_pi72": [0, 1, 2, 3], "pch_pi144": [0, 1, 2, 4], "hsdsch1": [2, 5, 12, 15], "hsdsch2": [0, 1, 2, 3], "unknown_ctl": []}

# ===== sections
# Sections of the generator (exec'd by mkumts_fp.py); everything is synthetic.

def bitpack(fields):
    """fields: list of (nbits, value) -> bytes, MSB first, zero padded"""
    acc, n = 0, 0
    for nb, v in fields:
        acc = (acc << nb) | (v & ((1 << nb) - 1))
        n += nb
    pad = -n % 8
    acc <<= pad
    return acc.to_bytes((n + pad) // 8, 'big')

# ===================================================================== reproducers
A, B, UID = '192.0.2.1', '192.0.2.2', 0x0102

def fp_mux(uid, fp):
    assert len(fp) < 128
    return struct.pack('>HB', uid, len(fp)) + fp

def fp_hint_pch_atm(pch_info4, fp):
    return struct.pack('<HBB', 8, 0, 0) + pch_info4 + struct.pack('>II', 8, (1 << 20) | (100 << 4)) + fp

note(main, 'reproducer 1 (PCH assertion): fp_mux DCH frame, then fp_hint PCH on the same flow')
dch = fp_data(bytes([0x05, 0x01]), bytes([0x11] + [0x22] * 18))
add_exp(main, exp_pdu('fp_mux', fp_mux(UID, dch), A, B, 1000, 2000))
pch = fp_data(bytes([0x00, 0x01, 0x00]), bytes([0xaa, 0xbb, 0xc0]))
add_exp(main, exp_pdu('fp_hint', fp_hint_pch_atm(bytes([0, 0, 0, 0]), pch), A, B, 0, UID))

note(pi, 'reproducer 2 (PI bitmap over-read): PCH heuristic learns 144 bits, fp_hint stores 18 bits')
A2, B2 = '192.0.2.3', '192.0.2.4'
f = fp_data(bytes([0x00, 0x11, 0x00]), bytes([0x5a] * 18))
add_exp(pi, exp_pdu('fp_mux', fp_mux(UID, f), A2, B2, 1000, 2000))
f = fp_data(bytes([0x00, 0x20, 0x01]), bytes([0x40] + [0x33] * 9))
add_exp(pi, exp_pdu('fp_mux', fp_mux(UID, f), A2, B2, 1000, 2000))
pch = fp_data(bytes([0x00, 0x31, 0x00]), bytes([0xaa, 0xbb, 0xc0]))
add_exp(pi, exp_pdu('fp_hint', fp_hint_pch_atm(bytes([0, 0, 0, 0]), pch), A2, B2, 0, UID))
add_exp(pi, exp_pdu('fp_mux', fp_mux(UID, fp_data(bytes([0x00, 0x40, 0x00]), b'')), A2, B2, 1000, 2000))

note(pi, 'reproducer 3 (PI bitmap NULL): invalid PICH mode from fp_hint')
A3, B3 = '192.0.2.5', '192.0.2.6'
f = fp_data(bytes([0x00, 0x11, 0x00]), bytes([0x5a] * 18))
add_exp(pi, exp_pdu('fp_mux', fp_mux(UID, f), A3, B3, 1000, 2000))
f = fp_data(bytes([0x00, 0x20, 0x01]), bytes([0x40] + [0x33] * 9))
add_exp(pi, exp_pdu('fp_mux', fp_mux(UID, f), A3, B3, 1000, 2000))
pch = fp_data(bytes([0x00, 0x31, 0x00]), b'')
add_exp(pi, exp_pdu('fp_hint', fp_hint_pch_atm(bytes([0, 0, 0xc0, 0x01]), pch), A3, B3, 0, UID))
add_exp(pi, exp_pdu('fp_mux', fp_mux(UID, fp_data(bytes([0x00, 0x40, 0x00]), b'')), A3, B3, 1000, 2000))

# ===================================================================== fp_hint frames
note(main, 'fp_hint records (PCH, RACH, FACH, DCH, control frames, Ethernet frame type)')
for rec in hintmod.main:
    add_exp(main, rec)
note(mal, 'fp_hint records without radio bearers, truncated hints, too many channels')
for rec in hintmod.mal:
    add_exp(mal, rec)

# ===================================================================== UDP heuristics
def flow(n):
    return dict(src='10.%d.0.1' % n, dst='10.%d.0.2' % n, sport=3000 + n, dport=4000 + n)

def udp(lst, payload, fl, rev=False):
    if rev:
        add_udp(lst, payload, fl['dst'], fl['src'], fl['dport'], fl['sport'])
    else:
        add_udp(lst, payload, fl['src'], fl['dst'], fl['sport'], fl['dport'])

# ---------------------------------------------------------------- flows from seeds.json
_flowno = [0]

def add_flow(lst, name, pick=0, text=None):
    seeds = SEEDS.get(name)
    if not seeds:
        if lst is main:
            raise SystemExit('no seed for flow ' + name)
        seeds = [0]
    seed = seeds[pick % len(seeds)]
    _flowno[0] += 1
    n = _flowno[0]
    ip = lambda k: '10.%d.%d.%d' % (n >> 8, 1 + (n & 127), k)
    note(lst, text or ('FP over UDP heuristic flow %s (seed %d)' % (name, seed)))
    for payload, rev in flows.FLOWS[name](seed):
        if rev:
            add_udp(lst, payload, ip(2), ip(1), 40000, 40000 + n)
        else:
            add_udp(lst, payload, ip(1), ip(2), 40000 + n, 40000)

add_flow(main, 'dch', 0, 'DCCH over DCH heuristic: DL/UL data, control frames, frames without TBs')
add_flow(main, 'dch', 1)
add_flow(main, 'fach1', 0, 'FACH heuristic, 1 TB (51 octets)')
add_flow(main, 'fach1', 1)
add_flow(main, 'fach1', 2)
add_flow(main, 'fach2', 0, 'FACH heuristic, 1 and 2 TBs (27, 48 octets)')
add_flow(main, 'fach2', 1)
add_flow(main, 'rach', 0, 'RACH heuristic (28 and 52 octets)')
add_flow(main, 'rach', 1)
add_flow(main, 'rach', 2)
add_flow(pi, 'pch_pi_tb', 0, 'PCH heuristic: PI bitmap first (18 bits), then the TB size')
add_flow(pi, 'pch_tb_pi', 0, 'PCH heuristic: TB first, then a 36 bit PI bitmap')
add_flow(pi, 'pch_pi72', 0, 'PCH heuristic: 72 bit bitmap and TB of 30 octets')
add_flow(pi, 'pch_pi144', 0, 'PCH heuristic: 144 bit bitmap')
add_flow(main, 'hsdsch1', 0, 'HS-DSCH type 1 heuristic (336 and 656 bit PDUs)')
add_flow(main, 'hsdsch2', 0, 'HS-DSCH type 2 (MAC-ehs) heuristic with several PDU blocks')
add_flow(main, 'hsdsch2', 1)
add_flow(main, 'edch1', 0, 'E-DCH type 1 heuristic')
add_flow(main, 'edch1', 1)
add_flow(mal, 'unknown_ctl', 0, 'control frame first: flow framed with unknown channel (FP has no channel info)')

# ===================================================================== DCT2000 records
# The DCT2000 log format gives FP its per-frame information (release, channel,
# direction, transport formats, DDIs ...) without any NBAP; the DCT2000
# dissector's FP outhdr is parsed in attach_fp_info().  Data frames here have
# transport blocks of size 0 (or none), so MAC is not called: MAC has no
# per-frame info for DCT2000 logs and would report an error for every block.
REL = {99: ('fp', b'1'), 4: ('fp_r4', b'1'), 5: ('fp_r5', b'1'), 61: ('fp_r6', b'1'), 62: ('fp_r6', b'2'),
       63: ('fp_r6', b'3'), 7: ('fp_r7', b'1'), 8: ('fp_r8', b'1')}
(RACH, RACH_TDD, FACH, FACH_TDD, DSCH, DSCH_TDD, USCH_384, PCH, CPCH, BCH, DCH, HSDSCH, IUR_CPCHF, IUR_FACH, IUR_DSCH,
 EDCH, RACH_TDD_128, HSDSCH_COMMON, HSDSCH_COMMON_T3, EDCH_COMMON, USCH_128) = (1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13,
 14, 15, 16, 17, 18, 19, 20, 21, 24)
DOWN, UP = 0, 1      # direction byte of the stub: sent (node type 2 -> downlink), received (-> uplink)

def oh(rel, ch, node=2, div=1, ent=0, crc=1, pi=0, tfs=(), ntbs=(), ddis=(), sizes=(), etype=0, nchans=None):
    v = [ch, node]
    if rel in (7, 8):
        v.append(div)
    if ch == HSDSCH and rel in (7, 8):
        v.append(ent)
    v += [crc, pi]
    if ch == EDCH:
        v += [1 if nchans is None else nchans, len(ddis)] + list(ddis) + list(sizes)
        if rel == 8:
            v.append(etype)
    else:
        v.append(len(tfs) if nchans is None else nchans)
        v += list(tfs) + list(ntbs)
    return v

def dd(lst, proto, fp, ohv, direction=DOWN, var=b'1'):
    lst.append((proto, var, ohv, direction, fp))

def d(lst, rel, fp, ohv, direction=DOWN):
    proto, var = REL[rel]
    dd(lst, proto, fp, ohv, direction, var)

def body(*parts):
    return b''.join(bytes(p) if not isinstance(p, bytes) else p for p in parts)

def u24(v):
    return struct.pack('>I', v)[1:]

# ---- control frames
def dch_ctl_body(t, variant=0):
    if t == 1: return bytes([variant & 0x7f or 0x20])
    if t == 2: return body([7], struct.pack('>h', -90))
    if t == 3: return bytes([9])
    if t == 4: return body([9], struct.pack('>h', 300))
    if t == 6: return u24(0x012345)
    if t == 7: return u24(0x012345) + u24(0x0a0b0c) + u24(0x300000)
    if t == 8:
        return [bytes([5, 0x80]), bytes([5, 0x80, 0x00]), bytes([5, 0x80, 0x02, 0x01]), bytes([5, 0x80, 0x03, 0x01]),
                bytes([5, 0x80, 0x01, 0x02])][variant % 5]
    if t == 9: return bytes([0x00, 0x7f, 0x05, 0x3f, 0x80, 0x00, 0x40])
    if t == 10: return [bytes([3, 0x0a]), bytes([3, 0x0a, 0x01, 0x01]), bytes([3, 0x0a, 0x00, 0x00])][variant % 3]
    if t == 11: return bytes([0x03])
    return bytes([1, 2, 3, 4])

def common_ctl_body(t, pch=False, variant=0):
    if t == 1: return bytes([0x30])
    if t in (2, 4): return (body(struct.pack('>H', 321), u24(0x7fff00)) if pch else body([5], struct.pack('>h', 77)))
    if t == 3: return (struct.pack('>H', 123) if pch else bytes([8]))
    if t == 6: return u24(0x00ff10)
    if t == 7: return u24(1) + u24(2) + u24(3)
    if t == 8: return bytes([2, 10, 20])
    if t == 9: return bytes([11, 0x15])
    if t == 10: return body([5], struct.pack('>H', 1234))
    if t == 11:
        credits, interval = [(0, 0), (2047, 5), (100, 20), (50, 150)][variant % 4]
        return bitpack([(2, 0), (2, variant & 3), (4, variant + 1), (13, 336 * 1), (11, credits), (8, interval), (8, 3 * (variant & 1))])
    if t == 12:
        credits, interval = [(0, 0), (65535, 5), (1000, 20), (500, 150)][variant % 4]
        return bitpack([(2, 0), (2, variant & 3), (4, variant + 1), (5, 0), (11, 656), (16, credits), (8, interval), (8, 3 * (variant & 1))])
    return bytes([1, 2, 3, 4])

note(dmain, 'DCT2000 control frames: every DCH control frame type in R99, R4, R6 (three variants), R7 (FDD, TDD 3.84 and 7.68), R8')
for rel, div in [(99, 1), (4, 1), (61, 1), (62, 1), (63, 1), (7, 1), (7, 2), (7, 4), (8, 1)]:
    types = list(range(1, 12)) + ([12] if rel == 99 else [])
    for t in types:
        if t == 8 and rel == 7:
            variants = [0, 1, 4] if div == 1 else [0, 2, 3, 4]      # E-RUCCH only in TDD
        elif t == 10 and rel == 7:
            variants = [0, 1, 2]
        else:
            variants = [0]
        for var in variants:
            d(dmain, rel, fp_ctl(t, dch_ctl_body(t, var)), oh(rel, DCH, div=div, tfs=[0], ntbs=[0]), DOWN if t % 2 else UP)
# E-RUCCH with an FDD division: "expecting TDD" (malformed group, note severity)
d(dmal, 7, fp_ctl(8, dch_ctl_body(8, 2)), oh(7, DCH, div=1, tfs=[0], ntbs=[0]), UP)

note(dmain, 'DCT2000 control frames on common channels: every common control frame type, all channels')
for rel in (99, 61, 7):
    for ch in (RACH, FACH, DSCH, USCH_384, CPCH, BCH, IUR_DSCH, HSDSCH_COMMON, USCH_128, RACH_TDD, FACH_TDD, DSCH_TDD, RACH_TDD_128):
        for t in ((1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 13) if rel == 61 else (1, 2, 3, 4, 8, 9)):
            if rel == 7 and ch not in (RACH, DSCH, HSDSCH_COMMON):
                continue
            d(dmain, rel, fp_ctl(t, common_ctl_body(t)), oh(rel, ch, tfs=[0], ntbs=[0]), UP if t % 2 else DOWN)
for rel in (5, 61, 7, 8):
    for t in (10, 11, 12):
        for var in range(4):
            if rel == 5 and var > 1:
                continue
            ent = 1 if rel in (7, 8) and t == 12 else 0
            d(dmain, rel, fp_ctl(t, common_ctl_body(t, variant=var)), oh(rel, HSDSCH, ent=ent, tfs=[0], ntbs=[0]), DOWN)
for t in (2, 3, 4):
    for rel in (99, 61):
        d(dmain, rel, fp_ctl(t, common_ctl_body(t, pch=True)), oh(rel, PCH, tfs=[0], ntbs=[0]), UP)

# ---- data frames, every channel
note(dmain, 'DCT2000 DCH data frames: DL/UL, 1-3 channels, CRCI bits, payload CRC absent/present, spare extension')
for rel, div in [(99, 1), (61, 1), (7, 1), (8, 1)]:
    kw = dict(div=div)
    d(dmain, rel, fp_data(bytes([5, 1]), b''), oh(rel, DCH, tfs=[0], ntbs=[1], **kw), DOWN)
    d(dmain, rel, fp_data(bytes([6, 1]), bytes([0x30, 0x00])), oh(rel, DCH, tfs=[0], ntbs=[1], **kw), UP)
    d(dmain, rel, fp_data(bytes([7, 1, 2, 3]), b''), oh(rel, DCH, tfs=[0, 0, 0], ntbs=[0, 2, 1], **kw), DOWN)
    d(dmain, rel, fp_data(bytes([8, 1, 2, 3]), bytes([0x10, 0x40])), oh(rel, DCH, tfs=[0, 0, 0], ntbs=[0, 2, 1], **kw), UP)
d(dmal, 61, fp_data(bytes([9, 0]), b'', crc=False), oh(61, DCH, crc=0, tfs=[0], ntbs=[0]), DOWN)   # 3 octets: ATM/AAL2 cuts it short
d(dmain, 61, fp_data(bytes([9, 0]), b'\xaa\xbb', crc=False), oh(61, DCH, crc=0, tfs=[0], ntbs=[0]), DOWN)       # spare extension
d(dmain, 61, fp_data(bytes([9, 0]), b'', crc=True), oh(61, DCH, crc=2, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 61, fp_data(bytes([9, 0]), b'', crc=False), oh(61, DCH, crc=2, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 61, fp_data(bytes([9, 0]), b'\x01\x02\x03', crc=True), oh(61, DCH, crc=1, tfs=[0], ntbs=[0]), DOWN)  # spare ext + crc

note(dmain, 'DCT2000 RACH data frames: R99, R6, R7 FDD/TDD with the new IE flags')
d(dmain, 99, fp_data(bytes([1, 0, 9]), b'\x00'), oh(99, RACH, tfs=[0], ntbs=[1]), UP)
d(dmain, 61, fp_data(bytes([1, 0, 9]), b'\x00'), oh(61, RACH, tfs=[0], ntbs=[1]), UP)
for flags, extra in [(0x00, b''), (0x01, b'\x07'), (0x02, b'\x01\x23'), (0x03, b'\x07\x01\x23'), (0xff, b'\x07\x01\x23')]:
    d(dmain, 7, fp_data(bytes([2, 0, 9]), b'\x00' + bytes([flags]) + extra), oh(7, RACH, div=1, tfs=[0], ntbs=[1]), UP)
d(dmain, 7, fp_data(bytes([2, 0, 9]), b'\x00\x00'), oh(7, RACH, div=2, tfs=[0], ntbs=[1]), UP)                   # flags, no IE
d(dmain, 7, fp_data(bytes([3, 0, 9]), b'\x00' + b'\x01\x03'), oh(7, RACH_TDD, div=2, tfs=[0], ntbs=[1]), UP)   # ext rx timing deviation, 384
d(dmain, 7, fp_data(bytes([3, 0, 9]), b'\x00' + b'\x01\x03'), oh(7, RACH_TDD, div=4, tfs=[0], ntbs=[1]), UP)   # 768
d(dmain, 7, fp_data(bytes([3, 0, 9]), b'\x00' + b'\x01\x03'), oh(7, RACH_TDD, div=1, tfs=[0], ntbs=[1]), UP)   # default division
d(dmain, 99, fp_data(bytes([3, 0, 9]), b'\x00'), oh(99, RACH_TDD, tfs=[0], ntbs=[1]), UP)
for flags, extra in [(0x00, b''), (0x01, b'\x01\x02'), (0x02, b'\x11\x22'), (0x03, b'\x00\x01\x1f\xff\x00\x02')]:
    d(dmain, 7, fp_data(bytes([4, 0, 9]), b'\x00' + bytes([flags]) + extra), oh(7, RACH_TDD_128, div=3, tfs=[0], ntbs=[1]), UP)
d(dmain, 99, fp_data(bytes([4, 0, 9]), b'\x00'), oh(99, RACH_TDD_128, tfs=[0], ntbs=[1]), UP)

note(dmain, 'DCT2000 FACH, DSCH, USCH, CPCH, BCH and Iur frames')
d(dmain, 99, fp_data(bytes([1, 0, 50]), b''), oh(99, FACH, tfs=[0], ntbs=[1]), DOWN)
d(dmain, 99, fp_data(bytes([1, 0, 50]), b''), oh(99, FACH_TDD, tfs=[0], ntbs=[1]), DOWN)
d(dmain, 7, fp_data(bytes([1, 0, 50]), b'\x01\x00\x10'), oh(7, FACH, tfs=[0], ntbs=[1]), DOWN)     # AoA present
d(dmain, 7, fp_data(bytes([1, 0, 50]), b'\x00\x00\x00'), oh(7, FACH, tfs=[0], ntbs=[1]), DOWN)     # AoA absent
d(dmain, 99, fp_data(bytes([2, 1, 8, 3, 0x45]), b''), oh(99, DSCH, tfs=[0], ntbs=[1]), DOWN)       # FDD, R99
d(dmain, 4, fp_data(bytes([2, 1, 8, 3, 0x45]), b''), oh(4, DSCH, tfs=[0], ntbs=[1]), DOWN)
d(dmain, 61, fp_data(bytes([2, 1, 7, 100]), b''), oh(61, DSCH, tfs=[0], ntbs=[1]), DOWN)
d(dmain, 99, fp_data(bytes([2, 1, 7, 100]), b''), oh(99, DSCH_TDD, tfs=[0], ntbs=[1]), DOWN)
for ch in (USCH_384, USCH_128):
    d(dmain, 99, fp_data(bytes([3, 1, 20]), bytes([0xa5, 0x77, 0x00])), oh(99, ch, tfs=[8], ntbs=[1]), UP)
    d(dmain, 7, fp_data(bytes([3, 1, 20]), bytes([0xa5, 0x77, 0x00, 0x01, 0x02])), oh(7, ch, tfs=[8], ntbs=[1]), UP)
    d(dmain, 7, fp_data(bytes([3, 1, 20]), bytes([0xa5, 0x77, 0x00, 0x00, 0x00])), oh(7, ch, tfs=[8], ntbs=[1]), UP)
d(dmain, 99, fp_data(bytes([4, 1, 9]), b'\x00'), oh(99, CPCH, tfs=[0], ntbs=[1]), UP)
d(dmain, 99, fp_data(bytes([4, 0]), b''), oh(99, BCH, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 99, fp_data(bytes([4, 0]), b''), oh(99, IUR_CPCHF, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 99, fp_data(bytes([4, 0]), b''), oh(99, IUR_FACH, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 99, fp_data(bytes([4, 0]), b''), oh(99, IUR_DSCH, tfs=[0], ntbs=[0]), DOWN)
dd(dmal, 'fpiur_r5', fp_ctl(3, bytes([4])), [12, 1], DOWN, b'1')   # FP over IuR never gets per-frame info

note(dmain, 'DCT2000 PCH frames: paging indication bitmaps of 18 and 144 bits, TBs, relevant PI tracking')
d(dmain, 99, fp_data(bytes([1, 0x21, 0]), bytes([0xa0, 0x41, 0xc0])), oh(99, PCH, pi=18, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 99, fp_data(bytes([2, 0x20, 1]), b''), oh(99, PCH, pi=18, tfs=[0], ntbs=[1]), DOWN)
d(dmain, 99, fp_data(bytes([3, 0x31, 1]), bytes(range(18))), oh(99, PCH, pi=144, tfs=[0], ntbs=[1]), DOWN)
d(dmain, 99, fp_data(bytes([4, 0x30, 1]), b''), oh(99, PCH, pi=144, tfs=[0], ntbs=[1]), DOWN)
d(dmain, 99, fp_data(bytes([5, 0x30, 0]), b''), oh(99, PCH, pi=144, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 61, fp_data(bytes([6, 0x31, 0]), bytes(range(3))), oh(61, PCH, pi=18, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 61, fp_data(bytes([7, 0x20, 1]), b''), oh(61, PCH, pi=18, tfs=[0], ntbs=[1]), DOWN)

# ---- HS-DSCH
def hs1_head(seq, plen, npdus, buf, flags=0, pi=5):
    return bytes([(seq << 4) | pi, (plen >> 5) & 0xff, ((plen & 0x1f) << 3) | flags, npdus]) + struct.pack('>H', buf)

def hs2_head(seq, nblocks, flags=0, fach=0, buf=300, pi=5):
    return bytes([(seq << 4) | pi, (nblocks << 3) | flags, fach << 7]) + struct.pack('>H', buf)

note(dmain, 'DCT2000 HS-DSCH frames: type 1 (R5, R6, R7) with new IE flags and DRT, type 2 (R7, R8) with PDU blocks, FACH indicator, DRT')
d(dmain, 5, fp_data(hs1_head(1, 336, 0, 100), b''), oh(5, HSDSCH, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 61, fp_data(hs1_head(2, 336, 0, 100, flags=0x06), b'\x00\x00\x00'), oh(61, HSDSCH, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 7, fp_data(hs1_head(3, 656, 0, 200), b'\x08\x12\x34'), oh(7, HSDSCH, ent=0, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 8, fp_data(hs1_head(3, 656, 0, 200), b''), oh(8, HSDSCH, ent=0, tfs=[0], ntbs=[0]), DOWN)
for nb in (1, 2, 3, 4, 31):
    blocks = [(40 + i, 0, i % 15) for i in range(nb)]
    for rel, flags, fach in ((7, 0x07, 1), (7, 0x00, 0), (8, 0x00, 0)):
        extra = (b'\x00\x05' if flags & 1 else b'') + (b'\x12\x34\x56\x00' if fach else b'')
        d(dmain, rel, fp_data(hs2_head(4, nb, flags, fach) + flows.hs2_blocks(blocks), extra + b'\x00\x00'),
          oh(rel, HSDSCH, ent=1, tfs=[0], ntbs=[0]), DOWN)

note(dmain, 'DCT2000 HS-DSCH common frames (experimental support warning), new IE flags with physical layer category')
for nb in (0, 1, 2):
    d(dmain, 7, fp_data(hs2_head(5, nb) + flows.hs2_blocks([(30, 0, 15), (31, 0, 1)][:nb]) if nb else hs2_head(5, 0), b'\x02\x0a'),
      oh(7, HSDSCH_COMMON, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 7, fp_data(hs2_head(5, 0), b'\x00'), oh(7, HSDSCH_COMMON, tfs=[0], ntbs=[0]), DOWN)
d(dmain, 61, fp_data(hs2_head(5, 1, fach=1) + flows.hs2_blocks([(30, 0, 15)]), b'\x12\x34\x56\x00\x00'), oh(61, HSDSCH_COMMON, tfs=[0], ntbs=[0]), DOWN)

# ---- E-DCH
def edch_t1(fsn, cfn, subs, pdus_payload=b'', legacy=False):
    hdr = bytes([fsn & 0xf, (len(subs) if legacy else len(subs) - 1), cfn])
    for sfn, pdus in subs:
        fields = [(8, sfn & 7), (4, len(pdus))]
        for ddi, n in pdus:
            fields += [(6, ddi), (6, n)]
        hdr += bitpack(fields)
    return fp_edch(hdr, pdus_payload)

note(dmain, 'DCT2000 E-DCH type 1 frames: DDI table from the outhdr, subframes with MAC-es PDUs without MAC-d PDUs')
DDIS = dict(ddis=(1, 2, 3), sizes=(336, 144, 656))
for rel, rv in ((61, 'v1'), (62, 'v2'), (7, ''), (8, '')):
    kw = dict(DDIS)
    if rel == 8:
        kw['etype'] = 0
    legacy = rel == 61
    d(dmain, rel, edch_t1(1, 10, [(0, [(1, 0)])], b'\x05', legacy=legacy), oh(rel, EDCH, **kw), UP)
    d(dmain, rel, edch_t1(2, 11, [(1, [(2, 0), (3, 0)]), (2, [(1, 0)])], b'\x05\x06\x07', legacy=legacy), oh(rel, EDCH, **kw), UP)
    d(dmain, rel, edch_t1(3, 12, [(i, [(1, 0)]) for i in range(5)] if not legacy else [(i, [(1, 0)]) for i in range(5)], b'\x01' * 5, legacy=legacy),
      oh(rel, EDCH, **kw), UP)
d(dmain, 7, fp_edch(bytes([0, 0, 12]), b''), oh(7, EDCH, **DDIS), UP)        # no subframe header at all: only header
note(dmain, 'DCT2000 E-DCH control frames')
d(dmain, 8, fp_ctl(1, bytes([0x20])), oh(8, EDCH, etype=0, **DDIS), UP)
d(dmain, 8, fp_ctl(2, dch_ctl_body(2)), oh(8, EDCH, etype=1, **DDIS), UP)

def t2_frame(fsn, cfn, subs, total_sdus, common=False, ernti=0x1234, lchid15=False, tail=b''):
    """subs: [(sfn, harq, [pdu: [(lchid, length), ...], ...])]"""
    hdr = bytes([fsn & 0xf, len(subs) - 1, cfn]) + b'\x00\x10' + struct.pack('>H', total_sdus & 0xfff)
    if common:
        hdr += struct.pack('>H', ernti)
    for sfn, harq, pdus in subs:
        if common:
            hdr += bitpack([(1, 0), (3, sfn), (4, len(pdus))])
        else:
            hdr += bitpack([(1, 0), (4, harq), (3, sfn), (4, len(pdus)), (4, 0)])
    data = b''
    for sfn, harq, pdus in subs:
        for sdus in pdus:
            for i, (lch, ln) in enumerate(sdus):
                if lch == 15:
                    hdr += bytes([0xf0]) + struct.pack('>H', ernti)
                    continue
                hdr += bitpack([(4, lch), (11, ln), (1, 1 if i == len(sdus) - 1 else 0)])
    for sfn, harq, pdus in subs:
        for sdus in pdus:
            ln = sum(l for c, l in sdus if c != 15)
            data += bytes([0x05]) + bytes([0x40 + (i & 0x3f) for i in range(ln)])
    return fp_edch(hdr, data + tail)

note(dmain, 'DCT2000 E-DCH type 2 (R8) and E-DCH common frames: MAC-is descriptors, E-RNTI')
T2 = dict(etype=1)
d(dmain, 8, t2_frame(1, 5, [(0, 1, [[(1, 4)]])], 1), oh(8, EDCH, **T2), UP)
d(dmain, 8, t2_frame(2, 6, [(1, 2, [[(1, 4), (2, 3)], [(3, 5)]]), (2, 0, [[(4, 2)]])], 4), oh(8, EDCH, **T2), UP)
d(dmain, 8, t2_frame(3, 7, [(3, 0, [])], 0), oh(8, EDCH, **T2), UP)
for rel in (7, 8):
    d(dmain, rel, t2_frame(4, 8, [(0, 0, [[(1, 4)]])], 1, common=True), oh(rel, EDCH_COMMON, tfs=[0], ntbs=[0]), UP)
    d(dmain, rel, t2_frame(5, 9, [(1, 0, [[(15, 0), (2, 3), (3, 2)]]), (2, 0, [[(4, 1)]])], 3, common=True), oh(rel, EDCH_COMMON, tfs=[0], ntbs=[0]), UP)
d(dmain, 8, t2_frame(6, 10, [(0, 1, [[(1, 4)]])], 1) + b'', oh(8, EDCH, etype=1, crc=0, **{k: v for k, v in DDIS.items()}), UP)

# the PI capture also goes into the malformed one (coverage only)
for _rec in pi:
    mal.append(_rec)

# ===================================================================== malformed capture only
# Mutated heuristic candidates: every datagram is its own flow.  Fields of a
# valid frame are changed and the header and payload CRCs are recomputed, so
# the heuristics reject them for the field, not for the CRC.
import random as _random

def refix(frame, hl, pl_end=None, edch=False):
    """recompute the header CRC (header of hl octets) and the payload CRC"""
    b = bytearray(frame)
    pe = len(b) - 2 if pl_end is None else pl_end
    pay = bytes(b[hl:pe])
    b[pe:pe + 2] = struct.pack('>H', crc16(pay))
    if edch:
        h = bytes([b[1] & 0x0f]) + bytes(b[2:hl])
        c = crc11(h)
        b[0] = (c >> 4) << 1 | (b[0] & 1)
        b[1] = ((c & 0xf) << 4) | (b[1] & 0x0f)
    else:
        b[0] = (crc7(bytes(b[1:hl])) << 1) | (b[0] & 1)
    return bytes(b)

_mrnd = _random.Random(20261112)
_mut_n = [0]

def add_mut(lst, payload):
    _mut_n[0] += 1
    n = 100 + _mut_n[0]
    ip = lambda k: '10.%d.%d.%d' % (n >> 8, 1 + (n & 127), k)
    add_udp(lst, payload, ip(1), ip(2), 41000 + n, 41000)

def mutate_set(lst, base, hl, count, edch=False, extra_lens=(), pos=None):
    pos = pos if pos is not None else list(range(1, hl))
    for i in range(count):
        b = bytearray(base)
        for _ in range(_mrnd.choice((1, 1, 2))):
            p = _mrnd.choice(pos)
            b[p] = _mrnd.choice((0, 1, 2, 3, 0x10, 0x40, 0x80, 0xf0, 0xff, _mrnd.randrange(256)))
        add_mut(lst, refix(bytes(b), hl, edch=edch))
    for dl in extra_lens:
        b = bytearray(base)
        if dl < 0:
            b = b[:dl - 2] + b[-2:]
        else:
            b = b[:-2] + bytes(dl) + b[-2:]
        add_mut(lst, refix(bytes(b), hl, edch=edch))

note(mal, 'mutated heuristic candidates (fields changed, CRCs recomputed): DCH, FACH, RACH, PCH, HS-DSCH, E-DCH')
_r = _random.Random(7)
_rb = lambda n: bytes(_r.randrange(256) for _ in range(n))
dch_dl = fp_data(bytes([1, 1]), bytes([0x11]) + _rb(18))
dch_ul = fp_data(bytes([1, 1]), bytes([0x11]) + _rb(20))
add_mut(mal, fp_data(bytes([1, 0]), b''))               # no TBs, DL: creates the conversation only
add_mut(mal, fp_data(bytes([1, 0]), b'\x00\x00'))       # no TBs, UL
add_mut(mal, fp_data(bytes([1, 0]), b'\x00'))           # odd length
add_mut(mal, bytes([0x01, 0x02, 0x03]))                 # control frame, bad CRC
add_mut(mal, b'\x00\x00')                               # too short
mutate_set(mal, dch_dl, 3, 14, pos=[2, 3])
mutate_set(mal, dch_ul, 3, 8, pos=[2, 3])
for dl in (-1, 1, -3):
    mutate_set(mal, dch_dl, 3, 0, extra_lens=(dl,))
bad = bytearray(dch_dl); bad[-1] ^= 1; add_mut(mal, bytes(bad))         # bad payload CRC
bad = bytearray(dch_dl); bad[0] ^= 2; add_mut(mal, bytes(bad))          # bad header CRC
fach1 = fp_data(bytes([1, 1, 0]), bytes([0x00]) + _rb(44))
fach2a = fp_data(bytes([1, 1, 0]), bytes([0x00]) + _rb(20))
fach2b = fp_data(bytes([1, 2, 0]), bytes([0x00]) + _rb(41))
for base, cnt in ((fach1, 10), (fach2a, 8), (fach2b, 8)):
    mutate_set(mal, base, 4, cnt, pos=[2, 3])
    mutate_set(mal, base, 4, 0, extra_lens=(-1, 1))
    for tctf in (0x41, 0x7f, 0x90, 0x40, 0x50, 0x5f, 0x80, 0x65, 0xc5, 0x20):
        b = bytearray(base); b[4] = tctf
        add_mut(mal, refix(bytes(b), 4))
    bad = bytearray(base); bad[-1] ^= 1; add_mut(mal, bytes(bad))
    bad = bytearray(base); bad[0] ^= 2; add_mut(mal, bytes(bad))
rach_a = fp_data(bytes([1, 0, 0]), bytes([0x00]) + _rb(20) + b'\x00')
rach_b = fp_data(bytes([1, 1, 0]), bytes([0x40]) + _rb(44) + b'\x00')
for base in (rach_a, rach_b):
    mutate_set(mal, base, 4, 8, pos=[2, 3])
    mutate_set(mal, base, 4, 0, extra_lens=(-1, 1))
    for tctf in (0x80, 0xc0, 0x40, 0x00):
        b = bytearray(base); b[4] = tctf
        add_mut(mal, refix(bytes(b), 4))
    bad = bytearray(base); bad[-1] ^= 1; add_mut(mal, bytes(bad))
    bad = bytearray(base); bad[0] ^= 2; add_mut(mal, bytes(bad))
# PCH candidates: reserved bits, TFI, PI lengths
for pibytes in (0, 1, 2, 3, 4, 5, 9, 18, 19):
    for tfi in (0, 1, 2):
        for b2 in (0x01, 0x21, 0x03, 0xf1):
            add_mut(mal, fp_data(bytes([1, b2, tfi]), _rb(pibytes)))
for tb in (10, 30, 7):
    add_mut(mal, fp_data(bytes([1, 0x20, 1]), _rb(tb)))
add_mut(mal, fp_data(bytes([1, 0x01, 0]), bytes(18)))        # 144 bits, CFN low bits zero and TFI byte zero
add_mut(mal, fp_data(bytes([1, 0x01, 0]), bytes([0x00]) + _rb(17)))
add_mut(mal, fp_data(bytes([1, 0x11, 0]), bytes(18)))
bad = bytearray(fp_data(bytes([1, 0x21, 0]), _rb(3))); bad[-1] ^= 1; add_mut(mal, bytes(bad))
bad = bytearray(fp_data(bytes([1, 0x21, 0]), _rb(3))); bad[0] ^= 2; add_mut(mal, bytes(bad))
# HS-DSCH type 1 candidates
def hs1_frame(plen, n, pad=0):
    pdus = b''.join(bitpack([(4, pad), (plen, int.from_bytes(_rb(plen // 8), 'big') & ~0xf)]) for _ in range(n))
    return fp_data(flows.hs1_hdr(1, plen, n, 100), pdus)
for plen, n in ((336, 2), (656, 1), (336, 33), (656, 18), (336, 0), (320, 2), (336, 1), (336, 3)):
    add_mut(mal, hs1_frame(plen, n))
add_mut(mal, hs1_frame(336, 2, pad=1))
add_mut(mal, hs1_frame(336, 2)[:-3])
add_mut(mal, b'\x00' * 10)
base = hs1_frame(336, 2)
mutate_set(mal, base, 7, 6, pos=[1, 2, 3, 4])
bad = bytearray(base); bad[-1] ^= 1; add_mut(mal, bytes(bad))
bad = bytearray(base); bad[0] ^= 2; add_mut(mal, bytes(bad))
# HS-DSCH type 2 candidates: block header variations
def hs2_frame(blocks, nb=None, fach=0, res3=0, lens=None):
    hdr = bytes([0x12, (len(blocks) if nb is None else nb) << 3, (fach << 7) | res3]) + struct.pack('>H', 50) + flows.hs2_blocks(blocks)
    pl = b''.join(_rb(l * n) for l, n, c in blocks)
    return fp_data(hdr, pl)
for blocks in ([(40, 1, 8)], [(0, 1, 8)], [(40, 0, 8)], [(40, 1, 15)], [(40, 1, 8), (30, 1, 8)], [(40, 1, 8), (30, 1, 8), (20, 1, 8)],
               [(40, 2, 8), (30, 2, 8), (20, 2, 8), (10, 2, 8)], [(400, 1, 8)], [(40, 1, 8)] * 5):
    add_mut(mal, hs2_frame(blocks))
add_mut(mal, hs2_frame([(40, 1, 8)], nb=0))
add_mut(mal, hs2_frame([(40, 1, 8)], res3=1))
add_mut(mal, hs2_frame([(40, 1, 8)], fach=1))
b = bytearray(hs2_frame([(40, 1, 8)])); b[8] |= 1; add_mut(mal, refix(bytes(b), 6 + 3))      # padding after the lchid
b = bytearray(hs2_frame([(40, 1, 8)])); b[7] |= 0x10; add_mut(mal, refix(bytes(b), 6 + 3))
base = hs2_frame([(40, 1, 8), (30, 1, 8)])
mutate_set(mal, base, 6 + 5, 8, pos=list(range(1, 11)))
bad = bytearray(base); bad[-1] ^= 1; add_mut(mal, bytes(bad))
bad = bytearray(base); bad[0] ^= 2; add_mut(mal, bytes(bad))
add_mut(mal, hs2_frame([(40, 1, 8)])[:11])
# E-DCH type 1 candidates
def edch_cand(subs, size=42, extra=0):
    hdr = bytes([1, len(subs) - 1, 5])
    pl = b''
    for sfn, pdus in subs:
        fields = [(8, sfn & 7), (4, len(pdus))]
        for ddi, n in pdus:
            fields += [(6, ddi), (6, n)]
        hdr += bitpack(fields)
    for sfn, pdus in subs:
        for ddi, n in pdus:
            pl += bytes([5]) + _rb(n * size)
    return fp_edch(hdr, pl + bytes(extra))
for subs in ([(0, [(1, 1)])], [(5, [(1, 1)])], [(0, [(1, 0)])], [(0, [])], [(0, [(1, 1)])] * 11, [(0, [(1, 1), (2, 1)])],
             [(0, [(1, 1)]), (1, [(1, 1)])], [(0, [(1, 63)])]):
    add_mut(mal, edch_cand(subs))
add_mut(mal, edch_cand([(0, [(1, 1)])], size=18))
add_mut(mal, edch_cand([(0, [(1, 2)])], size=18))
add_mut(mal, edch_cand([(0, [(1, 1)])], extra=3))
add_mut(mal, edch_cand([(0, [(1, 1)])])[:8])
base = edch_cand([(0, [(1, 1)])])
for k in range(10):
    b = bytearray(base)
    p = _mrnd.choice([1, 2, 3, 4, 5, 6])
    b[p] = _mrnd.choice((0, 1, 0x10, 0xf0, 0xff, 0x40))
    add_mut(mal, refix(bytes(b), 7, edch=True))
bad = bytearray(base); bad[-1] ^= 1; add_mut(mal, bytes(bad))
bad = bytearray(base); bad[0] ^= 2; add_mut(mal, bytes(bad))
bad = bytearray(base); bad[0] |= 1; add_mut(mal, bytes(bad))          # control bit
# control frames framing an UDP flow as channel unknown
for t, b_ in ((1, bytes([4])), (3, bytes([1, 2])), (6, bytes([0, 0, 1])), (0x10, b'\x00')):
    add_mut(mal, fp_ctl(t, b_))
add_mut(mal, bytes([0x01, 0x00, 0x00]))
add_mut(mal, b'\x01')

# ---- DCT2000 frames for the malformed capture: MAC without per-frame info, bad counts, unknown channel
note(dmal, 'DCT2000 data frames with transport blocks: MAC has no per-frame info for DCT2000 logs, so MAC reports an error for each block')
d(dmal, 99, fp_data(bytes([5, 1]), bytes([0x11] + [0x22] * 18)), oh(99, DCH, tfs=[148], ntbs=[1]), DOWN)
d(dmal, 99, fp_data(bytes([6, 1]), bytes([0x11] + [0x22] * 18) + b'\x30\x00'), oh(99, DCH, tfs=[148], ntbs=[1]), UP)
d(dmal, 99, fp_data(bytes([6, 1]), bytes([0x11] + [0x22] * 18) + b'\x30\x80'), oh(99, DCH, tfs=[148], ntbs=[1]), UP)     # CRCI set
d(dmal, 99, fp_data(bytes([1, 0, 9]), bytes([0x00] + [0x11] * 20) + b'\x00'), oh(99, RACH, tfs=[168], ntbs=[1]), UP)
d(dmal, 99, fp_data(bytes([1, 0, 9]), bytes([0x00] + [0x11] * 20) + b'\x80'), oh(99, RACH, tfs=[168], ntbs=[1]), UP)
d(dmal, 99, fp_data(bytes([1, 1, 50]), bytes([0x00] + [0x11] * 20)), oh(99, FACH, tfs=[168], ntbs=[1]), DOWN)
d(dmal, 99, fp_data(bytes([1, 0x20, 1]), bytes([0x40] + [0x11] * 9)), oh(99, PCH, pi=18, tfs=[80], ntbs=[1]), DOWN)
d(dmal, 99, fp_data(bytes([1, 0x21, 1]), bytes([0xa0, 0x41, 0xc0, 0x40] + [0x11] * 9)), oh(99, PCH, pi=18, tfs=[80], ntbs=[1]), DOWN)
d(dmal, 99, fp_data(bytes([7, 1, 2, 3]), bytes([0x11] * 12)), oh(99, DCH, tfs=[8, 16, 24], ntbs=[2, 0, 1]), DOWN)
d(dmal, 99, fp_data(bytes([7, 1]), bytes([0x11] * 2)), oh(99, DCH, tfs=[12], ntbs=[1]), DOWN)       # TB not byte aligned
d(dmal, 99, fp_data(bytes([7, 1, 1]), bytes([0x11] * 4)), oh(99, DCH, tfs=[12, 12], ntbs=[1, 1]), DOWN)
# too many channels (64), huge TB counts
d(dmal, 99, fp_data(bytes([7] + [1] * 64), b''), oh(99, DCH, tfs=[0] * 64, ntbs=[0] * 64), DOWN)
d(dmal, 99, fp_data(bytes([7] + [1] * 63), b''), oh(99, DCH, tfs=[0] * 63, ntbs=[0] * 63), DOWN)
# HS-DSCH with PDUs: MAC missing info
d(dmal, 61, fp_data(hs1_head(1, 336, 1, 100), bitpack([(4, 0), (336, 0x1234)])), oh(61, HSDSCH, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs1_head(1, 336, 63, 100), b''), oh(7, HSDSCH, ent=0, tfs=[0], ntbs=[0]), DOWN)         # too many PDUs
d(dmal, 7, fp_data(hs2_head(4, 1) + flows.hs2_blocks([(40, 1, 8)]), bytes(40)), oh(7, HSDSCH, ent=1, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs2_head(4, 1) + flows.hs2_blocks([(40, 15, 8)]), bytes(600)), oh(7, HSDSCH, ent=1, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs2_head(4, 1) + flows.hs2_blocks([(40, 1, 8)]), b''), oh(7, HSDSCH, ent=2, tfs=[0], ntbs=[0]), DOWN)   # entity neither hs nor ehs
d(dmal, 7, fp_data(hs2_head(5, 1) + flows.hs2_blocks([(30, 1, 15)]), bytes(30) + b'\x00'), oh(7, HSDSCH_COMMON, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs2_head(5, 1) + flows.hs2_blocks([(30, 2, 1)]), bytes(60) + b'\x00'), oh(7, HSDSCH_COMMON, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs2_head(5, 1) + flows.hs2_blocks([(30, 1, 1)]), bytes(30) + b'\x00'), oh(7, HSDSCH_COMMON, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs2_head(5, 1) + flows.hs2_blocks([(30, 15, 1)]), b''), oh(7, HSDSCH_COMMON, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs2_head(5, 0), b'\x00'), oh(7, HSDSCH_COMMON_T3, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs2_head(5, 0), b'\x00'), oh(7, 7, tfs=[0], ntbs=[0]), DOWN)            # unknown channel type
d(dmal, 7, fp_data(hs2_head(5, 0), b'\x00'), oh(7, 30, tfs=[0], ntbs=[0]), DOWN)
# E-DCH: MAC-d PDUs (MAC without info), undefined DDI, too many DDIs, SDU miscounts
note(dmal, 'DCT2000 E-DCH errors: DDI not defined, MAC-d PDUs, too many DDIs, MAC-is SDU counts, E-RNTI misuse')
d(dmal, 7, edch_t1(1, 10, [(0, [(1, 1)])], b'\x05' + bytes(42)), oh(7, EDCH, **DDIS), UP)
d(dmal, 7, edch_t1(1, 10, [(0, [(9, 1)])], b'\x05'), oh(7, EDCH, **DDIS), UP)               # DDI not defined
d(dmal, 7, edch_t1(1, 10, [(0, [(1, 63)])], b'\x05'), oh(7, EDCH, **DDIS), UP)              # many MAC-d PDUs
d(dmal, 7, edch_t1(1, 10, [(0, [(1, 0)])], b'\x05'), oh(7, EDCH, ddis=tuple(range(20)), sizes=(336,) * 20), UP)   # too many DDIs
d(dmal, 8, edch_t1(1, 10, [(0, [(1, 0)])], b'\x05'), oh(8, EDCH, etype=0, ddis=tuple(range(20)), sizes=(336,) * 20), UP)
d(dmal, 8, t2_frame(1, 5, [(0, 1, [[(1, 4)]])], 3), oh(8, EDCH, **T2), UP)                  # header said 3 SDUs, frame has 1
d(dmal, 8, t2_frame(1, 5, [(0, 1, [[(1, 4), (2, 3), (3, 2)]])], 1), oh(8, EDCH, **T2), UP)    # more SDUs than the header said
d(dmal, 8, t2_frame(1, 5, [(0, 1, [[(15, 0), (2, 3)]])], 2), oh(8, EDCH, **T2), UP)          # E-RNTI in a non common frame
d(dmal, 8, t2_frame(1, 5, [(0, 1, [[(1, 3), (15, 0)]])], 2), oh(8, EDCH, **T2), UP)          # E-RNTI not first
d(dmal, 8, t2_frame(1, 5, [(0, 1, [[(1, 1)] * 17])], 17), oh(8, EDCH, **T2), UP)             # 17 SDUs
d(dmal, 8, t2_frame(1, 5, [(0, 1, [[(1, 1)] * 16])], 16), oh(8, EDCH, **T2), UP)             # 16 SDUs
d(dmal, 8, t2_frame(1, 5, [(0, 1, [[(1, 4)]])], 1)[:12], oh(8, EDCH, **T2), UP)              # truncated
d(dmal, 8, t2_frame(2, 6, [(i & 7, 0, [[(1, 4)]]) for i in range(16)], 16), oh(8, EDCH, **T2), UP)   # 16 subframes
d(dmal, 8, t2_frame(2, 6, [(i & 7, 0, [[(1, 4)]]) for i in range(16)], 16, common=True), oh(8, EDCH_COMMON, tfs=[0], ntbs=[0]), UP)
# few outhdr values
dd(dmal, 'fp_r6', fp_ctl(3, bytes([4])), [12, 2], DOWN, b'1')
dd(dmal, 'fp_r9', fp_ctl(3, bytes([4])), [12, 2, 1, 0, 1, 16, 0], DOWN, b'1')


# ---- truncated captures (captured length shorter than the datagram) and IPv6 flows
def ipv6_udp_eth(src, dst, sport, dport, payload):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip6 = struct.pack('>IHBB16s16s', 0x60000000, len(udp), 17, 64, src, dst)
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x86\xdd' + ip6 + udp

note(mal, 'truncated datagrams (captured length below the reported length) for every heuristic, FP over IPv6')
_trunc = [(fp_data(bytes([1, 1]), bytes([0x11]) + _rb(18)), (2, 4, 12, 20)),
          (fp_data(bytes([1, 1, 0]), bytes([0x00]) + _rb(44)), (3, 5, 20, 40)),
          (fp_data(bytes([1, 1, 0]), bytes([0x00]) + _rb(20)), (3, 5, 20)),
          (fp_data(bytes([1, 0, 0]), bytes([0x00]) + _rb(20) + b'\x00'), (3, 5, 20)),
          (fp_data(bytes([1, 0x21, 0]), _rb(3)), (3, 5, 6)),
          (hs1_frame(336, 2), (4, 8, 30, 60)),
          (hs2_frame([(40, 1, 8)]), (4, 8, 12, 30)),
          (edch_cand([(0, [(1, 1)])]), (4, 8, 12, 30)),
          (fp_ctl(1, bytes([4])), (1, 2, 3))]
for frame, cuts in _trunc:
    for cut in cuts:
        _mut_n[0] += 1
        n = 100 + _mut_n[0]
        full = eth_udp('10.%d.%d.1' % (n >> 8, 1 + (n & 127)), '10.%d.%d.2' % (n >> 8, 1 + (n & 127)), 41000 + n, 41000, frame)
        mal.append((IDB_ETH, full[:14 + 20 + 8 + cut], len(full)))
for k, frame in enumerate((fp_data(bytes([1, 1]), bytes([0x11]) + _rb(18)), fp_data(bytes([1, 1, 0]), bytes([0x00]) + _rb(44)),
                           fp_data(bytes([1, 0, 0]), bytes([0x00]) + _rb(20) + b'\x00'), hs1_frame(336, 2), edch_cand([(0, [(1, 1)])]))):
    a6 = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1 + k]); b6 = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [0x80 + k])
    mal.append((IDB_ETH, ipv6_udp_eth(a6, b6, 42000 + k, 42100, frame)))
    mal.append((IDB_ETH, ipv6_udp_eth(a6, b6, 42000 + k, 42100, frame)))
# DCH heuristic: no-TB frames with bad CRCs, header only
add_mut(mal, bytes([0x00]) + bytes([5, 0]) + b'\x00\x00')                      # bad header CRC? (valid when 0x00 matches)
for hdrbyte in (0x02, 0x04, 0x20):
    add_mut(mal, bytes([hdrbyte, 1, 0, 0, 0]))
    b = bytearray(fp_data(bytes([1, 0]), b'')); b[-1] ^= 0x40; add_mut(mal, bytes(b))
    b = bytearray(fp_data(bytes([1, 0]), b'\x00\x00')); b[-1] ^= 0x40; add_mut(mal, bytes(b))
d(dmal, 61, fp_data(bytes([9, 0]), b'', crc=False), oh(61, DCH, crc=1, tfs=[0], ntbs=[0]), DOWN)     # header only, CRC configured
d(dmal, 7, fp_data(hs1_head(1, 336, 64, 100), b''), oh(7, HSDSCH, ent=0, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs1_head(1, 336, 200, 100), b''), oh(7, HSDSCH, ent=0, tfs=[0], ntbs=[0]), DOWN)

# ---- more heuristic and DCT2000 corner cases
add_mut(mal, fp_data(flows.hs1_hdr(1, 336, 0, 100), bytes(60)))                 # no PDUs (long enough for the length check)
add_mut(mal, fp_data(bytes([0x12, 31 << 3, 0x00]) + struct.pack('>H', 50), bytes(7)))     # 31 PDU blocks announced, frame too short
add_mut(mal, fp_data(bytes([0x12, 8 << 3, 0x00]) + struct.pack('>H', 50), bytes(14)))
# fp_hint Ethernet records: FP info is attached before the FP over UDP heuristics see the datagram
def _hint_eth(n, ch, body):
    udp = struct.pack('>HHHH', 41500, 41501, 8 + n, 0) + _rb(n)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2)))
    k = sum(struct.unpack('>10H', ip))
    while k >> 16:
        k = (k & 0xffff) + (k >> 16)
    ip = ip[:10] + struct.pack('>H', ~k & 0xffff) + ip[12:] + udp
    f = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip
    f += struct.pack('<I', zlib.crc32(f))
    return hintmod.P(hintmod.hint(hintmod.ETH, ch, body, f))
note(mal, 'fp_hint Ethernet records: FP info is attached before the FP over UDP heuristics run (they decline)')
for n in (51, 27, 48, 28, 52, 12, 60, 24, 26):
    add_exp(mal, _hint_eth(n, hintmod.DCH, b'\x01' + hintmod.tf4(1, 1, 8) + b'\x00'))
add_exp(mal, _hint_eth(12, hintmod.PCH, hintmod.blk(0, 0)))
for n, first in ((51, 0x01), (27, 0x01), (48, 0x03), (28, 0x01), (52, 0x01), (60, 0x01)):
    add_mut(mal, bytes([first]) + _rb(n - 1))                         # control frames of the right lengths: declined
# HS-DSCH common with the DRT flag, a header-only HS-DSCH frame (no payload CRC)
d(dmain, 7, fp_data(hs2_head(5, 0, flags=0x01), b'\x01\x23\x00'), oh(7, HSDSCH_COMMON, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs1_head(1, 336, 0, 100), b'', crc=False), oh(7, HSDSCH, ent=0, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 5, fp_data(hs1_head(1, 336, 0, 100), b'', crc=False), oh(5, HSDSCH, tfs=[0], ntbs=[0]), DOWN)
d(dmal, 7, fp_data(hs2_head(4, 1) + flows.hs2_blocks([(40, 1, 15)]), bytes(40)), oh(7, HSDSCH, ent=1, tfs=[0], ntbs=[0]), DOWN)   # lchid 15
d(dmal, 8, fp_data(hs2_head(4, 1) + flows.hs2_blocks([(40, 1, 15)]), bytes(40)), oh(8, HSDSCH, ent=1, tfs=[0], ntbs=[0]), DOWN)

# HS-DSCH type 2 heuristic: bad CRCs (single block frames: the odd block header is not read the way the dissector does)
_h2 = hs2_frame([(40, 1, 8)])
_b = bytearray(_h2); _b[-1] ^= 1; add_mut(mal, bytes(_b))
_b = bytearray(_h2); _b[0] ^= 2; add_mut(mal, bytes(_b))
# E-DCH data frames from fp_hint: header only (one subframe without MAC-es PDUs), with and without payload CRC
_ed_hdr = bytes([1, 0, 12]) + bitpack([(8, 0), (4, 0)])
_ed_body = b'\x02\x02' + bytes([1, 3]) + struct.pack('<H', 336) + bytes([2, 4]) + struct.pack('<H', 144) + b'\x01' + hintmod.rb_entry(0x5001, 2, 1, 3, 0, 0, 0)
note(main, 'fp_hint E-DCH data frame: one subframe without MAC-es PDUs')
add_exp(main, hintmod.P(hintmod.hint(hintmod.ATM, hintmod.EDCH, _ed_body, fp_edch(_ed_hdr, b''))))
add_exp(mal, hintmod.P(hintmod.hint(hintmod.ATM, hintmod.EDCH, _ed_body, fp_edch(_ed_hdr, b'')[:-2])))
add_exp(mal, hintmod.P(hintmod.hint(hintmod.ATM, hintmod.EDCH, _ed_body, fp_edch(_ed_hdr, b'')[:-1])))


if __name__ == '__main__':
    write_pcapng(os.path.join(out, 'umts_fp-coverage.pcapng'), main)
    write_pcapng(os.path.join(out, 'umts_fp-coverage-malformed.pcapng'), mal)
    # the PCH heuristic flows and the PI bitmap reproducers: one pass only (the first PCH frame is framed late)
    write_pcapng(os.path.join(out, 'umts_fp-pi-coverage.pcapng'), pi)
    write_dct(os.path.join(out, 'umts_fp-dct2000-coverage.out'), dmain)
    write_dct(os.path.join(out, 'umts_fp-dct2000-coverage-malformed.out'), dmal)
    print('main', len(main), 'malformed', len(mal), 'dct2000', len(dmain), 'dct2000 malformed', len(dmal))
    for k in ('main', 'mal', 'pi', 'dmain', 'dmal'):
        for n, t in notes[k]:
            print(k, n, t)
