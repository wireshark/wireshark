#!/usr/bin/env python3
# Helper module for the umts_rlc capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers for the synthetic UMTS MAC / RLC captures (copied into both
directories): pcapng writer with an Exported PDU interface and an Ethernet
interface, FP frame builders, FP Hint headers, RLC PDU builders.  Nothing
here comes from a real network."""
import struct
import zlib

# ---------------------------------------------------------------- pcapng
def _blk(btype, body):
    body += b'\0' * (-len(body) % 4)
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)

def write_pcapng(path, records, dt_us=1000000):
    """records: list of (interface, packet); interface 0 = Exported PDU
    (link type 252), 1 = Ethernet.  One second apart."""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (252, 1):
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    t = 1700000000 * 1000000
    for i, (ifc, pkt) in enumerate(records):
        ts = t + i * dt_us
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(pkt), len(pkt)) + pkt)
    open(path, 'wb').write(out)

def exp_pdu(name, payload, p2p_dir=None):
    n = name.encode()
    n += b'\0' * (-len(n) % 4)
    h = struct.pack('>HH', 12, len(n)) + n
    if p2p_dir is not None:
        h += struct.pack('>HHi', 35, 4, p2p_dir)
    return h + struct.pack('>HH', 0, 0) + payload

# ---------------------------------------------------------------- CRCs
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
    f = bytes([crc7(hdr) << 1]) + hdr + payload + tail
    if pcrc:
        f += struct.pack('>H', crc16(payload))
    return f

def fp_control(ftype, body=b''):
    rest = bytes([ftype]) + body
    return bytes([(crc7(bytes([1]) + rest) << 1) | 1]) + rest

# ---------------------------------------------------------------- bits
def bits(*spec):
    """bits((value, nbits), ... , bytes_obj) -> (bytes, nbits).  A bytes
    object is appended as 8*len bits."""
    s = ''
    for item in spec:
        if isinstance(item, (bytes, bytearray)):
            s += ''.join(format(b, '08b') for b in item)
        else:
            v, n = item
            s += format(v, '0%db' % n) if n else ''
    nb = len(s)
    s += '0' * (-len(s) % 8)
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8)), nb

# ---------------------------------------------------------------- FP hint
ATM, ETH = 0, 1
PCH, RACH, FACH, DCH, HSDSCH, EDCH = range(6)

def rb_entry(urnti, rlc=0, content=0, rbid=0, ctmux=0, ciph=0, deciph=0):
    b4 = (rlc & 3) | ((content & 3) << 2) | ((rbid & 0xf) << 4)
    b5 = ((rbid >> 4) & 1) | (ctmux << 1) | (ciph << 2) | (deciph << 3)
    return struct.pack('<IBBH', urnti, b4, b5, 0)

def blk(count, size, extra=0):
    v = (count & 0x1ff) | ((size & 0x1fff) << 9) | ((extra & 7) << 22)
    return struct.pack('<I', v)

def tf4(dch_id, n, size):
    v = (dch_id - 1) & 0x1f
    v |= (n & 0x1ff) << 5
    v |= (size & 0x1fff) << 14
    return struct.pack('<I', v)

def hint(frame_type, channel, body, pdu, cid=5, vpi=1, vci=33):
    h = struct.pack('<HBB', 4 + len(body), frame_type, channel) + body
    if frame_type == ATM:
        h += struct.pack('>II', cid, (vpi << 20) | (vci << 4))
    return h + pdu

def data(n, seed=0):
    return bytes((seed * 37 + 7 * i + 1) & 0xff for i in range(n))

# ---------------------------------------------------------------- FP frames
def pch_fp(pi, tfi, bitmap, tbs):
    return fp_frame(bytes([0x11, pi & 1, tfi]), bitmap + tbs)
def rach_fp(cfn, tb):
    return fp_frame(bytes([cfn, 0, 4]), tb + b'\x00')
def fach_fp(cfn, tb):
    return fp_frame(bytes([cfn, 0, 20]), tb)
def dch_fp(cfn, tfis, tbs):
    return fp_frame(bytes([cfn]) + bytes(tfis), tbs)

# ---------------------------------------------------------------- RLC PDUs
def um_pdu(sn, payload, lis=()):
    """RLC UM PDU, 7 bit SN; lis = list of (li, ext) 7 bit LIs (ext set on
    all but the last by this helper)"""
    if not lis:
        return bytes([(sn & 0x7f) << 1]) + payload
    h = bytes([((sn & 0x7f) << 1) | 1])
    for i, li in enumerate(lis):
        h += bytes([(li << 1) | (1 if i < len(lis) - 1 else 0)])
    return h + payload

def am_pdu(sn, payload, lis=(), p=0, he=None, li15=False):
    """RLC AM data PDU, 12 bit SN"""
    if he is None:
        he = 1 if lis else 0
    h = bytes([0x80 | (sn >> 5), ((sn & 0x1f) << 3) | (p << 2) | he])
    for i, li in enumerate(lis):
        last = i == len(lis) - 1
        if li15:
            h += struct.pack('>H', (li << 1) | (0 if last else 1))
        else:
            h += bytes([(li << 1) | (0 if last else 1)])
    return h + payload


def um_sdu(sn, sdu):
    """UM PDU holding one complete SDU: LI 0x7c (the SDU starts here), then
    the SDU length as LI"""
    return um_pdu(sn, sdu, lis=(0x7c, len(sdu)))

def am_sdu(sn, sdu):
    """AM PDU whose last octet ends the SDU (HE = 2)"""
    return am_pdu(sn, sdu, he=2)


def ip_checksum(hdr):
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def ipv4_udp(n=8, seed=0, sport=4000, dport=4001):
    """a small IPv4/UDP packet (documentation addresses) with n payload octets"""
    payload = data(n, seed)
    udp = struct.pack('>HHHH', sport, dport, 8 + n, 0) + payload
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), seed & 0xffff, 0, 64, 17, 0,
                      bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2)))
    hdr = hdr[:10] + struct.pack('>H', ip_checksum(hdr)) + hdr[12:]
    return hdr + udp
