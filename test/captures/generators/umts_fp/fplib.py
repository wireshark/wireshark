# Helper module for the umts_fp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import zlib
import random
import os
import sys
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
    for i, (idb, data) in enumerate(frames):
        ts = 1793440800 * 1000000 + i * 1000
        f += block(6, struct.pack('<IIIII', idb, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    open(path, 'wb').write(f)


def bitpack(fields):
    """fields: list of (nbits, value) -> bytes, MSB first, zero padded"""
    acc, n = 0, 0
    for nb, v in fields:
        acc = (acc << nb) | (v & ((1 << nb) - 1))
        n += nb
    pad = -n % 8
    acc <<= pad
    return acc.to_bytes((n + pad) // 8, 'big')
