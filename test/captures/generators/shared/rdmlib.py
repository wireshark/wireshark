# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers shared by mkrdm.py and selectrdm.py: Art-Net ArtRdm frames that carry RDM messages."""
import struct
import socket

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def rdm_msg(dst, src, tn, rt, cc, pid, pd, msgcount=0, subdev=0, intron=b'', trailer=b'', length=None, bad_csum=False):
    """RDM message (sub start code 0x01 on) with the checksum. dst and src are (manf, device)."""
    n = 24 + len(pd) + len(intron) if length is None else length
    b = struct.pack('>BBHIHIBBBH', 0x01, n & 0xff, dst[0], dst[1], src[0], src[1], tn & 0xff, rt, msgcount, subdev)
    b += struct.pack('>BHB', cc, pid, len(pd)) + pd + intron
    c = (0xCC + sum(b)) & 0xffff
    if bad_csum: c ^= 0x5a5a
    return b + struct.pack('>H', c) + trailer

def artrdm(msg, old=False):
    """ArtRdm (opcode 0x8300) packet; old=True: the old form with the 0xCC start code"""
    h = b'Art-Net\x00' + struct.pack('<H', 0x8300) + struct.pack('>H', 14)
    h += bytes([1, 0]) + bytes(5) + bytes([0, 0, 0]) + bytes([0, 0])
    return h + (b'\xcc' if old else b'') + msg

def eth_udp(payload, sport=6454, dport=6454, src='192.0.2.10', dst='192.0.2.255'):
    ulen = 8 + len(payload)
    udp = struct.pack('!HHHH', sport, dport, ulen, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + ulen, 1, 0, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('ffffffffffff020000000001') + b'\x08\x00' + ip + udp

def write_pcap(path, frames, lt=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, lt))
        for i, d in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(d), len(d)))
            f.write(d)
