#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helper: connectionless DCE/RPC (UDP) request/response frames for a given
interface UUID/version/opnum and stub. Synthetic addresses only."""
import struct
import uuid

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
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def udp(src, dst, sport, dport, payload, from_client):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 0, 0, 64, 17, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    mc, ms = bytes.fromhex('020000000050'), bytes.fromhex('020000000060')
    eth = (ms + mc) if from_client else (mc + ms)
    return eth + b'\x08\x00' + ip + u

def le_uuid(s):
    return uuid.UUID(s).bytes_le

def cl(ptype, if_uuid, if_ver, opnum, seq, act, stub, big=False):
    drep = b'\x00\x00\x00' if big else b'\x10\x00\x00'
    e = '>' if big else '<'
    ifu = uuid.UUID(if_uuid).bytes if big else le_uuid(if_uuid)
    actb = uuid.UUID(act).bytes if big else le_uuid(act)
    hdr = struct.pack('BBBB', 4, ptype, 0x28 if ptype == 0 else 0x0a, 0) + drep + b'\x00'
    hdr += b'\x00' * 16 + ifu + actb
    hdr += struct.pack(e + 'IIIHHHHH', 1, if_ver, seq, opnum, 0xffff, 0xffff, len(stub), 0)
    hdr += b'\x00\x00'
    assert len(hdr) == 80
    return hdr + stub

C = (192, 0, 2, 50)
S = (192, 0, 2, 60)

def pair(frames, if_uuid, if_ver, opnum, req, resp=None, big=False):
    seq = len(frames)
    act = '6b8c0000-0000-4000-8000-%012x' % seq
    frames.append(udp(C, S, 40000 + seq % 1000, 135, cl(0, if_uuid, if_ver, opnum, seq, act, req, big), True))
    if resp is not None:
        frames.append(udp(S, C, 135, 40000 + seq % 1000, cl(2, if_uuid, if_ver, opnum, seq, act, resp, big), False))
