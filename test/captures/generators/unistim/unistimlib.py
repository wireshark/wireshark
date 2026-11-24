# Helper module for the unistim capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers of mkunistim.py (packets and deterministic bodies)."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import random
import re
import struct

TREE = os.path.join(SRCDIR)
SRC = TREE + "/plugins/epan/unistim/packet-unistim.c"

# manager function -> UNISTIM command addresses it handles
MANAGERS = {
    'expansion_switch': [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e],
    'broadcast_switch': [0x11], 'audio_switch': [0x16], 'display_switch': [0x17],
    'key_indicator_switch': [0x19], 'basic_switch': [0x1a], 'network_switch': [0x1e],
    'expansion_phone': [0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e],
    'broadcast_phone': [0x91], 'audio_phone': [0x96], 'display_phone': [0x97],
    'key_indicator_phone': [0x99], 'basic_phone': [0x9a], 'network_phone': [0x9e],
}


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def frame(payload, sport, dport, src=(192, 0, 2, 10), dst=(192, 0, 2, 20)):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + udp


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def commands():
    """Command bytes of each manager function, read from the dissector source."""
    s = open(SRC).read()
    defs = [(m.start(), m.group(1)) for m in re.finditer(r'\ndissect_(\w+_(?:switch|phone))\(proto_tree \*msg_tree', s)
            if s[:m.start()].count('\n') > 400]
    out = {}
    for i, (a, n) in enumerate(defs):
        b = defs[i + 1][0] if i + 1 < len(defs) else s.index('\nproto_register_unistim(void)')
        cs = sorted({int(c, 16) for c in re.findall(r'case (0x[0-9a-fA-F]+):', s[a:b])})
        out[n] = cs
    return out


def body(addr, cmd, length, var):
    """Deterministic body (length octets after the command octet)."""
    r = random.Random('%d-%d-%d-%d' % (addr, cmd, length, var))
    mode = var % 4
    if mode == 0:
        return bytes(r.getrandbits(8) for _ in range(length))
    if mode == 1:
        return bytes(r.choice([0x00, 0xff, 0x55, 0xaa]) for _ in range(length))
    if mode == 2:
        return bytes(r.choice(b'abcdefgh 0123.') for _ in range(length))
    return bytes(r.choice([0, 1, 2, 3, 4, 5, 0x40, 0x41, 0x80]) for _ in range(length))


def message(addr, cmd, length, var):
    b = body(addr, cmd, length, var)
    return bytes([addr, 3 + length, cmd]) + b


def payload(msgs, seq=1, pay=1, termid=None):
    p = struct.pack('!IBB', seq, 2, pay)
    if pay == 2:
        p += struct.pack('!I', termid if termid is not None else 0xc0000201)
    return p + b''.join(msgs)
