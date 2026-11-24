# Helper module for the dhcp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared helpers for the packet-dhcp.c reproducers (synthetic addresses only).
import struct

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_frame(payload, sport=68, dport=67, src='192.0.2.1', dst='192.0.2.2', caplen=None):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, s, d)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    return eth + ip + udp

def bootp(options, op=1, sname=b'', file=b'', magic=True):
    hdr = struct.pack('!BBBBIHHIIII', op, 1, 6, 0, 0x12345678, 0, 0, 0, 0, 0, 0)
    chaddr = b'\x02\x00\x00\x00\x00\x01' + b'\0' * 10
    sname = sname.ljust(64, b'\0')[:64]
    file = file.ljust(128, b'\0')[:128]
    return hdr + chaddr + sname + file + (b'\x63\x82\x53\x63' if magic else b'') + options

def opt(code, data):
    return bytes([code, len(data)]) + data

def write_pcap(path, frames):
    """frames: list of bytes, or (bytes, orig_len) to make a truncated record."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            if isinstance(fr, tuple):
                fr, orig = fr
            else:
                orig = len(fr)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), orig))
            f.write(fr)
