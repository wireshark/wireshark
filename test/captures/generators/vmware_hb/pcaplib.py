# Helper module for the vmware_hb capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Small helpers for the generators of this batch: pcapng writer, checksum,
# Ethernet/IPv4/ICMP/UDP/ARP builders (synthetic addresses from 192.0.2.0/24).
import struct


def _block(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)


def write_pcapng(fn, linktypes, packets, snaplen=262144):
    """linktypes: one interface each; packets: list of (interface, data)."""
    out = _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _block(1, struct.pack('<HHI', lt, 0, snaplen))
    for i, (ifid, data) in enumerate(packets):
        ts = 1000000000 + i * 1000
        out += _block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(fn, 'wb') as f:
        f.write(out)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def mac(n):
    return bytes([2, 0, 0, 0, 0, n])


def eth(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack('>H', etype) + payload


def ipv4(proto, payload, src=1, dst=2, ipid=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ipid, 0, 64, proto, 0,
                    bytes([192, 0, 2, src]), bytes([192, 0, 2, dst]))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def icmp_echo(seq=1, data=b'0123456789abcdef', reply=False):
    h = struct.pack('>BBHHH', 0 if reply else 8, 0, 0, 0x1234, seq) + data
    return h[:2] + struct.pack('>H', csum(h)) + h[4:]


def udp(sport, dport, data):
    return struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data


def arp(op=1, sha=1, spa=1, tha=0, tpa=2):
    return struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, op, mac(sha), bytes([192, 0, 2, spa]),
                       mac(tha), bytes([192, 0, 2, tpa]))


def ip_ping(src=1, dst=2, seq=1):
    return ipv4(1, icmp_echo(seq), src, dst)
