#!/usr/bin/env python3
# Generates test/captures/data_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate a synthetic capture that exercises the raw data dissector
(packet-data.c).

"Data" is what every dissector hands bytes to when nothing else claims
them. The capture holds payloads that no other dissector takes: UDP and
TCP payloads on unassigned ports, an unknown IP protocol and an unknown
Ethertype, plain text, zlib compressed text and binary, invalid UTF-8,
a one octet payload, a frame cut by the snapshot length and a DCCP
packet without payload, which hands the data dissector an empty tvb. Every packet is built
from scratch with struct (and zlib); nothing comes from a real network.

Usage: mkdata.py <output directory>

Writes:
  data-coverage.pcap   the capture (the data dissector has no malformed
                       paths: it never reads past the captured data)
"""

import os
import struct
import sys
import zlib

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([198, 51, 100, 2])
SPORT = 50123
DPORT = 47999      # unassigned, no dissector or heuristic takes it


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ip4(proto, payload, src=IP_A, dst=IP_B, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     src, dst)
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + payload


def eth(payload, etype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', etype) + payload


def udp(payload, sport=SPORT, dport=DPORT, src=IP_A, dst=IP_B, ident=1):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, len(u))
    c = csum(pseudo + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    return eth(ip4(17, u, src, dst, ident))


def tcp(payload, seq, ack, flags, sport, dport, src, dst, ident):
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                    65535, 0, 0) + opts + payload
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(t))
    c = csum(pseudo + t)
    t = t[:16] + struct.pack('>H', c) + t[18:]
    smac, dmac = (MAC_A, MAC_B) if src == IP_A else (MAC_B, MAC_A)
    return eth(ip4(6, t, src, dst, ident), src=smac, dst=dmac)


def dccp(payload, ident):
    # DCCP-Data with extended sequence numbers and no options. DCCP hands
    # the rest of the packet to the data dissector even when it is empty.
    d = bytearray(struct.pack('>HHBBHBB', SPORT, DPORT, 4, 0, 0, (2 << 1) | 1, 0)
                  + (1).to_bytes(6, 'big') + payload)
    pseudo = struct.pack('>4s4sBBH', IP_A, IP_B, 0, 33, len(d))
    struct.pack_into('>H', d, 6, csum(pseudo + bytes(d)))
    return eth(ip4(33, bytes(d), ident=ident))


def write_pcap(path, frames, snaplen=65535):
    """frames: list of bytes, or (bytes, captured length) for a cut frame"""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, 1))
        for i, fr in enumerate(frames):
            caplen = len(fr)
            if isinstance(fr, tuple):
                fr, caplen = fr
            f.write(struct.pack('<IIII', 1700000000 + i, 0, caplen, len(fr)))
            f.write(fr[:caplen])


TEXT = (b'Synthetic payload for the Wireshark data dissector. '
        b'No dissector claims this port, so it is shown as Data.\n')
ZTEXT = b'Compressed text: ' + b'the quick brown fox jumps over the lazy dog. ' * 4
BINARY = bytes((i * 37 + 11) & 0xff for i in range(200))


def frames():
    f = []
    # 1: plain ASCII text over UDP
    f.append(udp(TEXT, ident=1))
    # 2: zlib compressed text (shown as text from the uncompressed data)
    f.append(udp(zlib.compress(ZTEXT, 9), ident=2))
    # 3: zlib compressed binary data
    f.append(udp(zlib.compress(BINARY, 9), ident=3))
    # 4: binary data that is not UTF-8 and not zlib (uncompressing fails)
    f.append(udp(b'\xff\xfe\x80\x81' + BINARY[:60], ident=4))
    # 5: a zlib stream of an empty input (uncompresses to nothing)
    f.append(udp(zlib.compress(b''), ident=5))
    # 6: one octet ("Data (1 byte)")
    f.append(udp(b'\x7f', ident=6))
    # 7: UTF-8 text with multi-octet characters
    f.append(udp('Grüße, ℵ₀ — café ☕\n'.encode('utf-8'), ident=7))
    # 8: unknown IP protocol 253 (RFC 3692 experimentation)
    f.append(eth(ip4(253, b'experimental protocol 253 payload', ident=8)))
    # 9: unknown Ethertype 0x88b5 (IEEE 802 local experimental)
    f.append(eth(b'local experimental ethertype 0x88b5 payload....', etype=0x88b5))
    # 10: UDP datagram cut by the snapshot length right after the UDP
    #     header: the data dissector gets a tvb with no captured octets
    fr = udp(TEXT[:40], ident=10)
    f.append((fr, 14 + 20 + 8))
    # 11: DCCP-Data without payload: the data dissector gets an empty tvb
    f.append(dccp(b'', 11))
    # 12-14: TCP handshake on an unassigned port, 15: data, 16: ack
    cs, ss = 7000, 9000
    a = dict(sport=SPORT + 1, dport=DPORT, src=IP_A, dst=IP_B)
    b = dict(sport=DPORT, dport=SPORT + 1, src=IP_B, dst=IP_A)
    f.append(tcp(b'', cs, 0, 0x02, ident=12, **a))
    f.append(tcp(b'', ss, cs + 1, 0x12, ident=13, **b))
    f.append(tcp(b'', cs + 1, ss + 1, 0x10, ident=14, **a))
    payload = zlib.compress(b'TCP stream payload, compressed. ' * 3)
    f.append(tcp(payload, cs + 1, ss + 1, 0x18, ident=15, **a))
    f.append(tcp(b'', ss + 1, cs + 1 + len(payload), 0x10, ident=16, **b))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'data-coverage.pcap'), frames())


if __name__ == '__main__':
    main()
