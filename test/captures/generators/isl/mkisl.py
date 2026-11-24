#!/usr/bin/env python3
# Generates test/captures/isl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the ISL (Cisco Inter-Switch Link) coverage captures.
# Usage: mkisl.py <outdir>. Everything is synthetic (documentation addresses).
import struct
import sys
import os
import zlib


def write_pcap(fn, linktype, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def eth(etype, payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('!H', etype) + payload


def tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def eth_ip_tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return eth(0x0800, ipv4(6, tcp(sport, dport, payload, seq, ack, flags)))


def eth_ip_udp(sport, dport, payload):
    return eth(0x0800, ipv4(17, udp(sport, dport, payload)))


ISL_DST = b'\x01\x00\x0c\x00\x00\x00'
ISL_SRC = b'\x02\x00\x00\x00\x00\x0a'


def fcs(b):
    return struct.pack('<I', zlib.crc32(b) & 0xffffffff)


def isl(type_user, inner, vlan=100, bpdu=0, index=3, reserved=0, length=None,
        trailer=b'', dst=ISL_DST, src=ISL_SRC, hsa=b'\x00\x00\x0c'):
    """ISL header (26 octets: 14 + the 12 octet part counted by length) +
    the encapsulated frame + trailer (ISL CRC). length counts the 12 octets
    after the length field plus the encapsulated frame."""
    if length is None:
        length = 12 + len(inner)
    d = dst[:5] + bytes([type_user])
    h = d + src + struct.pack('!H', length)
    h += b'\xaa\xaa\x03' + hsa + struct.pack('!HHH', (vlan << 1) | bpdu, index, reserved)
    return h + inner + trailer


def icmp(seq, payload=b''):
    m = struct.pack('!BBHHH', 0, 0, 0, 1, seq) + payload
    return m[:2] + struct.pack('!H', csum(m)) + m[4:]


def inner_eth(payload=b'', seq=0, withfcs=True):
    ip = ipv4(1, icmp(seq, payload))
    f = eth(0x0800, ip, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01')
    return f + fcs(f) if withfcs else f


def tr_frame(payload, rif=False):
    ac_fc = b'\x10\x40'
    dst = b'\x02\0\0\0\0\x02'
    src = b'\x02\0\0\0\0\x01'
    llc = b'\xaa\xaa\x03\x00\x00\x00\x08\x00'
    if rif:
        src = bytes([src[0] | 0x80]) + src[1:]
        rifb = b'\x04\x30\x01\x42'
        return ac_fc + dst + src + rifb + llc + payload
    return ac_fc + dst + src + llc + payload


def write_malformed(outdir):
    frames = []
    # 1: length 12, no encapsulated frame
    frames.append(isl(0x00, b'', vlan=4094, length=12))
    # 2: length below 12: no encapsulated frame is dissected
    frames.append(isl(0x00, b'', vlan=5, length=8))
    # 3: length larger than the data in the frame (no trailer, bounds error)
    inner = inner_eth(b'x' * 8, 3)
    frames.append(isl(0x00, inner[:30], vlan=6, length=12 + len(inner) + 60))
    # 4: encapsulated frame cut short (Ethernet header incomplete)
    frames.append(isl(0x00, inner[:9], vlan=7, length=12 + 9))
    # 5: only the first 26 octets, Token-Ring in ISL with no Token-Ring frame
    frames.append(isl(0x10, b'', vlan=8, length=12)[:26])
    # 6: Token-Ring in ISL with a truncated Token-Ring frame
    frames.append(isl(0x10, b'', vlan=9, length=12 + 5 + 10) + bytes(5 + 10))
    # 7: nested ISL, 600 levels (Ethernet -> ISL -> Ethernet -> ISL ...)
    inner = inner_eth(b'deep', 7)
    # (length 0 in every header, since a length above 1500 is no longer
    # recognised as ISL)
    for v in range(600):
        inner = isl(0x00, inner, vlan=v % 4000 + 1, length=0)
    frames.append(inner)
    write_pcap(os.path.join(outdir, 'isl-coverage-malformed.pcap'), 1, frames)


def main(outdir):
    frames = []
    ip_payload = b'ISL coverage'
    # 1-4: Ethernet in ISL, VLAN, all four user priorities (type 0)
    for i, user in enumerate((0, 1, 2, 3)):
        inner = inner_eth(ip_payload, i)
        frames.append(isl(0x00 | user, inner, vlan=100 + i, bpdu=0, index=i,
                          trailer=fcs(inner)))
    # 5: BPDU/CDP/VTP bit and reserved value set
    inner = inner_eth(ip_payload, 5)
    frames.append(isl(0x00, inner, vlan=1, bpdu=1, index=0xffff,
                      reserved=0x1234, trailer=fcs(inner)))
    # 6: no ISL trailer after the encapsulated frame
    inner = inner_eth(ip_payload, 6)
    frames.append(isl(0x00, inner, vlan=200))
    # 7: length field 0: everything after the first 14 octets is payload
    inner = inner_eth(ip_payload, 7)
    frames.append(isl(0x00, inner, vlan=300, length=0))
    # 10, 11: Token-Ring in ISL (type 1): user bits, VLAN, explorer, esize,
    # route descriptors, FCS not included; without and with a RIF
    for i, rif in enumerate((False, True)):
        trf = tr_frame(ipv4(1, icmp(10 + i)), rif)
        hdr = isl(0x10 | 0x05, b'', vlan=10 + i, index=7, reserved=0,
                  length=17 + len(trf))[:14 + 10]
        hdr += struct.pack('!HHHB', (0x123 << 1) | i, 0x0abc, 0x0def, (0x40 * i) | (0x0f + 0x12 * i))
        frames.append(hdr + trf)
    # 12, 13: FDDI (2) and ATM (3): the payload is shown as data
    for t in (2, 3):
        frames.append(isl(t << 4 | 0x0a, b'\xde\xad\xbe\xef' * 4, vlan=20 + t))
    # 12: ISL inside ISL inside ISL (the encapsulated frame is dissected as
    # Ethernet with FCS, which recognises ISL again)
    inner = inner_eth(ip_payload, 14)
    for v in (402, 401, 400):
        inner = isl(0x00, inner, vlan=v)
        inner += fcs(inner)
    frames.append(inner)
    # 13: an 8 octet trailer instead of the 4 octet ISL CRC
    inner = inner_eth(ip_payload, 13)
    frames.append(isl(0x00, inner, vlan=500, trailer=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
    write_pcap(os.path.join(outdir, 'isl-coverage.pcap'), 1, frames)
    write_malformed(outdir)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
