#!/usr/bin/env python3
# Generates test/captures/mint_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MINT coverage captures. Usage: mkmint.py <outdir> [-v]
Synthetic (the MINT protocol is Motorola/Extreme WiNG's); addresses from
192.0.2.0/24 and 02:00:00:00:00:xx."""
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def eth(payload, ethertype=0x0800, src=1, dst=2):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', ethertype) + payload
def ipv4(payload, proto=17, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.')); d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload
def udp(payload, sport, dport):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def pcapng(fn, frames):
    """frames: list of (linktype index 0=Ethernet 1=Exported PDU, bytes)"""
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack('<HHI', 1, 0, 0))
    out += blk(1, struct.pack('<HHI', 252, 0, 0))
    for i, (ifc, fr) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(fn, 'wb').write(out)

def expdu(name, payload):
    n = name.encode()
    n += b'\0' * (-len(n) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload

def mint_hdr(port, unk1=0, ttl=1, unk2=0, dst=b'\x0a\0\0\x01', src=b'\x0a\0\0\x02', sport=None):
    return struct.pack('!BBH4s4sHH', unk1, ttl, unk2, dst, src, port, sport if sport is not None else port)

INNER = eth(ipv4(udp(b'inner data', 1000, 9)), 0x0800, 5, 6)
INNER_ARP = eth(b'\x00\x01\x08\x00\x06\x04\x00\x01' + bytes([2, 0, 0, 0, 0, 5]) + bytes([192, 0, 2, 5]) + bytes(6) + bytes([192, 0, 2, 6]), 0x0806, 5, 6)

def data(inner=INNER, u=b'\x00\x01'): return mint_hdr(1) + u + inner
def flood(inner=INNER, vlan=10, seq=0x01020304): return mint_hdr(2) + struct.pack('!HI', vlan, seq) + b'\0\0\0\x07' + inner
def tlv(t, v): return bytes([t, len(v)]) + v
def router(mtype, tlvs, hl=12, sender=b'\x0a\0\0\x03', extra=b'', pad=0):
    return (mint_hdr(12) + bytes(32) + bytes([0xaa, 0x02, 0x55, hl]) + mtype + sender + extra + b''.join(tlvs) + bytes(pad))
def neighbor(body): return mint_hdr(30) + bytes(32) + body
def mlcp(msg, tlvs): return mint_hdr(34) + bytes(32) + struct.pack('!H', msg) + b''.join(tlvs)
def other(port, body=b'payload!'): return mint_hdr(port) + body
def shim(m): return eth(struct.pack('!HH', 0, len(m)) + m, 0x8783, 7, 8)
def UD(m, dp=24576, sp=24576): return eth(ipv4(udp(m, sp, dp)))

frames = []   # (interface, bytes)
ranges = []
def add(fr, ifc=0): frames.append((ifc, fr))
def mark(name): ranges.append((name, len(frames) + 1))

PORTS = [0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
         40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 131, 132, 133, 134, 135, 136, 138, 140, 142]

def build():
    mark('data frames: UDP 24576/24577, Ethernet shim, Exported PDU mint_data')
    add(UD(data()))
    add(UD(data(INNER_ARP), 24577, 24577))
    add(shim(data()))
    add(shim(data(INNER_ARP)))
    add(eth(b'', 0x8783, 7, 8)[:0] + shim(data(b'')))                       # no Ethernet frame after the header
    add(expdu('mint_data', data()), 1)
    add(expdu('mint_data', data(INNER_ARP)), 1)
    add(UD(flood()))
    add(shim(flood(INNER_ARP, 0, 0xffffffff)))
    add(expdu('mint_data', flood()), 1)
    add(expdu('mint_control', flood()), 1)
    add(expdu('mint_eth', struct.pack('!HH', 0, len(data())) + data()), 1)

    mark('router (IS-IS like) messages')
    el_csnp = bytes(range(12)) * 2
    add(UD(router(b'CSNP', [tlv(1, bytes(range(12)) * 2), tlv(2, b'\x01\x02')])))
    add(UD(router(b'CSNP', [bytes([1, 128, 24]) + el_csnp, tlv(3, b'x')])))   # array indicator
    add(UD(router(b'HELO', [tlv(1, b'\x0a\0\0\x03'), tlv(8, b'\xc0\x00\x02\x01')])))
    add(UD(router(b'HELO', [bytes([1, 128, 4]) + b'\x0a\0\0\x04', tlv(9, b'')])))
    add(UD(router(b'LSP\0', [tlv(1, bytes(range(16))), tlv(8, b'\x0a\0\0\x03abcd'), tlv(1, b'')])))
    add(UD(router(b'PSNP', [tlv(1, bytes(range(8))), tlv(2, b'ab')])))
    add(UD(router(b'XXXX', [tlv(1, b'abc'), tlv(2, b'')])))
    add(UD(router(b'HELO', [tlv(1, b'\x0a\0\0\x03')], hl=20, extra=bytes(8))))   # longer header
    add(UD(router(b'HELO', [], pad=2)))
    add(shim(router(b'HELO', [tlv(1, b'\x0a\0\0\x03'), tlv(8, b'\xc0\x00\x02\x01')])))

    mark('neighbor and MLCP')
    add(UD(neighbor(b'neighbor data bytes')))
    add(UD(neighbor(b'')))
    add(UD(mlcp(0x0103, [tlv(1, b'\x0a\0\0\x01'), tlv(2, b'name'), tlv(0x22, b'')])))
    add(UD(mlcp(0x0201, [tlv(5, bytes(6)), tlv(6, b'\x00')])))
    add(shim(mlcp(0x0103, [tlv(1, b'abcd')])))
    add(UD(mlcp(0x0100, [])))

    mark('every port of the port table and unknown ports (UDP control, shim)')
    for p in PORTS:
        if p in (1, 2, 12, 30, 34): continue
        add(UD(other(p)))
    for p in (4, 99, 200, 255):
        add(UD(other(p)))
    for p in (3, 8, 20, 61):
        add(shim(other(p)))
    for p in (3, 20):
        add(expdu('mint_data', other(p)), 1)
        add(expdu('mint_control', other(p)), 1)

def build_malformed():
    out = []
    # MINT inside the transported Ethernet frame of a MINT data frame: nesting is bounded
    inner = bytes(8)
    for i in range(1800):
        mint = mint_hdr(1) + b'\0\0' + inner
        inner = eth(struct.pack('!HH', 0, len(mint) & 0xffff) + mint, 0x8783)
    out.append((0, inner))
    out.append((0, shim(data(INNER[:20]))))                              # transported frame cut short: exception shown, continues
    out.append((0, shim(data(eth(b'', 0x0800)[:10]))))                   # Ethernet header cut short
    out.append((0, UD(mint_hdr(1)[:10])))                              # header cut
    out.append((0, UD(mint_hdr(12) + bytes(10))))                       # control frame cut
    out.append((0, UD(router(b'HELO', [bytes([1, 250]) + b'abc']))))    # TLV longer than the frame: stops
    out.append((0, UD(router(b'CSNP', [bytes([1, 128])]))))             # array indicator, length missing
    out.append((0, UD(router(b'HELO', [], hl=250))))                    # header length past the end
    out.append((0, UD(mlcp(0x0103, [bytes([1, 200]) + b'abc']))))       # TLV longer than the frame
    out.append((0, UD(mlcp(0x0103, [bytes([7])] ))))
    out.append((0, UD(neighbor(b'')[:20])))
    out.append((0, UD(mint_hdr(2) + b'\0\0\0')))                        # data-flood header cut
    out.append((0, shim(data(b''))[:20]))
    out.append((0, eth(struct.pack('!HH', 0, 1000) + mint_hdr(1) + b'\0\0', 0x8783)))   # shim length beyond the frame
    out.append((0, eth(b'\0\0', 0x8783)))                                # shim cut
    return out

build()

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcapng(os.path.join(out, 'mint-coverage.pcapng'), frames)
    pcapng(os.path.join(out, 'mint-coverage-malformed.pcapng'), build_malformed())
    if '-v' in sys.argv:
        for n, s in ranges: print(n, s)
        print(len(frames), 'frames')
