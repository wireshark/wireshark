#!/usr/bin/env python3
# Generates test/captures/ndp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# NDP (packet-ndp.c, Nortel Discovery Protocol) synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import os
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())
def write_pcapng(name, items):
    '''items: (linktype, frame). One interface per link type.'''
    def block(btype, body):
        body += bytes(-len(body) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifaces = {}
    for lt in sorted(set(l for l, _ in items)):
        ifaces[lt] = len(ifaces)
        out += block(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, f) in enumerate(items):
        ts = 1700000000 * 1000000 + i * 1000
        out += block(6, struct.pack('<IIIII', ifaces[lt], ts >> 32, ts & 0xffffffff, len(f), len(f)) + f)
    with open(name, 'wb') as fh:
        fh.write(out)

# ---- Nortel Discovery Protocol (SONMP): 802.3 frame, LLC SNAP with the
# Nortel OUI 00-00-81 and PID 0x01a1 (flatnet hello) or 0x01a2 (segment
# hello). The destination 01:00:81:00:01:00 is the segment hello group and
# 01:00:81:00:01:01 the flatnet one; the last byte of the destination
# gives the "Segment" or "FlatNet" prefix of the info column.
SEG = bytes.fromhex('010081000100')
FLAT = bytes.fromhex('010081000101')
OUI_NORTEL = b'\x00\x00\x81'

def hello(ip=(10, 0, 0, 1), seg=0x010203, chassis=40, backplane=2, state=2, links=4, extra=b''):
    return bytes(ip) + seg.to_bytes(3, 'big') + bytes([chassis, backplane, state, links]) + extra

def llc(pid, payload):
    return bytes([0xaa, 0xaa, 0x03]) + OUI_NORTEL + struct.pack('>H', pid) + payload

def frame(dst, pid, payload, src=bytes.fromhex('020000000001'), pad=True):
    body = llc(pid, payload)
    f = dst + src + struct.pack('>H', len(body)) + body
    if pad and len(f) < 60:
        f += bytes(60 - len(f))
    return f

items = []
def add(*a, **k):
    items.append((1, frame(*a, **k)))

add(SEG, 0x01a2, hello())                                   # segment hello
add(FLAT, 0x01a1, hello(ip=(10, 0, 0, 2), seg=0x0a0b0c, chassis=48, backplane=10, state=1, links=24))   # flatnet hello
add(SEG, 0x01a1, hello(ip=(10, 0, 0, 3)))                   # PID of the flatnet hello to the segment group
add(FLAT, 0x01a2, hello(ip=(10, 0, 0, 4)))
add(bytes.fromhex('010081000102'), 0x01a2, hello(ip=(10, 0, 0, 5)))      # other group address: no prefix
add(bytes.fromhex('ffffffffffff'), 0x01a1, hello(ip=(10, 0, 0, 6)))      # broadcast: no prefix
# chassis types: first, some with names, the gaps (19, 30, 47), the last and unknown
for ch in (1, 2, 12, 18, 19, 29, 30, 31, 47, 48, 81, 99, 162, 163, 213, 214, 255, 0):
    add(SEG, 0x01a2, hello(chassis=ch, ip=(10, 1, 0, ch & 0xff)))
# backplane types: every defined value, 0 and unknown
for bp in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 13, 255):
    add(SEG, 0x01a2, hello(backplane=bp, ip=(10, 2, 0, bp)))
# states: the three defined values and unknown
for st in (1, 2, 3, 0, 4, 255):
    add(FLAT, 0x01a1, hello(state=st, ip=(10, 3, 0, st)))
# segment identifiers and link counts
for seg, links in ((0, 0), (0xffffff, 255), (0x123456, 1), (0x000001, 128)):
    add(SEG, 0x01a2, hello(seg=seg, links=links, ip=(192, 0, 2, links)))
# trailing data after the 11 bytes
add(SEG, 0x01a2, hello(extra=b'trailing data after the hello' * 2))
# a hello inside a Linux cooked capture frame (no Ethernet destination address):
# packet type 0 (to us), ARPHRD_ETHER, protocol 0x0004 (802.2 LLC)
def sll(payload):
    return struct.pack('>HHH8sH', 0, 1, 6, bytes.fromhex('020000000001') + bytes(2), 0x0004) + payload
items.append((113, sll(llc(0x01a2, hello(ip=(10, 4, 0, 1))))))
items.append((113, sll(llc(0x01a1, hello(ip=(10, 4, 0, 2))))))
main = items
items = []

# ---- malformed: the 11 byte hello is cut short (frames are not padded)
add(SEG, 0x01a2, hello()[:10], pad=False)
add(FLAT, 0x01a1, hello()[:7], pad=False)
add(SEG, 0x01a2, hello()[:4], pad=False)
add(SEG, 0x01a2, b'', pad=False)
items.append((113, sll(llc(0x01a2, hello()[:6]))))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'ndp-coverage.pcapng'), main)
    gz(os.path.join(out, 'ndp-coverage.pcapng'))
    os.rename(os.path.join(out, 'ndp-coverage.pcapng.gz'), os.path.join(out, 'ndp_coverage.pcapng.gz'))
    write_pcapng(os.path.join(out, 'ndp-coverage-malformed.pcapng'), items)
