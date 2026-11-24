#!/usr/bin/env python3
# Generates test/captures/mpls_y1711_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared packet-building helpers (inlined into each mk<proto>.py).
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

class Cap:
    '''pcapng writer: interfaces are linktypes (1 Ethernet, 9 PPP, 104 Cisco HDLC)'''
    def __init__(self, links=(1,)):
        self.links = list(links)
        self.frames = []
    def add(self, data, link=1, comment=None):
        self.frames.append((self.links.index(link), bytes(data)))
        return len(self.frames)
    @staticmethod
    def _blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    def write(self, fname):
        out = self._blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for l in self.links:
            out += self._blk(1, struct.pack('<HHI', l, 0, 65535))
        ts = 1700000000 * 1000000
        for i, (ifc, d) in enumerate(self.frames):
            t = ts + i * 1000
            out += self._blk(6, struct.pack('<IIIII', ifc, t >> 32, t & 0xffffffff, len(d), len(d)) + d)
        with open(fname, 'wb') as f:
            f.write(out)

def eth(payload, etype=0x0800, dst='020000000002', src='020000000001'):
    return bytes.fromhex(dst + src) + struct.pack('!H', etype) + payload

def ipv4(payload, proto=17, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ident=1, ttl=64):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + payload

def ipv6(payload, nxt=17, src=b'\x20\x01\x0d\xb8' + b'\0' * 11 + b'\x01',
         dst=b'\x20\x01\x0d\xb8' + b'\0' * 11 + b'\x02'):
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, 64) + src + dst + payload

def udp(payload, sport=1024, dport=9):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def ipv4_udp(payload, sport=1024, dport=9, **kw):
    return ipv4(udp(payload, sport, dport), 17, **kw)

def ipv6_udp(payload, sport=1024, dport=9,
             src=b'\x20\x01\x0d\xb8' + b'\0' * 11 + b'\x01',
             dst=b'\x20\x01\x0d\xb8' + b'\0' * 11 + b'\x02'):
    u = udp(payload, sport, dport)
    ck = csum(src + dst + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u) or 0xffff
    u = u[:6] + struct.pack('!H', ck) + u[8:]
    return ipv6(u, 17, src, dst)

def label(lbl, exp=0, bos=0, ttl=64):
    return struct.pack('!I', (lbl << 12) | (exp << 9) | (bos << 8) | ttl)

def stack(*labels):
    '''labels: ints (label values) or (label, exp, bos, ttl) tuples; the last gets S=1'''
    out = b''
    for i, l in enumerate(labels):
        last = i == len(labels) - 1
        if isinstance(l, tuple):
            out += label(*l)
        else:
            out += label(l, 0, 1 if last else 0, 64)
    return out

def ach(chan, ver=1, res=0, nibble=1):
    return struct.pack('!BBH', (nibble << 4) | ver, res, chan)

def gal(chan, body=b'', ver=1, res=0, ttl=1, exp=0):
    '''GAL label (13, S=1) + associated channel header + body'''
    return label(13, exp, 1, ttl) + ach(chan, ver, res) + body

def mplsfr(payload, etype=0x8847):
    return eth(payload, etype)

# ---------------------------------------------------------------------
# ITU-T Y.1711 MPLS OAM (label 14): packet-mpls-y1711.c
# ---------------------------------------------------------------------
SECS = []
def sec(cap, name):
    SECS.append((len(cap.frames) + 1, name))

Z = lambda n: b'\0' * n
LSR = bytes([192, 0, 2, 1])
def cv(res=Z(3), p10=Z(10), ff=b'\xff\xff', lsr=LSR, lsp=7, p18=Z(18), bip=0x1234):
    return bytes([1]) + res + p10 + ff + lsr + struct.pack('!I', lsp) + p18 + struct.pack('!H', bip)
def fdi(ftype=2, res=Z(1), dtype=0x0201, ttsi=None, loc=65001, p14=Z(14), bip=0x4321):
    if ttsi is None:
        ttsi = Z(10) + b'\xff\xff' + LSR + struct.pack('!I', 9)
    return bytes([ftype]) + res + struct.pack('!H', dtype) + ttsi + struct.pack('!I', loc) + p14 + struct.pack('!H', bip)
def fdd(freq=3, res=Z(3), p10=Z(10), ff=b'\xff\xff', p17=Z(17), bip=0xabcd):
    return bytes([7]) + res + p10 + ff + LSR + struct.pack('!I', 5) + bytes([freq]) + p17 + struct.pack('!H', bip)
def unknown(t, fill=0):
    return bytes([t]) + bytes([fill]) * 43

def y(payload, lbl=14, exp=0, bos=1, ttl=1):
    return eth(label(lbl, exp, bos, ttl) + payload, 0x8847)

def build_main():
    c = Cap()
    sec(c, 'CV, FDI, BDI, FDD with clean fields')
    c.add(y(cv()))
    c.add(y(fdi(2)))
    c.add(y(fdi(3, dtype=0x0102)))
    c.add(y(fdd(3)))
    sec(c, 'FDI/BDI without TTSI (note), every defect type; FDD frequencies')
    for dt in (0x0000, 0x0101, 0x0202, 0x0203, 0x0204, 0x02ff, 0xffff, 0x1234):
        c.add(y(fdi(2, dtype=dt, ttsi=Z(20))))
    for fr in (0, 1, 2, 4, 5, 6, 7, 255):
        c.add(y(fdd(fr)))
    sec(c, 'warnings: reserved and padding octets not zero')
    c.add(y(cv(res=b'\x01\x02\x03', p10=b'\x01' + Z(9), p18=Z(17) + b'\x01')))
    c.add(y(fdi(2, res=b'\x05', p14=Z(13) + b'\x01', ttsi=b'\x01' + Z(9) + b'\xff\xff' + LSR + struct.pack('!I', 9))))
    c.add(y(fdi(3, res=b'\x05', ttsi=Z(10) + b'\xff\xff' + LSR + struct.pack('!I', 9))))
    c.add(y(fdd(res=b'\x00\x00\x07', p10=b'\x02' + Z(9), p17=b'\x01' + Z(16))))
    sec(c, 'unknown function types and a PDU longer than 44 octets')
    for t in (0x00, 0x04, 0x05, 0x06, 0x08, 0x99):
        c.add(y(unknown(t)))
    c.add(y(cv() + b'\0' * 6))
    return c

def build_malformed():
    c = Cap(links=(1, 252))
    sec(c, 'payload shorter than 44 octets (error expert info and data)')
    c.add(y(cv()[:43]))
    c.add(y(b'\x01'))
    sec(c, 'F4: EXP not 0 or TTL not 1 puts expert infos at offset - 2/-1 of the subset tvb: exception')
    c.add(y(cv(), exp=3, ttl=64))
    c.add(y(fdi(), exp=0, ttl=2))
    c.add(y(fdd(), exp=1, ttl=1))
    sec(c, 'padding that must be 0xFF (error expert info)')
    c.add(y(cv(ff=b'\x00\x00')))
    c.add(y(fdi(2, ttsi=Z(10) + b'\x00\x00' + LSR + struct.pack('!I', 9))))
    c.add(y(fdd(ff=b'\x12\x34')))
    sec(c, 'Decode As mpls.label==700,mpls_y1711 (a label other than 14: expert info before the start)')
    c.add(eth(label(700, 0, 1, 1) + cv(), 0x8847))
    c.add(eth(label(701, 0, 1, 1) + cv(), 0x8847))
    sec(c, 'Exported PDU naming mpls_y1711: no MPLS information is passed to the dissector (it rejects the packet)')
    name = b'mpls_y1711\0\0'
    c.add(struct.pack('!HH', 12, len(name)) + name + struct.pack('!HH', 0, 0) + cv(), link=252)
    return c

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    c = build_main()
    c.write(os.path.join(out, 'mpls-y1711-coverage.pcapng'))
    nmain = len(c.frames)
    main_secs = list(SECS); del SECS[:]
    m = build_malformed()
    m.write(os.path.join(out, 'mpls-y1711-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for s, n in main_secs: print('main frame %d: %s' % (s, n))
        print('main frames:', nmain)
        for s, n in SECS: print('malformed frame %d: %s' % (s, n))
        print('malformed frames:', len(m.frames))
