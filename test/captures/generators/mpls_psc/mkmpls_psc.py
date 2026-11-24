#!/usr/bin/env python3
# Generates test/captures/mpls_psc_coverage.pcapng.gz
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
# MPLS-TP Protection State Coordination (RFC 6378): packet-mpls-psc.c
# ---------------------------------------------------------------------
SECS = []
def sec(cap, name):
    SECS.append((len(cap.frames) + 1, name))

def psc(req=0, pt=2, rev=1, fpath=0, dpath=0, tlvlen=0, ver=0, res=0, extra=b''):
    return struct.pack('!BBBBB', (ver << 6) | (req << 2) | pt, (rev << 7) | res, fpath, dpath, tlvlen) + extra

def pscframe(body, gal_=True):
    return eth(gal(0x0024, body) if gal_ else stack(100) + ach(0x0024) + body, 0x8847)

def build_main():
    c = Cap()
    sec(c, 'every request code (0-15: assigned and unassigned), protection type 2, revertive')
    for req in range(16):
        c.add(pscframe(psc(req=req, fpath=1, dpath=1)))
    sec(c, 'protection types 0-3, revertive and non-revertive, fault and data path values')
    for pt in range(4):
        c.add(pscframe(psc(req=10, pt=pt, rev=pt & 1, fpath=pt, dpath=pt)))
    c.add(pscframe(psc(req=12, fpath=2, dpath=2)))
    c.add(pscframe(psc(req=14, fpath=255, dpath=255, rev=0)))
    sec(c, 'version 1-3, reserved bits, a TLV length and trailing TLV octets')
    c.add(pscframe(psc(req=5, ver=1, res=0x7f)))
    c.add(pscframe(psc(req=7, ver=3, tlvlen=4, extra=b'\x01\x02\x03\x04')))
    sec(c, 'without GAL: label stack and associated channel header (first nibble 1)')
    c.add(pscframe(psc(req=4, fpath=1, dpath=0), gal_=False))
    return c

def build_malformed():
    c = Cap()
    sec(c, 'cut short')
    c.add(pscframe(b'\x28\x80\x01'))     # only 3 octets
    c.add(pscframe(b'\x28\x80\x01\x01'))  # TLV length missing
    c.add(pscframe(b''))
    return c

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    c = build_main()
    c.write(os.path.join(out, 'mpls-psc-coverage.pcapng'))
    nmain = len(c.frames)
    main_secs = list(SECS); del SECS[:]
    m = build_malformed()
    m.write(os.path.join(out, 'mpls-psc-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for s, n in main_secs: print('main frame %d: %s' % (s, n))
        print('main frames:', nmain)
        for s, n in SECS: print('malformed frame %d: %s' % (s, n))
        print('malformed frames:', len(m.frames))
