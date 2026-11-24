#!/usr/bin/env python3
# Generates test/captures/mpls_pm_coverage.pcapng.gz
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
# MPLS performance monitoring (RFC 6374): packet-mpls-pm.c
# ---------------------------------------------------------------------
SECS = []
def sec(cap, name):
    SECS.append((len(cap.frames) + 1, name))

def ts(fmt, n=1):
    '''an 8 octet timestamp in the given format: 0 null, 1 sequence number, 2 NTP, 3 PTP'''
    if fmt == 0: return Z8
    if fmt == 1: return struct.pack('!Q', 1000 * n)
    if fmt == 2: return struct.pack('!II', 0xe8000000 + n, 0x40000000)
    if fmt == 3: return struct.pack('!II', 1700000000 + n, 123456789)
    return struct.pack('!Q', 0xdeadbeef00000000 + n)
Z8 = b'\0' * 8
def ctr(*v): return b''.join(struct.pack('!Q', x) for x in v)
CTR = ctr(1001, 2002, 3003, 4004)

def hdr(resp, tflag, code, length):
    return struct.pack('!BBH', (0 << 4) | (8 if resp else 0) | (4 if tflag else 0), code, length)
def sid_word(sid, tflag, ds=0):
    return struct.pack('!I', (sid << 6 | ds) if tflag else sid)

def loss(resp=False, t=False, x=False, b=False, otf=2, sid=77, ds=0, code=1, counters=CTR, dres=0):
    dflags = (0x80 if x else 0) | (0x40 if b else 0) | dres | otf
    return hdr(resp, t, code, 52) + bytes([dflags, 0, 0, 0]) + sid_word(sid, t, ds) + ts(otf) + counters

def delay(resp=False, t=False, qtf=2, rtf=2, rptf=2, sid=77, ds=0, code=1, tss=None, flagsres=0):
    tss = tss or [ts(qtf, 1), ts(qtf, 2), Z8, Z8] if not resp else (tss or [ts(rtf, 1), Z8, ts(qtf, 3), ts(qtf, 4)])
    h = hdr(resp, t, code, 44)
    h = bytes([h[0] | flagsres]) + h[1:]
    return h + bytes([(qtf << 4) | rtf, rptf << 4, 0, 0]) + sid_word(sid, t, ds) + b''.join(tss)

def comb(resp=False, t=False, b=False, x=False, qtf=2, rtf=2, rptf=2, sid=77, ds=0, code=1, counters=CTR, tss=None):
    tss = tss or ([ts(qtf, 1), ts(qtf, 2), Z8, Z8] if not resp else [ts(rtf, 1), Z8, ts(qtf, 3), ts(qtf, 4)])
    dflags = (0x80 if x else 0) | (0x40 if b else 0) | qtf
    return (hdr(resp, t, code, 76) + bytes([dflags, (rtf << 4) | rptf, 0, 0]) + sid_word(sid, t, ds) +
            b''.join(tss) + counters)

def p(chan, body, gal_=True):
    return eth(gal(chan, body) if gal_ else stack(100) + ach(chan) + body, 0x8847)

def build_main():
    c = Cap()
    sec(c, 'DLM (0x000A): queries with every origin timestamp format; responses; flags X, B, T; sessions with DS')
    for otf in (0, 1, 2, 3, 7):
        c.add(p(0x000A, loss(otf=otf)))
    c.add(p(0x000A, loss(resp=True, code=1, x=True)))
    c.add(p(0x000A, loss(resp=True, code=0x10, b=True, t=True, sid=5, ds=46, otf=3)))
    c.add(p(0x000A, loss(t=True, sid=1048575, ds=63, b=True, otf=1, dres=0x30)))
    c.add(p(0x000A, loss(resp=True, code=0x3f, otf=0)))
    sec(c, 'ILM (0x000B)')
    c.add(p(0x000B, loss()))
    c.add(p(0x000B, loss(resp=True, code=4, otf=1)))
    c.add(p(0x000B, loss(resp=True, code=0xff, b=True, t=True, ds=8)))
    sec(c, 'DM (0x000C): query and response with every querier/responder timestamp format')
    for q in (0, 1, 2, 3, 7):
        c.add(p(0x000C, delay(qtf=q, rtf=q)))
    for r in (0, 1, 2, 3, 7):
        c.add(p(0x000C, delay(resp=True, qtf=2, rtf=r, rptf=r, code=1)))
    c.add(p(0x000C, delay(resp=True, t=True, ds=34, qtf=3, rtf=3, rptf=3, code=0x1d, sid=999)))
    c.add(p(0x000C, delay(t=True, ds=10, flagsres=3, code=2)))
    sec(c, 'DLM+DM (0x000D) and ILM+DM (0x000E): queries and responses, all timestamp formats, counters in octets')
    for q in (0, 1, 2, 3, 7):
        c.add(p(0x000D, comb(qtf=q, rtf=q, rptf=q)))
    for r in (0, 1, 2, 3, 7):
        c.add(p(0x000D, comb(resp=True, qtf=2, rtf=r, rptf=r, code=1)))
    c.add(p(0x000D, comb(resp=True, t=True, ds=63, b=True, x=True, code=0x11)))
    c.add(p(0x000E, comb(t=True, ds=1)))
    c.add(p(0x000E, comb(qtf=1, rtf=1, rptf=1, b=True)))
    c.add(p(0x000E, comb(resp=True, qtf=3, rtf=3, rptf=3, code=0x19)))
    sec(c, 'without GAL: label stack and associated channel header (first nibble 1)')
    c.add(p(0x000A, loss(), gal_=False))
    c.add(p(0x000C, delay(resp=True, rtf=3, rptf=3), gal_=False))
    return c

def build_malformed():
    c = Cap()
    sec(c, 'F5: combined response with RTF 3 (PTP) and RPTF 1 (sequence number): the dissector uses RPTF')
    c.add(p(0x000D, comb(resp=True, qtf=2, rtf=3, rptf=1)))
    c.add(p(0x000E, comb(resp=True, qtf=0, rtf=2, rptf=0)))
    sec(c, 'cut short')
    c.add(p(0x000A, loss()[:30]))
    c.add(p(0x000C, delay()[:20]))
    c.add(p(0x000D, comb()[:60]))
    c.add(p(0x000B, b'\x08'))
    c.add(p(0x000C, b'\x00'))
    return c

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    c = build_main()
    c.write(os.path.join(out, 'mpls-pm-coverage.pcapng'))
    nmain = len(c.frames)
    main_secs = list(SECS); del SECS[:]
    m = build_malformed()
    m.write(os.path.join(out, 'mpls-pm-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for s, n in main_secs: print('main frame %d: %s' % (s, n))
        print('main frames:', nmain)
        for s, n in SECS: print('malformed frame %d: %s' % (s, n))
        print('malformed frames:', len(m.frames))
