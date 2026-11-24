#!/usr/bin/env python3
# Generates test/captures/mpls_coverage.pcapng.gz
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
# MPLS coverage captures (packet-mpls.c: MPLS, PW ACH, PW MCC, PW MCW)
# ---------------------------------------------------------------------
SECS = []
def sec(cap, name):
    SECS.append((len(cap.frames) + 1, name))

IP = ipv4_udp(b'mpls coverage payload')
IP6 = ipv6_udp(b'mpls coverage payload')
BFD_CTRL = bytes([0x20, 0x40, 3, 24]) + struct.pack('!IIIII', 0x11, 0x22, 1000000, 1000000, 0)
MEP_LSP = struct.pack('!HHIIHH', 1, 12, 7, 8, 9, 10)

def build_main():
    c = Cap(links=(1, 9, 104))
    sec(c, 'label stacks, EXP/BOS/TTL values and IP payloads')
    c.add(eth(stack(100) + IP, 0x8847))
    c.add(eth(stack((200, 5, 0, 255), (100, 0, 1, 1)) + IP6, 0x8847))
    # Ethernet trailer: the IPv4 dissector shortens the tvb, MPLS follows
    c.add(eth(stack(101) + IP + b'\0' * 12, 0x8847))
    c.add(eth(stack(300, 301, 302, 303) + IP, 0x8848))
    sec(c, 'reserved labels')
    c.add(eth(stack(0) + IP, 0x8847))
    c.add(eth(stack(2) + IP6, 0x8847))
    c.add(eth(stack(1, 3, 7, 5, 100) + IP, 0x8847))
    c.add(eth(stack(15) + IP, 0x8847))
    c.add(eth(stack(4, 6, 8, 9, 10, 11, 12, 1048575) + IP, 0x8847))
    sec(c, 'post-stack first nibble: other nibbles and Ethernet pseudowires')
    ethpw = eth(IP, 0x0800)
    c.add(eth(stack(400) + b'\0\0\0\1' + ethpw, 0x8847))               # nibble 0, CW
    c.add(eth(stack(401) + eth(IP, 0x0800, dst='2a0000000002'), 0x8847))   # nibble 2, heuristic
    c.add(eth(stack(402) + b'\x30\x00\x00\x00 unknown nibble 3', 0x8847))
    c.add(eth(stack(403) + b'\xf0\x01\x02\x03 unknown nibble 15', 0x8847))
    sec(c, 'post-stack first nibble 1 (PW associated channel header without GAL)')
    c.add(eth(stack(410) + ach(0x0021) + IP, 0x8847))
    c.add(eth(stack(411) + ach(0x0057) + IP6, 0x8847))
    c.add(eth(stack(412) + ach(0x7777, res=3) + b'abcdefgh', 0x8847))
    c.add(eth(stack(413) + ach(0x0001) + struct.pack('!H', 0x0021) + IP, 0x8847))
    sec(c, 'GAL (label 13) and the associated channel header')
    c.add(eth(gal(0x0021, IP), 0x8847))
    c.add(eth(gal(0x0057, IP6), 0x8847))
    c.add(eth(label(500, 0, 0, 64) + gal(0x7777, b'unknown channel type'), 0x8847))
    c.add(eth(gal(0x7ff8, b'experimental'), 0x8847))
    c.add(eth(gal(0x0001, struct.pack('!H', 0x0021) + IP), 0x8847))      # MCC carrying IPv4
    c.add(eth(gal(0x0001, struct.pack('!H', 0x0057) + IP6), 0x8847))     # MCC carrying IPv6
    c.add(eth(gal(0x0001, struct.pack('!H', 0x1234) + b'unknown mcc protocol'), 0x8847))
    c.add(eth(gal(0x0023, BFD_CTRL + MEP_LSP), 0x8847))                  # BFD CV: MEP TLV added
    c.add(eth(gal(0x0021, IP, res=7), 0x8847))                           # reserved byte not zero
    c.add(eth(label(100, 0, 0, 64) + gal(0x0021, IP), 0x8847))           # GAL under another label
    c.add(eth(label(13, 0, 0, 1) + stack(100) + IP, 0x8847))              # GAL without S bit: warning
    c.add(eth(gal(0x0021, IP, ver=0, ttl=255, exp=7), 0x8847))
    sec(c, 'label 14 (OAM alert) reaches Y.1711 through the label table')
    cv = bytes([1, 0, 0, 0]) + b'\0' * 10 + b'\xff\xff' + bytes([192, 0, 2, 1]) + struct.pack('!I', 7) + b'\0' * 18 + b'\x12\x34'
    c.add(eth(label(14, 0, 1, 1) + cv, 0x8847))
    sec(c, 'MPLS in other encapsulations: UDP 6635, IP protocol 137, GRE, PPP, Cisco HDLC')
    c.add(eth(ipv4_udp(stack(100) + IP, dport=6635), 0x0800))
    c.add(eth(ipv4(stack(100) + IP, proto=137), 0x0800))
    c.add(eth(ipv4(struct.pack('!HH', 0, 0x8847) + stack(100) + IP, proto=47), 0x0800))
    c.add(eth(ipv4(struct.pack('!HH', 0, 0x8848) + stack(100) + IP, proto=47), 0x0800))
    c.add(b'\xff\x03\x02\x81' + stack(100) + IP, link=9)
    c.add(b'\xff\x03\x02\x83' + stack(100, 101) + IP, link=9)
    c.add(b'\x0f\x00\x88\x47' + stack(100) + IP, link=104)
    c.add(b'\x0f\x00\x88\x48' + stack(100) + IP, link=104)
    sec(c, 'frames for Decode As mpls.label==500,mplspwcw (generic PW control word)')
    c.add(eth(stack(500) + b'\x03\xc5\x12\x34' + b'payload after the control word', 0x8847))   # CW, flags and length
    c.add(eth(stack(500) + b'\x00\x00\x00\x07' + ethpw, 0x8847))
    c.add(eth(stack(500) + IP, 0x8847))                                   # first nibble 4
    c.add(eth(stack(500) + IP6, 0x8847))                                  # first nibble 6
    c.add(eth(stack(500) + ach(0x0021) + IP, 0x8847))                     # first nibble 1
    sec(c, 'MCC (channel type 1) without a sub-dissector for protocol 0x00ff')
    c.add(eth(stack(510) + b'\x10\x00\x00\x01' + struct.pack('!H', 0x00ff) + b'mcc data', 0x8847))
    return c

def build_malformed():
    c = Cap()
    sec(c, 'truncated or empty MPLS')
    c.add(eth(stack(100)[:3], 0x8847))                      # label cut short
    c.add(eth(stack(100), 0x8847))                          # bottom of stack, no payload
    c.add(eth(label(100, 0, 0, 64) + label(101, 0, 0, 64), 0x8847))   # S bit never set
    c.add(eth(label(100, 0, 0, 64) + b'\x00\x00', 0x8847))  # second label cut short
    sec(c, 'short associated channel headers')
    c.add(eth(stack(100) + b'\x10\x00', 0x8847))            # first nibble 1, 2 octets
    c.add(eth(label(13, 0, 1, 1) + b'\x10\x00\x00', 0x8847))   # GAL, ACH cut short
    c.add(eth(label(13, 0, 1, 1), 0x8847))                  # GAL, no ACH
    c.add(eth(stack(500) + b'\x00\x00', 0x8847))            # pwcw (Decode As), CW cut short
    c.add(eth(stack(500) + b'\x00', 0x8847))
    c.add(eth(gal(0x0001, b'\x00'), 0x8847))                # MCC, protocol field cut short
    c.add(eth(gal(0x0023, BFD_CTRL[:6]), 0x8847))           # BFD CV, MEP TLV missing
    return c

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    c = build_main()
    c.write(os.path.join(out, 'mpls-coverage.pcapng'))
    nmain = len(c.frames)
    main_secs = list(SECS); del SECS[:]
    m = build_malformed()
    m.write(os.path.join(out, 'mpls-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for s, n in main_secs: print('main frame %d: %s' % (s, n))
        print('main frames:', nmain)
        for s, n in SECS: print('malformed frame %d: %s' % (s, n))
        print('malformed frames:', len(m.frames))
