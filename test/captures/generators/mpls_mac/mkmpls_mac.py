#!/usr/bin/env python3
# Generates test/captures/mpls_mac_coverage.pcapng.gz
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
# MPLS MAC Address Withdrawal OAM over static PW (RFC 7769): packet-mpls-mac.c
# ---------------------------------------------------------------------
SECS = []
def sec(cap, name):
    SECS.append((len(cap.frames) + 1, name))

def mactlv(t, v, res=0):
    return struct.pack('!HH', (res << 14) | t, len(v)) + v

def macmsg(tlvs=b'', flags=0, total=None, reserved=0):
    return struct.pack('!HBB', reserved, len(tlvs) if total is None else total, flags) + tlvs

def macframe(body, chan=0x0028, gal_=True):
    if gal_:
        return eth(gal(chan, body), 0x8847)
    return eth(stack(100) + ach(chan) + body, 0x8847)

def build_main():
    c = Cap()
    sec(c, 'header only: flags A, R, both, reserved flag bits')
    c.add(macframe(macmsg()))
    c.add(macframe(macmsg(flags=0x80)))
    c.add(macframe(macmsg(flags=0x40)))
    c.add(macframe(macmsg(flags=0xff, reserved=0x1234)))
    sec(c, 'TLVs: sequence number (type 1), unknown types, empty value, several TLVs')
    c.add(macframe(macmsg(mactlv(1, struct.pack('!I', 4242)))))
    c.add(macframe(macmsg(mactlv(1, struct.pack('!I', 0xffffffff), res=3), flags=0x40)))
    c.add(macframe(macmsg(mactlv(2, b'\x01\x02\x03\x04\x05\x06'))))
    c.add(macframe(macmsg(mactlv(1, struct.pack('!I', 1)) + mactlv(0x3fff, b'unknown tlv') + mactlv(7, b''))))
    c.add(macframe(macmsg(mactlv(5, b''))))
    c.add(macframe(macmsg(mactlv(9, b'\xaa' * 200), flags=0x80)))
    sec(c, 'carried without GAL: label stack and associated channel header (first nibble 1)')
    c.add(macframe(macmsg(mactlv(1, struct.pack('!I', 99)), flags=0xc0), gal_=False))
    return c

def build_malformed():
    c = Cap()
    sec(c, 'truncated and inconsistent messages')
    c.add(macframe(b'\x00\x00\x00'))                                        # header cut short
    c.add(macframe(macmsg(mactlv(1, b'\x00\x00\x00\x01'), total=40)))       # total length beyond the packet
    c.add(macframe(macmsg(struct.pack('!HH', 2, 100) + b'\x01\x02')))        # TLV longer than the packet
    c.add(macframe(macmsg(struct.pack('!HH', 1, 0))))                        # sequence number TLV without value
    c.add(macframe(macmsg(mactlv(1, b'\x00\x00\x00\x01\x02\x03\x04\x05'))))  # type 1 longer than 4: only 4 are skipped
    c.add(macframe(macmsg(b'\x00\x01')))                                    # TLV header cut short
    return c

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    c = build_main()
    c.write(os.path.join(out, 'mpls-mac-coverage.pcapng'))
    nmain = len(c.frames)
    main_secs = list(SECS); del SECS[:]
    m = build_malformed()
    m.write(os.path.join(out, 'mpls-mac-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for s, n in main_secs: print('main frame %d: %s' % (s, n))
        print('main frames:', nmain)
        for s, n in SECS: print('malformed frame %d: %s' % (s, n))
        print('malformed frames:', len(m.frames))
