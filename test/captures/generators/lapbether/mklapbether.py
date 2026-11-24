#!/usr/bin/env python3
# Generates test/captures/lapbether_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate lapbether-coverage.pcapng and lapbether-coverage-malformed.pcapng. Usage: mklapbether.py <outdir> [-v]"""
import struct
import sys
import os

# ------------------------------------------------------------ pcapng writer
LT_ETHERNET = 1
LT_LINUX_LAPD = 177
LT_LAPD = 203
LT_EXPPDU = 252


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def block(btype, body):
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)


def opt(code, val):
    return struct.pack('<HH', code, len(val)) + pad4(val)


class Pcapng:
    def __init__(self):
        self.out = [block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))]
        self.n = 0
        self.t = 1700000000 * 1000000

    def iface(self, linktype, name=None):
        o = b''
        if name:
            o = opt(2, name.encode()) + struct.pack('<HH', 0, 0)
        self.out.append(block(1, struct.pack('<HHI', linktype, 0, 65535) + o))

    def pkt(self, ifid, data, flags=None):
        self.t += 1000
        o = b''
        if flags is not None:
            o = opt(2, struct.pack('<I', flags)) + struct.pack('<HH', 0, 0)
        body = struct.pack('<IIIII', ifid, self.t >> 32, self.t & 0xffffffff,
                           len(data), len(data)) + pad4(data) + o
        self.out.append(block(6, body))
        self.n += 1
        return self.n

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.out))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def eth(payload, etype=0x0800, src=b'\x02\0\0\0\0\x01', dst=b'\x02\0\0\0\0\x02'):
    return dst + src + struct.pack('!H', etype) + payload


def ipv4(proto, payload, src, dst, ident=1):
    h = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0) + ip4(src) + ip4(dst)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def udp_frame(payload, src, sport, dst, dport):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    return eth(ipv4(17, u, src, dst))


def exported_pdu(name, payload, src=None, sport=None, dst=None, dport=None):
    nb = name.encode()
    tags = struct.pack('!HH', 12, len(pad4(nb))) + pad4(nb)
    if src:
        tags += struct.pack('!HH', 20, 4) + ip4(src)
        tags += struct.pack('!HH', 21, 4) + ip4(dst)
        tags += struct.pack('!HHI', 24, 4, 2)          # UDP
        tags += struct.pack('!HHI', 25, 4, sport)
        tags += struct.pack('!HHI', 26, 4, dport)
    tags += struct.pack('!HH', 0, 0)
    return tags + payload


def gsmtap(typ, sub, payload, uplink=False, arfcn=20, ts=1, fn=1000, sig=-60, snr=20):
    a = arfcn | (0x4000 if uplink else 0)
    h = struct.pack('!BBBBHbbIBBBB', 2, 4, typ, ts, a, sig, snr, fn, sub, 0, 0, 0)
    return h + payload


def gsmtap_udp(typ, sub, payload, uplink=False, **kw):
    g = gsmtap(typ, sub, payload, uplink, **kw)
    if uplink:
        return udp_frame(g, '192.0.2.10', 4729, '192.0.2.20', 4729)
    return udp_frame(g, '192.0.2.20', 4729, '192.0.2.10', 4729)


# ------------------------------------------------------------------ LAPB
def lU(mod, pf=0):
    return bytes([mod | 0x03 | (pf << 4)])


def lS(kind, nr, pf=0):
    return bytes([(nr << 5) | (pf << 4) | (kind << 2) | 1])


def lI(ns, nr, pf=0):
    return bytes([(nr << 5) | (pf << 4) | (ns << 1)])


def x25(typ, lcn=1, rest=b'', gfi=1):
    return bytes([(gfi << 4) | (lcn >> 8), lcn & 0xff, typ]) + rest


X25_CALL = x25(0x0b, rest=bytes.fromhex('22123400')) + b'ping'
X25_ACCEPT = x25(0x0f, rest=b'\x00\x00')
X25_DATA = lambda ps, pr, d, m=0: bytes([0x10, 0x01, (pr << 5) | (m << 4) | (ps << 1)]) + d
X25_RR = x25(0x01 | (3 << 5))
X25_CLEAR = x25(0x13, rest=b'\x00\x00')
X25_CLEAR_CONF = x25(0x17)
X25_RESET = x25(0x1b, rest=b'\x00\x00')
X25_RESTART = bytes([0x10, 0x00, 0xfb, 0x07, 0x00])
X25_INT = x25(0x23, rest=b'\x7f')
X25_REJ = x25(0x09 | (2 << 5))



def build(outdir, verbose=False):
    pc = Pcapng()
    pc.iface(LT_ETHERNET, 'eth')
    ranges = []
    sa = b'\x02\0\0\0\0\x01'
    sb = b'\x02\0\0\0\0\x02'

    def ethf(f, src=sa, dst=sb, pad=True, extra=0, ln=None):
        body = struct.pack('<H', len(f) if ln is None else ln) + f
        if pad:
            body += bytes(max(0, 46 - len(body)))
        body += bytes(extra)
        return pc.pkt(0, eth(body, 0x6000, src, dst))

    ranges.append(('LAPBETHER (Ethernet type 0x6000): unnumbered frames, all addresses, both directions', pc.n + 1))
    for src, dst in ((sa, sb), (sb, sa)):
        for a in (0x01, 0x03, 0x07, 0x0f):
            ethf(bytes([a]) + lU(0x2c, 1), src, dst)
            ethf(bytes([a]) + lU(0x60, 1), src, dst)
            ethf(bytes([a]) + lU(0x0c, 0), src, dst)
            ethf(bytes([a]) + lU(0x40, 0), src, dst)
            ethf(bytes([a]) + lU(0x84, 0) + b'\x00\x01\x02', src, dst)
    ranges.append(('Supervisory frames', pc.n + 1))
    for k in range(4):
        ethf(b'\x01' + lS(k, k + 1, k & 1))
        ethf(b'\x03' + lS(k, k + 1, k & 1))
    ranges.append(('Information frames carrying X.25 (call request/accept, data, RR, clear, ...), the frame padded and with a trailer', pc.n + 1))
    ethf(b'\x01' + lI(0, 0) + X25_CALL)
    ethf(b'\x03' + lI(0, 1) + X25_ACCEPT, sb, sa)
    ethf(b'\x01' + lI(1, 1, 1) + X25_DATA(0, 0, b'hello'))
    ethf(b'\x01' + lI(2, 1) + X25_DATA(1, 0, bytes(range(100))))      # longer than the Ethernet minimum
    ethf(b'\x03' + lI(1, 3) + X25_DATA(0, 2, b'x', 1), sb, sa)
    ethf(b'\x01' + lI(3, 1) + X25_RR)
    ethf(b'\x01' + lI(4, 1) + X25_CLEAR)
    ethf(b'\x03' + lI(2, 5) + X25_CLEAR_CONF, sb, sa)
    ethf(b'\x01' + lI(5, 2) + X25_DATA(2, 0, b'tail'), extra=4)       # Ethernet trailer after the LAPB frame
    ranges.append(('Invalid LAPB address octets inside LAPBETHER', pc.n + 1))
    ethf(b'\x05' + lU(0x2c, 1))
    ethf(b'\x00' + lU(0x2c, 1))
    ranges.append(('end', pc.n + 1))
    pc.write(os.path.join(outdir, 'lapbether-coverage.pcapng'))

    pm = Pcapng()
    pm.iface(LT_ETHERNET)
    pc = pm
    pm.pkt(0, eth(b'\x00', 0x6000))                                   # shorter than the length field
    ethf(b'', ln=0)                                                    # zero length
    ethf(b'\x01' + lU(0x2c, 1), ln=200)                               # length beyond the frame
    ethf(b'\x01' + lI(0, 3))                                          # I frame without X.25 data
    ethf(b'\x01' + lI(0, 0) + b'\x10')                               # X.25 header cut short
    pm.write(os.path.join(outdir, 'lapbether-coverage-malformed.pcapng'))
    if verbose:
        for i, (nm, s) in enumerate(ranges[:-1]):
            print('%d-%d: %s' % (s, ranges[i + 1][1] - 1, nm))
    return ranges


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build(out, '-v' in sys.argv)
