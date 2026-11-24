#!/usr/bin/env python3
# Generates test/captures/lapb_coverage.trc.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate lapb-coverage.trc (EyeSDN file with LAPB records), lapb-coverage-ether.pcapng and the malformed captures. Usage: mklapb.py <outdir> [-v]"""
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


def eyesdn_rec(sec, usec, direction, payload, channel=0):
    def esc(b):
        o = bytearray()
        for x in b:
            if x in (0xfe, 0xff):
                o += bytes([0xfe, x - 2])
            else:
                o.append(x)
        return bytes(o)
    hdr = struct.pack('>I', usec)[1:] + struct.pack('>Q', sec)[3:] + bytes([channel, direction]) + struct.pack('>H', len(payload))
    return b'\xff' + esc(hdr + payload)


def build(outdir, verbose=False):
    recs = [b'EyeSDN']
    t = [1700000000, 0]
    ranges = []
    n = [0]

    def mark(name):
        ranges.append((name, n[0] + 1))

    def rec(sent, payload, enc=2):
        t[1] += 1000
        recs.append(eyesdn_rec(t[0], t[1], (enc << 1) | (1 if sent else 0), payload))
        n[0] += 1

    mark('Unnumbered frames, all addresses (01, 03, 07, 0f), both directions')
    for sent in (True, False):
        for a in (0x01, 0x03, 0x07, 0x0f):
            rec(sent, bytes([a]) + lU(0x2c, 1))          # SABM
            rec(sent, bytes([a]) + lU(0x60, 1))          # UA
            rec(sent, bytes([a]) + lU(0x0c, 0))          # DM
            rec(sent, bytes([a]) + lU(0x40, 0))          # DISC
            rec(sent, bytes([a]) + lU(0x84, 0) + b'\x00\x01\x02')   # FRMR
            rec(sent, bytes([a]) + lU(0x6c, 1))          # SABME
    mark('Supervisory frames RR, RNR, REJ, SREJ with and without P/F')
    for sent in (True, False):
        for a in (0x01, 0x03):
            for k in range(4):
                rec(sent, bytes([a]) + lS(k, k + 1, k & 1))
    mark('Information frames carrying X.25: call request, call accepted, data, RR, REJ, interrupt, reset, restart, clear')
    for sent in (True, False):
        a = 0x01 if sent else 0x03
        rec(sent, bytes([a]) + lI(0, 0) + X25_CALL)
        rec(not sent, bytes([0x03 if sent else 0x01]) + lI(0, 1) + X25_ACCEPT)
        rec(sent, bytes([a]) + lI(1, 1, 1) + X25_DATA(0, 0, b'hello'))
        rec(not sent, bytes([0x03 if sent else 0x01]) + lI(1, 2) + X25_DATA(0, 1, b'world', 1))
        rec(sent, bytes([a]) + lI(2, 2) + X25_RR)
        rec(sent, bytes([a]) + lI(3, 2) + X25_REJ)
        rec(sent, bytes([a]) + lI(4, 2) + X25_INT)
        rec(sent, bytes([a]) + lI(5, 2) + X25_RESET)
        rec(sent, bytes([a]) + lI(6, 2) + X25_RESTART)
        rec(sent, bytes([a]) + lI(7, 2) + X25_CLEAR)
        rec(not sent, bytes([0x03 if sent else 0x01]) + lI(2, 0) + X25_CLEAR_CONF)
    mark('Invalid LAPB address octets (not 01, 03, 07, 0f), both directions')
    for sent in (True, False):
        rec(sent, b'\x05' + lU(0x2c, 1))
        rec(sent, b'\xfe\x2f')                                  # contains the escape octet
        rec(sent, b'\xff\x2f')                                  # contains the flag octet
    ranges.append(('end', n[0] + 1))
    open(os.path.join(outdir, 'lapb-coverage.trc'), 'wb').write(b''.join(recs))

    # the same frames over Ethernet (LAPBETHER): direction unknown
    pc = Pcapng()
    pc.iface(LT_ETHERNET)
    ethf = lambda f: pc.pkt(0, eth(struct.pack('<H', len(f)) + f + bytes(max(0, 46 - 2 - len(f))), 0x6000))
    for a in (0x01, 0x03, 0x07, 0x0f):
        ethf(bytes([a]) + lU(0x2c, 1))
        ethf(bytes([a]) + lU(0x60, 1))
        ethf(bytes([a]) + lS(0, 1, 1))
        ethf(bytes([a]) + lI(0, 0) + X25_CALL)
        ethf(bytes([a]) + lI(1, 1) + X25_DATA(0, 0, b'hello'))
    ethf(b'\x09' + lU(0x2c, 1))
    pc.write(os.path.join(outdir, 'lapb-coverage-ether.pcapng'))

    pm = Pcapng()
    pm.iface(LT_ETHERNET)
    pm.pkt(0, eth(b'\x00', 0x6000))
    pm.pkt(0, eth(struct.pack('<H', 3) + b'\x01' + lI(0, 3) + bytes(41), 0x6000))     # I frame without X.25 data
    pm.pkt(0, eth(struct.pack('<H', 0) + bytes(44), 0x6000))                 # zero length
    pm.pkt(0, eth(struct.pack('<H', 200) + b'\x01\x2f' + bytes(42), 0x6000))  # length beyond the frame
    pm.pkt(0, eth(struct.pack('<H', 3) + bytes([0x01]) + lI(0, 0) + b'\x10', 0x6000) + bytes(40))
    pm.write(os.path.join(outdir, 'lapb-coverage-malformed.pcapng'))
    # LAPB records that are malformed: truncated before the control octet and X.25
    r = [b'EyeSDN']
    t[1] = 0
    for sent in (True, False):
        for pl in (b'\x01', b'\x03', b'\x01' + lI(0, 3), b'\x01' + lI(0, 0), b'\x01' + lI(0, 0) + b'\x10\x01', b'\x01' + lI(0, 0) + b'\x10'):
            t[1] += 1000
            r.append(eyesdn_rec(t[0], t[1], (2 << 1) | sent, pl))
    open(os.path.join(outdir, 'lapb-coverage-malformed.trc'), 'wb').write(b''.join(r))
    if verbose:
        for i, (nm, s) in enumerate(ranges[:-1]):
            print('%d-%d: %s' % (s, ranges[i + 1][1] - 1, nm))
    return ranges


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build(out, '-v' in sys.argv)
