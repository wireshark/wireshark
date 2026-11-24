#!/usr/bin/env python3
# Generates test/captures/lapsat_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate lapsat-coverage.pcapng and lapsat-coverage-malformed.pcapng. Usage: mklapsat.py <outdir> [-v]"""
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


# ---------------------------------------------------------------- LAPSat
GMR1_SDCCH = 0x08
GMR1_TCH3_FACCH = 0x12
GMR1_TCH6_FACCH = 0x16
GMR1_TCH9_FACCH = 0x1a
GMR1_BCCH = 0x01

SST, CRB, SIB, LFI = 0x01, 0x02, 0x10, 0x80


def saddr(sapi=0, cr=0, si=0, lpd=0, sst=0, lfi=0):
    return (sst & 1) | (cr << 1) | (sapi << 2) | (si << 4) | (lpd << 5) | (lfi << 7)


# 12 bit control fields
def cI(ns, nr, pf=0):
    return (nr << 7) | (pf << 6) | (ns << 1)


def cS(rr_or_grej, nr, pf=0):
    return (nr << 7) | (pf << 6) | (rr_or_grej << 2) | 1


def cU(mod, pf=0, mii=0):
    return mod | (pf << 6) | (mii << 9) | 3


def lapsat(addr_byte, ctl, payload=b'', length=None, pad=0):
    """Frame: address, 12 bit control + last nibble, optional length octet.
    The last payload nibble is carried in the control field's trailing nibble
    unless a length octet says the frame is padded."""
    lfi = bool(addr_byte & LFI)
    if payload and not pad:
        nib = payload[-1] >> 4
        raw = payload[:-1] + bytes([payload[-1] & 0x0f])
    else:
        nib = 0
        raw = payload
    b = bytes([addr_byte, ctl >> 4, ((ctl & 0xf) << 4) | nib])
    if lfi:
        b += bytes([len(payload) if length is None else length])
    return b + raw + bytes(pad)


L3A = bytes.fromhex('051801')                  # MM identity request
L3B = bytes.fromhex('0301')
L3SMS = bytes.fromhex('0904')
LONG = bytes.fromhex('0305') + bytes(range(0x40, 0x40 + 30))


def build(outdir, verbose=False):
    pc = Pcapng()
    pc.iface(LT_ETHERNET, 'eth')
    ranges = []

    def mark(name):
        ranges.append((name, pc.n + 1))

    def gm(sub, payload, up, ts=1, ss=0):
        g = gsmtap(0x0a, sub, payload, uplink=up, ts=ts, fn=2000 + pc.n)
        g = g[:14] + bytes([ss]) + g[15:]
        pc.pkt(0, udp_frame(g, '192.0.2.10', 4729, '192.0.2.20', 4729) if up
               else udp_frame(g, '192.0.2.20', 4729, '192.0.2.10', 4729))

    mark('Supervisory frames: RR and GREJ, with and without P/F, both directions')
    for up in (True, False):
        for cr in (0, 1):
            for pf in (0, 1):
                gm(GMR1_SDCCH, lapsat(saddr(0, cr), cS(0, 3, pf)), up)
                gm(GMR1_SDCCH, lapsat(saddr(0, cr), cS(2, 4, pf)), up)
    gm(GMR1_SDCCH, lapsat(saddr(0, 0), cS(1, 4, 0)), True)     # S function 1: unknown
    gm(GMR1_SDCCH, lapsat(saddr(0, 0), cS(3, 4, 1)), False)    # S function 3: unknown
    mark('Unnumbered frames: SABM (MII 0/1), DM, DISC, UA, UI, unknown modifier; both directions, P/F')
    for up in (True, False):
        for cr in (0, 1):
            gm(GMR1_SDCCH, lapsat(saddr(0, cr), cU(0x08c, 1, 0)), up)
            gm(GMR1_SDCCH, lapsat(saddr(0, cr), cU(0x08c, 0, 1)), up)
            gm(GMR1_SDCCH, lapsat(saddr(0, cr), cU(0x00c, 1)), up)
            gm(GMR1_SDCCH, lapsat(saddr(0, cr), cU(0x100, 0)), up)
            gm(GMR1_SDCCH, lapsat(saddr(0, cr), cU(0x180, 1)), up)
            gm(GMR1_SDCCH, lapsat(saddr(0, cr), cU(0x000, 0), L3A), up)
            gm(GMR1_SDCCH, lapsat(saddr(0, cr), cU(0x084, 0)), up)     # unknown modifier
    mark('Information frames: SAPI 0 and 3, no length field / length field, padding, LPD, SST, P bit, no dissector')
    for up in (True, False):
        gm(GMR1_SDCCH, lapsat(saddr(0, 0), cI(0, 0), L3A), up)
        gm(GMR1_SDCCH, lapsat(saddr(0, 1), cI(1, 1, 1), L3B), up)
        gm(GMR1_SDCCH, lapsat(saddr(3, 0), cI(2, 1), L3SMS), up)
        gm(GMR1_SDCCH, lapsat(saddr(0, 0, lfi=1), cI(3, 1), L3A), up)
        gm(GMR1_SDCCH, lapsat(saddr(0, 0, lfi=1), cI(4, 1), L3A, pad=3), up)    # length < frame: no nibble merge
        gm(GMR1_SDCCH, lapsat(saddr(0, 0, lpd=1), cI(5, 1), L3B), up)
        gm(GMR1_SDCCH, lapsat(saddr(0, 0, sst=1), cI(6, 1), L3B), up)
        gm(GMR1_SDCCH, lapsat(saddr(1, 0), cI(7, 1), b'\x01\x02\x03'), up)      # SAPI 1: no dissector
        gm(GMR1_SDCCH, lapsat(saddr(2, 0), cI(8, 1), b'\x01\x02\x03'), up)
        gm(GMR1_SDCCH, lapsat(saddr(0, 0), cI(9, 1)), up)                       # no payload
        gm(GMR1_SDCCH, lapsat(saddr(0, 0, lfi=1), cI(10, 1), b'', length=0), up)
    mark('Segmented I frames (SI): 2 and 3 segments on one channel, interleaved with another time slot')
    s1, s2 = LONG[:12], LONG[12:]
    gm(GMR1_SDCCH, lapsat(saddr(0, 0, si=1), cI(0, 0), s1), True, 2)
    gm(GMR1_SDCCH, lapsat(saddr(0, 0, si=0), cI(1, 0), s2), True, 2)
    a, b, c = LONG[:10], LONG[10:22], LONG[22:]
    gm(GMR1_SDCCH, lapsat(saddr(0, 1, si=1, lfi=1), cI(0, 0), a), False, 3)
    gm(GMR1_SDCCH, lapsat(saddr(0, 1, si=1), cI(1, 1), b), False, 3)
    gm(GMR1_SDCCH, lapsat(saddr(0, 0, si=1), cI(0, 0), s1), True, 4)
    gm(GMR1_SDCCH, lapsat(saddr(0, 1, si=0), cI(2, 2), c), False, 3)
    gm(GMR1_SDCCH, lapsat(saddr(0, 0, si=0), cI(1, 0), s2), True, 4)
    gm(GMR1_SDCCH, lapsat(saddr(3, 0, si=1), cI(2, 0), b'\x09'), True, 4)
    gm(GMR1_SDCCH, lapsat(saddr(3, 0, si=0), cI(3, 0), b'\x04'), True, 4)
    mark('FACCH on TCH3/6/9 and a channel type that LAPSat is not used for (BCCH, plain data)')
    for ch in (GMR1_TCH3_FACCH, GMR1_TCH6_FACCH, GMR1_TCH9_FACCH):
        gm(ch, lapsat(saddr(0, 0), cI(0, 0), L3A), True, 5)
        gm(ch, lapsat(saddr(0, 1), cI(0, 1), L3B), False, 5)
    gm(GMR1_BCCH, lapsat(saddr(0, 0), cI(0, 0), L3A), False, 5)
    mark('Whole (non-I) frames on a SAPI without a dissector: UI and SABM')
    gm(GMR1_SDCCH, lapsat(saddr(1, 0), cU(0x000, 0), b'\x01\x02\x03'), True)
    gm(GMR1_SDCCH, lapsat(saddr(2, 1), cU(0x08c, 1, 1), b'\x01\x02\x03'), False)
    ranges.append(('end', pc.n + 1))
    pc.write(os.path.join(outdir, 'lapsat-coverage.pcapng'))

    pm = Pcapng()
    pm.iface(LT_ETHERNET)

    def gm2(sub, payload, up, ts=1):
        g = gsmtap(0x0a, sub, payload, uplink=up, ts=ts, fn=2000 + pm.n)
        pm.pkt(0, udp_frame(g, '192.0.2.10', 4729, '192.0.2.20', 4729))
    gm2(GMR1_SDCCH, b'\x00\x01', True)                               # shorter than the header
    gm2(GMR1_SDCCH, lapsat(saddr(0, 0, lfi=1), cI(0, 0), L3A)[:3], True)    # LFI but no length octet
    gm2(GMR1_SDCCH, lapsat(saddr(0, 0, lfi=1), cI(0, 0), L3A, length=60), True)    # length beyond the frame
    gm2(GMR1_SDCCH, lapsat(saddr(0, 0), cI(0, 0), b'\x05'), False)   # one octet L3 message
    gm2(GMR1_SDCCH, lapsat(saddr(0, 0), cI(0, 0), b'\xff\xff\xff\xff'), False)
    gm2(GMR1_SDCCH, lapsat(saddr(0, 0, si=1), cI(0, 0), LONG[:12]), True, 7)   # reassembly never finishes
    # the same segment twice, then the end
    gm2(GMR1_SDCCH, lapsat(saddr(0, 0, si=1), cI(0, 0), LONG[:12]), True, 8)
    gm2(GMR1_SDCCH, lapsat(saddr(0, 0, si=1), cI(0, 0), LONG[:12]), True, 8)
    gm2(GMR1_SDCCH, lapsat(saddr(0, 0, si=0), cI(1, 0), LONG[12:]), True, 8)
    pm.write(os.path.join(outdir, 'lapsat-coverage-malformed.pcapng'))
    if verbose:
        for i, (n, s) in enumerate(ranges[:-1]):
            print('%d-%d: %s' % (s, ranges[i + 1][1] - 1, n))
    return ranges


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build(out, '-v' in sys.argv)
