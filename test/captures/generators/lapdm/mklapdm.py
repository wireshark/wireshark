#!/usr/bin/env python3
# Generates test/captures/lapdm_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate lapdm-coverage.pcapng and lapdm-coverage-malformed.pcapng. Usage: mklapdm.py <outdir> [-v]"""
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


# ----------------------------------------------------------------- LAPDm
CH_SDCCH4, CH_SDCCH8, CH_TCH_F, CH_TCH_H, CH_SDCCH, ACCH = 7, 8, 9, 10, 6, 0x80


def maddr(sapi, cr, lpd=0):
    return bytes([(lpd << 5) | (sapi << 2) | (cr << 1) | 1])


def mU(mod, pf=0):
    return bytes([mod | 0x03 | (pf << 4)])


def mS(kind, nr, pf=0):
    return bytes([(nr << 5) | (pf << 4) | (kind << 2) | 1])


def mI(ns, nr, pf=0):
    return bytes([(nr << 5) | (pf << 4) | (ns << 1)])


def mlen(n, m=0):
    return bytes([(n << 2) | (m << 1) | 1])


def lapdm_b(sapi, cr, ctl, info=b'', m=0, lpd=0, l=None):
    return maddr(sapi, cr, lpd) + ctl + mlen(len(info) if l is None else l, m) + info


CC_ALERT = bytes.fromhex('0301')
MM_IDREQ = bytes.fromhex('051801')
SMS_ACK = bytes.fromhex('0904')
RR_MEAS = bytes.fromhex('0615') + bytes(14)
SETUP_L3 = bytes.fromhex('0305') + bytes.fromhex('7e22') + bytes(range(0x30, 0x30 + 34))     # 38 octets
SI5 = bytes([0x49, 0x06, 0x1d]) + bytes(16) + b'\x2b\x2b'


def sacch(l1, frame):
    return bytes([l1, 0x00]) + frame


def mk_um(pc, ifid, sub, payload, up, ts=1, fn=[1000], **kw):
    fn[0] += 51
    pc.pkt(ifid, gsmtap_udp(1, sub, payload, uplink=up, ts=ts, fn=fn[0], **kw))


def build(outdir, verbose=False):
    pc = Pcapng()
    pc.iface(LT_ETHERNET, 'eth')
    ranges = []

    def mark(name):
        ranges.append((name, pc.n + 1))

    def um(sub, payload, up, ts=1, ss=0):
        g = gsmtap(1, sub, payload, uplink=up, ts=ts, fn=1000 + pc.n)
        g = g[:14] + bytes([ss]) + g[15:]
        pc.pkt(0, udp_frame(g, '192.0.2.10', 4729, '192.0.2.20', 4729) if up
               else udp_frame(g, '192.0.2.20', 4729, '192.0.2.10', 4729))

    mark('Format A (no information): SABM, UA, DM, DISC, RR, RNR, REJ; SAPI 0 and 3; both directions, C/R and P/F')
    for up in (True, False):
        for cr in (0, 1):
            for sapi in (0, 3):
                um(CH_SDCCH4, lapdm_b(sapi, cr, mU(0x2c, 1)), up, 2)
                um(CH_SDCCH4, lapdm_b(sapi, cr, mU(0x60, 1)), up, 2)
                um(CH_SDCCH4, lapdm_b(sapi, cr, mU(0x0c, 0)), up, 2)
                um(CH_SDCCH4, lapdm_b(sapi, cr, mU(0x40, 1)), up, 2)
                um(CH_SDCCH4, lapdm_b(sapi, cr, mS(0, 1, 0)), up, 2)
                um(CH_SDCCH4, lapdm_b(sapi, cr, mS(1, 2, 1)), up, 2)
                um(CH_SDCCH4, lapdm_b(sapi, cr, mS(2, 3, 0)), up, 2)
    mark('Format B information: SABM/UA with L3 contention resolution data, I frames SAPI 0 (CC, MM), SAPI 3 (SMS), SAPI 1/2 (no dissector), UI, cell broadcast LPD')
    for up in (True, False):
        um(CH_SDCCH8, lapdm_b(0, 0, mU(0x2c, 1), MM_IDREQ), up, 3)
        um(CH_SDCCH8, lapdm_b(0, 1, mU(0x60, 1), MM_IDREQ), up, 3)
        um(CH_SDCCH8, lapdm_b(0, 0, mI(0, 0), CC_ALERT), up, 3)
        um(CH_SDCCH8, lapdm_b(0, 1, mI(1, 1, 1), MM_IDREQ), up, 3)
        um(CH_SDCCH8, lapdm_b(3, 0, mI(2, 1), SMS_ACK), up, 3)
        um(CH_SDCCH8, lapdm_b(1, 0, mI(3, 1), b'\x01\x02\x03'), up, 3)
        um(CH_SDCCH8, lapdm_b(2, 0, mI(4, 1), b'\x01\x02\x03'), up, 3)
        um(CH_SDCCH8, lapdm_b(0, 0, mU(0x00, 0), CC_ALERT), up, 3)
        um(CH_SDCCH8, lapdm_b(3, 1, mU(0x00, 0), SMS_ACK), up, 3)
        um(CH_SDCCH8, lapdm_b(0, 0, mI(5, 1), CC_ALERT, lpd=1), up, 3)
        um(CH_SDCCH8, lapdm_b(0, 0, mI(6, 1), b''), up, 3)    # I frame, empty
    mark('Segmented I frames (M bit): 2 and 3 segments, other subslot, SABM with information between segments')
    seg1, seg2 = SETUP_L3[:19], SETUP_L3[19:]
    um(CH_SDCCH4, lapdm_b(0, 0, mI(0, 0), seg1, m=1), True, 4)
    um(CH_SDCCH4, lapdm_b(0, 0, mI(1, 0), seg2, m=0), True, 4)
    a, b_, c_ = SETUP_L3[:14], SETUP_L3[14:28], SETUP_L3[28:]
    um(CH_SDCCH4, lapdm_b(0, 1, mI(0, 0), a, m=1), False, 4)
    um(CH_SDCCH4, lapdm_b(0, 1, mI(1, 1), b_, m=1), False, 4)
    um(CH_SDCCH4, lapdm_b(0, 1, mI(2, 2), c_, m=0), False, 4)
    # interleaved with a second link (other subslot) and a SAPI 3 message
    um(CH_SDCCH4, lapdm_b(0, 0, mI(3, 0), seg1, m=1), True, 4, 1)
    um(CH_SDCCH4, lapdm_b(3, 0, mI(0, 0), SMS_ACK), True, 4, 0)
    um(CH_SDCCH4, lapdm_b(0, 0, mI(4, 0), seg2, m=0), True, 4, 1)
    # SABM with a contention resolution octets restarts the N(S) tracking
    um(CH_SDCCH4, lapdm_b(0, 0, mU(0x2c, 1), MM_IDREQ), True, 5)
    um(CH_SDCCH4, lapdm_b(0, 0, mI(0, 0), seg1, m=1), True, 5)
    um(CH_SDCCH4, lapdm_b(0, 0, mU(0x2c, 1), MM_IDREQ), True, 5)
    um(CH_SDCCH4, lapdm_b(0, 0, mI(1, 0), seg2, m=0), True, 5)
    mark('SACCH (L1 header + LAPDm): uplink format B, downlink UI format B4 with L2 pseudo length (SI5), downlink non-UI')
    um(CH_SDCCH4 | ACCH, sacch(0x05, lapdm_b(0, 0, mU(0x00, 0), RR_MEAS)), True, 1)
    um(CH_SDCCH4 | ACCH, sacch(0x05, lapdm_b(0, 0, mI(0, 0), CC_ALERT)), True, 1)
    um(CH_SDCCH4 | ACCH, sacch(0x05, lapdm_b(0, 0, mS(0, 0, 0))), True, 1)
    for i in range(3):
        um(CH_SDCCH4 | ACCH, sacch(0x0a, maddr(0, 0) + mU(0x00, 0) + SI5), False, 1)
    um(CH_SDCCH4 | ACCH, sacch(0x0a, lapdm_b(0, 1, mI(0, 0), CC_ALERT)), False, 1)
    um(CH_SDCCH4 | ACCH, sacch(0x0a, lapdm_b(0, 1, mS(0, 0, 0))), False, 1)
    um(CH_SDCCH4 | ACCH, sacch(0x0a, maddr(0, 1) + mU(0x00, 0)), False, 1)   # B4, no payload
    mark('FACCH on TCH/F and TCH/H, SDCCH (unspecified): I frames, UI, SACCH on TCH/F')
    for ch in (CH_TCH_F, CH_TCH_H, CH_SDCCH):
        um(ch, lapdm_b(0, 0, mI(0, 0), CC_ALERT), True, 6)
        um(ch, lapdm_b(0, 1, mI(0, 1), MM_IDREQ), False, 6)
    um(CH_TCH_F | ACCH, sacch(0x05, lapdm_b(0, 0, mU(0x00, 0), RR_MEAS)), True, 6)
    um(CH_TCH_F | ACCH, sacch(0x0a, maddr(0, 0) + mU(0x00, 0) + SI5), False, 6)
    ranges.append(('end', pc.n + 1))
    pc.write(os.path.join(outdir, 'lapdm-coverage.pcapng'))

    pm = Pcapng()
    pm.iface(LT_ETHERNET)

    def um2(sub, payload, up, ts=1):
        g = gsmtap(1, sub, payload, uplink=up, ts=ts, fn=1000 + pm.n)
        pm.pkt(0, udp_frame(g, '192.0.2.10', 4729, '192.0.2.20', 4729))
    um2(CH_SDCCH4, b'\x01', True)                                   # shorter than the header
    um2(CH_SDCCH4, b'\x01\x03', True)                               # no length octet
    um2(CH_SDCCH4, lapdm_b(0, 0, mI(0, 0), CC_ALERT, l=40), True)   # length beyond the frame
    um2(CH_SDCCH4, lapdm_b(0, 0, mI(0, 0), CC_ALERT, l=63, m=1), True, 7)
    um2(CH_SDCCH4, lapdm_b(0, 0, mU(0x00), CC_ALERT, l=40), False)
    um2(CH_SDCCH4 | ACCH, sacch(0x0a, maddr(0, 0) + mU(0x00, 0)[:1]), False)    # B4, 1 octet
    um2(CH_SDCCH4 | ACCH, sacch(0x0a, maddr(0, 0)), False)          # B4, no control octet
    um2(CH_SDCCH4, lapdm_b(0, 0, mI(0, 0), b'\x03'), True, 8)       # one octet L3 message
    # retransmitted segment: the same N(S) twice (the second is skipped in the first pass)
    um2(CH_SDCCH4, lapdm_b(0, 0, mI(2, 0), SETUP_L3[:19], m=1), True, 9)
    um2(CH_SDCCH4, lapdm_b(0, 0, mI(2, 0), SETUP_L3[:19], m=1), True, 9)
    um2(CH_SDCCH4, lapdm_b(0, 0, mI(3, 0), SETUP_L3[19:], m=0), True, 9)
    # unfinished reassembly followed by a SABM
    um2(CH_SDCCH4, lapdm_b(0, 0, mI(0, 0), SETUP_L3[:19], m=1), True, 10)
    pm.write(os.path.join(outdir, 'lapdm-coverage-malformed.pcapng'))
    if verbose:
        for i, (n, s) in enumerate(ranges[:-1]):
            print('%d-%d: %s' % (s, ranges[i + 1][1] - 1, n))
    return ranges


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build(out, '-v' in sys.argv)
