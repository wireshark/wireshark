#!/usr/bin/env python3
# Generates test/captures/lapd_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate lapd-coverage.pcapng and lapd-coverage-malformed.pcapng. Usage: mklapd.py <outdir> [-v]"""
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


# ------------------------------------------------------------------ LAPD
def crc_x25(b):
    c = 0xffff
    for x in b:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0x8408 if c & 1 else c >> 1
    return c ^ 0xffff


def addr(sapi, cr, tei):
    return bytes([(sapi << 2) | (cr << 1), (tei << 1) | 1])


def U(mod, pf=0):
    return bytes([mod | 0x03 | (pf << 4)])


def S(kind, nr, pf=0):
    return bytes([0x01 | (kind << 2), (nr << 1) | pf])


def I(ns, nr, pf=0):
    return bytes([ns << 1, (nr << 1) | pf])


SABME, UA, DM, DISC, UI, FRMR, XID, SABM = 0x6c, 0x60, 0x0c, 0x40, 0x00, 0x84, 0xac, 0x2c
SNRM, TEST, UP, SIM, RESET, SARM, SARME, SNRME = 0x80, 0xe0, 0x20, 0x04, 0x8c, 0x0c, 0x4c, 0xcc

SETUP = bytes.fromhex('0801010504038090a3180103')
CONNECT = bytes.fromhex('08018207')
TEIREQ = bytes.fromhex('0f12340 1ff'.replace(' ', ''))
TEIASSIGN = bytes.fromhex('0f12340205')
X25CALL = bytes.fromhex('100 10b 22 1234 00 '.replace(' ', '')) + b'hi'
RSL = bytes.fromhex('0201010801')
OML = bytes.fromhex('80000a0001')


def lapd(sapi, cr, tei, ctl, payload=b''):
    return addr(sapi, cr, tei) + ctl + payload


def sll(pkttype, we_net, data):
    return struct.pack('!HHH', pkttype, 1, 8) + bytes([we_net]) + b'\0' * 7 + struct.pack('!H', 0x0030) + data


def hdlc_bits(frame_bytes, with_flags_before=1, flags_after=1):
    bits = []
    flag = [0, 1, 1, 1, 1, 1, 1, 0]
    for _ in range(with_flags_before):
        bits += flag
    ones = 0
    for byte in frame_bytes:
        for i in range(8):
            b = (byte >> i) & 1
            bits.append(b)
            if b:
                ones += 1
                if ones == 5:
                    bits.append(0)
                    ones = 0
            else:
                ones = 0
    for _ in range(flags_after):
        bits += flag
    return bits


def pack_bits(bits):
    bits = bits + [1] * ((-len(bits)) % 8)
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def with_crc(f):
    c = crc_x25(f)
    return f + struct.pack('>H', c)


def build(outdir, verbose=False):
    pc = Pcapng()
    pc.iface(LT_LAPD, 'lapd')            # 0
    pc.iface(LT_LINUX_LAPD, 'linux-lapd')  # 1
    pc.iface(LT_ETHERNET, 'eth')         # 2
    pc.iface(LT_EXPPDU, 'exppdu')        # 3
    ranges = []

    def mark(name):
        ranges.append((name, pc.n + 1))

    # --- 203: user/network direction from pcapng flags
    mark('LAPD frames, link type 203: no direction, inbound, outbound; U/S/I frames')
    for fl in (None, 1, 2):
        for cr in (0, 1):
            tei = 64 if cr else 127
            pc.pkt(0, lapd(0, cr, tei, U(SABME, 1)), fl)
            pc.pkt(0, lapd(0, 1 - cr, tei, U(UA, 1)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(DM, 0)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(DISC, 1)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(FRMR, 0), b'\x00\x01\x02'), fl)
            pc.pkt(0, lapd(0, cr, tei, U(XID, 1), b'\x82\x80\x00'), fl)
            pc.pkt(0, lapd(0, cr, tei, U(SABM, 0)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(SNRM, 0)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(TEST, 1), b'\xaa\x55'), fl)
            pc.pkt(0, lapd(0, cr, tei, U(UP, 0)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(SIM, 0)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(RESET, 0)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(SARM, 1)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(SARME, 0)), fl)
            pc.pkt(0, lapd(0, cr, tei, U(SNRME, 0)), fl)
            pc.pkt(0, lapd(0, cr, tei, S(0, 3, 0)), fl)   # RR
            pc.pkt(0, lapd(0, cr, tei, S(1, 4, 1)), fl)   # RNR
            pc.pkt(0, lapd(0, cr, tei, S(2, 5, 0)), fl)   # REJ
            pc.pkt(0, lapd(0, cr, tei, S(3, 6, 1)), fl)   # SREJ
            pc.pkt(0, lapd(0, cr, tei, I(0, 0, 0), SETUP), fl)
            pc.pkt(0, lapd(0, cr, tei, I(1, 1, 1), CONNECT), fl)
    mark('Information, UI and other SAPIs: Q.931, TEI management, X.25, unknown SAPIs, empty frames')
    pc.pkt(0, lapd(63, 0, 127, U(UI), TEIREQ), 2)
    pc.pkt(0, lapd(63, 1, 127, U(UI), TEIASSIGN), 1)
    pc.pkt(0, lapd(16, 0, 70, I(2, 0), X25CALL), 2)
    pc.pkt(0, lapd(1, 0, 70, I(3, 0), b'\x01\x02'), 2)       # packet mode Q.931, no dissector
    pc.pkt(0, lapd(5, 0, 70, I(4, 0), b'\x01\x02'), 2)       # unknown SAPI -> data
    pc.pkt(0, lapd(5, 0, 70, I(5, 0)), 2)                    # empty I frame
    pc.pkt(0, lapd(5, 0, 70, U(UI)), None)                   # empty UI
    pc.pkt(0, lapd(0, 0, 70, I(6, 1), SETUP), 1)
    pc.pkt(0, lapd(62, 0, 1, U(UI), OML), 2)                 # GSM O&M SAPI
    pc.pkt(0, lapd(62, 0, 1, I(0, 0), OML), 1)
    pc.pkt(0, lapd(10, 0, 1, I(1, 0), b'\x01\x02\x03'), 2)   # GSM TFP SAPI
    pc.pkt(0, lapd(12, 0, 1, I(2, 0), b'\x01\x02\x03'), 2)   # GSM PGSL SAPI
    pc.pkt(0, lapd(1, 0, 1, I(3, 0), b'\x01\x02\x03'), 2)    # GSM not used SAPI
    pc.pkt(0, lapd(16, 0, 1, I(4, 0), b'\x01\x02\x03'), 2)   # GSM not used SAPI

    # --- 177: Linux LAPD pseudo-header: every pkttype x we_network
    mark('LAPD frames, link type 177 (Linux LAPD): packet type 0, 3, 4 and we_network 0, 1')
    for pt in (0, 3, 4):
        for wn in (0, 1):
            pc.pkt(1, sll(pt, wn, lapd(0, 0, 64, U(SABME, 1))))
            pc.pkt(1, sll(pt, wn, lapd(0, 1, 64, U(UA, 1))))
            pc.pkt(1, sll(pt, wn, lapd(0, 0, 64, I(0, 0), SETUP)))
            pc.pkt(1, sll(pt, wn, lapd(0, 1, 64, S(0, 1))))

    # --- GSMTAP E1T1 LAPD -> lapd-phdr (uton from the uplink bit)
    mark('GSMTAP E1T1 LAPD (UDP 4729), uplink and downlink -> lapd-phdr')
    for up in (True, False):
        pc.pkt(2, gsmtap_udp(0x13, 1, lapd(0, 0, 64, U(SABME, 1)), uplink=up))
        pc.pkt(2, gsmtap_udp(0x13, 1, lapd(0, 1, 64, U(UA, 1)), uplink=up))
        pc.pkt(2, gsmtap_udp(0x13, 1, lapd(0, 0, 64, I(0, 0), SETUP), uplink=up))
        pc.pkt(2, gsmtap_udp(0x13, 1, lapd(0, 1, 64, S(0, 1)), uplink=up))

    mark('UDP port 9000 (plain LAPD; dissected with the lapd.udp.port preference or Decode As only)')
    pc.pkt(2, udp_frame(lapd(0, 0, 64, U(SABME, 1)), '192.0.2.30', 9000, '192.0.2.31', 9000))
    pc.pkt(2, udp_frame(lapd(0, 1, 64, U(UA, 1)), '192.0.2.31', 9000, '192.0.2.30', 9000))
    pc.pkt(2, udp_frame(lapd(0, 0, 64, I(0, 0), SETUP), '192.0.2.30', 9000, '192.0.2.31', 9000))
    # --- bitstream via Exported PDU lapd-bitstream
    mark('lapd-bitstream (Exported PDU, HDLC bit stream with CRC), two directions')
    A = ('192.0.2.1', 3000, '192.0.2.2', 3001)
    B = (A[2], A[3], A[0], A[1])

    def bs(bits, d, flags=None):
        pc.pkt(3, exported_pdu('lapd-bitstream', pack_bits(bits), *d))

    # one complete frame per packet, preceded by an out-of-sync stretch
    f1 = with_crc(lapd(0, 0, 64, U(SABME, 1)))
    f2 = with_crc(lapd(0, 1, 64, U(UA, 1)))
    f3 = with_crc(lapd(0, 0, 64, I(0, 0), SETUP))
    f4 = with_crc(lapd(0, 1, 64, S(0, 1)))
    bs([1, 0, 1, 1, 0, 1, 0] + hdlc_bits(f1, 2), A)
    bs(hdlc_bits(f2, 1), B)
    # a frame with five consecutive ones in the data (bit stuffing)
    f5 = with_crc(lapd(0, 0, 64, I(1, 1), SETUP + bytes([0x7e, 5, 4, 0x1f, 0xff, 0x3e, 0xf8])))
    bs(hdlc_bits(f5, 1), A)
    # two frames back to back in one packet, sharing a flag
    bits = hdlc_bits(f3, 1, 1)
    bits += hdlc_bits(f4, 0, 1)[0:]
    bs(bits, B)
    # a frame split over two packets in each direction of a conversation of its own
    C = ('192.0.2.1', 3100, '192.0.2.2', 3101)
    D = (C[2], C[3], C[0], C[1])
    big = with_crc(lapd(5, 0, 64, I(2, 1), bytes(range(60))))
    bits = hdlc_bits(big, 1)
    cut = len(bits) // 2 // 8 * 8
    pc.pkt(3, exported_pdu('lapd-bitstream', pack_bits(bits[:cut]), *C))
    pc.pkt(3, exported_pdu('lapd-bitstream', pack_bits(bits[:cut]), *D))
    pc.pkt(3, exported_pdu('lapd-bitstream', pack_bits(bits[cut:]), *C))
    pc.pkt(3, exported_pdu('lapd-bitstream', pack_bits(bits[cut:]), *D))
    # a frame with a bad CRC
    bad = bytearray(with_crc(lapd(0, 0, 64, U(UI), SETUP)))
    bad[-1] ^= 0x55
    bs(hdlc_bits(bytes(bad), 1), B)
    # a frame longer than the 1024 byte buffer: the surplus is dropped
    huge = with_crc(lapd(16, 0, 64, I(3, 1), bytes(1100)))
    bs(hdlc_bits(huge, 1), A)
    # a frame with no addressing information (Exported PDU without addresses)
    pc.pkt(3, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(f1, 1))))
    mark('Reproducer of "LAPD: Check the length of frames that have a CRC" (3 and 4 byte frames, error expert info)')
    pc.pkt(3, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(b'\x01\x02\x03', 1)), *A))
    pc.pkt(3, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(b'\x01\x02\x03\x04', 1)), *B))
    mark('pcapng packet flags present with the direction field 0 (unknown), link type 203')
    pc.pkt(0, lapd(0, 0, 64, U(SABME, 1)), 0)
    pc.pkt(0, lapd(0, 0, 64, I(0, 0), SETUP), 0)
    ranges.append(('end', pc.n + 1))
    pc.write(os.path.join(outdir, 'lapd-coverage.pcapng'))

    # malformed capture
    pm = Pcapng()
    pm.iface(LT_LAPD)
    pm.iface(LT_EXPPDU)
    pm.pkt(0, b'\x00')                                   # shorter than the address
    pm.pkt(0, b'\x00\x01')                               # no control field
    pm.pkt(0, lapd(0, 0, 64, I(0, 0)[:1]))               # I frame, extended control cut short
    pm.pkt(0, lapd(0, 0, 64, S(0, 0)[:1]))
    pm.pkt(0, lapd(0, 0, 64, I(0, 0), SETUP), 2)
    pm.pkt(0, lapd(0, 0, 1, I(5, 0), RSL), 2)             # RSL payload, Q.931 without the GSM SAPI preference
    pm.pkt(0, lapd(0, 0, 64, I(5, 0)), 2)                 # empty I frame to Q.931
    pm.pkt(0, lapd(0, 0, 64, U(UI)), 2)
    # 6 ones that do not match a flag, 7 ones (abort)
    pm.pkt(1, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(f1, 1)[:20] + [1] * 6 + [0] + [1, 0, 1, 1, 0, 0, 1, 0])))
    pm.pkt(1, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(f1, 1)[:24] + [1] * 8 + [0, 1, 0, 1])))
    pm.pkt(1, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(f1, 1)[:12] + [1] * 6 + [0, 0, 1] * 4 + [1] * 7)))
    # the stuffed zero inside the first data octet is not removed (SAPI 63, TEI 127: six ones): empty frame
    pm.pkt(1, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(with_crc(lapd(63, 0, 127, U(UI), TEIREQ)), 1))))
    for n in (3, 4):
        pm.pkt(1, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(bytes(range(1, n + 1)), 1))))
    pm.pkt(1, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(b'\x00\x01\x02\x03\x04', 1))))
    pm.pkt(1, exported_pdu('lapd-bitstream', pack_bits(hdlc_bits(b'', 1))))
    pm.write(os.path.join(outdir, 'lapd-coverage-malformed.pcapng'))
    if verbose:
        for i, (n, s) in enumerate(ranges[:-1]):
            print('%d-%d: %s' % (s, ranges[i + 1][1] - 1, n))
    return ranges


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build(out, '-v' in sys.argv)
