#!/usr/bin/env python3
# Generates test/captures/ptp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the PTP dissector
(packet-ptp.c): IEEE 1588 PTPv1 and PTPv2 over UDP (ports 319/320) and
PTPv2 over Ethernet (ethertype 0x88F7, including IEEE 802.1AS).

Every packet is built from scratch with struct; no captured traffic is
used. The capture timestamps are set explicitly because the dissector's
analysis (sync interval, rate ratio, peer delay) uses them.

Usage: mkptp.py <output directory>

Writes:
  ptp-coverage.pcap            PTPv1 messages, PTPv2 messages with every
                               TLV and management ID, analysis of two step
                               and one step sync and of peer delay, 802.1AS
  ptp-coverage-malformed.pcap  message lengths that are too large or too
                               small, TLVs cut short
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000.0
        self.ipid = 1

    def at(self, t):
        self.t = t

    def udp(self, port, payload, src=1, dst=2):
        u = struct.pack('!HHHH', port, port, 8 + len(payload), 0) + payload
        iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), self.ipid, 0, 1,
                          17, 0, bytes([10, 0, 0, src]), bytes([224, 0, 1, 129]))
        self.ipid += 1
        iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
        mac = bytes([2, 0, 0, 0, 0, src])
        self.frames.append((self.t, bytes.fromhex('01005e000181') + mac + b'\x08\x00' + iph + u))

    def eth(self, payload, src=1, dst=bytes.fromhex('0180c200000e')):
        mac = bytes([2, 0, 0, 0, 0, src])
        self.frames.append((self.t, dst + mac + b'\x88\xf7' + payload))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for ts, fr in self.frames:
                sec = int(ts)
                usec = int(round((ts - sec) * 1e6))
                f.write(struct.pack('<IIII', sec, usec, len(fr), len(fr)) + fr)


# ----------------------------------------------------------------- PTPv2

CLK_A = bytes.fromhex('001b19fffe000001')     # EUI-64 with ff:fe (vendor lookup)
CLK_B = bytes.fromhex('0011223344556677')     # no ff:fe
CLK_C = bytes.fromhex('080030fffe00cafe')
SYNC, DREQ, PDREQ, PDRESP, FUP, DRESP, PDFUP, ANN, SIG, MGMT = 0, 1, 2, 3, 8, 9, 10, 11, 12, 13
TWO_STEP, UNICAST, ALT, UTCV, PTPTS, LI59, LI61 = 0x0200, 0x0400, 0x0100, 0x0004, 0x0008, 0x0002, 0x0001
SEC, SP1, SP2, TTRA, FTRA, SYNCU = 0x8000, 0x2000, 0x4000, 0x0010, 0x0020, 0x0040
EVENT = (SYNC, DREQ, PDREQ, PDRESP)


def ts(sec, ns):
    return struct.pack('>HIi', sec >> 32, sec & 0xffffffff, 0)[:0] + \
        struct.pack('>Q', sec)[2:] + struct.pack('>I', ns)


def corr(ns, sub=0):
    return (ns << 16) | sub


def v2(mtype, body, clk=CLK_A, port=1, seq=0, flags=0, domain=0, majorsdo=0,
       minorsdo=0, minorver=0, ver=2, control=None, logint=0, correction=0,
       mtspec=0, length=None, extra=b''):
    if control is None:
        control = {SYNC: 0, DREQ: 1, FUP: 2, DRESP: 3, MGMT: 4}.get(mtype, 5)
    hdr = struct.pack('>BBHBBHqI8sHHBb', (majorsdo << 4) | mtype, (minorver << 4) | ver,
                      0, domain, minorsdo, flags, correction, mtspec, clk, port,
                      seq, control, logint)
    pkt = hdr + body + extra
    n = len(pkt) if length is None else length
    return pkt[:2] + struct.pack('>H', n) + pkt[4:]


def tlv(t, data):
    return struct.pack('>HH', t, len(data)) + data


def oe(org, sub, data, t=3):
    return tlv(t, org.to_bytes(3, 'big') + sub.to_bytes(3, 'big') + data)


def text(s):
    b = s.encode()
    return bytes([len(b)]) + b


def even(data, extra_hdr=4):
    """Pad TLV data so that header plus data has an even length."""
    return data + (b'\0' if (len(data) + extra_hdr) % 2 else b'')


def an_body(utc=37, p1=128, cls=6, acc=0x21, var=0x4e5d, p2=128, gm=CLK_A,
            steps=0, src=0x20, tsec=1000, tns=500, as_=False):
    o = b'\0' * 10 if as_ else ts(tsec, tns)
    return o + struct.pack('>hBBBBHB8sHB', utc, 0, p1, cls, acc, var, p2, gm, steps, src)


def pid(clk, port):
    return clk + struct.pack('>H', port)


def mgmt_body(target=pid(b'\xff' * 8, 0xffff), start=3, bound=3, action=0):
    return target + bytes([start, bound, action, 0])


def mm(mid, data=b'', action=2, **kw):
    return v2(MGMT, mgmt_body(action=action), control=4, **kw,
              extra=tlv(1, struct.pack('>H', mid) + data))


# ---------------------------------------------------------------- PTPv1

def v1(control, key=0, size=None, subdomain=b'_DFLT', mtype=1, flags=0x0105):
    n = size or (124 if control in (0, 1) else 60 if control == 3 else 52 if control == 2 else 160)
    b = bytearray((i * 7 + 3) & 0x5f | 0x20 for i in range(n))
    b[0:2] = struct.pack('>H', 1)
    b[2:4] = struct.pack('>H', 1)
    b[4:20] = subdomain.ljust(16, b'\0')
    b[20] = mtype
    b[21] = 1
    b[22:28] = bytes.fromhex('00e04c681234')
    b[28:30] = struct.pack('>H', 1)
    b[30:32] = struct.pack('>H', 17)
    b[32] = control
    b[33] = 0
    b[34:36] = struct.pack('>H', flags)
    if control == 4:
        b[55] = key
        b[56:58] = b'\0\0'
        b[58:60] = struct.pack('>H', n - 60)
    for o, v in ((40, 1000000), (44, 123456), (72, 5), (76, 6)):
        if control in (0, 1, 3) or o >= 60:
            pass
    return bytes(b)


def build_v1(c):
    c.at(1699990000.0)
    # Sync / Delay_Req (control 0, 1), Follow_Up (2), Delay_Resp (3)
    c.udp(319, v1(0, mtype=1, flags=0x0000))
    c.udp(319, v1(0, mtype=1, flags=0x007f))     # every flag bit
    c.udp(319, v1(1, mtype=1))
    c.udp(320, v1(2, mtype=2))
    c.udp(320, v1(3, mtype=2))
    # Management with every key, and a key that is not defined
    for key in range(0, 28):
        c.udp(320, v1(4, key=key, mtype=2))
    c.udp(320, v1(4, key=99, mtype=2))
    c.udp(320, v1(4, key=9, mtype=2, size=140))
    # Control field that is not defined
    c.udp(320, v1(5, mtype=2, size=60))
    # The current data set with the top bit of the nanoseconds set
    p = bytearray(v1(4, key=11, mtype=2))
    p[68:72] = struct.pack('>I', 0x80000123)
    c.udp(320, bytes(p))


# --------------------------------------------------------- management IDs

def mm_data():
    """Management TLV data (without the management id) per id."""
    cd = (struct.pack('>H', 0x8000 | 0x4000 | 0x2000 | 0x1000 | 0x0800) + text('IEEE 802.3') +
          struct.pack('>H', 6) + bytes.fromhex('020000000001') +
          struct.pack('>HH', 1, 4) + bytes([10, 0, 0, 1]) +
          bytes.fromhex('00b0c8') + b'\0' + text('Synthetic clock') + text('1.2.3') +
          text('user desc') + bytes.fromhex('00a1b2c3d4e5'))
    cd_odd = (struct.pack('>H', 0x0080) + text('') + struct.pack('>H', 0) +
              struct.pack('>HH', 3, 5) + bytes([1, 2, 3, 4, 5]) +   # odd address length: expert
              bytes.fromhex('00b0c8') + b'\0' + text('') + text('') + text('') + bytes(6))
    def fault(sec, ns, sev, name, val, desc):
        body = ts(sec, ns) + bytes([sev]) + text(name) + text(val) + text(desc)
        return struct.pack('>H', len(body) + 2) + body
    fl = struct.pack('>H', 2) + fault(1000, 7, 3, 'fault-a', '12', 'first') + fault(1001, 8, 7, 'b', '', 'desc')
    d = {}
    d[0x0001] = even(cd, 6)
    d[0x0002] = even(text('lab clock '), 6)
    d[0x0005] = struct.pack('>H', 0x0000)
    d[0x0006] = even(fl, 6)
    d[0x2000] = (bytes([0x03, 0]) + struct.pack('>H', 2) + bytes([128, 6, 0x21]) + struct.pack('>H', 0x4e5d) +
                 bytes([128]) + CLK_A + bytes([0, 0]))
    d[0x2001] = struct.pack('>H', 1) + struct.pack('>q', corr(1234, 0x4000)) + struct.pack('>q', corr(5678))
    d[0x2002] = (CLK_B + struct.pack('>H', 1) + bytes([1, 0]) + struct.pack('>H', 0xffff) + struct.pack('>I', 0x7fffffff) +
                 bytes([128, 6, 0x21]) + struct.pack('>H', 0x4e5d) + bytes([128]) + CLK_A)
    d[0x2003] = struct.pack('>H', 37) + bytes([0x3f, 0x20])
    d[0x2004] = (CLK_A + struct.pack('>HBb', 1, 6, 0) + struct.pack('>q', corr(100)) +
                 bytes([1, 3, 0, 0, 0, 2]))
    for mid in (0x2005, 0x2006, 0x2007, 0x2009, 0x200a, 0x200b, 0x200c, 0x2010, 0x4002, 0x6000, 0x6001,
                0x2014, 0x2016, 0x201b, 0x201e, 0x2020, 0x3000, 0x3001, 0x3002, 0x3003, 0x2008, 0x2012):
        d[mid] = bytes([0x80 | 1, 0])
    d[0x200f] = ts(1700000000, 123456789)
    d[0x2011] = struct.pack('>H', 37) + bytes([0x07, 0])
    d[0x2013] = bytes([0x01, 0x20])
    d[0x2015] = CLK_A + CLK_B
    cl = (struct.pack('>bB', -2, 2) + struct.pack('>HH', 1, 4) + bytes([10, 0, 0, 1]) +
          struct.pack('>HH', 2, 16) + bytes(16))
    d[0x2017] = cl
    d[0x2018] = even(struct.pack('>bH', -1, 2) + struct.pack('>HH', 1, 4) + bytes([10, 0, 0, 2]) +
                     struct.pack('>HH', 2, 16) + bytes(range(16)), 6)
    d[0x2019] = struct.pack('>H', 16)
    d[0x201a] = even(struct.pack('>H', 1) + (CLK_A + CLK_B + struct.pack('>HB', 1, 100)), 6)
    d[0x201c] = struct.pack('>H', 8)
    d[0x201d] = bytes([1, 3, 0xfd, 0])
    d[0x201f] = even(bytes([1]) + text('Time zone'), 6)
    d[0x2021] = bytes([1]) + struct.pack('>ii', -3600, 3600) + ts(1800000000, 0)[:6] + b'\0'
    d[0x4000] = CLK_A + struct.pack('>H', 4) + bytes([1, 24])
    d[0x4001] = CLK_A + struct.pack('>H', 2) + bytes([1, 0]) + struct.pack('>q', corr(50))
    return d


def build_mgmt(c):
    d = mm_data()
    t = 1700000100.0
    seq = 0
    for mid, data in sorted(d.items()):
        c.at(t); t += 0.01
        c.udp(320, mm(mid, data, action=(1 if seq % 5 == 1 else 2), seq=seq))
        seq += 1
    # Variants: IDs without data (GET), with data for the no data IDs, unknown ID
    for mid in (0x0000, 0x0003, 0x0004, 0x0007, 0x200d, 0x200e):
        c.udp(320, mm(mid, b'', action=0, seq=seq)); seq += 1
        c.udp(320, mm(mid, b'\0\0', action=3, seq=seq)); seq += 1
    c.udp(320, mm(0x7777, b'\0\0\0\0', action=4, seq=seq)); seq += 1
    c.udp(320, mm(0x2001, b'', action=0, seq=seq)); seq += 1
    c.udp(320, mm(0x2004, b'', action=5, seq=seq)); seq += 1      # unknown action
    # Clock description with an odd protocol address length (expert), user
    # description with odd text length (pad)
    odd = (struct.pack('>H', 0x0080) + text('') + struct.pack('>H', 0) +
           struct.pack('>HH', 3, 5) + bytes([1, 2, 3, 4, 5]) +
           bytes.fromhex('00b0c8') + b'\0' + text('') + text('') + text('') + bytes(6))
    c.udp(320, mm(0x0001, even(odd, 6), seq=seq)); seq += 1
    c.udp(320, mm(0x0002, even(text('abc'), 6), seq=seq)); seq += 1
    # Grandmaster cluster table with an odd length (expert), unicast master
    # table without padding (expert)
    c.udp(320, mm(0x2017, struct.pack('>bB', -2, 1) + struct.pack('>HH', 1, 3) + bytes([10, 0, 0]) + b'\0', seq=seq)); seq += 1
    c.udp(320, mm(0x2018, struct.pack('>bH', -1, 1) + struct.pack('>HH', 1, 3) + bytes([10, 0, 0]), seq=seq)); seq += 1
    # Management error status with and without display data
    c.udp(320, v2(MGMT, mgmt_body(action=4), seq=seq,
                  extra=tlv(2, struct.pack('>HHI', 0x0002, 0x2004, 0))))
    seq += 1
    c.udp(320, v2(MGMT, mgmt_body(action=4), seq=seq,
                  extra=tlv(2, even(struct.pack('>HHI', 0xfffe, 0x2000, 0) + text('bad'), 4))))
    seq += 1
    c.udp(320, v2(MGMT, mgmt_body(action=4), seq=seq,
                  extra=tlv(2, even(struct.pack('>HHI', 0x0042, 0x2000, 0) + text('odd!'), 4))))
    seq += 1
    # A management message whose TLV is neither management nor error status
    c.udp(320, v2(MGMT, mgmt_body(action=0), seq=seq,
                  extra=oe(0x123456, 1, b'\1\2')))
    seq += 1


# ------------------------------------------------------------------ TLVs

def build_tlvs(c):
    t = 1700000300.0
    c.at(t)
    seq = 100
    # Announce messages with TLVs
    pt = tlv(8, CLK_A + CLK_B + CLK_C)
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=pt, domain=24, minorsdo=7)); seq += 1
    # Path trace with a length that is not a multiple of 8 (regression: the
    # end was computed 4 octets too far), followed by another TLV
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=tlv(8, CLK_A + b'\x09\x0a\x0b\x0c') + tlv(0x8008, b'\xaa\xbb\xcc\xdd'))); seq += 1
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=tlv(8, b''))); seq += 1
    atoi = tlv(9, bytes([1]) + struct.pack('>ii', -3600, 3600) + ts(1800000000, 0)[:6] + text('DST') + b'\0')
    c.udp(320, v2(ANN, an_body(p1=1, cls=248, acc=0xfe, var=0xffff, src=0xa0), seq=seq,
                  flags=UTCV | PTPTS | TTRA | FTRA | LI59 | UNICAST | ALT | SYNCU | SP1 | SP2 | SEC,
                  extra=atoi)); seq += 1
    # CERN White Rabbit TLVs in Announce and Signaling messages
    CERN = 0x080030
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(CERN, 0xdead01, struct.pack('>HH', 0x2000, 0x7)))); seq += 1
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(CERN, 0xdead01, struct.pack('>HH', 0x2000, 0x0)))); seq += 1
    for mid, data in ((0x1000, b''), (0x1001, b''), (0x1002, b''), (0x1003, struct.pack('>BBI', 3, 2, 1000)),
                      (0x1004, struct.pack('>qq', corr(1000), corr(2000))), (0x1005, b''), (0x0000, b''),
                      (0x4321, b'')):
        c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=oe(CERN, 0xdead01, struct.pack('>H', mid) + data))); seq += 1
    # Signaling with unicast negotiation TLVs
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(4, struct.pack('>BbI', 0x00, 1, 300)))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(4, struct.pack('>BbI', 0x10, 0, 60)))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(5, struct.pack('>BbIBB', 0x00, -3, 300, 0, 1)))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(5, struct.pack('>BbIBB', 0xb0, 7, 300, 0, 0)))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(6, bytes([0x00, 0, 0, 0])))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(6, bytes([0x10, 0x00])) + tlv(7, bytes([0x10, 0x00])))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(7, bytes([0x00, 0x00])))); seq += 1
    # Signaling with an L1 sync TLV (basic and extended flags), interface
    # rate, authentication TLV, unknown TLVs, pad TLV
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(0x8001, bytes([0x07, 0x03])))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(0x8001, bytes([0x00, 0x00])))); seq += 1
    ext = (bytes([0x0f, 0xff, 0xff]) + struct.pack('>q', corr(12, 3)) + ts(1700000000, 5) +
           struct.pack('>q', corr(-4)) + ts(1700000001, 6))
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(0x8001, even(ext)))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq,
                  extra=oe(0x0019a7, 2, struct.pack('>QHH', 1000000, 10, 20)))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=oe(0x0019a7, 3, b'\0\0\0\0'))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(0x8009, bytes([1, 0]) + struct.pack('>I', 7) + bytes(16)))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(0x8009, bytes([1, 0]) + struct.pack('>I', 7)))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(0x2000, bytes(range(12))) + tlv(0x4000, b'\1\2\3\4') +
                  tlv(0x8008, bytes(8)) + tlv(0x0077, b'\1\2'))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(0x8003, b'') + tlv(0x4001, b'\0\0'))); seq += 1
    # Organisation extension TLVs of the other organisations over UDP
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x1c129d, 1, struct.pack('>HII', 0x10, 100, 200) + b'\0\0'))); seq += 1
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x1c129d, 2, struct.pack('>HIIH', 0x10, 0, 300, 0)))); seq += 1
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x1c129d, 3, b'\0\0'))); seq += 1
    smpte = (struct.pack('>II', 30000, 1001) + bytes([1, 0x03]) + struct.pack('>ii', 3600, 0) +
             ts(0, 0)[:6] + ts(1, 0)[:6] + ts(2, 0)[:6] + struct.pack('>i', 0) + bytes([0x07, 0x01]))
    assert len(smpte) == 42
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x6897e8, 1, smpte))); seq += 1
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x6897e8, 2, b'\0\0'))); seq += 1
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x123456, 9, b'\1\2\3\4\5\6'))); seq += 1
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x00005e, 7, b'\1\2'))); seq += 1
    # IEEE 802.1 TLVs over UDP (not 802.1AS: expert)
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=oe(0x0080c2, 2, bytes([1, 2, 3, 0x07]) + b'\0\0'))); seq += 1
    # NTP TLV in an Announce message (propagated and not propagated)
    ntp = bytes([0x23, 2, 6, 0xec]) + bytes(44)
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x00005e, 1, b'\0\0' + ntp))); seq += 1
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x00005e, 1, b'\0\0' + ntp, t=0x8000))); seq += 1
    c.udp(320, v2(ANN, an_body(), seq=seq, extra=oe(0x00005e, 1, b'\0\0' + ntp) + tlv(0x8008, bytes(4)))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=oe(0x00005e, 5, b'\1\2\3\4', t=0x8000))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=oe(0x123456, 5, b'\1\2\3\4', t=0x8000))); seq += 1
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=oe(0x0080c2, 9, b'\1\2\3\4', t=0x8000))); seq += 1
    # Trailing octets after the last TLV (too short for a TLV header)
    c.udp(320, v2(SIG, pid(CLK_B, 1), seq=seq, extra=tlv(0x0077, b'\1\2') + b'\1\2\3')); seq += 1


# ------------------------------------------------------------- analysis

def build_analysis(c):
    s = 1000
    # Two step sync, rate ratio and interval on the second pair on
    t = 1700001000.0
    for i in range(4):
        c.at(t + i * 1.0)
        c.udp(319, v2(SYNC, ts(0, 0), seq=10 + i, flags=TWO_STEP | UTCV | PTPTS, logint=0))
        c.at(t + i * 1.0 + 0.001)
        c.udp(320, v2(FUP, ts(s + i, 100 + i * 1000000000 // 1000000 * 0 + i * 9), seq=10 + i,
                      correction=corr(200 + i, 0x2000), logint=0, control=2))
    # One step sync
    t = 1700001010.0
    for i in range(3):
        c.at(t + i * 1.0)
        c.udp(319, v2(SYNC, ts(s + 20 + i, 5000 + i * 11), seq=20 + i, flags=UTCV | PTPTS,
                      correction=corr(300, 1), logint=127 if i == 2 else -3))
    # Sync sequence wrapping: seq 65535 then 0
    c.at(1700001020.0)
    c.udp(319, v2(SYNC, ts(s + 30, 0), seq=65535, flags=0, logint=1))
    c.at(1700001021.0)
    c.udp(319, v2(SYNC, ts(s + 31, 0), seq=0, flags=0, logint=1))
    # The same sequence id again more than a second later: not a match
    c.at(1700001030.0)
    c.udp(319, v2(SYNC, ts(s + 40, 0), seq=0, flags=0))
    # Two step sync without follow up, follow up without sync
    c.at(1700001040.0)
    c.udp(319, v2(SYNC, ts(0, 0), seq=500, flags=TWO_STEP))
    c.at(1700001041.0)
    c.udp(320, v2(FUP, ts(s + 50, 0), seq=501, control=2))
    # Another clock, domain and sdo id, minor version
    c.at(1700001050.0)
    c.udp(319, v2(SYNC, ts(0, 0), clk=CLK_B, port=2, seq=1, flags=TWO_STEP, domain=7, minorsdo=3, minorver=1))
    c.at(1700001050.01)
    c.udp(320, v2(FUP, ts(s + 60, 7), clk=CLK_B, port=2, seq=1, domain=7, minorsdo=3, minorver=1, control=2))
    # Delay request/response (no analysis)
    c.at(1700001060.0)
    c.udp(319, v2(DREQ, ts(0, 0), clk=CLK_B, port=2, seq=3))
    c.udp(320, v2(DRESP, ts(s + 70, 1) + pid(CLK_B, 2), clk=CLK_A, port=1, seq=3, control=3))
    # Peer delay: requests from A answered by B
    t = 1700001100.0
    for i in range(3):
        c.at(t + i)
        c.udp(319, v2(PDREQ, ts(0, 0) + bytes(10), clk=CLK_A, port=1, seq=30 + i))
        c.at(t + i + 0.0002)
        c.udp(319, v2(PDRESP, ts(s + 80 + i, 1000 + i * 3) + pid(CLK_A, 1), clk=CLK_B, port=1, seq=30 + i,
                      flags=TWO_STEP))
        c.at(t + i + 0.0003)
        c.udp(320, v2(PDFUP, ts(s + 80 + i, 1000 + i * 3 + 100000) + pid(CLK_A, 1), clk=CLK_B, port=1, seq=30 + i))
    # The request receipt time two seconds after the response origin time
    # (odd seconds in the mean propagation delay)
    c.at(1700001105.0)
    c.udp(319, v2(PDREQ, ts(0, 0) + bytes(10), clk=CLK_A, port=1, seq=35))
    c.at(1700001105.5)
    c.udp(319, v2(PDRESP, ts(s + 87, 1000) + pid(CLK_A, 1), clk=CLK_B, port=1, seq=35, flags=TWO_STEP))
    c.udp(320, v2(PDFUP, ts(s + 85, 2000) + pid(CLK_A, 1), clk=CLK_B, port=1, seq=35))
    # Peer delay failures: request without response, response without
    # request, two step response without follow up, follow up without
    # response, one step response with a follow up
    c.at(1700001110.0)
    c.udp(319, v2(PDREQ, ts(0, 0) + bytes(10), clk=CLK_A, port=1, seq=40))
    c.at(1700001111.0)
    c.udp(319, v2(PDRESP, ts(s + 90, 1) + pid(CLK_C, 9), clk=CLK_B, port=1, seq=41, flags=TWO_STEP))
    c.at(1700001112.0)
    c.udp(319, v2(PDREQ, ts(0, 0) + bytes(10), clk=CLK_C, port=9, seq=42))
    c.udp(319, v2(PDRESP, ts(s + 91, 1) + pid(CLK_C, 9), clk=CLK_B, port=1, seq=42, flags=TWO_STEP))
    c.at(1700001113.0)
    c.udp(320, v2(PDFUP, ts(s + 92, 1) + pid(CLK_C, 9), clk=CLK_B, port=1, seq=43))
    c.at(1700001114.0)
    c.udp(319, v2(PDREQ, ts(0, 0) + bytes(10), clk=CLK_C, port=9, seq=44))
    c.udp(319, v2(PDRESP, ts(s + 93, 1) + pid(CLK_C, 9), clk=CLK_B, port=1, seq=44, flags=0))
    c.udp(320, v2(PDFUP, ts(s + 93, 5) + pid(CLK_C, 9), clk=CLK_B, port=1, seq=44))


# ------------------------------------------------------------- 802.1AS

def build_as(c):
    G = dict(majorsdo=1, minorver=0)
    t = 1700002000.0
    c.at(t)
    ga = CLK_C
    c.eth(v2(ANN, an_body(as_=True, gm=ga, steps=1), clk=ga, port=1, seq=1, domain=0, flags=PTPTS | UTCV | TTRA | FTRA,
             logint=0, **G,
             extra=tlv(8, ga)))
    # Two step sync (no origin timestamp) and follow up with the information TLV
    fu_tlv = oe(0x0080c2, 1, struct.pack('>iH', 0x1000, 0) + struct.pack('>IIq', 0, 0, 0)[:12] +
                struct.pack('>i', 0x20))
    for i in range(3):
        c.at(t + 1 + i * 0.125)
        c.eth(v2(SYNC, b'\0' * 10, clk=ga, port=1, seq=10 + i, flags=TWO_STEP, logint=-3, **G))
        c.at(t + 1 + i * 0.125 + 0.0005)
        c.eth(v2(FUP, ts(s_ := 2000 + i, 125000000 * i), clk=ga, port=1, seq=10 + i, logint=-3, control=2,
                 correction=corr(10 + i), **G, extra=fu_tlv))
    # One step sync with the follow up information TLV, without it (expert)
    c.at(t + 2)
    c.eth(v2(SYNC, ts(2100, 1), clk=ga, port=1, seq=20, flags=0, logint=-3, **G, extra=fu_tlv))
    c.at(t + 2.125)
    c.eth(v2(SYNC, ts(2100, 2), clk=ga, port=1, seq=21, flags=0, logint=-3, **G))
    # Two step sync with the follow up TLV (expert), follow up without TLV
    c.at(t + 2.25)
    c.eth(v2(SYNC, b'\0' * 10, clk=ga, port=1, seq=22, flags=TWO_STEP, **G, extra=fu_tlv))
    c.at(t + 2.3)
    c.eth(v2(FUP, ts(2200, 0), clk=ga, port=1, seq=22, control=2, **G))
    # Peer delay in 802.1AS (no origin timestamp)
    for i in range(2):
        c.at(t + 3 + i)
        c.eth(v2(PDREQ, b'\0' * 20, clk=CLK_B, port=2, seq=70 + i, logint=0, **G), src=2)
        c.at(t + 3 + i + 0.0001)
        c.eth(v2(PDRESP, ts(2300 + i, 100) + pid(CLK_B, 2), clk=ga, port=1, seq=70 + i, flags=TWO_STEP, **G))
        c.at(t + 3 + i + 0.0002)
        c.eth(v2(PDFUP, ts(2300 + i, 600 + i) + pid(CLK_B, 2), clk=ga, port=1, seq=70 + i, **G))
    # Signaling with the message interval request TLV, gPTP capable TLVs,
    # CSN TLV and the drift tracking TLV
    t += 10
    c.at(t)
    mi = oe(0x0080c2, 2, bytes([0x7f, 0xfd, 0x7e, 0x07]) + b'\0\0')
    c.eth(v2(SIG, pid(CLK_B, 2), clk=ga, port=1, seq=80, **G, extra=mi))
    c.eth(v2(SIG, pid(CLK_B, 2), clk=ga, port=1, seq=81, **G,
             extra=oe(0x0080c2, 4, bytes([3, 1, 0, 0, 0, 0]), t=0x8000)))
    c.eth(v2(SIG, pid(CLK_B, 2), clk=ga, port=1, seq=82, **G,
             extra=oe(0x0080c2, 5, bytes([3, 0, 0, 0]), t=0x8000)))
    csn = oe(0x0080c2, 3, bytes(12) + bytes(4) + bytes(12) + bytes(12) + b'\0')
    c.eth(v2(SIG, pid(CLK_B, 2), clk=ga, port=1, seq=83, **G, extra=csn))
    dt = oe(0x0080c2, 6, ts(2400, 1)[:6] + struct.pack('>IH', 77, 0x8000) + ga + struct.pack('>Hi', 3, 1 << 20))
    c.eth(v2(SIG, pid(CLK_B, 2), clk=ga, port=1, seq=84, **G, extra=dt))
    # Gate: unknown 802.1 subtype, and a 802.1AS flag combination
    c.eth(v2(SIG, pid(CLK_B, 2), clk=ga, port=1, seq=85, **G, extra=oe(0x0080c2, 9, b'\1\2')))
    # Not 802.1AS: Ethernet with majorSdoId 0 and a Management message
    c.eth(v2(ANN, an_body(), clk=CLK_A, port=1, seq=90, extra=tlv(8, CLK_A)), dst=bytes.fromhex('011b19000000'))
    c.eth(v2(DREQ, ts(0, 0), clk=CLK_A, port=1, seq=91), dst=bytes.fromhex('011b19000000'))
    c.eth(mm(0x2004, mm_data()[0x2004], seq=92, clk=CLK_A), dst=bytes.fromhex('011b19000000'))


# ---------------------------------------------------------------- others

def build_misc(c):
    t = 1700003000.0
    c.at(t)
    # Message type values that are not defined, and message length
    # shorter than the packet (extra octets cut off)
    c.udp(320, v2(0x04, b'\0' * 10, seq=1))
    c.udp(320, v2(0x0e, b'\0' * 10, seq=2))
    c.udp(320, v2(SYNC, ts(1, 2) + b'\xee\xee\xee\xee', seq=3, length=44))
    # PTP version 3 is not PTPv2 and PTP version 1 in the second octet
    # of the new header is PTPv1; both are shown as data
    c.udp(320, v2(SYNC, ts(1, 2), seq=4, ver=3))
    # A negative correction field and the maximum value
    c.udp(319, v2(SYNC, ts(1, 2), seq=5, correction=-(5 << 16) - 3))
    c.udp(319, v2(SYNC, ts(1, 2), seq=6, correction=0x7fffffffffffffff))


def build_malformed(path):
    c = Cap()
    c.at(1700004000.0)
    # Message length larger than the packet, too small, smaller than header
    c.udp(320, v2(SYNC, ts(1, 2), seq=1, length=400))
    c.udp(320, v2(SYNC, ts(1, 2), seq=2, length=3))
    c.udp(320, v2(ANN, an_body(), seq=3, length=20))
    # Truncated bodies
    c.udp(320, v2(ANN, an_body())[:50])
    c.udp(320, v2(FUP, ts(1, 2))[:40])
    c.udp(320, v2(DRESP, ts(1, 2) + pid(CLK_B, 2))[:50])
    c.udp(320, v2(PDRESP, ts(1, 2) + pid(CLK_B, 2))[:50])
    c.udp(320, v2(SIG, pid(CLK_B, 2))[:38])
    c.udp(320, v2(MGMT, mgmt_body())[:46])
    # TLVs cut short or with bad lengths
    c.udp(320, v2(SIG, pid(CLK_B, 1), extra=tlv(0x8009, b'\1\0\0\0')))             # ICV length < 0
    c.udp(320, v2(SIG, pid(CLK_B, 1), extra=struct.pack('>HH', 0x0003, 40) + b'\0\x80\xc2\0\0\x02'))
    c.udp(320, v2(SIG, pid(CLK_B, 1), extra=struct.pack('>HH', 0x0077, 40) + b'\1\2'))
    c.udp(320, v2(SIG, pid(CLK_B, 1), extra=struct.pack('>HH', 0x0003, 4) + b'\0\x00\x5e\0\0\x01'))  # NTP TLV too short
    c.udp(320, v2(MGMT, mgmt_body(), extra=struct.pack('>HHH', 1, 40, 0x2004)))
    c.udp(320, v2(MGMT, mgmt_body(), extra=struct.pack('>HHH', 1, 40, 0x0006) + struct.pack('>H', 200)))
    c.udp(320, v2(MGMT, mgmt_body(), extra=struct.pack('>HHH', 1, 40, 0x0001) + b'\0\0\xff'))
    c.udp(320, v2(MGMT, mgmt_body(), extra=struct.pack('>HHH', 1, 40, 0x2017) + bytes([0, 50]) + b'\0\0\0\2'))
    c.udp(320, v2(MGMT, mgmt_body(), extra=struct.pack('>HHH', 1, 40, 0x201a) + struct.pack('>H', 9)))
    c.udp(320, v2(MGMT, mgmt_body(), extra=struct.pack('>HHH', 2, 40, 0x0001)))
    # Version 1 messages cut short
    c.udp(320, v1(2, size=60)[:45])
    c.udp(320, v1(4, key=8)[:100])
    c.write(path)


def main(outdir):
    c = Cap()
    build_v1(c)
    build_analysis(c)
    build_tlvs(c)
    build_mgmt(c)
    build_as(c)
    build_misc(c)
    c.write(os.path.join(outdir, 'ptp-coverage.pcap'))
    build_malformed(os.path.join(outdir, 'ptp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1])
