#!/usr/bin/env python3
# Generates test/captures/zbee_zcl_se_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic coverage captures for packet-zbee-zcl-se.c (ZigBee Smart Energy
# clusters: Price, DRLC, Metering, Messaging, Tunneling, Prepayment, Energy
# Management, Calendar, Daily Schedule, Device Management, Events, MDU
# Pairing, Sub-GHz, Key Establishment, Keep-Alive).
# Usage: mkzbee-zcl-se.py <outdir> [-v]
# Writes zbee-zcl-se-coverage.pcapng (main) and
# zbee-zcl-se-coverage-malformed.pcapng.
# Frames that fit in 127 octets go over ZEP v2 / UDP 17754 / Ethernet
# (IDB 0), longer ones as raw 802.15.4 without FCS (linktype 230, IDB 1).
# The ZCL payloads are built field by field from the dissector; nothing is
# captured, all addresses are 192.0.2.0/24.  No security is used.
import struct
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != '-v' else '.'
VERBOSE = '-v' in sys.argv

# ---------------------------------------------------------------- helpers
def u8(v): return struct.pack('<B', v & 0xff)
def u16(v): return struct.pack('<H', v & 0xffff)
def u24(v): return struct.pack('<I', v & 0xffffff)[:3]
def u32(v): return struct.pack('<I', v & 0xffffffff)
def S(s):
    s = s.encode() if isinstance(s, str) else s
    return u8(len(s)) + s
T0 = 0x2c1f0000          # a ZigBee UTC time (seconds since 2000-01-01)
def T(n=0): return u32(T0 + n)
def date(y=22, m=11, d=12, w=6): return bytes([y, m, d, w])

def crc16_kermit(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc

def ip_csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

SE = 0x0109
seqno = [0]

def wpan_nwk_aps(cluster, zcl, profile=SE):
    seqno[0] = (seqno[0] + 1) & 0xff
    s = seqno[0]
    mac = struct.pack('<HBHHH', 0x8841, s, 0x1234, 0x0000, 0x0001)
    nwk = struct.pack('<HHHBB', 0x0008, 0x0000, 0x0001, 0x1e, s)
    aps = struct.pack('<BBHHBB', 0x00, 0x01, cluster, profile, 0x01, s)
    return mac + nwk + aps + zcl

def zep(frame, seq):
    return (b'EX' + bytes([2, 1, 11]) + struct.pack('!H', 1) + bytes([1, 0xff])
            + struct.pack('!Q', 0) + struct.pack('!I', seq) + b'\0' * 10
            + bytes([len(frame)]) + frame)

def udp_ip_eth(payload, i):
    udp = struct.pack('!HHHH', 17754, 17754, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), i & 0xffff, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('!H', ip_csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002' '020000000001' '0800') + ip + udp

class Cap:
    def __init__(self):
        self.pk = []          # (idb, bytes)
        self.groups = []
    def frame(self, cluster, zcl, profile=SE):
        f = wpan_nwk_aps(cluster, zcl, profile)
        n = len(self.pk) + 1
        if len(f) + 2 <= 127:
            f += struct.pack('<H', crc16_kermit(f))
            self.pk.append((0, udp_ip_eth(zep(f, n), n)))
        else:
            self.pk.append((1, f))
    def group(self, name):
        self.groups.append((name, len(self.pk) + 1))
    def write(self, path):
        def blk(t, body):
            body += b'\0' * (-len(body) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 1, 0, 65535))
        out += blk(1, struct.pack('<HHI', 230, 0, 65535))
        for i, (idb, p) in enumerate(self.pk):
            ts = 1700000000_000000 + i * 1000
            out += blk(6, struct.pack('<IIIII', idb, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
        open(path, 'wb').write(out)

def fcf(to_client, specific=True):
    return (0x01 if specific else 0x00) | (0x08 if to_client else 0) | 0x10

zseq = [0]
def zcl(to_client, cmd, payload=b'', specific=True):
    zseq[0] = (zseq[0] + 1) & 0xff
    return bytes([fcf(to_client, specific), zseq[0], cmd]) + payload

main = Cap()
mal = Cap()

def srv(cap, cluster, cmd, payload=b''):      # client -> server (Get ...)
    cap.frame(cluster, zcl(False, cmd, payload))
def cli(cap, cluster, cmd, payload=b''):      # server -> client (Publish ...)
    cap.frame(cluster, zcl(True, cmd, payload))

def attr_rec(aid, typ, data, status=0):
    if status: return u16(aid) + u8(status)
    return u16(aid) + u8(status) + u8(typ) + data
def read_attr_resp(cap, cluster, recs, to_client=True):
    cap.frame(cluster, zcl(to_client, 0x01, b''.join(recs), False))
def report_attr(cap, cluster, recs, to_client=True):
    cap.frame(cluster, zcl(to_client, 0x0a, b''.join(recs), False))
def write_attr(cap, cluster, recs, to_client=False):
    recs = [r[:2] + r[3:] for r in recs]          # no status octet in a write record
    cap.frame(cluster, zcl(to_client, 0x02, b''.join(recs), False))

# data types
BOOL, BM8, BM16, BM32, U8, U16, U24, U32, S8, S16, S32, ENUM8, ENUM16 = 0x10, 0x18, 0x19, 0x1b, 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2b, 0x30, 0x31
OCT, CHR, UTC, EUI = 0x41, 0x42, 0xe2, 0xf0

# ------------------------------------------------------------- Keep-Alive
KA, PRICE, DRLC, MET, MSG, TUN, PP, EM, CAL, DSH, DEV, EVT, MDU, SGHZ, KE = (
    0x0025, 0x0700, 0x0701, 0x0702, 0x0703, 0x0704, 0x0705, 0x0706, 0x0707,
    0x070d, 0x0708, 0x0709, 0x070a, 0x070b, 0x0800)
ALLC = [KA, PRICE, DRLC, MET, MSG, TUN, PP, EM, CAL, DSH, DEV, EVT, MDU, SGHZ, KE]

main.group('Keep-Alive')
cli(main, KA, 0x00, b'')                           # no payload
srv(main, KA, 0x00, b'\x01')
read_attr_resp(main, KA, [attr_rec(0x0000, U8, u8(10)), attr_rec(0x0001, U16, u16(5)),
                          attr_rec(0xfffe, U8, u8(1)), attr_rec(0x0100, U8, u8(7)),
                          attr_rec(0x0002, 0, b'', status=0x86)])

# ------------------------------------------------------------------ Price
main.group('Price: get commands')
srv(main, PRICE, 0x00, u8(0x01))
srv(main, PRICE, 0x00)
srv(main, PRICE, 0x01, T() + u8(3))
srv(main, PRICE, 0x02, u32(1) + u32(2) + T(5) + u8(1))
srv(main, PRICE, 0x03, T() + u8(2))
srv(main, PRICE, 0x03, T() + u8(2) + u8(0x01))
srv(main, PRICE, 0x04, T() + u32(7) + u8(1))
srv(main, PRICE, 0x05, T() + u32(7) + u8(1))
srv(main, PRICE, 0x06, T() + u32(7) + u8(2) + u8(0x01))
srv(main, PRICE, 0x07, u32(0x1234))
srv(main, PRICE, 0x08, u32(0x1234))
srv(main, PRICE, 0x09, T() + u32(7) + u8(1))
srv(main, PRICE, 0x09, T() + u32(7) + u8(1) + u8(0x02))
srv(main, PRICE, 0x0a, u32(0x1234))
srv(main, PRICE, 0x0b, T() + u32(7) + u8(1))
srv(main, PRICE, 0x0b, T() + u32(7) + u8(1) + u8(0x01))
srv(main, PRICE, 0x0c, T() + u32(7) + u8(1))
srv(main, PRICE, 0x0c, T() + u32(7) + u8(1) + u8(0x03))
srv(main, PRICE, 0x0d, u32(0x55) + u8(1))
srv(main, PRICE, 0x0e, T() + u8(5))
srv(main, PRICE, 0x0f, u32(1) + u32(2))
srv(main, PRICE, 0x10, u32(1) + u32(2))

main.group('Price: publish price (progressively longer optional tail)')
base = (u32(0x100) + S('Tariff 1') + u32(0x77) + T(0) + u8(0x00) + u16(826) + u8(0x23)
        + u8(0x12) + T(3600) + u16(60) + u32(15000))
tail = [u8(0x80), u32(9000), u8(0x40), u32(12345), u8(0x01), u8(0x32), u8(3), u8(0x01), u8(2),
        u8(1), u8(4), u8(0x05), u8(0x06)]
for k in range(len(tail) + 1):
    cli(main, PRICE, 0x00, base + b''.join(tail[:k]))
cli(main, PRICE, 0x00, u32(0x100) + S('') + u32(0x77) + T(0) + u8(0xa0) + u16(0x0348) + u8(0x00)
    + u8(0xf0) + T(0) + u16(0xffff) + u32(0))      # empty label, no optional
main.group('Price: other publish commands')
def bt(n): return struct.pack('<Q', n)[:6]          # 48 bit block threshold
cli(main, PRICE, 0x01, u32(1) + u32(2) + T(0) + u24(1440) + u8(0x01) + u8(0x02) + u8(0x01) + u8(15))
cli(main, PRICE, 0x02, u32(2) + T(0) + u32(1000000) + u8(0x23))
cli(main, PRICE, 0x03, u32(2) + T(0) + u32(38000000) + u8(0x01) + u8(0x47))
cli(main, PRICE, 0x04, u32(1) + u32(2) + u32(0x33) + T(0) + u8(0x22) + S('Standard') + u8(4) + u8(2)
    + u8(0x00) + u16(826) + u8(0x21) + u32(2500) + u8(0x01) + u24(1) + u24(2))
cli(main, PRICE, 0x04, u32(1) + u32(2) + u32(0x33) + T(0) + u8(0x13) + S('') + u8(1) + u8(0)
    + u8(0x01) + u16(840) + u8(0x30) + u32(0) + u8(0x00) + u24(0) + u24(1))
hdr = u32(1) + u32(2) + T(0) + u32(0x33) + u8(0) + u8(1)
cli(main, PRICE, 0x05, hdr + u8(0) + u8(0x00) + u32(1500) + u8(0x11) + u32(1600) + u8(0x32) + u32(1700))
cli(main, PRICE, 0x05, hdr + u8(1) + u8(0x03) + u32(1500) + u8(0x04) + u32(1700))
cli(main, PRICE, 0x06, hdr + u8(0) + u8(0x22) + bt(100) + bt(200) + u8(0x01) + bt(5))
cli(main, PRICE, 0x06, hdr + u8(1) + u8(0x01) + bt(5) + u8(0x02) + bt(7) + bt(8) + u8(0x00))
cli(main, PRICE, 0x07, u32(1) + u32(2) + T(0) + u8(0x01) + u32(5000) + u8(0x01) + u8(0x21))
cli(main, PRICE, 0x08, u32(1) + u32(2) + u32(0x33) + u8(0) + u8(1) + u8(3)
    + u8(1) + S('Peak') + u8(2) + S('Off-peak') + u8(3) + S(''))
cli(main, PRICE, 0x09, u32(1) + u32(2) + T(0) + u24(30) + u8(0x02) + u8(0x01))
cli(main, PRICE, 0x0a, u32(1) + u32(2) + T(0) + u24(30) + u8(0x01) + u8(0x01) + u32(123456) + u16(826) + u8(0x23))
cli(main, PRICE, 0x0b, u32(1) + u32(2) + T(0) + u16(120) + u8(0x01) + u8(2) + u8(1))
cli(main, PRICE, 0x0c, u32(1) + u32(2) + T(0) + u32(2500) + u8(1) + u32(5000) + T(7) + S('REF123'))
cli(main, PRICE, 0x0d, u32(1) + u32(2) + T(0) + u16(826) + u16(978) + u32(11500) + u8(0x23) + u32(0x00000001))
cli(main, PRICE, 0x0e, u32(1) + u32(2) + u8(0x01))
cli(main, PRICE, 0x00)
read_attr_resp(main, PRICE, [attr_rec(0x0000, CHR, S('Tier 1')), attr_rec(0x0100, U32, u32(100)),
                             attr_rec(0xfffe, U8, u8(1))])
read_attr_resp(main, PRICE, [attr_rec(0xfffe, U8, u8(2)), attr_rec(0x0300, U8, u8(3))], to_client=False)

# ------------------------------------------------------------------- DRLC
main.group('DRLC')
cli(main, DRLC, 0x00, u32(0x1001) + u16(0x0101) + u8(1) + T(60) + u16(30) + u8(2) + u8(0x10) + u8(0x20)
    + u16(2500) + u16(2000) + u8(50) + u8(60) + u8(0x03))
cli(main, DRLC, 0x01, u32(0x1001) + u16(0x00ff) + u8(1) + u8(0x01) + T(0))
cli(main, DRLC, 0x02, u8(0x01))
srv(main, DRLC, 0x00, u32(0x1001) + u8(1) + T(60) + u8(2) + u16(2500) + u16(2000) + u8(50) + u8(60) + u8(0x01) + u8(0)
    + b'')
srv(main, DRLC, 0x00, u32(0x1002) + u8(3) + T(60) + u8(2) + u16(2500) + u16(2000) + u8(50) + u8(60) + u8(0x01) + u8(1)
    + b'\xaa' * 12)
srv(main, DRLC, 0x01, T(0) + u8(2))
srv(main, DRLC, 0x01, T(0) + u8(2) + u32(0x1001))
srv(main, DRLC, 0x01, T(0) + u8(2) + u32(0x1001) + u8(0xff))      # reproducer: issuer id in a 32 bit field
read_attr_resp(main, DRLC, [attr_rec(0xfffe, U8, u8(1)), attr_rec(0x0000, U8, u8(3)), attr_rec(0x0001, BM8, u8(3))],
               to_client=False)
read_attr_resp(main, DRLC, [attr_rec(0xfffe, U8, u8(1)), attr_rec(0x0100, U16, u16(3))])

# --------------------------------------------------------------- Metering
main.group('Metering: requests')
srv(main, MET, 0x00, u8(1) + T() + u8(4))
srv(main, MET, 0x01, u16(0x1234))
srv(main, MET, 0x02, u16(0x1234))
srv(main, MET, 0x03, u8(10) + u8(30))
srv(main, MET, 0x04, u32(5) + u8(1) + u8(1) + u8(1) + T(60) + u24(0x010203) + u8(0x00) + u32(0x0000000f))
srv(main, MET, 0x05, u32(0x0000000f))
srv(main, MET, 0x06, T() + T(100) + u8(2) + u32(0x00000005))
srv(main, MET, 0x07, u32(1) + T() + u8(0) + u16(60) + u16(10))
srv(main, MET, 0x08, u16(1) + T() + u8(0) + u16(5))
srv(main, MET, 0x09, u8(1) + u32(0x00000011))                                  # scheme A: 1 flag word
srv(main, MET, 0x09, u8(2) + b''.join(u32(i + 1) for i in range(5)))           # scheme B: 5 flag words
srv(main, MET, 0x09, u8(3) + u32(1) + u32(2))                                  # other scheme: all words
srv(main, MET, 0x0a, u32(1) + u32(2))
srv(main, MET, 0x0b, u32(1) + u32(2) + u32(3) + u32(4) + u8(1) + u8(1))
srv(main, MET, 0x0c, u8(1))
srv(main, MET, 0x0d, u32(1) + u8(1) + u8(2) + u8(1) + u8(3))
srv(main, MET, 0x0e, u32(1) + u32(2) + u16(3) + u8(4) + u16(5) + u16(6) + u8(7) + u16(8))
main.group('Metering: responses')
cli(main, MET, 0x00, T() + u8(0) + u8(4) + u8(3) + u24(1) + u24(2) + u24(3))
cli(main, MET, 0x00, T() + u8(1) + u8(4) + u8(0))
cli(main, MET, 0x01, u16(1))
cli(main, MET, 0x02, u16(1))
cli(main, MET, 0x03, u8(1) + T())
cli(main, MET, 0x04, u32(5) + u8(1) + u8(0) + u8(2) + u8(1))
cli(main, MET, 0x05, u32(5) + u8(0))
cli(main, MET, 0x06, u32(5) + T() + u8(1) + u8(0) + u8(1) + u32(0x00000003) + u8(0) + b'\x01\x02\x03\x04\x05')
cli(main, MET, 0x07, u16(1) + T() + u8(0) + u16(60) + u16(3) + u24(1) + u24(2) + u24(3))
cli(main, MET, 0x07, u16(1) + T() + u8(0) + u16(60) + u16(0))
cli(main, MET, 0x08, u32(1) + u24(0x2a2a2a) + u8(1) + u8(2))
cli(main, MET, 0x09, u32(1) + u8(1) + u32(0x00000007))
cli(main, MET, 0x0a, u32(1) + u8(2) + u16(0x0000) + u16(0x0702) + u16(0x1234) + u8(3) + u8(1) + u8(2) + u8(3))
cli(main, MET, 0x0b, u8(1) + u16(0x0000) + u32(0x00000001))
cli(main, MET, 0x0b, u8(2) + u16(0x0001) + u32(0x00000002))
cli(main, MET, 0x0b, u8(2) + u16(0x0002) + u32(0x00000003))
cli(main, MET, 0x0b, u8(2) + u16(0x0003) + u32(0x00000004))
cli(main, MET, 0x0b, u8(2) + u16(0x0004) + u32(0x00000005))
cli(main, MET, 0x0b, u8(2) + u16(0x0009) + u32(0x00000006))
cli(main, MET, 0x0c, u32(1) + u32(2) + u32(3) + u8(1))
cli(main, MET, 0x0d, u16(0x0102))
for a in range(5):
    read_attr_resp(main, MET, [attr_rec(a, BM32, u32(0x0000ffff >> a))], to_client=False)
read_attr_resp(main, MET, [attr_rec(0xfffe, U8, u8(2)), attr_rec(0x0000, U24, u24(1234)), attr_rec(0x0200, ENUM8, u8(1))])
read_attr_resp(main, MET, [attr_rec(0xfffe, U8, u8(2)), attr_rec(0x0010, 0x25, b'\x01\x02\x03\x04\x05\x06')], to_client=False)

# -------------------------------------------------------------- Messaging
main.group('Messaging')
srv(main, MSG, 0x00)
srv(main, MSG, 0x01, u32(0x77) + T(10))
srv(main, MSG, 0x01, u32(0x77) + T(10) + u8(0x01))
srv(main, MSG, 0x01, u32(0x77) + T(10) + u8(0x01) + S('OK thanks'))
srv(main, MSG, 0x02, T(100))
cli(main, MSG, 0x00, u32(0x77) + u8(0x13) + T(0) + u16(60) + S('Hello meter'))
cli(main, MSG, 0x00, u32(0x78) + u8(0x82) + T(5) + u16(0xffff) + S('Until changed') + u8(0x01))
cli(main, MSG, 0x00, u32(0x79) + u8(0x00) + T(5) + u16(1) + S(''))
cli(main, MSG, 0x01, u32(0x77) + u8(0x00))
cli(main, MSG, 0x01, u32(0x77) + u8(0x01))
cli(main, MSG, 0x02, u32(0x7a) + u8(0x13) + T(0) + u16(60) + S('Protected') + u8(0x00))
cli(main, MSG, 0x03, T(50))

# ------------------------------------------------------------- Tunneling
main.group('Tunneling')
srv(main, TUN, 0x00, u8(1) + u16(0x1002) + u8(1) + u16(1500))
srv(main, TUN, 0x01, u16(0x0102))
ipv4 = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])))
ipv4[10:12] = struct.pack('!H', ip_csum(bytes(ipv4)))
ip_pkt = bytes(ipv4) + struct.pack('!HHHH', 4000, 4001, 8, 0)
srv(main, TUN, 0x02, u16(0x0102) + ip_pkt)
srv(main, TUN, 0x02, u16(0x0102) + b'\x01\x02\x03\x04\x05\x06')
srv(main, TUN, 0x03, u16(0x0102) + u8(2))
srv(main, TUN, 0x04, u16(0x0102) + u16(14))
srv(main, TUN, 0x05, u16(0x0102) + u16(14))
srv(main, TUN, 0x06, u8(0))
cli(main, TUN, 0x00, u16(0x0102) + u8(0) + u16(1500))
cli(main, TUN, 0x01, u16(0x0102) + ip_pkt)
cli(main, TUN, 0x01, u16(0x0102) + b'\xaa\xbb\xcc')
cli(main, TUN, 0x02, u16(0x0102) + u8(1))
cli(main, TUN, 0x03, u16(0x0102) + u16(14))
cli(main, TUN, 0x04, u16(0x0102) + u16(14))
cli(main, TUN, 0x05, u8(1) + u8(3) + u16(0x1002) + u8(1) + u16(0xffff) + u8(0) + u16(0x1002) + u8(2))
cli(main, TUN, 0x06, u16(0x0102))
read_attr_resp(main, TUN, [attr_rec(0x0000, U16, u16(3600)), attr_rec(0xfffe, U8, u8(1))])

# ------------------------------------------------------------- Prepayment
main.group('Prepayment')
srv(main, PP, 0x00, T(1) + u8(1))
srv(main, PP, 0x02, u32(0x11) + S('Debt1') + u32(1000) + u8(1) + u8(2) + T(0) + u16(60) + u8(2) + u32(500) + u8(10))
srv(main, PP, 0x03, u32(1) + T(1) + u32(5000) + u32(300))
srv(main, PP, 0x04, u8(1) + S('1234-5678-9012'))
srv(main, PP, 0x05, u32(1) + T(1) + u8(1) + u32(500))
srv(main, PP, 0x06, u32(1) + u32(2) + T(1) + u16(0x1111) + u32(7))
srv(main, PP, 0x07, u32(1) + T(1) + u8(0) + u32(0x00000003))
srv(main, PP, 0x08, T(100) + u8(3))
srv(main, PP, 0x09, u32(2500))
srv(main, PP, 0x0a, T(100) + u8(3) + u8(1))
srv(main, PP, 0x0b, u32(1) + u32(2) + T(1) + u32(10000) + u32(5000))
srv(main, PP, 0x0c, u32(1) + u32(2) + T(1) + u32(20000))
cli(main, PP, 0x01, u32(1) + T(1) + u8(1) + u8(0) + u8(1) + u32(0x00000001) + u8(0) + b'\x01' * 10)
cli(main, PP, 0x02, u8(0) + u32(1) + u32(2) + u32(3))
cli(main, PP, 0x03, u8(0) + u32(1000) + u8(1) + u32(2000))
cli(main, PP, 0x05, u8(0) + u8(1) + S('CODE-1') + u32(1000) + T(5) + S('') + u32(2000) + T(6))
cli(main, PP, 0x06, u8(0) + u8(1) + T(1) + u32(100) + u8(0) + u32(500) + T(2) + u32(200) + u8(1) + u32(250))
read_attr_resp(main, PP, [attr_rec(0x0000, BM16, u16(0x0011)), attr_rec(0xfffe, U8, u8(1)), attr_rec(0x0100, U32, u32(5))],
               to_client=False)
read_attr_resp(main, PP, [attr_rec(0x0000, BM16, u16(0x0011)), attr_rec(0xfffe, U8, u8(1))])

# ------------------------------------------------------- Energy Management
main.group('Energy Management')
srv(main, EM, 0x00, u32(0x40) + u16(0x00ff) + u8(1) + u8(0x01))
cli(main, EM, 0x00, u32(0x40) + u8(1) + T(1) + u8(2) + u16(2500) + u16(2000) + u8(50) + u8(60) + u8(0x01))
srv(main, EM, 0x01, u8(0))
cli(main, EM, 0x01, u8(0))
read_attr_resp(main, EM, [attr_rec(0xfffe, U8, u8(1)), attr_rec(0x0000, ENUM8, u8(1))])

# --------------------------------------------------------------- Calendar
main.group('Calendar')
srv(main, CAL, 0x00, T() + u32(5) + u8(1) + u8(2) + u32(7))
srv(main, CAL, 0x01, u32(5) + u32(7) + u8(1) + u8(2))
srv(main, CAL, 0x02, u32(5) + u32(7) + u8(1) + u8(2))
srv(main, CAL, 0x03, u32(5) + u32(7))
srv(main, CAL, 0x04, T() + u8(1) + u8(2) + u32(5) + u32(7))
srv(main, CAL, 0x05, u32(1) + u32(2))
cli(main, CAL, 0x00, u32(1) + u32(2) + u32(3) + T(0) + u8(0) + u8(1) + S('Calendar A') + u8(2) + u8(1) + u8(7))
cli(main, CAL, 0x00, u32(1) + u32(2) + u32(3) + T(0) + u8(4) + u8(0) + S('') + u8(1) + u8(1) + u8(1))
for ctype, ent in ((0, u8(1)), (1, u8(2)), (2, u8(3)), (3, u8(1)), (4, u8(0)), (9, u8(0))):
    cli(main, CAL, 0x01, u32(1) + u32(2) + u32(3) + u8(1) + u8(3) + u8(1) + u8(1) + u8(ctype)
        + b''.join(u16(h * 60) + ent for h in (0, 6, 22)))
cli(main, CAL, 0x01, u32(1) + u32(2) + u32(3) + u8(1) + u8(0) + u8(1) + u8(1) + u8(0))
cli(main, CAL, 0x02, u32(1) + u32(2) + u32(3) + u8(1) + bytes(range(1, 8)))
cli(main, CAL, 0x03, u32(1) + u32(2) + u32(3) + u8(0) + u8(1) + date(22, 1, 1, 0xff) + u8(1) + date(22, 6, 1, 0xff) + u8(2))
cli(main, CAL, 0x04, u32(1) + u32(2) + u32(3) + T(0) + u8(0) + u8(2) + u8(0) + u8(1)
    + date(22, 12, 25, 0xff) + u8(1) + date(0xff, 0xff, 0xff, 0xff) + u8(2))
cli(main, CAL, 0x05, u32(1) + u32(2) + u8(0))
read_attr_resp(main, CAL, [attr_rec(0xfffe, U8, u8(1)), attr_rec(0x0000, U8, u8(1))])

# --------------------------------------------------------- Daily Schedule
main.group('Daily Schedule')
srv(main, DSH, 0x00, u32(1) + u32(2) + u32(3) + u8(1) + u8(2))
srv(main, DSH, 0x01, u32(1) + u32(2))
srv(main, DSH, 0x05, u32(1) + u32(2))
cli(main, DSH, 0x00, u32(1) + u32(2) + u32(3) + T(0) + u8(1) + u8(2) + S('Schedule'))
cli(main, DSH, 0x01, u32(1) + u32(2) + u32(3) + u8(2) + u8(1) + u8(1) + u8(0)
    + u16(0) + u8(1) + u8(0) + u16(360) + u8(2) + u8(1))
cli(main, DSH, 0x01, u32(1) + u32(2) + u32(3) + u8(2) + u8(1) + u8(1) + u8(1)
    + u16(0) + u8(1) + u16(360) + u8(2))
cli(main, DSH, 0x05, u32(1) + u32(2) + u8(0))
read_attr_resp(main, DSH, [attr_rec(0xfffe, U8, u8(1)), attr_rec(0x0000, U8, u8(1))])

# ------------------------------------------------------ Device Management
main.group('Device Management')
for c in (0x00, 0x01, 0x03, 0x05):
    srv(main, DEV, c)
srv(main, DEV, 0x02, u8(1))
srv(main, DEV, 0x04, u8(1) + u8(2) + u16(0x0101) + u8(0x07) + u16(0x0102) + u8(0x01))
cli(main, DEV, 0x00, u32(1) + u32(2) + u8(1) + T(10) + u32(0x00000003))
cli(main, DEV, 0x01, u32(1) + u32(2) + u8(1) + u32(3) + T(10) + u32(4) + S('Acme Energy') + S('0800 123456'))
cli(main, DEV, 0x02, u32(1) + T(10) + u16(30) + u8(1) + S('s3cret'))
cli(main, DEV, 0x03, u32(1) + T(10) + u32(3) + S('SITE-0001'))
ev = u32(1) + T(10) + u8(0x03)
cli(main, DEV, 0x04, ev + u8(0) + u8(2) + u16(0x0101) + u16(0x0102))
cli(main, DEV, 0x04, ev + u8(1) + u16(0x0100))
cli(main, DEV, 0x04, ev + u8(2) + u8(3))
cli(main, DEV, 0x04, ev + u8(3) + u8(0x01))
cli(main, DEV, 0x04, ev + u8(9))
cli(main, DEV, 0x05, u16(0x0101))
cli(main, DEV, 0x06, u32(1) + T(10) + u32(3) + S('CIN-123'))
read_attr_resp(main, DEV, [attr_rec(0xfffe, U8, u8(1)), attr_rec(0x0000, 0x42, S('abc'))], to_client=False)

# ----------------------------------------------------------------- Events
main.group('Events')
srv(main, EVT, 0x00, u8(1) + u16(0x1234) + T(0) + T(100) + u8(5) + u16(0))
srv(main, EVT, 0x01, u8(1))
cli(main, EVT, 0x00, u8(1) + u16(0x1234) + T(0) + u8(1) + S('event data'))
cli(main, EVT, 0x01, u16(3) + u8(1) + u8(1) + u8(0x01) + u8(1) + u16(0x1234) + T(0) + S('a')
    + u8(2) + u16(0x1235) + T(1) + S(''))
cli(main, EVT, 0x02, u8(0x03))

# ------------------------------------------------------------ MDU Pairing
main.group('MDU Pairing')
srv(main, MDU, 0x00, u32(1) + bytes(range(8)))
cli(main, MDU, 0x00, u32(1) + u8(2) + u8(1) + u8(1) + bytes(range(8)) + bytes(range(8, 16)))
cli(main, MDU, 0x00, u32(1) + u8(0) + u8(1) + u8(1))

# ----------------------------------------------------------------- Sub-GHz
main.group('Sub-GHz')
srv(main, SGHZ, 0x00)
srv(main, SGHZ, 0x00, b'\x01')
cli(main, SGHZ, 0x00)
cli(main, SGHZ, 0x00, u8(5))
read_attr_resp(main, SGHZ, [attr_rec(0xfffe, U8, u8(1)), attr_rec(0x0000, U8, u8(11)),
                            attr_rec(0x0001, BM32, u32(0x07ff8000)), attr_rec(0x0002, BM32, u32(1)),
                            attr_rec(0x0003, BM32, u32(1)), attr_rec(0x0004, BM32, u32(1))], to_client=False)

# ------------------------------------------------------ Key Establishment
main.group('Key Establishment')
cert1 = bytes(range(22)) + b'\x31' * 8 + b'\x32' * 8 + b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09'
assert len(cert1) == 48
def cert2x(valid_to, usage):
    return (u8(0) + bytes(range(1, 9)) + u8(0x0d) + u8(0x00) + b'\x11' * 8 + b'\x00\x00\x00\x00\x5a'
            + struct.pack('>I', valid_to) + b'\x22' * 8 + u8(usage) + b'\x33' * 37)
srv(main, KE, 0x00, u16(1) + u8(2) + u8(3) + cert1)
cli(main, KE, 0x00, u16(1) + u8(2) + u8(3) + cert1)
srv(main, KE, 0x00, u16(2) + u8(2) + u8(3) + cert2x(0x01e13380, 0x88))
cli(main, KE, 0x00, u16(2) + u8(2) + u8(3) + cert2x(0xffffffff, 0x08))        # reproducer: Valid To does not expire
cli(main, KE, 0x00, u16(2) + u8(2) + u8(3) + cert2x(0x01e13380, 0x80))
cli(main, KE, 0x00, u16(2) + u8(2) + u8(3) + cert2x(0, 0x00))
srv(main, KE, 0x00, u16(7) + u8(2) + u8(3) + b'\x01\x02\x03\x04')              # unknown suite
srv(main, KE, 0x01, bytes(range(22)))
cli(main, KE, 0x01, bytes(range(22, 44)))
srv(main, KE, 0x02, bytes(range(16)))
cli(main, KE, 0x02, bytes(range(16, 32)))
srv(main, KE, 0x03, u8(0x01) + u8(30) + u16(1))
cli(main, KE, 0x03, u8(0x02) + u8(0) + u16(2))
srv(main, KE, 0x04)
cli(main, KE, 0x04)
read_attr_resp(main, KE, [attr_rec(0x0000, U16, u16(1)), attr_rec(0x0001, U16, u16(2))], to_client=False)
read_attr_resp(main, KE, [attr_rec(0x0000, U16, u16(1)), attr_rec(0x0010, U8, u8(2))])

# ------------------------------------------- unknown commands, no handler
main.group('Unknown commands and commands without a payload decoder')
for c in ALLC:
    srv(main, c, 0x7f, b'\x01\x02')
    cli(main, c, 0x7f, b'\x01\x02')
srv(main, MSG, 0x00, b'\x01\x02\x03\x04')
for c in (0x00, 0x01, 0x03, 0x05):
    srv(main, DEV, c, u32(0x12345678))
cli(main, DRLC, 0x00, u32(0x1003) + u16(0x0101) + u8(1) + T(60) + u16(30) + u8(2) + u8(0xff) + u8(0xff)
    + u16(0x8000) + u16(0x8000) + u8(0x80) + u8(0xff) + u8(0x01))
read_attr_resp(main, TUN, [attr_rec(0x0001, U8, u8(3)), attr_rec(0x0002, U16, u16(4))])
read_attr_resp(main, TUN, [attr_rec(0x0001, U8, u8(3))], to_client=False)

main.group('Time fields with the value 0 (Now), byte order fixes')
cli(main, MET, 0x00, u32(0) + u8(0) + u8(4) + u8(1) + u24(7))
cli(main, MSG, 0x00, u32(0x7b) + u8(0x00) + u32(0) + u16(5) + S('Now'))
cli(main, DEV, 0x00, u32(1) + u32(2) + u8(1) + T(10) + u32(0x00000001))
cli(main, DEV, 0x02, u32(1) + T(10) + u16(0x0102) + u8(1) + S('pw'))

# ---------------------------------------------------- attribute commands
main.group('Report/Write attributes on SE clusters')
for c in ALLC:
    report_attr(main, c, [u16(0xfffe) + u8(U8) + u8(1)])
    write_attr(main, c, [attr_rec(0xfffe, U8, u8(1))])
report_attr(main, MET, [u16(0x0000) + u8(BM32) + u32(0xffffffff)], to_client=False)
write_attr(main, MET, [attr_rec(0x0001, BM32, u32(0x1))], to_client=False)
write_attr(main, TUN, [attr_rec(0x0000, U16, u16(300))])
write_attr(main, PP, [attr_rec(0x0000, BM16, u16(0x0011))])

# =================================================== malformed capture
mal.group('Reproducer, Change Debt label length 0xff')
srv(mal, PP, 0x02, u32(0x11223344) + b'\xff' + b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
srv(mal, PP, 0x02, u32(0x11223344) + b'\x04ABCDE')
mal.group('Truncated commands')
# every command of the main capture with its last octets cut off
def trunc_all():
    src = main.pk
    for idb, p in src:
        if idb != 0:
            continue
        # ZEP: 8+... rebuild from the 802.15.4 frame
        eth = p[:14]; ip = p[14:34]; udp = p[34:42]; z = p[42:]
        frame = z[32:]
        yield frame[:-2]       # strip FCS
trunc = []
for fr in trunc_all():
    # ZCL payload starts after mac(9) nwk(8) aps(8) = 25
    trunc.append(fr)
seen = set()
for fr in trunc:
    zhdr = fr[25:28]
    cl = struct.unpack('<H', fr[19:21])[0]
    key = (cl, zhdr[0], zhdr[2], len(fr))
    pay = fr[28:]
    if len(pay) < 2:
        continue
    for cut in (1, max(1, len(pay) // 2)):
        k = (key[:3], len(pay) - cut)
        if k in seen:
            continue
        seen.add(k)
        mal.frame(cl, fr[25:28] + pay[:len(pay) - cut])

main.write(os.path.join(OUT, 'zbee-zcl-se-coverage.pcapng'))
mal.write(os.path.join(OUT, 'zbee-zcl-se-coverage-malformed.pcapng'))
if VERBOSE:
    for cap, name in ((main, 'main'), (mal, 'malformed')):
        print(name, len(cap.pk), 'frames')
        g = cap.groups
        for i, (n, s) in enumerate(g):
            e = (g[i + 1][1] - 1) if i + 1 < len(g) else len(cap.pk)
            print('  %d-%d %s' % (s, e, n))
