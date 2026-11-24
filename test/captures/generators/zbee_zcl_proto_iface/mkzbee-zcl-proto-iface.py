#!/usr/bin/env python3
# Generates test/captures/zbee_zcl_proto_iface_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic coverage captures for packet-zbee-zcl-proto-iface.c (ZigBee
# Protocol Interface clusters: the Generic Tunnel cluster 0x0600).
# Usage: mkzbee-zcl-proto-iface.py <outdir> [-v]
# Writes zbee-zcl-proto-iface-coverage.pcapng (main) and
# zbee-zcl-proto-iface-coverage-malformed.pcapng.
# Frames go over ZEP v2 / UDP 17754 / Ethernet (IDB 0), HA profile; nothing
# is captured, all addresses are 192.0.2.0/24.  No security is used.
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

SE = 0x0104      # Home Automation profile
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


GT = 0x0600
EUI64 = bytes.fromhex('00124b0001020304')

# ---------------------------------------------------------- commands
main.group('Generic Tunnel commands')
srv(main, GT, 0x00, S(b'\x0a\x00\x00\x01'))                      # Match Protocol Address
srv(main, GT, 0x00, S(b''))                                       # empty address
srv(main, GT, 0x00)                                               # no payload
srv(main, GT, 0x01, b'\x01\x02\x03')                              # unknown command with payload
srv(main, GT, 0x01)
cli(main, GT, 0x00, EUI64 + S(b'\x0a\x00\x00\x01'))             # Match Protocol Address Response
cli(main, GT, 0x00, EUI64 + S(b''))                               # minimum length (9)
cli(main, GT, 0x00, EUI64)                                        # too short for the address: nothing decoded
cli(main, GT, 0x00)
cli(main, GT, 0x01, S(b'\x20\x01\x0d\xb8\x00\x00\x00\x01'))     # Advertise Protocol Address
cli(main, GT, 0x01, S(b''))
cli(main, GT, 0x01)
cli(main, GT, 0x02, b'\x01\x02\x03')                              # unknown command with payload
cli(main, GT, 0x02)

# --------------------------------------------------------- attributes
main.group('Generic Tunnel attributes')
read_attr_resp(main, GT, [attr_rec(0x0001, U16, u16(1500)), attr_rec(0x0002, U16, u16(1280)),
                          attr_rec(0x0003, OCT, S(b'\xc0\xa8\x00\x01'))])
read_attr_resp(main, GT, [attr_rec(0x0001, U16, u16(1500)), attr_rec(0x0002, U16, u16(1280)),
                          attr_rec(0x0003, OCT, S(b''))], to_client=False)
read_attr_resp(main, GT, [attr_rec(0x0003, OCT, S(b'\x00' * 20)), attr_rec(0x0004, U8, u8(1)),
                          attr_rec(0x0010, 0x42, S('text')), attr_rec(0x0005, 0, b'', status=0x86)])
report_attr(main, GT, [u16(0x0001) + u8(U16) + u16(576), u16(0x0003) + u8(OCT) + S(b'\x01\x02')])
report_attr(main, GT, [u16(0x0002) + u8(U16) + u16(576)], to_client=False)
write_attr(main, GT, [attr_rec(0x0001, U16, u16(900)), attr_rec(0x0003, OCT, S(b'\x09\x08\x07'))])
write_attr(main, GT, [attr_rec(0x0003, OCT, S(b'\x09'))], to_client=True)
# Read Attributes Request: the attribute ids are named by the cluster
main.frame(GT, zcl(False, 0x00, u16(0x0001) + u16(0x0002) + u16(0x0003), False))

# =================================================== malformed capture
mal.group('Truncated frames')
mal.frame(GT, zcl(False, 0x00, b'\x05\x0a'))                       # address length 5, one octet
mal.frame(GT, zcl(True, 0x00, EUI64[:5]))
mal.frame(GT, zcl(True, 0x00, EUI64 + b'\x08\x01'))                 # address length 8, one octet
mal.frame(GT, zcl(True, 0x01, b'\xff\x01'))
mal.frame(GT, zcl(True, 0x01, b'\x04\x01\x02'))
mal.frame(GT, zcl(False, 0x00, b'\xff'))
mal.frame(GT, zcl(True, 0x01, b'\x01'))
mal.frame(GT, zcl(True, 0x01, b'\x7f' + b'\x00' * 20))
for recs in ([u16(0x0001) + u8(0) + u8(U16) + u8(0)],               # 16 bit attribute cut short
             [u16(0x0002) + u8(0) + u8(U16)],
             [u16(0x0003) + u8(0) + u8(OCT) + u8(9) + b'\x01'],      # octet string longer than the frame
             [u16(0x0003) + u8(0) + u8(OCT)],
             [u16(0x0003) + u8(0)],
             [u16(0x0001)]):
    mal.frame(GT, zcl(True, 0x01, b''.join(recs), False))
    mal.frame(GT, zcl(False, 0x01, b''.join(recs), False))

main.write(os.path.join(OUT, 'zbee-zcl-proto-iface-coverage.pcapng'))
mal.write(os.path.join(OUT, 'zbee-zcl-proto-iface-coverage-malformed.pcapng'))
if VERBOSE:
    for cap, name in ((main, 'main'), (mal, 'malformed')):
        print(name, len(cap.pk), 'frames')
        g = cap.groups
        for i, (n, s_) in enumerate(g):
            e = (g[i + 1][1] - 1) if i + 1 < len(g) else len(cap.pk)
            print('  %d-%d %s' % (s_, e, n))
