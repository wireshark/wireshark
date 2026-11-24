#!/usr/bin/env python3
# Generates test/captures/zbee_zcl_general_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the ZigBee ZCL General coverage captures
# (epan/dissectors/packet-zbee-zcl-general.c).
#
#   mkzbee_zcl_general.py <outdir> [-v]
#
# writes zbee-zcl-general-coverage.pcap (valid frames only) and
# zbee-zcl-general-coverage-malformed.pcap.  Frames are reached the way a
# capture reaches them: ZEP v2 on UDP 17754 -> IEEE 802.15.4 (with FCS) ->
# ZigBee NWK (heuristic) -> APS (HA profile) -> ZCL cluster.
# Everything is synthetic: addresses are 10.0.0.x, the 802.15.4 and EUI-64
# addresses are made up, the GP and Touchlink keys are filler bytes.
# No key, encryption or decryption code is written here.
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv


def crc16_kermit(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc


def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Cap:
    def __init__(self):
        self.pkts = []
        self.seq = 0
        self.marks = []

    def mark(self, text):
        self.marks.append((len(self.pkts) + 1, text))

    def add(self, cluster, zcl, profile=0x0104):
        self.seq += 1
        n = self.seq & 0xff
        nwk = struct.pack('<HHHBB', 0x0008, 0x0000, 0x0001, 30, n)
        aps = struct.pack('<BBHHBB', 0x00, 1, cluster, profile, 1, n)
        hdr = struct.pack('<HBHHH', 0x8841, n, 0x1a62, 0x0000, 0x0001)
        f = hdr + nwk + aps + zcl
        f += struct.pack('<H', crc16_kermit(f))
        assert len(f) <= 127, (cluster, len(f))
        z = b'EX' + struct.pack('>BBBHBB', 2, 1, 11, 1, 1, 0xff)
        z += b'\0' * 8 + struct.pack('>I', self.seq) + b'\0' * 10 + bytes([len(f)])
        z += f
        udp = struct.pack('>HHHH', 17754, 17754, 8 + len(z), 0) + z
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                         bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
        ip = ip[:10] + struct.pack('>H', ip_csum(ip)) + ip[12:]
        self.pkts.append(b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + udp)

    def write(self, path):
        with open(path, 'wb') as fh:
            fh.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                fh.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                fh.write(p)


MAIN = Cap()
MAL = Cap()
tsn = 0


def u8(*v):
    return bytes(v)


def u16(v):
    return struct.pack('<H', v)


def u24(v):
    return struct.pack('<I', v)[:3]


def u32(v):
    return struct.pack('<I', v)


def eui(n):
    return bytes((0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, n))


def filler(n, start=1):
    return bytes((start + i) & 0xff for i in range(n))


def cmd(cap, cluster, command, payload=b'', to_client=False, mfr=None,
        profile=0x0104, ddr=False):
    """Cluster specific command."""
    global tsn
    tsn = (tsn + 1) & 0xff
    fc = 0x01 | (0x08 if to_client else 0) | (0x10 if ddr else 0)
    hdr = bytes([fc | (0x04 if mfr is not None else 0)])
    if mfr is not None:
        hdr += u16(mfr)
    cap.add(cluster, hdr + bytes([tsn, command]) + payload, profile)


def prof(cap, cluster, command, payload=b'', to_client=False):
    """Profile-wide (foundation) command."""
    global tsn
    tsn = (tsn + 1) & 0xff
    cap.add(cluster, bytes([0x00 | (0x08 if to_client else 0), tsn, command]) + payload)


def lstr(s):
    return bytes([len(s)]) + s


# Attribute ids and data types, found by trying each type on the cluster's attribute decoder
# (dev/discover.py): (attribute, type, alternate size type, string type)
ATTRS = {
    0x0000: [
        (0x0, 0x30, 0x21, 0x42),
        (0x1, 0x30, 0x21, 0x42),
        (0x2, 0x30, 0x21, 0x42),
        (0x3, 0x30, 0x21, 0x42),
        (0x4, 0x30, 0x21, 0x42),
        (0x5, 0x30, 0x21, 0x42),
        (0x6, 0x30, 0x21, 0x42),
        (0x7, 0x30, None, None),
        (0x10, 0x30, 0x21, 0x42),
        (0x11, 0x30, 0x21, 0x42),
        (0x12, 0x30, None, None),
        (0x13, 0x30, None, None),
        (0x14, 0x30, None, None),
        (0x4000, 0x30, 0x21, 0x42)],
    0x0001: [
        (0x0, 0x21, None, None),
        (0x1, 0x30, None, None),
        (0x10, 0x30, None, None),
        (0x11, 0x21, None, None),
        (0x12, 0x21, None, None),
        (0x13, 0x21, None, None),
        (0x20, 0x30, None, None),
        (0x21, 0x30, None, None),
        (0x30, 0x30, 0x21, 0x42),
        (0x31, 0x30, None, None),
        (0x32, 0x21, None, None),
        (0x33, 0x30, 0x21, 0x42),
        (0x34, 0x30, None, None),
        (0x35, 0x30, None, None),
        (0x36, 0x30, None, None)],
    0x0002: [
        (0x0, 0x30, 0x21, 0x42),
        (0x1, 0x30, 0x21, 0x42),
        (0x2, 0x30, 0x21, 0x42),
        (0x3, 0x30, 0x21, 0x42),
        (0x10, 0x30, None, None),
        (0x11, 0x30, 0x21, 0x42),
        (0x12, 0x30, 0x21, 0x42),
        (0x13, 0x30, 0x21, 0x42),
        (0x14, 0x30, 0x21, 0x42)],
    0x0003: [
        (0x0, 0x21, None, None)],
    0x0004: [
        (0x0, 0x30, None, None)],
    0x0005: [
        (0x0, 0x30, 0x21, 0x42),
        (0x1, 0x30, 0x21, 0x42),
        (0x2, 0x30, 0x21, 0x42),
        (0x3, 0x30, None, None),
        (0x4, 0x30, None, None),
        (0x5, 0x30, 0x21, 0x42)],
    0x0006: [
        (0x0, 0x30, None, None),
        (0x4000, 0x30, None, None),
        (0x4001, 0x21, None, None),
        (0x4002, 0x21, None, None),
        (0x4003, 0x30, None, None)],
    0x0007: [
        (0x0, 0x30, None, None),
        (0x10, 0x30, None, None)],
    0x0008: [
        (0x0, 0x30, None, None),
        (0x1, 0x21, None, None),
        (0x10, 0x21, None, None),
        (0x11, 0x30, None, None),
        (0x4000, 0x30, None, None)],
    0x0009: [
        (0x0, 0x30, 0x21, 0x42)],
    0x000a: [
        (0x0, 0x30, 0x21, 0x42),
        (0x1, 0x30, None, None),
        (0x2, 0x30, 0x21, 0x42),
        (0x3, 0x30, 0x21, 0x42),
        (0x4, 0x30, 0x21, 0x42),
        (0x5, 0x30, 0x21, 0x42),
        (0x6, 0x30, 0x21, 0x42),
        (0x7, 0x30, 0x21, 0x42),
        (0x8, 0x30, 0x21, 0x42),
        (0x9, 0x30, 0x21, 0x42)],
    0x000b: [
        (0x0, 0x30, None, None),
        (0x1, 0x30, None, None),
        (0x2, 0x30, 0x21, 0x42),
        (0x3, 0x30, 0x21, 0x42),
        (0x4, 0x30, 0x21, 0x42),
        (0x10, 0x30, 0x21, 0x42),
        (0x11, 0x30, 0x21, 0x42),
        (0x12, 0x30, 0x21, 0x42),
        (0x13, 0x30, 0x21, 0x42),
        (0x14, 0x30, 0x21, 0x42),
        (0x15, 0x30, 0x21, 0x42),
        (0x16, 0x30, 0x21, 0x42),
        (0x17, 0x30, 0x21, 0x42)],
    0x000c: [
        (0x1c, 0x30, 0x21, 0x42),
        (0x41, 0x30, 0x21, 0x42),
        (0x45, 0x30, 0x21, 0x42),
        (0x51, 0x30, 0x21, 0x42),
        (0x55, 0x30, 0x21, 0x42),
        (0x67, 0x30, None, None),
        (0x6a, 0x30, 0x21, 0x42),
        (0x6f, 0x30, None, None),
        (0x75, 0x30, 0x21, 0x42),
        (0x100, 0x30, 0x21, 0x42)],
    0x000d: [
        (0x1c, 0x30, 0x21, 0x42),
        (0x41, 0x30, 0x21, 0x42),
        (0x45, 0x30, 0x21, 0x42),
        (0x51, 0x30, 0x21, 0x42),
        (0x55, 0x30, 0x21, 0x42),
        (0x67, 0x30, None, None),
        (0x68, 0x30, 0x21, 0x42),
        (0x6a, 0x30, 0x21, 0x42),
        (0x6f, 0x30, None, None),
        (0x75, 0x30, 0x21, 0x42),
        (0x100, 0x30, 0x21, 0x42)],
    0x000e: [
        (0x1c, 0x30, 0x21, 0x42),
        (0x51, 0x30, 0x21, 0x42),
        (0x55, 0x30, 0x21, 0x42),
        (0x67, 0x30, None, None),
        (0x68, 0x30, 0x21, 0x42),
        (0x6f, 0x30, None, None),
        (0x75, 0x30, 0x21, 0x42),
        (0x100, 0x30, 0x21, 0x42)],
    0x000f: [
        (0x4, 0x30, 0x21, 0x42),
        (0x1c, 0x30, 0x21, 0x42),
        (0x2e, 0x30, 0x21, 0x42),
        (0x51, 0x30, 0x21, 0x42),
        (0x54, 0x30, None, None),
        (0x55, 0x30, 0x21, 0x42),
        (0x67, 0x30, None, None),
        (0x6f, 0x30, None, None),
        (0x100, 0x30, 0x21, 0x42)],
    0x0010: [
        (0x4, 0x30, 0x21, 0x42),
        (0x1c, 0x30, 0x21, 0x42),
        (0x2e, 0x30, 0x21, 0x42),
        (0x42, 0x30, 0x21, 0x42),
        (0x43, 0x30, 0x21, 0x42),
        (0x51, 0x30, 0x21, 0x42),
        (0x54, 0x30, None, None),
        (0x55, 0x30, 0x21, 0x42),
        (0x67, 0x30, None, None),
        (0x68, 0x30, 0x21, 0x42),
        (0x6f, 0x30, None, None),
        (0x100, 0x30, 0x21, 0x42)],
    0x0011: [
        (0x4, 0x30, 0x21, 0x42),
        (0x1c, 0x30, 0x21, 0x42),
        (0x2e, 0x30, 0x21, 0x42),
        (0x42, 0x30, 0x21, 0x42),
        (0x43, 0x30, 0x21, 0x42),
        (0x51, 0x30, 0x21, 0x42),
        (0x55, 0x30, 0x21, 0x42),
        (0x67, 0x30, None, None),
        (0x68, 0x30, 0x21, 0x42),
        (0x6f, 0x30, None, None),
        (0x100, 0x30, 0x21, 0x42)],
    0x0012: [
        (0xe, 0x30, 0x21, 0x42),
        (0x1c, 0x30, 0x21, 0x42),
        (0x4a, 0x30, 0x21, 0x42),
        (0x51, 0x30, 0x21, 0x42),
        (0x55, 0x30, 0x21, 0x42),
        (0x67, 0x30, None, None),
        (0x6f, 0x30, None, None),
        (0x100, 0x30, 0x21, 0x42)],
    0x0013: [
        (0xe, 0x30, 0x21, 0x42),
        (0x1c, 0x30, 0x21, 0x42),
        (0x4a, 0x30, 0x21, 0x42),
        (0x51, 0x30, 0x21, 0x42),
        (0x55, 0x30, 0x21, 0x42),
        (0x67, 0x30, None, None),
        (0x68, 0x30, 0x21, 0x42),
        (0x6f, 0x30, None, None),
        (0x100, 0x30, 0x21, 0x42)],
    0x0014: [
        (0xe, 0x30, 0x21, 0x42),
        (0x1c, 0x30, 0x21, 0x42),
        (0x4a, 0x30, 0x21, 0x42),
        (0x51, 0x30, 0x21, 0x42),
        (0x55, 0x30, 0x21, 0x42),
        (0x67, 0x30, None, None),
        (0x68, 0x30, 0x21, 0x42),
        (0x6f, 0x30, None, None),
        (0x100, 0x30, 0x21, 0x42)],
    0x0015: [
        (0x0, 0x30, 0x21, 0x42),
        (0x1, 0x30, 0x21, 0x42),
        (0x2, 0x30, 0x21, 0x42),
        (0x3, 0x30, 0x21, 0x42),
        (0x4, 0x30, 0x21, 0x42),
        (0x5, 0x30, None, None),
        (0x6, 0x30, None, None),
        (0x10, 0x30, 0x21, 0x42),
        (0x11, 0x30, 0x21, 0x42),
        (0x12, 0x30, 0x21, 0x42),
        (0x13, 0x30, 0x21, 0x42),
        (0x14, 0x30, 0x21, 0x42),
        (0x15, 0x30, 0x21, 0x42),
        (0x16, 0x30, 0x21, 0x42),
        (0x17, 0x30, 0x21, 0x42),
        (0x20, 0x30, 0x21, 0x42),
        (0x21, 0x30, 0x21, 0x42),
        (0x22, 0x30, 0x21, 0x42),
        (0x23, 0x30, 0x21, 0x42),
        (0x30, 0x30, 0x21, 0x42),
        (0x31, 0x30, 0x21, 0x42),
        (0x40, 0x30, 0x21, 0x42),
        (0x41, 0x30, 0x21, 0x42),
        (0x42, 0x30, 0x21, 0x42)],
    0x0016: [
        (0x0, 0x30, 0x21, 0x42),
        (0x1, 0x30, 0x21, 0x42),
        (0x2, 0x30, 0x21, 0x42),
        (0x3, 0x30, 0x21, 0x42),
        (0x4, 0x30, 0x21, 0x42),
        (0x5, 0x30, 0x21, 0x42),
        (0x6, 0x30, 0x21, 0x42),
        (0x7, 0x30, 0x21, 0x42),
        (0x8, 0x30, 0x21, 0x42),
        (0x9, 0x30, 0x21, 0x42)],
    0x0019: [
        (0x0, 0x30, 0x21, 0x42),
        (0x1, 0x30, 0x21, 0x42),
        (0x2, 0x23, None, None),
        (0x3, 0x21, None, None),
        (0x4, 0x23, None, None),
        (0x5, 0x21, None, None),
        (0x6, 0x30, None, None),
        (0x7, 0x21, None, None),
        (0x8, 0x21, None, None),
        (0x9, 0x30, 0x21, 0x42)],
    0x001a: [
        (0x0, 0x30, None, None),
        (0x1, 0x30, None, None),
        (0x2, 0x30, None, None),
        (0x3, 0x30, None, None),
        (0x4, 0x30, None, None)],
    0x001b: [
        (0x0, 0x21, None, None),
        (0x1, 0x21, None, None),
        (0x2, 0x21, None, None)],
    0x0020: [
        (0x0, 0x30, 0x21, 0x42),
        (0x1, 0x30, 0x21, 0x42),
        (0x2, 0x30, 0x21, 0x42),
        (0x3, 0x30, 0x21, 0x42),
        (0x4, 0x30, 0x21, 0x42),
        (0x5, 0x30, 0x21, 0x42),
        (0x6, 0x30, 0x21, 0x42)],
    0x0021: [
        (0x0, 0x30, 0x21, 0x42),
        (0x2, 0x30, None, None),
        (0x3, 0x30, None, None),
        (0x4, 0x30, 0x21, 0x42),
        (0x5, 0x30, None, None),
        (0x6, 0x22, None, None),
        (0x7, 0x22, None, None),
        (0x10, 0x30, 0x21, 0x42),
        (0x12, 0x30, 0x21, 0x42),
        (0x13, 0x30, 0x21, 0x42),
        (0x14, 0x30, 0x21, 0x42),
        (0x15, 0x30, 0x21, 0x42),
        (0x16, 0x22, None, None),
        (0x17, 0x22, None, None),
        (0x20, 0x30, 0x21, 0x42),
        (0x21, 0x30, 0x21, 0x42),
        (0x22, 0x30, 0x21, 0x42)],
}


# ---------------------------------------------------------------------------
# Cluster ids
BASIC, POWER, DEVTEMP, IDENT, GROUPS, SCENES, ONOFF, ONOFFSW, LEVEL, ALARMS, \
    TIME, RSSI = 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, \
    0x0007, 0x0008, 0x0009, 0x000a, 0x000b
COMMISSION, PART, OTA, PWRPROF, APPLCTRL, POLL, GP, TOUCHLINK = \
    0x0015, 0x0016, 0x0019, 0x001a, 0x001b, 0x0020, 0x0021, 0x1000

# ---------------------------------------------------------------------------
# 1. Attributes of every cluster in the file: Read Attributes Response (server
# and client direction), Report Attributes, with numeric values 0, 0xfe and
# 0xff (special labels: frequency, power profile id, delay) and a string
# value where the attribute decodes by data type.
MAIN.mark('attributes')
for cl in sorted(ATTRS):
    for (attr, t1, t2, ts) in ATTRS[cl]:
        sz = {0x10: 1, 0x18: 1, 0x19: 2, 0x1b: 4, 0x20: 1, 0x21: 2, 0x22: 3,
              0x23: 4, 0x28: 1, 0x29: 2, 0x2b: 4, 0x30: 1, 0x31: 2, 0x38: 2,
              0x39: 4, 0x41: 5, 0x42: 6, 0xe0: 4, 0xe1: 4, 0xe2: 4, 0xe8: 2, 0xe9: 2,
              0xea: 4, 0xf0: 8, 0xf1: 16, 0x08: 1, 0x09: 2}

        def val(t, fill):
            if t in (0x41, 0x42):
                return lstr(b'abcde'[:sz[t] - 1])
            return bytes([fill]) * sz[t]
        prof(MAIN, cl, 0x01, u16(attr) + u8(0, t1) + val(t1, 0x00), True)
        prof(MAIN, cl, 0x0a, u16(attr) + u8(t1) + val(t1, 0xfe), True)
        if t2:
            prof(MAIN, cl, 0x01, u16(attr) + u8(0, t2) + val(t2, 0xff), False)
        else:
            prof(MAIN, cl, 0x01, u16(attr) + u8(0, t1) + val(t1, 0xff), False)
        if ts:
            prof(MAIN, cl, 0x01, u16(attr) + u8(0, ts) + val(ts, 0), True)

# ---------------------------------------------------------------------------
# 2. Basic, Identify, Groups
MAIN.mark('basic, identify, groups')
cmd(MAIN, BASIC, 0x00)
cmd(MAIN, BASIC, 0x00, mfr=0x1234, ddr=True)
cmd(MAIN, IDENT, 0x00, u16(10))
cmd(MAIN, IDENT, 0x01, b'\x00')
cmd(MAIN, IDENT, 0x40, u8(0x01, 0x00))
cmd(MAIN, IDENT, 0x00, u16(5), to_client=True)          # query response
cmd(MAIN, GROUPS, 0x00, u16(0x0001) + lstr(b'living'))
cmd(MAIN, GROUPS, 0x00, u16(0x0002) + u8(0xff))          # name length 0xff
cmd(MAIN, GROUPS, 0x00, u16(0x0003) + lstr(b''))
cmd(MAIN, GROUPS, 0x01, u16(0x0001))
cmd(MAIN, GROUPS, 0x02, u8(2) + u16(1) + u16(2))
cmd(MAIN, GROUPS, 0x02, u8(0))
cmd(MAIN, GROUPS, 0x03, u16(0x0001))
cmd(MAIN, GROUPS, 0x04, b'\x00')
cmd(MAIN, GROUPS, 0x05, u16(0x0004) + lstr(b'kitchen'))
cmd(MAIN, GROUPS, 0x00, u8(0) + u16(1), True)            # add response
cmd(MAIN, GROUPS, 0x01, u8(0) + u16(1) + lstr(b'living'), True)
cmd(MAIN, GROUPS, 0x01, u8(0) + u16(2) + u8(0xff), True)
cmd(MAIN, GROUPS, 0x01, u8(0x8b) + u16(9) + lstr(b''), True)
cmd(MAIN, GROUPS, 0x02, u8(10, 3) + u16(1) + u16(2) + u16(3), True)
cmd(MAIN, GROUPS, 0x02, u8(10, 0), True)
cmd(MAIN, GROUPS, 0x03, u8(0) + u16(1), True)

# ---------------------------------------------------------------------------
# 3. Scenes with extension field sets
MAIN.mark('scenes')


def ext(cluster, data):
    return u16(cluster) + bytes([len(data)]) + data


ext_all = (ext(0x0006, u8(1)) + ext(0x0008, u8(0x80)) +
           ext(0x0300, u16(0x4000) + u16(0x8000) + u16(0x1234) + u8(0xfe, 1, 1) + u16(30)) +
           ext(0x0101, u8(1)) + ext(0x0102, u8(50, 25)) +
           ext(0x0201, u16(2600) + u16(2000) + u8(4)) + ext(0x0abc, u8(1, 2, 3)))
cmd(MAIN, SCENES, 0x00, u16(1) + u8(1) + u16(5) + lstr(b'warm'))
cmd(MAIN, SCENES, 0x00, u16(1) + u8(2) + u16(0) + u8(0xff) + ext(0x0006, u8(0)) + ext(0x0008, u8(0x10)))
cmd(MAIN, SCENES, 0x00, u16(1) + u8(3) + u16(5) + lstr(b'all') + ext_all[:60])
cmd(MAIN, SCENES, 0x40, u16(1) + u8(4) + u16(50) + lstr(b'enh') + ext(0x0006, u8(1)))
cmd(MAIN, SCENES, 0x40, u16(1) + u8(5) + u16(50) + lstr(b'') +
    ext(0x0300, u16(0x4000) + u16(0x8000) + u16(0x1234) + u8(0xfe, 1, 1) + u16(30)))
cmd(MAIN, SCENES, 0x00, u16(1) + u8(6) + u16(5) + lstr(b'cl') + ext(0x0101, u8(1)) + ext(0x0102, u8(50, 25)))
cmd(MAIN, SCENES, 0x00, u16(1) + u8(7) + u16(5) + lstr(b'th') + ext(0x0201, u16(2600) + u16(2000) + u8(4)))
cmd(MAIN, SCENES, 0x00, u16(1) + u8(8) + u16(5) + lstr(b'sh') + ext(0x0006, b'') + ext(0x0abc, u8(1, 2, 3)))
for c in (0x01, 0x02, 0x04, 0x05, 0x41):
    cmd(MAIN, SCENES, c, u16(1) + u8(2))
cmd(MAIN, SCENES, 0x03, u16(1))
cmd(MAIN, SCENES, 0x06, u16(1))
cmd(MAIN, SCENES, 0x42, u8(0) + u16(1) + u8(2) + u16(3) + u8(4))
for c in (0x00, 0x02, 0x04, 0x40):
    cmd(MAIN, SCENES, c, u8(0) + u16(1) + u8(2), True)
cmd(MAIN, SCENES, 0x01, u8(0) + u16(1) + u8(1) + u16(5) + lstr(b'warm') + ext(0x0006, u8(1)) +
    ext(0x0008, u8(0x80)), True)
cmd(MAIN, SCENES, 0x01, u8(0) + u16(1) + u8(2) + u16(5) + u8(0xff), True)
cmd(MAIN, SCENES, 0x01, u8(0x8b) + u16(1) + u8(3), True)
cmd(MAIN, SCENES, 0x41, u8(0) + u16(1) + u8(1) + u16(50) + lstr(b'enh') + ext(0x0006, u8(1)), True)
cmd(MAIN, SCENES, 0x03, u8(0) + u16(1), True)
cmd(MAIN, SCENES, 0x06, u8(0, 5) + u16(1) + u8(3, 1, 2, 3), True)
cmd(MAIN, SCENES, 0x06, u8(0x8b, 5) + u16(1), True)
cmd(MAIN, SCENES, 0x42, u8(0) + u16(1) + u8(2), True)

# ---------------------------------------------------------------------------
# 4. On/Off, On/Off switch configuration, Level control, Alarms, Time
MAIN.mark('on/off, level, alarms')
cmd(MAIN, ONOFF, 0x00, b'\x00')
cmd(MAIN, ONOFF, 0x01, b'\x00')
cmd(MAIN, ONOFF, 0x02, b'\x00')
cmd(MAIN, ONOFF, 0x40, u8(0x00, 0x00))     # delayed all off
cmd(MAIN, ONOFF, 0x40, u8(0x00, 0x01))
cmd(MAIN, ONOFF, 0x40, u8(0x01, 0x00))     # dying light
cmd(MAIN, ONOFF, 0x40, u8(0x02, 0x00))     # reserved effect
cmd(MAIN, ONOFF, 0x41, b'\x00')
cmd(MAIN, ONOFF, 0x42, u8(0x01) + u16(100) + u16(50))
cmd(MAIN, ONOFF, 0x42, u8(0x00) + u16(0) + u16(0))
cmd(MAIN, LEVEL, 0x00, u8(128) + u16(10) + u8(0, 0))
cmd(MAIN, LEVEL, 0x04, u8(255) + u16(0) + u8(1, 1))
cmd(MAIN, LEVEL, 0x01, u8(0, 20))
cmd(MAIN, LEVEL, 0x05, u8(1, 20))
cmd(MAIN, LEVEL, 0x02, u8(0, 10) + u16(5))
cmd(MAIN, LEVEL, 0x06, u8(1, 10) + u16(5))
cmd(MAIN, LEVEL, 0x03, b'\x00')
cmd(MAIN, LEVEL, 0x07, b'\x00')
cmd(MAIN, ALARMS, 0x00, u8(3) + u16(0x0001))
cmd(MAIN, ALARMS, 0x01, b'\x00')
cmd(MAIN, ALARMS, 0x02, b'\x00')
cmd(MAIN, ALARMS, 0x03, b'\x00')
cmd(MAIN, ALARMS, 0x00, u8(3) + u16(0x0001), True)
cmd(MAIN, ALARMS, 0x01, u8(0, 3) + u16(1) + u32(0x12345678), True)
cmd(MAIN, ALARMS, 0x01, u8(0x86), True)

# ---------------------------------------------------------------------------
# 5. RSSI location
MAIN.mark('rssi location')
cmd(MAIN, RSSI, 0x00, u16(10) + u16(20) + u16(30) + u16(40) + u16(50))
cmd(MAIN, RSSI, 0x01, u16(40) + u16(50) + u16(60) + u8(5) + u16(70))
cmd(MAIN, RSSI, 0x02, eui(1))
cmd(MAIN, RSSI, 0x03, u8(0x00, 3))
cmd(MAIN, RSSI, 0x03, u8(0x04, 3) + eui(2))
cmd(MAIN, RSSI, 0x04, eui(3) + u16(1) + u16(2) + u16(3) + u8(0xd0, 4))
cmd(MAIN, RSSI, 0x05, eui(4) + u8(5) + u16(60))
cmd(MAIN, RSSI, 0x06, eui(5) + u16(1) + u16(2) + u16(3))
cmd(MAIN, RSSI, 0x00, u8(0) + u16(40) + u16(50) + u16(60) + u8(5) + u16(70), True)
cmd(MAIN, RSSI, 0x00, u8(0x81), True)
cmd(MAIN, RSSI, 0x01, u8(0, 0x01) + u16(1) + u16(2) + u16(3) + u16(4) + u16(5) + u8(2, 3) + u16(7), True)
cmd(MAIN, RSSI, 0x01, u8(0x81), True)
cmd(MAIN, RSSI, 0x02, u8(0x00) + u16(1) + u16(2) + u16(3) + u16(4) + u16(5) + u8(2, 3) + u16(7), True)   # 3D
cmd(MAIN, RSSI, 0x02, u8(0x02) + u16(1) + u16(2) + u16(4) + u16(5) + u8(2, 3) + u16(7), True)           # 2D
cmd(MAIN, RSSI, 0x02, u8(0x0c) + u16(1) + u16(2) + u16(3) + u16(4) + u16(5) + u8(3) + u16(7), True)     # 0x0c: no method
cmd(MAIN, RSSI, 0x03, u8(0x00) + u16(1) + u16(2) + u16(3) + u8(3) + u16(7), True)
cmd(MAIN, RSSI, 0x03, u8(0x02) + u16(1) + u16(2) + u8(3) + u16(7), True)
cmd(MAIN, RSSI, 0x03, u8(0x0c) + u16(1) + u16(2) + u16(3) + u16(7), True)
cmd(MAIN, RSSI, 0x04, u8(0x01), True)
cmd(MAIN, RSSI, 0x05, b'', True)
cmd(MAIN, RSSI, 0x06, eui(1) + u8(2) + eui(2) + u16(1) + u16(2) + u16(3) + u8(0xd0, 4) +
    eui(3) + u16(4) + u16(5) + u16(6) + u8(0xd1, 5), True)
cmd(MAIN, RSSI, 0x06, eui(1) + u8(0), True)
cmd(MAIN, RSSI, 0x07, eui(7), True)

# ---------------------------------------------------------------------------
# 6. Commissioning, Partition
MAIN.mark('commissioning, partition')
cmd(MAIN, COMMISSION, 0x00, u8(0x01, 5, 3))
cmd(MAIN, COMMISSION, 0x01, u8(0x01, 2))
cmd(MAIN, COMMISSION, 0x02, u8(0x01, 2))
cmd(MAIN, COMMISSION, 0x03, u8(0x03, 2))
for c in range(4):
    cmd(MAIN, COMMISSION, c, u8(0), True)
cmd(MAIN, PART, 0x00, u8(0x01, 1) + lstr(b'frame-data'))
cmd(MAIN, PART, 0x00, u8(0x02) + u16(0x0102) + lstr(b'frame-data'))
cmd(MAIN, PART, 0x01, u16(0x0006) + u16(0) + u16(1))
cmd(MAIN, PART, 0x02, u16(0x0006) + u16(0) + u8(0x21) + u16(200))
cmd(MAIN, PART, 0x00, u8(0x00, 1, 2, 3, 4), True)         # multiple ack, 1 octet ids
cmd(MAIN, PART, 0x00, u8(0x01) + u16(0x0100) + u16(0x0101) + u16(0x0102), True)
cmd(MAIN, PART, 0x01, u16(0x0006) + u16(0) + u8(0, 0x21) + u16(200) + u16(1) + u8(0x86), True)

# ---------------------------------------------------------------------------
# 7. OTA upgrade
MAIN.mark('ota')
fv = u32(0x01020304)
cmd(MAIN, OTA, 0x00, u8(0, 10), True)
cmd(MAIN, OTA, 0x00, u8(1, 10) + u16(0x1234), True)
cmd(MAIN, OTA, 0x00, u8(2, 10) + u16(0x1234) + u16(7), True)
cmd(MAIN, OTA, 0x00, u8(3, 10) + u16(0x1234) + u16(7) + fv, True)
cmd(MAIN, OTA, 0x01, u8(0) + u16(0x1234) + u16(7) + fv)
cmd(MAIN, OTA, 0x01, u8(1) + u16(0x1234) + u16(7) + fv + u16(3))
cmd(MAIN, OTA, 0x02, u8(0) + u16(0x1234) + u16(7) + fv + u32(4096), True)
cmd(MAIN, OTA, 0x02, u8(0x98), True)
cmd(MAIN, OTA, 0x03, u8(0) + u16(0x1234) + u16(7) + fv + u32(0) + u8(48))
cmd(MAIN, OTA, 0x03, u8(1) + u16(0x1234) + u16(7) + fv + u32(48) + u8(48) + eui(9))
cmd(MAIN, OTA, 0x03, u8(2) + u16(0x1234) + u16(7) + fv + u32(96) + u8(48) + u16(100))
cmd(MAIN, OTA, 0x03, u8(3) + u16(0x1234) + u16(7) + fv + u32(96) + u8(48) + eui(9) + u16(100))
cmd(MAIN, OTA, 0x04, u8(0) + u16(0x1234) + u16(7) + fv + u32(0) + u8(48) + u16(256) + u16(20))
cmd(MAIN, OTA, 0x04, u8(1) + u16(0x1234) + u16(7) + fv + u32(0) + u8(48) + u16(256) + u16(20) + eui(9))
cmd(MAIN, OTA, 0x05, u8(0) + u16(0x1234) + u16(7) + fv + u32(0) + lstr(filler(32)), True)
cmd(MAIN, OTA, 0x05, u8(0x97) + u32(0) + u32(60) + u16(10), True)         # wait, current time 0: offset
cmd(MAIN, OTA, 0x05, u8(0x97) + u32(1000) + u32(2000) + u16(10), True)    # wait, UTC
cmd(MAIN, OTA, 0x05, u8(0x95), True)                                      # abort
cmd(MAIN, OTA, 0x06, u8(0) + u16(0x1234) + u16(7) + fv)
cmd(MAIN, OTA, 0x06, u8(0x95) + u16(0x1234) + u16(7) + fv)
cmd(MAIN, OTA, 0x07, u16(0x1234) + u16(7) + fv + u32(0) + u32(60), True)
cmd(MAIN, OTA, 0x07, u16(0x1234) + u16(7) + fv + u32(1000) + u32(2000), True)
cmd(MAIN, OTA, 0x07, u16(0x1234) + u16(7) + fv + u32(0) + u32(0xffffffff), True)
cmd(MAIN, OTA, 0x07, u16(0x1234) + u16(7) + fv + u32(1000) + u32(0xffffffff), True)
cmd(MAIN, OTA, 0x08, eui(9) + u16(0x1234) + u16(7) + fv + u16(2))
cmd(MAIN, OTA, 0x09, u8(0) + u16(0x1234) + u16(7) + fv + u32(4096), True)
cmd(MAIN, OTA, 0x09, u8(0x98), True)

# ---------------------------------------------------------------------------
# 8. Power profile, Appliance control, Poll control
MAIN.mark('power profile, appliance control, poll control')
cmd(MAIN, PWRPROF, 0x00, u8(1))
cmd(MAIN, PWRPROF, 0x01, u8(1) + u16(840) + u32(1250) + u8(2))        # state request (price rsp layout)
cmd(MAIN, PWRPROF, 0x02, u8(0) + u16(840) + u32(1250) + u8(2))
cmd(MAIN, PWRPROF, 0x03, u16(840) + u32(1250) + u8(2))
cmd(MAIN, PWRPROF, 0x04, u8(1, 2, 1) + u16(30) + u8(2) + u16(60))
cmd(MAIN, PWRPROF, 0x05, u8(1, 0))
cmd(MAIN, PWRPROF, 0x06, u8(1))
cmd(MAIN, PWRPROF, 0x07, u8(1))
cmd(MAIN, PWRPROF, 0x08, u8(1) + u16(840) + u32(1250) + u8(2))
cmd(MAIN, PWRPROF, 0x00, u8(2, 1, 2) + u8(1, 1) + u16(10) + u16(20) + u16(30) + u16(40) +
    u8(2, 1) + u16(11) + u16(21) + u16(31) + u16(41), True)
cmd(MAIN, PWRPROF, 0x00, u8(0), True)
cmd(MAIN, PWRPROF, 0x01, u8(1, 1, 1) + u8(1, 1) + u16(10) + u16(20) + u16(30) + u16(40), True)
cmd(MAIN, PWRPROF, 0x02, u8(2, 1, 1, 0, 2, 2, 2, 1, 3), True)
cmd(MAIN, PWRPROF, 0x03, u8(1), True)
cmd(MAIN, PWRPROF, 0x04, u8(1, 1, 2, 1, 3), True)
cmd(MAIN, PWRPROF, 0x05, u8(1, 2, 1) + u16(30) + u8(2) + u16(60), True)
cmd(MAIN, PWRPROF, 0x06, u8(0), True)                                 # all profiles
cmd(MAIN, PWRPROF, 0x07, u8(1, 2, 1) + u16(30) + u8(2) + u16(60), True)
cmd(MAIN, PWRPROF, 0x08, u8(1, 2, 1) + u16(30) + u8(2) + u16(60), True)
cmd(MAIN, PWRPROF, 0x09, u8(1) + u16(0) + u16(60), True)
cmd(MAIN, PWRPROF, 0x0a, u8(1) + u16(120) + u16(0), True)
cmd(MAIN, PWRPROF, 0x0b, u8(1, 1) + u16(15), True)
cmd(MAIN, APPLCTRL, 0x00, u8(1))
cmd(MAIN, APPLCTRL, 0x01, b'\x00')
cmd(MAIN, APPLCTRL, 0x02, u16(0) + u8(0x21) + u16(60) + u16(1) + u8(0x21) + u16(120) + u16(2) + u8(0x21) + u16(30))
cmd(MAIN, APPLCTRL, 0x03, b'\x00')
cmd(MAIN, APPLCTRL, 0x04, b'\x00')
cmd(MAIN, APPLCTRL, 0x05, u8(1))
cmd(MAIN, APPLCTRL, 0x00, u8(0x03, 0x42, 0x01) + u8(0xaa, 0xbb, 0xcc), True)
cmd(MAIN, APPLCTRL, 0x01, u8(0x03, 0x42, 0x01) + u8(0xaa, 0xbb, 0xcc), True)
cmd(MAIN, POLL, 0x00, b'', True)
cmd(MAIN, POLL, 0x00, u8(1) + u16(20))
cmd(MAIN, POLL, 0x01, b'\x00')
cmd(MAIN, POLL, 0x02, u32(8))
cmd(MAIN, POLL, 0x03, u16(4))

# ---------------------------------------------------------------------------
# 9. Green Power cluster: commands, sink and proxy tables
MAIN.mark('green power')
SRC = u32(0x12345678)
ZGP = eui(0x21) + u8(3)
gpd = u8(0x10, 1, 7)             # GPD command 0x10 (Recall scene), payload size 1: scene 7
gpd0 = u8(0x22, 0)               # toggle, no payload
link = u8(0xa5)
cmd(MAIN, GP, 0x00, u16(0x4000) + SRC + u32(100) + gpd + u16(0x1234) + link)
cmd(MAIN, GP, 0x00, u16(0x4002 | 0x0008) + ZGP[:8] + u8(3) + u32(101) + gpd0 + u16(0x1234) + link)
cmd(MAIN, GP, 0x00, u16(0x0000) + SRC + u32(102) + u8(0x22, 0xff))
cmd(MAIN, GP, 0x01, u16(0x0000) + SRC)
cmd(MAIN, GP, 0x03, b'\x00')
cmd(MAIN, GP, 0x04, u16(0x0000) + SRC + u32(0) + u8(0xe0, 2, 2, 0))
cmd(MAIN, GP, 0x04, u16(0x0800 | 0x0002) + ZGP[:8] + u8(3) + u32(1) + gpd0 + u16(0x1234) + link)
cmd(MAIN, GP, 0x04, u16(0x0200) + SRC + u32(1) + gpd0 + u32(0xdeadbeef))
cmd(MAIN, GP, 0x05, u8(0x0f) + u16(0x1111) + u16(0x2222) + u8(5))
cmd(MAIN, GP, 0x07, u8(0, 0))
cmd(MAIN, GP, 0x08, u8(0))
# Pairing configuration: short form, then every optional part
cmd(MAIN, GP, 0x09, u8(0x01) + u16(0x0000) + SRC + u8(0x02) + u8(5) + u8(0))
pc_opts = 0x0002 | (2 << 3) | 0x0020 | 0x0040 | 0x0080 | 0x0100 | 0x0200 | 0x0400
cmd(MAIN, GP, 0x09, u8(0x0a) + u16(pc_opts) + ZGP + u8(0x02) +
    u8(2) + u16(0x1001) + u16(0x2001) + u16(0x1002) + u16(0x2002) +   # group list
    u16(0xabcd) + u8(7) +                                              # alias, radius
    u8(0x05) + u32(1000) + filler(16) +                                # security, key
    u8(2, 1, 2) +                                                       # paired endpoints
    u8(0x0f) + u16(0x1037) + u16(0x0102) + u8(2, 0x20, 0x22) +          # app info
    u8(0x21) + u16(0x0006) + u16(0x0008) + u16(0x0300))
cmd(MAIN, GP, 0x09, u8(0x02) + u16(0x0000) + SRC + u8(0x02) + u8(5) + u8(0xfe))
cmd(MAIN, GP, 0x0a, u8(0x00) + SRC)
cmd(MAIN, GP, 0x0a, u8(0x02) + ZGP)
cmd(MAIN, GP, 0x0a, u8(0x08) + u8(3))
cmd(MAIN, GP, 0x0b, u8(0, 3, 0, 1) + u16(0x0000 | 0x0008 | 0x0010) + SRC + u8(0x7f))
# GP -> client
cmd(MAIN, GP, 0x00, u8(0x00, 0x00) + SRC + u32(100), True)
cmd(MAIN, GP, 0x01, u24(0x000008) + SRC + u8(2), True)
cmd(MAIN, GP, 0x01, u24(0x000008 | 0x0060 | 0x4000 | 0x8000 | 0x10000 | 0x20000) + SRC + eui(1) + u16(0x1234) +
    u8(2) + u32(500) + filler(16) + u16(0xabcd) + u8(5), True)
cmd(MAIN, GP, 0x01, u24(0x000008 | 0x0020 | 0x4000) + SRC + u16(0x2001) + u8(2) + u32(500), True)
cmd(MAIN, GP, 0x01, u24(0x000002 | 0x0010) + ZGP, True)
cmd(MAIN, GP, 0x02, u8(0x00), True)
cmd(MAIN, GP, 0x02, u8(0x01 | 0x02 | 0x10) + u16(180) + u8(15), True)
cmd(MAIN, GP, 0x06, u8(0x00) + u16(0xfff0) + u8(0x05) + SRC + u8(0x00, 0), True)
cmd(MAIN, GP, 0x06, u8(0x0a) + u16(0xfff0) + u8(0x0d) + ZGP + gpd, True)
cmd(MAIN, GP, 0x08, u8(0), True)
SINK_E1 = u16(0x0000 | (1 << 5)) + SRC + u8(2) + u8(5) + u32(9)
SINK_E2 = (u16(0x0002 | (2 << 3) | (1 << 6) | (1 << 7) | 0x100 | 0x200) + ZGP + u8(0x02) +
           u8(1) + u16(0x1001) + u16(0x2001) + u16(0xabcd) + u8(4) + u8(0x05) + u32(77) + filler(16))
cmd(MAIN, GP, 0x0a, u8(0, 2, 0, 2) + SINK_E1 + SINK_E2, True)
cmd(MAIN, GP, 0x0a, u8(0, 0, 0, 0), True)
cmd(MAIN, GP, 0x0b, u8(0x08, 1), True)
cmd(MAIN, GP, 0x0b, u8(0x00) + SRC, True)
cmd(MAIN, GP, 0x0b, u8(0x02) + ZGP, True)
# GP attributes: sink table, proxy table, bitmask attributes
PX_E1 = u16(0x0000 | 0x08 | 0x10 | 0x20) + SRC + u32(55) + u8(3)
PX_E2 = (u16(0x0002 | 0x40 | 0x100 | 0x2000 | 0x4000 | 0x8000) + ZGP +
         u16(0xabcd) + u8(0x05) + u32(66) + filler(16) +
         u8(1) + eui(2) + u16(0x1234) +                  # lightweight unicast list
         u8(1) + u16(0x1001) + u16(0x2001) +             # commissioned group list
         u8(6) + u8(9) + u8(0x01) + u8(1) + eui(3) + u16(0x4321))   # radius, search counter, ext options, full unicast
PX_E3 = u16(0x0000 | 0x08) + SRC + u8(2) + u8(9)         # active but not valid: search counter
sinktbl = SINK_E1 + SINK_E2
prof(MAIN, GP, 0x01, u16(0x0001) + u8(0, 0x41) + u16(len(sinktbl)) + sinktbl, True)
prof(MAIN, GP, 0x01, u16(0x0001) + u8(0, 0x41) + u16(0), True)
proxytbl = PX_E1 + PX_E2 + PX_E3
prof(MAIN, GP, 0x01, u16(0x0011) + u8(0, 0x41) + u16(len(proxytbl)) + proxytbl, True)
prof(MAIN, GP, 0x0a, u16(0x0011) + u8(0x41) + u16(len(PX_E1)) + PX_E1, True)
prof(MAIN, GP, 0x01, u16(0x0011) + u8(0, 0x41) + u16(0), True)

# ---------------------------------------------------------------------------
# 10. Touchlink commissioning
MAIN.mark('touchlink')
TID = 0x11223344
ZLL = 0xc05e
cmd(MAIN, TOUCHLINK, 0x00, u32(TID) + u8(0x04, 0x13), profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x06, u32(TID) + u16(5), profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x07, u32(TID), profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x10, u32(TID) + eui(1) + u8(0) + filler(16) + u8(15) + u16(0x1a62) + u16(0x0001) +
    u16(0x0010) + u16(0x0020) + u16(0x0100) + u16(0x0200) + u16(0x0030) + u16(0x0040) + eui(2) + u16(0x0003),
    profile=ZLL)


def scan_rsp(resp, sub=0, tid=TID):
    r = (u32(tid) + u8(0xf0, 0x04, 0x13) + u16(0x8001) + u32(resp) + eui(1) +
         u8(0, 11) + u16(0x1a62) + u16(0x0002) + u8(sub, 3))
    if sub == 1:
        r += u8(1) + u16(0xc05e) + u16(0x0100) + u8(2, 1)
    return r


def join_req(command, key_index, tid=TID):
    return (u32(tid) + eui(1) + u8(key_index) + filler(16) + u8(0, 11) + u16(0x1a62) +
            u16(0x0010) + u16(0x0020) + u16(0x0100) + u16(0x0200) + u16(0x0030) + u16(0x0040) +
            u16(0x0050))


# Scan Response, then the Join Request of the same transaction with the
# development key (no key to configure), the certification key, the master key
# (not in the keyring: expert warning) and an unused key index.  Every
# transaction has its own id: a second Scan Response of the same transaction
# after the Join Request changes the key derived on the second pass (see the
# malformed capture and the README).
cmd(MAIN, TOUCHLINK, 0x01, scan_rsp(0xaaaaaaaa), True, profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x12, join_req(0x12, 0), profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x01, scan_rsp(0x01020304, 1, TID + 1), True, profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x14, join_req(0x14, 15, TID + 1), profile=ZLL)  # certification key
cmd(MAIN, TOUCHLINK, 0x01, scan_rsp(0x0a0b0c0d, 0, TID + 2), True, profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x14, join_req(0x14, 4, TID + 2), profile=ZLL)   # master key: not in the keyring
cmd(MAIN, TOUCHLINK, 0x14, join_req(0x14, 7, TID + 3), profile=ZLL)   # unused key index
cmd(MAIN, TOUCHLINK, 0x16, u32(TID) + eui(1) + u8(1, 11) + u16(0x1a62) + u16(0x0002), profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x02, u32(TID) + u8(0), profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x41, u8(0), profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x42, u8(0), profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x11, u32(TID) + u8(0) + eui(1) + u8(1, 11) + u16(0x1a62), True, profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x13, u32(TID) + u8(0), True, profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x15, u32(TID) + u8(1), True, profile=ZLL)
rec = lambda n: eui(n) + u8(1) + u16(0x0104) + u16(0x0100) + u8(2, 1, 0)
cmd(MAIN, TOUCHLINK, 0x03, u32(TID) + u8(3, 0, 2) + rec(1) + rec(2), True, profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x40, eui(1) + u16(0x0002) + u8(1) + u16(0x0104) + u16(0x0100) + u8(2), True, profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x41, u8(2, 0, 2) + u16(0x1001) + u8(0) + u16(0x1002) + u8(1), True, profile=ZLL)
cmd(MAIN, TOUCHLINK, 0x42, u8(2, 0, 2) + u16(0x0002) + u8(1) + u16(0x0104) + u16(0x0100) + u8(2) +
    u16(0x0003) + u8(2) + u16(0x0104) + u16(0x0101) + u8(2), True, profile=ZLL)

# ---------------------------------------------------------------------------
# 11. Foundation commands carrying cluster attributes (Write, Write structured,
# a nested array) and manufacturer specific frames
MAIN.mark('foundation commands with cluster attributes')
prof(MAIN, BASIC, 0x02, u16(0x0010) + u8(0x42) + lstr(b'office'))
prof(MAIN, ONOFF, 0x02, u16(0x4001) + u8(0x21) + u16(10) + u16(0x4002) + u8(0x21) + u16(20))
prof(MAIN, GROUPS, 0x0f, u16(0x0000) + u8(0) + u8(0x20, 1))                # Write Attributes Structured
prof(MAIN, BASIC, 0x01, u16(0x4000) + u8(0, 0x48, 0x48) + u16(2) +
     u8(0x20) + u16(2) + u8(1, 2) + u8(0x20) + u16(1) + u8(3), True)       # array of arrays
prof(MAIN, ONOFF, 0x01, u16(0x0000) + u8(0, 0x10, 1), True)


# ---------------------------------------------------------------------------
# 12. Unknown commands and attributes, attributes of fixed size, clusters
# without cluster specific commands
MAIN.mark('unknown commands and attributes, priority arrays, clusters without commands')
for cl in (BASIC, IDENT, GROUPS, SCENES, ONOFF, LEVEL, ALARMS, RSSI, COMMISSION, PART,
           OTA, PWRPROF, APPLCTRL, POLL, GP, TOUCHLINK):
    cmd(MAIN, cl, 0x7e, filler(2), profile=0x0c05e if cl == TOUCHLINK else 0x0104)
    cmd(MAIN, cl, 0x7e, filler(2), True, profile=0x0c05e if cl == TOUCHLINK else 0x0104)
for cl in (POWER, DEVTEMP, ONOFFSW, TIME, 0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011,
           0x0012, 0x0013, 0x0014):
    cmd(MAIN, cl, 0x00, filler(2))
    cmd(MAIN, cl, 0x00, filler(2), True)
for cl in sorted(ATTRS):
    prof(MAIN, cl, 0x01, u16(0x7ffe) + u8(0, 0x20, 5), True)
for cl in (0x000d, 0x000e, 0x0010, 0x0011, 0x0013, 0x0014):
    pa = b''.join(u8(i & 1) + struct.pack('<f', i * 1.5) for i in range(16))
    prof(MAIN, cl, 0x01, u16(0x0057) + u8(0, 0x41) + pa, True)
prof(MAIN, POWER, 0x01, u16(0x0001) + u8(0, 0x20, 50), True)
prof(MAIN, POWER, 0x01, u16(0x0001) + u8(0, 0x20, 0xfe), True)
cmd(MAIN, RSSI, 0x05, u8(1), True)
cmd(MAIN, OTA, 0x05, u8(0x97) + u32(0) + u32(0xffffffff) + u16(10), True)
cmd(MAIN, PWRPROF, 0x00, u8(1, 1, 1) + u8(1, 1) + u16(10) + u16(20) + u16(30) + u16(0), True)
cmd(MAIN, TOUCHLINK, 0x11, u32(TID) + u8(0) + eui(1) + u8(1, 11) + u16(0x1a62) + u8(0xee, 0xff), True, profile=ZLL)
cmd(MAIN, GP, 0x01, u24(0x000008) + SRC + u8(2) + u8(0xaa, 0xbb), True)
# reproducer of the GP proxy table fix: the extension options are the last octet of the frame
pxe = u16(0x8000 | 0x08 | 0x10) + SRC + u8(3) + u8(0x00)
prof(MAIN, GP, 0x01, u16(0x0011) + u8(0, 0x41) + u16(len(pxe)) + pxe, True)
# a table entry with an unsupported application id stops the table dissection
prof(MAIN, GP, 0x01, u16(0x0001) + u8(0, 0x41) + u16(2) + u16(0x0007), True)
prof(MAIN, GP, 0x01, u16(0x0011) + u8(0, 0x41) + u16(2) + u16(0x0007), True)
cmd(MAIN, GP, 0x0a, u8(0, 1, 0, 1) + u16(0x0007), True)
cmd(MAIN, GP, 0x0b, u8(0, 1, 0, 1) + u16(0x0007))

# ---------------------------------------------------------------------------
# Malformed capture: truncated and over-long fields, reserved values
MAL.mark('truncated commands')
for cl, cmds in ((GROUPS, (0, 1, 2, 3, 5)), (SCENES, (0, 1, 3, 6, 0x40, 0x41, 0x42)),
                 (IDENT, (0, 0x40)), (ONOFF, (0x40, 0x42)), (LEVEL, (0, 1, 2)),
                 (ALARMS, (0,)), (RSSI, (0, 1, 2, 3, 4, 5, 6)),
                 (COMMISSION, (0, 1, 3)), (PART, (0, 1, 2)),
                 (OTA, (1, 3, 4, 6, 8)), (PWRPROF, (0, 1, 3, 4, 7, 8)),
                 (APPLCTRL, (0, 2, 5)), (POLL, (0, 2, 3))):
    for c in cmds:
        for n in (1, 2, 3):
            cmd(MAL, cl, c, filler(n))
for cl, cmds in ((GROUPS, (0, 1, 2, 3)), (SCENES, (0, 1, 2, 3, 4, 6, 0x40, 0x41, 0x42)),
                 (IDENT, (0,)), (ALARMS, (1,)), (RSSI, (0, 1, 2, 3, 4, 6, 7)),
                 (COMMISSION, (0,)), (PART, (0, 1)),
                 (OTA, (0, 2, 5, 7, 9)), (PWRPROF, (0, 1, 2, 4, 5, 6, 7, 8, 9, 0x0b)),
                 (APPLCTRL, (1,))):
    for c in cmds:
        for n in (1, 2, 3):
            cmd(MAL, cl, c, filler(n), True)
MAL.mark('Touchlink two-pass reproducer')
# Scan Response R1, Join Request with the development key, Scan Response R2 of the
# same transaction: tshark -2 derives the key of the Join Request from R2
cmd(MAL, TOUCHLINK, 0x01, scan_rsp(0xaaaaaaaa, 0, TID + 9), True, profile=ZLL)
cmd(MAL, TOUCHLINK, 0x12, join_req(0x12, 0, TID + 9), profile=ZLL)
cmd(MAL, TOUCHLINK, 0x01, scan_rsp(0x55555555, 0, TID + 9), True, profile=ZLL)
MAL.mark('GP and Touchlink truncated')
cmd(MAL, GP, 0x00, u16(0x0002) + filler(3))
cmd(MAL, GP, 0x04, u16(0x0802) + filler(5))
cmd(MAL, GP, 0x09, u8(0x01) + u16(0x0002 | 0x0200 | 0x0400 | 0x0008) + filler(4))
cmd(MAL, GP, 0x0a, u8(0x08))
cmd(MAL, GP, 0x0b, u8(0, 3, 0, 5) + u16(0x0002) + filler(4))
cmd(MAL, GP, 0x01, u24(0x020002) + filler(4), True)
cmd(MAL, GP, 0x02, u8(0x13), True)
cmd(MAL, GP, 0x06, u8(0x0a) + filler(6), True)
cmd(MAL, GP, 0x0a, u8(0, 2, 0, 3) + SINK_E1, True)
prof(MAL, GP, 0x01, u16(0x0001) + u8(0, 0x41) + u16(100) + SINK_E1, True)
prof(MAL, GP, 0x01, u16(0x0001) + u8(0, 0x41) + u16(4) + u16(0x0007) + filler(4), True)   # app id 7: stops
prof(MAL, GP, 0x01, u16(0x0011) + u8(0, 0x41) + u16(100) + PX_E1, True)
prof(MAL, GP, 0x01, u16(0x0011) + u8(0, 0x41) + u16(4) + u16(0x0007) + filler(4), True)
prof(MAL, GP, 0x01, u16(0x0011) + u8(0, 0x41) + u16(3) + u16(0x8000) + u8(1), True)       # extension options at the end
for c in (0x00, 0x03, 0x06, 0x10, 0x12, 0x14, 0x16, 0x02, 0x41, 0x42):
    for n in (4, 6, 12):
        cmd(MAL, TOUCHLINK, c, filler(n), profile=ZLL)
for c in (0x01, 0x03, 0x11, 0x13, 0x40, 0x41, 0x42):
    for n in (4, 6, 12):
        cmd(MAL, TOUCHLINK, c, filler(n), True, profile=ZLL)
cmd(MAL, TOUCHLINK, 0x03, u32(TID) + u8(3, 0, 3) + rec(1), True, profile=ZLL)
cmd(MAL, TOUCHLINK, 0x42, u8(2, 0, 3) + u16(0x0002) + u8(1) + u16(0x0104), True, profile=ZLL)
MAL.mark('attribute data cut short')
for cl in sorted(ATTRS):
    for (attr, t1, t2, ts) in ATTRS[cl][:6]:
        prof(MAL, cl, 0x01, u16(attr) + u8(0, 0x23) + u8(1), True)

MAIN.write(os.path.join(OUT, 'zbee-zcl-general-coverage.pcap'))
MAL.write(os.path.join(OUT, 'zbee-zcl-general-coverage-malformed.pcap'))
print('main', len(MAIN.pkts), 'malformed', len(MAL.pkts))
if VERBOSE:
    for (n, t) in MAIN.marks:
        print('main from frame', n, t)
    for (n, t) in MAL.marks:
        print('malformed from frame', n, t)
