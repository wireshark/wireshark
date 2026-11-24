#!/usr/bin/env python3
# Generates the bthci_cmd captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures for the Bluetooth HCI Command dissector
# (epan/dissectors/packet-bthci_cmd.c: protocols "bthci_cmd" and
# "btcommon" with the EIR/AD decoder). Every packet is built with struct;
# nothing comes from a real device.
#
# Usage: mkbthci_cmd.py <outdir>
# Writes bthci_cmd-coverage.pcap (main, DLT 201 HCI H4 with phdr),
# bthci_cmd-coverage-exppdu.pcap (Exported PDU, DLT 252) and
# bthci_cmd-coverage-malformed.pcap (DLT 201).
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def write_pcap(path, linktype, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            # 10 ms apart so the response time deltas are round numbers
            f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000, len(p), len(p)))
            f.write(p)


def h4(sent, h4type, payload):
    # LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR: 4 octet direction, 0 sent, 1 received
    return struct.pack('>I', 0 if sent else 1) + bytes([h4type]) + payload


def cmd(opcode, params, plen=None):
    if plen is None:
        plen = len(params)
    return h4(True, 0x01, struct.pack('<HB', opcode, plen & 0xff) + params)


def evt(code, params):
    return h4(False, 0x04, struct.pack('<BB', code, len(params)) + params)


def cmd_complete(opcode, ret):
    return evt(0x0e, struct.pack('<BH', 1, opcode) + ret)


def cmd_status(opcode, status=0):
    return evt(0x0f, struct.pack('<BBH', status, 1, opcode))


def exppdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


def op(ogf, ocf):
    return (ogf << 10) | ocf


def le16(v):
    return struct.pack('<H', v)


def le24(v):
    return struct.pack('<I', v)[:3]


def le32(v):
    return struct.pack('<I', v)


BD1 = bytes([0x66, 0x55, 0x44, 0x33, 0x22, 0x11])   # 11:22:33:44:55:66 (little endian on the wire)
BD2 = bytes([0x06, 0x05, 0x04, 0x03, 0x02, 0x00])   # 00:02:03:04:05:06
KEY = bytes(range(0x10, 0x20))


def ad(t, data):
    return bytes([len(data) + 1, t]) + data


def uuid128_sig(u16):
    # 0000xxxx-0000-1000-8000-00805F9B34FB, little endian on the wire
    return bytes.fromhex('FB349B5F8000008000100000') + le16(u16) + b'\0\0'


CUSTOM128 = bytes(range(0xa0, 0xb0))
NAME = b'WS-HCI'

# Parameter lengths of the fixed size commands, every octet 0x01.
# Commands with length 0 take no parameters.
LENS = {
    0x0401: 5, 0x0402: 0, 0x0403: 9, 0x0404: 0, 0x0405: 13, 0x0406: 3,
    0x0407: 4, 0x0408: 6, 0x0409: 7, 0x040a: 7, 0x040b: 22, 0x040c: 6,
    0x040d: 23, 0x040e: 6, 0x040f: 4, 0x0411: 2, 0x0413: 3, 0x0415: 2,
    0x0417: 1, 0x0419: 10, 0x041a: 6, 0x041b: 2, 0x041c: 3, 0x041d: 2,
    0x041f: 2, 0x0420: 2, 0x0428: 17, 0x0429: 21, 0x042a: 7, 0x042b: 9,
    0x042c: 6, 0x042d: 6, 0x042e: 10, 0x042f: 6, 0x0430: 38, 0x0433: 6,
    0x0434: 7, 0x0435: 4, 0x0436: 4, 0x0437: 2, 0x0438: 33, 0x0439: 33,
    0x043a: 2, 0x043b: 2, 0x043c: 33, 0x043d: 59, 0x043e: 63, 0x043f: 9,
    0x0440: 6, 0x0441: 11, 0x0442: 34, 0x0443: 0, 0x0444: 12, 0x0445: 70,
    0x0801: 6, 0x0803: 10, 0x0804: 2, 0x0805: 6, 0x0806: 2, 0x0807: 20,
    0x0809: 2, 0x080b: 7, 0x080c: 2, 0x080d: 4, 0x080e: 0, 0x080f: 2,
    0x0810: 21, 0x0811: 8,
    0x0c01: 8, 0x0c03: 0, 0x0c05: 8, 0x0c08: 2, 0x0c09: 0, 0x0c0a: 1,
    0x0c0b: 0, 0x0c0d: 7, 0x0c11: 23, 0x0c12: 7, 0x0c13: 248, 0x0c14: 0,
    0x0c15: 0, 0x0c16: 2, 0x0c17: 0, 0x0c18: 2, 0x0c19: 0, 0x0c1a: 1,
    0x0c1b: 0, 0x0c1c: 4, 0x0c1d: 0, 0x0c1e: 4, 0x0c1f: 0, 0x0c20: 1,
    0x0c21: 0, 0x0c22: 1, 0x0c23: 0, 0x0c24: 3, 0x0c25: 0, 0x0c26: 2,
    0x0c27: 2, 0x0c28: 4, 0x0c29: 0, 0x0c2a: 1, 0x0c2b: 0, 0x0c2c: 1,
    0x0c2d: 3, 0x0c2e: 0, 0x0c2f: 1, 0x0c31: 1, 0x0c33: 7, 0x0c35: 5,
    0x0c36: 2, 0x0c37: 4, 0x0c38: 0, 0x0c39: 0, 0x0c3a: 4, 0x0c3b: 0,
    0x0c3c: 1, 0x0c3d: 0, 0x0c3e: 1, 0x0c3f: 10, 0x0c42: 0, 0x0c43: 1,
    0x0c44: 0, 0x0c45: 1, 0x0c46: 0, 0x0c47: 1, 0x0c48: 0, 0x0c49: 1,
    0x0c51: 0, 0x0c52: 241, 0x0c53: 2, 0x0c55: 0, 0x0c56: 1, 0x0c57: 0,
    0x0c58: 0, 0x0c59: 1, 0x0c5a: 0, 0x0c5b: 1, 0x0c5f: 3, 0x0c60: 7,
    0x0c61: 0, 0x0c62: 2, 0x0c63: 8, 0x0c64: 0, 0x0c65: 5, 0x0c66: 0,
    0x0c67: 1, 0x0c68: 3, 0x0c69: 2, 0x0c6a: 6, 0x0c6b: 2, 0x0c6c: 0,
    0x0c6d: 2, 0x0c6e: 10, 0x0c6f: 10, 0x0c70: 30, 0x0c71: 9, 0x0c72: 5,
    0x0c73: 5, 0x0c74: 1, 0x0c75: 1, 0x0c76: 4, 0x0c77: 0, 0x0c78: 9,
    0x0c79: 0, 0x0c7a: 1, 0x0c7b: 2, 0x0c7c: 4, 0x0c7d: 0, 0x0c7e: 0,
    0x0c7f: 2, 0x0c80: 0, 0x0c81: 2, 0x0c82: 2, 0x0c83: 4, 0x0c84: 1,
    0x1001: 0, 0x1002: 0, 0x1003: 0, 0x1004: 1, 0x1005: 0, 0x1007: 0,
    0x1009: 0, 0x100a: 0, 0x100b: 0, 0x100c: 0, 0x1010: 0,
    0x1401: 2, 0x1402: 2, 0x1403: 2, 0x1405: 2, 0x1406: 2, 0x1407: 3,
    0x1408: 2, 0x1409: 0, 0x140a: 5, 0x140b: 6, 0x140c: 0, 0x140d: 6,
    0x1801: 0, 0x1802: 1, 0x1803: 0, 0x1804: 1, 0x1807: 2, 0x1808: 0,
    0x1809: 1, 0x180a: 4,
    0x2001: 8, 0x2002: 0, 0x2003: 0, 0x2005: 6, 0x2006: 15, 0x2007: 0,
    0x2008: 32, 0x2009: 32, 0x200a: 1, 0x200b: 7, 0x200c: 2, 0x200d: 25,
    0x200e: 0, 0x200f: 0, 0x2010: 0, 0x2011: 7, 0x2012: 7, 0x2013: 14,
    0x2014: 5, 0x2015: 2, 0x2016: 2, 0x2017: 32, 0x2018: 0, 0x2019: 28,
    0x201a: 18, 0x201b: 2, 0x201c: 0, 0x201d: 1, 0x201e: 3, 0x201f: 0,
    0x2020: 14, 0x2021: 3, 0x2022: 6, 0x2023: 0, 0x2024: 4, 0x2025: 0,
    0x2026: 64, 0x2027: 39, 0x2028: 7, 0x2029: 0, 0x202a: 0, 0x202b: 7,
    0x202c: 7, 0x202d: 1, 0x202e: 2, 0x202f: 0, 0x2030: 2, 0x2031: 3,
    0x2032: 7, 0x2033: 3, 0x2034: 4, 0x2035: 7, 0x2036: 25, 0x2039: 6,
    0x203a: 0, 0x203b: 0, 0x203c: 1, 0x203d: 0, 0x203e: 7, 0x2040: 2,
    0x2041: 8, 0x2042: 6, 0x2043: 26, 0x2044: 14, 0x2045: 0, 0x2046: 2,
    0x2047: 8, 0x2048: 8, 0x2049: 0, 0x204a: 0, 0x204b: 0, 0x204c: 0,
    0x204d: 4, 0x204e: 8, 0x204f: 8, 0x2050: 8, 0x2051: 6, 0x2052: 2,
    0x2053: 7, 0x2054: 6, 0x2055: 5, 0x2056: 7, 0x2057: 3, 0x2058: 0,
    0x2059: 3, 0x205a: 6, 0x205b: 5, 0x205c: 8, 0x205d: 6, 0x205e: 65,
    0x205f: 1, 0x2060: 0, 0x2061: 2, 0x2062: 24, 0x2063: 29, 0x2064: 5,
    0x2065: 1, 0x2066: 2, 0x2067: 3, 0x2068: 16, 0x2069: 21, 0x206a: 2,
    0x206b: 25, 0x206c: 1, 0x206d: 2, 0x206e: 14, 0x206f: 3, 0x2070: 3,
    0x2071: 3, 0x2072: 2, 0x2073: 2, 0x2074: 2, 0x2075: 2, 0x2076: 3,
    0x2077: 3, 0x2078: 8, 0x2079: 3, 0x207a: 4, 0x207b: 9, 0x207c: 2,
    0x207d: 10, 0x207e: 12, 0x207f: 27, 0x2080: 4, 0x2081: 19, 0x2084: 6,
    0x2085: 28, 0x2086: 12, 0x2087: 0, 0x2088: 3, 0x2089: 0, 0x208a: 2,
    0x208b: 29, 0x208c: 2, 0x208d: 5, 0x208e: 2, 0x208f: 74, 0x2090: 28,
    0x2091: 3, 0x2092: 10, 0x2093: 23, 0x2094: 4, 0x2095: 49, 0x2096: 0,
    0x2097: 3, 0x2098: 10, 0x2099: 7, 0x209a: 0, 0x209b: 0, 0x209c: 1,
    0x209d: 9, 0x209e: 4, 0x209f: 1, 0x20a0: 2, 0x20a1: 20, 0x20a2: 18,
    0x20a3: 0, 0x20a4: 9, 0x20a5: 0, 0x20a6: 35, 0x20a7: 10, 0x20a8: 8,
}

# ---------------------------------------------------------------- AD/EIR
# Entries grouped so that each group fits a 31 octet legacy AD field or a
# 240 octet EIR. Every type the decoder knows, with SIG and custom UUIDs.
AD_FLAGS = ad(0x01, b'\x06')
AD_UUID16 = ad(0x02, le16(0x180d) + le16(0x180f)) + ad(0x03, le16(0x110b)) + ad(0x14, le16(0x1812))
AD_UUID32 = ad(0x04, le32(0x0000180a)) + ad(0x05, le32(0x12345678)) + ad(0x1f, le32(0x0000110a))
AD_UUID128 = (ad(0x06, uuid128_sig(0x180d)) + ad(0x07, CUSTOM128) + ad(0x15, uuid128_sig(0x1101)))
AD_NAMES = ad(0x08, b'WS') + ad(0x09, NAME)
AD_DID_SIG = ad(0x10, le16(1) + le16(0x000f) + le16(0x1234) + le16(0x0100))
AD_DID_USB = ad(0x10, le16(2) + le16(0x046d) + le16(0xc077) + le16(0x0200))
AD_DID_OTHER = ad(0x10, le16(3) + le16(0x0042) + le16(0x0001) + le16(0x0001))
AD_TK = ad(0x10, bytes(range(0x40, 0x50)))
AD_MISC = (ad(0x0a, b'\xf6') + ad(0x0b, le16(0x0042)) + ad(0x0d, bytes([0x0c, 0x02, 0x5a]))
           + ad(0x11, b'\x0b') + ad(0x12, le16(6) + le16(3200)))
AD_HASHES = ad(0x0e, KEY) + ad(0x0f, KEY[::-1]) + ad(0x1d, KEY) + ad(0x1e, KEY[::-1])
AD_BDADDR = ad(0x0c, BD2) + ad(0x09, b'EIR-Name')
AD_SVC16 = (ad(0x16, le16(0x180f)) + ad(0x16, le16(0x180f) + b'\x64')
            + ad(0x16, le16(0xfff7) + bytes([0x91, 0x34, 0x12, 0x00, 0x00])))
AD_SVC16_REG = (ad(0x16, le16(0xfd6f) + bytes(range(16)) + b'\xaa\xbb\xcc\xdd')
                + ad(0x16, le16(0xfff6) + bytes([0x00, 0x34, 0x12, 0xf1, 0xff, 0x01, 0x80, 0x01])))
AD_SVC32 = ad(0x20, le32(0x0000180f)) + ad(0x20, le32(0x89abcdef) + b'\x01\x02')
AD_SVC128 = ad(0x21, uuid128_sig(0x180f)) + ad(0x21, CUSTOM128 + b'\x01\x02')
AD_TARGETS = ad(0x17, BD1 + BD2) + ad(0x18, BD2)
AD_APPEAR = (ad(0x19, le16(0x00c1)) + ad(0x1a, le16(0x0800)) + ad(0x1b, b'\x01' + BD1)
             + ad(0x1c, b'\x02'))
AD_LESC = ad(0x22, KEY) + ad(0x23, KEY[::-1])
AD_URI = ad(0x24, b'\x16//example.com/')
AD_IPS = (ad(0x25, b'') + ad(0x25, bytes([0x3d]) + le32(0x12345678) + le32(0x87654321) + le16(10) + le16(20)
          + b'\x05' + le16(300) + b'\x03' + b'\x42') + ad(0x25, bytes([0x00])))
AD_TDS = ad(0x26, bytes([0x01, 0x05, 0x02, 0xaa, 0xbb, 0x02, 0x08, 0x00]))
AD_LEFEAT = ad(0x27, bytes([0xff, 0x01])) + ad(0x27, bytes([0x01, 0, 0, 0, 0, 0, 0, 0x80]))
AD_CHMAP = ad(0x28, bytes([0xff, 0xff, 0xff, 0xff, 0x1f]) + le16(0x0102))
AD_3D = ad(0x3d, bytes([0x07, 0x40]))
AD_BIGINFO_BODY = (le32((2 << 27) | (24 << 15) | 0x0010) + le32(0x12345678) + le24(0x123456) + b'\x40'
                   + b'\x00' + le32(0x8e89bed6) + le32(0x00271010) + le16(0x5555)
                   + bytes([0xff, 0xff, 0xff, 0xff, 0x3f]) + bytes([0x01, 0, 0, 0, 0x40]))
AD_BIGINFO = ad(0x2c, AD_BIGINFO_BODY)
AD_BIGINFO_ENC = ad(0x2c, AD_BIGINFO_BODY + bytes(range(8)) + KEY)
AD_BCAST = ad(0x2d, b'secret') + ad(0x2e, bytes([1, 2, 3, 4, 5, 6])) + ad(0x30, b'Bcast')
AD_PAWR = ad(0x32, le32(0x11223344) + bytes([4, 0x20, 2, 4]))
AD_MANUF = (ad(0xff, le16(0x000f) + bytes([0x00, 0x01, 0x20])) + ad(0xff, le16(0x0059) + b'\x01\x02\x03'))
AD_IBEACON = ad(0xff, le16(0x004c) + bytes([0x02, 0x15]) + CUSTOM128 + bytes([0, 1, 0, 2, 0xc5]))
# Unknown type, and a Flags entry longer than its octet (trailing data)
AD_UNKNOWN = ad(0x99, b'\x01\x02') + ad(0x01, b'\x06\x00')
# Mesh: unprovisioned device beacon, PB-ADV Link Open
AD_MESH = (ad(0x2a, bytes([0x68]) + bytes(range(1, 20))) + ad(0x2b, bytes([0x00]) + CUSTOM128 + le16(0x0000))
           + ad(0x29, le32(0x01020304) + bytes([0x00, 0x03]) + CUSTOM128))

EIR_GROUPS = [
    AD_FLAGS + AD_UUID16 + AD_UUID32 + AD_UUID128 + AD_NAMES + AD_DID_SIG + AD_MISC + AD_HASHES,
    AD_BDADDR + AD_DID_USB + AD_DID_OTHER + AD_TK + AD_SVC16 + AD_SVC16_REG + AD_SVC32 + AD_SVC128 + AD_TARGETS,
    AD_APPEAR + AD_LESC + AD_URI + AD_IPS + AD_TDS + AD_LEFEAT + AD_CHMAP + AD_3D + AD_BCAST + AD_PAWR + AD_MANUF,
    AD_BIGINFO + AD_BIGINFO_ENC + AD_UNKNOWN + AD_MESH,
]
for g in EIR_GROUPS:
    assert len(g) <= 240, len(g)


def eir(data, fec=1):
    return cmd(0x0c52, bytes([fec]) + data.ljust(240, b'\0'))


def adv(data, ocf=0x0008, dlen=None):
    if dlen is None:
        dlen = len(data)
    return cmd(op(8, ocf), bytes([dlen]) + data.ljust(31, b'\0'))


def ext_adv(data, ocf=0x0037, handle=1, operation=3):
    return cmd(op(8, ocf), bytes([handle, operation, 1, len(data)]) + data)


# ---------------------------------------------------------------- commands
def default_params(opcode):
    return b'\x01' * LENS[opcode]


def special_commands():
    """Commands whose parameters select branches, or that need real values."""
    f = []
    LC, LP, HC, INF, ST, TE, LE = 1, 2, 3, 4, 5, 6, 8
    # Link control
    f.append(cmd(op(LC, 0x05), BD1 + le16(0xcc18) + b'\x01\x00' + le16(0x8010) + b'\x01'))   # Create Connection
    f.append(cmd(op(LC, 0x09), BD1 + b'\x00'))                                              # Accept, become central
    f.append(cmd(op(LC, 0x0d), BD1 + b'\x04' + b'1234'.ljust(16, b'\0')))                   # PIN Code Reply
    f.append(cmd(op(LC, 0x19), BD1 + b'\x01\x00' + le16(0x0000)))                           # Remote Name Request, clock offset invalid
    f.append(cmd(op(LC, 0x29), BD2 + le32(8000) * 2 + le16(10) + le16(0x0060) + b'\x01' + le16(0x003f)))
    f.append(cmd(op(LC, 0x3d), le16(0x0001) + b'\x00' * 57))                                # Enhanced Setup Sync, all zero
    f.append(cmd(op(LC, 0x3e), BD2 + b'\x00' * 57))                                         # Enhanced Accept Sync, all zero
    # Truncated Page, clock offset 0x8010 (reproducer bthci_cmd_small_fixes.py)
    f.append(cmd(op(LC, 0x3f), bytes([0, 0, 0, 0, 0, 2]) + b'\x01' + le16(0x8010)))
    # Link policy: Sniff Mode, QoS Setup, Flow Specification with other values
    f.append(cmd(op(LP, 0x03), le16(0x0001) + le16(0x0320) + le16(0x0010) + le16(4) + le16(1)))
    f.append(cmd(op(LP, 0x10), le16(0x0001) + b'\x00\x01\x02' + le32(0xffffffff) * 3 + le32(0)))
    # Set Event Filter: clear, inquiry all/CoD/BD_ADDR/unknown condition,
    # connection setup all/CoD/BD_ADDR/unknown condition, unknown type
    f.append(cmd(op(HC, 0x05), b'\x00'))
    f.append(cmd(op(HC, 0x05), b'\x01\x00'))
    f.append(cmd(op(HC, 0x05), b'\x01\x01' + bytes([0x0c, 0x02, 0x5a]) + bytes([0xfc, 0xff, 0x1f])))
    f.append(cmd(op(HC, 0x05), b'\x01\x02' + BD1))
    f.append(cmd(op(HC, 0x05), b'\x01\x07'))
    f.append(cmd(op(HC, 0x05), b'\x02\x00\x02'))
    f.append(cmd(op(HC, 0x05), b'\x02\x01' + bytes([0x04, 0x04, 0x24]) + bytes([0xfc, 0x1f, 0x00]) + b'\x03'))
    f.append(cmd(op(HC, 0x05), b'\x02\x02' + BD2 + b'\x01'))
    f.append(cmd(op(HC, 0x05), b'\x02\x07'))
    f.append(cmd(op(HC, 0x05), b'\x05'))
    # Write Stored Link Key with two keys, Change Local Name, Page Timeout
    f.append(cmd(op(HC, 0x11), b'\x02' + BD1 + KEY + BD2 + KEY[::-1]))
    f.append(cmd(op(HC, 0x13), b'Wireshark HCI host'.ljust(248, b'\0')))
    f.append(cmd(op(HC, 0x18), le16(0x2000)))
    f.append(cmd(op(HC, 0x1a), b'\x03'))
    # Class of Device for every major device class, and every service bit
    for cod in ([0x04, 0x01, 0x00], [0x0c, 0x02, 0x5a], [0x00, 0x03, 0x02], [0x04, 0x04, 0x24],
                [0xc0, 0x05, 0x00], [0x80, 0x06, 0x08], [0x04, 0x07, 0x00], [0x08, 0x08, 0x00],
                [0x0c, 0x09, 0x00], [0x00, 0x1f, 0xff], [0x00, 0x00, 0x00], [0x00, 0x2a, 0xfe]):
        f.append(cmd(op(HC, 0x24), bytes(cod)))
    # Host Buffer Size, Host Number Of Completed Packets with two handles,
    # Write Current IAC LAP with two LAPs
    f.append(cmd(op(HC, 0x33), le16(1021) + b'\x40' + le16(8) + le16(4)))
    f.append(cmd(op(HC, 0x35), b'\x02' + le16(1) + le16(3) + le16(2) + le16(1)))
    f.append(cmd(op(HC, 0x3a), b'\x02' + bytes([0x33, 0x8b, 0x9e, 0x00, 0x8b, 0x9e])))
    # Set External Frame Configuration with two periods, MWS Scan Frequency
    # Table with two entries, MWS Pattern Configuration with two intervals
    f.append(cmd(op(HC, 0x6f), le16(5000) + le16(100) + le16(2) + b'\x02' + le16(2500) + b'\x01' + le16(2500) + b'\x02'))
    f.append(cmd(op(HC, 0x72), b'\x02' + le16(2400) + le16(2420) + le16(2460) + le16(2480)))
    f.append(cmd(op(HC, 0x73), b'\x01\x02' + le16(1000) + b'\x00' + le16(2000) + b'\x03'))
    f.append(cmd(op(HC, 0x76), b'\x01\x03\x03' + b'abc'))
    f.append(cmd(op(HC, 0x82), le16(0)))
    f.append(cmd(op(HC, 0x82), le16(0x0018)))
    f.append(cmd(op(HC, 0x83), b'\x01\x01\x02\xaa\xbb'))
    f.append(cmd(op(HC, 0x83), b'\x00\x00\x00'))
    # Write Page Scan Mode (reproducer bthci_cmd_small_fixes.py)
    f.append(cmd(op(HC, 0x3e), b'\x01'))
    # Write Remote AMP Assoc with 3 octets of fragment
    f.append(cmd(op(ST, 0x0b), b'\x01' + le16(0) + le16(3) + b'\x01\x02\x03'))
    # LE: Set Advertising Parameters with other values
    f.append(cmd(op(LE, 0x06), le16(0x0800) + le16(0x0800) + b'\x00\x01\x00' + BD2 + b'\x07\x00'))
    # Receiver / Transmitter Test v3 and v4 with antenna patterns, Tx power
    # setting as dBm, minimum and maximum
    f.append(cmd(op(LE, 0x4f), b'\x13\x02\x00\x14\x00\x01\x03\x00\x01\x02'))
    f.append(cmd(op(LE, 0x50), b'\x13\x25\x00\x02\x14\x02\x02\x00\x01'))
    for p in (0xfb, 0x7e, 0x7f):
        f.append(cmd(op(LE, 0x7b), b'\x13\x25\x00\x02\x14\x01\x02\x00\x01' + bytes([p])))
    # Extended Advertising Enable with two sets, Extended Scan Parameters
    # with all three PHY bits, Extended Create Connection v1 and v2
    f.append(cmd(op(LE, 0x39), b'\x01\x02' + b'\x00' + le16(0) + b'\x00' + b'\x01' + le16(100) + b'\x05'))
    f.append(cmd(op(LE, 0x41), b'\x00\x00\x07' + (b'\x01' + le16(0x0010) + le16(0x0010)) * 3))
    phys = (le16(0x0010) * 2 + le16(0x0018) * 2 + le16(0) + le16(0x0048) + le16(0) * 2)
    f.append(cmd(op(LE, 0x43), b'\x00\x00\x00' + BD1 + b'\x07' + phys * 3))
    f.append(cmd(op(LE, 0x85), b'\x01\xff' + b'\x00\x00\x00' + BD1 + b'\x01' + phys))
    f.append(cmd(op(LE, 0x85), b'\x01\x02' + b'\x00\x01\x01' + BD2 + b'\x04' + phys))
    f.append(cmd(op(LE, 0x86), b'\x01' + le16(0x0050) + le16(0x0060) + le16(0x0040) + b'\x04\x20\x02\x04\x05'))
    f.append(cmd(op(LE, 0x7f), b'\x01' + le16(0x13) + le24(0xa0) + le24(0xa0) + b'\x07\x00\x00' + BD1 + b'\x00\x7f\x01\x00\x03\x00\x00\x01\x02'))
    # CTE: transmit parameters, IQ sampling all/limited, receive parameters,
    # connection CTE request with interval 0 and non-zero
    f.append(cmd(op(LE, 0x51), b'\x01\x14\x07\x01\x02\x00\x01'))
    f.append(cmd(op(LE, 0x53), le16(1) + b'\x01\x01\x00\x02\x00\x01'))
    f.append(cmd(op(LE, 0x53), le16(1) + b'\x01\x02\x05\x00'))
    f.append(cmd(op(LE, 0x54), le16(1) + b'\x01\x01\x03\x00\x01\x02'))
    f.append(cmd(op(LE, 0x55), le16(1) + b'\x07\x02\x00\x01'))
    f.append(cmd(op(LE, 0x56), le16(1) + b'\x01' + le16(0) + b'\x14\x00'))
    f.append(cmd(op(LE, 0x56), le16(1) + b'\x01' + le16(4) + b'\x14\x01'))
    # CIG parameters with two CIS, CIG parameters test (reproducer and two
    # CIS with burst numbers 0 and non-zero), Create CIS with two CIS
    cis = lambda i: bytes([i]) + le16(100) + le16(100) + b'\x02\x02\x02\x02'
    f.append(cmd(op(LE, 0x62), b'\x01' + le24(10000) * 2 + b'\x00\x00\x00' + le16(10) * 2 + b'\x02' + cis(0) + cis(1)))
    cist = bytes([0x01, 0x02]) + le16(100) * 4 + bytes([1, 1, 3, 0])   # BN C->P 3, BN P->C 0
    f.append(cmd(op(LE, 0x63), b'\x01' + b'\x10\x27\x00' * 2 + b'\x01\x01' + le16(8) + b'\x00\x00\x00\x01' + cist))
    cist2 = bytes([0x02, 0x02]) + le16(100) * 4 + bytes([2, 2, 0, 2])
    f.append(cmd(op(LE, 0x63), b'\x02' + b'\x10\x27\x00' * 2 + b'\x01\x01' + le16(8) + b'\x00\x01\x01\x02' + cist + cist2))
    f.append(cmd(op(LE, 0x64), b'\x02' + le16(0x0060) + le16(0x0001) + le16(0x0061) + le16(0x0002)))
    # Create BIG with/without encryption, BIG Create Sync with three BIS
    f.append(cmd(op(LE, 0x68), b'\x01\x01\x02' + le24(10000) + le16(100) + le16(10) + b'\x02\x02\x00\x01' + KEY))
    f.append(cmd(op(LE, 0x6b), b'\x01' + le16(1) + b'\x01' + KEY + b'\x00' + le16(100) + b'\x03\x01\x02\x03'))
    # Setup ISO Data Path, data path HCI / logical channel / disabled
    for dp in (0x00, 0x05, 0xff):
        f.append(cmd(op(LE, 0x6e), le16(0x60) + b'\x00' + bytes([dp]) + b'\x06' + le16(0) + le16(0) + le24(100) + b'\x02\x01\x02'))
    # Decision data, decision instructions with every test field class
    f.append(cmd(op(LE, 0x80), b'\x01\x01\x03abc'))
    tests = b''
    for tf in (0x05, 0x14, 0x23, 0x33, 0x1c, 0xf5):
        tests += b'\x01' + bytes([tf]) + bytes(16)
    f.append(cmd(op(LE, 0x81), b'\x06' + tests))
    # Periodic advertising subevent data (two subevents), response data,
    # sync subevent with three subevents
    sub = lambda n, data: bytes([n, 0, 4, len(data)]) + data
    f.append(cmd(op(LE, 0x82), b'\x01\x02' + sub(0, AD_FLAGS + AD_NAMES) + sub(1, ad(0x0a, b'\x00'))))
    f.append(cmd(op(LE, 0x83), le16(1) + le16(2) + b'\x00\x00\x01' + bytes([len(AD_NAMES)]) + AD_NAMES))
    f.append(cmd(op(LE, 0x84), le16(1) + le16(0) + b'\x03\x00\x01\x02'))
    # LE UTP Send, LE Set Event Mask [v2] with RFU octets
    f.append(cmd(op(LE, 0xa0), b'\x03abc'))
    f.append(cmd(op(LE, 0xa4), b'\xff' * 8 + b'\x00\x00'))
    # CS Test: override config 0 (channel map), all bits set but bit 0,
    # bit 0 (channel list) with the rest
    head = bytes([1, 1, 2, 3, 0, 0, 1, 1]) + le24(5000) + le16(0) + b'\x01\x7f' + bytes([10, 10, 10, 10, 10, 1, 0, 0xff, 0xff]) + le16(0) + b'\x01'
    f.append(cmd(op(LE, 0x95), head + le16(0x0000) + b'\x0d' + b'\xfc' + b'\xff' * 8 + b'\x1f' + b'\x00\x00\x02'))
    body = (b'\xfc' + b'\xff' * 8 + b'\x1f' + b'\x00\x00\x02' + b'\x03' + b'\x01' + b'\x02'
            + le32(0x11223344) + le32(0x55667788) + b'\x01\x02' + b'\x00' + b'\x01' + KEY)
    f.append(cmd(op(LE, 0x95), head[:4] + b'\x01\x03' + head[6:] + le16(0x01fc) + bytes([len(body)]) + body))
    body = (b'\x03\x02\x03\x04' + b'\x03' + b'\x01' + b'\x02' + le32(0x11223344) + le32(0x55667788)
            + b'\x01\x02' + b'\x00' + b'\x01' + KEY)
    f.append(cmd(op(LE, 0x95), head + le16(0x01fd) + bytes([len(body)]) + body))
    # CS Write Cached Remote Supported Capabilities v2
    f.append(cmd(op(LE, 0xa6), b'\x01' * 35))
    return f


def all_commands():
    return [cmd(o, default_params(o)) for o in sorted(LENS) if o not in (0x0c52, 0x2008, 0x2009, 0x0c13)]


def ad_commands():
    f = []
    for g in EIR_GROUPS:
        f.append(eir(g))
    f.append(eir(b'', fec=0))                                     # empty EIR
    f.append(adv(AD_FLAGS + AD_NAMES + ad(0x0a, b'\x04')))
    f.append(adv(AD_FLAGS + AD_UUID16 + ad(0x19, le16(0x0341)), ocf=0x0009))
    f.append(adv(AD_IBEACON))
    f.append(adv(AD_DID_SIG + AD_LESC[:18]))
    # Reproducers bthci_cmd_ad_misparse.py: the entry after a TDS block, a
    # 16 octet TK value and a 1 octet LE Supported Features decodes
    name = ad(0x09, b'test')
    f.append(adv(bytes([6, 0x26, 0x01, 0x00, 0x02, 0xaa, 0xbb]) + name))
    f.append(adv(bytes([17, 0x10]) + bytes(range(0x40, 0x50)) + name))
    f.append(adv(bytes([2, 0x27, 0x01]) + name))
    # Extended / periodic advertising data
    f.append(ext_adv(EIR_GROUPS[0]))
    f.append(ext_adv(EIR_GROUPS[2][:200], ocf=0x0038))
    f.append(cmd(op(8, 0x3f), b'\x01\x03' + bytes([len(AD_BIGINFO)]) + AD_BIGINFO))
    return f


def vendor_frames():
    f = []
    # Read Local Version Information and its Command Complete naming
    # Broadcom (0x000F)
    f.append(cmd(0x1001, b''))
    f.append(cmd_complete(0x1001, struct.pack('<BBHBHH', 0, 0x09, 0x0001, 0x09, 0x000f, 0x0001)))
    # Broadcom LE Multi Advertising Write Advertising Data (reproducer
    # bthci_cmd_vendor_ad_confusion.py) and Set Advertising Parameters
    adv31 = (bytes([5, 0x09]) + b'test').ljust(31, b'\0')
    f.append(cmd(op(0x3f, 0x154), b'\x02' + adv31 + b'\x01'))
    # Broadcom Update UART baud rate, and a vendor command without parameters
    f.append(cmd(op(0x3f, 0x018), le16(0) + le32(115200)))
    f.append(cmd(op(0x3f, 0x002), b''))
    # A command in the received direction (Info "Rcvd")
    f.append(h4(False, 0x01, struct.pack('<HB', op(3, 0x03), 0)))
    return f


def response_frames():
    """Command Status and Command Complete events, so commands show the
    Pending In / Response In frames (only in the second pass)."""
    f = []
    f.append(cmd(op(1, 0x01), bytes([0x33, 0x8b, 0x9e, 0x08, 0x00])))
    f.append(cmd_status(op(1, 0x01)))
    f.append(cmd(op(3, 0x14), b''))
    f.append(cmd_complete(op(3, 0x14), b'\x00' + b'WS-host'.ljust(248, b'\0')))
    f.append(cmd(op(3, 0x03), b''))
    f.append(cmd_complete(op(3, 0x03), b'\x00'))
    return f


def event_ad_frames():
    """Events carrying EIR / AD data with the remote BD_ADDR, decoded by
    the same btcommon EIR/AD code (the device name tap with bd_addr)."""
    f = []
    # Extended Inquiry Result: 1 response, BD_ADDR, PSRM, reserved, CoD,
    # clock offset, RSSI, 240 octets EIR
    eirdata = (AD_FLAGS + ad(0x09, b'Remote') + AD_UUID16).ljust(240, b'\0')
    f.append(evt(0x2f, b'\x01' + BD2 + b'\x01\x00' + bytes([0x0c, 0x02, 0x5a]) + le16(0x1234) + b'\xc4' + eirdata))
    # LE Advertising Report: 1 report, ADV_IND, public, BD_ADDR, AD, RSSI
    addata = AD_FLAGS + ad(0x09, b'LEdev')
    f.append(evt(0x3e, b'\x02\x01\x00\x00' + BD1 + bytes([len(addata)]) + addata + b'\xc0'))
    return f


def main_capture():
    sections = [
        ('Command Status / Complete', response_frames()),
        ('vendor commands', vendor_frames()),
        ('every command opcode, fixed size parameters', all_commands()),
        ('parameter variants', special_commands()),
        ('EIR / AD data', ad_commands()),
        ('events with EIR / AD', event_ad_frames()),
    ]
    pkts = []
    for name, fr in sections:
        print('%-45s frames %d-%d' % (name, len(pkts) + 1, len(pkts) + len(fr)))
        pkts += fr
    return pkts


def write_pcapng(path, linktypes, pkts):
    """pkts: list of (interface id, packet)."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    with open(path, 'wb') as f:
        f.write(block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)))
        for lt in linktypes:
            f.write(block(1, struct.pack('<HHI', lt, 0, 65535)))
        for i, (ifid, p) in enumerate(pkts):
            ts = (1700000000 + i) * 1000000
            f.write(block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p))


def exppdu_capture():
    data = AD_FLAGS + ad(0x09, b'test') + AD_UUID16
    return [
        # Reproducer bthci_cmd_ad_null_data.py: the AD and EIR dissectors
        # called by name without data use the default interface and adapter
        exppdu('btcommon.eir_ad.ad', bytes([5, 0x09]) + b'test' + bytes([2, 0x01, 0x06])),
        exppdu('btcommon.eir_ad.eir', bytes([5, 0x09]) + b'test' + bytes([2, 0x01, 0x06])),
        exppdu('btcommon.eir_ad.ad', data + AD_BDADDR + AD_TDS + AD_MANUF),
        exppdu('btcommon.eir_ad.eir', (EIR_GROUPS[1]).ljust(240, b'\0')),
        exppdu('btcommon.cod', bytes([0x0c, 0x02, 0x5a])),
        exppdu('btcommon.channel_map', b'\xff' * 9 + b'\x7f'),
        exppdu('btcommon.le_channel_map', b'\xff' * 4 + b'\x1f'),
    ]


def extra_capture():
    # Interface 0: Exported PDU; interface 1: HCI H4 without the direction
    # pseudo-header, so the direction is unknown
    f = [(0, p) for p in exppdu_capture()]
    f.append((1, b'\x01' + struct.pack('<HB', op(1, 0x06), 3) + le16(0x0001) + b'\x13'))
    f.append((1, b'\x01' + struct.pack('<HB', op(8, 0x08), 32) + bytes([len(AD_FLAGS + AD_NAMES)]) + (AD_FLAGS + AD_NAMES).ljust(31, b'\0')))
    return f


def malformed_capture():
    f = []
    LE = 8
    # Vendor commands while the manufacturer is not known (in the main
    # capture they would decode as Broadcom on the second pass, since the
    # manufacturer is kept per adapter, not per frame)
    f.append(cmd(op(0x3f, 0x0001), b'\x01\x02\x03'))
    f.append(cmd(op(0x3f, 0x0002), b''))
    # Zigbee Direct service data shorter than 5 octets, IPS reserved flags
    f.append(ext_adv(ad(0x16, le16(0xfff7) + b'\x01\x02')))
    f.append(ext_adv(ad(0x25, bytes([0xc0]))))
    # Unknown OCFs in every OGF, and the Logo Testing OGF
    for ogf, ocf in ((1, 0x010), (2, 0x002), (3, 0x002), (4, 0x006), (5, 0x00f), (6, 0x00f),
                     (8, 0x0fe), (0x3e, 0x001), (0x07, 0x001)):
        f.append(cmd(op(ogf, ocf), b'\x01\x02'))
    # No-parameter commands given parameters
    for o in sorted(LENS):
        if LENS[o] == 0:
            f.append(cmd(o, b'\x01'))
    # Fixed size commands cut short
    f.append(cmd(op(1, 0x05), BD1))
    f.append(cmd(op(8, 0x0d), b'\x01' * 10))
    # Parameter length larger than the data
    f.append(cmd(op(1, 0x06), le16(1), plen=3))
    # Counts larger than the data
    f.append(cmd(op(3, 0x11), b'\x05' + BD1))
    f.append(cmd(op(8, 0x62), b'\x01' * 15 + b'\x09'))
    f.append(cmd(op(8, 0x64), b'\x07' + le16(1)))
    f.append(cmd(op(3, 0x6f), b'\x00' * 6 + b'\x09'))
    # AD entries that run past the field
    f.append(adv(bytes([40, 0x09]) + b'x' * 29))
    f.append(ext_adv(bytes([0x10, 0x0e]) + b'\x00' * 4))
    f.append(ext_adv(ad(0x26, bytes([0x01, 0x00, 0x09, 0xaa]))))            # TDS data length past the entry
    f.append(ext_adv(ad(0x25, bytes([0xff]) + b'\x00' * 12)))               # IPS reserved flags, short
    f.append(ext_adv(ad(0x02, b'\x0d')))                                    # odd 16-bit UUID list
    f.append(ext_adv(ad(0x10, b'\x01\x02\x03')))                            # DID / TK of another length
    f.append(ext_adv(ad(0x27, bytes(10))))                                  # LE features longer than 8
    # Reproducer data from bthci_cmd_randfuzz.py style: random parameters
    # are in the review; a short Create Connection is enough here.
    return f


def main():
    os.makedirs(OUT, exist_ok=True)
    write_pcap(os.path.join(OUT, 'bthci_cmd-coverage.pcap'), 201, main_capture())
    write_pcapng(os.path.join(OUT, 'bthci_cmd-coverage-exppdu.pcapng'), [252, 187], extra_capture())
    write_pcap(os.path.join(OUT, 'bthci_cmd-coverage-malformed.pcap'), 201, malformed_capture())


if __name__ == '__main__':
    main()
