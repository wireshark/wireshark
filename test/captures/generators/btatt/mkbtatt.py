#!/usr/bin/env python3
# Generates test/captures/btatt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Bluetooth ATT/GATT coverage captures for packet-btatt.c.

Usage: mkbtatt.py <outdir>

Writes btatt-coverage.pcap (main capture) and btatt-coverage-malformed.pcap.
Every packet is built with struct: Bluetooth HCI H4 with Linux header
(DLT 201), an LE Connection Complete event and then ACL data on the
LE fixed ATT channel (CID 0x0004).  The local host is the GATT client
(Sent), the remote device the GATT server (Rcvd).
"""
import os
import struct
import sys

SENT = 0
RECV = 1


def u8(v):
    return struct.pack('<B', v & 0xff)


def s8(v):
    return struct.pack('<b', v)


def u16(v):
    return struct.pack('<H', v & 0xffff)


def s16(v):
    return struct.pack('<h', v)


def u24(v):
    return struct.pack('<I', v & 0xffffff)[:3]


def u32(v):
    return struct.pack('<I', v & 0xffffffff)


def u48(v):
    return struct.pack('<Q', v)[:6]


def u64(v):
    return struct.pack('<Q', v)


def ts(y=2024, mo=5, d=17, h=12, mi=34, s=56):
    """Date Time (0x2A08): year, month, day, hours, minutes, seconds."""
    return u16(y) + bytes([mo, d, h, mi, s])


def uuid128(text):
    """128-bit UUID as sent on the air (little endian)."""
    return bytes.fromhex(text.replace('-', ''))[::-1]


# ---------------------------------------------------------------------------
# Capture framing
# ---------------------------------------------------------------------------

class Capture:
    def __init__(self, chandle=0x0040):
        self.frames = []
        self.chandle = chandle

    def raw(self, direction, h4):
        self.frames.append(struct.pack('>I', direction) + h4)

    def le_connect(self, chandle=None, peer=b'\x11\x22\x33\x44\x55\x66'):
        chandle = self.chandle if chandle is None else chandle
        # HCI Event 0x3E (LE Meta), subevent 0x01 LE Connection Complete:
        # status, handle, role (central), peer address type, peer address,
        # interval, latency, supervision timeout, central clock accuracy
        ev = bytes([0x01, 0x00]) + u16(chandle) + bytes([0x00, 0x00]) + peer[::-1] + \
            u16(0x0018) + u16(0) + u16(0x00c8) + bytes([0x00])
        self.raw(RECV, bytes([0x04, 0x3e, len(ev)]) + ev)

    def att(self, direction, pdu, chandle=None, cid=0x0004):
        chandle = self.chandle if chandle is None else chandle
        l2 = struct.pack('<HH', len(pdu), cid) + pdu
        self.raw(direction, struct.pack('<BHH', 0x02, 0x2000 | chandle, len(l2)) + l2)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 201))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000, len(fr), len(fr)))
                f.write(fr)

    # ATT helpers ---------------------------------------------------------
    def read(self, handle, value):
        self.att(SENT, u8(0x0a) + u16(handle))
        self.att(RECV, u8(0x0b) + value)

    def write_req(self, handle, value):
        self.att(SENT, u8(0x12) + u16(handle) + value)
        self.att(RECV, u8(0x13))

    def notify(self, handle, value):
        self.att(RECV, u8(0x1b) + u16(handle) + value)

    def indicate(self, handle, value):
        self.att(RECV, u8(0x1d) + u16(handle) + value)
        self.att(SENT, u8(0x1e))

    def command(self, handle, value):
        self.att(SENT, u8(0x52) + u16(handle) + value)

    def command_in(self, handle, value):
        # Write Command from the remote device to a local server (Mesh
        # Provisioning/Proxy Data In handles are saved for the local side)
        self.att(RECV, u8(0x52) + u16(handle) + value)

    def op(self, kind, handle, value):
        {'R': self.read, 'W': self.write_req, 'N': self.notify,
         'I': self.indicate, 'C': self.command, 'c': self.command_in}[kind](handle, value)


# ---------------------------------------------------------------------------
# Characteristic table: UUID -> (service UUID, opcodes allowed by the
# dissector's usage checks).  R = Read Request/Response, W = Write
# Request/Response, N = Notification, I = Indication/Confirmation,
# C = Write Command.  Service 0 = no service check (put in 0x18FF).
# ---------------------------------------------------------------------------

CHARS = {
    0x2A00: (0x1800, 'R'), 0x2A01: (0x1800, 'R'), 0x2A02: (0x1800, 'RW'), 0x2A03: (0x1800, 'W'),
    0x2A04: (0x1800, 'R'), 0x2AA6: (0x1800, 'R'), 0x2AC9: (0x1800, 'R'),
    0x2A05: (0x1801, 'I'),
    0x2A06: (0x1802, 'C'),
    0x2A07: (0x1804, 'R'),
    0x2A08: (0, 'R'), 0x2A09: (0, 'R'),
    0x2A0A: (0x1805, 'R'), 0x2A0B: (0x1805, 'R'), 0x2A0C: (0x1805, 'R'), 0x2A2B: (0x1805, 'NRW'),
    0x2A0D: (0, 'R'), 0x2A0E: (0, 'R'),
    0x2A0F: (0x1805, 'RW'), 0x2A10: (0x1805, 'RW'),
    0x2A11: (0x1807, 'R'), 0x2A12: (0, 'R'), 0x2A13: (0, 'R'), 0x2A14: (0x1805, 'R'), 0x2A15: (0, 'R'),
    0x2A16: (0x1806, 'C'), 0x2A17: (0x1806, 'R'),
    0x2A18: (0x1808, 'N'), 0x2A19: (0x180F, 'NR'), 0x2A1A: (0, 'R'), 0x2A1B: (0, 'R'),
    0x2A1C: (0x1809, 'I'), 0x2A1E: (0x1809, 'N'), 0x2A1D: (0x1809, 'R'), 0x2A1F: (0, 'R'),
    0x2A20: (0, 'R'), 0x2A21: (0x1809, 'IRW'),
    0x2A22: (0x1812, 'NRW'),
    0x2A23: (0x180A, 'R'), 0x2A24: (0x180A, 'R'), 0x2A25: (0x180A, 'R'), 0x2A26: (0x180A, 'R'),
    0x2A27: (0x180A, 'R'), 0x2A28: (0x180A, 'R'), 0x2A29: (0x180A, 'R'), 0x2A2A: (0x180A, 'R'),
    0x2A2C: (0x181A, 'NR'), 0x2A2F: (0, 'R'), 0x2A30: (0, 'R'), 0x2A31: (0x1813, 'N'),
    0x2A32: (0x1812, 'CRW'), 0x2A33: (0x1812, 'NRW'), 0x2A34: (0x1808, 'N'),
    0x2A35: (0x1810, 'I'), 0x2A36: (0x1810, 'N'),
    0x2A37: (0x180D, 'N'), 0x2A38: (0x180D, 'R'), 0x2A39: (0x180D, 'W'),
    0x2A3A: (0, 'R'), 0x2A3B: (0, 'R'), 0x2A3C: (0, 'R'), 0x2A3D: (0, 'R'), 0x2A3E: (0, 'R'),
    0x2A3F: (0x180E, 'NR'), 0x2A40: (0x180E, 'C'), 0x2A41: (0x180E, 'NR'),
    0x2A42: (0x1811, 'R'), 0x2A47: (0x1811, 'R'), 0x2A48: (0x1811, 'R'), 0x2A43: (0, 'R'),
    0x2A44: (0x1811, 'W'), 0x2A45: (0x1811, 'N'), 0x2A46: (0x1811, 'N'),
    0x2A49: (0x1810, 'R'), 0x2A4A: (0x1812, 'R'), 0x2A4B: (0x1812, 'R'), 0x2A4C: (0x1812, 'C'),
    0x2A4D: (0x1812, 'CNRW'), 0x2A4E: (0x1812, 'CR'), 0x2A4F: (0x1813, 'C'),
    0x2A50: (0x180A, 'R'), 0x2A51: (0x1808, 'R'), 0x2A52: (0x1808, 'WI'),
    0x2A53: (0x1814, 'N'), 0x2A54: (0x1814, 'R'), 0x2A55: (0x1814, 'WI'),
    0x2A56: (0x1815, 'CNRW'), 0x2A57: (0, 'R'), 0x2A58: (0x1815, 'CNRW'), 0x2A59: (0, 'R'),
    0x2A5A: (0x1815, 'NR'), 0x2A5B: (0x1816, 'N'), 0x2A5C: (0x1816, 'R'), 0x2A5D: (0x1814, 'R'),
    0x2A5E: (0x1822, 'I'), 0x2A5F: (0x1822, 'N'), 0x2A60: (0x1822, 'R'),
    0x2A63: (0x1818, 'N'), 0x2A64: (0x1818, 'N'), 0x2A65: (0x1818, 'R'), 0x2A66: (0x1818, 'WI'),
    0x2A67: (0x1819, 'N'), 0x2A68: (0x1819, 'N'), 0x2A69: (0x1819, 'R'), 0x2A6A: (0x1819, 'R'),
    0x2A6B: (0x1819, 'WI'),
    0x2A6C: (0x181A, 'NR'), 0x2A6D: (0x181A, 'NR'), 0x2A6E: (0x181A, 'NR'), 0x2A6F: (0x181A, 'NR'),
    0x2A70: (0x181A, 'NR'), 0x2A71: (0x181A, 'NR'), 0x2A72: (0x181A, 'NR'), 0x2A73: (0x181A, 'NR'),
    0x2A74: (0x181A, 'NR'), 0x2A75: (0x181A, 'NR'), 0x2A76: (0x181A, 'NR'), 0x2A77: (0x181A, 'NR'),
    0x2A78: (0x181A, 'NR'), 0x2A79: (0x181A, 'NR'), 0x2A7A: (0x181A, 'NR'), 0x2A7B: (0x181A, 'NR'),
    0x2A7D: (0x181A, 'I'), 0x2AA0: (0x181A, 'NR'), 0x2AA1: (0x181A, 'NR'), 0x2AA3: (0x181A, 'NR'),
    0x2A7E: (0, 'R'),
    0x2A7F: (0x181C, 'RW'), 0x2A80: (0x181C, 'RW'), 0x2A81: (0x181C, 'RW'), 0x2A82: (0x181C, 'RW'),
    0x2A83: (0x181C, 'RW'), 0x2A84: (0x181C, 'RW'), 0x2A85: (0x181C, 'RW'), 0x2A86: (0x181C, 'RW'),
    0x2A87: (0x181C, 'RW'), 0x2A88: (0x181C, 'RW'), 0x2A89: (0x181C, 'RW'), 0x2A8A: (0x181C, 'RW'),
    0x2A8B: (0x181C, 'RW'), 0x2A8C: (0x181C, 'RW'), 0x2A8D: (0x181C, 'RW'), 0x2A8E: (0x181C, 'RW'),
    0x2A8F: (0x181C, 'RW'), 0x2A90: (0x181C, 'RW'), 0x2A91: (0x181C, 'RW'), 0x2A92: (0x181C, 'RW'),
    0x2A93: (0x181C, 'RW'), 0x2A94: (0x181C, 'RW'), 0x2A95: (0x181C, 'RW'), 0x2A96: (0x181C, 'RW'),
    0x2A97: (0x181C, 'RW'), 0x2A98: (0x181C, 'RW'), 0x2A99: (0x181C, 'NRW'), 0x2A9A: (0x181C, 'R'),
    0x2A9F: (0x181C, 'WI'), 0x2AA2: (0x181C, 'RW'),
    0x2A9B: (0x181B, 'R'), 0x2A9C: (0x181B, 'I'),
    0x2A9D: (0x181D, 'I'), 0x2A9E: (0x181D, 'R'),
    0x2AA4: (0x181E, 'W'), 0x2AA5: (0x181E, 'R'),
    0x2AA7: (0x181F, 'N'), 0x2AA8: (0x181F, 'R'), 0x2AA9: (0x181F, 'R'), 0x2AAA: (0x181F, 'RW'),
    0x2AAB: (0x181F, 'RW'), 0x2AAC: (0x181F, 'WI'),
    0x2AAD: (0x1821, 'CRW'), 0x2AAE: (0x1821, 'CRW'), 0x2AAF: (0x1821, 'CRW'), 0x2AB0: (0x1821, 'CRW'),
    0x2AB1: (0x1821, 'CRW'), 0x2AB2: (0x1821, 'CRW'), 0x2AB3: (0x1821, 'CRW'), 0x2AB4: (0x1821, 'CRW'),
    0x2AB5: (0x1821, 'CRW'),
    0x2AB6: (0x1823, 'W'), 0x2AB7: (0x1823, 'RW'), 0x2AB8: (0x1823, 'N'), 0x2AB9: (0x1823, 'RW'),
    0x2ABA: (0x1823, 'W'), 0x2ABB: (0x1823, 'R'),
    0x2ABC: (0x1824, 'WI'),
    0x2ABD: (0x1825, 'R'), 0x2ABE: (0x1825, 'RW'), 0x2ABF: (0x1825, 'R'), 0x2AC0: (0x1825, 'R'),
    0x2AC1: (0x1825, 'RW'), 0x2AC2: (0x1825, 'RW'), 0x2AC3: (0x1825, 'R'), 0x2AC4: (0x1825, 'RW'),
    0x2AC5: (0x1825, 'WI'), 0x2AC6: (0x1825, 'WI'), 0x2AC7: (0x1825, 'RW'), 0x2AC8: (0x1825, 'I'),
    0x2ACC: (0x1826, 'R'), 0x2ACD: (0x1826, 'N'), 0x2ACE: (0x1826, 'N'), 0x2ACF: (0x1826, 'N'),
    0x2AD0: (0x1826, 'N'), 0x2AD1: (0x1826, 'N'), 0x2AD2: (0x1826, 'N'), 0x2AD3: (0x1826, 'NR'),
    0x2AD4: (0x1826, 'R'), 0x2AD5: (0x1826, 'R'), 0x2AD6: (0x1826, 'R'), 0x2AD7: (0x1826, 'R'),
    0x2AD8: (0x1826, 'R'), 0x2AD9: (0x1826, 'WI'), 0x2ADA: (0x1826, 'N'),
    0x2ADB: (0, 'C'), 0x2ADC: (0, 'N'), 0x2ADD: (0, 'C'), 0x2ADE: (0, 'NR'),
    0x2B7D: (0, 'R'), 0x2B7E: (0, 'W'), 0x2B7F: (0, 'R'),
    # Characteristics without a decoder (the TODO/default branch)
    0x2AE0: (0, 'R'), 0x2B1F: (0, 'R'),
}

# Characteristic values.  Each entry is a list of payloads (sent with the
# first allowed opcode) or (opcode, payload) tuples.  Every allowed opcode
# not used by an entry is exercised once with the first payload.
V = {}

V[0x2A00] = [b'Synthetic GATT Server']
# Appearance: category in bits 15..6; one per subcategory table + generic
V[0x2A01] = [u16((c << 6) | 1) for c in (0x003, 0x00C, 0x00D, 0x00E, 0x00F, 0x011, 0x012,
                                          0x031, 0x033, 0x035, 0x051, 0x001)]
V[0x2A02] = [u8(1)]
V[0x2A03] = [bytes.fromhex('665544332211')]
V[0x2A04] = [u16(0x18) + u16(0x28) + u16(0) + u16(0x1f4)]
V[0x2AA6] = [u8(1)]
V[0x2A05] = [u16(0x0001) + u16(0x00ff)]
V[0x2A06] = [u8(2)]
V[0x2A07] = [s8(-8)]
V[0x2A08] = [ts()]
V[0x2A09] = [u8(5)]
V[0x2A0A] = [ts() + u8(5)]
V[0x2A0B] = [ts() + u8(5) + u8(50)]
V[0x2A0C] = [ts() + u8(5) + u8(128)]
V[0x2A2B] = [ts() + u8(5) + u8(128) + u8(0x0f)]
V[0x2A0D] = [u8(4)]
V[0x2A0E] = [s8(4)]
V[0x2A0F] = [s8(4) + u8(4)]
V[0x2A10] = [u8(0x03) + s8(-20) + u8(0)]
V[0x2A11] = [ts(2024, 10, 27, 3, 0, 0) + u8(0)]
V[0x2A12] = [u8(10)]
V[0x2A13] = [u8(1)]
V[0x2A14] = [u8(1) + u8(10) + u8(2) + u8(5)]
V[0x2A15] = [ts() + u8(5) + u8(128) + s8(4) + u8(4) + u8(1) + u8(10) + u8(2) + u8(5)]
V[0x2A16] = [u8(1)]
V[0x2A17] = [u8(1) + u8(0)]
# Glucose Measurement: all fields, kg/L, mol/L
V[0x2A18] = [u8(0x0b) + u16(1) + ts() + s16(30) + u16(0xb064) + u8(0x11) + u16(0x0fff),
             u8(0x0f) + u16(2) + ts() + s16(-30) + u16(0xd050) + u8(0x22) + u16(0x0001),
             u8(0x00) + u16(3) + ts()]
V[0x2A19] = [u8(87)]
V[0x2A1A] = [u8(0xbb)]
V[0x2A1B] = [u8(50) + u8(0xbb), u8(60)]
V[0x2A1C] = [u8(0x07) + u32(0xff00016e) + ts() + u8(2), u8(0x00) + u32(0xff000172)]
V[0x2A1E] = [u8(0x06) + u32(0xff00016e) + ts() + u8(3)]
V[0x2A1D] = [u8(2)]
V[0x2A1F] = [s16(215)]
V[0x2A20] = [s16(705)]
V[0x2A21] = [u16(60)]
V[0x2A22] = [bytes([0x02, 0x00, 0x04, 0x05, 0, 0, 0, 0])]
V[0x2A23] = [bytes.fromhex('0102030405') + bytes.fromhex('a1b2c3')]
V[0x2A24] = [b'Model-1']
V[0x2A25] = [b'SN-0001']
V[0x2A26] = [b'FW 1.2.3']
V[0x2A27] = [b'HW rev B']
V[0x2A28] = [b'SW 4.5']
V[0x2A29] = [b'Example Inc.']
# Regulatory Certification Data List: authorizing body data (type 1),
# regulation bit field (type 2), other type (3)
_rc_items = (u8(2) + u8(1) + u16(8) + u8(1) + u8(2) + u16(1) + u16(2) + u16(0x1004) +
             u8(2) + u8(2) + u16(2) + u16(0x0001) +
             u8(2) + u8(3) + u16(2) + b'xy')
_rc_one = u8(2) + u8(1) + u16(8) + u8(1) + u8(2) + u16(1) + u16(2) + u16(0x1004)
_rc_two = u8(2) + u8(2) + u16(2) + u16(0x0001)
_rc_three = u8(2) + u8(3) + u16(2) + b'xy'
V[0x2A2A] = [u16(1) + u16(len(x)) + x for x in (_rc_one, _rc_two, _rc_three)]
# More than one item: the per-item length check warns (malformed capture)
BAD_2A2A = u16(3) + u16(len(_rc_items)) + _rc_items
V[0x2A2C] = [u16(1234)]
V[0x2A2F] = [struct.pack('<ii', 523456789, 134567890)]
V[0x2A30] = [struct.pack('<ii', 523456789, 134567890) + u24(1500)]
V[0x2A31] = [u8(0)]
V[0x2A32] = [u8(0x05)]
V[0x2A33] = [bytes([0x01, 0x05, 0xfb, 0x00])]
V[0x2A34] = [u8(0xdf) + u16(1) + u8(0x00) + u8(1) + u16(0xb050) + u8(2) + u8(0x34) + u16(1800) + u8(50)
             + u8(1) + u16(0xa020) + u16(0xb065),
             u8(0xff) + u16(2) + u8(0x00) + u8(2) + u16(0xb050) + u8(3) + u8(0x12) + u16(600) + u8(30)
             + u8(2) + u16(0xa020) + u16(0xb065)]
V[0x2A35] = [u8(0x1f) + u16(0xf8a0) + u16(0xf870) + u16(0xf880) + ts() + u16(0x0048) + u8(1) + u16(0x003f),
             u8(0x00) + u16(120) + u16(80) + u16(93)]
V[0x2A36] = [u8(0x1e) + u16(130) + u16(0x07ff) + u16(0x07ff) + ts() + u16(70) + u8(2) + u16(0x0001)]
V[0x2A37] = [u8(0x1f) + u16(300) + u16(1000) + u16(800) + u16(812), u8(0x06) + u8(72)]
V[0x2A38] = [u8(1)]
V[0x2A39] = [u8(1)]
V[0x2A3A] = [u8(0x01)]
V[0x2A3B] = [u8(0x01)]
V[0x2A3C] = [struct.pack('<d', 21.5)]
V[0x2A3D] = [b'string value']
V[0x2A3E] = [u8(1)]
V[0x2A3F] = [u8(0x07)]
V[0x2A40] = [u8(1)]
V[0x2A41] = [u8(1)]
V[0x2A42] = [u8(0xff) + u8(0x03), u8(0x0f)]
V[0x2A47] = [u8(0xff) + u8(0x03)]
V[0x2A48] = [u8(0x0f)]
V[0x2A43] = [u8(3)]
V[0x2A44] = [u8(0) + u8(1)]
V[0x2A45] = [u8(3) + u8(2)]
V[0x2A46] = [u8(4) + u8(1) + b'Missed call', u8(5) + u8(1)]
V[0x2A49] = [u16(0x003f)]
V[0x2A4A] = [u16(0x0111) + u8(0) + u8(0x03)]
# Report Map: a tiny HID report descriptor (keyboard)
V[0x2A4B] = [bytes.fromhex('05010906a101050719e029e715002501750195088102c0')]
V[0x2A4C] = [u8(0)]
V[0x2A4D] = [bytes([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])]
V[0x2A4E] = [u8(1)]
V[0x2A4F] = [u16(0x0010) + u16(0x0010)]
V[0x2A50] = [u8(1) + u16(0x000f) + u16(0x1234) + u16(0x0110),
             u8(2) + u16(0x046d) + u16(0xc52b) + u16(0x1201),
             u8(9) + u16(0x0001) + u16(0x0002) + u16(0x0003)]
V[0x2A51] = [u16(0x07ff)]
# Record Access Control Point: requests (Write) and responses (Indication)
V[0x2A52] = [('W', u8(1) + u8(1)),
             ('W', u8(1) + u8(2) + u8(1) + u16(100)),
             ('W', u8(2) + u8(3) + u8(1) + u16(10)),
             ('W', u8(4) + u8(4) + u8(1) + u16(10) + u16(20)),
             ('W', u8(1) + u8(2) + u8(2) + u16(5)),
             ('W', u8(1) + u8(3) + u8(2) + u16(5)),
             ('W', u8(1) + u8(4) + u8(2) + u16(5) + u16(9)),
             ('W', u8(1) + u8(5)),
             ('W', u8(3) + u8(0)),
             ('I', u8(5) + u8(0) + u16(17)),
             ('I', u8(6) + u8(0) + u8(1) + u8(1))]
V[0x2A53] = [u8(0x07) + u16(0x0300) + u8(90) + u16(120) + u32(123456), u8(0x00) + u16(0x0200) + u8(80)]
V[0x2A54] = [u16(0x001f)]
V[0x2A55] = [('W', u8(1) + u32(1000)), ('W', u8(2)), ('W', u8(3) + u8(4)), ('W', u8(4)),
             ('I', u8(16) + u8(1) + u8(1)),
             ('I', u8(16) + u8(4) + u8(1) + bytes([1, 4, 5, 6]))]
V[0x2A56] = [u8(0x1b)]
V[0x2A57] = [u8(0x55) + u8(0xaa)]
V[0x2A58] = [u16(0x0123)]
V[0x2A59] = [u16(0x0456)]
V[0x2A5A] = [u8(0x1b) + u16(0x0123)]
V[0x2A5B] = [u8(0x03) + u32(1000) + u16(2048) + u16(500) + u16(1024), u8(0x00)]
V[0x2A5C] = [u16(0x0007)]
V[0x2A5D] = [u8(4)]
V[0x2A5E] = [u8(0x0f) + u16(0x0062) + u16(0x0048) + ts() + u16(0x0fe0) + u24(0x00ffff) + u16(0xf064),
             u8(0x00) + u16(0x0061) + u16(0x0046)]
V[0x2A5F] = [u8(0x1f) + u16(98) + u16(72) + u16(97) + u16(73) + u16(96) + u16(71) + u16(0x0fe0)
             + u24(0x00ffff) + u16(0xf064), u8(0x00) + u16(99) + u16(60)]
V[0x2A60] = [u16(0x0007) + u16(0x0fe0) + u24(0x00ffff), u16(0x0004)]
V[0x2A63] = [u16(0x0fff) + s16(250) + u8(100) + u16(3200) + u32(10000) + u16(4096) + u16(500)
             + u16(2048) + s16(200) + s16(-50) + s16(80) + s16(-20) + u24(0x05a0b4) + u16(10)
             + u16(190) + u16(42),
             u16(0x0000) + s16(120)]
V[0x2A64] = [u8(0x07) + u16(300) + u16(4096) + u16(90) + s16(10) + s16(20) + s16(30),
             u8(0x08) + s16(5) + s16(6)]
V[0x2A65] = [u32(0x003fffff)]
V[0x2A66] = [('W', u8(1) + u32(5000)), ('W', u8(2) + u8(5)), ('W', u8(3)), ('W', u8(4) + u16(345)),
             ('W', u8(5)), ('W', u8(6) + u16(1100)), ('W', u8(7)), ('W', u8(8) + u16(250)), ('W', u8(9)),
             ('W', u8(10) + u16(40)), ('W', u8(11)), ('W', u8(12)), ('W', u8(13) + u16(0x01ff)),
             ('W', u8(14)), ('W', u8(15)), ('W', u8(99)),
             ('I', u8(32) + u8(1) + u8(1)),
             ('I', u8(32) + u8(3) + u8(1) + bytes([5, 6, 7])),
             ('I', u8(32) + u8(5) + u8(1) + u16(345)),
             ('I', u8(32) + u8(7) + u8(1) + u16(1100)),
             ('I', u8(32) + u8(9) + u8(1) + u16(250)),
             ('I', u8(32) + u8(11) + u8(1) + u16(40)),
             ('I', u8(32) + u8(12) + u8(1) + s16(-12)),
             ('I', u8(32) + u8(14) + u8(1) + u8(20)),
             ('I', u8(32) + u8(15) + u8(1) + ts()),
             ('I', u8(32) + u8(3) + u8(2)),
             ('I', u8(32) + u8(5) + u8(3)),
             ('I', u8(32) + u8(7) + u8(3)),
             ('I', u8(32) + u8(9) + u8(3)),
             ('I', u8(32) + u8(11) + u8(3)),
             ('I', u8(32) + u8(12) + u8(3)),
             ('I', u8(32) + u8(14) + u8(3)),
             ('I', u8(32) + u8(15) + u8(3))]
V[0x2A67] = [u16(0x1f7f) + u16(512) + u24(12345) + struct.pack('<ii', 523456789, 134567890)
             + struct.pack('<i', 12000)[:3] + u16(9000) + u8(3) + ts(), u16(0x0000)]
V[0x2A68] = [u16(0x001f) + u16(4500) + u16(9000) + u24(2000) + u24(150) + ts(), u16(0x0000) + u16(1) + u16(2)]
V[0x2A69] = [u16(0x01ff) + u8(5) + u8(9) + u16(300) + u32(500) + u32(800) + u8(4) + u8(6), u16(0x0000)]
V[0x2A6A] = [u32(0x001fffff)]
V[0x2A6B] = [('W', u8(1) + u24(1000)), ('W', u8(2) + u16(0x007f)), ('W', u8(3) + u8(1)), ('W', u8(4)),
             ('W', u8(5) + u16(2)), ('W', u8(6) + u16(2)), ('W', u8(7) + u8(1)), ('W', u8(8) + u24(500)),
             ('W', u8(99)),
             ('I', u8(32) + u8(1) + u8(1)),
             ('I', u8(32) + u8(4) + u8(1) + u16(3)),
             ('I', u8(32) + u8(5) + u8(1) + b'Home'),
             ('I', u8(32) + u8(9) + u8(2))]
V[0x2A6C] = [struct.pack('<i', 12345)[:3]]
V[0x2A6D] = [u32(1013250)]
V[0x2A6E] = [s16(2150)]
V[0x2A6F] = [u16(4550)]
V[0x2A70] = [u16(512)]
V[0x2A71] = [u16(27000)]
V[0x2A72] = [u16(612)]
V[0x2A73] = [u16(9000)]
V[0x2A74] = [u8(15)]
V[0x2A75] = [u24(1200)]
V[0x2A76] = [u8(6)]
V[0x2A77] = [u16(800)]
V[0x2A78] = [u16(25)]
V[0x2A79] = [s8(-5)]
V[0x2A7A] = [s8(30)]
V[0x2A7B] = [s8(12)]
V[0x2A7D] = [u16(0x001f) + u16(0x290c), u16(0x0001) + uuid128('0000290d-0000-1000-8000-00805f9b34fb')]
V[0x2A7E] = [u8(90)]
V[0x2A7F] = [u8(120)]
V[0x2A80] = [u8(42)]
V[0x2A81] = [u8(130)]
V[0x2A82] = [u8(160)]
V[0x2A83] = [u8(150)]
V[0x2A84] = [u8(140)]
V[0x2A85] = [u16(1982) + u8(3) + u8(14)]
V[0x2A86] = [u16(2024) + u8(1) + u8(2)]
V[0x2A87] = [b'user@example.com']
V[0x2A88] = [u8(100)]
V[0x2A89] = [u8(130)]
V[0x2A8A] = [b'Alice']
V[0x2A8B] = [bytes([100, 120, 140, 160])]
V[0x2A8C] = [u8(1)]
V[0x2A8D] = [u8(185)]
V[0x2A8E] = [u16(178)]
V[0x2A8F] = [u16(95)]
V[0x2A90] = [b'Example']
V[0x2A91] = [u8(180)]
V[0x2A92] = [u8(55)]
V[0x2A93] = [u8(2)]
V[0x2A94] = [bytes([120, 150])]
V[0x2A95] = [u8(125)]
V[0x2A96] = [u8(48)]
V[0x2A97] = [u16(80)]
V[0x2A98] = [u16(15000)]
V[0x2A99] = [u32(7)]
V[0x2A9A] = [u8(1)]
V[0x2A9B] = [u32(0x0007ffff)]
V[0x2A9C] = [u16(0x0ffe) + u16(215) + ts() + u8(1) + u16(7000) + u16(400) + u16(30000) + u16(50000)
             + u16(28000) + u16(36000) + u16(5000) + u16(70000 & 0xffff) + u16(1780),
             u16(0x0fe1) + u16(220) + u16(66000 & 0xffff) + u16(110000 & 0xffff) + u16(60000)
             + u16(80000 & 0xffff) + u16(5000) + u16(150000 & 0xffff) + u16(700)]
V[0x2A9D] = [('I', u8(0x0e) + u16(15000) + ts() + u8(1) + u16(237) + u16(1780)),
             ('I', u8(0x09) + u16(33000) + u16(237) + u16(70)),
             ('W', u8(0x00) + u16(15000))]
V[0x2A9E] = [u32(0x000003ff)]
V[0x2A9F] = [('W', u8(1) + u16(1234)), ('W', u8(2) + u8(1) + u16(1234)), ('W', u8(3)), ('W', u8(9)),
             ('I', u8(0x20) + u8(1) + u8(1) + u8(2)), ('I', u8(0x20) + u8(2) + u8(5))]
V[0x2AA0] = [s16(100) + s16(-200)]
V[0x2AA1] = [s16(100) + s16(-200) + s16(300)]
V[0x2AA2] = [b'en']
V[0x2AA3] = [u8(3)]
V[0x2AA4] = [u8(3) + b'0000', u8(6)]
V[0x2AA5] = [u24(0x83ffff) + u8(0x81) + u8(0x01), u24(0x00ffff)]
V[0x2AA7] = [u8(5) + u8(0xe3) + u16(0xb064) + u16(10) + u8(0x01) + u8(0x02) + u8(0x04) + u16(0xe005)
             + u16(0xb050) + u16(0x1234),
             u8(5) + u8(0x00) + u16(100) + u16(20)]
V[0x2AA8] = [u24(0x01ffff) + u8(0x11) + u16(0xffff)]
V[0x2AA9] = [u16(30) + u8(0x01) + u8(0x02) + u8(0x04) + u16(0x5555), u16(31) + u24(0)]
V[0x2AAA] = [ts() + s8(4) + u8(0) + u16(0x2222), ts() + s8(4) + u8(0)]
V[0x2AAB] = [u16(168) + u16(0x3333), u16(169)]
V[0x2AAC] = [('W', u8(1) + u8(5)), ('W', u8(2)), ('W', u8(4) + u16(0xb064) + u16(10) + u8(0x11) + u16(20)
                                                       + u16(1) + u8(0x07)),
             ('W', u8(5) + u16(1)), ('W', u8(7) + u16(0xb0c8)), ('W', u8(19) + u16(0xb00a)),
             ('W', u8(26) + u16(0x4444)), ('W', u8(99)),
             ('I', u8(28) + u8(3) + u8(1) + u8(5)),
             ('I', u8(28) + u8(6) + u8(1) + u16(0xb064) + u16(10) + u8(0x11) + u16(20) + u16(1) + u8(0x00)),
             ('I', u8(28) + u8(9) + u8(1) + u16(0xb0c8)),
             ('I', u8(28) + u8(21) + u8(1) + u16(0xb00a)),
             ('I', u8(28) + u8(99) + u8(2))]
V[0x2AAD] = [u8(0x7f)]
V[0x2AAE] = [struct.pack('<i', 523456789)]
V[0x2AAF] = [struct.pack('<i', 134567890)]
V[0x2AB0] = [s16(150)]
V[0x2AB1] = [s16(-75)]
V[0x2AB2] = [u8(22)]
V[0x2AB3] = [u16(1200)]
V[0x2AB4] = [u8(0x7f)]
V[0x2AB5] = [b'Lobby']
V[0x2AB6] = [b'http://example.com/index.html']
V[0x2AB7] = [b'Host: example.com\r\nAccept: */*\r\n\r\n']
V[0x2AB8] = [u16(200) + u8(0x0f)]
V[0x2AB9] = [b'<html>ok</html>']
V[0x2ABA] = [u8(1)]
V[0x2ABB] = [u8(1)]
V[0x2ABC] = [('W', u8(1) + u8(0x01) + b'\x0a\x0b'), ('W', u8(1) + u8(0x01)),
             ('I', u8(1) + u8(0) + b'\x01\x02'), ('I', u8(1) + u8(0))]
V[0x2ABD] = [u32(0x000003ff) + u32(0x0000000f)]
V[0x2ABE] = [b'object.bin']
V[0x2ABF] = [u16(0x2aca), uuid128('6e400001-b5a3-f393-e0a9-e50e24dcca9e')]
V[0x2AC0] = [u32(1000) + u32(4096)]
V[0x2AC1] = [ts(2023, 1, 2, 3, 4, 5)]
V[0x2AC2] = [ts(2024, 6, 7, 8, 9, 10)]
V[0x2AC3] = [u48(0x000000000100)]
V[0x2AC4] = [u32(0x000000ff)]
V[0x2AC5] = [('W', u8(1) + u32(1024) + u16(0x2aca)), ('W', u8(2)), ('W', u8(3) + u32(0) + u32(100)),
             ('W', u8(4) + b'\x01\x02\x03'), ('W', u8(4)), ('W', u8(5) + u32(0) + u32(64)),
             ('W', u8(6) + u32(0) + u32(64)), ('W', u8(7)), ('W', u8(99)),
             ('I', u8(0x60) + u8(1) + u8(1) + u8(1)),
             ('I', u8(0x60) + u8(3) + u8(1) + bytes([3, 0x11, 0x22, 0x33])),
             ('I', u8(0x60) + u8(4) + u8(1) + bytes([4, 0x99])),
             ('I', u8(0x60) + u8(4) + u8(1) + bytes([4])),
             ('I', u8(0x60) + u8(9) + u8(1) + bytes([9]))]
V[0x2AC6] = [('W', u8(1)), ('W', u8(5) + u48(0x100)), ('W', u8(6) + u8(1)), ('W', u8(99)),
             ('I', u8(0x70) + u8(1) + u8(1)), ('I', u8(0x70) + u8(7) + u8(1) + u32(12)),
             ('I', u8(0x70) + u8(9) + u8(1))]
V[0x2AC7] = [u8(0), u8(1) + b'img', u8(5) + u16(0x2aca), u8(6) + ts(2023) + ts(2024), u8(8) + u32(10) + u32(100),
             u8(0x0b)]
V[0x2AC8] = [u8(0x1e) + u48(0x101)]
V[0x2AC9] = [u8(1)]
V[0x2ACC] = [u32(0x0001ffff) + u32(0x0001ffff)]
V[0x2ACD] = [u16(0x0000) + u16(1000)]
V[0x2ACE] = [u24(0) + u16(500)]
V[0x2ACF] = [u16(0) + u16(10)]
V[0x2AD0] = [u16(0) + u16(11)]
V[0x2AD1] = [u16(0) + u8(20) + u16(5)]
V[0x2AD2] = [u16(0) + u16(2500)]
V[0x2AD3] = [u8(0x02) + u8(1) + b'Warming up', ('R', u8(0x00) + u8(2))]
V[0x2AD4] = [u16(100) + u16(2000) + u16(10)]
V[0x2AD5] = [s16(-50) + s16(150) + u16(5)]
V[0x2AD6] = [s16(10) + s16(200) + u16(10)]
V[0x2AD7] = [bytes([60, 200, 1])]
V[0x2AD8] = [s16(25) + s16(1000) + u16(5)]
V[0x2AD9] = [('W', u8(0)), ('I', u8(0x80) + u8(0) + u8(1))]
V[0x2ADA] = [u8(s) + p for s, p in ((0x01, b''), (0x02, u8(1)), (0x05, u16(1000)), (0x06, s16(20)),
                                    (0x07, u8(5)), (0x08, s16(200)), (0x09, u8(140)), (0x0A, u16(300)),
                                    (0x0B, u16(1000)), (0x0C, u16(800)), (0x0D, u24(5000)), (0x0E, u16(1800)),
                                    (0x0F, u16(600) + u16(900)), (0x10, u16(1) + u16(2) + u16(3)),
                                    (0x11, u16(1) + u16(2) + u16(3) + u16(4) + u16(5)),
                                    (0x12, s16(100) + s16(50) + u8(30) + u8(40)), (0x13, u16(2100)),
                                    (0x14, u8(1)), (0x15, u16(180)), (0xFF, b''))]
V[0x2B7D] = [u8(100) + u8(0) + u8(3)]
V[0x2B7E] = [u8(0) + u8(1), u8(4) + u8(2) + u8(50), u8(7)]
V[0x2B7F] = [u8(1)]
V[0x2AE0] = [u8(0x10) + u16(0x1234)]
V[0x2B1F] = [u8(0x01)]

# Bluetooth Mesh Provisioning / Proxy PDUs (SAR 0, message type in the
# low six bits): Provisioning Invite and Capabilities, a Mesh Beacon.
V[0x2ADB] = [('c', bytes([0x03, 0x00, 0x05]))]
V[0x2ADC] = [bytes([0x03, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])]
V[0x2ADD] = [('c', bytes([0x01, 0x00]) + bytes(range(16)) + u16(0x0000) + u32(0))]
V[0x2ADE] = [bytes([0x01, 0x00]) + bytes(range(16)) + u16(0x0000) + u32(0)]

# Descriptors: (descriptor UUID, list of (opcode, value)) per characteristic
DESCS = {
    0x2A00: [(0x2900, [('R', u16(0x0003))]),
             (0x2901, [('R', b'Name of the device'), ('W', b'Renamed')])],
    0x2A6E: [(0x2906, [('R', s16(-4000) + s16(8500))]),
             (0x290B, [('R', u8(1))]),
             (0x290C, [('R', u16(0) + u8(1) + u24(60) + u24(10) + u8(0x02) + u8(10))]),
             (0x290D, [('R', u8(3) + s16(2500))]),
             (0x290A, [('R', u8(0)), ('W', u8(1) + u16(100)), ('W', u8(4) + u8(0x1b)),
                       ('W', u8(5) + u16(10) + u16(20)), ('W', u8(7))]),
             (0x290E, [('R', u8(0) + u8(0)), ('W', u8(1) + u24(60)), ('W', u8(3) + u16(5)), ('W', u8(4))]),
             (0x2903, [('R', u16(0x0001)), ('W', u16(0x0000))]),
             (0x2904, [('R', u8(0x0e) + s8(-2) + u16(0x272f) + u8(1) + u16(0x0106)),
                       ('R', u8(0x06) + s8(0) + u16(0x2700) + u8(2) + u16(0x0001))]),
             (0x2905, [('R', u16(0x0001) + u16(0x0002))])],
    0x2A4B: [(0x2907, [('R', u16(0x2a19))]),
             (0x2907, [('R', uuid128('00002a19-0000-1000-8000-00805f9b34fb'))])],
    0x2A4D: [(0x2908, [('R', u8(1) + u8(1))])],
    0x2A56: [(0x2909, [('R', u8(2))])],
}

# Custom 128-bit services handled by registered "bluetooth.uuid" dissectors
NUS = '6e400001-b5a3-f393-e0a9-e50e24dcca9e'
DFU = '00001530-1212-efde-1523-785feabcd123'
MB = 'e95d%s-251d-470a-a062-fa1922dfa9a8'
CUSTOM = [
    (NUS, [('6e400002-b5a3-f393-e0a9-e50e24dcca9e', 'W', [b'AT+HELLO\r\n']),
           ('6e400003-b5a3-f393-e0a9-e50e24dcca9e', 'N', [b'OK\r\n'])]),
    (DFU, [('00001531-1212-efde-1523-785feabcd123', 'W',
            [u8(1) + u8(4), u8(2) + u8(0), u8(2), u8(3), u8(8) + u16(10), u8(0x10) + u8(7) + u8(1) + u32(4096),
             u8(0x10) + u8(1) + u8(1), u8(0x11) + u32(2048), u8(0x20)]),
           ('00001532-1212-efde-1523-785feabcd123', 'C', [bytes(range(16))])]),
    (MB % '0753', [(MB % 'ca4b', 'N', [s16(120) + s16(-340) + s16(1010)]), (MB % 'fb24', 'R', [u16(20)])]),
    (MB % 'f2d8', [(MB % 'fb11', 'N', [s16(10) + s16(20) + s16(-30)]), (MB % '386c', 'R', [u16(40)]),
                   (MB % '9715', 'N', [u16(270)])]),
    (MB % '9882', [(MB % 'da90', 'N', [u8(1)]), (MB % 'da91', 'N', [u8(2)])]),
    (MB % '127b', [(MB % '8d00', 'N', [bytes([0, 10, 1, 20])]), (MB % '5899', 'W', [u24(0x000005)]),
                   (MB % 'b9fe', 'W', [u24(0x000003)]), (MB % 'd822', 'W', [bytes([0, 1, 0, 2]) + u32(20000)])]),
    (MB % 'd91d', [(MB % '7b77', 'R', [bytes([0x1f, 0x11, 0x11, 0x11, 0x1f])]), (MB % '93ee', 'W', [b'Hi']),
                   (MB % '0d2d', 'R', [u16(120)])]),
    (MB % '93af', [(MB % 'b84c', 'R', [u32(0x00010002)]), (MB % '9775', 'N', [u32(0x00030004)]),
                   (MB % '23c4', 'W', [u32(0x00050006)]), (MB % '5404', 'W', [u32(0x00070008)])]),
    (MB % '93b0', [(MB % '93b1', 'W', [u8(1)])]),
    (MB % '6100', [(MB % '9250', 'N', [s8(21)]), (MB % '1b25', 'R', [u16(1000)])]),
]

SERVICE_ORDER = [0x1800, 0x1801, 0x1802, 0x1803, 0x1804, 0x1805, 0x1806, 0x1807, 0x1808, 0x1809,
                 0x180A, 0x180D, 0x180E, 0x180F, 0x1810, 0x1811, 0x1812, 0x1813, 0x1814, 0x1815,
                 0x1816, 0x1818, 0x1819, 0x181A, 0x181B, 0x181C, 0x181D, 0x181E, 0x181F, 0x1821,
                 0x1822, 0x1823, 0x1824, 0x1825, 0x1826, 0x18FF, 0xFFF6]

# Matter BTP service (0xFFF6, "btatt.service" table): Handshake Request
# written to C1 and Handshake Response indicated on C2
MATTER = [('18ee2ef5-263d-4559-959f-4f9c429f9d11', 'W', [bytes([0x65, 0x6c, 0x04, 0x00, 0x00, 0x00]) + u16(244) + u8(6)]),
          ('18ee2ef5-263d-4559-959f-4f9c429f9d12', 'I', [bytes([0x65, 0x6c, 0x04]) + u16(244) + u8(6)])]


# Extra (service, characteristic, opcodes) placements beyond CHARS
EXTRA = [(0x181F, 0x2A52, 'WI'), (0x1822, 0x2A52, 'WI'), (0x1803, 0x2A06, 'RW'), (0x1816, 0x2A55, 'WI'), (0x1816, 0x2A5D, 'R'), (0x1818, 0x2A5D, 'R')]

# Service-specific Application Error codes (0x80) of these services
ERROR_SERVICES = [0x1815, 0x1811, 0x181E, 0x181F, 0x1818, 0x1816, 0x1805, 0x181A, 0x1808, 0x1823,
                  0x180D, 0x1809, 0x1821, 0x1825, 0x1814, 0x181C, 0x180F]


class Server:
    """Attribute database of the remote GATT server."""

    def __init__(self):
        self.services = []      # (start, end, uuid bytes)
        self.chars = []         # (svc uuid, decl handle, value handle, props, uuid bytes, ops, uuid16)
        self.descs = []         # (handle, uuid16, char uuid16, values)
        self.by_uuid = {}
        self.svc_of = {}
        h = 1
        done = set()
        placements = {}
        for u, (s, ops) in CHARS.items():
            placements.setdefault(s or 0x18FF, []).append((u, ops))
        for s, u, ops in EXTRA:
            placements.setdefault(s, []).append((u, ops))
        for s in SERVICE_ORDER:
            start = h
            h += 1
            if s == 0x18FF:
                self.include_handle = h
                h += 1
            if s == 0xFFF6:
                self.matter = []
                for cu, ops, vals in MATTER:
                    props = {'W': 0x08, 'I': 0x20}[ops]
                    self.matter.append((h, h + 1, props, uuid128(cu), ops, vals))
                    h += 2
                    if ops == 'I':
                        self.descs.append((h, 0x2902, None, [('W', u16(0x0002))]))
                        h += 1
            for u, ops in placements.get(s, []):
                props = 0
                props |= 0x02 if 'R' in ops else 0
                props |= 0x04 if 'C' in ops else 0
                props |= 0x08 if 'W' in ops else 0
                props |= 0x10 if 'N' in ops else 0
                props |= 0x20 if 'I' in ops else 0
                self.chars.append((s, h, h + 1, props, u16(u), ops, u))
                self.by_uuid.setdefault(u, h + 1)
                self.svc_of[h + 1] = s
                h += 2
                if 'N' in ops or 'I' in ops:
                    # Database Change Increment is listed as not notifiable
                    cccd = 0x0002 if ('I' in ops or u == 0x2A99) else 0x0001
                    self.descs.append((h, 0x2902, u, [('W', u16(cccd))]))
                    h += 1
                if u not in done:
                    done.add(u)
                    for du, vals in DESCS.get(u, []):
                        self.descs.append((h, du, u, vals))
                        h += 1
            self.services.append((start, h - 1, u16(s)))
        self.secondary = (h, h, u16(0x1900))
        h += 1
        self.custom = []
        for su, chars in CUSTOM:
            start = h
            h += 1
            cl = []
            for cu, ops, vals in chars:
                props = {'R': 0x02, 'W': 0x08, 'N': 0x10, 'C': 0x04}[ops]
                cl.append((h, h + 1, props, uuid128(cu), ops, vals))
                h += 2
                if ops == 'N':
                    self.descs.append((h, 0x2902, None, [('W', u16(0x0001))]))
                    h += 1
            self.custom.append((start, h - 1, uuid128(su), cl))
        self.last = h - 1


def discovery(c, srv):
    # Primary services, 16-bit UUIDs (one Read By Group Type Response)
    c.att(SENT, u8(0x10) + u16(0x0001) + u16(0xffff) + u16(0x2800))
    c.att(RECV, u8(0x11) + u8(6) + b''.join(u16(s) + u16(e) + uu for s, e, uu in srv.services))
    # Primary services, 128-bit UUIDs
    first = srv.custom[0][0]
    c.att(SENT, u8(0x10) + u16(first) + u16(0xffff) + u16(0x2800))
    c.att(RECV, u8(0x11) + u8(20) + b''.join(u16(s) + u16(e) + uu for s, e, uu, _ in srv.custom))
    c.att(SENT, u8(0x10) + u16(srv.last + 1) + u16(0xffff) + u16(0x2800))
    c.att(RECV, u8(0x01) + u8(0x10) + u16(srv.last + 1) + u8(0x0a))
    # Secondary service and the include declaration that refers to it
    s, e, uu = srv.secondary
    c.att(SENT, u8(0x10) + u16(0x0001) + u16(0xffff) + u16(0x2801))
    c.att(RECV, u8(0x11) + u8(6) + u16(s) + u16(e) + uu)
    fs, fe, _ = srv.services[-2]
    c.att(SENT, u8(0x08) + u16(fs) + u16(fe) + u16(0x2802))
    c.att(RECV, u8(0x09) + u8(8) + u16(srv.include_handle) + u16(s) + u16(e) + uu)
    # Characteristic declarations of each service
    for s, e, uu in srv.services:
        chars = [ch for ch in srv.chars if s < ch[1] <= e]
        if not chars:
            continue
        c.att(SENT, u8(0x08) + u16(s) + u16(e) + u16(0x2803))
        c.att(RECV, u8(0x09) + u8(7) + b''.join(u16(d) + u8(p) + u16(v) + cu for _, d, v, p, cu, _, _ in chars))
    for s, e, uu, cl in [srv.services[-1] + (srv.matter,)] + srv.custom:
        c.att(SENT, u8(0x08) + u16(s) + u16(e) + u16(0x2803))
        c.att(RECV, u8(0x09) + u8(21) + b''.join(u16(d) + u8(p) + u16(v) + cu for d, v, p, cu, _, _ in cl))
    # Descriptors (Find Information, 16-bit format)
    descs = srv.descs
    for i in range(0, len(descs), 20):
        chunk = descs[i:i + 20]
        c.att(SENT, u8(0x04) + u16(chunk[0][0]) + u16(chunk[-1][0]))
        c.att(RECV, u8(0x05) + u8(1) + b''.join(u16(h) + u16(du) for h, du, _, _ in chunk))


def values(c, srv):
    for s, d, v, props, cu, ops, u in srv.chars:
        items = V.get(u, [b'\x00'])
        used = set()
        first_op = [o for o in 'RNWIC' if o in ops][0]
        for it in items:
            op, val = it if isinstance(it, tuple) else (first_op, it)
            c.op(op, v, val)
            used.add(op)
        first_val = items[0][1] if isinstance(items[0], tuple) else items[0]
        for op in 'RNWIC':
            if op in ops and op not in used:
                c.op(op, v, first_val)
    for h, du, cu, vals in srv.descs:
        for op, val in vals:
            c.op(op, h, val)
    for s, e, uu, cl in [srv.services[-1] + (srv.matter,)] + srv.custom:
        for d, v, p, cu, ops, vals in cl:
            for val in vals:
                c.op(ops, v, val)
            if ops in 'NWC':
                c.read(v, vals[0])


def extras(c, srv):
    """Other ATT opcodes and transaction types on the main connection."""
    h = srv.by_uuid
    first_in = {}
    for svc, d, v, props, cu, ops, u in srv.chars:
        first_in.setdefault(svc, v)
    # Service-specific Application Errors (0x80) and common error codes
    for svc in ERROR_SERVICES:
        c.att(SENT, u8(0x0a) + u16(first_in[svc]))
        c.att(RECV, u8(0x01) + u8(0x0a) + u16(first_in[svc]) + u8(0x80))
    c.att(SENT, u8(0x0a) + u16(first_in[0x18FF]))
    c.att(RECV, u8(0x01) + u8(0x0a) + u16(first_in[0x18FF]) + u8(0x81))
    c.att(SENT, u8(0x0a) + u16(h[0x2A00]))
    c.att(RECV, u8(0x01) + u8(0x0a) + u16(h[0x2A00]) + u8(0x02))
    c.att(SENT, u8(0x08) + u16(0x0001) + u16(0xffff) + u16(0x2a9a))
    c.att(RECV, u8(0x01) + u8(0x08) + u16(0x0001) + u8(0x0a))
    # Find Information Response in 128-bit format
    s0, e0, uu0, cl0 = srv.custom[0]
    c.att(SENT, u8(0x04) + u16(cl0[0][1]) + u16(cl0[1][1]))
    c.att(RECV, u8(0x05) + u8(2) + b''.join(u16(v) + cu for d, v, p, cu, o, vals in cl0[:2] if True)[:36])
    bs = [x for x in srv.services if x[2] == u16(0x180F)][0]
    # Read By Type with a 128-bit UUID (Nordic UART Rx)
    rx = cl0[1]
    c.att(SENT, u8(0x08) + u16(s0) + u16(e0) + rx[3])
    c.att(RECV, u8(0x09) + u8(2 + 4) + u16(rx[1]) + b'OK\r\n')
    # Read By Type of a characteristic value: two entries of Battery Level
    c.att(SENT, u8(0x08) + u16(bs[0]) + u16(bs[1]) + u16(0x2a19))
    c.att(RECV, u8(0x09) + u8(3) + u16(h[0x2A19]) + u8(55))
    # Read By Type and Read By Group Type Responses without a request
    c.read(h[0x2A19], u8(56))
    c.att(RECV, u8(0x09) + u8(3) + u16(h[0x2A19]) + u8(56))
    c.att(RECV, u8(0x11) + u8(6) + u16(bs[0]) + u16(bs[1]) + u16(0x180F))
    # Read Response and Read Blob Response without a request
    c.write_req(h[0x2A39], u8(1))
    c.att(RECV, u8(0x0b) + b'orphan')
    c.att(RECV, u8(0x0d) + b'orphan blob')
    # Read Blob at offset 0 of a short attribute
    c.att(SENT, u8(0x0c) + u16(h[0x2A19]) + u16(0))
    c.att(RECV, u8(0x0d) + u8(77))
    # Read Multiple and Read Multiple Variable
    c.att(SENT, u8(0x0e) + u16(h[0x2A19]) + u16(h[0x2A6E]) + u16(h[0x2A38]))
    c.att(RECV, u8(0x0f) + u8(80) + s16(2210) + u8(2))
    c.att(SENT, u8(0x20) + u16(h[0x2A12]) + u16(h[0x2A00]) + u16(h[0x2A1F]))
    c.att(RECV, u8(0x21) + u16(1) + u8(81) + u16(7) + b'Gadget1' + u16(2) + s16(222))
    # Read Multiple Variable Response cut short (remaining < 2, < length)
    c.att(SENT, u8(0x20) + u16(h[0x2A12]) + u16(h[0x2A00]))
    c.att(RECV, u8(0x21) + u16(1) + u8(82) + u16(9) + b'Gadget')
    c.att(SENT, u8(0x20) + u16(h[0x2A12]) + u16(h[0x2A00]))
    c.att(RECV, u8(0x21) + u16(1) + u8(83) + u8(0))
    # Read Multiple Response without a request
    c.att(RECV, u8(0x0f) + b'stray')
    # Prepare Write / Execute Write of the Characteristic User Description
    ud = [d for d in srv.descs if d[1] == 0x2901][0][0]
    c.att(SENT, u8(0x16) + u16(ud) + u16(0) + b'Long user ')
    c.att(RECV, u8(0x17) + u16(ud) + u16(0) + b'Long user ')
    c.att(SENT, u8(0x16) + u16(ud) + u16(10) + b'description')
    c.att(RECV, u8(0x17) + u16(ud) + u16(10) + b'description')
    c.att(SENT, u8(0x18) + u8(0x01))
    c.att(RECV, u8(0x19))
    c.att(SENT, u8(0x18) + u8(0x00))
    c.att(RECV, u8(0x19))
    # Signed Write Command (short, and the >255 octet reproducer of
    # btatt_signed_write_len.py on String 0x2A3D)
    c.att(SENT, u8(0xd2) + u16(h[0x2A3D]) + b'signed' + u32(0x11223344) + b'S' * 8)
    c.att(SENT, u8(0xd2) + u16(h[0x2A3D]) + b'V' * 288 + u32(0x11223344) + b'S' * 8)
    # Signed Write Command with only the signature
    c.att(SENT, u8(0xd2) + u16(h[0x2A3D]) + u32(1) + b'S' * 8)
    # Multiple Handle Value Notification (no decoder) and an unknown opcode
    c.att(RECV, u8(0x23) + u16(h[0x2A19]) + u16(1) + u8(84))
    c.att(RECV, u8(0x7e) + b'??')
    # Notification on a handle without a known UUID
    c.att(RECV, u8(0x1b) + u16(srv.last + 0x10) + b'unknown')


def eatt(c, srv):
    """Enhanced ATT bearer: LE Credit Based Connection on PSM 0x0027, then
    a read, a write and a notification as K-frames with an SDU length."""
    sig = u8(0x14) + u8(0x01) + u16(10) + u16(0x0027) + u16(0x0040) + u16(64) + u16(64) + u16(10)
    c.att(SENT, sig, cid=0x0005)
    sig = u8(0x15) + u8(0x01) + u16(10) + u16(0x0041) + u16(64) + u16(64) + u16(10) + u16(0)
    c.att(RECV, sig, cid=0x0005)

    def k(direction, pdu):
        c.att(direction, u16(len(pdu)) + pdu, cid=0x0041 if direction == SENT else 0x0040)
    h = srv.by_uuid
    k(SENT, u8(0x0a) + u16(h[0x2A19]))
    k(RECV, u8(0x0b) + u8(66))
    k(SENT, u8(0x12) + u16(h[0x2A39]) + u8(1))
    k(RECV, u8(0x13))
    k(RECV, u8(0x1b) + u16(h[0x2A37]) + u8(0x00) + u8(64))


def long_values(c):
    """Second connection, default LE ATT_MTU (23): long attribute values
    reassembled from a Read Response and Read Blob Responses."""
    c.le_connect(0x0041, b'\x22\x33\x44\x55\x66\x77')
    c.chandle = 0x0041
    c.att(SENT, u8(0x04) + u16(0x0001) + u16(0x0004))
    c.att(RECV, u8(0x05) + u8(1) + u16(0x0001) + u16(0x2800) + u16(0x0003) + u16(0x2a00)
          + u16(0x0004) + u16(0x2a19))
    name = b'A rather long device name for the blob'
    c.att(SENT, u8(0x0a) + u16(3))
    c.att(RECV, u8(0x0b) + name[:22])
    c.att(SENT, u8(0x0c) + u16(3) + u16(22))
    c.att(RECV, u8(0x0d) + name[22:])
    # Three part value: second Read Blob Response fills the MTU again
    name2 = b'Another very long name that needs three reads to arrive'
    c.att(SENT, u8(0x0a) + u16(3))
    c.att(RECV, u8(0x0b) + name2[:22])
    c.att(SENT, u8(0x0c) + u16(3) + u16(22))
    c.att(RECV, u8(0x0d) + name2[22:44])
    c.att(SENT, u8(0x0c) + u16(3) + u16(44))
    c.att(RECV, u8(0x0d) + name2[44:])
    c.chandle = 0x0040


def reproducers(c):
    """Third connection: reproducers of the fixes on the branch
    (btatt_*.py), on their own server so their handles do
    not mix with the main attribute database."""
    c.le_connect(0x0042, b'\x33\x44\x55\x66\x77\x88')
    c.chandle = 0x0042
    c.att(SENT, u8(0x02) + u16(517))
    c.att(RECV, u8(0x03) + u16(600))
    # btatt_fbtv_uuid_offset.py: Find By Type Value takes the type from its offset
    c.att(SENT, struct.pack('<BHHHH', 0x06, 0x0001, 0xffff, 0x2800, 0x180f))
    c.att(RECV, struct.pack('<BHH', 0x07, 0x0010, 0x0014))
    # btatt_sc_cp_offset.py: SC Control Point Supported Sensor Locations
    c.att(SENT, struct.pack('<BHHH', 0x08, 0x0020, 0xffff, 0x2a55))
    c.att(RECV, bytes([0x09, 0x08]) + struct.pack('<H', 0x0020) + bytes([0x10, 0x04, 0x01, 0x05, 0x06, 0x07]))
    # btatt_rbt_len1_norequest.py (short): attribute length shorter than the handle(s)
    c.att(RECV, bytes([0x09, 0x01]) + b'\x01' * 16)
    c.att(RECV, bytes([0x11, 0x03]) + b'\x01' * 16)
    c.chandle = 0x0040


def malformed(srv):
    """Paths reached only by invalid input: opcodes a characteristic must
    not be used with, values of the wrong length or range, truncated PDUs."""
    c = Capture()
    c.le_connect()
    c.att(SENT, u8(0x02) + u16(517))
    c.att(RECV, u8(0x03) + u16(517))
    discovery(c, srv)
    h = srv.by_uuid
    # Read Requests carrying a value: reaches the "request has no value"
    # checks of every decoder
    for svc, d, v, props, cu, ops, u in srv.chars:
        c.att(SENT, u8(0x0a) + u16(v) + b'\x00')
    for dh, du, cu, vals in srv.descs:
        c.att(SENT, u8(0x0a) + u16(dh) + b'\x00')
    for s0, e0, uu, cl in srv.custom + [srv.services[-1] + (srv.matter,)]:
        for d, v, p, cu, ops, vals in cl:
            c.att(SENT, u8(0x0a) + u16(v) + b'\x00')
        c.att(SENT, u8(0x0a) + u16(s0) + b'\x00')
        c.att(SENT, u8(0x0a) + u16(cl[0][0]) + b'\x00')
    c.att(SENT, u8(0x0a) + u16(srv.include_handle) + b'\x00')
    c.att(SENT, u8(0x0a) + u16(srv.last + 0x10) + b'\x00')
    # Each characteristic with a usage check, once with a wrong opcode
    for svc, d, v, props, cu, ops, u in srv.chars:
        if CHARS.get(u, (0,))[0] == 0 or u in (0x2A00, 0x2A01):
            continue
        items = V.get(u, [b'\x00'])
        val = items[0][1] if isinstance(items[0], tuple) else items[0]
        bad = [o for o in 'NRWIC' if o not in ops][0]
        c.op(bad, v, val)
    for dh, du, cu, vals in srv.descs:
        c.notify(dh, vals[0][1])
    c.notify(srv.services[0][0], u16(0x1800))
    c.notify(srv.include_handle, u16(1) + u16(2) + u16(0x180f))
    c.notify(srv.chars[0][1], u8(2) + u16(3) + u16(0x2a00))
    # Wrong value lengths
    c.read(srv.services[0][0], b'\x00\x18\x00')
    c.read(srv.chars[0][1], u8(2) + u16(3) + b'\x00\x2a\x00')
    hr = [x for x in srv.descs if x[1] == 0x2907][0][0]
    c.read(hr, b'\x19\x2a\x00')
    c.indicate(h[0x2A7D], u16(1) + b'\x0c\x29\x00')
    c.read(h[0x2ABF], b'\xca\x2a\x00')
    c.write_req(h[0x2AC7], u8(5) + b'\xca\x2a\x00')
    # Out of range values
    c.read(h[0x2A19], u8(150))
    c.read(h[0x2A1B], u8(150))
    c.read(h[0x2A1F], s16(-3000))
    c.read(h[0x2A20], s16(-5000))
    c.read(h[0x2A2A], BAD_2A2A)
    c.notify(h[0x2AA7], u8(15) + u8(0x00) + u16(100) + u16(20))
    c.write_req(h[0x2A9F], u8(1) + u16(12345))
    c.write_req(h[0x2A9F], u8(2) + u8(1) + u16(12345))
    for op in (3, 6, 9, 12, 15, 18, 21, 24):
        c.write_req(h[0x2AAC], u8(op) + b'\x00' * 11)
    c.indicate(h[0x2AAC], u8(28) + u8(1) + u8(1))
    c.indicate(h[0x2AC5], u8(0x60) + u8(1) + u8(1))
    c.write_req(srv.custom[1][3][0][1], u8(3) + b'extra')
    # Client Characteristic Configuration: notification and indication on
    # characteristics that do not allow them, reserved bits
    cccd = {cu: dh for dh, du, cu, vals in srv.descs if du == 0x2902}
    c.write_req(cccd[0x2A05], u16(0x0001))
    c.write_req(cccd[0x2A18], u16(0x0002))
    c.write_req(cccd[0x2A19], u16(0x0007))
    # Malformed ATT PDUs
    c.att(RECV, u8(0x05) + u8(3) + u16(1) + u16(0x2800))
    c.att(SENT, u8(0x08) + u16(1) + u16(0xffff) + b'\x00\x28\x00')
    c.att(SENT, u8(0x10) + u16(1) + u16(0xffff) + b'\x00\x28\x00')
    c.att(SENT, u8(0x0e) + u16(h[0x2A19]))
    c.att(SENT, u8(0x0a) + u16(h[0x2A19]))
    c.att(RECV, u8(0x09) + u8(0))
    c.att(RECV, u8(0x01) + u8(0x0a))
    c.att(RECV, u8(0x01))
    c.att(RECV, u8(0x0b))
    # Read By Type of Primary Service with a 3 octet value
    c.att(SENT, u8(0x08) + u16(1) + u16(0xffff) + u16(0x2800))
    c.att(RECV, u8(0x09) + u8(5) + u16(1) + b'\x00\x18\x00')
    # Truncated values
    for u in (0x2A18, 0x2A1C, 0x2A35, 0x2A37, 0x2A63, 0x2A9C, 0x2AA7, 0x2A2A, 0x2A52, 0x2A66):
        items = V[u]
        op, val = items[0] if isinstance(items[0], tuple) else ([o for o in 'RNWIC' if o in CHARS[u][1]][0], items[0])
        c.op(op, h[u], val[:2])
    # A second connection that keeps the default ATT_MTU (23): exceeded
    c.le_connect(0x0041, b'\x22\x33\x44\x55\x66\x77')
    c.chandle = 0x0041
    c.att(RECV, u8(0x1b) + u16(3) + b'x' * 40)
    # Long value read with a gap between the Read Response and Read Blob
    c.att(RECV, u8(0x05) + u8(1) + u16(0x0003) + u16(0x2a00))
    c.att(SENT, u8(0x0a) + u16(3))
    c.att(RECV, u8(0x0b) + b'n' * 22)
    c.att(SENT, u8(0x0c) + u16(3) + u16(30))
    c.att(RECV, u8(0x0d) + b'tail')
    c.chandle = 0x0040
    return c


def exported_pdu(path):
    """Exported PDU (DLT 252) frames naming the btatt and btgatt
    dissectors directly, so they run without L2CAP data: the reproducer
    of btatt_exported_pdu_null_data.py and Find By Type Value
    Requests whose value is decoded without a connection."""
    def tag(t, v):
        return struct.pack('>HH', t, len(v)) + v
    frames = []
    for name, data in ((b'btgatt.uuid0x2a00', b'hello'), (b'btgatt', b'hello'),
                       (b'btatt', u8(0x06) + u16(1) + u16(0xffff) + u16(0x2a03) + bytes.fromhex('665544332211')),
                       (b'btatt', u8(0x06) + u16(1) + u16(0xffff) + u16(0x2adb) + bytes([0x03, 0x00, 0x05])),
                       (b'btatt', u8(0x0a) + u16(3)),
                       (b'btatt', u8(0x0b) + b'value')):
        frames.append(tag(12, name) + struct.pack('>HH', 0, 0) + data)
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def main(outdir):
    srv = Server()
    c = Capture()
    c.le_connect()
    c.att(SENT, u8(0x02) + u16(517))
    c.att(RECV, u8(0x03) + u16(600))
    discovery(c, srv)
    values(c, srv)
    extras(c, srv)
    eatt(c, srv)
    long_values(c)
    reproducers(c)
    c.write(os.path.join(outdir, 'btatt-coverage.pcap'))
    print(len(c.frames), 'frames, last handle', hex(srv.last))
    m = malformed(srv)
    m.write(os.path.join(outdir, 'btatt-coverage-malformed.pcap'))
    print(len(m.frames), 'malformed frames')
    exported_pdu(os.path.join(outdir, 'btatt-coverage-exppdu.pcap'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
