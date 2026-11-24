#!/usr/bin/env python3
# Generates test/captures/isobus_vt_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ISOBUS Virtual Terminal
dissector (packet-isobus-vt.c, ISO 11783-6).

The VT dissector is called by the ISOBUS dissector for PDU formats 230
(VT to ECU) and 231 (ECU to VT), and ISOBUS is reached only through the
"can.subdissector" Decode As table (-d can.subdissector,isobus). Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkisobus_vt.py <output directory>

Writes pcapng files with two interfaces:
  0  LINKTYPE_CAN_SOCKETCAN (227)       VT frames (CAN FD, up to 64 bytes)
  1  LINKTYPE_WIRESHARK_UPPER_PDU (252) an Exported PDU naming
                                        "isobus.vt.vt_to_ecu" (no ISOBUS
                                        information)

  isobus-vt-coverage.pcapng            every function code in both
                                       directions: realistic messages and
                                       responses, then a sweep that sets
                                       each of the error code bits in each
                                       of the first bytes of every message
  isobus-vt-coverage-malformed.pcapng  strings and lists longer than their
                                       frame, truncated messages
"""

import os
import struct
import sys

T0 = 1700000000
CAN_EFF_FLAG = 0x80000000


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    tot = 12 + len(body)
    return struct.pack('<II', 0x0A0D0D0A, tot) + body + struct.pack('<I', tot)


def idb(linktype):
    body = struct.pack('<HHI', linktype, 0, 0)
    tot = 12 + len(body)
    return struct.pack('<II', 1, tot) + body + struct.pack('<I', tot)


def epb(ifid, ts, data):
    t = int(ts * 1000000)
    body = (struct.pack('<IIIII', ifid, t >> 32, t & 0xffffffff, len(data), len(data))
            + pad4(data))
    tot = 12 + len(body)
    return struct.pack('<II', 6, tot) + body + struct.pack('<I', tot)


def write(path, frames):
    with open(path, 'wb') as f:
        f.write(shb() + idb(227) + idb(252))
        for i, (ifid, data) in enumerate(frames):
            f.write(epb(ifid, T0 + i * 0.001, data))


FD_SIZES = (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64)


def fd_pad(body):
    """CAN FD frames have a restricted set of lengths: pad with 0xff."""
    for n in FD_SIZES:
        if n >= len(body):
            return body + b'\xff' * (n - len(body))
    raise ValueError('too long')


def can_id(pf, dst=0x26, src=0x80):
    return CAN_EFF_FLAG | (6 << 26) | (pf << 16) | (dst << 8) | src


def to_vt(body, exact=False):
    """ECU to VT (PDU format 231), CAN FD."""
    b = body if exact else fd_pad(body)
    return (0, struct.pack('>IBBBB', can_id(231, 0x26, 0x80), len(b), 0x04, 0, 0) + b)


def to_ecu(body, exact=False):
    """VT to ECU (PDU format 230)."""
    b = body if exact else fd_pad(body)
    return (0, struct.pack('>IBBBB', can_id(230, 0x80, 0x26), len(b), 0x04, 0, 0) + b)


def u16(v):
    return struct.pack('<H', v)


def u32(v):
    return struct.pack('<I', v)


def label(s, n):
    return s.encode().ljust(n, b' ')[:n]


def ucs2(s, bom=True):
    return (b'\xff\xfe' if bom else b'') + s.encode('utf-16-le')


# Function codes that have a decoder
FCS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 17, 18, 32, 33, 34, 35, 36, 37, 38, 39, 146] \
    + list(range(160, 200)) + list(range(208, 215)) + [223, 224, 253, 254, 255]


# Function codes with error code bits in a response: the others are covered
# by the messages above
SWEEP_FCS = [4, 6, 7, 18, 35, 36, 37, 146] + list(range(160, 179)) + list(range(180, 184)) + [185, 186, 188, 189, 190, 198] \
    + [208, 209, 210, 212, 213, 214]


def build_main():
    fr = []
    # The VT version is global state of the dissector: set it first (Working
    # Set Maintenance with version 5 and the initiating bit)
    fr.append(to_vt(bytes([255, 0x80, 5]) + b'\xff' * 5))

    # --- VT to ECU -------------------------------------------------------
    fr.append(to_ecu(bytes([254, 0x80]) + u16(0x1000) + u16(0x2000) + bytes([0xff, 0x00]) + b'\x00'))   # VT status
    fr.append(to_ecu(bytes([254, 0x26]) + u16(0xffff) + u16(0x2001) + bytes([0xff, 0xff]) + b'\x00'))   # all busy codes
    fr.append(to_ecu(bytes([254, 0x26]) + u16(0x1000) + u16(0x2001) + bytes([0xff, 0x7b]) + b'\x00'))
    for act in range(6):
        fr.append(to_ecu(bytes([0, act]) + u16(0x2002) + u16(0x1000) + bytes([3])))                       # soft key
        fr.append(to_ecu(bytes([1, act]) + u16(0x2003) + u16(0xffff) + bytes([4])))                       # button
    fr.append(to_ecu(bytes([2]) + u16(100) + u16(200) + bytes([1]) + b'\xff\xff'))                        # pointing event, touch state
    fr.append(to_ecu(bytes([3]) + u16(0x2004) + bytes([1, 1]) + b'\xff' * 3))                             # select input object
    fr.append(to_ecu(bytes([4]) + u16(0x2004) + bytes([0x11]) + b'\xff' * 4))                             # ESC with errors
    fr.append(to_ecu(bytes([5]) + u16(0x2005) + bytes([0xff]) + u32(1234)))                               # change numeric value
    fr.append(to_ecu(bytes([6]) + u16(0x1000) + bytes([0x3c]) + u16(0x2006) + u16(0x2007)))               # change active mask with errors
    fr.append(to_ecu(bytes([6]) + u16(0x1000) + bytes([0x00]) + u16(0xffff) + u16(0xffff)))
    fr.append(to_ecu(bytes([8]) + u16(0x2008) + bytes([5]) + b'Hello' + b'\xff' * 3))                     # change string value
    fr.append(to_ecu(bytes([8]) + u16(0x2008) + bytes([8]) + ucs2('Hi!', True)[:8]))                      # UCS-2 string with BOM
    fr.append(to_ecu(bytes([9]) + u16(0x2009) + bytes([1]) + u16(0x200a) + bytes([0]) + b'\xff' * 2))     # user layout hide/show
    fr.append(to_ecu(bytes([10, 1]) + b'\xff' * 6))                                                       # audio termination
    fr.append(to_ecu(bytes([10, 0]) + b'\xff' * 6))
    # pointing event with the older VT version: no touch state
    fr.append(to_vt(bytes([255, 0x80, 3]) + b'\xff' * 5))
    fr.append(to_ecu(bytes([2]) + u16(10) + u16(20) + b'\xff' * 3))
    fr.append(to_ecu(bytes([3]) + u16(0x2004) + bytes([0]) + b'\xff' * 4))
    fr.append(to_vt(bytes([255, 0x80, 0xff]) + b'\xff' * 5))
    fr.append(to_vt(bytes([255, 0x00, 4]) + b'\xff' * 5))
    fr.append(to_vt(bytes([255, 0x80, 4]) + b'\xff' * 5))
    fr.append(to_vt(bytes([255, 0x80, 5]) + b'\xff' * 5))
    fr += hand_made()
    return fr


def hand_made():
    """Messages with lists, strings and sub-commands, which the sweep does
    not build, in both directions."""
    fr = []
    name = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    # Preferred assignment: two input units with two and one functions
    unit1 = name + u16(0x0102) + bytes([2]) + u16(0x3000) + u16(0x3001) + u16(0x3002) + u16(0x3003)
    unit2 = name[::-1] + u16(0x0103) + bytes([1]) + u16(0x3004) + u16(0x3005)
    fr.append(to_vt(bytes([34, 2]) + unit1 + unit2))
    fr.append(to_vt(bytes([34, 0])))
    for e in (0x02, 0x08, 0x10, 0x1f):
        fr.append(to_ecu(bytes([34, e]) + u16(0x3000)))
    fr.append(to_ecu(bytes([34, 0]) + u16(0xffff)))                         # accepted
    fr.append(to_ecu(bytes([34, 0x05]) + u16(0x3000)))                      # errors
    # Auxiliary capabilities: request and response with two units
    fr.append(to_vt(bytes([39, 0])))
    fr.append(to_vt(bytes([39, 1])))
    aux1 = name + bytes([2]) + bytes([1, 2, 0]) + bytes([3, 4, 1])
    aux2 = name[::-1] + bytes([1]) + bytes([5, 6, 2])
    fr.append(to_ecu(bytes([39, 2]) + aux1 + aux2))
    fr.append(to_ecu(bytes([39, 0])))
    # Auxiliary assignment type 1 and 2, input status and maintenance
    fr.append(to_vt(bytes([32, 0x26, 3]) + u16(0x3006)))
    fr.append(to_ecu(bytes([32, 0x26, 3]) + u16(0x3006)))
    for b in (0, 1, 2, 0xff, 7):
        fr.append(to_vt(bytes([33, 3]) + u16(1000) + u16(5) + bytes([b])))
    fr.append(to_vt(bytes([35]) + u16(0x0102) + bytes([0])))
    fr.append(to_vt(bytes([35]) + u16(0x0102) + bytes([1])))
    fr.append(to_ecu(bytes([35]) + u16(0x0102) + bytes([1])))
    fr.append(to_vt(bytes([36]) + name + bytes([0x80]) + u16(0x3007) + u16(0x3008)))
    fr.append(to_vt(bytes([36]) + name + bytes([0x05]) + u16(0x3007) + u16(0x3008)))
    fr.append(to_ecu(bytes([36]) + name + bytes([0x00]) + u16(0x3007) + u16(0x3008) + bytes([0])))
    fr.append(to_ecu(bytes([36]) + name + bytes([0x00]) + u16(0x3007) + u16(0x3008) + bytes([3])))
    for en in (0, 1, 2):
        fr.append(to_vt(bytes([37]) + u16(0x3009) + bytes([en, 0])))
    for st in (0, 1, 2):
        fr.append(to_ecu(bytes([37]) + u16(0x3009) + bytes([st, 0])))
    fr.append(to_ecu(bytes([37]) + u16(0x3009) + bytes([1, 3])))
    fr.append(to_vt(bytes([38]) + u16(0x300a) + u16(100) + u16(200) + bytes([0x03])))
    fr.append(to_vt(bytes([38]) + u16(0x300a) + u16(100) + u16(200) + bytes([0x00])))
    # Commands with an action or a command byte
    for fc in (160, 161):
        for act in (0, 1, 2):
            fr.append(to_vt(bytes([fc]) + u16(0x300b) + bytes([act])))
            fr.append(to_ecu(bytes([fc]) + u16(0x300b) + bytes([act, 0])))
    for opt in (0xff, 0, 5):
        fr.append(to_vt(bytes([162]) + u16(0x300c) + bytes([opt])))
    for resp in (0, 1, 2, 3):
        fr.append(to_ecu(bytes([162]) + u16(0x300c) + bytes([resp, 0])))
    fr.append(to_vt(bytes([163, 3]) + u16(500) + u16(100) + u16(50)))      # control audio signal
    fr.append(to_ecu(bytes([163, 0])))
    fr.append(to_vt(bytes([164, 70])))
    fr.append(to_ecu(bytes([164, 0])))
    fr.append(to_vt(bytes([165]) + u16(0x1000) + u16(0x300d) + bytes([5, 6])))
    fr.append(to_vt(bytes([166]) + u16(0x300d) + u16(100) + u16(50)))
    fr.append(to_vt(bytes([167]) + u16(0x300d) + bytes([7])))
    fr.append(to_vt(bytes([168]) + u16(0x300d) + bytes([0xff]) + u32(99)))
    fr.append(to_vt(bytes([169]) + u16(0x300d) + u16(10) + u16(20) + bytes([1])))
    fr.append(to_vt(bytes([170]) + u16(0x300d) + bytes([1, 2, 0, 0x0f])))
    fr.append(to_vt(bytes([171]) + u16(0x300d) + bytes([1, 2]) + u16(0xaaaa)))
    fr.append(to_vt(bytes([172]) + u16(0x300d) + bytes([2, 3]) + u16(0x300e)))
    fr.append(to_vt(bytes([173]) + u16(0x1000) + u16(0x1001)))
    fr.append(to_vt(bytes([174, 2]) + u16(0x1000) + u16(0x2001)))
    fr.append(to_vt(bytes([175]) + u16(0x300d) + bytes([3]) + u32(0x01020304)))
    fr.append(to_vt(bytes([176]) + u16(0x300d) + bytes([2])))
    fr.append(to_vt(bytes([177]) + u16(0x300d) + bytes([4]) + u16(0x300f)))
    fr.append(to_vt(bytes([178])))
    fr.append(to_ecu(bytes([178, 0])))
    fr.append(to_vt(bytes([180]) + u16(0x1000) + u16(0x300d) + u16(100) + u16(200)))
    fr.append(to_vt(bytes([181]) + u16(0x300d) + u16(0x3010) + bytes([1]) + u16(0x3011)))
    fr.append(to_vt(bytes([182]) + u16(0x300d) + bytes([2]) + u16(10) + u16(20)))
    fr.append(to_vt(bytes([183]) + u16(0x300d) + u16(300) + u16(400)))
    # Strings: change string value (ASCII, UCS-2 with and without BOM)
    fr.append(to_vt(bytes([179]) + u16(0x3012) + u16(5) + b'Hello'))
    fr.append(to_vt(bytes([179]) + u16(0x3012) + u16(10) + ucs2('Hi!!')))
    fr.append(to_ecu(bytes([179, 0xff, 0xff]) + u16(0x3012) + bytes([0])))
    for e in (2, 4, 8, 0x10, 0x1e):
        fr.append(to_ecu(bytes([179, 0xff, 0xff]) + u16(0x3012) + bytes([e])))
    fr.append(to_vt(bytes([5]) + u16(0x2005) + bytes([0xff]) + u32(4321)))
    fr.append(to_vt(bytes([8, 0xff, 0xff]) + u16(0x3012)))
    # Graphics context: every sub-command
    gc = lambda sub, args: to_vt(bytes([184]) + u16(0x3013) + bytes([sub]) + args)
    fr.append(gc(0, struct.pack('<hh', 10, -20)))
    fr.append(gc(1, struct.pack('<hh', -5, 6)))
    fr.append(gc(2, bytes([3])))
    fr.append(gc(3, bytes([4])))
    fr.append(gc(4, u16(0x3014)))
    fr.append(gc(5, u16(0x3015)))
    fr.append(gc(6, u16(0x3016)))
    fr.append(gc(7, u16(30) + u16(40)))
    fr.append(gc(8, struct.pack('<hh', 1, 2)))
    fr.append(gc(9, struct.pack('<hh', 3, 4)))
    fr.append(gc(10, u16(30) + u16(40)))
    fr.append(gc(11, u16(30) + u16(40)))
    fr.append(gc(12, bytes([3]) + struct.pack('<hhhhhh', 1, 2, 3, 4, 5, 6)))
    fr.append(gc(13, bytes([0, 5]) + b'Hello'))
    fr.append(gc(13, bytes([1, 10]) + ucs2('Text')))
    fr.append(gc(14, struct.pack('<hh', 7, 8)))
    fr.append(gc(15, struct.pack('<f', 1.5)))
    fr.append(gc(17, u16(300) + u16(200)))
    fr.append(gc(18, u16(0x3017)))
    fr.append(gc(19, u16(0x3018)))
    fr.append(gc(20, u16(0x3019)))
    fr.append(gc(21, b'\x00\x00'))
    fr.append(to_ecu(bytes([184]) + u16(0x3013) + bytes([7, 0, 0, 0, 0])))
    # Get attribute value
    fr.append(to_vt(bytes([185]) + u16(0x3013) + bytes([4])))
    fr.append(to_ecu(bytes([185]) + u16(0x3013) + bytes([4]) + u32(77)))
    fr.append(to_ecu(bytes([185, 0xff, 0xff, 4]) + u16(0x3013) + bytes([0x13])))
    fr.append(to_vt(bytes([186]) + u16(0x301a)))
    fr.append(to_vt(bytes([187])))
    fr.append(to_ecu(bytes([187, 1, 0, 0, 0, 0, 0, 0])))
    fr.append(to_vt(bytes([188]) + u16(0x301b)))
    fr.append(to_vt(bytes([189, 1]) + u16(0x1000) + u16(5000)))              # lock mask with timeout
    fr.append(to_vt(bytes([189, 0]) + u16(0x1000)))                          # unlock
    for cmd in (0, 1, 2):
        for e in (0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0xff):
            fr.append(to_ecu(bytes([189, cmd, e]) + b'\xff' * 4))
    fr.append(to_vt(bytes([190, 7])))
    # Get memory, widechars, soft keys, fonts, window mask, objects, hardware
    fr.append(to_vt(bytes([192, 0xff]) + u32(100000)))
    fr.append(to_ecu(bytes([192, 5, 0])))
    fr.append(to_ecu(bytes([192, 5, 1])))
    fr.append(to_vt(bytes([193, 0]) + u16(0x20) + u16(0x7e)))
    fr.append(to_ecu(bytes([193, 0]) + u16(0x20) + u16(0x7e) + bytes([0, 0])))
    fr.append(to_ecu(bytes([193, 0]) + u16(0x20) + u16(0x7e) + bytes([0, 1]) + u16(0x20) + u16(0x7e)))
    fr.append(to_ecu(bytes([193, 1]) + u16(0x20) + u16(0x7e) + bytes([0, 3]) + u16(0x20) + u16(0x40) + u16(0x50) + u16(0x60) + u16(0x70) + u16(0x7e)))
    fr.append(to_ecu(bytes([193, 1]) + u16(0x20) + u16(0x7e) + bytes([0x13, 0])))
    fr.append(to_vt(bytes([194])))
    fr.append(to_ecu(bytes([194, 2, 0xff, 0xff, 60, 40, 6, 8])))
    fr.append(to_vt(bytes([195])))
    fr.append(to_ecu(bytes([195, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x7f, 0xff, 0xff])))
    fr.append(to_ecu(bytes([195, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00])))
    fr.append(to_vt(bytes([196])))
    fr.append(to_ecu(bytes([196, 1, 2, 0xff, 0xff, 0xff, 0xff, 0xff])))
    fr.append(to_vt(bytes([197])))
    fr.append(to_ecu(bytes([197, 5, 0, 1, 2, 3, 4])))
    fr.append(to_ecu(bytes([197, 5, 0, 1, 0xff, 3, 4])))
    fr.append(to_ecu(bytes([197, 0])))
    fr.append(to_vt(bytes([198, 0, 0])))
    # The error code field of the screen capture response has the mask 0x80
    # (see README): only that bit is decoded
    fr.append(to_ecu(bytes([198, 0, 1, 0x80]) + u16(0)))
    fr.append(to_ecu(bytes([198, 0, 0, 0]) + u16(0x1234)))
    fr.append(to_vt(bytes([199])))
    fr.append(to_ecu(bytes([199, 10, 2, 0xff]) + u16(480) + u16(480)))
    fr.append(to_ecu(bytes([199, 10, 0, 0x00]) + u16(240) + u16(240)))
    # Versions: 7 byte labels and 32 byte extended labels
    for fc in (208, 209, 210):
        fr.append(to_vt(bytes([fc]) + label('V1', 7)))
        for e in (0, 1, 2, 4, 8, 0x10):
            fr.append(to_ecu(bytes([fc, 0xff, 0xff, 0xff, 0xff, e])))
    for fc in (212, 213, 214):
        fr.append(to_vt(bytes([fc]) + label('Extended V1', 32)))
        for e in (0, 1, 2, 4, 8, 0x10):
            fr.append(to_ecu(bytes([fc, 0xff, 0xff, 0xff, 0xff, e])))
    fr.append(to_vt(bytes([211])))
    fr.append(to_ecu(bytes([211, 1]) + label('Label one', 32)))
    fr.append(to_ecu(bytes([211, 0])))
    fr.append(to_vt(bytes([223])))
    fr.append(to_ecu(bytes([224, 2]) + label('V1', 7) + label('V2', 7)))
    fr.append(to_ecu(bytes([224, 0])))
    fr.append(to_vt(bytes([253, 0x33])))
    fr.append(to_ecu(bytes([253, 0x33])))
    # End of object pool and object pool transfer
    fr.append(to_vt(bytes([18])))
    fr.append(to_ecu(bytes([18, 0]) + u16(0xffff) + u16(0xffff) + bytes([0])))
    fr.append(to_ecu(bytes([18, 1]) + u16(0x1000) + u16(0x1001) + bytes([0x0f])))
    fr.append(to_ecu(bytes([18, 2]) + u16(0xffff) + u16(0xffff) + bytes([0])))
    fr.append(to_vt(bytes([17]) + bytes(range(7))))
    # Screen capture, ESC command, aux assignment errors
    fr.append(to_vt(bytes([146])))
    fr.append(to_ecu(bytes([146]) + u16(0x3020) + bytes([0x11])))
    fr.append(to_ecu(bytes([146]) + u16(0x3020) + bytes([0x00])))
    # Unknown function codes (no decoder)
    for fc in (11, 12, 100, 128, 145, 191, 200, 215, 222, 225, 250):
        fr.append(to_vt(bytes([fc]) + bytes(range(7))))
        fr.append(to_ecu(bytes([fc]) + bytes(range(7))))
    return fr


def sweep():
    """For every function code and both directions, the first eight bytes
    of the message with one of the error code bits (0x01, 0x02, 0x04, 0x08,
    0x10, 0x20) set at each position and the other bytes zero."""
    fr = []
    for fc in SWEEP_FCS:
        # the label of the versions commands is a string: no sweep of the
        # ECU to VT direction (its bytes would follow a NUL)
        for direction in ((to_ecu,) if fc in (208, 209, 210, 212, 213, 214) else (to_vt, to_ecu)):
            for pos in range(1, 9):
                for v in (1, 2, 4, 8, 0x10, 0x20):
                    body = bytearray(48 if fc >= 208 else 16)
                    body[0] = fc
                    body[pos] = v
                    fr.append(direction(bytes(body), exact=True))
    return fr


def build_malformed():
    fr = []
    # Pan and zoom viewport: the zoom value is read as a float of length 2
    # (packet-isobus-vt.c, hf_isobus_vt_graphicscontext_panandzoomviewport_zoomvalue)
    fr.append(to_vt(bytes([184]) + u16(0x3013) + bytes([16]) + struct.pack('<hh', 7, 8) + struct.pack('<f', 2.0)))
    fr.append(to_ecu(bytes([184]) + u16(0x3013) + bytes([16]) + struct.pack('<hh', 7, 8) + struct.pack('<f', 2.0)))
    # Strings shorter than the byte order mark, in both directions
    for d in (to_vt, to_ecu):
        for ln in (0, 1):
            fr.append(d(bytes([179, 1, 0, ln, 0, 0xff, 0xfe, 0x41]), exact=True))
            fr.append(d(bytes([8, 1, 0, ln, 0xff, 0xfe, 0x41, 0x42]), exact=True))
            fr.append(d(bytes([184, 1, 0, 13, 0, ln, 0xff, 0xfe, 0x41]), exact=True))
    # A string with a NUL followed by more characters (warning, not malformed)
    fr.append(to_vt(bytes([179]) + u16(0x3012) + u16(6) + ucs2('A', False) + b'BCD'))
    fr.append(to_vt(bytes([208]) + b'AB\0CDEF'))
    # Strings and lists longer than the frame
    fr.append(to_vt(bytes([179]) + u16(0x3012) + u16(40) + b'Hello', exact=True))
    fr.append(to_ecu(bytes([8]) + u16(0x3012) + bytes([40]) + b'Hello', exact=True))
    fr.append(to_ecu(bytes([193, 0]) + u16(0x20) + u16(0x7e) + bytes([0, 9]), exact=True))
    fr.append(to_ecu(bytes([211, 5]) + label('Label', 32), exact=True))
    fr.append(to_ecu(bytes([224, 7]) + label('V1', 7), exact=True))
    fr.append(to_vt(bytes([34, 3]) + bytes(8) + u16(1) + bytes([4]), exact=True))
    fr.append(to_ecu(bytes([39, 4]) + bytes(8) + bytes([3]), exact=True))
    fr.append(to_vt(bytes([184]) + u16(0x3013) + bytes([12, 200]), exact=True))
    # Truncated messages: only the function code and one or two bytes
    for fc in (0, 1, 2, 3, 4, 5, 6, 7, 9, 18, 32, 33, 36, 37, 38, 160, 165, 168, 170, 175, 177, 185, 189, 192, 193, 194, 195, 198, 199, 208, 254):
        fr.append(to_ecu(bytes([fc, 1]), exact=True))
        fr.append(to_vt(bytes([fc]), exact=True))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = build_main() + sweep()
    write(os.path.join(out, 'isobus-vt-coverage.pcapng'), m)
    write(os.path.join(out, 'isobus-vt-coverage-malformed.pcapng'), build_malformed())
    print('main frames: %d' % len(m))


if __name__ == '__main__':
    main()
