#!/usr/bin/env python3
# Generates test/captures/bthci_evt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures that exercise packet-bthci_evt.c (Bluetooth HCI
# events) on LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR (201).  Every packet is
# built here with struct; nothing comes from a real device.
#
# Usage: mkbthci_evt.py <outdir>
#   writes bthci_evt-coverage.pcap, bthci_evt-coverage-malformed.pcap and
#   bthci_evt_coverage.pcap.gz (gzip -9 of the main capture)
import gzip
import os
import struct
import sys

DLT = 201
SENT, RCVD = 0, 1

LOCAL = bytes.fromhex('020000000001')     # BD_ADDR 02:00:00:00:00:01 (local)
REMOTE = bytes.fromhex('020000000002')    # 02:00:00:00:00:02 (BR/EDR peer)
REMOTE2 = bytes.fromhex('020000000003')   # 02:00:00:00:00:03 (SCO peer)
LEPEER = bytes.fromhex('c20000000004')    # c2:00:00:00:00:04 (LE peer)
LOCAL_NAME = 'Coverage Host'
REMOTE_NAME = 'Remote Device'


def ba(addr):
    '''BD_ADDR as sent on the wire (little endian)'''
    return addr[::-1]


def u8(v): return struct.pack('<B', v & 0xff)
def u16(v): return struct.pack('<H', v & 0xffff)
def u24(v): return struct.pack('<I', v & 0xffffff)[:3]
def u32(v): return struct.pack('<I', v & 0xffffffff)
def i8(v): return struct.pack('<b', v)
def i16(v): return struct.pack('<h', v)


def name248(s):
    b = s.encode()
    return b + bytes(248 - len(b))


def evt(code, body):
    assert len(body) <= 255, (hex(code), len(body))
    return (RCVD, bytes([0x04, code, len(body)]) + body)


def cmd(opcode, params=b''):
    return (SENT, bytes([0x01]) + u16(opcode) + bytes([len(params)]) + params)


def cc(opcode, ret=b'\x00'):
    '''Command Complete'''
    return evt(0x0e, b'\x01' + u16(opcode) + ret)


def cs(opcode, status=0):
    '''Command Status'''
    return evt(0x0f, bytes([status, 1]) + u16(opcode))


def le(sub, body=b''):
    return evt(0x3e, bytes([sub]) + body)


def acl(direction, handle, payload, pb=2):
    return (direction, bytes([0x02]) + u16(handle | (pb << 12)) + u16(len(payload)) + payload)


def l2cap_echo(ident, code=0x08):
    sig = bytes([code, ident]) + u16(4) + b'ping'
    return u16(len(sig)) + u16(0x0001) + sig


def lmp_features():
    return bytes([0xff, 0xfe, 0x8f, 0xfe, 0xdb, 0xff, 0x5b, 0x87])


def eir_block(name, size=240):
    '''EIR/AD: flags-less name, a 16-bit UUID list, then zero padding'''
    n = name.encode()
    d = bytes([len(n) + 1, 0x09]) + n            # Complete Local Name
    d += bytes([3, 0x03]) + u16(0x110b)          # Complete list of 16-bit UUIDs
    d += bytes([5, 0x08]) + b'Rmte'              # Shortened Local Name
    if size is None:
        return d
    return d + bytes(size - len(d))


def cs_caps(v2):
    d = u8(4) + u16(10) + u8(2) + u8(4) + u8(3) + u8(1) + u8(7) + u8(1) + u8(2) + u8(3)
    d += u16(0x0003) + u16(0x0005) + u8(0x06) + u16(0x000e) + u16(0x00ff) + u16(0x00ff)
    d += u16(0x03ff) + u16(0x007f) + u8(0x0a) + u8(0x1f)
    if v2:
        d += u16(0x0055) + u8(0x02) + u8(1) + u8(2) + u8(3)
    return d


# ---------------------------------------------------------------- frames
pk = []

# == Part 1: commands and their completions, state across packets ==========
# Reset and Read Local Version Information (stores the manufacturer,
# Broadcom, whose dissector then gets the vendor-specific packets)
pk += [cmd(0x0c03), cc(0x0c03)]
pk += [cmd(0x1001), cc(0x1001, b'\x00' + u8(0x0c) + u16(0x1234) + u8(0x0c) + u16(0x000f) + u16(0x5678))]
# Read BD_ADDR: the local address used for ACL source/destination
pk += [cmd(0x1009), cc(0x1009, b'\x00' + ba(LOCAL))]
# Reproducer of the fix (bthci_evt_localname_uninit.py):
# Change Local Name without parameters, a successful Command Complete,
# then ISO data.  No local name is saved.
pk += [cmd(0x0c13), cc(0x0c13),
       (SENT, bytes([0x05, 0x01, 0x00, 0x04, 0x00, 0, 0, 0, 0])),
       (RCVD, bytes([0x05, 0x01, 0x00, 0x04, 0x00, 0, 0, 0, 0]))]
# Change Local Name with a name and success: the name is saved
pk += [cmd(0x0c13, name248(LOCAL_NAME)), cc(0x0c13)]
# Create Connection, Command Status (pending), Connection Complete
pk += [cmd(0x0405, ba(REMOTE) + u16(0xcc18) + u8(1) + u8(0) + u16(0x8000 | 0x1234) + u8(1)),
       cs(0x0405),
       evt(0x03, b'\x00' + u16(0x0001) + ba(REMOTE) + u8(1) + u8(0))]
# Remote Name Request, pending, Remote Name Request Complete
pk += [cmd(0x0419, ba(REMOTE) + u8(1) + u8(0) + u16(0)),
       cs(0x0419),
       evt(0x07, b'\x00' + ba(REMOTE) + name248(REMOTE_NAME))]
# ACL sent and received on the connection: local and remote names
pk += [acl(SENT, 0x0001, l2cap_echo(1)), acl(RCVD, 0x0001, l2cap_echo(1, 0x09))]
# Authentication Requested refused in the Command Status (status result)
pk += [cmd(0x0411, u16(0x0001)), cs(0x0411, 0x0c)]
# Sniff Mode, pending, Mode Change (success)
pk += [cmd(0x0803, u16(0x0001) + u16(0x0320) + u16(0x0190) + u16(4) + u16(1)),
       cs(0x0803),
       evt(0x14, b'\x00' + u16(0x0001) + u8(2) + u16(0x0320))]
# Commands whose completion feeds the Bluetooth device tap
pk += [cmd(0x0c18, u16(0x2000)), cc(0x0c18)]
pk += [cmd(0x0c1a, u8(3)), cc(0x0c1a)]
pk += [cmd(0x0c20, u8(1)), cc(0x0c20)]
pk += [cmd(0x0c22, u8(1)), cc(0x0c22)]
pk += [cmd(0x0c24, u24(0x5a020c)), cc(0x0c24)]
pk += [cmd(0x0c26, u16(0x0060)), cc(0x0c26)]
pk += [cmd(0x0c33, u16(1021) + u8(64) + u16(8) + u16(4)), cc(0x0c33)]
pk += [cmd(0x0c45, u8(2)), cc(0x0c45)]
pk += [cmd(0x0c56, u8(1)), cc(0x0c56)]
# A failed completion: the device tap and the local name are not updated
pk += [cmd(0x0c18, u16(0x4000)), cc(0x0c18, b'\x12')]
# LE Create Connection, pending, LE Connection Complete (LE link)
pk += [cmd(0x200d, u16(0x0060) + u16(0x0030) + u8(0) + u8(1) + ba(LEPEER) + u8(0) +
           u16(0x18) + u16(0x28) + u16(0) + u16(0x48) + u16(0) + u16(0)),
       cs(0x200d),
       le(0x01, b'\x00' + u16(0x0040) + u8(0) + u8(1) + ba(LEPEER) + u16(0x0028) + u16(0) +
          u16(0x0048) + u8(5))]
# Disconnect, pending, Disconnection Complete (closes the ACL session)
pk += [cmd(0x0406, u16(0x0001) + u8(0x13)), cs(0x0406),
       evt(0x05, b'\x00' + u16(0x0001) + u8(0x16))]

# Minimum connection interval groups numbered 1..n (repro
# bthci_evt_smallfixes.py, item 4)
pk.append(cc(0x20a3, bytes([0x00, 6, 3]) + (u16(6) + u16(10) + u16(1)) +
             (u16(12) + u16(40) + u16(2)) + (u16(48) + u16(400) + u16(4))))
# Get MWS Transport Layer Configuration from the right offset: one
# transport with two baud rates each way
pk.append(cc(0x140c, b'\x00' + u8(1) + u8(1) + u8(2) +
             u32(115200) + u32(921600) + u32(230400) + u32(3000000)))

# == Part 2: every event ===================================================
pk.append(evt(0x01, b'\x00'))
pk.append(evt(0x01, b'\xfe'))
pk.append(evt(0x02, u8(2) + ba(REMOTE) + u8(1) + u8(2) + u8(0) + u24(0x5a020c) + u16(0x1234) +
              ba(REMOTE2) + u8(0) + u8(0) + u8(0) + u24(0x240404) + u16(0x0001)))
# Connection Complete: SCO link handle 3 (success) and a failure
pk.append(evt(0x03, b'\x00' + u16(0x0003) + ba(REMOTE2) + u8(0) + u8(1)))
pk.append(evt(0x03, b'\x04' + u16(0x0000) + ba(REMOTE2) + u8(1) + u8(0)))
pk.append(evt(0x04, ba(REMOTE2) + u24(0x240404) + u8(1)))
# Disconnection Complete: failure, and success for a handle never connected
pk.append(evt(0x05, b'\x0c' + u16(0x0003) + u8(0x13)))
pk.append(evt(0x05, b'\x00' + u16(0x0123) + u8(0x13)))
pk.append(evt(0x05, b'\x0c' + u16(0x0123) + u8(0xfe)))
pk.append(evt(0x06, b'\x00' + u16(0x0001)))
pk.append(evt(0x08, b'\x00' + u16(0x0001) + u8(1)))
pk.append(evt(0x59, b'\x00' + u16(0x0001) + u8(1) + u8(16)))
pk.append(evt(0x09, b'\x00' + u16(0x0001)))
pk.append(evt(0x0a, b'\x00' + u16(0x0001) + u8(1)))
pk.append(evt(0x0b, b'\x00' + u16(0x0001) + lmp_features()))
pk.append(evt(0x0c, b'\x00' + u16(0x0001) + u8(0x0b) + u16(0x000f) + u16(0x4321)))
pk.append(evt(0x0c, b'\x00' + u16(0x0777) + u8(0x0b) + u16(0x000f) + u16(0x4321)))
pk.append(evt(0x0d, b'\x00' + u16(0x0001) + u8(0) + u8(1) + u32(8000) + u32(16000) + u32(10000) + u32(0xffffffff)))
pk.append(evt(0x10, u8(0x42)))
pk.append(evt(0x11, u16(0x0001)))
# Role Change: peripheral, central, unknown role; a failure
pk.append(evt(0x12, b'\x00' + ba(REMOTE) + u8(0)))
pk.append(evt(0x12, b'\x00' + ba(REMOTE) + u8(1)))
pk.append(evt(0x12, b'\x00' + ba(REMOTE2) + u8(2)))
pk.append(evt(0x12, b'\x0c' + ba(REMOTE2) + u8(1)))
pk.append(evt(0x13, u8(2) + u16(0x0001) + u16(3) + u16(0x0003) + u16(1)))
pk.append(evt(0x14, b'\x0c' + u16(0x0001) + u8(0) + u16(0)))
pk.append(evt(0x15, u8(2) + ba(REMOTE) + bytes(range(16)) + ba(REMOTE2) + bytes(range(16, 32))))
pk.append(evt(0x16, ba(REMOTE)))
pk.append(evt(0x17, ba(REMOTE)))
pk.append(evt(0x18, ba(REMOTE) + bytes(range(0x10, 0x20)) + u8(4)))
# Loopback Command: the looped-back HCI command (Read BD_ADDR)
pk.append(evt(0x19, u16(0x1009) + u8(0)))
pk.append(evt(0x1a, u8(1)))
pk.append(evt(0x1b, u16(0x0001) + u8(5)))
pk.append(evt(0x1c, b'\x00' + u16(0x0001) + u16(0x1000)))
# Connection Packet Type Changed: ACL handle, SCO handle, unknown handle
pk.append(evt(0x1d, b'\x00' + u16(0x0001) + u16(0xcc18)))
pk.append(evt(0x1d, b'\x00' + u16(0x0003) + u16(0x00e0)))
pk.append(evt(0x1d, b'\x00' + u16(0x0040) + u16(0x0018)))
pk.append(evt(0x1e, u16(0x0001)))
pk.append(evt(0x1f, ba(REMOTE) + u8(1)))
pk.append(evt(0x20, ba(REMOTE) + u8(2)))
pk.append(evt(0x21, b'\x00' + u16(0x0001) + u8(0) + u8(1) + u8(2) + u32(1000) + u32(2000) + u32(3000) + u32(4000)))
pk.append(evt(0x22, u8(1) + ba(REMOTE) + u8(1) + u8(0) + u24(0x5a020c) + u16(0x1234) + i8(-60)))
# Read Remote Extended Features Complete, pages 0, 1, 2 and 3
for page in range(4):
    pk.append(evt(0x23, b'\x00' + u16(0x0001) + u8(page) + u8(3) + lmp_features()))
# Synchronous Connection Complete twice (SCO stream numbers 1 and 2), a failure
pk.append(evt(0x2c, b'\x00' + u16(0x0002) + ba(REMOTE2) + u8(2) + u8(12) + u8(2) + u16(60) + u16(60) + u8(3)))
pk.append(evt(0x2c, b'\x00' + u16(0x0004) + ba(REMOTE2) + u8(0) + u8(6) + u8(0) + u16(30) + u16(30) + u8(2)))
pk.append(evt(0x2c, b'\x1a' + u16(0x0005) + ba(REMOTE2) + u8(2) + u8(0) + u8(0) + u16(0) + u16(0) + u8(0)))
pk.append(evt(0x1d, b'\x00' + u16(0x0002) + u16(0x03c0)))
pk.append(evt(0x2d, b'\x00' + u16(0x0002) + u8(12) + u8(4) + u16(60) + u16(60)))
pk.append(evt(0x2e, b'\x00' + u16(0x0001) + u16(10) + u16(20) + u16(30) + u16(40)))
# Extended Inquiry Result with a name (saved for the address), and with
# no response (no address)
pk.append(evt(0x2f, u8(1) + ba(REMOTE2) + u8(1) + u8(0) + u24(0x240404) + u16(0x2000) + i8(-50) +
              eir_block('Inquired Device')))
pk.append(evt(0x2f, u8(0) + eir_block('Nobody')))
pk.append(evt(0x30, b'\x00' + u16(0x0001)))
pk.append(evt(0x31, ba(REMOTE)))
pk.append(evt(0x32, ba(REMOTE) + u8(1) + u8(0) + u8(3)))
pk.append(evt(0x33, ba(REMOTE) + u32(123456)))
pk.append(evt(0x34, ba(REMOTE)))
pk.append(evt(0x35, ba(REMOTE)))
pk.append(evt(0x36, b'\x00' + ba(REMOTE)))
pk.append(evt(0x38, u16(0x0001) + u16(0x7d00)))
pk.append(evt(0x39, u16(0x0001)))
pk.append(evt(0x3b, ba(REMOTE) + u32(999999)))
pk.append(evt(0x3c, ba(REMOTE) + u8(1)))
pk.append(evt(0x3d, ba(REMOTE) + bytes([0x0f]) + bytes(7)))
pk.append(evt(0x40, b'\x00' + u8(1)))
pk.append(evt(0x41, u8(1)))
pk.append(evt(0x42, b'\x00' + u8(1) + u8(0x13)))
pk.append(evt(0x43, u8(1) + u8(2)))
pk.append(evt(0x44, u8(1)))
pk.append(evt(0x45, b'\x00' + u16(0x0101) + u8(1) + u8(2)))
pk.append(evt(0x46, b'\x00' + u16(0x0101) + u8(0x16)))
pk.append(evt(0x47, b'\x00' + u16(0x0001)))
pk.append(evt(0x48, u16(100) + u8(2) + u16(0x0001) + u16(2) + u16(4) + u16(0x0003) + u16(1) + u16(1)))
pk.append(evt(0x49, b'\x00' + u8(1)))
pk.append(evt(0x4a, b'\x00' + u8(1)))
pk.append(evt(0x4b, u8(1) + u8(0) + u8(1) + u16(100) + u16(2) + u32(80000) + u32(17)))
pk.append(evt(0x4c, b'\x00' + u8(1) + u8(1)))
pk.append(evt(0x4d, b'\x00' + u8(1)))
# Events 0x4e-0x57 (their fields are on the top-level tree, not fixed)
pk.append(evt(0x4e, u16(0x0001) + u8(0) + u32(0x12345678) + u16(0x0010)))
pk.append(evt(0x4f, b'\x00'))
pk.append(evt(0x50, b'\x00' + ba(REMOTE) + u32(0x1000) + bytes([0xff] * 9 + [0x7f]) + u8(1) +
              u32(0x2000) + u16(0x0100) + u8(0x22)))
pk.append(evt(0x51, ba(REMOTE) + u8(1) + u32(0x3000) + u32(0x10) + u8(0) + u8(3) + u8(1) + b'\xaa'))
pk.append(evt(0x52, ba(REMOTE) + u8(1)))
pk.append(evt(0x53, b'\x00' + ba(REMOTE)))
pk.append((RCVD, bytes([0x04, 0x54, 0x00])))
pk.append(evt(0x55, bytes([0xff] * 9 + [0x7f])))
pk.append(evt(0x56, u24(0x9e8b33) + i8(-70)))
pk.append(evt(0x57, u16(0x0001)))
pk.append(evt(0x58, u16(0x0001) + bytes([1, 0x55, 0xaa, 2, 0x0f, 0xf0])))
# An event with no parameters at all, and an unknown event code
pk.append((RCVD, bytes([0x04, 0x01, 0x00])))
pk.append(evt(0x5a, b'\x01\x02'))

# == Part 3: Command Complete for every opcode ==============================
STATUS_ONLY = [int(x, 16) for x in '''
0402 0403 0404 080f 0c01 0c03 0c05 0c0a 0c0b 0c13 0c16 0c18 0c1a 0c1c 0c1e 0c20 0c22 0c24 0c26
0c2a 0c2c 0c2f 0c31 0c33 0c3a 0c3c 0c3e 0c3f 0c43 0c45 0c47 0c49 0c52 0c56 0c59 0c5b 0c62 0c63
0c65 0c67 0c6a 0c6d 0c6e 0c6f 0c71 0c72 0c73 0c7a 0c7f 0c81 0c82 0c83 0c84 140d 1802 1803 1804
1807 1808 1809 2001 2005 2006 2008 2009 200a 200b 200c 200e 2010 2011 2012 2014 201d 201e 2024
2027 2028 2029 202d 202e 2031 2033 2034 2035 2037 2038 2039 203c 203d 203e 203f 2040 2041 2042
2045 2046 2047 2048 2049 204d 204e 204f 2050 2051 2052 2059 205d 205f 2074 207b 207c 207d 2080
2081 2092 2095 2098 2099 209a 209c 209e 209f 20a0 20a2 20a4 20a8'''.split()]
STATUS_BDADDR = [int(x, 16) for x in '''
0408 040b 040c 040d 040e 041a 042b 042c 042d 042e 042f 0430 0433 0434 0440 0445 0c60 202b 202c'''.split()]
STATUS_HANDLE = [int(x, 16) for x in '''
080d 0811 0c08 0c28 0c37 0c7c 1402 180a 201a 201b 2020 2021 2022 2054 2055 2056 2057 205a 205b
205c 2078 2079 207a 208b 208d 208f 2093 20a6 20a7'''.split()]
for op in STATUS_ONLY:
    pk.append(cc(op))
for op in STATUS_BDADDR:
    pk.append(cc(op, b'\x00' + ba(REMOTE)))
for op in STATUS_HANDLE:
    pk.append(cc(op, b'\x00' + u16(0x0001)))

S = b'\x00'
H = u16(0x0001)
RET = [
    (0x0c15, S + u16(0x1fa0)),
    (0x0c17, S + u16(0x2000)),
    (0x0c27, S + H + u16(0x0100)),
    (0x0c36, S + H + u16(0x7d00)),
    (0x0c1b, S + u16(0x0800) + u16(0x0012)),
    (0x0c1d, S + u16(0x1000) + u16(0x0012)),
    (0x0420, S + H + u8(7) + bytes(4)),
    (0x043b, S + u8(1) + u8(2)),
    (0x0809, S + H + u8(1)),
    (0x080c, S + H + u16(0x000f)),
    (0x080e, S + u16(0x0005)),
    (0x0c09, S + u8(1)),
    (0x0c0d, S + u16(16) + u16(2)),
    (0x0c11, S + u8(2)),
    (0x0c12, S + u16(2)),
    (0x0c14, S + name248(LOCAL_NAME)),
    (0x0c19, S + u8(3)),
    (0x0c1f, S + u8(1)),
    (0x0c21, S + u8(1)),
    (0x0c23, S + u24(0x5a020c)),
    (0x0c25, S + u16(0x0060)),
    (0x0c29, S + u8(1)),
    (0x0c2b, S + u8(7)),
    (0x0c2d, S + H + i8(4)),
    (0x0c2e, S + u8(1)),
    (0x0c38, S + u8(2)),
    (0x0c39, S + u8(2) + u24(0x9e8b33) + u24(0x9e8b00)),
    (0x0c3b, S + u8(1)),
    (0x0c3d, S + u8(0)),
    (0x0c42, S + u8(1)),
    (0x0c46, S + u8(0)),
    (0x0c44, S + u8(2)),
    (0x0c48, S + u8(1)),
    (0x0c51, S + u8(1) + eir_block(LOCAL_NAME)),
    (0x0c55, S + u8(1)),
    (0x0c57, S + bytes(range(16)) + bytes(range(16, 32))),
    (0x0c58, S + i8(-4)),
    (0x0c5a, S + u8(1)),
    (0x0c61, S + u16(0x1f40)),
    (0x0c64, S + u8(1) + b'GB' + b' ' + u8(0)),
    (0x0c66, S + u8(1)),
    (0x0c68, S + H + i8(4) + i8(2) + i8(0)),
    (0x0c69, S + u32(0xffffffff)),
    (0x0c6c, S + u8(1) + u8(0)),
    (0x0c74, S + u8(1)),
    (0x0c75, S + u8(1)),
    (0x0c76, S + u8(1)),
    (0x1002, S + bytes([0xff] * 40) + bytes(24)),
    (0x1010, S + bytes([0xff] * 48) + bytes(16) + bytes([0x03, 0x00])),
    (0x1003, S + lmp_features()),
    (0x1004, S + u8(0) + u8(2) + lmp_features()),
    (0x1004, S + u8(1) + u8(2) + bytes([0x0f]) + bytes(7)),
    (0x1004, S + u8(2) + u8(2) + bytes([0x7f, 0x0f]) + bytes(6)),
    (0x1004, S + u8(5) + u8(5) + bytes(8)),
    (0x1005, S + u16(1021) + u8(64) + u16(8) + u16(4)),
    (0x100a, S + u16(1021) + u16(64) + u16(16)),
    (0x100b, S + u8(3) + bytes([0, 2, 3]) + u8(2) + u16(0x000f) + u16(1) + u16(0x0002) + u16(2)),
    (0x100c, S + u8(1) + u8(16)),
    (0x1007, S + u8(0)),
    (0x1401, S + H + u16(3)),
    (0x1403, S + H + u8(255)),
    (0x1405, S + H + i8(-5)),
    (0x1406, S + H + u8(1) + bytes([0xff] * 9 + [0x7f])),
    # Read Clock: the accuracy is read as 32 bits, so two extra octets
    (0x1407, S + H + u32(0x00123456) + u16(10) + bytes(2)),
    (0x1408, S + H + u8(16)),
    (0x1409, S + u8(1) + u32(30000) + u32(20000) + u32(100) + u32(1492) + u8(1) + u16(1) + u16(672) +
     u32(0xffffffff) + u32(10000)),
    (0x140a, S + u8(1) + u16(4) + b'\x01\x02\x03\x04'),
    (0x140b, S + u8(1)),
    (0x1801, S + u8(1)),
    (0x2002, S + u16(0) + u8(0)),
    (0x2002, S + u16(251) + u8(8)),
    (0x2060, S + u16(251) + u8(8) + u16(310) + u8(4)),
    (0x2003, S + bytes([0xff, 0xff, 0xff, 0x7f, 0x00, 0, 0, 0])),
    (0x2007, S + i8(-4)),
    (0x200f, S + u8(8)),
    (0x2015, S + u16(0x0040) + bytes([0xff, 0xff, 0xff, 0xff, 0x1f])),
    (0x2017, S + bytes(range(16))),
    (0x2018, S + bytes(range(8))),
    (0x201c, S + bytes([0xff, 0xff, 0xff, 0x1f, 0, 0, 0, 0])),
    (0x201f, S + u16(1234)),
    (0x2030, S + u16(0x0040) + u8(2) + u8(3)),
    (0x2036, S + i8(-2)),
    (0x207f, S + i8(3)),
    (0x203a, S + u16(1650)),
    (0x203b, S + u8(4)),
    (0x2053, S + u16(0x0001)),
    (0x0441, S + u8(1) + u16(0x0100)),
    (0x0442, S + ba(REMOTE) + u8(1)),
    (0x0c70, b''.join(u16(10 * i + 1) for i in range(16))),
    (0x0c77, S + u16(0x0080) + u32(0x0002ee00) + u8(0x33)),
    (0x0c78, S + u16(0x0080)),
    (0x0c79, S + u8(1)),
    (0x0c7b, S + H + u16(3000)),
    (0x0c7d, S + bytes(range(64))),
    (0x0c7e, S + u16(0x0100)),
    (0x0c80, S + u16(0x0200)),
    (0x2023, S + u16(251) + u16(2120)),
    (0x202a, S + u8(8)),
    (0x202f, S + u16(251) + u16(17040) + u16(251) + u16(17040)),
    (0x204a, S + u8(4)),
    (0x204b, S + i8(-20) + i8(10)),
    (0x204c, S + i16(-15) + i16(25)),
    (0x2058, S + u8(0x07) + u8(4) + u8(8) + u8(20)),
    (0x2061, S + u16(0x0060) + u16(7) + u32(1000000) + u24(500)),
    (0x2062, S + u8(1) + u8(2) + u16(0x0060) + u16(0x0061)),
    (0x2063, S + u8(2) + u8(1) + u16(0x0062)),
    (0x2065, S + u8(1)),
    (0x2067, S + u16(0x0060)),
    (0x206c, S + u8(1)),
    (0x206e, S + u16(0x0060)),
    (0x206f, S + u16(0x0060)),
    (0x2070, S + u16(0x0060)),
    (0x2071, S + u16(0x0060)),
    (0x2072, S + u16(0x0060) + u32(100) + u32(2) + u32(1)),
    (0x2073, S + u16(0x0060) + u32(200) + u32(3) + u32(2)),
    (0x2075, S + u16(0x0060) + b''.join(u32(i) for i in range(1, 8))),
    (0x2076, S + u16(0x0040) + u8(1) + i8(5) + i8(10)),
    (0x2082, S + u8(1)),
    (0x2086, S + u8(2)),
    (0x2083, S + u16(0x0001)),
    (0x2084, S + u16(0x0002)),
    (0x2087, S + u8(1) + bytes([0xff] * 8) + bytes([0x01]) + bytes(7) + bytes(232)),
    (0x2089, S + cs_caps(False)),
    (0x20a5, S + cs_caps(True)),
    (0x209b, S + u8(16)),
]
for op, ret in RET:
    pk.append(cc(op, ret))
# Status / device-tap paths with a failing status
for op, ret in [(0x0c17, b'\x0c' + u16(0)), (0x0c14, b'\x0c' + bytes(248)),
                (0x0c19, b'\x0c\x00'), (0x0c1f, b'\x0c\x00'), (0x0c21, b'\x0c\x00'),
                (0x0c23, b'\x0c' + bytes(3)), (0x0c25, b'\x0c' + bytes(2)),
                (0x0c44, b'\x0c\x00'), (0x0c55, b'\x0c\x00'), (0x1005, b'\x0c' + bytes(7)),
                (0x2002, b'\x0c' + bytes(3)),
                (0x1001, b'\x0c' + bytes(8))]:
    pk.append(cc(op, ret))
# Read Local Version Information again with the same values.  (Changed
# values are in the malformed capture: the vendor state is keyed by
# adapter only, so a second pass compares with the last values seen.)
pk.append(cc(0x1001, b'\x00' + u8(0x0c) + u16(0x1234) + u8(0x0c) + u16(0x000f) + u16(0x5678)))
# Host Number Of Completed Packets without and with (unexpected) parameters
pk.append(evt(0x0e, b'\x01' + u16(0x0c35)))
pk.append(cc(0x0c35, b'\x00'))
# An opcode answered by Command Status only, and an unknown opcode
pk.append(cc(0x0405, b'\x00'))
pk.append(cc(0x0c00, b'\x00'))
# Command Status: vendor-specific opcode, unknown opcode
pk.append(cs(0xfc01))
pk.append(cs(0x0c00, 0x01))
# Vendor-specific Command Complete (Broadcom Write BD ADDR) and vendor event
pk.append(cc(0xfc01, b'\x00'))
pk.append(evt(0xff, b'\x01\x02\x03'))
# Command Status for every OGF (opcode field names)
for op in (0x0401, 0x0803, 0x0c01, 0x1001, 0x1401, 0x1801, 0x2001, 0xf801):
    pk.append(cs(op))
pk.append(cc(0xf801, b'\x00'))

# == Part 4: LE Meta subevents =============================================
LEH = u16(0x0040)
pk.append(le(0x01, b'\x3e' + u16(0x0041) + u8(1) + u8(0) + ba(LEPEER) + u16(0x28) + u16(0) + u16(0x48) + u8(1)))
pk.append(le(0x02, u8(3) +
             u8(0) + u8(1) + ba(LEPEER) + u8(len(eir_block('LE Peripheral', None))) + eir_block('LE Peripheral', None) + i8(-60) +
             u8(4) + u8(0) + ba(LEPEER) + u8(0) + i8(-61) +
             u8(2) + u8(1) + ba(LEPEER) + u8(3) + bytes([2, 0x01, 0x06]) + i8(-62)))
pk.append(le(0x03, b'\x00' + LEH + u16(0x18) + u16(1) + u16(0x100)))
pk.append(le(0x04, b'\x00' + LEH + bytes([0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0])))
pk.append(le(0x05, LEH + bytes(range(8)) + u16(0x1234)))
pk.append(le(0x06, LEH + u16(6) + u16(12) + u16(0) + u16(0x100)))
pk.append(le(0x07, LEH + u16(251) + u16(2120) + u16(251) + u16(2120)))
pk.append(le(0x08, b'\x00' + bytes(range(64))))
pk.append(le(0x09, b'\x00' + bytes(range(32))))
pk.append(le(0x0a, b'\x00' + u16(0x0042) + u8(0) + u8(3) + ba(LEPEER) + ba(bytes.fromhex('4a0000000005')) +
             ba(bytes.fromhex('4b0000000006')) + u16(0x28) + u16(0) + u16(0x48) + u8(2)))
pk.append(le(0x29, b'\x00' + u16(0x0043) + u8(1) + u8(0) + ba(LEPEER) + bytes(6) + bytes(6) +
             u16(0x28) + u16(0) + u16(0x48) + u8(2) + u8(1) + u16(0x0005)))
pk.append(le(0x29, b'\x3e' + u16(0x0044) + u8(1) + u8(0) + ba(LEPEER) + bytes(6) + bytes(6) +
             u16(0x28) + u16(0) + u16(0x48) + u8(2) + u8(1) + u16(0x0005)))
pk.append(le(0x0b, u8(2) + u8(1) + u8(1) + ba(LOCAL) + u8(0) + ba(LEPEER) + i8(-70) +
             u8(1) + u8(1) + ba(LOCAL) + u8(1) + ba(LEPEER) + i8(-71)))
pk.append(le(0x0c, b'\x00' + LEH + u8(2) + u8(2)))
ad = eir_block('Ext Adv', None)
pk.append(le(0x0d, u8(2) +
             u16(0x0013) + u8(0) + ba(LEPEER) + u8(1) + u8(2) + u8(3) + i8(5) + i8(-40) + u16(0x0010) +
             u8(0) + ba(LOCAL) + u8(len(ad)) + ad +
             u16(0x0060) + u8(1) + ba(LEPEER) + u8(1) + u8(0) + u8(0xff) + u8(127) + u8(127) + u16(0) +
             u8(0xff) + bytes(6) + u8(0)))
pk.append(le(0x0e, b'\x00' + u16(0x0001) + u8(2) + u8(0) + ba(LEPEER) + u8(2) + u16(0x0050) + u8(5)))
pk.append(le(0x24, b'\x00' + u16(0x0002) + u8(3) + u8(1) + ba(LEPEER) + u8(1) + u16(0x0050) + u8(5) +
             u8(4) + u8(10) + u8(2) + u8(3)))
pk.append(le(0x0f, u16(0x0001) + i8(10) + i8(-50) + u8(0xff) + u8(0) + u8(3) + b'\x02\x01\x06'))
pk.append(le(0x0f, u16(0x0001) + u8(127) + u8(127) + u8(0) + u8(0xff) + u8(0)))
pk.append(le(0x25, u16(0x0002) + i8(10) + i8(-50) + u8(0) + u16(77) + u8(3) + u8(1) + u8(2) + b'\xab\xcd'))
pk.append(le(0x10, u16(0x0001)))
pk.append(le(0x11))
pk.append(le(0x12, b'\x00' + u8(1) + LEH + u8(3)))
pk.append(le(0x13, u8(1) + u8(0) + ba(LEPEER)))
pk.append(le(0x14, LEH + u8(1)))
pk.append(le(0x15, u16(0x0001) + u8(10) + i16(-450) + u8(1) + u8(0) + u8(1) + u8(0) + u16(33) +
             u8(3) + bytes([1, 0xff, 0x7f, 0x80, 0, 0])))
pk.append(le(0x15, u16(0x0001) + u8(11) + i16(-400) + u8(0) + u8(0) + u8(2) + u8(0xff) + u16(34) + u8(0)))
pk.append(le(0x16, LEH + u8(2) + u8(12) + i16(-300) + u8(2) + u8(1) + u8(1) + u8(1) + u16(35) +
             u8(2) + bytes([5, 6, 7, 8])))
pk.append(le(0x17, b'\x00' + LEH))
pk.append(le(0x2e, b'\x00' + LEH))
pk.append(le(0x18, b'\x00' + LEH + u16(0x1234) + u16(0x0003) + u8(1) + u8(0) + ba(LEPEER) + u8(1) + u16(0x40) + u8(2)))
pk.append(le(0x26, b'\x00' + LEH + u16(0x1234) + u16(0x0004) + u8(1) + u8(0) + ba(LEPEER) + u8(1) + u16(0x40) + u8(2) +
             u8(4) + u8(10) + u8(2) + u8(3)))
cis = u24(1000) + u24(900) + u24(5000) + u24(6000) + u8(2) + u8(2) + u8(3) + u8(1) + u8(1) + u8(2) + u8(2) + \
    u16(120) + u16(120) + u16(8)
pk.append(le(0x19, b'\x00' + u16(0x0060) + cis))
pk.append(le(0x2a, b'\x00' + u16(0x0061) + cis + u24(2500) + u16(100) + u16(100) + u24(10000) + u24(10000) + u8(0)))
pk.append(le(0x19, b'\x3e' + u16(0x0062) + cis))
pk.append(le(0x1a, LEH + u16(0x0063) + u8(1) + u8(2)))
pk.append(le(0x1b, b'\x00' + u8(1) + u24(1000) + u24(2000) + u8(2) + u8(4) + u8(2) + u8(1) + u8(1) + u16(100) +
             u16(8) + u8(2) + u16(0x0070) + u16(0x0071)))
pk.append(le(0x1c, u8(1) + u8(0x16)))
pk.append(le(0x1e, u8(1) + u8(0x08)))
pk.append(le(0x1d, b'\x00' + u8(2) + u24(2000) + u8(4) + u8(2) + u8(1) + u8(1) + u16(100) + u16(8) +
             u8(1) + u16(0x0072)))
pk.append(le(0x1f, b'\x00' + LEH + u8(3)))
pk.append(le(0x20, LEH + u8(40) + u8(1)))
pk.append(le(0x21, b'\x00' + LEH + u8(0) + u8(1) + i8(4) + u8(3) + i8(-2)))
pk.append(le(0x21, b'\x00' + LEH + u8(1) + u8(2) + u8(0x7f) + u8(0) + i8(127)))
pk.append(le(0x21, b'\x00' + LEH + u8(2) + u8(3) + u8(0x7e) + u8(0) + i8(127)))
pk.append(le(0x22, u16(0x0001) + u8(2) + u8(4) + u16(8) + u8(2) + u8(1) + u8(1) + u16(100) + u24(10000) +
             u16(100) + u8(2) + u8(0) + u8(1)))
pk.append(le(0x23, b'\x00' + LEH + u16(3) + u16(2) + u16(1) + u16(0x100)))
pk.append(le(0x27, u8(1) + u8(0) + u8(4)))
pk.append(le(0x28, u8(1) + u8(2) + u8(0) + u8(2) +
             i8(5) + i8(-55) + u8(0) + u8(1) + u8(0) + u8(3) + b'\x02\x01\x06' +
             i8(5) + i8(-56) + u8(0xff) + u8(2) + u8(0xff) + u8(0)))
pk.append(le(0x2b, b'\x00' + LEH + u8(1) + u8(1) + bytes([0xff] * 8) + bytes([0x01]) + bytes(7) + bytes(232)))
pk.append(le(0x2c, b'\x00' + LEH + cs_caps(False)))
pk.append(le(0x38, b'\x00' + LEH + cs_caps(True)))
pk.append(le(0x2d, b'\x00' + LEH + bytes(range(72))))


def cs_config(handle, config_id, action, role, rtt, status=0):
    return le(0x2f, u8(status) + u16(handle) + u8(config_id) + u8(action) + u8(1) + u8(0xff) + u8(2) + u8(5) +
              u8(1) + u8(3) + u8(role) + u8(rtt) + u8(1) + bytes([0xfc, 0xff, 0x7f] + [0xff] * 6 + [0x1f]) +
              u8(1) + u8(0) + u8(0) + u8(2) + u8(0x05) + u8(10) + u8(20) + u8(15) + u8(10))


# CS configurations: config 1 initiator with sounding sequence (RTT type 1),
# config 2 reflector without (RTT type 0); a failed and a "remove" config
pk.append(cs_config(0x0040, 1, 1, 0, 1))
pk.append(cs_config(0x0040, 2, 1, 1, 0))
pk.append(cs_config(0x0040, 3, 1, 0, 2, status=0x0c))
pk.append(cs_config(0x0040, 4, 0, 0, 2))
pk.append(le(0x30, b'\x00' + LEH + u8(1) + u8(1) + u8(0) + i8(10) + u24(5000) + u8(1) + u16(0) + u16(10) +
             u16(20) + u16(5) + u16(100)))


def iq(i, q):
    return u24((i & 0xfff) | ((q & 0xfff) << 12))


def step(mode, chan, data):
    return u8(mode) + u8(chan) + u8(len(data)) + data


mode1_snd = u8(0x10) + i8(-60) + i16(100) + u8(1) + iq(0x900, 0x100) + u8(0) + u32(0xffffffff)
mode1_snd2 = u8(0x10) + i8(-62) + i16(-100) + u8(2) + u32(0xffffffff) + iq(0x7ff, 0x800) + u8(1)
mode1_na = u8(0x01) + i8(-61) + i16(-32768) + u8(2)
mode2 = u8(3) + iq(0x123, 0xfed) + u8(0x01) + iq(0x0ff, 0x801) + u8(0x12)
steps1 = (step(0, 2, u8(0x00) + i8(-50) + u8(1)) +                  # mode 0, 3 octets
          step(0, 3, u8(0x01) + i8(-51) + u8(2) + i16(-16384)) +    # mode 0, 5 octets
          step(0, 4, u8(0x02) + i8(-52) + u8(3) + u16(0x4100)) +
          step(1, 5, u8(0x00) + mode1_snd) +                        # mode 1 with sounding
          step(1, 13, u8(0x00) + mode1_snd2) +
          step(2, 6, mode2) +                                       # mode 2, 2 tones
          step(3, 7, u8(0x00) + mode1_snd + mode2) +                # mode 3
          step(1, 8, b'') +                                         # no step data
          step(5, 9, b'\x01\x02'))                                  # unknown mode
pk.append(le(0x31, LEH + u8(1) + u16(10) + u16(1) + i16(-16384) + i8(127) + u8(0) + u8(0) + u8(0) + u8(2) +
             u8(9) + steps1))
pk.append(le(0x32, LEH + u8(1) + u8(0) + u8(0) + u8(0x21) + u8(2) + u8(1) + step(0, 10, u8(0) + i8(-40) + u8(1))))
# Config 2 (reflector, no sounding): mode 1 without PCT samples
pk.append(le(0x31, LEH + u8(2) + u16(11) + u16(2) + i16(0x0064) + i8(-10) + u8(0) + u8(0) + u8(0) + u8(1) +
             u8(1) + step(1, 11, u8(0x00) + mode1_na)))
# Unknown configuration: initiator without sounding by default
pk.append(le(0x31, u16(0x0050) + u8(3) + u16(12) + u16(3) + i16(0x4100) + i8(0) + u8(0) + u8(0) + u8(0) + u8(1) +
             u8(1) + step(1, 12, u8(0x00) + mode1_na)))
pk.append(le(0x33, b'\x00'))
pk.append(le(0x34, u8(0) + ba(LEPEER) + u8(1)))
pk.append(le(0x35, b'\x00' + LEH + u8(1) + u16(150) + u8(0x07) + u16(0x001f)))
pk.append(le(0x36, u8(4) + b'\x01\x02\x03\x04'))
pk.append(le(0x37, b'\x00' + LEH + u16(6) + u16(3) + u16(2) + u16(1) + u16(0x100)))
pk.append(le(0x3f, b'\x01\x02'))                                    # unknown subevent

# A Command Status for LE Create Connection, then a second LE Connection
# Complete (enhanced) answering it
pk += [cmd(0x200d, u16(0x0060) + u16(0x0030) + u8(0) + u8(1) + ba(LEPEER) + u8(0) +
           u16(0x18) + u16(0x28) + u16(0) + u16(0x48) + u16(0) + u16(0)),
       cs(0x200d),
       le(0x0a, b'\x00' + u16(0x0045) + u8(0) + u8(1) + ba(LEPEER) + bytes(6) + bytes(6) + u16(0x28) +
          u16(0) + u16(0x48) + u8(5))]
# ACL after the connection is gone: names still known
pk += [acl(SENT, 0x0003, l2cap_echo(2))]

MAIN = pk

# ---------------------------------------------------------------- malformed
bad = []
# Change Local Name answered, then the Bluetooth layer has nothing
for code, body in [
        (0x03, b'\x00\x01'),                       # Connection Complete cut short
        (0x07, b'\x00' + ba(REMOTE)),              # Remote Name cut (248 octets needed)
        (0x13, u8(5) + u16(1)),                    # Number Of Completed Packets, count too high
        (0x15, u8(3)),                             # Return Link Keys, no keys
        (0x2f, u8(1) + bytes(14)),                 # Extended Inquiry Result without EIR
        (0x0e, b'\x01'),                           # Command Complete without opcode
        (0x0f, b'\x00\x01'),                       # Command Status without opcode
        (0x3e, b''),                               # (length 0: nothing parsed)
        (0x51, ba(REMOTE) + u8(1) + bytes(10) + u8(10)),   # data length beyond the event
        ]:
    bad.append(evt(code, body))
bad.append(le(0x02, u8(1) + u8(0) + u8(1) + ba(LEPEER) + u8(40) + b'\x02\x01\x06'))
bad.append(le(0x0d, u8(1) + bytes(10)))
bad.append(le(0x0f, u16(1) + bytes(4) + u8(50)))
bad.append(le(0x15, u16(1) + bytes(9) + u8(10)))
bad.append(le(0x1b, b'\x00' + bytes(16) + u8(5)))
bad.append(le(0x28, u8(1) + u8(2) + u8(0) + u8(3) + bytes(6)))
bad.append(le(0x31, LEH + u8(9) + bytes(7) + u8(0) + u8(0) + u8(0) + u8(1) + u8(3) + step(0, 1, b'\x00')))
bad.append(le(0x36, u8(40) + b'\x01'))
bad.append(le(0x2b, b'\x00' + LEH + bytes(10)))
# Read Clock with exactly the 9 octets of return parameters: the 32 bit
# read of the 16 bit accuracy runs off the end
bad.append(cc(0x1407, b'\x00' + H + u32(0x00123456) + u16(10)))
for op, ret in [(0x0c39, b'\x00' + u8(10)), (0x100b, b'\x00' + u8(20)), (0x0c14, b'\x00abc'),
                (0x140c, b'\x00' + u8(3) + u8(1) + u8(9)), (0x20a3, b'\x00\x06\x05'),
                (0x2062, b'\x00\x01\x09'), (0x1004, b'\x00'), (0x0c51, b'\x00\x01'),
                (0x2089, b'\x00' + bytes(5)), (0x2087, b'\x00' + bytes(4))]:
    bad.append(cc(op, ret))
# The CS Subevent Result mode-3 step with Step_Data_Length 1 (not fixed,
# bthci_evt_smallfixes.py item 3)
csr = u16(0x0001) + u8(0) + u16(0) + u16(0) + i16(0) + i8(0) + bytes([0, 0, 0, 1, 2])
csr += bytes([3, 10, 1, 0x00]) + bytes([0, 11, 3, 0x00, 0xc4, 0x01]) + bytes(240)
bad.append(le(0x31, csr[:254]))
# Get MWS Transport Layer Configuration with two transports (baud rate
# count taken from the last transport only; not fixed)
bad.append(cc(0x140c, bytes([0x00, 2, 1, 1, 2, 2]) + u32(0x11111111) + u32(0x22222222) + u32(0x33333333) +
              u32(0x44444444) + u32(0x55555555) + u32(0x66666666)))
# Vendor-specific packets before any vendor is known, then with the
# Broadcom and Intel dissectors (changed manufacturer: expert warning)
bad.append(evt(0xff, b'\x01\x02\x03'))
bad.append(cc(0xfc01, b'\x00\x01\x02'))
bad.append(cs(0xfc01))
bad.append(cc(0x1001, b'\x00' + u8(0x0c) + u16(0x1234) + u8(0x0c) + u16(0x000f) + u16(0x5678)))
bad.append(evt(0xff, b'\x01\x02\x03'))
bad.append(cc(0xfc01, b'\x00\x01\x02'))
bad.append(cs(0xfc01))
bad.append(cc(0xfc01, b"\x00" + bytes(range(1, 21))))
bad.append(evt(0x0f, bytes([0, 1]) + u16(0xfc01) + bytes(range(1, 21))))
bad.append(evt(0xff, bytes(range(1, 30))))
bad.append(cc(0x1001, b'\x00' + u8(0x0c) + u16(0x1235) + u8(0x0c) + u16(0x0002) + u16(0x5679)))
bad.append(evt(0xff, b'\x01\x02\x03'))
bad.append(cc(0xfc01, b'\x00\x01\x02'))
bad.append(cs(0xfc01))
# An event sent by the host, and event 0x54 with an (ignored) parameter
bad.append((SENT, bytes([0x04, 0x01, 0x01, 0x00])))
bad.append(evt(0x54, b'\x00'))
MALFORMED = bad


def write(path, frames, dlt=DLT):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, dlt))
        for i, (direction, payload) in enumerate(frames):
            data = struct.pack('>I', direction) + payload if dlt == DLT else payload
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, (i % 1000) * 1000, len(data), len(data)))
            f.write(data)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write(os.path.join(out, 'bthci_evt-coverage.pcap'), MAIN)
    write(os.path.join(out, 'bthci_evt-coverage-malformed.pcap'), MALFORMED)
    # LINKTYPE_BLUETOOTH_HCI_H4 (187) has no direction: "UnknownDirection"
    write(os.path.join(out, 'bthci_evt-coverage-nodir.pcap'), [evt(0x01, b'\x00'), cc(0x0c03)], 187)
    with open(os.path.join(out, 'bthci_evt-coverage.pcap'), 'rb') as f:
        data = f.read()
    with gzip.GzipFile(os.path.join(out, 'bthci_evt_coverage.pcap.gz'), 'wb', 9, mtime=0) as g:
        g.write(data)
    print('main: %d frames, malformed: %d frames' % (len(MAIN), len(MALFORMED)))


if __name__ == '__main__':
    main()
