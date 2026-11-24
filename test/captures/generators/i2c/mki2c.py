#!/usr/bin/env python3
# Generates test/captures/i2c_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-i2c.c: DLT_I2C_LINUX (209) with the Linux
pseudo header (bus, flags), and DLT_IPMB_KONTRON (199) in one pcapng file.
Usage: mki2c.py <outdir>"""
import struct
import sys
import os
from pylib import Pcapng

LINUX, KONTRON = 209, 199

def lin(bus, flags, data=b'', event=False):
    return bytes([bus | (0x80 if event else 0)]) + struct.pack('>I', flags) + data

def cksum(b):
    return (-sum(b)) & 0xff

def ipmb(rs_sa, netfn, rq_sa, seq, cmd, data=b'', lun=0, rqlun=0):
    h = bytes([rs_sa, (netfn << 2) | lun])
    h += bytes([cksum(h)])
    t = bytes([rq_sa, (seq << 2) | rqlun, cmd]) + data
    return h + t + bytes([cksum(t)])

def kontron(rw, port, ipmb_msg):
    # data length, port number, then the IPMB message starting at the address
    return bytes([len(ipmb_msg) + 1 | rw, port]) + ipmb_msg

def main(out):
    p = Pcapng(); a = p.add_if(LINUX); k = p.add_if(KONTRON)
    ev = lambda bus, fl: p.add(a, lin(bus, fl, b'', True))
    # State events
    for i, bit in enumerate([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]):
        ev(i, 1 << bit)
    # Detached with every error flag, and without
    ev(1, 0x20)
    for bit in range(16, 23):
        ev(1, 0x20 | (1 << bit))
    # Unknown events
    ev(2, 0x0400)
    ev(2, 0)
    # Data: writes and reads at several addresses, bus numbers
    p.add(a, lin(0, 0, bytes([0x50 << 1]) + bytes([0x00, 0x10, 0x20])))
    p.add(a, lin(0, 1, bytes([(0x50 << 1) | 1]) + bytes(range(16))))
    p.add(a, lin(5, 0, bytes([0x20 << 1]) + b'hello world'))
    p.add(a, lin(127, 1, bytes([0x7f << 1 | 1]) + bytes(4)))
    # General call (address 0), no payload beyond the address byte
    p.add(a, lin(1, 0, bytes([0x00]) + bytes([0x06])))
    p.add(a, lin(1, 0, bytes([0x00])))
    # Other flags: ten bit address, reversed direction, no start
    p.add(a, lin(2, 0x10, bytes([0xf0, 0x55])))
    p.add(a, lin(2, 0x2001, bytes([0x42, 0x01, 0x02])))
    p.add(a, lin(2, 0x4000, bytes([0x42, 0x03])))
    # Kontron IPMB frames: request and response, read and write bit
    p.add(k, kontron(0, 1, ipmb(0x20, 6, 0x81, 1, 0x01)))
    p.add(k, kontron(0, 1, ipmb(0x81, 7, 0x20, 1, 0x01, bytes([0, 0x20, 0x01, 0x01, 0x02, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]))))
    p.add(k, kontron(1, 2, ipmb(0x20, 0x0a, 0x81, 2, 0x40, bytes(4), lun=0)))
    p.add(k, kontron(0, 0, ipmb(0x00, 6, 0x81, 3, 0x01)))
    p.write(os.path.join(out, 'i2c-coverage.pcapng'))

    m = Pcapng(); a = m.add_if(LINUX); k = m.add_if(KONTRON)
    # Data frame with only the pseudo header (nothing to read the address from)
    m.add(a, lin(0, 0))
    # Kontron frames too short for the address and for the IPMB message
    m.add(k, bytes([1]))
    m.add(k, bytes([2, 1]))
    m.add(k, bytes([3, 1, 0x20]))
    m.add(k, bytes([4, 1, 0x20, 0x18]))
    m.write(os.path.join(out, 'i2c-coverage-malformed.pcapng'))

main(sys.argv[1])
