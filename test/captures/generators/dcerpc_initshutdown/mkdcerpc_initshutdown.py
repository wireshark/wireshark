#!/usr/bin/env python3
# Generates test/captures/dcerpc_initshutdown_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the INITSHUTDOWN DCE/RPC
dissector (packet-dcerpc-initshutdown.c, Windows remote shutdown, generated
by Pidl from initshutdown.idl).

Connection-oriented DCE/RPC over TCP: a client binds to the INITSHUTDOWN
interface (894de0c0-0d55-11d3-a322-00c04fa321a1 version 1.0) and sends
requests for every opnum (Init, Abort, InitEx); the server answers each.
The DCE/RPC heuristic on TCP finds the PDUs, so no Decode As is needed.
Every packet is built from scratch with struct (dcelib.py); no captured
traffic is used.

Usage: mkdcerpc_initshutdown.py <output directory>

Writes:
  dcerpc_initshutdown-coverage.pcap            NDR little endian, big
                                               endian and NDR64
                                               connections, every opnum
                                               with NULL and non-NULL
                                               pointers, error status
  dcerpc_initshutdown-coverage-malformed.pcap  stubs cut short
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from dcelib import CO, TCP, NDR, pcap  # noqa: E402

UUID_INITSHUTDOWN = '894de0c0-0d55-11d3-a322-00c04fa321a1'
VER_INITSHUTDOWN = (1, 0)

WERR_ACCESS_DENIED = 5
WERR_SHUTDOWN_IN_PROGRESS = 0x45b
WERR_NO_SHUTDOWN_IN_PROGRESS = 0x45c


def u16ptr(n, v):
    """[unique] uint16 *: referent id, then the uint16 (deferred, but it
    is a top-level pointer, so it follows at once)"""
    n.ptr(v is not None)
    if v is not None:
        n.u16(v)


def string_large(n, s):
    """[unique] lsa_StringLarge *: length, size, [unique] *string, then
    the conformant varying UTF-16 string (no terminating NUL counted in
    length; size has room for it)"""
    n.ptr(s is not None)
    if s is None:
        return
    if n.ndr64:
        n.align(8)
    n.u16(2 * len(s))
    n.u16(2 * len(s) + 2)
    n.ptr(True)
    n.count(len(s) + 1)
    n.count(0)
    n.count(len(s))
    n.raw(s.encode('utf-16-le' if n.le else 'utf-16-be'))


def werror(le, ndr64, status):
    r = NDR(le, ndr64)
    r.u32(status)
    return r.bytes()


def initshutdown_calls(rpc, le, ndr64):
    def N():
        return NDR(le, ndr64)

    # Init: hostname and message, force apps and reboot
    q = N()
    u16ptr(q, 0x5c5c)
    string_large(q, 'System maintenance')
    q.u32(30)
    q.u8(1)
    q.u8(1)
    rpc.call(0, q.bytes(), werror(le, ndr64, 0))
    # Init: NULL pointers, no reboot; a shutdown is already running
    q = N()
    u16ptr(q, None)
    string_large(q, None)
    q.u32(0)
    q.u8(0)
    q.u8(0)
    rpc.call(0, q.bytes(), werror(le, ndr64, WERR_SHUTDOWN_IN_PROGRESS))
    # Init: empty message
    q = N()
    u16ptr(q, 0x0053)
    string_large(q, '')
    q.u32(0xffffffff)
    q.u8(0)
    q.u8(1)
    rpc.call(0, q.bytes(), werror(le, ndr64, WERR_ACCESS_DENIED))
    # Abort
    q = N()
    u16ptr(q, 0x5c5c)
    rpc.call(1, q.bytes(), werror(le, ndr64, 0))
    q = N()
    u16ptr(q, None)
    rpc.call(1, q.bytes(), werror(le, ndr64, WERR_NO_SHUTDOWN_IN_PROGRESS))
    # InitEx: planned, application, maintenance reason
    q = N()
    u16ptr(q, 0x5c5c)
    string_large(q, 'Installing updates')
    q.u32(600)
    q.u8(0)
    q.u8(1)
    q.u32(0x80040001)
    rpc.call(2, q.bytes(), werror(le, ndr64, 0))
    # InitEx: NULL pointers, user defined reason; error with no name
    q = N()
    u16ptr(q, None)
    string_large(q, None)
    q.u32(5)
    q.u8(1)
    q.u8(0)
    q.u32(0x40000000)
    rpc.call(2, q.bytes(), werror(le, ndr64, 0x0badc0de))


def main_frames():
    F = []
    for cport, le, ndr64 in ((50001, True, False), (50002, False, False), (50003, True, True)):
        t = TCP(F, cport)
        rpc = CO(t, UUID_INITSHUTDOWN, VER_INITSHUTDOWN, le, ndr64)
        rpc.bind()
        initshutdown_calls(rpc, le, ndr64)
        if cport == 50001:
            # an opnum the interface does not have
            rpc.call(3, b'\0' * 8, b'\0' * 4)
        t.fin()
    return F


def malformed_frames():
    F = []
    t = TCP(F, 50101)
    rpc = CO(t, UUID_INITSHUTDOWN, VER_INITSHUTDOWN)
    rpc.bind()
    # Init: message string announced longer than the stub; response
    # without the status
    q = NDR()
    u16ptr(q, 0x5c5c)
    q.ptr(True)
    q.u16(200)
    q.u16(202)
    q.ptr(True)
    q.u32(101)
    q.u32(0)
    q.u32(100)
    q.raw(b'A\0B\0')
    rpc.call(0, q.bytes(), b'\0\0')
    # Abort: pointer without the uint16
    q = NDR()
    q.ptr(True)
    rpc.call(1, q.bytes(), None)
    # InitEx without the reason
    q = NDR()
    u16ptr(q, None)
    string_large(q, None)
    q.u32(5)
    q.u8(1)
    q.u8(0)
    rpc.call(2, q.bytes(), None)
    t.fin()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_initshutdown-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_initshutdown-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
