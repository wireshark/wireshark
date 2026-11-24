#!/usr/bin/env python3
# Generates test/captures/dcerpc_rfr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the RFR DCE/RPC dissector
(packet-dcerpc-rfr.c, Exchange 2003 Directory Request For Response,
[MS-OXABREF], interface 1544f5e0-613c-11d1-93df-00c04fd7bd09 v1.0).

Connection-oriented DCE/RPC over TCP with a bind, in NDR little endian,
big endian and NDR64. The DCE/RPC heuristics find the PDUs, so no Decode
As is needed. Every packet is built from scratch with struct (dcelib.py);
no captured traffic is used.

Usage: mkdcerpc_rfr.py <output directory>

Writes:
  dcerpc-rfr-coverage.pcap            both opnums, every pointer case
  dcerpc-rfr-coverage-malformed.pcap  stubs cut short, rfr_smoke.pcap
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from dcelib import CO, NDR, TCP, pcap  # noqa: E402
from repro import reproducer_dir

UUID_RFR = '1544f5e0-613c-11d1-93df-00c04fd7bd09'
VER_RFR = (1, 0)
USER_DN = '/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice'
SERVER_DN = '/o=Example/ou=Exchange Administrative Group/cn=Configuration/cn=Servers/cn=MBX1'
MAPI_E_NOT_FOUND = 0x8004010F
MAPI_E_LOGON_FAILED = 0x80040111


def strptr(n, s, unique_outer=True):
    """[unique] uint8 **: outer pointer, inner pointer, string.  s None is
    a NULL inner pointer, unique_outer False a NULL outer pointer."""
    n.ptr(unique_outer)
    if not unique_outer:
        return
    n.ptr(s is not None)
    if s is not None:
        n.cstr(s)


def rfr_calls(rpc, le, ndr64=False):
    def N():
        return NDR(le, ndr64)
    # RfrGetNewDSA: no suggested server, a DSA returned
    q = N()
    q.u32(0)
    q.cstr(USER_DN)
    strptr(q, None, False)
    strptr(q, None)
    r = N()
    strptr(r, None, False)
    strptr(r, 'dc1.example.test')
    r.u32(0)
    rpc.call(0, q.bytes(), r.bytes())
    # RfrGetNewDSA: unused and server strings present, MAPI_E_NOT_FOUND
    q = N()
    q.u32(1)
    q.cstr(USER_DN)
    strptr(q, '')
    strptr(q, 'dc2.example.test')
    r = N()
    strptr(r, '')
    strptr(r, None)
    r.u32(MAPI_E_NOT_FOUND)
    rpc.call(0, q.bytes(), r.bytes())
    # RfrGetFQDNFromLegacyDN: found
    q = N()
    q.u32(0)
    q.u32(len(SERVER_DN) + 1)
    q.cstr(SERVER_DN)
    r = N()
    r.ptr(True)
    r.cstr('mbx1.example.test')
    r.u32(0)
    rpc.call(1, q.bytes(), r.bytes())
    # RfrGetFQDNFromLegacyDN: no result, a status the dissector does not know
    q = N()
    q.u32(2)
    q.u32(10)
    q.cstr('/o=Ex/cn=X')
    r = N()
    r.ptr(False)
    r.u32(0x80070005)
    rpc.call(1, q.bytes(), r.bytes())


def main_frames():
    F = []
    for cport, le, ndr64 in ((50001, True, False), (50002, False, False), (50003, True, True)):
        t = TCP(F, cport)
        rpc = CO(t, UUID_RFR, VER_RFR, le, ndr64)
        rpc.bind()
        rfr_calls(rpc, le, ndr64)
        if cport == 50001:
            # A logon failure answered with a status only
            q = NDR()
            q.u32(0)
            q.u32(len(SERVER_DN) + 1)
            q.cstr(SERVER_DN)
            r = NDR()
            r.ptr(False)
            r.u32(MAPI_E_LOGON_FAILED)
            rpc.call(1, q.bytes(), r.bytes())
            # An opnum the interface does not have
            rpc.call(2, b'\0' * 8, b'\0' * 4)
        t.fin()
    return F


def read_pcap(path):
    d = open(path, 'rb').read()
    assert struct.unpack_from('<I', d, 20)[0] == 1
    off, out = 24, []
    while off < len(d):
        n = struct.unpack_from('<I', d, off + 8)[0]
        out.append(d[off + 16:off + 16 + n])
        off += 16 + n
    return out


REPRO = reproducer_dir(os.path.dirname(os.path.abspath(__file__)), ['rfr_smoke.py'])


def malformed_frames():
    F = []
    t = TCP(F, 50101)
    rpc = CO(t, UUID_RFR, VER_RFR)
    rpc.bind()
    calls = []

    class Rec:
        def call(self, op, q, r):
            calls.append((op, q, r))
    rfr_calls(Rec(), True)
    for op, q, r in calls:
        rpc.call(op, q[:-3], r[:-3])
    # String counts larger than the stub
    q = NDR()
    q.u32(0)
    q.u32(500)
    q.u32(0)
    q.u32(500)
    q.raw(b'/o=')
    rpc.call(0, q.bytes(), None)
    t.fin()
    # The review's smoke test: both opnums, then random stubs
    F += read_pcap(os.path.join(REPRO, 'rfr_smoke.pcap'))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc-rfr-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc-rfr-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
