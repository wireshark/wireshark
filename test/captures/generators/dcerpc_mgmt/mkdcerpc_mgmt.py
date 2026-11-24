#!/usr/bin/env python3
# Generates test/captures/dcerpc_mgmt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the MGMT DCE/RPC dissector
(packet-dcerpc-mgmt.c, DCE/RPC Remote Management interface that every
DCE/RPC server exports).

Connection-oriented DCE/RPC over TCP with a bind (NDR little endian, big
endian and NDR64) and connectionless DCE/RPC over UDP in both byte
orders. The DCE/RPC heuristics find the PDUs, so no Decode As is needed.
Only rpc__mgmt_inq_princ_name has stub dissectors; the other opnums are
shown by name with their stubs as data. Every packet is built from
scratch with struct (dcelib.py); no captured traffic is used.

Usage: mkdcerpc_mgmt.py <output directory>

Writes:
  dcerpc_mgmt-coverage.pcap            every opnum
  dcerpc_mgmt-coverage-malformed.pcap  stubs cut short
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from dcelib import CL, CO, NDR, TCP, pcap  # noqa: E402

UUID_MGMT = 'afa8bd80-7d8a-11c9-bef4-08002b102989'
VER_MGMT = (1, 0)


def mgmt_calls(rpc, le, ndr64=False):
    def N():
        return NDR(le, ndr64)
    # rpc__mgmt_inq_if_ids: no [in] arguments; an if_id_vector with one
    # interface (shown as stub data)
    r = N()
    r.ptr(True)
    r.u32(1)
    r.u32(1)
    r.ptr(True)
    r.uuid(UUID_MGMT)
    r.u16(1)
    r.u16(0)
    r.u32(0)
    rpc.call(0, b'', r.bytes())
    # rpc__mgmt_inq_stats: count 4, four statistics
    q = N()
    q.u32(4)
    r = N()
    r.u32(4)
    for v in (4, 100, 99, 7, 6):
        r.u32(v)
    r.u32(0)
    rpc.call(1, q.bytes(), r.bytes())
    # rpc__mgmt_is_server_listening
    r = N()
    r.u32(1)
    r.u32(0)
    rpc.call(2, b'', r.bytes())
    # rpc__mgmt_stop_server_listening: refused
    r = N()
    r.u32(0x16c9a0d6)
    rpc.call(3, b'', r.bytes())
    # rpc__mgmt_inq_princ_name: Kerberos (0x10), size 1024, a name
    q = N()
    q.u32(0x10)
    q.u32(1024)
    r = N()
    r.cstr('host/server.example.test@EXAMPLE.TEST')
    r.u32(0)
    rpc.call(4, q.bytes(), r.bytes())
    # rpc__mgmt_inq_princ_name: NTLM (0x0a), size 0, empty name and error
    q = N()
    q.u32(0x0a)
    q.u32(0)
    r = N()
    r.cstr('')
    r.u32(0xc0000022)
    rpc.call(4, q.bytes(), r.bytes())


def main_frames():
    F = []
    for cport, le, ndr64 in ((50001, True, False), (50002, False, False), (50003, True, True)):
        t = TCP(F, cport)
        rpc = CO(t, UUID_MGMT, VER_MGMT, le, ndr64)
        rpc.bind()
        mgmt_calls(rpc, le, ndr64)
        if cport == 50001:
            # an opnum the interface does not have
            rpc.call(5, b'\0' * 8, b'\0' * 4)
        t.fin()
    rpc = CL(F, UUID_MGMT, VER_MGMT[0], True, cport=40001, sport=135)
    mgmt_calls(rpc, True)
    rpc = CL(F, UUID_MGMT, VER_MGMT[0], False, cport=40002, sport=135)
    mgmt_calls(rpc, False)
    return F


def malformed_frames():
    F = []
    t = TCP(F, 50101)
    rpc = CO(t, UUID_MGMT, VER_MGMT)
    rpc.bind()
    q = NDR()
    q.u32(0x10)                      # princ size missing
    r = NDR()
    r.u32(50)                        # name counts, too few octets
    r.u32(0)
    r.u32(50)
    r.raw(b'host/')
    rpc.call(4, q.bytes(), r.bytes())
    r = NDR()
    r.cstr('x')                      # status missing
    rpc.call(4, b'\x10\0\0\0\0\4\0\0', r.bytes())
    t.fin()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_mgmt-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_mgmt-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
