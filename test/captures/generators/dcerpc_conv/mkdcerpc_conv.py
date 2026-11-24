#!/usr/bin/env python3
# Generates test/captures/dcerpc_conv_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CONV DCE/RPC dissector
(packet-dcerpc-conv.c, DCE/RPC Conversation Manager, the callback a
connectionless server makes to learn a client's sequence number).

Connectionless DCE/RPC over UDP (the transport conv is used on); the
DCE/RPC heuristic on UDP finds the packets, so no Decode As is needed.
Every packet is built from scratch with struct (dcelib.py); no captured
traffic is used.

Usage: mkdcerpc_conv.py <output directory>

Writes:
  dcerpc_conv-coverage.pcap            every opnum, little and big endian
  dcerpc_conv-coverage-malformed.pcap  stubs cut short
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from dcelib import CL, NDR, pcap  # noqa: E402

UUID_CONV = '333a2276-0000-0000-0d00-00809c000000'
VER_CONV = 3
ACT = 'a1b2c3d4-e5f6-4711-8899-aabbccddeeff'
CAS = '01234567-89ab-4cde-8f01-23456789abcd'
BOOT = 1700000000


def conv_calls(rpc, le):
    def N():
        return NDR(le)
    # who_are_you: activity UID and boot time; ok
    q = N()
    q.uuid(ACT)
    q.u32(BOOT)
    r = N()
    r.u32(42)
    r.u32(0)
    rpc.call(0, q.bytes(), r.bytes())
    # who_are_you: an error status
    q = N()
    q.uuid('00000000-0000-0000-0000-000000000000')
    q.u32(0)
    r = N()
    r.u32(0)
    r.u32(556613636)        # "Error returned from rpc service"
    rpc.call(0, q.bytes(), r.bytes())
    # who_are_you2: also returns the client address space UUID
    q = N()
    q.uuid(ACT)
    q.u32(BOOT + 60)
    r = N()
    r.u32(43)
    r.uuid(CAS)
    r.u32(0)
    rpc.call(1, q.bytes(), r.bytes())
    # who_are_you2 with a status that has no name
    q = N()
    q.uuid(CAS)
    q.u32(BOOT)
    r = N()
    r.u32(0xffffffff)
    r.uuid(ACT)
    r.u32(0x12345678)
    rpc.call(1, q.bytes(), r.bytes())
    # are_you_there, who_are_you_auth, who_are_you_auth_more: no stub
    # dissectors, the stub is shown as data
    for op in (2, 3, 4):
        q = N()
        q.uuid(ACT)
        q.u32(BOOT)
        r = N()
        r.u32(0)
        rpc.call(op, q.bytes(), r.bytes())


def main_frames():
    F = []
    for cport, le in ((40001, True), (40002, False)):
        rpc = CL(F, UUID_CONV, VER_CONV, le, cport=cport, sport=34567)
        conv_calls(rpc, le)
        if le:
            # an opnum the interface does not have
            rpc.call(5, b'\0' * 8, b'\0' * 4)
    return F


def malformed_frames():
    F = []
    rpc = CL(F, UUID_CONV, VER_CONV, cport=40101, sport=34567)
    q = NDR()
    q.raw(b'\x01' * 10)              # UUID cut short
    r = NDR()
    r.u32(1)                         # status missing
    rpc.call(0, q.bytes(), r.bytes())
    q = NDR()
    q.uuid(ACT)                      # boot time missing
    r = NDR()
    r.u32(1)
    r.raw(b'\x02' * 8)               # cas UUID cut short
    rpc.call(1, q.bytes(), r.bytes())
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_conv-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_conv-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
