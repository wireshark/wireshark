#!/usr/bin/env python3
# Generates test/captures/dcerpc_messenger_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Messenger DCE/RPC
dissector (packet-dcerpc-messenger.c, Microsoft Messenger Service,
NetrSendMessage).

Connection-oriented DCE/RPC over TCP with a bind (NDR little endian, big
endian and NDR64) and connectionless DCE/RPC over UDP (the dynamic UDP
endpoint the service also listens on). The DCE/RPC heuristics find the
PDUs, so no Decode As is needed. Every packet is built from scratch with
struct (dcelib.py); no captured traffic is used.

Usage: mkdcerpc_messenger.py <output directory>

Writes:
  dcerpc_messenger-coverage.pcap            NetrSendMessage calls
  dcerpc_messenger-coverage-malformed.pcap  stubs cut short
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from dcelib import CL, CO, NDR, TCP, pcap  # noqa: E402

UUID_MSG = '5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc'
VER_MSG = (1, 0)


def send(rpc, le, ndr64, server, client, message, status, nul=True):
    """[in][string][ref] char *server, *client, *message: top-level
    reference pointers, so only the conformant varying strings"""
    q = NDR(le, ndr64)
    q.cstr(server, nul)
    q.cstr(client, nul)
    q.cstr(message, nul)
    r = NDR(le, ndr64)
    r.u32(status)
    rpc.call(0, q.bytes(), r.bytes())


def messenger_calls(rpc, le, ndr64=False):
    send(rpc, le, ndr64, 'WORKSTATION1', 'ADMIN', 'The server will restart in 5 minutes.', 0)
    send(rpc, le, ndr64, 'PC2', 'ALICE', '', 0xc0000022)     # STATUS_ACCESS_DENIED
    send(rpc, le, ndr64, 'PC3', 'BOB', 'no terminating NUL', 0x00000103, nul=False)


def main_frames():
    F = []
    for cport, le, ndr64 in ((50001, True, False), (50002, False, False), (50003, True, True)):
        t = TCP(F, cport)
        rpc = CO(t, UUID_MSG, VER_MSG, le, ndr64)
        rpc.bind()
        messenger_calls(rpc, le, ndr64)
        if cport == 50001:
            # an opnum the interface does not have
            rpc.call(1, b'\0' * 8, b'\0' * 4)
        t.fin()
    rpc = CL(F, UUID_MSG, VER_MSG[0], True, cport=40001, sport=1029)
    messenger_calls(rpc, True)
    rpc = CL(F, UUID_MSG, VER_MSG[0], False, cport=40002, sport=1029)
    messenger_calls(rpc, False)
    return F


def malformed_frames():
    F = []
    t = TCP(F, 50101)
    rpc = CO(t, UUID_MSG, VER_MSG)
    rpc.bind()
    q = NDR()
    q.cstr('S')
    q.u32(100)                       # client: counts with no data
    q.u32(0)
    q.u32(100)
    q.raw(b'AB')
    rpc.call(0, q.bytes(), b'\0\0')  # status cut short
    t.fin()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_messenger-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_messenger-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
