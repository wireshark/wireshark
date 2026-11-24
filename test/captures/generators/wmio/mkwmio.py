#!/usr/bin/env python3
# Generates test/captures/wmio_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the WMIO dissector
(packet-wmio.c, MS-WMIO IWbemClassObject marshalling) beyond what
test/captures/dcerpc_iwbemservices_coverage.pcap.gz already covers (that
capture has the classes, qualifiers of every type, properties, methods
and the reproducers of earlier fixes; this one adds the nesting limit).

WMIO is reached through DCOM: a custom OBJREF with the IWbemClassObject
IID inside a DCE/RPC response (here the GetObject response of
IWbemServices, TCP with a bind; the DCE/RPC heuristic finds it, so no
Decode As). An object whose class method signature points at another
object recurses; since "WMIO: Bound object nesting" the nesting is
bounded by WMIO_MAX_OBJECT_DEPTH (32): the 33rd nested object gets the
"Object nesting too deep" expert info. Every packet is built from
scratch with struct (rpcgen.py, dcomgen.py are helpers copied from the
IWbemServices generator); no captured traffic is used.

Usage: mkwmio.py <output directory>

Writes:
  wmio-coverage.pcap            ordinary classes, chains of 2 and 5 objects,
                                chains of 32 and 31 objects (the deepest
                                allowed is 32) through the in/out signatures,
                                only the input signature of the parent class
                                or only the output signature of the class; a
                                chain of 33 (the expert info, the only one)
                                and the 300 object reproducer
  wmio-coverage-malformed.pcap  more chains past the limit through the other
                                routes, a truncated chain
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from rpcgen import TCP, RPC, pcap  # noqa: E402
from iwbem_gen import (UUID_IWBEMSERVICES, VER, getobject_request_plain,  # noqa: E402
                       getobject_response_wmio, service_class, plain_class,
                       instance_object, rp_classpart, rp_methodpart, bad_signature)

P = struct.pack


def chain_sigs(K, last_sigs=True):
    """K objects; the in and out method signatures of both the parent and
    the current class of each point at the next object (the layout of the
    exponential reproducer)."""
    MID = 4 + 1 + 29 + 36 + 29 + 36
    blob = b''
    for i in range(K):
        p = i * MID
        nxt = [] if i == K - 1 else [((i + 1) * MID, (i + 1) * MID)]
        o = P('<IB', 0, 0x01) + rp_classpart()
        o += rp_methodpart(p + len(o), nxt)
        o += rp_classpart()
        o += rp_methodpart(p + len(o), nxt)
        blob += o
    return P('<I', 0x12345678) + blob


def chain_parent(K):
    """K objects; only the input signature of the parent class's method
    points at the next object (the reproducer of the recursion bug: it
    reaches the next object once per level, not through the output
    signature or the current class)."""
    MID = 4 + 1 + 29 + 36 + 29 + 12
    blob = b''
    for i in range(K):
        p = i * MID
        o = P('<IB', 0, 0x01) + rp_classpart()
        if i == K - 1:
            o += rp_methodpart(p + len(o), [])
        else:
            heap = p + len(o) + 8 + 24 + 4
            nxt = (i + 1) * MID
            b = P('<IHH', 8 + 24 + 4, 1, 0)
            b += P('<IB3xIIii', 0xffffffff, 0, 0, 0, nxt - heap, 0)
            o += b + P('<I', 0)
        o += rp_classpart() + rp_methodpart(0, [])
        blob += o
    return P('<I', 0x12345678) + blob


def chain_out(K):
    """Like chain_sigs but only the output signature of the current class
    points at the next object."""
    MID = 4 + 1 + 29 + 12 + 29 + 36
    blob = b''
    for i in range(K):
        p = i * MID
        o = P('<IB', 0, 0x01) + rp_classpart() + rp_methodpart(0, [])
        o += rp_classpart()
        if i == K - 1:
            o += rp_methodpart(p + len(o), [])
        else:
            heap = p + len(o) + 8 + 24 + 4
            nxt = (i + 1) * MID
            b = P('<IHH', 8 + 24 + 4, 1, 0)
            b += P('<IB3xIIii', 0xffffffff, 0, 0, 0, 0, nxt - heap)
            o += b + P('<I', 0)
        blob += o
    return P('<I', 0x12345678) + blob


def conn(F, port, payloads, le=True):
    t = TCP(F, port)
    r = RPC(t, UUID_IWBEMSERVICES, VER, le)
    r.bind()
    for pl in payloads:
        r.call(6, getobject_request_plain(), getobject_response_wmio(pl))
    t.fin()


def main_frames():
    F = []
    conn(F, 50701, [service_class(), plain_class(), instance_object(), bad_signature(),
                    chain_sigs(1), chain_sigs(2), chain_sigs(5), chain_parent(5), chain_out(5)])
    conn(F, 50702, [chain_sigs(32), chain_parent(32), chain_out(32)])
    conn(F, 50703, [chain_parent(31), chain_out(31), chain_sigs(31)])
    # past the limit: the expert info (the only one in this capture) and,
    # as in the reproducer of the recursion bug, a chain of 300 objects
    conn(F, 50704, [chain_parent(33), chain_parent(300)])
    return F


def malformed_frames():
    F = []
    conn(F, 50711, [chain_sigs(33), chain_out(33)])
    conn(F, 50712, [chain_sigs(34), chain_parent(40)])
    conn(F, 50714, [chain_parent(40)[:-30]])
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'wmio-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'wmio-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
