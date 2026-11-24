#!/usr/bin/env python3
# Generates test/captures/dcerpc_epm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EPM DCE/RPC dissector
(packet-dcerpc-epm.c, DCE/RPC Endpoint Mapper, interface versions 3
and 4).

Connection-oriented DCE/RPC over TCP port 135 (bind/bind_ack, then
requests and responses; NDR little endian, big endian and NDR64) and
connectionless DCE/RPC over UDP port 135 (EPM v4 little endian, EPM v3
big endian). Every opnum is called; the towers carry every floor
protocol the dissector knows. Every packet is built from scratch with
struct (dcelib.py); no captured traffic is used.

Usage: mkdcerpc_epm.py <output directory>

Writes:
  dcerpc_epm-coverage.pcap            every opnum and floor protocol
  dcerpc_epm-coverage-malformed.pcap  stubs cut short and the
                                      annotation length reproducer of
                                      "EPM: Do not let an annotation
                                      length move back, fix the replace
                                      field" (epm_annlen.py)
"""

import os
import struct
import sys
from dcelib import CL, CO, NDR, TCP, pcap, uuid_bytes  # noqa: E402

UUID_EPM = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa'
UUID_NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
UUID_NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'
UUID_LSA = '12345778-1234-abcd-ef00-0123456789ab'      # lsarpc v0
UUID_UNKNOWN = '0b0a0908-0706-4504-8302-010000ff00ee'
OBJ = '9e1c8d04-3b2e-4c59-8a71-5d2f00a1b2c3'
HND0 = b'\0' * 20
HND1 = struct.pack('<I', 0) + uuid_bytes('5b1f3d2e-4a6c-4f8e-9d0b-1c2e3f405162')


# ------------------------------------------------------------- towers
def floor(lhs, rhs):
    return struct.pack('<H', len(lhs)) + lhs + struct.pack('<H', len(rhs)) + rhs


def uuid_floor(u, major_bytes, minor):
    """Protocol 0x0d: UUID and major version on the left, minor version
    on the right. The dissector reads the major version as big endian."""
    return floor(b'\x0d' + uuid_bytes(u) + major_bytes, struct.pack('<H', minor))


def tower(*floors):
    return struct.pack('<H', len(floors)) + b''.join(floors)


F_EPM_LE = uuid_floor(UUID_EPM, b'\x03\x00', 0)        # usual encoding
F_EPM_BE = uuid_floor(UUID_EPM, b'\x00\x03', 0)        # matches EPM v3
F_LSA = uuid_floor(UUID_LSA, b'\x00\x00', 0)           # lsarpc v0
F_UNKNOWN = uuid_floor(UUID_UNKNOWN, b'\x02\x01', 7)
F_NDR = uuid_floor(UUID_NDR, b'\x02\x00', 0)
F_NDR64 = uuid_floor(UUID_NDR64, b'\x01\x00', 0)
F_CO = floor(b'\x0b', struct.pack('<H', 0))
F_CL = floor(b'\x0a', struct.pack('<H', 0))
F_TCP = floor(b'\x07', struct.pack('>H', 49155))
F_TCP135 = floor(b'\x07', struct.pack('>H', 135))
F_UDP = floor(b'\x08', struct.pack('>H', 49156))
F_IP = floor(b'\x09', bytes((192, 0, 2, 60)))
F_IP0 = floor(b'\x09', bytes(4))
F_NP = floor(b'\x0f', b'\\PIPE\\lsass\0')
F_NETBIOS = floor(b'\x11', b'\\\\SERVER\0')
F_LRPC = floor(b'\x10', b'LRPC-0123456789abcdef01\0')
F_HTTP = floor(b'\x1f', struct.pack('>H', 593))

T_TCP = tower(F_EPM_LE, F_NDR, F_CO, F_TCP135, F_IP0)        # ncacn_ip_tcp
T_TCP_LSA = tower(F_LSA, F_NDR, F_CO, F_TCP, F_IP)
T_UDP = tower(F_EPM_BE, F_NDR, F_CL, F_UDP, F_IP)            # ncadg_ip_udp
T_NP = tower(F_LSA, F_NDR, F_CO, F_NP, F_NETBIOS)            # ncacn_np
T_LRPC = tower(F_UNKNOWN, F_NDR64, F_CO, F_LRPC)             # ncalrpc
T_HTTP = tower(F_LSA, F_NDR, F_CO, F_HTTP, F_IP)             # ncacn_http
# every other protocol identifier, with an empty right hand side, and an
# identifier the dissector does not know
OTHER_IDS = (0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0c, 0x0e, 0x12, 0x13,
             0x14, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x20, 0x21,
             0x22, 0x30)
T_OTHER = tower(F_UNKNOWN, F_NDR, *[floor(bytes([i]), b'') for i in OTHER_IDS])
# OSI TP4 with a right hand side the dissector does not decode (a
# "RightHandSide not decoded yet" warning)
T_TP4 = tower(F_LSA, F_NDR, F_CO, floor(b'\x05', b'TSEL'))
T_EMPTY = tower()


def put_tower(n, t):
    """twr_t: conformance, tower_length, octets"""
    n.count(len(t))
    n.u32(len(t))
    n.raw(t)


# ------------------------------------------------------------- entries
def put_entries(n, entries, varying):
    """ept_entry_t array: object, tower pointer, annotation (offset,
    length, characters); the towers follow the array."""
    n.count(len(entries))
    if varying:
        n.count(0)
        n.count(len(entries))
    for obj, t, ann in entries:
        n.uuid(obj)
        n.ptr(t is not None)
        n.u32(0)
        a = ann.encode() + b'\0' if ann else b''
        n.u32(len(a))
        n.raw(a)
    for obj, t, ann in entries:
        if t is not None:
            put_tower(n, t)


ENTRIES = [
    (OBJ, T_TCP_LSA, 'LSA access'),
    ('00000000-0000-0000-0000-000000000000', T_NP, ''),
    ('00000000-0000-0000-0000-000000000000', None, 'no tower'),
    (OBJ, T_HTTP, 'RPC over HTTP'),
]


def epm_calls(rpc, le, ndr64, full=True):
    def N():
        return NDR(le, ndr64)

    def R():
        # response referent IDs above those of the request
        return NDR(le, ndr64, ref=0x00040000)

    # Insert: four entries, replace = 256 (a 32 bit field)
    q = N()
    q.u32(len(ENTRIES))
    put_entries(q, ENTRIES, False)
    q.u32(256)
    r = R()
    r.u32(0)
    rpc.call(0, q.bytes(), r.bytes())
    # Insert: no entries, replace = 0; error status
    q = N()
    q.u32(0)
    q.count(0)
    q.u32(0)
    r = R()
    r.u32(0x16c9a0d6)          # ept_s_not_registered
    rpc.call(0, q.bytes(), r.bytes())
    # Delete: one entry with an LRPC tower
    q = N()
    q.u32(1)
    put_entries(q, [(OBJ, T_LRPC, 'local')], False)
    r = R()
    r.u32(0)
    rpc.call(1, q.bytes(), r.bytes())
    # Lookup: every inquiry type, with and without object and interface
    for inq, obj, ifid in ((0, None, None), (1, None, (UUID_LSA, 0, 0)),
                           (2, OBJ, None), (3, OBJ, (UUID_EPM, 3, 0))):
        q = N()
        q.u32(inq)
        q.ptr(obj is not None)
        if obj:
            q.uuid(obj)
        q.ptr(ifid is not None)
        if ifid:
            q.uuid(ifid[0])
            q.u16(ifid[1])
            q.u16(ifid[2])
        q.u32(1)                 # version option
        q.raw(HND0 if inq == 0 else HND1)
        q.u32(500)
        r = R()
        if inq == 0:
            r.raw(HND1)
            r.u32(len(ENTRIES))
            put_entries(r, ENTRIES, True)
            r.u32(0)
        else:
            r.raw(HND0)
            r.u32(0)
            r.count(0)
            r.count(0)
            r.count(0)
            r.u32(0x16c9a0d6)
        rpc.call(2, q.bytes(), r.bytes())
    # Map: TCP tower in, two towers out
    for obj, t, outs in ((None, T_TCP_LSA, [T_TCP_LSA, T_NP]),
                         (OBJ, T_UDP, [T_UDP, None, T_LRPC]),
                         (None, T_OTHER, [T_OTHER, T_TP4]),
                         (None, T_HTTP, [T_HTTP, T_EMPTY, T_TCP]),
                         (None, None, [])):
        q = N()
        q.ptr(obj is not None)
        if obj:
            q.uuid(obj)
        q.ptr(t is not None)
        if t is not None:
            put_tower(q, t)
        q.raw(HND0)
        q.u32(4)
        r = R()
        r.raw(HND1 if outs else HND0)
        r.u32(len(outs))
        r.count(4)
        r.count(0)
        r.count(len(outs))
        for o in outs:
            r.ptr(o is not None)
        for o in outs:
            if o is not None:
                put_tower(r, o)
        r.u32(0 if outs else 0x16c9a0d6)
        rpc.call(3, q.bytes(), r.bytes())
        if not full:
            break
    # LookupHandleFree
    q = N()
    q.raw(HND1)
    r = R()
    r.raw(HND0)
    r.u32(0)
    rpc.call(4, q.bytes(), r.bytes())
    # InqObject, MgmtDelete: no stub dissectors
    q = N()
    q.raw(HND0)
    r = R()
    r.uuid(OBJ)
    r.u32(0)
    rpc.call(5, q.bytes(), r.bytes())
    q = N()
    q.u32(1)
    q.ptr(True)
    q.uuid(OBJ)
    r = R()
    r.u32(0)
    rpc.call(6, q.bytes(), r.bytes())


def main_frames():
    F = []
    # CO over TCP 135: NDR little endian, big endian, NDR64
    for cport, le, ndr64 in ((50001, True, False), (50002, False, False), (50003, True, True)):
        t = TCP(F, cport, sport=135)
        rpc = CO(t, UUID_EPM, (3, 0), le, ndr64)
        rpc.bind()
        epm_calls(rpc, le, ndr64, full=(cport != 50003))
        if cport == 50001:
            rpc.call(7, b'\0' * 8, b'\0' * 4)    # unknown opnum
        t.fin()
    # CL over UDP 135: EPM v4 little endian, EPM v3 big endian
    rpc = CL(F, UUID_EPM, 4, True, cport=40001, sport=135)
    epm_calls(rpc, True, False)
    rpc = CL(F, UUID_EPM, 3, False, cport=40002, sport=135)
    epm_calls(rpc, False, False, full=False)
    return F


def malformed_frames():
    F = []
    # Reproducer of the annotation length fix (epm_annlen.py): Insert with
    # annotation length 0xffffffff; with the fix it throws instead of
    # moving the offset back.
    rpc = CL(F, UUID_EPM, 3, True, cport=40101, sport=135)
    stub = (struct.pack('<I', 1) + struct.pack('<I', 1) + b'\x11' * 16 +
            struct.pack('<III', 0, 0, 0xffffffff) + b'svc\0' + struct.pack('<I', 0x12345678))
    rpc.call(0, stub, None)
    # annotation longer than the stub
    q = NDR()
    q.u32(1)
    q.u32(1)
    q.uuid(OBJ)
    q.u32(0)
    q.u32(0)
    q.u32(100)
    q.raw(b'short\0')
    rpc.call(0, q.bytes(), None)
    # tower with more floors than data
    q = NDR()
    q.ptr(False)
    q.ptr(True)
    t = struct.pack('<H', 5) + F_CO
    put_tower(q, t)
    rpc.call(3, q.bytes(), None)
    # Map response: tower array cut short
    r = NDR()
    r.raw(HND1)
    r.u32(2)
    r.u32(4)
    r.u32(0)
    r.u32(2)
    r.ptr(True)
    rpc.call(3, b'', r.bytes())
    # Lookup request without the handle
    q = NDR()
    q.u32(0)
    q.ptr(False)
    q.ptr(False)
    q.u32(0)
    rpc.call(2, q.bytes(), None)
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_epm-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_epm-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
