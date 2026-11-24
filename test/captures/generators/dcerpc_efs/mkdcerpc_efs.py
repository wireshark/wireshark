#!/usr/bin/env python3
# Generates test/captures/dcerpc_efs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EFS DCE/RPC dissector
(packet-dcerpc-efs.c, Encrypting File System Remote Protocol, generated
by Pidl from efs.idl and efs.cnf).

Connection-oriented DCE/RPC over TCP: a client binds to the EFS
interface (c681d488-d850-11d0-8c52-00c04fd90f7e version 1.0) and sends
requests for every opnum 0-13; the server answers each. The DCE/RPC
heuristic on TCP finds the PDUs, so no Decode As is needed. Every packet
is built from scratch with struct (rpcgen.py); no captured traffic is
used. A fourth connection holds the reproducer of "EFS: Dissect a user
SID as an NDR RPC_SID" (efs_sid_conformance.py) unchanged.

Usage: mkdcerpc_efs.py <output directory>

Writes:
  dcerpc_efs-coverage.pcap            NDR little endian, big endian and
                                      NDR64 connections, every opnum,
                                      and the reproducer
  dcerpc_efs-coverage-malformed.pcap  stubs cut short
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from rpcgen import TCP, RPC, NDR, pcap  # noqa: E402

UUID_EFS = 'c681d488-d850-11d0-8c52-00c04fd90f7e'
VER = (1, 0)
FILE = 'C:\\Users\\alice\\secret.txt'


def sid(n, auth, subs):
    """RPC_SID: max_count of the sub-authorities, then the SID. The
    sub-authorities follow the data representation; dissect_nt_sid()
    always reads them little endian."""
    n.count(len(subs))
    n.u8(1)
    n.u8(len(subs))
    n.raw(struct.pack('>Q', auth)[2:])
    for s in subs:
        n.u32(s)


def hash_list(n, entries):
    """ENCRYPTION_CERTIFICATE_HASH_LIST behind a unique pointer: the
    conformance first, nCert_Hash, the pointer array, then each entry
    with its own deferred SID, hash blob and display name"""
    n.count(len(entries))
    n.u32(len(entries))
    for e in entries:
        n.ptr(e is not None)
    if n.ndr64:
        n.align(8)
    for e in entries:
        if e is None:
            continue
        user_sid, blob, name = e
        if n.ndr64:
            n.align(8)
        n.u32(64)                       # cbTotalLength
        n.ptr(user_sid is not None)
        n.ptr(blob is not None)
        n.ptr(name is not None)
        if n.ndr64:
            n.align(8)
        if user_sid is not None:
            sid(n, *user_sid)
        if blob is not None:
            if n.ndr64:
                n.align(8)
            n.u32(len(blob) if blob else 0)
            n.ptr(bool(blob))
            if n.ndr64:
                n.align(8)
            if blob:
                n.count(len(blob))
                n.raw(blob)
        if name is not None:
            n.wstr(name)


def efs_calls(rpc, le, ndr64, extra, hid):
    HANDLE = bytes([0, 0, 0, 0, hid]) + bytes(range(0x31, 0x40))
    def N():
        return NDR(le, ndr64)

    def status(st):
        r = N()
        r.u32(st)
        return r.bytes()

    # 0 EfsRpcOpenFileRaw: export and import flags
    for flags, st in ((0, 0), (1, 0), (2, 5)):
        q = N()
        q.wstr(FILE)
        q.u32(flags)
        r = N()
        r.handle(HANDLE if st == 0 else bytes(20))
        r.u32(st)
        rpc.call(0, q.bytes(), r.bytes())
    # 1 EfsRpcReadFileRaw, 2 EfsRpcWriteFileRaw (only the handle)
    for op in (1, 2):
        for st in (0, 0x00000006):      # WERR_INVALID_HANDLE
            q = N()
            q.handle(HANDLE)
            rpc.call(op, q.bytes(), status(st))
    # 3 EfsRpcCloseRaw
    q = N()
    q.handle(HANDLE)
    r = N()
    r.handle(bytes(20))
    rpc.call(3, q.bytes(), r.bytes())
    # 4 EfsRpcEncryptFileSrv, 5 EfsRpcDecryptFileSrv
    for st in (0, 0x00001770):          # ERROR_ENCRYPTION_FAILED
        q = N()
        q.wstr(FILE)
        rpc.call(4, q.bytes(), status(st))
    for st in (0, 0x00001771):
        q = N()
        q.wstr(FILE)
        q.u32(0)
        rpc.call(5, q.bytes(), status(st))
    # 6 EfsRpcQueryUsersOnFile: two users (one with every pointer, one
    # with NULL SID, an empty hash and no name) and a NULL entry
    q = N()
    q.wstr(FILE)
    r = N()
    r.ptr(True)
    hash_list(r, [((5, [21, 1111, 2222, 3333, 1001]), bytes(range(20)), 'Alice (alice@example.com)'),
                  (None, b'', None),
                  None])
    r.u32(0)
    rpc.call(6, q.bytes(), r.bytes())
    # 6 with no list
    q = N()
    q.wstr('D:\\x')
    r = N()
    r.ptr(False)
    r.u32(0x00000002)                   # WERR_FILE_NOT_FOUND
    rpc.call(6, q.bytes(), r.bytes())
    # 7 EfsRpcQueryRecoveryAgents: one agent; then an empty list and an
    # error
    q = N()
    q.wstr(FILE)
    r = N()
    r.ptr(True)
    hash_list(r, [((5, [21, 1111, 2222, 3333, 500]), bytes(range(0x80, 0x94)), 'Recovery Agent')])
    r.u32(0)
    rpc.call(7, q.bytes(), r.bytes())
    q = N()
    q.wstr(FILE)
    r = N()
    r.ptr(True)
    hash_list(r, [])
    r.u32(0x0000000d)                   # WERR_INVALID_DATA
    rpc.call(7, q.bytes(), r.bytes())
    # 8 EfsRpcRemoveUsersFromFile, 9 EfsRpcAddUsersToFile (file name only)
    for op in (8, 9):
        for st in (0, 5):
            q = N()
            q.wstr(FILE)
            rpc.call(op, q.bytes(), status(st))
    # 10 EfsRpcSetFileEncryptionKey: a certificate with SID and blob,
    # one with NULL members, and a NULL certificate
    for case in ('full', 'empty', 'null'):
        q = N()
        q.ptr(case != 'null')
        if case != 'null':
            if ndr64:
                q.align(8)
            q.u32(100)
            q.ptr(case == 'full')
            q.ptr(case == 'full')
            if ndr64:
                q.align(8)
            if case == 'full':
                sid(q, 5, [32, 544])
                if ndr64:
                    q.align(8)
                q.u32(1)                # X509_ASN_ENCODING
                q.u32(8)
                q.ptr(True)
                if ndr64:
                    q.align(8)
                q.count(8)
                q.raw(b'\x30\x06\x02\x01\x01\x02\x01\x02')
        rpc.call(10, q.bytes(), status(0 if case == 'full' else 0x00000057))
    # 11 EfsRpcNotSupported, 12 EfsRpcFileKeyInfo,
    # 13 EfsRpcDuplicateEncryptionInfoFile (no parameters)
    for op in (11, 12, 13):
        rpc.call(op, b'', status(0x00000032))   # WERR_NOT_SUPPORTED
    if extra:
        rpc.call(14, b'\0' * 8, b'\0' * 4)


def reproducer(F):
    """efs_sid_conformance.py: EfsRpcQueryUsersOnFile response with one
    ENCRYPTION_CERTIFICATE_HASH whose pUserSid is S-1-5-21-1-2-3-500,
    hash and display name NULL"""
    sid_ = struct.pack('<I', 5) + struct.pack('<BB', 1, 5) + b'\0\0\0\0\0\x05' + \
        struct.pack('<5I', 21, 1, 2, 3, 500)
    s = struct.pack('<I', 0x00020000)
    s += struct.pack('<II', 1, 1)
    s += struct.pack('<I', 0x00020004)
    s += struct.pack('<IIII', 64, 0x00020008, 0, 0)
    s += sid_
    s += struct.pack('<I', 0)
    req = struct.pack('<III', 2, 0, 2) + 'a'.encode('utf-16-le') + b'\0\0'
    t = TCP(F, 50601)
    r = RPC(t, UUID_EFS, VER)
    r.bind()
    r.call(6, req, s)
    t.fin()


def main_frames():
    F = []
    for cport, le, ndr64 in ((50001, True, False), (50002, False, False), (50003, True, True)):
        t = TCP(F, cport)
        rpc = RPC(t, UUID_EFS, VER, le, ndr64)
        rpc.bind()
        efs_calls(rpc, le, ndr64, cport == 50001, cport - 50000)
        t.fin()
    reproducer(F)
    return F


def malformed_frames():
    F = []
    t = TCP(F, 50101)
    rpc = RPC(t, UUID_EFS, VER)
    rpc.bind()
    # QueryUsersOnFile response announcing three entries, one present
    r = NDR()
    r.ptr(True)
    r.u32(3)
    r.u32(3)
    r.ptr(True)
    rpc.call(6, b'\0' * 12, r.bytes())
    # a SID with more sub-authorities than octets
    r = NDR()
    r.ptr(True)
    r.u32(1)
    r.u32(1)
    r.ptr(True)
    r.u32(64)
    r.ptr(True)
    r.ptr(False)
    r.ptr(False)
    r.u32(15)
    r.raw(b'\x01\x0f\0\0\0\0\0\x05\x15\0\0\0')
    rpc.call(7, b'\0' * 12, r.bytes())
    # OpenFileRaw request whose file name is longer than the stub
    q = NDR()
    q.u32(100)
    q.u32(0)
    q.u32(100)
    q.raw(b'A\0')
    rpc.call(0, q.bytes(), b'\0' * 8)
    # SetFileEncryptionKey with a certificate blob longer than the stub
    q = NDR()
    q.ptr(True)
    q.u32(1)
    q.ptr(False)
    q.ptr(True)
    q.u32(1)
    q.u32(1000)
    q.ptr(True)
    q.u32(1000)
    q.raw(b'\x30')
    rpc.call(10, q.bytes(), None)
    t.fin()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_efs-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_efs-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
