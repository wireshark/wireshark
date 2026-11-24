#!/usr/bin/env python3
# Generates test/captures/dcerpc_frsrpc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the FRSRPC DCE/RPC
dissector (packet-dcerpc-frsrpc.c, File Replication Service, generated
by Pidl from frsrpc.idl and frsrpc.cnf).

Connection-oriented DCE/RPC over TCP: a client binds to the FRSRPC
interface (f5cc59b4-4264-101a-8c59-08002b2f8426 version 1.1) and sends a
request for every opnum; the server answers each. FrsSendCommPkt carries
communication packets with every chunk type. The DCE/RPC heuristic on TCP
finds the PDUs, so no Decode As is needed. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkdcerpc_frsrpc.py <output directory>

Writes:
  dcerpc_frsrpc-coverage.pcap            NDR little endian, big endian and
                                         NDR64 connections, every opnum,
                                         every chunk type, change orders
                                         with short, long and full-length
                                         file names, error status
                                         and the file name reproducer
                                         (frsrpc_filename_assert.py)
  dcerpc_frsrpc-coverage-malformed.pcap  the chunk size reproducer
                                         (frsrpc_chunk_loop.py), chunks
                                         and stubs cut short
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from covlib import TCP, RPC, NDR, pcap

UUID_FRSRPC = 'f5cc59b4-4264-101a-8c59-08002b2f8426'
VER_FRSRPC = (1, 1)

WERR_OK = 0
WERR_ACCESS_DENIED = 5
WERR_INVALID_PARAMETER = 87

G_TO = '11111111-2222-3333-4444-555555555555'
G_FROM = '66666666-7777-8888-9999-aaaaaaaaaaaa'
G_REPLICA = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'
G_CXTION = '01234567-89ab-cdef-0123-456789abcdef'


def guid(e, u):
    h = u.replace('-', '')
    return struct.pack(e + 'IHH', int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)) + bytes.fromhex(h[16:])


# ---------------------------------------------------------------- chunks
# The chunk container is a subcontext without NDR64 and without alignment;
# integers follow the byte order of the stub.

def chunk(e, typ, data):
    return struct.pack(e + 'HI', typ, len(data)) + data


def sub(e, data):
    """[subcontext(4)] inside a chunk"""
    return struct.pack(e + 'I', len(data)) + data


def guid_name(e, g, name):
    return sub(e, guid(e, g)) + sub(e, (name + '\0').encode('utf-16-le'))


def nttime(e, v):
    """NTTIME as dissect_ndr_nt_NTTIME() reads it: the low 32 bits first,
    each half in the byte order of the stub"""
    return struct.pack(e + 'II', v & 0xffffffff, v >> 32)


def gsvn(e, vsn, g):
    return struct.pack(e + 'Q', vsn) + guid(e, g)


def change_order(e, full, name, name_bytes=None):
    """frsrpc_CommPktChangeOrderCommand, 792 octets"""
    b = struct.pack(e + 'I', 0x1234 if full else 0)               # sequence_number
    b += struct.pack(e + 'I', 0x03743677 | 0x80000000 if full else 0)   # flags
    b += struct.pack(e + 'I', 0x00000007 | 0x100 if full else 0)  # iflags
    b += struct.pack(e + 'I', 0x00000018 if full else 0x00000099)  # status
    b += struct.pack(e + 'I', 0x00027f77 | 0x01000000 if full else 0)   # content_cmd
    b += struct.pack(e + 'I', 0x0000000f if full else 0x00000077)  # location_cmd
    b += struct.pack(e + '4I', 0x20, 3, 0x1233, 0)
    b += struct.pack(e + '6Q', 4096, 0, 0x100000001, 0x2000, 0x3000, 0x1000)
    b += struct.pack(e + '2I', 1, 2)
    for g in (G_TO, G_FROM, G_REPLICA, G_CXTION, G_TO, G_FROM):
        b += guid(e, g)
    b += struct.pack(e + '6Q', 7, 0, 0, 0, 0, 0)
    b += struct.pack(e + '4I', 0, 0, 0, 0)
    b += nttime(e, 0x01d9e5c4a1b2c3d4)                             # event_time
    nb = name_bytes if name_bytes is not None else name.encode('utf-16-le' if e == '<' else 'utf-16-be')
    b += struct.pack(e + 'H', len(nb))
    b += nb[:522] + b'\0' * (522 - len(nb[:522]))
    b += b'\0\0\0\0'                                               # padding1-4
    assert len(b) == 0x318
    return b


def checksum_ext(e, data):
    return struct.pack(e + 'II', 0x18, 1) + data


def retry_timeout_ext(e):
    return struct.pack(e + 'IIII', 0x18, 2, 3, 0) + nttime(e, 0x01d9e5c4a1b2c3d4)


def co_ext_win2k(e, major=0):
    return struct.pack(e + 'IHHII', 0x28, major, 1, 0x10, 0) + checksum_ext(e, bytes(range(16)))


def co_extension2(e, major=1):
    return (struct.pack(e + 'IHHIIII', 0x48, major, 2, 0x18, 0x30, 0, 0)
            + checksum_ext(e, bytes(range(16, 32))) + retry_timeout_ext(e))


LONG_NAME = 'dir\\' + 'longname' * 17           # 140 characters
FULL_NAME = 'F' * 261                           # fills the array, no NUL


def chunks_join(e):
    """A join: every chunk except the change order ones"""
    return b''.join([
        chunk(e, 0x0001, struct.pack(e + 'I', 0)),                       # BOP
        chunk(e, 0x0002, struct.pack(e + 'I', 0x00000122)),              # COMMAND START_JOIN
        chunk(e, 0x0003, guid_name(e, G_TO, 'DC1.example.test')),        # TO
        chunk(e, 0x0004, guid_name(e, G_FROM, 'DC2.example.test')),      # FROM
        chunk(e, 0x0005, guid_name(e, G_REPLICA, 'SYSVOL')),             # REPLICA
        chunk(e, 0x0008, guid_name(e, G_CXTION, '')),                    # CONNECTION
        chunk(e, 0x0006, sub(e, guid(e, G_CXTION))),                     # JOIN_GUID
        chunk(e, 0x0012, nttime(e, 0x01d9e5c4a1b2c3d4)),      # LAST_JOIN_TIME
        chunk(e, 0x0007, sub(e, gsvn(e, 0x123456789, G_FROM))),          # VVECTOR
        chunk(e, 0x0011, sub(e, nttime(e, 0x01d9e5c4a1b2c3d5))),  # JOIN_TIME
        chunk(e, 0x0014, sub(e, guid(e, G_REPLICA))),                    # REPLICA_VERSION_GUID
        chunk(e, 0x0018, guid(e, G_TO)),                                 # COMPRESSION_GUID
        chunk(e, 0x0013, struct.pack(e + 'I', 0xffffffff)),              # EOP
    ])


def chunks_remote_co(e, name, full, name_bytes=None):
    """A remote change order with its staging file data"""
    return b''.join([
        chunk(e, 0x0001, struct.pack(e + 'I', 0)),
        chunk(e, 0x0002, struct.pack(e + 'I', 0x00000218)),              # REMOTE_CO
        chunk(e, 0x0003, guid_name(e, G_TO, 'DC1')),
        chunk(e, 0x0004, guid_name(e, G_FROM, 'DC2')),
        chunk(e, 0x0005, guid_name(e, G_REPLICA, 'SYSVOL')),
        chunk(e, 0x0008, guid_name(e, G_CXTION, 'cxtion')),
        chunk(e, 0x000d, sub(e, change_order(e, full, name, name_bytes))),   # REMOTE_CO
        chunk(e, 0x0016, sub(e, co_ext_win2k(e, 0 if full else 7))),     # CO_EXT_WIN2K
        chunk(e, 0x0017, co_extension2(e, 1 if full else 0)),            # CO_EXTENSION_2
        chunk(e, 0x000e, sub(e, gsvn(e, 42, G_TO))),                     # GVSN
        chunk(e, 0x000f, sub(e, guid(e, G_FROM))),                       # CO_GUID
        chunk(e, 0x0010, struct.pack(e + 'I', 0x1234)),                  # CO_SEQUENCE_NUMBER
        chunk(e, 0x000a, struct.pack(e + 'Q', 65536)),                   # BLOCK_SIZE
        chunk(e, 0x000b, struct.pack(e + 'Q', 4096)),                    # FILE_SIZE
        chunk(e, 0x000c, struct.pack(e + 'Q', 0)),                       # FILE_OFFSET
        chunk(e, 0x0009, b'staging file data'),                          # BLOCK
        chunk(e, 0x0099, b'\x01\x02\x03'),                               # unknown type: blob
        chunk(e, 0x0013, struct.pack(e + 'I', 0xffffffff)),
    ])


def chunks_commands(e):
    """Every command once, and an unknown one"""
    out = b''
    for c in (0x218, 0x238, 0x250, 0x246, 0x244, 0x121, 0x122, 0x130, 0x128,
              0x148, 0x136, 0x228, 0x999):
        out += chunk(e, 0x0002, struct.pack(e + 'I', c))
    return out


def send_comm_pkt(n, ctr, major=0, minor=9):
    """FrsSendCommPkt request: frsrpc_FrsSendCommPktReq by value"""
    n.a5()
    n.u32(major)
    n.u32(minor)
    n.u32(1)                                    # cs_id
    n.u32(len(ctr) + 12 if ctr is not None else 12)   # memory_len
    n.u32(len(ctr) if ctr is not None else 0)  # pkt_len
    n.u32(0)                                    # upk_len

    def deferred():
        n.count(len(ctr))
        n.raw(ctr)
    n.ptr(None if ctr is None else deferred)
    n.u3264(0)                                  # data_name
    n.u3264(0)                                  # data_handle
    n.a5()
    n.flush()


def top_wstr(n, s):
    n.top(None if s is None else (lambda: n.wstr(s)))


def top_guid(n, g, e):
    def sc():
        n.count(16)
        n.raw(guid(e, g))
    n.top(None if g is None else sc)


TODO_OPS = [(4, 'FRSRPC_BACKUP_COMPLETE'), (5, 'FRSRPC_BACKUP_COMPLETE_5'),
            (6, 'FRSRPC_BACKUP_COMPLETE_6'), (7, 'FRSRPC_BACKUP_COMPLETE_7'),
            (8, 'FRSRPC_BACKUP_COMPLETE_8'), (9, 'FRSRPC_BACKUP_COMPLETE_9'),
            (10, 'FRSRPC_VERIFY_PROMOTION_PARENT_EX')]


def frsrpc_calls(rpc, le, ndr64):
    e = '<' if le else '>'

    def N():
        return NDR(le, ndr64)

    def werr(s):
        r = N()
        r.u32(s)
        return r.bytes()

    # 0 FrsSendCommPkt
    for ctr, minor, st in ((chunks_join(e), 9, WERR_OK),
                           (chunks_remote_co(e, 'scripts\\logon.cmd', True), 9, WERR_OK),
                           (chunks_remote_co(e, LONG_NAME, False), 4, WERR_OK),
                           (chunks_remote_co(e, FULL_NAME, True), 5, WERR_OK),
                           (chunks_commands(e), 0, WERR_OK),
                           (b'', 1, WERR_INVALID_PARAMETER),
                           (None, 0x10, WERR_ACCESS_DENIED)):
        q = N()
        send_comm_pkt(q, ctr, minor=minor)
        rpc.call(0, q.bytes(), werr(st))

    # 1 FrsVerifyPromotionParent
    q = N()
    top_wstr(q, 'EXAMPLE\\DC1$')
    top_wstr(q, 'secret')
    top_wstr(q, 'DOMAIN SYSTEM VOLUME (SYSVOL SHARE)')
    top_wstr(q, 'DOMAIN')
    q.u32(0)
    q.u32(16)
    rpc.call(1, q.bytes(), werr(WERR_OK))
    q = N()
    for i in range(4):
        top_wstr(q, None)
    q.u32(1)
    q.u32(0)
    rpc.call(1, q.bytes(), werr(WERR_ACCESS_DENIED))

    # 2 FrsStartPromotionParent
    q = N()
    top_wstr(q, 'EXAMPLE\\DC1$')
    top_wstr(q, 'secret')
    top_wstr(q, 'DOMAIN SYSTEM VOLUME (SYSVOL SHARE)')
    top_wstr(q, 'DOMAIN')
    top_wstr(q, 'cxtion')
    top_wstr(q, 'DC2.example.test')
    top_wstr(q, 'DC2$@EXAMPLE.TEST')
    q.u32(0)
    q.u32(16)
    top_guid(q, G_CXTION, e)
    top_guid(q, G_TO, e)
    top_guid(q, G_FROM, e)
    r = N()
    top_guid(r, G_REPLICA, e)
    r.u32(WERR_OK)
    rpc.call(2, q.bytes(), r.bytes())
    q = N()
    for i in range(7):
        top_wstr(q, None)
    q.u32(1)
    q.u32(16)
    top_guid(q, None, e)
    top_guid(q, None, e)
    top_guid(q, None, e)
    r = N()
    top_guid(r, None, e)
    r.u32(WERR_ACCESS_DENIED)
    rpc.call(2, q.bytes(), r.bytes())

    # 3 FrsNOP
    rpc.call(3, b'', werr(WERR_OK))
    rpc.call(3, b'', werr(WERR_ACCESS_DENIED))

    # 4-10 [todo] functions without arguments or result
    for op, name in TODO_OPS:
        rpc.call(op, b'', b'')


def main_frames():
    F = []
    for cport, le, ndr64 in ((50001, True, False), (50002, False, False), (50003, True, True)):
        t = TCP(F, cport)
        rpc = RPC(t, UUID_FRSRPC, VER_FRSRPC, le, ndr64)
        rpc.bind()
        frsrpc_calls(rpc, le, ndr64)
        if cport == 50001:
            # an opnum the interface does not have
            rpc.call(11, b'\0' * 8, b'\0' * 4)
        t.fin()
    # frsrpc_filename_assert.py: a REMOTE_CO chunk of 908 octets of 'A'
    # with no UTF-16 NUL in the file name (assertion before the fix; it
    # decodes with the fix)
    t = TCP(F, 50004)
    rpc = RPC(t, UUID_FRSRPC, VER_FRSRPC)
    rpc.bind()
    co = b'\x41' * 900 + b'\0' * 8
    rpc.call(0, repro_send_comm_pkt(struct.pack('<HI', 0x000D, len(co)) + co), struct.pack('<I', 0))
    t.fin()
    return F


def repro_send_comm_pkt(chunks):
    """frsrpc_common.py send_comm_pkt(): FrsSendCommPkt, NDR32 LE"""
    s = struct.pack('<6I', 0, 0, 1, len(chunks) + 12, len(chunks), 0)
    s += struct.pack('<I', 0x00020000)
    s += struct.pack('<II', 0, 0)
    s += struct.pack('<I', len(chunks)) + chunks
    return s


def malformed_frames():
    F = []
    t = TCP(F, 50101)
    rpc = RPC(t, UUID_FRSRPC, VER_FRSRPC)
    rpc.bind()
    # frsrpc_chunk_loop.py: a BOP chunk with size 0xfffffffa, which wrapped
    # the offset back to the start of the chunk (endless loop before the fix)
    rpc.call(0, repro_send_comm_pkt(struct.pack('<HI', 0x0001, 0xFFFFFFFA) + struct.pack('<I', 0)),
             struct.pack('<I', 0))
    # chunk cut in its header, chunk size beyond the packet
    rpc.call(0, repro_send_comm_pkt(b'\x01\x00\x04'), struct.pack('<I', 0))
    rpc.call(0, repro_send_comm_pkt(struct.pack('<HI', 0x0002, 0x100) + b'\0' * 4), struct.pack('<I', 0))
    # change order cut short inside its subcontext
    co = change_order('<', True, 'x')[:300]
    rpc.call(0, repro_send_comm_pkt(chunk('<', 0x000d, sub('<', co))), struct.pack('<I', 0))
    # guid/name subcontext sizes larger than the chunk
    rpc.call(0, repro_send_comm_pkt(chunk('<', 0x0003, struct.pack('<I', 64) + b'\0' * 8)),
             struct.pack('<I', 0))
    # StartPromotionParent with a GUID subcontext of 4 octets
    q = NDR()
    for i in range(7):
        q.u32(0)
    q.u32(0)
    q.u32(16)
    q.u32(0x20000)
    q.u32(4)
    q.raw(b'\0' * 4)
    rpc.call(2, q.bytes(), b'\0\0')
    t.fin()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_frsrpc-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_frsrpc-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
