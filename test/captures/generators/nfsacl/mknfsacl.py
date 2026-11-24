#!/usr/bin/env python3
# Generates test/captures/nfsacl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# mknfsacl.py <outdir> [-v]: writes nfsacl-coverage.pcap and nfsacl-coverage-malformed.pcap
# NFSACL (RPC program 100227, versions 1-3) over UDP/TCP, found by the RPC heuristics.
import struct
import sys
import os
import socket

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

CLI, SRV = '192.0.2.1', '192.0.2.2'
MC, MS = b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02'

def ethip(proto, payload, to_srv):
    src, dst = (CLI, SRV) if to_srv else (SRV, CLI)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return (MS + MC if to_srv else MC + MS) + b'\x08\x00' + ip + payload

def udp(payload, cport, to_srv, sport=2049):
    sp, dp = (cport, sport) if to_srv else (sport, cport)
    return ethip(17, struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload, to_srv)

class Tcp:
    def __init__(self, cport, sport=2049):
        self.c, self.s, self.cs, self.ss = cport, sport, 1000, 5000
    def seg(self, payload, to_srv, flags=0x18):
        if to_srv:
            sp, dp, seq, ack = self.c, self.s, self.cs, self.ss
            self.cs += len(payload)
        else:
            sp, dp, seq, ack = self.s, self.c, self.ss, self.cs
            self.ss += len(payload)
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0) + payload
        src, dst = (CLI, SRV) if to_srv else (SRV, CLI)
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(pseudo + t)) + t[18:]
        return ethip(6, t, to_srv)
    def handshake(self):
        a = self.seg(b'', True, 0x02); self.cs += 1
        b = self.seg(b'', False, 0x12); self.ss += 1
        c = self.seg(b'', True, 0x10)
        return [a, b, c]

def u32(v): return struct.pack('>I', v & 0xffffffff)
def u64(v): return struct.pack('>Q', v)
def opaque(b): return u32(len(b)) + b + b'\0' * ((4 - len(b) % 4) % 4)

def rpc_call(xid, vers, proc, args=b''):
    return struct.pack('>IIIIII', xid, 0, 2, 100227, vers, proc) + u32(0) * 4 + args

def rpc_reply(xid, res=b''):
    return struct.pack('>IIIIII', xid, 1, 0, 0, 0, 0) + res

def rm(b):  # TCP record mark
    return u32(0x80000000 | len(b)) + b

FH2 = bytes(range(32))
FH3 = bytes(range(0x40, 0x40 + 28))

def fattr2(ftype=1, mode=0o100644, size=4096):
    return struct.pack('>11I', ftype, mode, 1, 1000, 1000, size, 4096, 0, 8, 1, 4242) + struct.pack('>6I', 1700000000, 0, 1700000001, 5, 1700000002, 6)

def fattr3(ftype=1, mode=0o100644, size=4096):
    return (struct.pack('>5I', ftype, mode, 1, 1000, 1000) + u64(size) + u64(4096) + struct.pack('>II', 0, 0) +
            u64(1) + u64(4242) + struct.pack('>6I', 1700000000, 0, 1700000001, 5, 1700000002, 6))

def post_op(present=True):
    return u32(1) + fattr3() if present else u32(0)

def aclent(t, uid, perm): return u32(t) + u32(uid) + u32(perm)

def secattr(mask, acls, dfs):
    return (u32(mask) + u32(len(acls)) + u32(len(acls)) + b''.join(aclent(*a) for a in acls) +
            u32(len(dfs)) + u32(len(dfs)) + b''.join(aclent(*a) for a in dfs))

ACLS = [(0x1, 0xffffffff, 7), (0x2, 1000, 6), (0x4, 0xffffffff, 5), (0x8, 100, 4), (0x10, 0xffffffff, 3), (0x20, 0xffffffff, 1)]
DFS = [(0x1000 | 0x1, 0xffffffff, 7), (0x1000 | 0x2, 500, 2), (0x1000 | 0x4, 0xffffffff, 0), (0x1000 | 0x8, 77, 7),
       (0x1000 | 0x10, 0xffffffff, 5), (0x1000 | 0x20, 0xffffffff, 4), (0x1000, 0, 1), (0x40, 0, 6)]

def frames():
    fr, sec = [], []
    port = [40000]
    xid = [0x5000]
    def add(n, f):
        sec.append((n, len(fr) + 1, len(fr) + len(f)))
        fr.extend(f)
    def pair(vers, proc, call, reply):
        port[0] += 1; xid[0] += 1
        return [udp(rpc_call(xid[0], vers, proc, call), port[0], True),
                udp(rpc_reply(xid[0], reply), port[0], False)]
    ok = u32(0)
    # version 1 and the NULL procedures
    f = pair(1, 0, b'', b'') + pair(2, 0, b'', b'') + pair(3, 0, b'', b'')
    add("NULL v1-v3", f)
    # version 2
    f = []
    for mask in (0x0f, 0x01, 0x00, 0x0a):
        f += pair(2, 1, FH2 + u32(mask), ok + fattr2() + secattr(mask, ACLS, DFS))
    f += pair(2, 1, FH2 + u32(0x0f), u32(13))
    f += pair(2, 2, FH2 + secattr(0x0f, ACLS, DFS), ok + fattr2())
    f += pair(2, 1, FH2 + u32(0x0f), ok + fattr2() + secattr(0, [], []))
    f += pair(2, 2, FH2 + secattr(0x00, [], []), ok + fattr2())
    f += pair(2, 2, FH2 + secattr(0x0f, ACLS[:2], DFS[:1]), u32(1))
    f += pair(2, 3, FH2, fattr2(2, 0o40755, 512))
    for am in (0x1f, 0x01, 0x00):
        f += pair(2, 4, FH2 + u32(am), ok + fattr2() + u32(am))
    f += pair(2, 4, FH2 + u32(0x1f), ok + fattr2() + u32(0x07))
    f += pair(2, 4, FH2 + u32(0x3f), ok + fattr2() + u32(0x3f))
    f += pair(2, 4, FH2 + u32(0x1f), u32(13))
    f += pair(2, 5, FH2 + u32(1), ok + FH2[::-1] + fattr2(2, 0o40700, 0))
    f += pair(2, 5, FH2 + u32(0), u32(2))
    add("v2 GETACL/SETACL/GETATTR/ACCESS/GETXATTRDIR", f)
    # version 3
    f = []
    for mask in (0x0f, 0x03, 0x0c, 0x00):
        f += pair(3, 1, opaque(FH3) + u32(mask), ok + post_op() + secattr(mask, ACLS, DFS))
    f += pair(3, 1, opaque(FH3) + u32(0x0f), u32(13) + post_op())
    f += pair(3, 1, opaque(FH3) + u32(0x0f), u32(70) + post_op(False))
    f += pair(3, 2, opaque(FH3) + secattr(0x0f, ACLS, DFS), ok + post_op())
    f += pair(3, 1, opaque(FH3) + u32(0x0f), ok + post_op(False) + secattr(0, [], []))
    f += pair(3, 2, opaque(FH3) + secattr(0x00, [], []), ok + post_op(False))
    f += pair(3, 2, opaque(FH3) + secattr(0x03, ACLS[:3], []), u32(13) + post_op())
    f += pair(3, 3, opaque(FH3) + u32(1), ok + opaque(FH3[::-1]) + post_op())
    f += pair(3, 3, opaque(FH3) + u32(0), ok + opaque(b'') + post_op(False))
    f += pair(3, 3, opaque(FH3) + u32(1), u32(2))
    add("v3 GETACL/SETACL/GETXATTRDIR", f)
    # unknown procedures of each version are left to the RPC dissector
    f = pair(1, 7, b'', b'') + pair(2, 9, b'', b'') + pair(3, 4, b'', b'')
    add("unknown procedures", f)
    # over TCP with record marking (one call and reply of each version)
    t = Tcp(40500)
    f = t.handshake()
    for vers, proc, call, rep in (
            (2, 1, FH2 + u32(0x0f), ok + fattr2() + secattr(0x0f, ACLS, DFS)),
            (3, 1, opaque(FH3) + u32(0x0f), ok + post_op() + secattr(0x0f, ACLS, DFS)),
            (3, 2, opaque(FH3) + secattr(0x0f, ACLS, DFS), ok + post_op())):
        xid[0] += 1
        f.append(t.seg(rm(rpc_call(xid[0], vers, proc, call)), True))
        f.append(t.seg(rm(rpc_reply(xid[0], rep)), False))
    add("TCP", f)
    return fr, sec

def malformed():
    fr = []
    port = [41000]
    xid = [0x6000]
    def pair(vers, proc, call, reply):
        port[0] += 1; xid[0] += 1
        return [udp(rpc_call(xid[0], vers, proc, call), port[0], True),
                udp(rpc_reply(xid[0], reply), port[0], False)]
    ok = u32(0)
    # ACL counts past the data (the entry loops stop with an exception)
    huge = u32(0x0f) + u32(1) + u32(0xffffffff)
    fr += pair(2, 1, FH2 + u32(0x0f), ok + fattr2() + huge)
    fr += pair(2, 2, FH2 + huge, ok + fattr2())
    fr += pair(3, 1, opaque(FH3) + u32(0x0f), ok + post_op() + huge)
    fr += pair(3, 2, opaque(FH3) + huge, ok + post_op())
    fr += pair(3, 1, opaque(FH3) + u32(0x0f), ok + post_op() + u32(0x0f) + u32(2) + u32(2) + aclent(1, 0, 7) + aclent(2, 1, 6) + u32(0xfffffff0))
    fr += pair(2, 1, FH2 + u32(0x0f), ok + fattr2() + u32(0x0f) + u32(0) + u32(0))
    # truncated calls and replies of every procedure
    fr += pair(2, 1, FH2[:20], b'')
    fr += pair(2, 1, FH2, ok + fattr2()[:30])
    fr += pair(2, 2, FH2 + u32(0x0f) + u32(1) + u32(1) + aclent(1, 0, 7)[:6], ok)
    fr += pair(2, 3, FH2[:8], fattr2()[:20])
    fr += pair(2, 4, FH2, ok + fattr2() + b'')
    fr += pair(2, 5, FH2, ok + FH2[:10])
    fr += pair(2, 5, FH2 + b'\0\0', ok)
    fr += pair(3, 1, u32(5000) + b'\x01\x02', b'\x00\x00')
    fr += pair(3, 1, opaque(FH3), ok + u32(1) + fattr3()[:20])
    fr += pair(3, 2, opaque(FH3) + u32(0x0f) + u32(1) + u32(1) + aclent(1, 0, 7)[:8], ok + u32(1))
    fr += pair(3, 3, opaque(FH3), ok + opaque(FH3)[:10])
    fr += pair(3, 3, opaque(FH3), ok)
    return fr

def pcap(fname, pkts):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
fr, sec = frames()
pcap(os.path.join(out, 'nfsacl-coverage.pcap'), fr)
m = malformed()
pcap(os.path.join(out, 'nfsacl-coverage-malformed.pcap'), m)
if '-v' in sys.argv:
    for n, a, b in sec:
        print('%-46s frames %d-%d' % (n, a, b))
    print('main %d frames, malformed capture %d frames' % (len(fr), len(m)))
