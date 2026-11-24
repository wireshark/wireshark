#!/usr/bin/env python3
# Generates test/captures/nfsauth_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# mknfsauth.py <outdir> [-v]: writes nfsauth-coverage.pcap and nfsauth-coverage-malformed.pcap
# NFSAUTH (RPC program 100231, version 1) over UDP/TCP, found by the RPC heuristics.
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
    return struct.pack('>IIIIII', xid, 0, 2, 100231, vers, proc) + u32(0) * 4 + args

def rpc_reply(xid, res=b''):
    return struct.pack('>IIIIII', xid, 1, 0, 0, 0, 0) + res

def rm(b):  # TCP record mark
    return u32(0x80000000 | len(b)) + b


def frames():
    fr, sec = [], []
    port = [40000]
    xid = [0x7000]
    def add(n, f):
        sec.append((n, len(fr) + 1, len(fr) + len(f)))
        fr.extend(f)
    def pair(vers, proc, call, reply, tcp=None):
        xid[0] += 1
        c, r = rpc_call(xid[0], vers, proc, call), rpc_reply(xid[0], reply)
        if tcp:
            return [tcp.seg(rm(c), True), tcp.seg(rm(r), False)]
        port[0] += 1
        return [udp(c, port[0], True), udp(r, port[0], False)]
    # NULL; ACCESS has no decoder (the arguments and results are shown as data):
    # an XDR-looking request (netname, a path, uid, gid list, flavor) and short or odd bodies
    acc = opaque(b'client.example.net') + opaque(b'/export/home') + u32(1) + u32(1000) + u32(2) + u32(100) + u32(200)
    add("NULL and ACCESS", pair(1, 0, b'', b'') + pair(1, 1, acc, u32(0) + u32(7) + u32(1000)) +
        pair(1, 1, b'', b'') + pair(1, 1, b'\x01', b'\x01\x02\x03') + pair(1, 1, bytes(range(200)), bytes(range(100))))
    # unknown procedure, unknown versions (RPC program mismatch handling is in the RPC dissector)
    add("unknown procedure and versions", pair(1, 5, b'', b'') + pair(2, 1, acc, b'') + pair(7, 0, b'', b''))
    t = Tcp(40500)
    f = t.handshake() + pair(1, 0, b'', b'', t) + pair(1, 1, acc, u32(0) + u32(7), t)
    add("TCP", f)
    return fr, sec

def malformed():
    fr = []
    # truncated RPC after the program header: call without the credentials, reply cut short
    c = rpc_call(0x7100, 1, 1, b'')
    fr.append(udp(c[:30], 41001, True))
    fr.append(udp(c[:12], 41002, True))
    fr.append(udp(rpc_reply(0x7100)[:10], 41001, False))
    return fr

def pcap(fname, pkts):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
fr, sec = frames()
pcap(os.path.join(out, 'nfsauth-coverage.pcap'), fr)
m = malformed()
pcap(os.path.join(out, 'nfsauth-coverage-malformed.pcap'), m)
if '-v' in sys.argv:
    for n, a, b in sec:
        print('%-36s frames %d-%d' % (n, a, b))
    print('main %d frames, malformed capture %d frames' % (len(fr), len(m)))
