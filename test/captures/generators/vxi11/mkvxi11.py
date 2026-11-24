#!/usr/bin/env python3
# Generates test/captures/vxi11_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-vxi11.c (VXI-11 core, asynchronous
abort and interrupt channels, ONC RPC programs 0x0607af, 0x0607b0 and 0x0607b1).
    mkvxi11.py <outdir>
Writes vxi11-coverage.pcap and vxi11-coverage-malformed.pcap
RPC messages are found by the RPC heuristics (no portmapper needed): UDP
datagrams, and TCP with record marking.
"""
import struct
import socket
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

MAC_C = b'\x02\0\0\0\0\x01'
MAC_S = b'\x02\0\0\0\0\x02'
CLI = '192.0.2.1'
SRV = '192.0.2.2'

def ipv4(proto, payload, src, dst, ident=1, frag=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, frag, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def eth_ip(ip, from_client):
    d, s = (MAC_S, MAC_C) if from_client else (MAC_C, MAC_S)
    return d + s + b'\x08\x00' + ip

def udp(sp, dp, payload, from_client=True):
    src, dst = (CLI, SRV) if from_client else (SRV, CLI)
    u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    return eth_ip(ipv4(17, u, src, dst), from_client)

class Tcp:
    """One TCP connection, client port cp to server port sp."""
    def __init__(self, cp, sp):
        self.cp, self.sp = cp, sp
        self.cseq, self.sseq = 1000, 5000
    def seg(self, payload, from_client=True, flags=0x18):
        if from_client:
            sport, dport, seq, ack = self.cp, self.sp, self.cseq, self.sseq
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            sport, dport, seq, ack = self.sp, self.cp, self.sseq, self.cseq
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        src, dst = (CLI, SRV) if from_client else (SRV, CLI)
        if flags == 0x02: ack = 0
        opts = b'\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02\x01\x01' if flags & 2 else b''
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return eth_ip(ipv4(6, t, src, dst), from_client)
    def handshake(self):
        return [self.seg(b'', True, 0x02), self.seg(b'', False, 0x12), self.seg(b'', True, 0x10)]
    def close(self):
        return [self.seg(b'', False, 0x11), self.seg(b'', True, 0x11), self.seg(b'', False, 0x10)]

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000, len(fr), len(fr)))
            f.write(fr)

CORE, ASYNC, INTR = 0x0607AF, 0x0607B0, 0x0607B1

def opaque(b):
    return struct.pack('!I', len(b)) + b + b'\0' * (-len(b) % 4)

def string(s):
    return opaque(s if isinstance(s, bytes) else s.encode())

def call(xid, prog, proc, args, vers=1):
    return struct.pack('!IIIIII', xid, 0, 2, prog, vers, proc) + b'\0' * 16 + args

def reply(xid, res):
    return struct.pack('!III', xid, 1, 0) + b'\0' * 8 + struct.pack('!I', 0) + res

def u32(*v):
    return struct.pack('!%dI' % len(v), *v)

class Flow:
    """RPC calls and replies on one transport: UDP or TCP (record marking)."""
    def __init__(self, tcp_port=None, udp_port=40001, cport=40100):
        self.xid = 100
        self.frames = []
        self.cport = cport
        self.udp_port = udp_port
        self.tcp = Tcp(cport, tcp_port) if tcp_port else None
        if self.tcp:
            self.frames += self.tcp.handshake()
    def rm(self, msg):
        return struct.pack('!I', 0x80000000 | len(msg)) + msg
    def send(self, msg, from_client):
        if self.tcp:
            self.frames.append(self.tcp.seg(self.rm(msg), from_client))
            self.frames.append(self.tcp.seg(b'', not from_client, 0x10))
        elif from_client:
            self.frames.append(udp(self.cport, self.udp_port, msg, True))
        else:
            self.frames.append(udp(self.udp_port, self.cport, msg, False))
    def rpc(self, prog, proc, args, res, vers=1):
        self.xid += 1
        self.send(call(self.xid, prog, proc, args, vers), True)
        if res is not None:
            self.send(reply(self.xid, res), False)

def flags_args(lid, flags, io=1000, lock=2000):
    return u32(lid, flags, io, lock)

def main(outdir):
    out = []
    for tcp_port, cport in ((9010, 40100), (None, 40101)):
        fl = Flow(tcp_port, 9010 if tcp_port else 40001, cport)
        # NULL
        fl.rpc(CORE, 0, b'', b'')
        # CREATE_LINK: device name, lock, errors
        fl.rpc(CORE, 10, u32(1, 1, 5000) + string('inst0'), u32(0, 7, 0x12345678, 1024))
        fl.rpc(CORE, 10, u32(2, 0, 0) + string('gpib0,5'), u32(3, 0, 0, 0))
        # DEVICE_WRITE: every flag combination
        for i, flg in enumerate((0, 1, 8, 0x80, 0x89, 0x7e)):
            fl.rpc(CORE, 11, u32(7, 1000, 2000, flg) + opaque(b'*IDN?\n'), u32(0, 6))
        fl.rpc(CORE, 11, u32(7, 1000, 2000, 8) + opaque(b'x' * 150), u32(0, 150))
        fl.rpc(CORE, 11, u32(7, 1000, 2000, 8) + opaque(b''), u32(11, 0))
        # DEVICE_READ: flags, terminating character, reasons
        for flg, reason in ((0, 1), (0x80, 2), (8, 4), (0x88, 7), (0, 0), (0x81, 5)):
            fl.rpc(CORE, 12, u32(7, 100, 1000, 2000, flg, 0x0a) + b'',
                   u32(0, reason) + opaque(b'ACME,Model 1,0,1.0\n'))
        fl.rpc(CORE, 12, u32(7, 4096, 1000, 2000, 0, 0), u32(0, 4) + opaque(b'y' * 200))
        fl.rpc(CORE, 12, u32(7, 100, 1000, 2000, 0, 0), u32(15, 0) + opaque(b''))
        # field type reproducer: values that need all 32 bits
        fl.rpc(CORE, 12, u32(7, 100, 0, 0, 0x80, 0x41424344), u32(0, 4) + opaque(b'abcd'))
        # DEVICE_READSTB
        fl.rpc(CORE, 13, flags_args(7, 0), u32(0, 0x40))
        fl.rpc(CORE, 13, flags_args(7, 0), u32(0, 0x1234))
        fl.rpc(CORE, 13, flags_args(7, 0), u32(4, 0))
        # DEVICE_TRIGGER, CLEAR, REMOTE, LOCAL
        for proc in (14, 15, 16, 17):
            fl.rpc(CORE, proc, flags_args(7, 8), u32(0))
        fl.rpc(CORE, 14, flags_args(7, 0), u32(17))
        # DEVICE_LOCK / UNLOCK
        fl.rpc(CORE, 18, u32(7, 1, 3000), u32(0))
        fl.rpc(CORE, 18, u32(7, 0, 0), u32(11))
        fl.rpc(CORE, 19, u32(7), u32(0))
        fl.rpc(CORE, 19, u32(7), u32(12))
        # DEVICE_ENABLE_SRQ
        fl.rpc(CORE, 20, u32(7, 1) + opaque(b'handle-0001'), u32(0))
        fl.rpc(CORE, 20, u32(7, 0) + opaque(b''), u32(8))
        # DEVICE_DOCMD: every command and an unknown one
        for cmd in (0x020000, 0x020001, 0x020002, 0x020003, 0x020004, 0x02000a, 0x020010, 0x1234):
            fl.rpc(CORE, 22, u32(7, 8, 1000, 2000, cmd, 1, 4) + opaque(b'\x01\x02\x03\x04'),
                   u32(0) + opaque(b'\x00\x01'))
        fl.rpc(CORE, 22, u32(7, 0x80, 0, 0, 0x020001, 0, 0) + opaque(b''), u32(5) + opaque(b''))
        # DESTROY_LINK
        fl.rpc(CORE, 23, u32(7), u32(0))
        fl.rpc(CORE, 23, u32(8), u32(4))
        # CREATE_INTR_CHAN, DESTROY_INTR_CHAN
        fl.rpc(CORE, 25, bytes([192, 0, 2, 1]) + u32(40200, INTR, 1, 0), u32(0))
        fl.rpc(CORE, 25, bytes([192, 0, 2, 1]) + u32(40201, INTR, 1, 1), u32(29))
        fl.rpc(CORE, 26, b'', u32(0))
        fl.rpc(CORE, 26, b'', u32(6))
        # an unknown error code and an unknown procedure version/number
        fl.rpc(CORE, 19, u32(7), u32(99))
        # asynchronous abort channel
        fl.rpc(ASYNC, 0, b'', b'')
        fl.rpc(ASYNC, 1, u32(7), u32(0))
        fl.rpc(ASYNC, 1, u32(9), u32(23))
        # interrupt channel: SRQ callback, the reply carries no data
        fl.rpc(INTR, 0, b'', b'')
        fl.rpc(INTR, 30, opaque(b'handle-0001'), b'')
        fl.rpc(INTR, 30, opaque(b''), b'')
        if fl.tcp:
            fl.frames += fl.tcp.close()
        out += fl.frames
    # a TCP RPC call split over two segments, and two calls in one segment
    fl = Flow(9010, 0, 40102)
    msg = fl.rm(call(300, CORE, 11, u32(7, 1000, 2000, 8) + opaque(b'split write data\n')))
    fl.frames.append(fl.tcp.seg(msg[:30], True))
    fl.frames.append(fl.tcp.seg(msg[30:], True))
    fl.frames.append(fl.tcp.seg(fl.rm(reply(300, u32(0, 17))), False))
    m1 = fl.rm(call(301, CORE, 13, flags_args(7, 0)))
    m2 = fl.rm(call(302, CORE, 14, flags_args(7, 0)))
    fl.frames.append(fl.tcp.seg(m1 + m2, True))
    fl.frames.append(fl.tcp.seg(fl.rm(reply(301, u32(0, 0))) + fl.rm(reply(302, u32(0))), False))
    fl.frames += fl.tcp.close()
    out += fl.frames
    write_pcap(os.path.join(outdir, 'vxi11-coverage.pcap'), out)

    m = []
    fl = Flow(None, 40001, 40103)
    # Device_ReadResp whose data length (60) is larger than the data present
    fl.rpc(CORE, 12, u32(7, 100, 0, 0, 0x80, 0x41424344), u32(0, 4) + struct.pack('!II', 60, 0x61626364))
    # Device_WriteParms with a data length larger than the data present
    fl.rpc(CORE, 11, u32(7, 1000, 2000, 8) + struct.pack('!I', 300) + b'short', u32(0, 5))
    # truncated parameters and results
    fl.rpc(CORE, 10, u32(1, 1, 5000) + struct.pack('!I', 40) + b'abc', u32(0, 7))
    fl.rpc(CORE, 13, u32(7, 0), u32(0))
    fl.rpc(CORE, 12, u32(7, 100, 0, 0, 0, 0), u32(0))
    fl.rpc(CORE, 22, u32(7, 8, 1000, 2000, 0x020000, 1, 4) + struct.pack('!I', 9) + b'\1\2', u32(0))
    fl.rpc(CORE, 25, bytes([192, 0, 2, 1]) + u32(1), u32())
    fl.rpc(CORE, 20, u32(7, 1) + struct.pack('!I', 99) + b'ab', u32())
    fl.rpc(INTR, 30, struct.pack('!I', 99) + b'ab', b'')
    fl.rpc(ASYNC, 1, b'', u32())
    m += fl.frames
    write_pcap(os.path.join(outdir, 'vxi11-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
