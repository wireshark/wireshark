#!/usr/bin/env python3
# Generates test/captures/ocp1_coverage.pcap.gz, ocp1_coverage_wrap.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OCP.1 (AES70) coverage captures.  Usage: mkocp1.py <outdir>
Writes ocp1-coverage.pcap (valid traffic), ocp1-coverage-malformed.pcap
(paths only malformed input reaches) and ocp1-coverage-wrap.pcap (the
reproducers of the PDU size wrap loop fixed by "OCP.1: Bound the PDU size
to avoid an endless loop").  Everything is synthetic."""
import struct
import sys
import os

# ---------------------------------------------------------------- pcap
def ip_csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_ip(proto, payload, src, dst):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 1, 0, 64, proto, 0, s, d)
    ip = ip[:10] + struct.pack('!H', ip_csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + payload

class Cap:
    def __init__(self): self.pkts = []
    def add(self, p): self.pkts.append(p)
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)

C, S = '192.0.2.1', '192.0.2.2'

class Tcp:
    """One TCP connection; frames are added to cap."""
    def __init__(self, cap, cport, sport):
        self.cap, self.cp, self.sp = cap, cport, sport
        self.cseq, self.sseq = 1000, 5000
    def seg(self, fromclient, data, flags=0x18):
        if fromclient:
            sp, dp, seq, ack, a, b = self.cp, self.sp, self.cseq, self.sseq, C, S
        else:
            sp, dp, seq, ack, a, b = self.sp, self.cp, self.sseq, self.cseq, S, C
        if flags == 0x02: ack = 0
        h = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
        self.cap.add(eth_ip(6, h + data, a, b))
        n = len(data) + (1 if flags & 3 else 0)
        if fromclient: self.cseq += n
        else: self.sseq += n
    def handshake(self):
        self.seg(True, b"", 0x02)
        self.seg(False, b'', 0x12)
        self.seg(True, b'', 0x10)
    def c(self, d): self.seg(True, d)
    def s(self, d): self.seg(False, d)

def udp(cap, sport, dport, data, fromclient=True):
    a, b = (C, S) if fromclient else (S, C)
    cap.add(eth_ip(17, struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data, a, b))

# ---------------------------------------------------------------- OCP.1
u8 = lambda v: struct.pack('!B', v)
u16 = lambda v: struct.pack('!H', v)
u32 = lambda v: struct.pack('!I', v)
u64 = lambda v: struct.pack('!Q', v)

def Str(s): s = s.encode() if isinstance(s, str) else s; return u16(len(s)) + s
Blob = lambda b: u16(len(b)) + b
def ClassID(*f): return u16(len(f)) + b''.join(u16(x) for x in f)
def ClassIdent(*f, ver=2): return ClassID(*f) + u16(ver)
def MgrDesc(ono, name, cid, ver=1): return u32(ono) + Str(name) + ClassID(*cid) + u16(ver)
def MID(level, idx): return u16(level) + u16(idx)
def Event(ono, level, idx): return u32(ono) + MID(level, idx)
def Method(ono, level, idx): return u32(ono) + MID(level, idx)
def Ver(a, b, c, d): return u32(a) + u32(b) + u32(c) + u16(d)
LibVolType = lambda auth, i: auth + u32(i)
def LibIdent(auth, i, ono): return LibVolType(auth, i) + u32(ono)
def LibVolIdent(ono, i): return u32(ono) + u32(i)
def PTP(neg, sec, ns): return u8(neg) + u64(sec) + u32(ns)
NTP = lambda s, f: u32(s) + u32(f)
def List(items): return u16(len(items)) + b''.join(items)
def ONoList(*o): return List([u32(x) for x in o])

def Task(tid, label, lib, grp, mode, units, clock, interval, app, start=None):
    if start is None:
        start = PTP(0, 1700000000, 5) if mode == 1 else u64(48000)
    return (u32(tid) + Str(label) + LibVolIdent(*lib) + u16(grp) + u8(mode) +
            u8(units) + u32(clock) + start + u32(interval) + Blob(app))

# message builders
def cmd(handle, ono, level, idx, pcount, params=b''):
    body = u32(handle) + u32(ono) + MID(level, idx) + u8(pcount) + params
    return u32(len(body) + 4) + body
def rsp(handle, status, pcount, params=b''):
    body = u32(handle) + u8(status) + u8(pcount) + params
    return u32(len(body) + 4) + body
def ntf(ono, level, idx, pcount, ctx, emitter, elevel, eidx, params=b''):
    body = (u32(ono) + MID(level, idx) + u8(pcount) + Blob(ctx) + u32(emitter) +
            MID(elevel, eidx) + params)
    return u32(len(body) + 4) + body

def pdu(ptype, msgs, count=None):
    data = b''.join(msgs)
    return (u8(0x3B) + u16(1) + u32(9 + len(data)) + u8(ptype) +
            u16(len(msgs) if count is None else count) + data)
CMD, RRQ, NTF, RSP, KA = 0, 1, 2, 3, 4

# ------------------------------------------------- method table
# (ono, level, idx, kind, pcount, params): kind 'q' = request with parameters,
# 'r' = response carrying the parameters.  Every decoder branch of
# packet-ocp1.c is listed once.
DEV, SEC, FW, SUB, PWR, NET, CLK, LIB, AUD, TIME, TASK, COD, DIAG = range(1, 14)
T1 = Task(7, 'tone', (0x10, 3), 1, 1, 2, 0x20, 1000, b'app')       # PTP start
T2 = Task(9, 'fade', (0x10, 4), 2, 2, 2, 0x21, 0, b'')            # samples start
T2B = Task(11, 'rampdown', (0x10, 7), 2, 2, 2, 0x21, 10, b'abc')
TBIG = Task(12, 'big', (0x10, 8), 2, 1, 1, 0x23, 7, bytes(512))
T3 = Task(5, 'x', (0x10, 5), 3, 0, 2, 0x22, 5, b'z')              # bad time mode
T4 = Task(6, 'sec', (0x10, 6), 3, 1, 1, 0x22, 5, b'z')            # units seconds
def maptask(t, n):
    # The decoder reads the label length of map items 4 bytes after the key;
    # with a task ID whose upper 16 bits equal the label length it gets the
    # length right (see README).
    label = struct.unpack('!H', t[4:6])[0]
    return u32(n) + u32((label << 16) | struct.unpack('!I', t[:4])[0]) + t[4:]
SPECS = [
 # OcaRoot
 (DEV, 1, 1, 'r', 1, ClassIdent(1, 3, 1)),
 (DEV, 1, 2, 'r', 1, u8(1)),
 (DEV, 1, 5, 'r', 1, Str('Root')),
 (DEV, 1, 6, 'q', 1, b'\x01\x02'),           # no decoder: raw parameters
 # OcaDeviceManager
 (DEV, 3, 1, 'r', 1, u16(3)),
 (DEV, 3, 2, 'r', 1, b'\0' + b'\x00\x1a\x2b' + b'\x00\x00\x00\x07'),
 (DEV, 3, 3, 'r', 1, Str('SN-12345')),
 (DEV, 3, 4, 'r', 1, Str('Mixer')),
 (DEV, 3, 5, 'q', 1, Str('Mixer2')),
 (DEV, 3, 6, 'r', 1, Str('Acme') + Str('M1') + Str('1.0')),
 (DEV, 3, 7, 'r', 1, Str('Main')),
 (DEV, 3, 8, 'q', 1, Str('Main2')),
 (DEV, 3, 9, 'r', 1, Str('INV-1')),
 (DEV, 3, 10, 'q', 1, Str('INV-2')),
 (DEV, 3, 11, 'r', 1, u8(1)),
 (DEV, 3, 12, 'q', 1, u8(0)),
 (DEV, 3, 13, 'r', 1, u16(0x0005)),
 (DEV, 3, 14, 'q', 2, bytes(range(16)) + Blob(b'\xc0\x00\x02\x01')),
 (DEV, 3, 15, 'r', 1, u8(2)),
 (DEV, 3, 16, 'q', 0, b'\xaa\xbb'),          # ClearResetCause with stray bytes
 (DEV, 3, 17, 'r', 1, Str('hello')),
 (DEV, 3, 18, 'q', 1, Str('hi')),
 (DEV, 3, 19, 'r', 1, List([MgrDesc(2, 'Security', (1, 3, 2)), MgrDesc(3, 'Fw', (1, 3, 3))])),
 (DEV, 3, 20, 'r', 1, Str('rev-A')),
 (DEV, 2, 1, 'q', 1, b'\x00'),               # level 2: raw parameters
 (14, 3, 1, 'q', 1, b'\x00'),                # unknown manager number
 # OcaSecurityManager
 (SEC, 3, 1, 'q', 0, b''),
 (SEC, 3, 2, 'q', 0, b''),
 (SEC, 3, 3, 'q', 2, Str('id') + Blob(b'\x01\x02')),
 (SEC, 3, 4, 'q', 2, Str('id2') + Blob(b'\x03')),
 (SEC, 3, 5, 'q', 1, Str('id')),
 (SEC, 3, 9, 'q', 1, b'\x01'),               # unknown method
 # OcaFirmwareManager
 (FW, 3, 1, 'r', 1, List([Ver(1, 2, 3, 4), Ver(2, 0, 0, 1)])),
 (FW, 3, 2, 'q', 0, b''),
 (FW, 3, 3, 'q', 1, u16(2)),
 (FW, 3, 4, 'q', 2, u32(1) + Blob(b'image-bytes')),
 (FW, 3, 5, 'q', 1, Blob(b'verify')),
 (FW, 3, 6, 'q', 0, b''),
 (FW, 3, 7, 'q', 3, u16(1) + Blob(b'\xc0\xa8\x00\x01') + Str('fw.bin')),
 (FW, 3, 8, 'q', 0, b''),
 (FW, 3, 12, 'q', 1, b'\x01'),
 # OcaSubscriptionManager
 (SUB, 3, 1, 'q', 5, u32(0x100) + MID(3, 5) + Event(0x101, 3, 4)[:0] + Method(0x200, 3, 1) +
    Blob(b'ctx') + u8(1) + Blob(b'\xc0\xa8\x00\x02')),
 (SUB, 3, 2, 'q', 2, Event(0x100, 3, 2) + Method(0x200, 3, 1)),
 (SUB, 3, 3, 'q', 0, b''),
 (SUB, 3, 4, 'q', 0, b''),
 (SUB, 3, 5, 'q', 6, u32(0x100) + MID(3, 6) + Method(0x200, 3, 1) + Blob(b'') + u8(1) +
    Blob(b'\xc0\xa8\x00\x02')),
 (SUB, 3, 6, 'q', 3, u32(0x100) + MID(3, 6) + Method(0x200, 3, 1)),
 (SUB, 3, 7, 'r', 1, u16(32)),
 (SUB, 3, 9, 'q', 1, b'\x01'),
 # OcaPowerManager
 (PWR, 3, 1, 'r', 1, u8(1)),
 (PWR, 3, 2, 'q', 1, u8(2)),
 (PWR, 3, 3, 'r', 1, ONoList(0x300, 0x301)),
 (PWR, 3, 4, 'r', 1, ONoList(0x300)),
 (PWR, 3, 5, 'q', 3, u32(0x300) + u32(0x301) + u8(1)),
 (PWR, 3, 6, 'r', 1, u8(1)),
 (PWR, 3, 9, 'q', 1, b'\x01'),
 # OcaNetworkManager
 (NET, 3, 1, 'r', 1, ONoList(0x400, 0x401)),
 (NET, 3, 2, 'r', 1, ONoList(0x400)),
 (NET, 3, 3, 'r', 1, ONoList(0x401)),
 (NET, 3, 4, 'r', 1, ONoList(0x402, 0x403)),
 (NET, 3, 9, 'q', 1, b'\x01'),
 # OcaMediaClockManager
 (CLK, 3, 1, 'r', 1, ONoList(0x500, 0x501)),
 (CLK, 3, 2, 'r', 1, List([u8(0), u8(1), u8(2)])),
 (CLK, 3, 3, 'r', 1, ONoList(0x502)),
 (CLK, 3, 9, 'q', 1, b'\x01'),
 # OcaLibraryManager
 (LIB, 3, 1, 'q', 1, LibVolType(b'\x00\x1a\x2b', 3)),
 (LIB, 3, 1, 'r', 1, LibIdent(b'\x00\x1a\x2b', 3, 0x600)),
 (LIB, 3, 2, 'q', 1, u32(0x600)),
 (LIB, 3, 3, 'q', 1, LibVolType(b'\x00\x1a\x2b', 3)),
 (LIB, 3, 3, 'r', 1, u16(2)),
 (LIB, 3, 4, 'q', 1, LibVolType(b'\x00\x1a\x2b', 3)),
 (LIB, 3, 4, 'r', 1, List([LibIdent(b'\x00\x1a\x2b', 3, 0x600), LibIdent(b'\x00\x1a\x2b', 4, 0x601)])),
 (LIB, 3, 5, 'r', 1, LibVolIdent(0x600, 1)),
 (LIB, 3, 6, 'q', 1, LibVolIdent(0x600, 2)),
 (LIB, 3, 9, 'q', 1, b'\x01'),
 # OcaAudioProcessing manager (no methods)
 (AUD, 3, 1, 'q', 1, b'\x01\x02\x03'),
 # OcaDeviceTimeManager
 (TIME, 3, 1, 'r', 1, NTP(0xE0000000, 0x80000000)),
 (TIME, 3, 2, 'q', 1, NTP(0xE0000001, 0)),
 (TIME, 3, 3, 'r', 1, ONoList(0x700, 0x701)),
 (TIME, 3, 4, 'r', 1, u32(0x700)),
 (TIME, 3, 5, 'q', 1, u32(0x701)),
 (TIME, 3, 6, 'r', 1, PTP(0, 1700000000, 12345)),
 (TIME, 3, 7, 'q', 1, PTP(1, 5, 6)),
 (TIME, 3, 9, 'q', 1, b'\x01'),
 # OcaTaskManager
 (TASK, 3, 1, 'q', 1, u8(1)),
 (TASK, 3, 2, 'q', 2, u8(2) + Blob(b'p')),
 (TASK, 3, 3, 'q', 3, u16(1) + u8(3) + Blob(b'pp')),
 (TASK, 3, 4, 'q', 3, u32(7) + u8(1) + Blob(b'')),
 (TASK, 3, 5, 'r', 1, u8(2)),
 (TASK, 3, 6, 'q', 1, u32(7) + u8(1) + u16(0)),
 (TASK, 3, 7, 'q', 1, u32(7)),
 (TASK, 3, 7, 'r', 1, u32(7) + u8(1) + u16(0)),
 (TASK, 3, 8, 'q', 1, T1),
 (TASK, 3, 8, 'r', 1, T2),
 (TASK, 3, 8, 'q', 1, T3),
 (TASK, 3, 8, 'q', 1, T4),
 (TASK, 3, 9, 'r', 1, u16(2) + maptask(T2, 1) + maptask(T2B, 2)),
 (TASK, 3, 9, 'r', 1, u16(1) + maptask(T1, 1)),
 (TASK, 3, 9, 'r', 1, u16(1) + maptask(T4, 1)),
 (TASK, 3, 9, 'r', 1, u16(1) + u32(1) + T2B),   # label length misread: returns
 (TASK, 3, 9, 'r', 1, u16(1) + maptask(TBIG, 1)),   # units 1, 0x02 at the blob length
 (TASK, 3, 9, 'r', 1, u16(1) + maptask(T3, 1)),
 (TASK, 3, 10, 'q', 1, u32(7)),
 (TASK, 3, 10, 'r', 1, T1),
 (TASK, 3, 10, 'r', 1, T4),
 (TASK, 3, 11, 'q', 2, u32(7) + T2),
 (TASK, 3, 11, 'q', 2, u32(7) + T4),
 (TASK, 3, 12, 'q', 1, u32(7)),
 (TASK, 3, 20, 'q', 1, b'\x01'),
 # OcaCodingManager
 (COD, 3, 1, 'r', 1, u16(1) + u16(1) + Str(b'\0\0PCM')),
 (COD, 3, 2, 'r', 1, u16(1) + u16(2) + Str(b'\0\0AAC')),
 (COD, 3, 9, 'q', 1, b'\x01'),
 # OcaDiagnosticManager
 (DIAG, 3, 1, 'q', 1, u32(0x42)),
 (DIAG, 3, 1, 'r', 1, Str('unlocked')),
 (DIAG, 3, 9, 'q', 1, b'\x01'),
]

def build_exchange(specs, h0, maxmsg=1100):
    """Return a list of (cmd_pdu, rsp_pdu) pairs, filling PDUs up to maxmsg."""
    groups, cur, size = [], [], 0
    for i, (ono, lvl, idx, kind, pc, params) in enumerate(specs):
        h = h0 + i
        if kind == 'q':
            c = cmd(h, ono, lvl, idx, pc, params); r = rsp(h, 0, 0)
        else:
            c = cmd(h, ono, lvl, idx, 0); r = rsp(h, 0, pc, params)
        if cur and size + len(c) > maxmsg or size + len(r) > maxmsg:
            groups.append(cur); cur, size = [], 0
        cur.append((c, r)); size += max(len(c), len(r))
    if cur: groups.append(cur)
    out = []
    for g in groups:
        out.append((pdu(CMD, [c for c, r in g]), pdu(RSP, [r for c, r in g])))
    return out

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    cap = Cap()
    # ------------------------------------------------ TCP stream
    t = Tcp(cap, 49321, 50111)
    t.handshake()
    # keep-alives: 2 byte (seconds) and 4 byte (milliseconds) heartbeat
    t.c(pdu(KA, [u16(1)]))
    t.s(pdu(KA, [u32(500)]))
    exchanges = build_exchange(SPECS, 0x1000)
    for i, (c, r) in enumerate(exchanges):
        if i % 2:
            # CommandRrq PDU (type 1) for half of the groups
            c = bytes([c[0]]) + c[1:7] + bytes([RRQ]) + c[8:]
        t.c(c); t.s(r)
    # a command whose handle was already answered: response_in is added
    t.c(pdu(CMD, [cmd(0x1000, DEV, 3, 1, 0)]))
    # a response without a request on this connection (warning)
    t.s(pdu(RSP, [rsp(0x7777, 0, 1, Str('orphan'))]))
    # notifications: property changed events
    t.s(pdu(NTF, [ntf(DEV, 3, 11, 1, b'ctx', 0x100, 1, 1, u8(1))]))
    t.s(pdu(NTF, [ntf(DEV, 3, 4, 1, b'', 0x101, 1, 1, Str('NewName')),
                  ntf(DEV, 1, 2, 1, b'\x01\x02', 0x102, 1, 1, u8(0)),
                  ntf(DEV, 2, 1, 1, b'', 0x103, 1, 1, b'\xaa'),
                  ntf(14, 3, 1, 1, b'', 0x104, 1, 1, b'\xbb')]))
    t.s(pdu(NTF, [ntf(PWR, 3, 3, 1, b'', 0x300, 1, 1, ONoList(0x300))]))
    t.s(pdu(NTF, [ntf(DEV, 1, 1, 0, b'', 0x105, 1, 1)]))      # no parameters
    # several PDUs in one TCP segment
    t.c(pdu(CMD, [cmd(0x2001, DEV, 3, 4, 0)]) + pdu(RRQ, [cmd(0x2002, DEV, 3, 3, 0)]) +
        pdu(KA, [u16(1)]))
    t.s(pdu(RSP, [rsp(0x2001, 0, 1, Str('Mixer'))]) + pdu(RSP, [rsp(0x2002, 0, 1, Str('SN-1'))]))
    # a PDU split into two TCP segments, and a PDU followed by the start of
    # the next one (desegmentation across segments)
    big = pdu(CMD, [cmd(0x2010 + i, DEV, 3, 5, 1, Str('name-%d' % i * 4)) for i in range(4)])
    t.c(big[:50]); t.c(big[50:])
    r1 = pdu(RSP, [rsp(0x2010 + i, 0, 0) for i in range(4)])
    r2 = pdu(RSP, [rsp(0x2020, 0, 1, Str('late'))])
    t.c(pdu(CMD, [cmd(0x2020, DEV, 3, 4, 0)]))
    t.s(r1 + r2[:15]); t.s(r2[15:])
    # invalid PDU type after a valid PDU, in the same segment
    t.c(pdu(CMD, [cmd(0x2030, DEV, 3, 4, 0)]) + pdu(9, [], 0) [:10] + b'\x01\x02\x03')
    # ------------------------------------------------ UDP
    udp(cap, 49400, 50222, pdu(CMD, [cmd(1, DEV, 3, 1, 0), cmd(2, DEV, 3, 4, 0)]))
    udp(cap, 50222, 49400, pdu(RSP, [rsp(1, 0, 1, u16(3)), rsp(2, 0, 1, Str('UdpMixer'))]), False)
    udp(cap, 49400, 50222, pdu(KA, [u16(1)]))
    udp(cap, 50222, 49400, pdu(KA, [u32(1000)]), False)
    udp(cap, 50222, 49400, pdu(NTF, [ntf(DEV, 3, 11, 1, b'', 0x100, 1, 1, u8(1))]), False)
    udp(cap, 49400, 50222, pdu(CMD, [cmd(3, DEV, 3, 4, 0)]) + pdu(CMD, [cmd(4, DEV, 3, 3, 0)]))
    udp(cap, 50222, 49400, pdu(RSP, [rsp(3, 0, 1, Str('A')), ]) + pdu(RSP, [rsp(4, 0, 1, Str('B'))]), False)
    # UDP datagram of a valid PDU followed by an unknown PDU type
    udp(cap, 49400, 50222, pdu(CMD, [cmd(5, DEV, 3, 4, 0)]) + pdu(7, [], 0)[:10] + b'\x00')
    # more conversations using the same small handle numbers: the request
    # table is keyed by (conversation, handle) and the keys collide
    for k in range(3):
        for h in (1, 2, 3):
            udp(cap, 49500 + k, 50300 + k, pdu(CMD, [cmd(h, DEV, 3, 4, 0)]))
            udp(cap, 50300 + k, 49500 + k, pdu(RSP, [rsp(h, 0, 1, Str('conv%d-%d' % (k, h)))]), False)
    cap.write(os.path.join(outdir, 'ocp1-coverage.pcap'))

    # ------------------------------------------------ malformed
    m = Cap()
    t = Tcp(m, 49330, 50111)
    t.handshake()
    t.c(pdu(CMD, [cmd(0x10, DEV, 3, 4, 0)]))
    # failed command: status != 0
    t.s(pdu(RSP, [rsp(0x10, 5, 0)]))
    # message size < 4 in a command, notification and response PDU
    t.c(pdu(CMD, [u32(2) + b'\0\0\0\0']))
    t.c(pdu(NTF, [u32(1) + b'\0\0\0\0']))
    t.c(pdu(RSP, [u32(0) + b'\0\0\0\0']))
    # keep-alive with two messages / bad size
    t.c(pdu(KA, [u16(1)], 2))
    t.c(pdu(KA, [u16(1) + b'\0'], 1))
    # command truncated in the middle of its parameters (exception)
    t.c(pdu(CMD, [cmd(0x11, DEV, 3, 19, 1, u16(5) + b'\0\0\0\1')]))
    t.s(pdu(RSP, [rsp(0x11, 0, 1, u16(5) + b'\0\0\0\1')]))
    t.c(pdu(CMD, [cmd(0x12, TASK, 3, 8, 1, T1[:30])]))
    # truncated notification, truncated header-only message
    t.s(pdu(NTF, [u32(12) + b'\0' * 8]))
    t.c(pdu(CMD, [u32(8) + b'\0\0\0\0']))
    # PDU size fields: smaller than header, larger than frame
    t.c(b'\x3b\x00\x01\x00\x00\x00\x05\x00\x00\x01\x00')
    t.c(b'\x3b\x00\x01\x00\x00\x00\x09\x00\x00\x00' + b'\0')
    # heuristic rejections on UDP: too short, wrong sync, version, type,
    # size too small, trailing byte that is not a sync value
    udp(m, 51000, 51001, b'\x3b\x00\x01')
    udp(m, 51000, 51001, b'\x3a' + pdu(CMD, [cmd(1, DEV, 3, 1, 0)])[1:])
    udp(m, 51000, 51001, b'\x3b\x00\x02' + pdu(CMD, [cmd(1, DEV, 3, 1, 0)])[3:])
    udp(m, 51000, 51001, pdu(5, [], 0))
    udp(m, 51000, 51001, b'\x3b\x00\x01\x00\x00\x00\x02\x00\x00\x00')
    udp(m, 51000, 51001, pdu(CMD, [cmd(1, DEV, 3, 1, 0)]) + b'\x55' * 30)
    # valid heuristic, then a PDU where the next sync byte is missing
    udp(m, 51000, 51001, pdu(CMD, [cmd(1, DEV, 3, 1, 0)]) + b'\x3b\x00\x01\x00\x00\x00\x09\x00\x00\x00' + b'\0')
    udp(m, 51000, 51001, pdu(CMD, [cmd(1, DEV, 3, 1, 0)]) + b'\x55' + pdu(CMD, [cmd(2, DEV, 3, 1, 0)]))
    # too-short trailing PDU, PDU shorter than header size, size beyond data
    udp(m, 51000, 51001, pdu(CMD, [cmd(1, DEV, 3, 1, 0)]) + b'\x3b\x00\x01\x00\x00')
    udp(m, 51000, 51001, pdu(CMD, [cmd(1, DEV, 3, 1, 0)]) + b'\x3b\x00\x01\x00\x00\x00\x05\x00\x00\x01\x00')
    udp(m, 51000, 51001, pdu(CMD, [cmd(1, DEV, 3, 1, 0)]) + pdu(CMD, [cmd(2, DEV, 3, 1, 0)])[:-3])
    # keep-alive PDU with a bad PDU size on UDP
    udp(m, 51000, 51001, pdu(KA, [u16(1) + b'\0\0\0\0']))
    # the PDU size wrap reproducers (see the wrap capture)
    wrap = pdu(CMD, [], 0)[:5] + u32(9) + b'\x00\x00\x01'
    data = (u8(0x3B) + u16(1) + u32(9) + u8(2) + u16(1)) + \
           (u8(0x3B) + u16(1) + u32(0xFFFFFFF5) + u8(2) + u16(1)) + b'\x00'
    udp(m, 51100, 51101, data)
    t2 = Tcp(m, 51102, 51103); t2.handshake(); t2.c(data)
    m.write(os.path.join(outdir, 'ocp1-coverage-malformed.pcap'))

    # ------------------------------------------------ wrap reproducers
    w = Cap()
    udp(w, 61000, 61001, data)
    t3 = Tcp(w, 61002, 61003); t3.c(data)
    w.write(os.path.join(outdir, 'ocp1-coverage-wrap.pcap'))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
