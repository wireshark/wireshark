#!/usr/bin/env python3
# Generates test/captures/ndmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the NDMP coverage captures.  Usage: mkndmp.py <outdir> [-v]
Writes ndmp-coverage.pcap (main) and ndmp-coverage-malformed.pcap.
Everything is synthetic; addresses are from 192.0.2.0/24."""
import struct
import sys
import os
from netlib import Conn, tcp_seg, write_pcap

TS = 0x50000000
C, S = '192.0.2.10', '192.0.2.20'

def u32(x): return struct.pack('!I', x)
def u64(x): return struct.pack('!Q', x)
def xs(b):
    if isinstance(b, str): b = b.encode()
    return u32(len(b)) + b + b'\0' * ((-len(b)) % 4)
def arr(items): return u32(len(items)) + b''.join(items)
def hdr(seq, typ, code, rseq=0, err=0, ts=TS):
    return struct.pack('!IIIIII', seq, ts, typ, code, rseq, err)
def rm(data, last=True): return u32(len(data) | (0x80000000 if last else 0)) + data

# --- building blocks -------------------------------------------------------
def env(pairs): return arr([xs(k) + xs(v) for k, v in pairs])
def addr_tcp(ver, ip=0xc0000214, port=10001):
    if ver < 4:
        return u32(1) + u32(ip) + u32(port)
    return u32(1) + arr([u32(ip) + u32(port) + env([('USER', 'bob')]), u32(ip + 1) + u32(port + 1) + env([])])
def addr_local(ver): return u32(0)
def addr_fc(ver): return u32(2) + u32(0x7e)
def addr_ipc(ver): return u32(3) + xs(b'\x01\x02\x03\x04\x05')
def addr_unknown(ver): return u32(9)

def fname(t, a=b'/usr/lib/file', b=b'DOSNAME~1.TXT'):
    if t == 1: return u32(1) + xs(a) + xs(b)
    return u32(t) + xs(a)

def fstats(invalid=0, fst=0, ftype=4, links=1):
    return (u32(invalid) + u32(fst) + u32(ftype) + u32(1700000000) + u32(1700000100) + u32(1700000200)
            + u32(1000) + u32(100) + u32(0o100644) + u64(123456789) + u32(links))

def fs_info(inv=0):
    return (u32(inv) + xs('ext4') + xs('/dev/mapper/vg0-root') + xs('/dev/sda2') + u64(1 << 40) + u64(1 << 39)
            + u64(1 << 38) + u64(1000000) + u64(500000) + env([('MOUNT', '/'), ('RO', 'no')]) + xs('online'))

def sense18(): return bytes([0x70, 0, 0x02, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x3a, 0, 0, 0, 0, 0])

class Sess:
    """One NDMP TCP connection with request/reply helpers."""
    def __init__(self, frames, ver, cport, connect=True, c=C, s=S, port=10000, isn=1000, seq0=1):
        self.conn = Conn(frames, c, s, cport, port, isn_c=isn, isn_s=isn + 4000)
        self.ver = ver
        self.seq = seq0
        self.sseq = 500
        self.last = None
        if connect and ver:
            r = self.req(0x900, u32(ver))
            self.rep(0x900, r, u32(0))

    def req(self, code, body=b'', err=0, typ=0, last=True, send=True):
        n = self.seq
        self.seq += 1
        d = hdr(n, typ, code, 0, err) + body
        if send:
            self.conn.c2s(rm(d, last))
        return n

    def rep(self, code, rseq, body=b'', err=0, send=True):
        n = self.sseq
        self.sseq += 1
        d = hdr(n, 1, code, rseq, err) + body
        if send:
            self.conn.s2c(rm(d))
        return n

    def rr(self, code, reqbody=b'', repbody=b'', err=0, bodyerr=0, rep_has_err=True):
        r = self.req(code, reqbody)
        self.rep(code, r, (u32(bodyerr) if rep_has_err else b'') + repbody, err)
        return r

# --- the NDMP conversation for one protocol version -----------------------------
def config_msgs(s):
    v = s.ver
    s.rr(0x100, b'', xs('backup01') + xs('Linux') + xs('6.8.0') + xs('0123456789abcdef'))
    s.rr(0x102, b'', arr([u32(0), u32(1), u32(2), u32(3)]))
    for t in (0, 1, 2):
        s.rr(0x103, u32(t), u32(t) + (b'\xa5' * 64 if t == 2 else b''))
    s.rr(0x104, b'', arr([
        xs('dump') + env([('TYPE', 'ufs'), ('LEVEL', '0')]) + u32(0x1ff),
        xs('tar') + env([]) + u32(0x0)]))
    s.rr(0x105, b'', arr([fs_info(0), fs_info(0x1f)]))
    cap = lambda: arr([xs('REWIND') + xs('Y'), xs('MAXBLK') + xs('65536')])
    s.rr(0x106, b'', arr([
        xs('Quantum DLT') + arr([xs('/dev/nst0') + u32(3) + cap(), xs('/dev/nst1') + u32(1) + arr([])]),
        xs('IBM ULT') + arr([])]))
    s.rr(0x107, b'', arr([
        xs('Spectra Logic') + arr([xs('/dev/sg3') + u32(2) + cap()]),
        xs('Empty') + arr([])]))
    s.rr(0x108, b'', xs('Acme') + xs('Backup Server') + xs('r1.2') + arr([u32(0), u32(1), u32(2)]))
    s.rr(0x10a, b'', arr([u32(0x100) + arr([u32(1), u32(2)]), u32(0x200) + arr([])]))
    s.rr(0x109, arr([u32(0x100) + u32(1), u32(0x200) + u32(3)]), b'')

def scsi_msgs(s):
    s.rr(0x200, xs('/dev/sg3'))
    s.rr(0x202, b'', u32(1) + u32(2) + u32(3))
    s.rr(0x203, xs('/dev/sg3') + u32(1) + u32(2) + u32(0))
    s.rr(0x204)
    s.rr(0x205)

    def cdb(code, cdbb, dataout=b'', datain=b'', status=0, sense=b'', timeout=60000, flags=1, dlen=0):
        pad = lambda b: b + b'\0' * ((-len(b)) % 4)
        rq = (u32(flags) + u32(timeout) + u32(dlen) + u32(len(cdbb)) + pad(cdbb)
              + u32(len(dataout)) + pad(dataout))
        rp = (u32(status) + u32(len(dataout)) + u32(len(datain)) + pad(datain)
              + u32(len(sense)) + pad(sense))
        s.rr(code, rq, rp)
    # SCSI media changer (0x206)
    cdb(0x206, bytes([0x00, 0, 0, 0, 0, 0]))
    cdb(0x206, bytes([0x12, 0, 0, 0, 36, 0]), datain=bytes([8, 0x80, 5, 2, 31, 0, 0, 0]) + b'ACME    ' + b'CHANGER-9000    ' + b'0001', dlen=36)
    cdb(0x206, bytes([0xb8, 0, 0, 0, 0, 1, 0, 0, 0, 32, 0, 0]), datain=b'\0\1\0\0\0\0\0\0', flags=2, dlen=8)
    cdb(0x206, bytes([0xa5, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0]), status=2, sense=sense18())
    cdb(0x206, bytes([0x15, 0x10, 0, 0, 4, 0]), dataout=b'\0' * 4, flags=2)
    s.rr(0x206, u32(1) + u32(10) + u32(0) + u32(0) + u32(0), u32(0) + u32(0) + u32(0) + u32(0) + u32(0))
    s.rr(0x201)

def tape_msgs(s):
    v = s.ver
    s.rr(0x300, xs('/dev/nst0') + u32(1))
    s.rr(0x300, xs('/dev/nst0') + u32(0))
    st = (u32(0x7f) + u32(0) + u32(0xf) + u32(3) + u32(2) + u32(32768) + u32(17) + u64(1 << 41) + u64(1 << 40)
          + (b'' if v == 4 else u32(1)))
    r = s.req(0x302)
    s.rep(0x302, r, st[:4] + u32(0) + st[4:])
    r = s.req(0x302)
    s.rep(0x302, r, u32(0) + u32(5) + st[4:], err=7)
    for op in range(7):
        s.rr(0x303, u32(op) + u32(op + 1), u32(0))
    s.rr(0x304, xs(b'tape data block' * 4), u32(60))
    s.rr(0x305, u32(1024), xs(b'tape record'))
    s.rr(0x305, u32(0), xs(b''))
    def cdb(cdbb, dataout=b'', datain=b'', status=0, sense=b'', flags=1, dlen=0):
        pad = lambda b: b + b'\0' * ((-len(b)) % 4)
        rq = (u32(flags) + u32(30000) + u32(dlen) + u32(len(cdbb)) + pad(cdbb) + u32(len(dataout)) + pad(dataout))
        rp = (u32(status) + u32(len(dataout)) + u32(len(datain)) + pad(datain) + u32(len(sense)) + pad(sense))
        s.rr(0x307, rq, rp)
    cdb(bytes([0x01, 0, 0, 0, 0, 0]))
    cdb(bytes([0x08, 1, 0, 0x10, 0, 0]), datain=b'\x55' * 16, dlen=16)
    cdb(bytes([0x0a, 1, 0, 0x08, 0, 0]), dataout=b'\xaa' * 8, flags=2)
    cdb(bytes([0x11, 1, 0, 0, 1, 0]), status=2, sense=sense18())
    s.rr(0x301)

def addrs(v):
    return [addr_local(v), addr_tcp(v), addr_fc(v), addr_ipc(v), addr_unknown(v)]

def nlist(v):
    if v == 2:
        return arr([xs('/home/a') + xs('/restore/a') + u32(0) + u64(0x1000),
                    xs('/home/b') + xs('/restore/b') + u32(0) + u64(0x2000)])
    return arr([xs('/home/a') + xs('/restore/a') + xs('a.new') + xs('a.other') + u64(77) + u64(0x1000),
                xs('/home/b') + xs('') + xs('') + xs('') + u64(78) + u64(0x2000)])

def data_msgs(s):
    v = s.ver
    inv = 3
    for i, a in enumerate(addrs(v)):
        r = s.req(0x400)
        s.rep(0x400, r, u32(inv if i % 2 else 0) + u32(0) + u32(i % 3) + u32(i % 4) + u32(i % 5) + u64(1 << 33)
              + u64(1 << 32) + u32(3600) + a + u64(0) + u64(0xffffffffffffffff))
    s.rr(0x401, xs('dump') + env([('FILESYSTEM', '/home'), ('LEVEL', '1')]))
    pre = addr_local(v) if v == 2 else b''
    s.rr(0x402, pre + env([('FILESYSTEM', '/home')]) + nlist(v) + xs('dump'))
    s.rr(0x403)
    s.rr(0x404, b'', env([('FILESYSTEM', '/home'), ('TYPE', 'dump')]))
    s.rr(0x407)
    s.rr(0x409, u32(1), addr_tcp(v))
    s.rr(0x409, u32(0), addr_local(v))
    for a in addrs(v):
        s.rr(0x40a, a)

def mover_msgs(s):
    v = s.ver
    for i, a in enumerate(addrs(v)):
        r = s.req(0xa00)
        body = ((u32(i % 3)) if v >= 4 else b'') + u32(i % 5) + u32(i % 6) + u32(i % 5) + u32(65536) + u32(i) \
            + u64(1 << 30) + u64(0) + u64(1 << 20) + u64(0) + u64(0xffffffffffffffff) + (b'' if v == 2 else a)
        s.rep(0xa00, r, u32(0) + body)
    s.rr(0xa01, u32(1) + u32(1), addr_tcp(v))
    s.rr(0xa01, u32(0) + u32(0), addr_local(v))
    s.rr(0xa02)
    s.rr(0xa03)
    s.rr(0xa04)
    s.rr(0xa05, u64(0) + u64(1 << 32))
    s.rr(0xa06, u64(4096) + u64(8192))
    s.rr(0xa07)
    s.rr(0xa08, u32(32768))
    for a in addrs(v):
        s.rr(0xa09, u32(1) + a)

def notify_msgs(s):
    v = s.ver
    tail = xs('shutdown') if v in (2, 3) else b''
    s.req(0x501, u32(1) + tail)
    s.req(0x503, u32(3) + tail)
    s.req(0x502, u32(1) + u32(v) + xs('connected'))
    s.req(0x504, u32(4) + u64(1 << 20))
    s.req(0x505, u64(0) + u64(4096))

def log_msgs(s):
    s.req(0x602, xs('/var/log/backup.log') + u32(0))
    for t in range(4):
        s.req(0x603, u32(t) + u32(100 + t) + xs('log line %d' % t))

def fh_msgs(s):
    files = arr([
        arr([fname(0), fname(1), fname(2, b'other')]) + arr([fstats(0, 0, 4), fstats(7, 1, 0, 3), fstats(2, 2, 5)]) + u64(11) + u64(12),
        arr([fname(0, b'/etc/hosts')]) + arr([]) + u64(13) + u64(14)])
    s.req(0x703, files)
    s.req(0x704, arr([arr([fname(0, b'bin'), fname(1)]) + u64(20) + u64(2),
                       arr([fname(2, b'x')]) + u64(21) + u64(2)]))
    s.req(0x705, arr([arr([fstats(1, 0, 1), fstats(4, 1, 6)]) + u64(30) + u64(31),
                       arr([fstats(0, 2, 8)]) + u64(32) + u64(33)]))

def auth_msgs(s):
    for t in range(3):
        s.rr(0x901, u32(t) + (xs('bob') + xs('secret') if t == 1 else b'') if t != 2 else u32(2) + xs('bob') + b'\x11' * 16)
    s.req(0x901, u32(0))
    s.rr(0x903, u32(0), u32(0))
    s.rr(0x903, u32(2) + b'\x5a' * 64, u32(2) + xs('alice') + b'\x22' * 16)
    s.rr(0x903, u32(1), u32(1) + xs('alice') + xs('pw'))
    s.rr(0x902, rep_has_err=False)

def version_session(f, ver, cport):
    s = Sess(f, ver, cport)
    for fn in (config_msgs, scsi_msgs, tape_msgs, data_msgs, mover_msgs, notify_msgs, log_msgs, fh_msgs, auth_msgs):
        fn(s)
    # Error replies
    for e in (1, 4, 0x17):
        r = s.req(0x300, xs('/dev/nst9') + u32(1))
        s.rep(0x300, r, u32(e), err=e)
    s.conn.fin()
    return s

def build_main():
    f = []
    for ver, port in ((4, 40004), (2, 40002), (3, 40003), (5, 40005)):
        version_session(f, ver, port)

    # --- Unknown version: no CONNECT_OPEN, the default (4) applies
    s = Sess(f, 0, 40010, connect=False)
    r = s.req(0x302)
    s.rep(0x302, r, u32(0) + u32(0) + u32(0) + u32(1) + u32(0) + u32(0) + u32(512) + u32(0) + u64(0) + u64(0))
    s.rr(0xa00, b'', u32(0) + u32(0) + u32(0) + u32(0) + u32(0) + u32(0) + u32(0) + u64(0) + u64(0) + u64(0)
         + u64(0) + u64(0) + addr_local(4))
    s.req(0x501, u32(2))
    # Messages that are in the table but have no request or no reply function
    s.rep(0x501, 99, u32(0))            # reply to a notify: no reply dissector
    s.req(0x100)                        # request without body dissector
    s.rep(0x902, 98, b'')               # reply to CONNECT_CLOSE
    s.rep(0x300, 12345, u32(0))         # reply to an unknown request: no task
    # Unknown message number: passes the sanity check, not in the table (expert info)
    s.req(0x101, b'\0' * 8)
    s.rep(0x2ff, 5, b'\0' * 4)
    s.conn.fin()

    # --- Records that are not (or no longer) NDMP, and reassembly -----------
    s = Sess(f, 4, 40020)
    # Several records in one TCP segment
    d1 = hdr(s.seq, 0, 0x202); s.seq += 1
    d2 = hdr(s.seq, 0, 0x203) + xs('/dev/sg3') + u32(1) + u32(2) + u32(0); s.seq += 1
    s.conn.c2s(rm(d1) + rm(d2))
    # One record split over two TCP segments (desegmentation)
    r = s.req(0x100, send=False)
    d = hdr(r, 0, 0x100)
    s.conn.c2s(rm(d)[:10])
    s.conn.c2s(rm(d)[10:])
    rr = s.sseq; s.sseq += 1
    body = hdr(rr, 1, 0x100, r) + u32(0) + xs('host-a') + xs('Linux') + xs('6.8') + xs('id')
    s.conn.s2c(rm(body)[:30])
    s.conn.s2c(rm(body)[30:60])
    s.conn.s2c(rm(body)[60:])
    # A record that is too short and a record with a bad header
    s.conn.c2s(u32(0x80000000 | 10) + b'\0' * 10)
    s.conn.c2s(rm(hdr(s.seq, 0, 0x100, 0, 0, ts=1)))
    s.seq += 1
    s.conn.c2s(rm(hdr(s.seq, 0, 0x100, 0, 0, ts=0x7fffffff)))
    s.conn.c2s(rm(hdr(s.seq, 2, 0x100)))           # bad message type
    s.conn.c2s(rm(hdr(s.seq, 0, 0xb00)))           # message number out of range
    s.conn.c2s(rm(hdr(s.seq, 0, 0x100, 0, 0x30)))  # error code out of range
    s.conn.c2s(rm(hdr(s.seq, 0, 0)))               # message number zero
    # Fragmented records: three fragments, client direction (0x303 MTIO with a long write)
    n = s.seq; s.seq += 1
    data = xs(bytes(range(256)) * 3)
    full = hdr(n, 0, 0x304) + data
    a, b, c = full[:60], full[60:400], full[400:]
    s.conn.c2s(rm(a, False))
    s.conn.c2s(rm(b, False))
    lastseq = s.conn.sc
    s.conn.c2s(rm(c, True))
    # The last fragment again, as a TCP retransmission: the record was
    # reassembled in the earlier frame
    s.conn.f.append(tcp_seg(C, S, 40020, 10000, lastseq, s.conn.ss, rm(c, True)))
    r2 = s.sseq; s.sseq += 1
    s.conn.s2c(rm(hdr(r2, 1, 0x304, n) + u32(0) + u32(768)))
    # Server direction fragments
    n = s.seq; s.seq += 1
    s.conn.c2s(rm(hdr(n, 0, 0x305) + u32(4096)))
    r2 = s.sseq; s.sseq += 1
    full = hdr(r2, 1, 0x305, n) + u32(0) + xs(b'R' * 1000)
    s.conn.s2c(rm(full[:100], False))
    s.conn.s2c(rm(full[100:700], False))
    s.conn.s2c(rm(full[700:], True))
    # Last two fragments in one TCP segment, then a second record right behind
    n = s.seq; s.seq += 1
    full = hdr(n, 0, 0x304) + xs(b'W' * 200)
    s.conn.c2s(rm(full[:50], False))
    s.conn.c2s(rm(full[50:120], False) + rm(full[120:], True))
    # Fragments each in their own segment with a complete record behind the last
    n = s.seq; s.seq += 1
    full = hdr(n, 0, 0x304) + xs(b'V' * 64)
    s.conn.c2s(rm(full[:30], False))
    n2 = s.seq; s.seq += 1
    s.conn.c2s(rm(full[30:], True) + rm(hdr(n2, 0, 0x203) + xs('/dev/sg1') + u32(0) + u32(0) + u32(0)))
    s.conn.fin()

    # --- Client and server with the same address: the direction comes from the ports
    s = Sess(f, 4, 40030, c='192.0.2.30', s='192.0.2.30')
    s.rr(0x100, b'', xs('loop') + xs('Linux') + xs('6') + xs('1'))
    n = s.seq; s.seq += 1
    full = hdr(n, 0, 0x304) + xs(b'L' * 80)
    s.conn.c2s(rm(full[:40], False)); s.conn.c2s(rm(full[40:], True))
    r2 = s.sseq; s.sseq += 1
    full = hdr(r2, 1, 0x304, n) + u32(0) + u32(80)
    s.conn.s2c(rm(full[:30], False)); s.conn.s2c(rm(full[30:], True))
    s.conn.fin()

    # --- Reproducer of "NDMP: Fix a NULL tvb after incomplete reassembly":
    # two connections between the same hosts whose fragments share a
    # relative sequence number.
    def hdr1(seq): return hdr(seq, 0, 0x900)
    fa0 = rm(hdr1(1), False); fb0 = rm(hdr1(2), False)
    fa1 = rm(u32(4), True); fb1 = rm(u32(3), True)
    ca = Conn(f, C, S, 40100, 10000, isn_c=999, isn_s=7000, syn=False)
    cb = Conn(f, C, S, 40101, 10000, isn_c=999, isn_s=8000, syn=False)
    f.append(tcp_seg(C, S, 40100, 10000, 999, 0, b'', 0x02))
    f.append(tcp_seg(C, S, 40101, 10000, 999, 0, b'', 0x02))
    ca.sc = cb.sc = 1000
    ca.c2s(fa0); cb.c2s(fb0)
    ca.c2s(fa1); cb.c2s(fb1)
    return f

def build_malformed():
    f = []
    s = Sess(f, 4, 41000)
    # Truncated bodies of every shape: records that end inside a structure
    def trunc(code, body, typ=0):
        n = s.seq; s.seq += 1
        s.conn.c2s(rm(hdr(n, typ, code) + body))
    trunc(0x203, xs('/dev/sg3') + u32(1))            # SCSI_SET_TARGET cut short
    trunc(0x206, u32(1) + u32(5) + u32(0) + u32(100) + b'\0' * 8)   # CDB length beyond the record
    trunc(0x307, u32(1) + u32(5) + u32(0) + u32(4) + bytes([8, 0, 0, 0]) + u32(0x7fffff00))
    trunc(0x703, u32(1000000) + b'\0' * 8)
    trunc(0x900, b'')
    trunc(0x401, xs('dump') + u32(3))
    trunc(0xa09, u32(1) + u32(3) + u32(5))
    # reply cases
    n = s.seq; s.seq += 1
    s.conn.c2s(rm(hdr(n, 0, 0x206) + u32(1) + u32(5) + u32(0) + u32(6) + bytes([0x12, 0, 0, 0, 36, 0, 0, 0])
                   + u32(0)))
    r = s.sseq; s.sseq += 1
    s.conn.s2c(rm(hdr(r, 1, 0x206, n) + u32(0) + u32(0) + u32(0) + u32(0x1000) + b'\0' * 16 + u32(0x1000) + b'\0' * 8))
    n = s.seq; s.seq += 1
    s.conn.c2s(rm(hdr(n, 0, 0x307) + u32(1) + u32(5) + u32(0) + u32(6) + bytes([8, 0, 0, 0, 0x10, 0, 0, 0])
                   + u32(0)))
    r = s.sseq; s.sseq += 1
    s.conn.s2c(rm(hdr(r, 1, 0x307, n) + u32(0) + u32(2) + u32(0) + u32(0) + u32(18) + sense18()[:12]))
    # Fragmentation oddities on one connection: a retransmission with
    # different content of a middle fragment, then a last fragment.
    n = s.seq; s.seq += 1
    full = hdr(n, 0, 0x304) + xs(b'X' * 300)
    s.conn.c2s(rm(full[:40], False))
    mid_seq = s.conn.sc
    s.conn.c2s(rm(full[40:100], False))
    s.conn.f.append(tcp_seg(C, S, 41000, 10000, mid_seq, s.conn.ss, rm(full[40:90] + b'Y' * 10, False)))
    s.conn.f.append(tcp_seg(C, S, 41000, 10000, mid_seq, s.conn.ss, rm(full[40:100], True)))
    s.conn.sc += 0
    # Decode As / heuristic only: valid NDMP on other ports, and a short first segment
    s2 = Sess(f, 4, 41001, port=10001)
    s2.rr(0x100, b'', xs('h') + xs('o') + xs('v') + xs('i'))
    s3 = Sess(f, 4, 41002, port=10002)
    s3.rr(0x100, b'', xs('h') + xs('o') + xs('v') + xs('i'))
    s4 = Sess(f, 4, 41003, connect=False)
    s4.conn.c2s(b'\x80\x00\x00\x18' + b'\0' * 10)
    # A last fragment alone with a bogus first header
    s.conn.c2s(rm(b'\xff' * 30, True))
    s.conn.fin()
    return f

if __name__ == '__main__':
    out = sys.argv[1]
    m = build_main()
    write_pcap(os.path.join(out, 'ndmp-coverage.pcap'), m)
    x = build_malformed()
    write_pcap(os.path.join(out, 'ndmp-coverage-malformed.pcap'), x)
    print(len(m), len(x))
