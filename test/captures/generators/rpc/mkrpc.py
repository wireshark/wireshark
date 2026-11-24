#!/usr/bin/env python3
# Generates test/captures/rpc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the RPC (ONC RPC, RFC 5531) coverage captures.
# Usage: mkrpc.py <outdir>
# Writes rpc-coverage.pcapng (main, decodes cleanly), rpc-coverage-malformed.pcapng
# (paths only malformed input reaches) and the standalone reproducers of the
# bugs fixed by "RPC: Fix type confusion on reused XIDs and an SRT tap overflow".
# Everything is built with struct; nothing comes from a real network.
import os
import struct
import sys

C, S = '192.0.2.1', '192.0.2.2'
PM, NFS = 100000, 100003


def u(*v):
    return b''.join(struct.pack('>I', x & 0xffffffff) for x in v)


def xstr(s):
    b = s.encode() if isinstance(s, str) else s
    return u(len(b)) + b + b'\0' * (-len(b) % 4)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src, dst):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def eth(payload):
    return bytes.fromhex('020000000002' '020000000001') + b'\x08\x00' + payload


def exp_pdu(name, payload):
    n = name.encode()
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload


class Cap:
    """Frames with a running time stamp; pcapng with one IDB per link type."""
    def __init__(self):
        self.frames = []        # (linktype, bytes, usec)
        self.t = 1700000000 * 1000000
        self.n = 0

    def add(self, fr, lt=1, dt=1000, orig=None):
        self.t += dt
        self.frames.append((lt, fr, self.t, orig if orig else len(fr)))
        self.n += 1
        return self.n

    def udp(self, sport, dport, data, to_server=True, dt=1000, keep=None):
        src, dst = (C, S) if to_server else (S, C)
        h = struct.pack('!HHHH', sport, dport, 8 + len(data), 0)
        fr = eth(ipv4(17, h + data, src, dst))
        if keep is not None:
            return self.add(fr[:14 + 20 + 8 + keep], dt=dt, orig=len(fr))
        return self.add(fr, dt=dt)

    def write(self, fn):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        lts = []
        for lt, _, _, _ in self.frames:
            if lt not in lts:
                lts.append(lt)
        for lt in lts:
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
        for lt, fr, ts, orig in self.frames:
            out += blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32, ts & 0xffffffff, len(fr), orig) + fr)
        open(fn, 'wb').write(out)


class Tcp:
    """One TCP connection; every call returns the frame number."""
    def __init__(self, cap, cport, sport, caddr=C, saddr=S):
        self.cap, self.cport, self.sport, self.caddr, self.saddr = cap, cport, sport, caddr, saddr
        self.cseq, self.sseq = 1000, 5000

    def _seg(self, to_server, flags, data, seq=None, dt=1000):
        if to_server:
            sp, dp, src, dst, s, a = self.cport, self.sport, self.caddr, self.saddr, self.cseq, self.sseq
        else:
            sp, dp, src, dst, s, a = self.sport, self.cport, self.saddr, self.caddr, self.sseq, self.cseq
        if seq is not None:
            s = seq
        if flags & 0x02:
            # SYN and SYN+ACK carry the MSS option; a SYN has no ACK number
            t = struct.pack('!HHIIBBHHH', sp, dp, s, a if flags & 0x10 else 0, 0x60, flags, 65535, 0, 0) \
                + b'\x02\x04\x05\xb4' + data
        else:
            t = struct.pack('!HHIIBBHHH', sp, dp, s, a, 0x50, flags, 65535, 0, 0) + data
        return self.cap.add(eth(ipv4(6, t, src, dst)), dt=dt)

    def handshake(self):
        self._seg(True, 0x02, b'')
        self.cseq += 1
        self._seg(False, 0x12, b'')
        self.sseq += 1
        self._seg(True, 0x10, b'')

    def c2s(self, data, dt=1000):
        n = self._seg(True, 0x18, data, dt=dt)
        self.cseq += len(data)
        return n

    def s2c(self, data, dt=1000):
        n = self._seg(False, 0x18, data, dt=dt)
        self.sseq += len(data)
        return n


def call(xid, prog, vers, proc, args=b'', cred=u(0, 0), verf=u(0, 0)):
    return u(xid, 0, 2, prog, vers, proc) + cred + verf + args


def reply(xid, res=b'', verf=u(0, 0), accept=0):
    return u(xid, 1, 0) + verf + u(accept) + res


def flavor(fl, body):
    return u(fl, len(body)) + body + b'\0' * (-len(body) % 4)


def rec(data, last=True):
    return u((0x80000000 if last else 0) | len(data)) + data


# ---- credentials ----------------------------------------------------------
def unix_cred(machine='client1', uid=1000, gid=100, gids=(4, 24, 27), stamp=0x5a5a5a5a):
    return flavor(1, u(stamp) + xstr(machine) + u(uid, gid, len(gids)) + u(*gids))


def des_full(netname='unix.1000@example.org', window=60):
    return flavor(3, u(0) + xstr(netname) + bytes(range(1, 9)) + u(window))


def des_nick(nick=0x1234):
    return flavor(3, u(1, nick))


def gluster_cred(gids=(5, 6)):
    return flavor(5, b'LKOWNER1' + u(4242, 1000, 100, len(gids)) + u(*gids))


def glusterfs_v2(gids=(7,), owner=b'OWNERBYT'):
    return flavor(390039, u(4242, 1000, 100, len(gids)) + u(*gids) + u(len(owner)) + owner)


def glusterfs_v3(gids=(7, 8), owner=b'OWNERBYT'):
    return flavor(390040, u(4242, 1000, 100, 0x10) + u(1700000000) + struct.pack('>q', 123456789)
                  + u(len(gids)) + u(*gids) + u(len(owner)) + owner)


def authgssapi(msg, handle=b'HNDL'):
    return flavor(300001, u(1, msg) + xstr(handle))


def gss(proc, ctx=b'CTX1', seq=1, svc=1, vers=1):
    return flavor(6, u(vers, proc, seq, svc) + xstr(ctx))


# ---- main capture ---------------------------------------------------------
MARKS = []


def mark(cap, text):
    MARKS.append((cap.n + 1, text))


def main_capture(cap):
    xid = [0x1000]

    def nx():
        xid[0] += 1
        return xid[0]

    def exch(prog, vers, proc, args=b'', rargs=b'', cred=u(0, 0), verf=u(0, 0), rverf=u(0, 0),
             accept=0, sport=800, dport=111, dt=250000, xid_=None):
        x = nx() if xid_ is None else xid_
        c = cap.udp(sport, dport, call(x, prog, vers, proc, args, cred, verf))
        r = cap.udp(dport, sport, reply(x, rargs, rverf, accept), to_server=False, dt=dt)
        return x, c, r

    # ---- UDP basics ----
    mark(cap, 'UDP, port 111: portmap NULL, GETPORT with reply (registered port)')
    exch(PM, 2, 0)
    exch(PM, 2, 3, u(NFS, 3, 17, 0), u(2049))
    mark(cap, 'UDP, heuristic (port 4444): NFS v3 and v4 NULL; Info "V3 NULL Call"')
    exch(NFS, 3, 0, sport=900, dport=4444)
    exch(NFS, 4, 0, sport=900, dport=4444)
    mark(cap, 'Unknown version and procedure of a known program (proc-N), unknown procedure reply')
    exch(NFS, 9, 77, b'\x01\x02\x03\x04', b'\x05\x06\x07\x08')
    mark(cap, 'Unknown program on port 111 (continuation), reply without a call (continuation)')
    x = nx()
    cap.udp(800, 111, call(x, 399999, 1, 0))
    cap.udp(111, 800, reply(x, b''), to_server=False)
    cap.udp(111, 800, reply(0x7777, b''), to_server=False)
    mark(cap, 'Non-RPC datagram on port 111 (continuation); short datagram')
    cap.udp(800, 111, u(1, 7, 3, 4, 5))
    cap.udp(800, 111, b'\x01\x02\x03')

    # ---- credential and verifier flavours ----
    mark(cap, 'AUTH_UNIX credentials: 3 gids, 0 gids, 20 gids (list ends in "..."), long machine name')
    exch(PM, 2, 0, cred=unix_cred())
    exch(PM, 2, 0, cred=unix_cred('h', 0, 0, ()))
    exch(PM, 2, 0, cred=unix_cred('client-with-a-long-machine-name.example.org', 65534, 65534, tuple(range(100, 120))))
    mark(cap, 'AUTH_SHORT, unknown flavour and AUTH_NULL with body (opaque data), unknown flavour verifier')
    exch(PM, 2, 0, cred=flavor(2, b'SHORTCRD'))
    exch(PM, 2, 0, cred=flavor(77, b'abcdefg'), rverf=flavor(78, b'verifier!'))
    exch(PM, 2, 0, cred=flavor(77, b''), rverf=flavor(78, b''))
    mark(cap, 'AUTH_DES: full name and nickname credentials; call verifier (timestamp, window), reply verifier (time, nickname)')
    exch(PM, 2, 0, cred=des_full(), verf=flavor(3, bytes(range(16, 24)) + u(60)),
         rverf=flavor(3, bytes(range(32, 40)) + u(0x1234)))
    exch(PM, 2, 0, cred=des_nick(), verf=flavor(3, bytes(range(16, 24)) + u(60)),
         rverf=flavor(3, bytes(range(32, 40)) + u(0x1234)))
    exch(PM, 2, 0, cred=flavor(3, u(2)))        # unknown name kind
    mark(cap, 'AUTH_UNIX as verifier; Gluster credentials: AUTH_RSA, AUTH_GLUSTERFS, AUTH_GLUSTERFS_V3')
    exch(PM, 2, 0, verf=unix_cred('verf', 1, 2, (3,)), rverf=unix_cred('rverf', 4, 5, ()))
    exch(PM, 2, 0, cred=gluster_cred())
    exch(PM, 2, 0, cred=glusterfs_v2())
    exch(PM, 2, 0, cred=glusterfs_v3())
    mark(cap, 'AUTH_GSSAPI: plain call (data is private), INIT/CONTINUE_INIT/MSG/DESTROY/EXIT messages and replies')
    exch(PM, 2, 0, args=xstr(b'privatedata'), cred=authgssapi(0))
    gi_arg = u(1) + xstr(b'')                       # AUTH_GSSAPI Msg: version, token
    gi_res = u(1) + xstr(b'HNDL') + u(0, 0) + xstr(b'') + xstr(b'ISN!')
    exch(PM, 2, 1, gi_arg, gi_res, cred=authgssapi(1))
    exch(PM, 2, 2, gi_arg, gi_res, cred=authgssapi(1))
    exch(PM, 2, 3, gi_arg, gi_res, cred=authgssapi(1))
    exch(PM, 2, 4, xstr(b'destroy'), xstr(b'destroyed'), cred=authgssapi(1))
    exch(PM, 2, 0, b'', b'', cred=authgssapi(1))
    mark(cap, 'RPCSEC_GSS: INIT call and reply, DATA (service none) and context tracking, '
              'CONTINUE_INIT, DESTROY, context handles of 0, 5 and 17 bytes (the latter is not tracked)')
    initres = lambda ctx: xstr(ctx) + u(0, 0, 128) + xstr(b'')
    for ctx in (b'CTX1', b'CTX3'):
        x, c, r = exch(NFS, 3, 0, xstr(b''), initres(ctx), cred=gss(1, b''), rverf=u(6, 0))
        exch(NFS, 3, 0, b'', b'', cred=gss(0, ctx), verf=u(6, 0), rverf=u(6, 0))
    exch(NFS, 3, 0, xstr(b''), initres(b'CTX2X'), cred=gss(2, b'CTX2X', 2), verf=u(6, 0), rverf=u(6, 0))
    exch(NFS, 3, 0, xstr(b''), initres(b'A' * 17), cred=gss(1, b'A' * 17), rverf=u(6, 0))
    exch(NFS, 3, 0, b'', b'', cred=gss(0, b'CTX2X', 3), rverf=u(6, 0))
    exch(NFS, 3, 0, b'', b'', cred=gss(3, b'CTX1', 4), rverf=u(6, 0))
    exch(NFS, 3, 0, b'', b'', cred=gss(0, b'CTX1', 5, vers=1), rverf=u(6, 0))
    exch(NFS, 3, 0, b'', b'', cred=gss(1, b'', 6, vers=7), rverf=u(6, 0))

    # ---- reply states ----
    mark(cap, 'Reply states: PROG_UNAVAIL, PROG_MISMATCH (version range), PROC_UNAVAIL, GARBAGE_ARGS, SYSTEM_ERR')
    exch(NFS, 3, 0, accept=1)
    x, c, r = exch(PM, 2, 0, rargs=u(2, 3), accept=2)
    exch(PM, 2, 99, accept=3)
    exch(PM, 2, 3, accept=4)
    exch(PM, 2, 3, accept=5)
    exch(PM, 2, 3, accept=1234)
    mark(cap, 'Denied replies: RPC_MISMATCH, AUTH_ERROR, unknown reject state; unknown reply state')
    for stat in ((1, 0, 2, 2), (1, 1, 5), (1, 9), (4,)):
        x = nx()
        cap.udp(800, 111, call(x, PM, 2, 0))
        cap.udp(111, 800, u(x, 1) + u(*stat), to_server=False, dt=250000)

    # ---- retransmission, duplicate reply, XID reuse ----
    mark(cap, 'Retransmission of a call and a duplicate reply (retransmission from a different source port)')
    x = nx()
    cap.udp(800, 111, call(x, PM, 2, 3, u(NFS, 3, 17, 0)))
    cap.udp(801, 111, call(x, PM, 2, 3, u(NFS, 3, 17, 0)), dt=700000)
    cap.udp(111, 800, reply(x, u(2049)), to_server=False)
    cap.udp(111, 801, reply(x, u(2049)), to_server=False)
    cap.udp(800, 111, call(x, PM, 2, 3, u(NFS, 3, 17, 0)), dt=900000)   # late retransmission after the reply
    # reproducers of "RPC: Fix type confusion on reused XIDs and an SRT tap overflow"
    mark(cap, 'Reproducer 1: NFS v3 ACCESS call, then portmap GETPORT with the same XID, reply goes to GETPORT')
    X = 0x11223344
    fh = u(8) + b'FHFHFHFH'
    cap.udp(700, 111, call(X, NFS, 3, 4, fh + u(0x1f)))
    cap.udp(700, 111, call(X, PM, 2, 3, u(NFS, 3, 17, 0)))
    cap.udp(111, 700, reply(X, u(2049)), to_server=False)
    mark(cap, 'Reproducer 2: NFS v3 ACCESS (XID 16), then CALLIT whose argument length 16 is the same key; '
              'the direct ACCESS reply is still an NFS reply')
    cap.udp(700, 111, call(16, NFS, 3, 4, fh + u(0x1f)))
    cap.udp(700, 111, call(0x55, PM, 2, 5, u(PM, 2, 3) + u(16) + u(NFS, 3, 17, 0)))
    cap.udp(111, 700, reply(16, u(0, 0, 0x1f)), to_server=False)
    cap.udp(111, 700, reply(0x55, u(2049) + u(4) + u(2049)), to_server=False)
    mark(cap, 'Reproducer 3: NFS v3 call and reply with procedure 0x80000000 (-z rpc,srt,100003,3)')
    cap.udp(700, 111, call(1, NFS, 3, 0x80000000), dt=100000)
    cap.udp(111, 700, reply(1, u(0)), to_server=False, dt=100000)
    mark(cap, 'Reproducer 4: two RPCSEC_GSS INIT exchanges returning the same context handle')
    gres = u(4) + b'CTX7' + u(0, 0, 128, 0)
    for xx in (0x101, 0x202):
        cap.udp(700, 111, call(xx, NFS, 3, 0, u(0), cred=gss(1, b'')))
        cap.udp(111, 700, reply(xx, gres), to_server=False)
        cap.udp(700, 111, call(xx + 1, NFS, 3, 0, b'', cred=gss(0, b'CTX7')))
    cap.udp(700, 111, call(0x303, NFS, 3, 0, b'', cred=gss(3, b'CTX7')))

    # ---- indirect calls: portmap CALLIT ----
    mark(cap, 'Indirect calls (CALLIT, port 4444): the reply is matched by the argument length (16) the '
              'call was recorded under; an unknown program; a reply whose key matches no call')
    cap.udp(700, 4444, call(0x66, PM, 2, 5, u(PM, 2, 3) + u(16) + u(NFS, 3, 17, 0)))
    cap.udp(4444, 700, reply(0x66, u(16) + u(4) + u(2049)), to_server=False)
    cap.udp(700, 4444, call(0x67, PM, 2, 5, u(777777, 1, 0) + u(8) + b'ABCDEFGH'))
    cap.udp(4444, 700, reply(0x67, u(2049) + u(4) + u(2049)), to_server=False)
    cap.udp(700, 4444, call(0x68, PM, 2, 5, u(PM, 2, 0) + u(0)))
    cap.udp(4444, 700, reply(0x68, u(0) + u(0)), to_server=False)

    # ---- TCP ----
    mark(cap, 'TCP, port 111: call and reply in one segment each, two records in one segment')
    t = Tcp(cap, 1023, 111)
    t.handshake()
    t.c2s(rec(call(0x2001, PM, 2, 0)))
    t.s2c(rec(reply(0x2001)), dt=300000)
    t.c2s(rec(call(0x2002, PM, 2, 3, u(NFS, 3, 6, 0))) + rec(call(0x2003, PM, 2, 0)))
    t.s2c(rec(reply(0x2002, u(2049))) + rec(reply(0x2003)), dt=300000)
    mark(cap, 'TCP: call whose record is split over two segments (desegmentation), then a reply split in three')
    d = rec(call(0x2004, PM, 2, 3, u(NFS, 3, 6, 0)))
    t.c2s(d[:30]); t.c2s(d[30:], dt=10000)
    d = rec(reply(0x2004, u(2049)))
    t.s2c(d[:5]); t.s2c(d[5:20]); t.s2c(d[20:], dt=10000)
    mark(cap, 'TCP: record in three RPC fragments, one TCP segment each; reply fragmented too; '
              'fragments of one record in one segment')
    msg = call(0x2005, PM, 2, 3, u(NFS, 3, 6, 0))
    t.c2s(rec(msg[:24], False)); t.c2s(rec(msg[24:44], False)); t.c2s(rec(msg[44:], True))
    msg = reply(0x2005, u(2049))
    t.s2c(rec(msg[:12], False)); t.s2c(rec(msg[12:], True))
    msg = call(0x2006, PM, 2, 3, u(NFS, 3, 6, 0))
    t.c2s(rec(msg[:24], False) + rec(msg[24:44], False) + rec(msg[44:], True))
    t.s2c(rec(reply(0x2006, u(2049))))
    mark(cap, 'TCP: fragments with a fragment in the middle of the next segment; many calls pipelined')
    msg = call(0x2007, PM, 2, 3, u(NFS, 3, 6, 0))
    t.c2s(rec(msg[:24], False)[:10]); t.c2s(rec(msg[:24], False)[10:] + rec(msg[24:], True))
    t.s2c(rec(reply(0x2007, u(2049))))
    for i in range(4):
        t.c2s(rec(call(0x2010 + i, PM, 2, 0)))
    for i in range(4):
        t.s2c(rec(reply(0x2010 + i)))
    mark(cap, 'TCP: non-RPC data on port 111, record mark that is too large, reply without a call, 3 byte segment')
    t.c2s(b'GET / HTTP/1.0\r\n\r\n')
    t.s2c(u(0x80000000 | 0x7fffff00) + b'\0' * 20)
    t.s2c(rec(reply(0x9999, u(2049))))
    t.c2s(b'\x80\x00\x00')
    t.c2s(u(0x80000001, 5))
    # TCP on a port only the heuristic finds
    mark(cap, 'TCP, port 41000 (heuristic): calls, replies, a call split in two segments, pipelined records')
    t2 = Tcp(cap, 40000, 41000)
    t2.handshake()
    t2.c2s(rec(call(0x3001, NFS, 3, 0, cred=unix_cred())))
    t2.s2c(rec(reply(0x3001)), dt=300000)
    d = rec(call(0x3002, NFS, 3, 0, cred=unix_cred()))
    t2.c2s(d[:20]); t2.c2s(d[20:], dt=10000)
    t2.s2c(rec(reply(0x3002)))
    t2.c2s(rec(call(0x3003, NFS, 4, 0)) + rec(call(0x3004, NFS, 4, 0)))
    t2.s2c(rec(reply(0x3003)) + rec(reply(0x3004)))
    mark(cap, 'TCP, port 41002 (heuristic): the first call is split in two segments, then a reply that is split')
    t5 = Tcp(cap, 40003, 41002)
    t5.handshake()
    d = rec(call(0x3101, NFS, 3, 0))
    t5.c2s(d[:24]); t5.c2s(d[24:], dt=10000)
    d = rec(reply(0x3101))
    t5.s2c(d[:10]); t5.s2c(d[10:], dt=10000)
    mark(cap, 'TCP, port 41001: a stream that starts in the middle of a record: the reply is found only with '
              'rpc.find_fragment_start (default: continuation)')
    t3 = Tcp(cap, 40001, 41001)
    t3.handshake()
    t3.s2c(b'\xde\xad\xbe\xef' * 3 + rec(reply(0x4001, u(0))), dt=300000)
    mark(cap, 'TCP, port 2049: RPC with AUTH_TLS (STARTTLS probe): NULL call, reply with the STARTTLS verifier')
    t4 = Tcp(cap, 40002, 2049)
    t4.handshake()
    t4.c2s(rec(call(0x5001, NFS, 3, 0, cred=u(7, 0))))
    t4.s2c(rec(reply(0x5001, verf=u(7, 8) + b'STARTTLS')), dt=300000)
    mark(cap, 'Exported PDU: rpc-tcp and rpc-with-tls entry points (no TCP/TLS information: continuation)')
    cap.add(exp_pdu('rpc-tcp', rec(call(0x6001, PM, 2, 0))), lt=252)
    cap.add(exp_pdu('rpc-with-tls', rec(call(0x6002, PM, 2, 0))), lt=252)
    cap.add(exp_pdu('rpc', call(0x6003, PM, 2, 0)), lt=252)


def malformed_capture(cap):
    xid = [0x8000]

    def nx():
        xid[0] += 1
        return xid[0]
    # XID reuse: the same XID for different procedures and programs, with replies in between. The
    # dissector keeps one entry per XID, so a second pass attaches the reply to the last call
    x = nx()
    for pr, vr, pc, ar, rr in ((PM, 2, 0, b'', b''), (PM, 2, 0, b'', b''), (PM, 2, 3, u(NFS, 3, 17, 0), u(2049)), (NFS, 3, 0, b'', b'')):
        cap.udp(800, 111, call(x, pr, vr, pc, ar))
        cap.udp(111, 800, reply(x, rr), to_server=False)
    # truncated captures (snaplen): the call is cut after the program, the version, the cred flavour
    for keep, cr in ((16, gss(0)), (24, gss(0)), (28, gss(0)), (36, gss(0)), (40, gss(0)),
                     (28, authgssapi(0)), (34, authgssapi(0)), (26, u(0, 0))):
        x = nx()
        cap.udp(800, 111, call(x, PM, 2, 0, cred=cr), keep=keep)
        cap.udp(111, 800, reply(x, u(2049)), to_server=False)
    # call with RPCSEC_GSS credential but no space for the GSS procedure and service
    cap.udp(800, 111, call(nx(), NFS, 3, 0, cred=u(6, 0)))
    # call with an RPCSEC_GSS credential that ends in the middle
    cap.udp(800, 111, call(nx(), NFS, 3, 0, cred=u(6, 8) + u(1, 1)))
    # AUTH_UNIX credential claiming 5 gids but holding none
    cap.udp(800, 111, call(nx(), PM, 2, 0, cred=flavor(1, u(1) + xstr('m') + u(1, 2, 5))))
    # AUTH_DES verifier too short for its window
    cap.udp(800, 111, call(nx(), PM, 2, 0, verf=flavor(3, b'12345678')))
    # reply too short for its accept state
    x = nx()
    cap.udp(800, 111, call(x, PM, 2, 0))
    cap.udp(111, 800, u(x, 1, 0, 0, 0), to_server=False)
    # PROG_MISMATCH without the version range
    x = nx()
    cap.udp(800, 111, call(x, PM, 2, 0))
    cap.udp(111, 800, u(x, 1, 0, 0, 0, 2), to_server=False)
    # AUTH_ERROR reject without the state
    x = nx()
    cap.udp(800, 111, call(x, PM, 2, 0))
    cap.udp(111, 800, u(x, 1, 1, 1), to_server=False)
    # NFS ACCESS truncated after the RPC header: exception inside the NFS dissector
    cap.udp(800, 111, call(nx(), NFS, 3, 4))
    # truncated GSS init argument and result (token length past the end)
    cap.udp(800, 111, call(nx(), NFS, 3, 0, u(1000, 1), cred=gss(1, b'')))
    x = nx()
    cap.udp(800, 111, call(x, NFS, 3, 0, u(0), cred=gss(1, b'')))
    cap.udp(111, 800, reply(x, u(300) + b'abc'), to_server=False)
    # RPCSEC_GSS tokens that are not GSS-API tokens (the GSS-API dissector throws), in a verifier and an init argument
    x = nx()
    cap.udp(800, 111, call(x, NFS, 3, 0, xstr(b'xyz'), cred=gss(1, b'')))
    cap.udp(111, 800, reply(x, u(4) + b'CTX9' + u(0, 0, 128) + xstr(b'abc'), verf=u(6) + xstr(b'junk')), to_server=False)
    # AUTH_GSSAPI messages with truncated bodies
    for proc in (1, 4):
        cap.udp(800, 111, call(nx(), PM, 2, proc, u(1), cred=authgssapi(1)))
    x = nx()
    cap.udp(800, 111, call(x, PM, 2, 1, u(1) + xstr(b''), cred=authgssapi(1)))
    cap.udp(111, 800, reply(x, u(1) + xstr(b'H')), to_server=False)
    # TCP: record mark claims more than is captured and no further data
    t = Tcp(cap, 1100, 111)
    t.handshake()
    t.c2s(u(0x80000040) + call(0x7001, PM, 2, 0)[:20])
    # fragments that never end (first fragment only), then a fragment from nowhere
    t.c2s(rec(call(0x7002, PM, 2, 3, u(NFS, 3, 6, 0))[:24], False))
    t.c2s(rec(b'\0' * 12, True))
    # a record whose fragments overlap in length: the last fragment is shorter than the call needs
    t.c2s(rec(call(0x7003, PM, 2, 3, u(NFS, 3, 6, 0))[:24], False))
    t.c2s(rec(b'\0' * 4, True))
    # RPC record containing only a record mark
    t.c2s(u(0x80000000))
    # truncated call on TCP: the stream says 20 bytes, the call needs more
    t.c2s(rec(call(0x7004, NFS, 3, 4)[:24]))
    # Exported PDU with a truncated RPC call
    cap.add(exp_pdu('rpc', u(0x7005, 0, 2, PM, 2)), lt=252)


def write_repro(path, frames, lt=1):
    cap = Cap()
    for f in frames:
        cap.add(f, lt=lt)
    cap.write(path)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    cap = Cap()
    main_capture(cap)
    cap.write(os.path.join(out, 'rpc-coverage.pcapng'))
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for n, text in MARKS:
            f.write('%d %s\n' % (n, text))
    print('main: %d frames' % cap.n)
    mc = Cap()
    malformed_capture(mc)
    # frames in the malformed capture may carry a separate reported length
    mc.write(os.path.join(out, 'rpc-coverage-malformed.pcapng'))
    print('malformed: %d frames' % mc.n)


if __name__ == '__main__':
    main()
