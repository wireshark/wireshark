#!/usr/bin/env python3
# Generates test/captures/rpcrdma_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the RPC-over-RDMA (RFC 8166) coverage captures: RoCEv2 (InfiniBand
# transport over UDP 4791) and iWARP (MPA/DDP/RDMAP over TCP).
# Usage: mkrpcrdma.py <outdir>
# Writes rpcrdma-coverage.pcapng (main, decodes cleanly) and rpcrdma-coverage-malformed.pcapng.
# Everything is built with struct; nothing comes from a real network.
import os
import struct
import sys

C, S = "192.0.2.1", "192.0.2.2"

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


PM, NFS = 100000, 100003


def call(xid, prog, vers, proc, args=b'', cred=u(0, 0), verf=u(0, 0)):
    return u(xid, 0, 2, prog, vers, proc) + cred + verf + args


def reply(xid, res=b'', verf=u(0, 0), accept=0):
    return u(xid, 1, 0) + verf + u(accept) + res


# ---- RPC-over-RDMA headers --------------------------------------------------
RDMA_MSG, RDMA_NOMSG, RDMA_MSGP, RDMA_DONE, RDMA_ERROR = 0, 1, 2, 3, 4


def rh(xid, typ, body=b'', credits=32):
    return u(xid, 1, credits, typ) + body


def seg(handle, length, offset):
    return u(handle, length) + struct.pack('>Q', offset)


def rdma_msg(xid, rpc, reads=(), writes=(), reply_chunk=None, typ=RDMA_MSG, credits=32):
    """reads: [(position, handle, length, offset)]; writes: [[(handle, length, offset), ...]];
    reply_chunk: [(handle, length, offset), ...] or None."""
    b = b''
    for pos, h, ln, off in reads:
        b += u(1, pos) + seg(h, ln, off)
    b += u(0)
    for chunk in writes:
        b += u(1, len(chunk)) + b''.join(seg(*s) for s in chunk)
    b += u(0)
    if reply_chunk is None:
        b += u(0)
    else:
        b += u(1, len(reply_chunk)) + b''.join(seg(*s) for s in reply_chunk)
    return rh(xid, typ, b, credits) + rpc


def rdma_msgp(xid, rpc, align=4, thresh=64):
    return u(xid, 1, 32, RDMA_MSGP) + u(align, thresh) + u(0, 0, 0) + rpc


# ---- NFS v3 messages used as the RPC payload ---------------------------------
FH = u(8) + b'FHFHFHFH'
CALL_HDR = 40          # RPC call header with AUTH_NULL credentials and verifier


def nfs3_write_call_reduced(xid, count):
    """NFS v3 WRITE call up to and including the opaque length (the data is
    transferred by an RDMA read); the data starts at XDR position CALL_HDR + 32."""
    return call(xid, NFS, 3, 7, FH + struct.pack('>Q', 0) + u(count, 2, count))


def nfs3_write_call_full(xid, data):
    return call(xid, NFS, 3, 7, FH + struct.pack('>Q', 0) + u(len(data), 2) + xstr(data))


def nfs3_read_call(xid, count):
    return call(xid, NFS, 3, 6, FH + struct.pack('>Q', 0) + u(count))


def nfs3_read_reply_reduced(xid, count):
    """READ reply up to and including the opaque length of the data."""
    return reply(xid, u(0, 0, count, 1, count))


def nfs3_read_reply_full(xid, data):
    return reply(xid, u(0, 0, len(data), 1) + xstr(data))


# ---- InfiniBand (RoCEv2) ---------------------------------------------------------
SEND_FIRST, SEND_MIDDLE, SEND_LAST, SEND_ONLY = 0x00, 0x01, 0x02, 0x04
WRITE_FIRST, WRITE_MIDDLE, WRITE_LAST, WRITE_ONLY = 0x06, 0x07, 0x08, 0x0a
WRITE_LAST_IMM, WRITE_ONLY_IMM = 0x09, 0x0b
READ_REQUEST = 0x0c
READ_RESP_FIRST, READ_RESP_MIDDLE, READ_RESP_LAST, READ_RESP_ONLY = 0x0d, 0x0e, 0x0f, 0x10
SEND_LAST_INVAL, SEND_ONLY_INVAL = 0x16, 0x17
QP_C, QP_S = 0x000a10, 0x000a20     # the QPs set up by the CM exchange


def bth(op, psn, pad=0, dqp=QP_S):
    return struct.pack('>BBHB', op, pad << 4, 0xffff, 0) + dqp.to_bytes(3, 'big') + b'\0' + psn.to_bytes(3, 'big')


# ---- CM (connection manager) MADs, copied in shape from the InfiniBand coverage generator ----
UD_SEND_ONLY = 100
CM_REQ, CM_REP, CM_RTU, CM_DREQ, CM_DRSP = 0x10, 0x13, 0x14, 0x15, 0x16


def deth(sqp, qkey=0x80010000):
    return struct.pack('>IB', qkey, 0) + sqp.to_bytes(3, 'big')


def mad(cls, method, attr, tid, data, status=0, cspec=0, mod=0, ver=1, clsver=1):
    h = struct.pack('>BBBBHHQHHI', ver, cls, clsver, method, status, cspec, tid, attr, 0, mod)
    return h + data.ljust(232, b'\0')[:232]


def cm_req(comm_id, sid, qpn, llid, rlid, lgid, rgid, ipcm_ver=None, priv=b'', v4=True):
    d = bytearray(232)
    struct.pack_into('>I', d, 0, comm_id)
    struct.pack_into('>Q', d, 8, sid)
    struct.pack_into('>Q', d, 16, 0x0002c90300aabbcc)     # CA GUID
    struct.pack_into('>I', d, 28, 0x80010000)
    d[32:35] = qpn.to_bytes(3, 'big')
    d[35] = 0x10
    d[39] = 0x10
    d[43] = 0x1f
    d[44:47] = (0x000100).to_bytes(3, 'big')
    struct.pack_into('>H', d, 48, 0xffff)
    d[50] = 0x40
    d[51] = 0x73
    struct.pack_into('>HH', d, 52, llid, rlid)
    if v4:
        d[56 + 12:56 + 16] = lgid
        d[72 + 12:72 + 16] = rgid
    else:
        d[56:72] = lgid
        d[72:88] = rgid
    d[88:90] = b'\x00\x01'
    d[140:140 + len(priv)] = priv
    return bytes(d)


def ipcm_priv(ipv, sip, dip, sport=0x1234, consumer=b''):
    """IP CM private data (36 octets) + 56 octets of consumer data"""
    p = bytes([0x00, ipv << 4]) + struct.pack('>H', sport)
    if ipv == 4:
        p += b'\0' * 12 + sip + b'\0' * 12 + dip
    else:
        p += sip + dip
    return p + consumer.ljust(56, b'\0')


def cm_rep(local_id, remote_id, qpn, priv=b''):
    d = bytearray(232)
    struct.pack_into('>II', d, 0, local_id, remote_id)
    struct.pack_into('>I', d, 8, 0x80010000)
    d[12:15] = qpn.to_bytes(3, 'big')
    d[20:23] = (0x000200).to_bytes(3, 'big')
    d[24] = 0x10
    d[25] = 0x10
    d[26] = 0x6c
    d[27] = 0x03
    struct.pack_into('>Q', d, 28, 0x0002c90300ddeeff)
    d[36:36 + len(priv)] = priv
    return bytes(d)


def cm_rtu(local_id, remote_id, priv=b''):
    return struct.pack('>II', local_id, remote_id) + priv.ljust(224, b'\0')


def cm_dreq(local_id, remote_id, qpn, priv=b''):
    return struct.pack('>II', local_id, remote_id) + qpn.to_bytes(3, 'big') + b'\0' + priv.ljust(220, b'\0')


def cm_drsp(local_id, remote_id, priv=b''):
    return struct.pack('>II', local_id, remote_id) + priv.ljust(224, b'\0')


CM_REQ, CM_REJ, CM_REP, CM_RTU, CM_DREQ, CM_DRSP = 0x10, 0x12, 0x13, 0x14, 0x15, 0x16


def ud_mad(m, dqp=1, sqp=1):
    return bth(UD_SEND_ONLY, 0, 0, dqp) + deth(sqp) + m


def cm(attr, tid, data):
    return ud_mad(mad(7, 3, attr, tid, data), 1, 1)


def reth(va, rkey, ln):
    return struct.pack('>QII', va, rkey, ln)


def aeth(msn=1):
    return b'\0' + msn.to_bytes(3, 'big')


class Ib:
    def __init__(self, cap):
        self.cap = cap
        self.psn = 100

    def pkt(self, to_server, op, payload=b'', extra=b'', psn=None, dt=1000):
        pad = (-len(payload)) % 4
        if psn is None:
            psn = self.psn
            self.psn += 1
        body = bth(op, psn, pad, QP_S if to_server else QP_C) + extra + payload + b'\0' * pad + b'\0\0\0\0'
        return self.wrap(body, to_server, dt)

    def wrap(self, body, to_server, dt=1000):
        h = struct.pack('!HHHH', 49152, 4791, 8 + len(body), 0)
        src, dst = (C, S) if to_server else (S, C)
        return self.cap.add(eth(ipv4(17, h + body, src, dst)), dt=dt)

    def connect(self, disconnect=False):
        a, b = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
        priv = ipcm_priv(4, a, b, consumer=b'rpcrdma')
        self.wrap(cm(CM_REQ, 0x100, cm_req(0x11, 0x0000000001060000 | 20049, QP_C, 0x11, 0x22, a, b, priv=priv)) + b'\0' * 4, True)
        self.wrap(cm(CM_REP, 0x100, cm_rep(0x22, 0x11, QP_S, priv=b'reply')) + b'\0' * 4, False)
        self.wrap(cm(CM_RTU, 0x100, cm_rtu(0x11, 0x22)) + b'\0' * 4, True)

    def send(self, to_server, payload, op=SEND_ONLY, psn=None):
        extra = b'\0\0\0\0' if op in (SEND_LAST_INVAL, SEND_ONLY_INVAL) else b''
        return self.pkt(to_server, op, payload, extra, psn)

    def send_frags(self, to_server, payload, sizes, last_op=SEND_LAST):
        pos = 0
        for i, n in enumerate(sizes):
            part = payload[pos:pos + n] if i < len(sizes) - 1 else payload[pos:]
            pos += n
            op = SEND_FIRST if i == 0 else (last_op if i == len(sizes) - 1 else SEND_MIDDLE)
            self.send(to_server, part, op)

    def write(self, to_server, va, rkey, total, data, op=WRITE_ONLY, extra_after=b''):
        e = reth(va, rkey, total) if op in (WRITE_FIRST, WRITE_ONLY, WRITE_ONLY_IMM) else b''
        e += extra_after
        return self.pkt(to_server, op, data, e)

    def write_frags(self, to_server, va, rkey, data, size):
        parts = [data[i:i + size] for i in range(0, len(data), size)]
        for i, p in enumerate(parts):
            if len(parts) == 1:
                self.write(to_server, va, rkey, len(data), p, WRITE_ONLY)
            elif i == 0:
                self.write(to_server, va, rkey, len(data), p, WRITE_FIRST)
            elif i == len(parts) - 1:
                self.write(to_server, va, rkey, len(data), p, WRITE_LAST)
            else:
                self.write(to_server, va, rkey, len(data), p, WRITE_MIDDLE)

    def read(self, req_to_server, va, rkey, data, size):
        """RDMA read of len(data) bytes: request and the response packets."""
        n = (len(data) + size - 1) // size
        p0 = self.psn
        self.pkt(req_to_server, READ_REQUEST, b'', reth(va, rkey, len(data)))
        self.psn = p0 + 1
        parts = [data[i:i + size] for i in range(0, len(data), size)] or [b'']
        for i, p in enumerate(parts):
            if n == 1:
                op, ex = READ_RESP_ONLY, aeth()
            elif i == 0:
                op, ex = READ_RESP_FIRST, aeth()
            elif i == n - 1:
                op, ex = READ_RESP_LAST, aeth()
            else:
                op, ex = READ_RESP_MIDDLE, b''
            self.pkt(not req_to_server, op, p, ex, psn=p0 + i)
        self.psn = p0 + max(n, 1)


# ---- iWARP (MPA/DDP/RDMAP over TCP) ----------------------------------------------
def ddp_send(msn, mo, data, last=True, qn=0):
    ctl = (0x40 if last else 0) | 0x01
    return bytes([ctl, 0x43]) + u(0) + struct.pack('>III', qn, msn, mo) + data


def ddp_write(stag, to, data, last=True):
    ctl = 0x80 | (0x40 if last else 0) | 0x01
    return bytes([ctl, 0x40]) + struct.pack('>IQ', stag, to) + data


def ddp_read_response(stag, to, data, last=True):
    ctl = 0x80 | (0x40 if last else 0) | 0x01
    return bytes([ctl, 0x42]) + struct.pack('>IQ', stag, to) + data


def rdma_read_request(sink_stag, sink_to, size, src_stag, src_to):
    return (bytes([0x41, 0x41]) + u(0) + struct.pack('>III', 1, 0, 0)
            + struct.pack('>IQIIQ', sink_stag, sink_to, size, src_stag, src_to))


def fpdu(ulpdu):
    base = struct.pack('>H', len(ulpdu)) + ulpdu
    base += b'\0' * ((-len(base)) % 4)
    return base + b'\0\0\0\0'


MARKS = []


def mark(cap, text):
    MARKS.append((cap.n + 1, text))


def main_capture(cap, reduced_replies=False):
    ib = Ib(cap)
    mark(cap, 'RoCEv2 connection set up by the CM (REQ, REP, RTU): the QPs of the RC connection')
    ib.connect()
    xid = [0]

    def nx():
        xid[0] += 1
        return xid[0]

    # ----- RoCEv2 ---------------------------------------------------------------
    mark(cap, 'RoCEv2 SEND_ONLY: RDMA_MSG call and reply without chunks (NFS v3 NULL)')
    x = nx()
    ib.send(True, rdma_msg(x, call(x, NFS, 3, 0)))
    ib.send(False, rdma_msg(x, reply(x)))
    mark(cap, 'RDMA_MSGP (padded) call, RDMA_NOMSG without chunks, RDMA_DONE')
    x = nx()
    ib.send(True, rdma_msgp(x, call(x, NFS, 3, 0)))
    ib.send(False, rdma_msgp(x, reply(x)))
    ib.send(True, rh(x, RDMA_NOMSG, u(0, 0, 0)))
    ib.send(True, rh(x, RDMA_DONE))
    mark(cap, 'RDMA_ERROR: ERR_VERS (versions), ERR_CHUNK, unknown error code with data')
    ib.send(False, rh(nx(), RDMA_ERROR, u(1, 1, 1)))
    ib.send(False, rh(nx(), RDMA_ERROR, u(2)))
    ib.send(False, rh(nx(), RDMA_ERROR, u(9, 0xdead, 0xbeef)))
    mark(cap, 'SEND_ONLY_INVAL; RDMA_MSG with a reply chunk and write chunks that need no I/O (NULL calls); '
              'RDMA_MSG whose RPC header has another XID (not RPC-over-RDMA: stays InfiniBand)')
    x = nx()
    ib.send(True, rdma_msg(x, call(x, NFS, 3, 0)), op=SEND_ONLY_INVAL)
    x = nx()
    ib.send(True, rdma_msg(x, call(x, NFS, 3, 0), writes=[[(0x7001, 0, 0x5000)], [(0x7002, 0, 0x6000), (0x7003, 0, 0x7000)]]))
    ib.send(False, rdma_msg(x, reply(x), writes=[[(0x7001, 0, 0x5000)], [(0x7002, 0, 0x6000), (0x7003, 0, 0x7000)]]))
    x = nx()
    ib.send(True, rh(x, RDMA_MSG, u(0, 0, 0)) + call(x + 5, NFS, 3, 0))
    mark(cap, 'RDMA_MSG split over SEND_FIRST/SEND_MIDDLE/SEND_LAST (reassembled), another over '
              'SEND_FIRST/SEND_LAST_INVAL; a call with data in the message (no chunks)')
    x = nx()
    m = rdma_msg(x, nfs3_write_call_full(x, bytes(range(64))))
    ib.send_frags(True, m, [40, 40], last_op=SEND_LAST)
    x = nx()
    m = rdma_msg(x, nfs3_write_call_full(x, bytes(range(80))))
    ib.send_frags(True, m, [60], last_op=SEND_LAST_INVAL)
    x = nx()
    ib.send(True, rdma_msg(x, nfs3_write_call_full(x, b'inline data')))
    ib.send(False, rdma_msg(x, reply(x, u(0, 0, 0, 0, 11, 2) + b'\0' * 8)))

    # --- read chunk: NFS WRITE with the data fetched by the server with RDMA reads
    mark(cap, 'Read chunk (NFS WRITE): the reduced call, the RDMA read request and a single READ_RESPONSE_ONLY '
              'that completes the call')
    x = nx()
    data = bytes((i * 7) & 0xff for i in range(100))
    ib.send(True, rdma_msg(x, nfs3_write_call_reduced(x, len(data)), reads=[(CALL_HDR + 32, 0x1001, len(data), 0x10000)]))
    ib.read(False, 0x10000, 0x1001, data, 100)
    ib.send(False, rdma_msg(x, reply(x, u(0, 0, 0, 0, len(data), 2) + b'\0' * 8)))
    mark(cap, 'Read chunk read with READ_RESPONSE_FIRST/MIDDLE/LAST (three packets of 64 bytes, the last shorter)')
    x = nx()
    data = bytes((i * 3) & 0xff for i in range(150))
    ib.send(True, rdma_msg(x, nfs3_write_call_reduced(x, len(data)), reads=[(CALL_HDR + 32, 0x1002, len(data), 0x20000)]))
    ib.read(False, 0x20000, 0x1002, data, 64)
    ib.send(False, rdma_msg(x, reply(x, u(0, 0, 0, 0, len(data), 2) + b'\0' * 8)))
    mark(cap, 'Read chunks at two XDR positions of one call (a list of two chunks)')
    x = nx()
    d1 = bytes(range(32)); d2 = bytes(range(40, 72))
    rpc = call(x, NFS, 3, 7, FH + struct.pack('>Q', 0) + u(len(d1), 2, len(d1)))
    ib.send(True, rdma_msg(x, rpc, reads=[(CALL_HDR + 32, 0x1003, 32, 0x30000), (CALL_HDR + 32 + 8, 0x1004, 32, 0x31000)]))
    ib.read(False, 0x30000, 0x1003, d1, 32)
    ib.read(False, 0x31000, 0x1004, d2, 32)
    ib.send(False, rdma_msg(x, reply(x, u(0, 0, 0, 0, 32, 2) + b'\0' * 8)))

    # --- write chunk: NFS READ with the data written by the server
    mark(cap, 'Write chunk (NFS READ): call with a write list and RDMA_WRITE_ONLY (the reduced replies are only in '
              'the malformed capture: a write chunk is reassembled on the second pass only)')
    x = nx()
    data = bytes((i * 5) & 0xff for i in range(64))
    ib.send(True, rdma_msg(x, nfs3_read_call(x, 64), writes=[[(0x2001, 64, 0x40000)]]))
    ib.write(False, 0x40000, 0x2001, 64, data, WRITE_ONLY)
    if reduced_replies:
        ib.send(False, rdma_msg(x, nfs3_read_reply_reduced(x, 64), writes=[[(0x2001, 64, 0x40000)]]))
    mark(cap, 'Write chunk written with WRITE_FIRST/MIDDLE/LAST (64 byte packets), two segments in the chunk')
    x = nx()
    data = bytes((i * 11) & 0xff for i in range(192))
    ib.send(True, rdma_msg(x, nfs3_read_call(x, 192), writes=[[(0x2002, 128, 0x50000), (0x2003, 64, 0x60000)]]))
    ib.write_frags(False, 0x50000, 0x2002, data[:128], 64)
    ib.write_frags(False, 0x60000, 0x2003, data[128:], 64)
    if reduced_replies:
        ib.send(False, rdma_msg(x, nfs3_read_reply_reduced(x, 192), writes=[[(0x2002, 128, 0x50000), (0x2003, 64, 0x60000)]]))
    mark(cap, 'Write chunk with WRITE_ONLY_IMM and WRITE_LAST_IMM')
    x = nx()
    data = bytes(range(64))
    ib.send(True, rdma_msg(x, nfs3_read_call(x, 64), writes=[[(0x2004, 64, 0x70000)]]))
    ib.pkt(False, WRITE_ONLY_IMM, data, reth(0x70000, 0x2004, 64) + u(0x11))
    if reduced_replies:
        ib.send(False, rdma_msg(x, nfs3_read_reply_reduced(x, 64), writes=[[(0x2004, 64, 0x70000)]]))

    # --- reply chunk
    mark(cap, 'Reply chunk: call with a reply chunk, the reply written with RDMA_WRITE_ONLY, then RDMA_NOMSG')
    x = nx()
    rp = reply(x)
    ib.send(True, rdma_msg(x, call(x, NFS, 3, 0), reply_chunk=[(0x3001, len(rp), 0x80000)]))
    ib.write(False, 0x80000, 0x3001, len(rp), rp, WRITE_ONLY)
    ib.send(False, rh(x, RDMA_NOMSG, u(0, 0, 1, 1) + seg(0x3001, len(rp), 0x80000)))
    mark(cap, 'Reply chunk written with WRITE_FIRST/WRITE_LAST (a reply of 100 bytes in two packets)')
    x = nx()
    rp = reply(x) + b'\0' * 76   # an NFS v3 NULL reply and trailing data: 100 bytes in two packets

    ib.send(True, rdma_msg(x, call(x, NFS, 3, 0), reply_chunk=[(0x3002, len(rp), 0x90000)]))
    ib.write_frags(False, 0x90000, 0x3002, rp, 64)
    ib.send(False, rh(x, RDMA_NOMSG, u(0, 0, 1, 1) + seg(0x3002, len(rp), 0x90000)))

    # --- position-zero read chunk: the whole RPC call is read, the last read response has padding bytes
    mark(cap, 'Position-zero read chunk (RDMA_NOMSG): the whole call (74 bytes) is read with a read response '
              'first (64) and last (10) packet, the last with 2 padding bytes')
    x = nx()
    pz = call(x, NFS, 3, 0) + bytes(range(34))
    ib.send(True, rh(x, RDMA_NOMSG, u(1, 0, 0x1201, len(pz)) + struct.pack('>Q', 0xa0000) + u(0, 0, 0)))
    ib.read(False, 0xa0000, 0x1201, pz, 64)

    # --- non-RPC traffic on the same transport
    mark(cap, 'Frames that are not RPC-over-RDMA: a SEND with garbage, a SEND with a bad version, '
              'an RDMA read that matches no chunk, a write with no segment, an unknown reply chunk')
    ib.send(True, b'garbage garbage garbage garbage')
    ib.send(True, u(1, 2, 3, 0) + u(0, 0, 0))
    ib.read(False, 0xdead0000, 0x9999, b'unmatched read data....', 16)
    ib.write(False, 0xdead0000, 0x9998, 8, b'12345678', WRITE_ONLY)
    ib.pkt(False, WRITE_MIDDLE, b'12345678')
    ib.pkt(True, 0x11, b'')               # an opcode RPC-over-RDMA ignores (ACKNOWLEDGE)

    # --- the reproducer of the stale InfiniBand info pointer
    mark(cap, 'Reproducer (stale InfiniBand pointer): RDMA_DONE over RoCEv2, then Exported PDU rpcordma with a read chunk')
    ib.send(True, rh(0x9001, RDMA_DONE))
    rdma = u(2, 1, 1, 0) + u(1, 4, 0x1234, 100, 0, 0) + u(0) + u(0) + u(0)
    cap.add(exp_pdu('rpcordma', rdma + u(2, 0, 2, NFS, 3, 7)), lt=252)
    cap.add(exp_pdu('rpcordma', rh(0x9002, RDMA_DONE)), lt=252)
    cap.add(exp_pdu('rpcordma', rdma_msg(0x9003, call(0x9003, NFS, 3, 0))), lt=252)

    # ----- iWARP -------------------------------------------------------------------
    mark(cap, 'iWARP: MPA handshake, SEND call and reply (RDMA_MSG)')
    CP, SP = 40000, 20049
    t = Tcp(cap, CP, SP)
    t.handshake()
    req = b'MPA ID Req Frame' + bytes([0, 1]) + struct.pack('!H', 0)
    rep = b'MPA ID Rep Frame' + bytes([0, 1]) + struct.pack('!H', 0)
    t.c2s(req)
    t.s2c(rep)
    msn = {True: [0], False: [0]}

    def isend(to_server, rpcrdma, last=True, mo=0, new=True):
        if new:
            msn[to_server][0] += 1
        d = ddp_send(msn[to_server][0], mo, rpcrdma, last)
        (t.c2s if to_server else t.s2c)(fpdu(d))
    x = nx()
    isend(True, rdma_msg(x, call(x, NFS, 3, 0)))
    isend(False, rdma_msg(x, reply(x)))
    mark(cap, 'iWARP: an RDMA_MSG split over two SENDs (first, last)')
    x = nx()
    m = rdma_msg(x, nfs3_write_call_full(x, bytes(range(60))))
    isend(True, m[:50], last=False)
    isend(True, m[50:], last=True, mo=50, new=False)
    mark(cap, 'iWARP: a SEND in three DDP segments (first, middle, last)')
    x = nx()
    m = rdma_msg(x, nfs3_write_call_full(x, bytes(range(60))))
    isend(True, m[:30], last=False)
    isend(True, m[30:60], last=False, mo=30, new=False)
    isend(True, m[60:], last=True, mo=60, new=False)
    mark(cap, 'iWARP read chunk (NFS WRITE, 101 bytes: the XDR padding is added by the dissector): '
              'RDMA read request, READ_RESPONSE in two segments')
    x = nx()
    data = bytes((i * 3) & 0xff for i in range(101))
    isend(True, rdma_msg(x, nfs3_write_call_reduced(x, len(data)), reads=[(CALL_HDR + 32, 0x4001, len(data), 0x1000)]))
    t.s2c(fpdu(rdma_read_request(0x5001, 0x2000, len(data), 0x4001, 0x1000)))
    t.c2s(fpdu(ddp_read_response(0x5001, 0x2000, data[:60], last=False)))
    t.c2s(fpdu(ddp_read_response(0x5001, 0x2000 + 60, data[60:], last=True)))
    isend(False, rdma_msg(x, reply(x, u(0, 0, 0, 0, len(data), 2) + b'\0' * 8)))
    mark(cap, 'iWARP read chunk of 100 bytes in one READ_RESPONSE')
    x = nx()
    data = bytes((i * 3) & 0xff for i in range(100))
    isend(True, rdma_msg(x, nfs3_write_call_reduced(x, len(data)), reads=[(CALL_HDR + 32, 0x4002, len(data), 0x3000)]))
    t.s2c(fpdu(rdma_read_request(0x5002, 0x2100, len(data), 0x4002, 0x3000)))
    t.c2s(fpdu(ddp_read_response(0x5002, 0x2100, data, last=True)))
    mark(cap, 'iWARP write chunk (NFS READ of 101 bytes): RDMA writes in two segments, the reduced reply; '
              'the reproducer of the padding tvb leak (the last write is not 4-byte aligned)')
    x = nx()
    data = bytes((i * 5) & 0xff for i in range(101))
    isend(True, rdma_msg(x, nfs3_read_call(x, len(data)), writes=[[(0x6001, len(data), 0x7000)]]))
    t.s2c(fpdu(ddp_write(0x6001, 0x7000, data[:64], last=False)))
    t.s2c(fpdu(ddp_write(0x6001, 0x7000 + 64, data[64:], last=True)))
    if reduced_replies:
        isend(False, rdma_msg(x, nfs3_read_reply_reduced(x, len(data)), writes=[[(0x6001, len(data), 0x7000)]]))
    mark(cap, 'iWARP write chunk of 100 bytes in one write; the unaligned reproducer of the leak: 5 bytes')
    x = nx()
    data = bytes((i * 9) & 0xff for i in range(100))
    isend(True, rdma_msg(x, nfs3_read_call(x, len(data)), writes=[[(0x6002, len(data), 0x8000)]]))
    t.s2c(fpdu(ddp_write(0x6002, 0x8000, data, last=True)))
    if reduced_replies:
        isend(False, rdma_msg(x, nfs3_read_reply_reduced(x, len(data)), writes=[[(0x6002, len(data), 0x8000)]]))
    x = nx()
    isend(True, rdma_msg(x, call(x, NFS, 3, 6, FH + struct.pack('>Q', 0) + u(5)), writes=[[(0x6003, 5, 0x9000)]]))
    t.s2c(fpdu(ddp_write(0x6003, 0x9000, b'ABCDE', last=True)))
    mark(cap, 'iWARP reply chunk: write of the reply, RDMA_NOMSG')
    x = nx()
    rp = reply(x)
    isend(True, rdma_msg(x, call(x, NFS, 3, 0), reply_chunk=[(0x6101, len(rp), 0xa000)]))
    t.s2c(fpdu(ddp_write(0x6101, 0xa000, rp, last=True)))
    isend(False, rh(x, RDMA_NOMSG, u(0, 0, 1, 1) + seg(0x6101, len(rp), 0xa000)))
    mark(cap, 'iWARP: a read response without a read request, a write that matches no chunk, an RDMA read request '
              'twice, a SEND with garbage')
    t.c2s(fpdu(ddp_read_response(0x5999, 0x0, b'noreq', last=True)))
    t.s2c(fpdu(ddp_write(0x6999, 0x0, b'nochunk!', last=True)))
    t.s2c(fpdu(rdma_read_request(0x5003, 0x2200, 8, 0x4003, 0x3100)))
    t.c2s(fpdu(ddp_send(msn[True][0] + 1, 0, b'garbage garbage garbage garbage')))


def malformed_capture(cap):
    ib = Ib(cap)
    # truncated RPC-over-RDMA headers in a SEND, lists that run past the message
    ib.send(True, u(1, 1, 32, 0) + u(1, 0, 0x1000, 100))
    ib.send(True, u(2, 1, 32, 0) + u(0, 1, 1000) + u(0))
    ib.send(True, u(3, 1, 32, 2) + u(4))
    ib.send(True, u(4, 1, 32, 4) + u(1))
    ib.send(True, u(5, 1, 32, 0) + u(0, 0, 0))
    # reduced message whose RDMA read never comes; write chunk whose reply has no offsets
    x = 6
    ib.send(True, rdma_msg(x, nfs3_read_call(x, 64), writes=[[(0x2100, 64, 0x40000)]]))
    ib.write(False, 0x40000, 0x2100, 64, bytes(64), WRITE_ONLY)
    ib.send(False, rdma_msg(x, reply(x, u(1)), writes=[[(0x2100, 64, 0x40000)]]))
    # read request for a chunk but the read response is shorter than the chunk
    x = 7
    ib.send(True, rdma_msg(x, nfs3_write_call_reduced(x, 100), reads=[(CALL_HDR + 32, 0x1101, 100, 0x10000)]))
    ib.read(False, 0x10000, 0x1101, bytes(50), 100)
    # a SEND_MIDDLE and SEND_LAST without a SEND_FIRST
    ib.pkt(True, SEND_MIDDLE, b'12345678')
    ib.pkt(True, SEND_LAST, b'12345678')
    ib.pkt(True, SEND_LAST_INVAL, b'1234', b'\0\0\0\0')
    # write chunk that is written more than announced
    x = 8
    ib.send(True, rdma_msg(x, nfs3_read_call(x, 32), writes=[[(0x2200, 32, 0x41000)]]))
    ib.write(False, 0x41000, 0x2200, 64, bytes(64), WRITE_ONLY)
    ib.send(False, rdma_msg(x, nfs3_read_reply_reduced(x, 32), writes=[[(0x2200, 32, 0x41000)]]))
    # the reply chunk that is announced larger than what is written
    x = 9
    rp = reply(x)
    ib.send(True, rdma_msg(x, call(x, NFS, 3, 0), reply_chunk=[(0x3100, 200, 0x80000)]))
    ib.write(False, 0x80000, 0x3100, len(rp), rp, WRITE_ONLY)
    ib.send(False, rh(x, RDMA_NOMSG, u(0, 0, 1, 1) + seg(0x3100, 200, 0x80000)))


def malformed_extra(cap):
    ib = Ib(cap)
    x = 0x100
    n0 = call(x, NFS, 3, 0)
    # heuristic rejects: too short, lists that run past the end, unknown message type, XID mismatch
    ib.send(True, u(x, 1, 32, 0) + u(0))
    ib.send(True, u(x, 1, 32, 0) + u(1, 0, 0x1000))                   # read list: no room for the chunk
    ib.send(True, u(x, 1, 32, 0) + u(0, 1, 50) + u(0, 0))             # write list: segment count too large
    ib.send(True, u(x, 1, 32, 0) + u(0, 0, 1))                        # reply chunk: no room
    ib.send(True, u(x, 1, 32, 0) + u(0, 0, 1, 50) + u(0))
    ib.send(True, u(x, 1, 32, 0) + u(0, 1, 1, 7, 8) + seg(1, 2, 3)[:4])   # write chunk cut short
    ib.send(True, u(x, 1, 32, 0) + u(0, 0, 0) + u(x))                 # RPC header too short
    ib.send(True, u(x, 1, 32, 9) + u(0, 0, 0) + n0)                   # unknown message type
    ib.send(True, u(x, 1, 32, 2) + u(0, 0))                           # MSGP too short
    ib.send(True, u(x, 1, 32, 2) + u(4, 64) + u(1, 0, 0x1000) + u(0))  # MSGP: read list overruns
    ib.send(True, u(x, 1, 32, 2) + u(4, 64) + u(0, 0, 0))              # MSGP: no RPC header
    ib.pkt(True, 0x24, b'unreliable connection send')                 # UC SEND only: not handled
    ib.send(True, u(x, 1, 32, 2) + u(4, 64) + u(0, 0, 0) + call(x + 1, NFS, 3, 0))   # MSGP: other XID
    # a write chunk without segments and a reduced reply with data after the chunk (pad bytes)
    ib.send(True, rdma_msg(x + 2, call(x + 2, NFS, 3, 0), writes=[[]]))
    x = 0x110
    ib.send(True, rdma_msg(x, nfs3_read_call(x, 101), writes=[[(0x2300, 101, 0x42000)]]))
    ib.write(False, 0x42000, 0x2300, 101, bytes(101), WRITE_ONLY)
    ib.send(False, rdma_msg(x, nfs3_read_reply_reduced(x, 101) + b'\0\0\0', writes=[[(0x2300, 101, 0x42000)]]))
    # Exported PDU entry: too short, wrong version
    cap.add(exp_pdu('rpcordma', u(1, 1, 32)), lt=252)
    cap.add(exp_pdu('rpcordma', u(1, 2, 32, 0)), lt=252)
    cap.add(exp_pdu('rpcordma', u(1, 1, 32, 7)), lt=252)
    cap.add(exp_pdu('rpcordma', rdma_msg(2, n0, writes=[[(0x2400, 8, 0x43000)]])), lt=252)
    # iWARP: a Send with solicited event (not handled), a terminate, a read response of a request
    # that was never seen, a Send fragment in the middle without a beginning
    CP, SP = 40100, 20049
    t = Tcp(cap, CP, SP)
    t.handshake()
    t.c2s(b'MPA ID Req Frame' + bytes([0, 1]) + struct.pack('!H', 0))
    t.s2c(b'MPA ID Rep Frame' + bytes([0, 1]) + struct.pack('!H', 0))
    t.c2s(fpdu(bytes([0x41, 0x45]) + u(0) + struct.pack('>III', 0, 1, 0) + rdma_msg(1, n0)))
    t.c2s(fpdu(bytes([0x41, 0x46]) + u(0) + struct.pack('>III', 0, 2, 0) + rdma_msg(2, n0)))
    t.c2s(fpdu(ddp_send(3, 20, b'12345678', last=False)))
    t.c2s(fpdu(ddp_send(3, 28, b'12345678', last=True)))
    t.c2s(fpdu(ddp_send(4, 0, rdma_msg(3, nfs3_write_call_full(3, bytes(range(60)))), last=False)))
    t.c2s(fpdu(ddp_send(4, 7, b'xx', last=True)))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    cap = Cap()
    main_capture(cap)
    cap.write(os.path.join(out, 'rpcrdma-coverage.pcapng'))
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for n, text in MARKS:
            f.write('%d %s\n' % (n, text))
    print('main: %d frames' % cap.n)
    mc = Cap()
    main_capture(mc, reduced_replies=True)
    malformed_capture(mc)
    malformed_extra(mc)
    mc.write(os.path.join(out, 'rpcrdma-coverage-malformed.pcapng'))
    print('malformed: %d frames' % mc.n)


if __name__ == '__main__':
    main()
