#!/usr/bin/env python3
# Generates test/captures/rquota_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the RQUOTA (ONC RPC program) coverage captures.
# Usage: mkrquota.py <outdir>
# Writes rquota-coverage.pcapng (main, decodes cleanly) and rquota-coverage-malformed.pcapng.
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


def call(xid, prog, vers, proc, args=b'', cred=u(0, 0), verf=u(0, 0)):
    return u(xid, 0, 2, prog, vers, proc) + cred + verf + args


def reply(xid, res=b'', verf=u(0, 0), accept=0):
    return u(xid, 1, 0) + verf + u(accept) + res


def flavor(fl, body):
    return u(fl, len(body)) + body + b'\0' * (-len(body) % 4)


def rec(data, last=True):
    return u((0x80000000 if last else 0) | len(data)) + data


RQ = 100011
Q_OK, Q_NOQUOTA, Q_EPERM = 1, 2, 3
MARKS = []


def mark(cap, text):
    MARKS.append((cap.n + 1, text))


def rquota_struct(bsize=1024, active=1, bhard=1000, bsoft=800, cur=500, fhard=100, fsoft=80, curf=50, bt=0, ft=3600):
    return u(bsize, active, bhard, bsoft, cur, fhard, fsoft, curf, bt, ft)


def main_capture(cap):
    xid = [0x500]

    def nx():
        xid[0] += 1
        return xid[0]

    def exch(vers, proc, args=b'', rargs=b'', sport=900, dport=32800, cred=u(0, 0), proto='udp', t=None):
        x = nx()
        if t is None:
            cap.udp(sport, dport, call(x, RQ, vers, proc, args, cred))
            cap.udp(dport, sport, reply(x, rargs), to_server=False, dt=40000)
        else:
            t.c2s(rec(call(x, RQ, vers, proc, args, cred)))
            t.s2c(rec(reply(x, rargs)), dt=40000)
        return x

    mark(cap, 'Version 1 over UDP (port 32800, RPC heuristic): NULL, GETQUOTA and GETACTIVEQUOTA with a path and a uid; '
              'OK results with the rquota structure, active and inactive')
    exch(1, 0)
    exch(1, 1, xstr('/export/home') + u(1000), u(Q_OK) + rquota_struct())
    exch(1, 1, xstr('/export/data') + u(0), u(Q_OK) + rquota_struct(active=0, bhard=0, bsoft=0, fhard=0, fsoft=0))
    exch(1, 2, xstr('/') + u(65534), u(Q_OK) + rquota_struct(bsize=4096, bt=0xffffffff, ft=0xffffffff))
    mark(cap, 'Results without a structure: NOQUOTA, EPERM and an unknown status value')
    exch(1, 1, xstr('/export/none') + u(1001), u(Q_NOQUOTA))
    exch(1, 2, xstr('/export/priv') + u(0), u(Q_EPERM))
    exch(1, 1, xstr('/export/odd') + u(7), u(99) + rquota_struct())
    exch(1, 1, xstr('/export/zero') + u(7), u(0))
    mark(cap, 'Paths of 0 to 5 bytes (padding bytes), a path with unprintable characters, a long path')
    for p in ('', 'a', 'ab', 'abc', 'abcd', 'abcde', '/x\x01\xffy', '/export/' + 'long-directory-name/' * 12):
        exch(1, 1, xstr(p) + u(42), u(Q_NOQUOTA))
    mark(cap, 'Version 2: GETQUOTA and GETACTIVEQUOTA with a type (user, group) and an id, NULL')
    exch(2, 0)
    exch(2, 1, xstr('/export/home') + u(0, 1000), u(Q_OK) + rquota_struct())
    exch(2, 1, xstr('/export/home') + u(1, 100), u(Q_OK) + rquota_struct(bhard=2000))
    exch(2, 2, xstr('/export/home') + u(2, 7), u(Q_NOQUOTA))
    exch(2, 2, xstr('/export/home') + u(0, 1000), u(Q_EPERM))
    mark(cap, 'Procedures that are named but not implemented (SETQUOTA, SETACTIVEQUOTA), unknown procedure and '
              'versions: shown as data')
    exch(1, 3, u(1, 2, 3), u(0))
    exch(1, 4, u(1, 2, 3), u(0))
    exch(2, 3, u(1, 2, 3), u(0))
    exch(1, 17, u(1), u(0))
    exch(3, 1, u(1), u(0))
    mark(cap, 'Credentials: AUTH_UNIX with the call (quota queries come from a client machine)')
    exch(1, 1, xstr('/export/home') + u(1000), u(Q_OK) + rquota_struct(), cred=flavor(1, u(1) + xstr('client') + u(1000, 100, 1, 100)))
    mark(cap, 'RPC error replies: PROG_MISMATCH (versions 1 to 2), PROC_UNAVAIL, GARBAGE_ARGS, and a denied call')
    x = nx()
    cap.udp(900, 32800, call(x, RQ, 3, 0))
    cap.udp(32800, 900, reply(x, u(1, 2), accept=2), to_server=False, dt=40000)
    x = nx()
    cap.udp(900, 32800, call(x, RQ, 1, 9))
    cap.udp(32800, 900, reply(x, accept=3), to_server=False, dt=40000)
    x = nx()
    cap.udp(900, 32800, call(x, RQ, 1, 1, b''))
    cap.udp(32800, 900, reply(x, accept=4), to_server=False, dt=40000)
    x = nx()
    cap.udp(900, 32800, call(x, RQ, 1, 1, xstr('/a') + u(1)))
    cap.udp(32800, 900, u(x, 1, 1, 1, 5), to_server=False, dt=40000)
    mark(cap, 'Over TCP (port 32801, RPC heuristic): version 1 and 2 queries, two calls in one segment')
    t = Tcp(cap, 40500, 32801)
    t.handshake()
    exch(1, 1, xstr('/export/home') + u(1000), u(Q_OK) + rquota_struct(), t=t)
    exch(2, 1, xstr('/export/home') + u(1, 5), u(Q_OK) + rquota_struct(), t=t)
    x1, x2 = nx(), nx()
    t.c2s(rec(call(x1, RQ, 1, 1, xstr('/p1') + u(1))) + rec(call(x2, RQ, 2, 2, xstr('/p2') + u(0, 2))))
    t.s2c(rec(reply(x1, u(Q_NOQUOTA))) + rec(reply(x2, u(Q_OK) + rquota_struct())), dt=40000)
    mark(cap, 'Exported PDU: the RPC dissector carrying RQUOTA (version 1 GETQUOTA call)')
    cap.add(exp_pdu('rpc', call(0x700, RQ, 1, 1, xstr('/exp') + u(5))), lt=252)


def malformed_capture(cap):
    xid = [0x900]

    def nx():
        xid[0] += 1
        return xid[0]

    def exch_raw(vers, proc, args, rargs, dport=32800):
        x = nx()
        cap.udp(900, dport, call(x, RQ, vers, proc, args))
        cap.udp(dport, 900, reply(x, rargs), to_server=False, dt=40000)
    # path longer than the data, path length with no data, truncated uid, truncated type/id
    exch_raw(1, 1, u(100) + b'abc', u(Q_NOQUOTA))
    exch_raw(1, 1, u(4) + b'abcd', u(Q_NOQUOTA))                 # uid missing
    exch_raw(1, 1, u(3) + b'abc', u(Q_NOQUOTA))                  # padding missing
    exch_raw(1, 1, u(0xffffffff) + b'abc', u(Q_NOQUOTA))         # length over everything
    exch_raw(2, 1, xstr('/p') + u(1), u(Q_NOQUOTA))              # id missing
    exch_raw(2, 2, xstr('/p'), u(Q_NOQUOTA))                     # type and id missing
    exch_raw(1, 1, b'', u(Q_NOQUOTA))
    # reply cut short: status only for OK, structure truncated, no status
    exch_raw(1, 1, xstr('/p') + u(1), u(Q_OK))
    exch_raw(1, 1, xstr('/p') + u(1), u(Q_OK) + rquota_struct()[:20])
    exch_raw(2, 1, xstr('/p') + u(0, 1), b'')
    exch_raw(1, 2, xstr('/p') + u(1), u(Q_OK) + rquota_struct()[:39])
    # truncated captures (snaplen) in the middle of a path and of the structure
    x = nx()
    cap.udp(900, 32800, call(x, RQ, 1, 1, xstr('/export/home') + u(7)), keep=48)
    cap.udp(32800, 900, reply(x, u(Q_OK) + rquota_struct()), to_server=False, keep=40)
    # a call with trailing bytes after the arguments
    exch_raw(1, 1, xstr('/p') + u(1) + b'trailing data', u(Q_NOQUOTA) + b'trailing')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    cap = Cap()
    main_capture(cap)
    cap.write(os.path.join(out, 'rquota-coverage.pcapng'))
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for n, text in MARKS:
            f.write('%d %s\n' % (n, text))
    print('main: %d frames' % cap.n)
    mc = Cap()
    malformed_capture(mc)
    mc.write(os.path.join(out, 'rquota-coverage-malformed.pcapng'))
    print('malformed: %d frames' % mc.n)


if __name__ == '__main__':
    main()
