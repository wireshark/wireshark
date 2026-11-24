#!/usr/bin/env python3
# Generates test/captures/rstat_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the RSTAT (ONC RPC program) coverage captures.
# Usage: mkrstat.py <outdir>
# Writes rstat-coverage.pcapng (main, decodes cleanly) and rstat-coverage-malformed.pcapng.
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


RS = 100001
MARKS = []


def mark(cap, text):
    MARKS.append((cap.n + 1, text))


def stats_body(vers):
    """A made-up statistics structure (the dissector shows the body as unknown data)."""
    return b''.join(u(i * 17 + vers) for i in range(16))


def main_capture(cap):
    xid = [0x600]

    def nx():
        xid[0] += 1
        return xid[0]

    def exch(vers, proc, args=b'', rargs=b'', sport=901, dport=32900, t=None):
        x = nx()
        if t is None:
            cap.udp(sport, dport, call(x, RS, vers, proc, args))
            cap.udp(dport, sport, reply(x, rargs), to_server=False, dt=30000)
        else:
            t.c2s(rec(call(x, RS, vers, proc, args)))
            t.s2c(rec(reply(x, rargs)), dt=30000)
        return x

    for v in (1, 2, 3, 4):
        mark(cap, 'Version %d over UDP (port 32900, RPC heuristic): NULL, STATS (body shown as unknown data), '
                  'HAVEDISK' % v)
        exch(v, 0)
        exch(v, 1, b'', stats_body(v))
        exch(v, 2, b'', u(1))
    mark(cap, 'Unknown procedure of RSTAT, unknown versions: shown as data; denied and error replies')
    exch(1, 9, u(1, 2), u(3))
    exch(5, 0)
    exch(0, 1, b'', b'')
    x = nx()
    cap.udp(901, 32900, call(x, RS, 5, 0))
    cap.udp(32900, 901, reply(x, u(1, 4), accept=2), to_server=False, dt=30000)
    x = nx()
    cap.udp(901, 32900, call(x, RS, 3, 1))
    cap.udp(32900, 901, reply(x, accept=1), to_server=False, dt=30000)
    mark(cap, 'Over TCP (port 32901, RPC heuristic): STATS for version 3 and 4, two calls in one segment')
    t = Tcp(cap, 40600, 32901)
    t.handshake()
    exch(3, 1, b'', stats_body(3), t=t)
    exch(4, 2, b'', u(0), t=t)
    x1, x2 = nx(), nx()
    t.c2s(rec(call(x1, RS, 2, 0)) + rec(call(x2, RS, 1, 1)))
    t.s2c(rec(reply(x1)) + rec(reply(x2, stats_body(1))), dt=30000)
    mark(cap, 'Exported PDU: the RPC dissector carrying RSTAT, and the RSTAT calls with credentials')
    cap.add(exp_pdu('rpc', call(0x800, RS, 3, 0)), lt=252)
    exch(2, 1, b'', stats_body(2), dport=32900, sport=904)
    # AUTH_UNIX credentials with the STATS call
    x = nx()
    cred = flavor(1, u(1) + xstr('client') + u(0, 0, 0))
    cap.udp(903, 32900, call(x, RS, 3, 1, cred=cred))
    cap.udp(32900, 903, reply(x, stats_body(3)), to_server=False, dt=30000)


def malformed_capture(cap):
    xid = [0xa00]

    def nx():
        xid[0] += 1
        return xid[0]
    # STATS reply cut short by the snap length; a call cut after the credentials
    x = nx()
    cap.udp(901, 32900, call(x, RS, 3, 1))
    cap.udp(32900, 901, reply(x, stats_body(3)), to_server=False, keep=20)
    x = nx()
    cap.udp(901, 32900, call(x, RS, 3, 1, u(1, 2, 3, 4)), keep=40)
    cap.udp(32900, 901, reply(x, stats_body(3)), to_server=False)
    # an empty STATS body and a body that is not a multiple of four bytes
    x = nx()
    cap.udp(901, 32900, call(x, RS, 4, 1))
    cap.udp(32900, 901, reply(x, b''), to_server=False)
    x = nx()
    cap.udp(901, 32900, call(x, RS, 4, 1, b'abc'))
    cap.udp(32900, 901, reply(x, b'12345'), to_server=False)
    # reply without a call: not RPC for the heuristics
    cap.udp(32900, 901, reply(0xdead, stats_body(3)), to_server=False)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    cap = Cap()
    main_capture(cap)
    cap.write(os.path.join(out, 'rstat-coverage.pcapng'))
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for n, text in MARKS:
            f.write('%d %s\n' % (n, text))
    print('main: %d frames' % cap.n)
    mc = Cap()
    malformed_capture(mc)
    mc.write(os.path.join(out, 'rstat-coverage-malformed.pcapng'))
    print('malformed: %d frames' % mc.n)


if __name__ == '__main__':
    main()
