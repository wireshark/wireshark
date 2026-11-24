#!/usr/bin/env python3
# Generates test/captures/fmp_notify_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the FMP/NOTIFY coverage captures (synthetic data only).

usage: mkfmp_notify.py <outdir> [-v]

fmp_notify-coverage.pcap     valid FMP/NOTIFY (ONC-RPC program 1001912, version 2)
                             over UDP; found by the RPC UDP heuristic
fmp_notify-coverage-malformed.pcap  truncated / out of range data
"""
import os
import struct
import sys

CLI = [192, 0, 2, 1]
SRV = [192, 0, 2, 2]
PROG = 1001912
VERS = 2


# ---------------------------------------------------------------- helpers
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_frame(src, dst, sport, dport, payload):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00'
    return eth + ip + udp


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000, i * 1000, len(fr), len(fr)))
            f.write(fr)


def rpc_call(xid, prog, vers, proc, body):
    return struct.pack('!IIIIIIIIII', xid, 0, 2, prog, vers, proc,
                       0, 0, 0, 0) + body


def rpc_reply(xid, body):
    return struct.pack('!IIIIII', xid, 1, 0, 0, 0, 0) + body


def u32(*v):
    return struct.pack('!%dI' % len(v), *v)


def u64(v):
    return struct.pack('!Q', v)


def opq(b):
    if isinstance(b, str):
        b = b.encode()
    return u32(len(b)) + b + b'\0' * ((-len(b)) % 4)


class Cap:
    def __init__(self, prog=PROG, vers=VERS):
        self.f = []
        self.xid = 0x1000
        self.prog = prog
        self.vers = vers

    def cr(self, proc, req, rep, sport=800, dport=4656):
        """One call and its reply; returns the first frame number."""
        self.xid += 1
        first = len(self.f) + 1
        self.f.append(udp_frame(CLI, SRV, sport, dport,
                                rpc_call(self.xid, self.prog, self.vers, proc, req)))
        if rep is not None:
            self.f.append(udp_frame(SRV, CLI, dport, sport,
                                    rpc_reply(self.xid, rep)))
        return first


# ------------------------------------------------- FMP/NOTIFY structures
SESS = opq(b'SESSION-HANDLE-0001')
FH = opq(b'FMPFILEHANDLE-01')

STATUSES = [0, 5, 12, 13, 22, 28, 79, 500, 501, 502, 503, 504, 505, 506, 507,
            508, 509, 510, 511, 512, 600, 7777]


def extent(first, nblk, vol, off, state):
    return u32(first, nblk, vol, off, state)


def extlist(*e):
    return u32(len(e)) + b''.join(e)


def build(c):
    marks = []

    def mark(name, n):
        marks.append((name, n))

    mark('NULL', c.cr(0, b'', b''))
    # DownGrade: request and a reply for every status
    mark('DownGrade', c.cr(1, SESS + FH + u32(7, 0, 64), u32(0)))
    mark('RevokeList', c.cr(2, SESS + FH + u32(8, 16, 32), u32(0)))
    mark('RevokeAll', c.cr(3, SESS + FH + u32(9), u32(0)))
    mark('FileSetEof', c.cr(4, SESS + FH + u32(10) + u64(1 << 34), u32(0)))
    # RequestDone: the status is in the request; an error has no body
    ext3 = extlist(extent(0, 16, 1, 0, 0), extent(16, 16, 2, 4096, 1),
                   extent(32, 8, 3, 8192, 2))
    mark('RequestDone', c.cr(5, u32(0) + SESS + FH + u32(11, 0x5a) + ext3, u32(0)))
    c.cr(5, u32(0) + SESS + FH + u32(12, 0x5b) + extlist(), u32(0))
    c.cr(5, u32(28) + SESS + FH + u32(13, 0x5c) + ext3, u32(0))
    c.cr(5, u32(508), u32(0))
    c.cr(5, u32(5), u32(0))
    mark('volFreeze', c.cr(6, SESS + u32(0x77), u32(0)))
    # revokeHandleList: every reason, an unknown one, 0, 1 and 3 handles
    mark('revokeHandleList', len(c.f) + 1)
    c.cr(7, SESS + u32(0) + u32(3) + FH + opq(b'FMPFILEHANDLE-02') + opq(b'H3'), u32(0))
    c.cr(7, SESS + u32(1) + u32(1) + FH, u32(0))
    c.cr(7, SESS + u32(2) + u32(0), u32(0))
    c.cr(7, SESS + u32(3) + u32(2) + FH + FH, u32(0))
    # a reply for every status (rval 0 and 1 paths of the status switch)
    mark('statuses', len(c.f) + 1)
    bodies = [SESS + FH + u32(7, 0, 64), SESS + FH + u32(8, 16, 32),
              SESS + FH + u32(9), SESS + FH + u32(10) + u64(5),
              u32(0) + SESS + FH + u32(11, 1) + extlist(),
              SESS + u32(1), SESS + u32(0) + u32(0)]
    for i, st in enumerate(STATUSES):
        c.cr(1 + i % 7, bodies[i % 7], u32(st))
    # a second client port
    c.cr(6, SESS + u32(0x78), u32(0), sport=801)
    return marks


def build_malformed(c):
    c.cr(1, SESS[:10], None)
    c.cr(1, SESS + FH + u32(7, 0), None)
    c.cr(1, SESS + FH + u32(7, 0, 64), b'')                 # empty reply
    c.cr(4, SESS + FH + u32(10) + b'\0' * 4, None)
    c.cr(5, u32(0) + SESS + FH + u32(11, 0x5a) + u32(1000), None)   # extents past end
    c.cr(5, u32(0) + SESS + FH + u32(11, 0x5a) + u32(1) + b'\0' * 8, None)
    c.cr(5, u32(0), None)
    c.cr(5, b'', None)
    c.cr(6, SESS, None)
    c.cr(7, SESS + u32(0) + u32(0xffffff) + FH, None)       # handle count too big
    c.cr(7, SESS + u32(0) + u32(2) + FH + opq(b'abcdef')[:6], None)
    c.cr(7, SESS + u32(0), None)


def main(out):
    verbose = '-v' in sys.argv
    c = Cap()
    marks = build(c)
    write_pcap(os.path.join(out, 'fmp_notify-coverage.pcap'), c.f)
    if verbose:
        for n, f in marks:
            print('%5d  %s' % (f, n))
    print('fmp_notify-coverage.pcap', len(c.f), 'frames')
    m = Cap()
    build_malformed(m)
    write_pcap(os.path.join(out, 'fmp_notify-coverage-malformed.pcap'), m.f)
    print('fmp_notify-coverage-malformed.pcap', len(m.f), 'frames')


if __name__ == '__main__':
    main(sys.argv[1])
