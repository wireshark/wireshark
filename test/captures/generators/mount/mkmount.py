#!/usr/bin/env python3
# Generates test/captures/mount_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds the MOUNT / SGI MOUNT coverage captures. Usage: mkmount.py <outdir> [-v]
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(a):
    return bytes(int(x) for x in a.split('.'))

ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01'

def ethip(proto, payload, src, dst, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH + b'\x08\x00' + ip + payload

def udp(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ethip(17, u, src, dst)

def tcp(payload, sport, dport, seq, ack, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 0x50, flags, 65535, 0, 0) + payload
    pseudo = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 6, len(t))
    c = csum(pseudo + t)
    t = t[:16] + struct.pack('>H', c) + t[18:]
    return ethip(6, t, src, dst)

def exp_pdu(name, payload, extra=b''):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + extra + struct.pack('>HH', 0, 0) + payload

def rtp(pt, seq, ts, payload, ssrc=0x11223344, marker=0):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq & 0xffff, ts & 0xffffffff, ssrc) + payload

class Cap:
    """pcapng writer with interface 0 = Ethernet, 1 = Exported PDU (252)."""
    def __init__(self):
        self.frames = []
    def eth(self, data, note=None):
        self.frames.append((1, data)); return len(self.frames)
    def epdu(self, name, payload, extra=b''):
        self.frames.append((252, exp_pdu(name, payload, extra))); return len(self.frames)
    def write(self, fname):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 1, 0, 0))
        out += blk(1, struct.pack('<HHI', 252, 0, 0))
        for i, (lt, d) in enumerate(self.frames):
            out += blk(6, struct.pack('<IIIII', 0 if lt == 1 else 1, 0, 1000 + i, len(d), len(d)) + d)
        open(fname, 'wb').write(out)

def pcap(fname, linktype, pkts):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)) + p)

PROG, SGIPROG = 100005, 391004

def xs(s):
    """XDR string"""
    b = s if isinstance(s, bytes) else s.encode()
    return struct.pack('>I', len(b)) + b + b'\0' * ((4 - len(b) % 4) % 4)

def rpc_call(xid, prog, vers, proc, args=b''):
    return struct.pack('>IIIIII', xid, 0, 2, prog, vers, proc) + struct.pack('>IIII', 0, 0, 0, 0) + args

def rpc_reply(xid, results=b''):
    return struct.pack('>IIIIII', xid, 1, 0, 0, 0, 0) + results

def xlist(entries):
    out = b''
    for e in entries:
        out += struct.pack('>I', 1) + e
    return out + struct.pack('>I', 0)

def fh(n, size=32):
    return bytes((n + i) & 0xff for i in range(size))

def pathconf(link=32000, canon=255, inp=256, name=255, path=1024, pipe=4096, vdis=0x7f, mask=0):
    b = struct.pack('>I', link)
    for v in (canon, inp, name, path, pipe):
        b += struct.pack('>I', v)
    b += struct.pack('>I', 0)
    b += struct.pack('>I', vdis)
    b += struct.pack('>II', mask, 0)
    return b

def statvfs(flag, n=1):
    b = b''.join(struct.pack('>I', v) for v in (4096, 512, 1000000, 500000, 400000, 65536, 30000, 20000))
    b += b'xfs'.ljust(16, b'\0')
    b += b'fstr-' + b'\x01' * 27      # 32 opaque bytes
    b += struct.pack('>III', 0x1234, flag, 255)
    return b

def main(out, verbose):
    cap = Cap()
    marks = []
    xid = [0x1000]
    cs, ss = '192.0.2.1', '192.0.2.2'
    cport = 40000

    def exchange(prog, vers, proc, args, results, tr='udp', port=None, sport=None):
        xid[0] += 1
        sport = sport or cport + (xid[0] & 0xff)
        port = port or 20048
        c = rpc_call(xid[0], prog, vers, proc, args)
        r = rpc_reply(xid[0], results)
        if tr == 'udp':
            cap.eth(udp(c, sport, port, cs, ss)); cap.eth(udp(r, port, sport, ss, cs))
        else:
            # record marking, one fragment each; handshake not needed for dissection
            tseq[0] = tseq.get('c', 1000);
            cap.eth(tcp(struct.pack('>I', 0x80000000 | len(c)) + c, sport, port, ctr['c'], ctr['s'], src=cs, dst=ss))
            ctr['c'] += 4 + len(c)
            cap.eth(tcp(struct.pack('>I', 0x80000000 | len(r)) + r, port, sport, ctr['s'], ctr['c'], src=ss, dst=cs))
            ctr['s'] += 4 + len(r)
        return len(cap.frames)
    tseq = {}
    ctr = {'c': 5000, 's': 9000}

    # version 1
    start = len(cap.frames) + 1
    exchange(PROG, 1, 0, b'', b'')
    exchange(PROG, 1, 1, xs('/export/home'), struct.pack('>I', 0) + fh(1))
    exchange(PROG, 1, 1, xs('/nonexistent'), struct.pack('>I', 2))
    exchange(PROG, 1, 1, xs('/denied'), struct.pack('>I', 13))
    exchange(PROG, 1, 1, xs('/weird'), struct.pack('>I', 77))
    exchange(PROG, 1, 2, b'', xlist([xs('client1.example') + xs('/export/home'),
                                     xs('client2.example') + xs('/export/data')]))
    exchange(PROG, 1, 2, b'', struct.pack('>I', 0))
    exchange(PROG, 1, 3, xs('/export/home'), b'')
    exchange(PROG, 1, 4, b'', b'')
    exg = lambda d, groups: xs(d) + xlist([xs(g) for g in groups])
    exchange(PROG, 1, 5, b'', xlist([exg('/export/home', ['alice', 'bob', 'staff']),
                                    exg('/export/pub', []), exg('/export/tmp', ['everyone'])]))
    exchange(PROG, 1, 6, b'', xlist([exg('/', ['@net'])]))
    exchange(PROG, 1, 5, b'', struct.pack('>I', 0))
    v1 = (start, len(cap.frames))
    # version 2: same plus PATHCONF
    start = len(cap.frames) + 1
    exchange(PROG, 2, 0, b'', b'')
    exchange(PROG, 2, 1, xs('/export/home'), struct.pack('>I', 0) + fh(9))
    exchange(PROG, 2, 2, b'', xlist([xs('host.example') + xs('/export')]))
    exchange(PROG, 2, 3, xs('/export'), b'')
    exchange(PROG, 2, 4, b'', b'')
    exchange(PROG, 2, 5, b'', xlist([exg('/export', ['g1', 'g2'])]))
    exchange(PROG, 2, 6, b'', xlist([exg('/export', [])]))
    # PATHCONF: all valid; each error bit alone; all errors; chown_restricted, no_trunc
    masks = [0, 0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200,
             0x03ff, 0x0180]
    for m in masks:
        exchange(PROG, 2, 7, xs('/export'), pathconf(mask=m))
    exchange(PROG, 2, 7, xs('/export'), pathconf(link=1, canon=0xffff, inp=0x8000, name=0x0102, path=0x7fff, pipe=0x0100, vdis=0xff))
    v2 = (start, len(cap.frames))
    # version 3
    start = len(cap.frames) + 1
    exchange(PROG, 3, 0, b'', b'')
    exchange(PROG, 3, 1, xs('/export/home'), struct.pack('>I', 0) + struct.pack('>I', 32) + fh(3) +
             struct.pack('>I', 3) + b''.join(struct.pack('>I', f) for f in (1, 390003, 6)))
    exchange(PROG, 3, 1, xs('/export/small'), struct.pack('>I', 0) + struct.pack('>I', 8) + fh(4, 8) +
             struct.pack('>I', 0))
    exchange(PROG, 3, 1, xs('/export/krb'), struct.pack('>I', 0) + struct.pack('>I', 64) + fh(5, 64) +
             struct.pack('>I', 4) + b''.join(struct.pack('>I', f) for f in (390003, 390004, 390005, 0)))
    for st in (1, 2, 5, 13, 20, 22, 63, 10004, 10006, 12345):
        exchange(PROG, 3, 1, xs('/export/err%d' % st), struct.pack('>I', st))
    exchange(PROG, 3, 2, b'', xlist([xs('client.example') + xs('/export/home')]))
    exchange(PROG, 3, 2, b'', struct.pack('>I', 0))
    exchange(PROG, 3, 3, xs('/export/home'), b'')
    exchange(PROG, 3, 4, b'', b'')
    exchange(PROG, 3, 5, b'', xlist([exg('/export/home', ['a', 'b']), exg('/export/x', [])]))
    exchange(PROG, 3, 5, b'', struct.pack('>I', 0))
    v3 = (start, len(cap.frames))
    # SGI mount v1
    start = len(cap.frames) + 1
    exchange(SGIPROG, 1, 0, b'', b'')
    exchange(SGIPROG, 1, 1, xs('/sgi'), struct.pack('>I', 0) + fh(7))
    exchange(SGIPROG, 1, 2, b'', xlist([xs('irix.example') + xs('/sgi')]))
    exchange(SGIPROG, 1, 3, xs('/sgi'), b'')
    exchange(SGIPROG, 1, 4, b'', b'')
    exchange(SGIPROG, 1, 5, b'', xlist([exg('/sgi', ['x'])]))
    exchange(SGIPROG, 1, 6, b'', xlist([exg('/sgi', [])]))
    exchange(SGIPROG, 1, 99, b'', xlist([xs('/sgi') + struct.pack('>I', 1) + xs('rw,nosuid'),
                                       xs('/sgi/pub') + struct.pack('>I', 0) + xs('')]))
    exchange(SGIPROG, 1, 99, b'', struct.pack('>I', 0))
    for fl in (0, 0x1, 0x2, 0x4, 0x20000000, 0x40000000, 0x80000000, 0xe0000007):
        exchange(SGIPROG, 1, 100, xs('/sgi'), statvfs(fl))
    sgi = (start, len(cap.frames))
    # TCP transport: record marking (the RPC TCP heuristic finds MOUNT by program number)
    start = len(cap.frames) + 1
    exchange(PROG, 3, 0, b'', b'', tr='tcp', port=20048, sport=900)
    exchange(PROG, 3, 1, xs('/export/home'), struct.pack('>I', 0) + struct.pack('>I', 32) + fh(3) +
             struct.pack('>I', 1) + struct.pack('>I', 1), tr='tcp', port=20048, sport=900)
    exchange(PROG, 3, 5, b'', xlist([exg('/export/home', ['a'])]), tr='tcp', port=20048, sport=900)
    exchange(PROG, 1, 2, b'', xlist([xs('h') + xs('/d')]), tr='tcp', port=20048, sport=900)
    tcpr = (start, len(cap.frames))
    # reproducer of the PATHCONF encoding fix: values that look like encodings
    start = len(cap.frames) + 1
    xid[0] += 1
    body = struct.pack('>I', 32000)
    body += struct.pack('>HH', 0x0004, 0x00ff) + struct.pack('>HH', 0x0001, 0x0100)
    body += struct.pack('>HH', 0x0000, 0x00ff) + struct.pack('>HH', 0x0000, 0x0400)
    body += struct.pack('>HH', 0x0000, 0x1000) + struct.pack('>I', 0)
    body += struct.pack('>HBB', 0x0001, 0, 0x7f) + struct.pack('>HH', 0, 0) + struct.pack('>I', 0)
    exchange(PROG, 2, 7, xs('/export'), body)
    repro = (start, len(cap.frames))
    cap.write(os.path.join(out, 'mount-coverage.pcapng'))

    # malformed: truncated bodies
    m = Cap()
    xid[0] = 0x2000
    cap2 = m
    def mx(prog, vers, proc, args, results):
        xid[0] += 1
        m.eth(udp(rpc_call(xid[0], prog, vers, proc, args), 40001, 20048, cs, ss))
        m.eth(udp(rpc_reply(xid[0], results), 20048, 40001, ss, cs))
    mx(PROG, 1, 1, xs('/export'), struct.pack('>I', 0) + fh(1, 10))       # short fhandle
    mx(PROG, 1, 1, b'\0\0', b'\0')                                       # short path call, reply
    mx(PROG, 2, 7, xs('/export'), pathconf()[:20])                       # short PATHCONF
    mx(PROG, 2, 7, xs('/export'), pathconf()[:35])
    mx(PROG, 3, 1, xs('/e'), struct.pack('>I', 0) + struct.pack('>I', 8) + fh(1, 8) + struct.pack('>I', 5))
    mx(PROG, 3, 1, xs('/e'), struct.pack('>I', 0) + struct.pack('>I', 8) + fh(1, 8) + struct.pack('>I', 0xffffff))
    mx(PROG, 3, 1, xs('/e'), struct.pack('>I', 0) + struct.pack('>I', 200) + fh(1, 20))
    mx(PROG, 1, 2, b'', struct.pack('>I', 1) + xs('host'))
    mx(PROG, 1, 5, b'', struct.pack('>I', 1) + xs('/d') + struct.pack('>I', 1) + xs('grp')[:6])
    mx(SGIPROG, 1, 99, b'', struct.pack('>I', 1) + xs('/d') + struct.pack('>I', 1))
    mx(SGIPROG, 1, 100, xs('/sgi'), statvfs(1)[:50])
    mx(SGIPROG, 1, 100, xs('/sgi'), b'')
    mx(PROG, 3, 1, struct.pack('>I', 0xffffff00) + b'abc', b'')           # huge string length in the call
    m.write(os.path.join(out, 'mount-coverage-malformed.pcapng'))
    if verbose:
        print('MOUNT v1 frames %d-%d, v2 %d-%d, v3 %d-%d, SGI %d-%d, TCP %d-%d, PATHCONF repro %d-%d; total %d'
              % (v1 + v2 + v3 + sgi + tcpr + repro + (len(cap.frames),)))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
