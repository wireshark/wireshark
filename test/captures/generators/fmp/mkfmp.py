#!/usr/bin/env python3
# Generates test/captures/fmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the FMP coverage captures (synthetic data only).

usage: mkfmp.py <outdir> [-v]

fmp-coverage.pcap            valid FMP (ONC-RPC program 1001911, version 3)
                             over UDP; found by the RPC UDP heuristic
fmp-coverage-malformed.pcap  truncated / out of range data
"""
import os
import struct
import sys

CLI = [192, 0, 2, 1]
SRV = [192, 0, 2, 2]
PROG = 1001911
VERS = 3


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


# --------------------------------------------------------- FMP structures
SESS = opq(b'SESSION-HANDLE-0001')
FH = opq(b'FMPFILEHANDLE-01')

# Native protocols
PATH, NFS, CIFS, FMP, FS_ONLY, SHARE, MOUNT, CIFSV2, UNC = range(9)
ASCII, UTF8, UNICODE = 0, 1, 2


def fhsrc(kind):
    """Source file handle."""
    if kind == PATH:
        r = u32(PATH) + opq('/export/fs1/file.dat')
    elif kind == NFS:
        r = u32(NFS) + opq(b'\x01\x02\x03\x04\x05\x06\x07\x08' * 4)
    elif kind == CIFS:
        r = u32(CIFS) + struct.pack('!HHH', 0x1234, 0x0042, 0x0007)
    elif kind == FMP:
        r = u32(FMP) + opq(b'FMPFHANDLE')
    elif kind == FS_ONLY:
        r = u32(FS_ONLY, 77)
    elif kind == SHARE:
        r = u32(SHARE, ASCII) + opq('share1')
    elif kind == MOUNT:
        r = u32(MOUNT, UTF8) + opq('/mnt/vol')
    elif kind == CIFSV2:
        r = u32(CIFSV2) + struct.pack('!HHHH', 0x1234, 0x0042, 0x0007, 445)
    elif kind == UNC:
        r = u32(UNC, UNICODE) + opq('//srv/share')
    elif kind == 'badenc':
        r = u32(SHARE, 9)             # unknown encoding mode: no string
    elif kind == 'badnp':
        r = u32(99)                   # unknown native protocol
    else:
        raise ValueError(kind)
    return r


def extent(first, nblk, vol, off, state):
    return u32(first, nblk, vol, off, state)


def extlist(*e):
    return u32(len(e)) + b''.join(e)


def extentEx(first, nblk, vol, off, state):
    return u64(first) + u32(nblk, vol) + u64(off) + u32(state)


def extlistEx(*e):
    return u32(len(e)) + b''.join(e)


def attrs():
    return (u32(1, 0o644, 1, 1000, 1000) + u64(4096) + u64(8192) + u64(0) +
            u64(0x55) + u64(0x1234567) + u32(1700000000, 1) + u32(1700000001, 2) +
            u32(1700000002, 3))


def devserial(q, off, sig):
    return u32(q, off) + opq(sig)


def voldesc_disk_sig(volid, sigoff, sigs):
    r = u32(0, volid) + u64(0x100) + u32(0) + u64(sigoff) + u32(len(sigs))
    for o, s in sigs:
        r += u32(o) + opq(s)
    return r


def voldesc_disk_serial(volid):
    return u32(0, volid) + u64(0x200) + u32(1) + devserial(1, 0, b'ABCD')


def voldesc_slice(volid):
    return u32(1, volid) + u64(0x1000) + u64(0x100000) + u32(5)


def voldesc_stripe(volid, vols):
    return u32(2, volid) + u64(65536) + u32(len(vols)) + u32(*vols)


def voldesc_meta(volid, vols):
    return u32(3, volid) + u32(len(vols)) + u32(*vols)


def hiervol(top, cursor, cookie, descs):
    return u32(top, cursor, cookie, len(descs)) + b''.join(descs)


STATUSES = [0, 5, 12, 13, 22, 28, 79, 500, 501, 502, 503, 504, 505, 506, 507,
            508, 509, 510, 511, 512, 600, 7777]


def build(c):
    marks = []

    def mark(name, n):
        marks.append((name, n))

    # ---- NULL, SessionCreate, HeartBeat
    mark('NULL', c.cr(0, b'', b''))
    mark('SessionCreate', c.cr(1, opq('client1.example') + u32(1700000000, 500) + u32(7000),
         u32(0) + SESS + opq('server1.example') + u32(1700000000, 600) + u64(30)))
    c.cr(1, opq('client2.example') + u32(1700000010, 0) + u32(7001), u32(22))
    mark('HeartBeat', c.cr(2, SESS, u32(0)))
    # ---- Mount: every source file handle, every volume management type
    mark('Mount', len(c.f) + 1)
    for k in (PATH, NFS, CIFS, FMP, FS_ONLY, SHARE, MOUNT, CIFSV2, UNC):
        c.cr(3, SESS + u32(0x01) + fhsrc(k), u32(13) if k == PATH else None)
    c.cr(3, SESS + u32(0x02) + fhsrc('badenc'), u32(13))
    c.cr(3, SESS + u32(0x04) + fhsrc('badnp'), u32(13))
    fsid = u32(0, 0x77, 8192)
    mark('Mount replies', len(c.f) + 1)
    c.cr(3, SESS + u32(0x01) + fhsrc(PATH),
         fsid + u32(1, 2) + devserial(0, 0x10, b'SER1') + u32(0) +
         devserial(1, 0x20, b'SER2') + u32(1))
    c.cr(3, SESS + u32(0x01) + fhsrc(NFS), u32(0, 0x77, 8192) + u32(1, 0))
    c.cr(3, SESS + u32(0x02) + fhsrc(NFS), fsid + u32(2) + opq(b'volhandle3rd'))
    c.cr(3, SESS + u32(0x04) + fhsrc(NFS), fsid + u32(4) + opq(b'voldart'))
    c.cr(3, SESS + u32(0x08) + fhsrc(NFS),
         fsid + u32(8) + devserial(1, 0, b'SIMPLE') + u32(3))
    c.cr(3, SESS + u32(0x10) + fhsrc(NFS),
         fsid + u32(0x10, 2) + u64(0x1000) + u32(2) + u32(0x10) + opq(b'sig1') +
         u32(0x20) + opq(b'sig2') + u32(11) +
         u64(0x2000) + u32(0) + u32(12))
    c.cr(3, SESS + u32(0x20) + fhsrc(NFS), fsid + u32(0x20))
    c.cr(3, SESS + u32(0x40) + fhsrc(NFS),
         fsid + u32(0x40) + hiervol(0x99, 6, 0xc00c1e, [
             voldesc_disk_sig(1, 0x400, [(0, b'a'), (4, b'bcd')]),
             voldesc_disk_serial(2),
             voldesc_slice(3), voldesc_stripe(4, [1, 2, 3]),
             voldesc_meta(5, [3, 4]), u32(9)]))
    c.cr(3, SESS + u32(0x7f) + fhsrc(NFS), fsid + u32(0x80))
    # ---- Open
    mark('Open', len(c.f) + 1)
    for k in (PATH, NFS, CIFS, FMP, FS_ONLY, SHARE, MOUNT, CIFSV2, UNC, 'badenc', 'badnp'):
        c.cr(4, SESS + fhsrc(k), u32(0) + FH + u32(1) + u64(1 << 33) + u32(0x77)
             if k in (PATH, FMP) else u32(512))
    # reproducers of the fixes
    mark('fix: Open FMP_FMP handle', c.cr(4, SESS + u32(3) + opq(b'FHND'), u32(22)))
    mark('fix: Open FMP_PATH, SHARE', c.cr(4, SESS + u32(0) + opq(b'/abc'), u32(22)))
    c.cr(4, SESS + u32(5, 0) + opq(b'share'), u32(22))
    # ---- Close
    mark('Close', c.cr(5, FH + u32(2), u32(0) + u32(3)))
    c.cr(5, FH + u32(2), u32(501))
    # ---- OpenGetMap, OpenAllocSpace, GetMap, AllocSpace
    ext3 = extlist(extent(0, 16, 1, 0, 0), extent(16, 16, 2, 4096, 1),
                   extent(32, 8, 3, 8192, 2))
    mark('OpenGetMap', c.cr(6, SESS + fhsrc(NFS) + u32(0, 64, 8),
         u32(0) + FH + u32(1, 0x55) + u64(100000) + u32(0x77) + ext3))
    c.cr(6, SESS + fhsrc(CIFS) + u32(0, 64, 8), u32(510))
    mark('OpenAllocSpace', c.cr(7, SESS + fhsrc(FS_ONLY) + u32(0, 64, 8),
         u32(0) + FH + u32(1, 0x56) + u64(100000) + u32(0x77) + extlist()))
    c.cr(7, SESS + fhsrc(FMP) + u32(8, 64, 8), u32(12))
    mark('GetMap', c.cr(8, FH + u32(3, 0, 16, 4),
         u32(0) + u32(3, 0x57) + u64(100000) + ext3))
    c.cr(8, FH + u32(3, 0, 16, 4), u32(500))
    mark('AllocSpace', c.cr(9, FH + u32(4, 0, 16, 4),
         u32(0) + u32(4, 0x58) + u64(100000) + ext3))
    c.cr(9, FH + u32(4, 0, 16, 4), u32(79))
    # ---- Flush: every flush command bit, none and an unknown bit
    mark('Flush', len(c.f) + 1)
    for cmd in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x00, 0x03, 0x3f, 0x40):
        c.cr(10, FH + u32(5) + u32(cmd) + u64(5000) + ext3,
             u32(0, 5) if cmd == 0x3f else u32(5))
    # ---- CancelReq, PlugIn
    mark('CancelReq', c.cr(11, FH + u32(6, 0x55), u32(0, 6)))
    c.cr(11, FH + u32(6, 0x55), u32(508))
    # dissect_plugInID() does not advance the offset, so the 16 octet plug
    # in ID is parsed again as the length of the arguments: the ID here
    # starts with a length of 12 so that the frame decodes cleanly.
    mark('PlugIn', c.cr(12, opq(b'PLUGIN-ID-12') + opq(b'plugin args'),
         u32(0) + opq(b'plugin result')))
    c.cr(12, opq(b'PLUGIN-ID-12') + opq(b''), u32(600))
    mark('SessionTerminate', c.cr(13, SESS, u32(0)))
    # ---- SessionCreateEx
    caps = [0, 1, 2, 4, 7]
    mark('SessionCreateEx', len(c.f) + 1)
    for i, cap in enumerate(caps):
        c.cr(14, opq('client3.example') + u32(1700000020, 1) + u32(7002, i % 2) +
             u32(10, 4) + opq('Linux') + u32(3, 2600) + u32(cap),
             u32(0) + SESS + opq('server1.example') + u32(1700000020, 2) + u64(60) +
             u32(5, 6) + opq('6.1.2 build 12') + u32(1, 77) + u32(cap)
             if i != 3 else u32(512))
    # ---- ReportClientError
    mark('ReportClientError', c.cr(15, opq('disk failed') + u32(2, 5), u32(0)))
    c.cr(15, opq('generic problem') + u32(1, 22), u32(22))
    c.cr(15, opq('other') + u32(3, 12345), u32(12))
    # ---- GetAttr, OpenGetAttr, FlushGetAttr
    mark('GetAttr', c.cr(16, FH + u32(7), u32(0) + u32(7) + attrs()))
    c.cr(16, FH + u32(7), u32(13))
    mark('OpenGetAttr', c.cr(17, SESS + fhsrc(NFS),
         u32(0) + FH + u32(8) + u64(8192) + u32(0x77) + attrs()))
    c.cr(17, SESS + fhsrc(CIFSV2), u32(13))
    mark('FlushGetAttr', c.cr(18, fhsrc(FMP) + u32(9) + u32(0x31) + u64(9000) +
         u32(1700000099, 5) + ext3, u32(0) + u32(9) + attrs()))
    c.cr(18, fhsrc(NFS) + u32(9) + u32(0x0e) + u64(9000) + u32(1700000099, 5) +
         extlist(), u32(5))
    # ---- Ex variants
    exl = extlistEx(extentEx(0, 16, 1, 0, 0), extentEx(1 << 33, 16, 2, 1 << 34, 1))
    mark('OpenGetMapEx', c.cr(19, SESS + fhsrc(NFS) + u64(1 << 32) + u32(64, 8),
         u32(0) + FH + u32(1, 0x59) + u64(1 << 40) + u32(0x77) + exl))
    c.cr(19, SESS + fhsrc(UNC) + u64(0) + u32(64, 8), u32(13))
    mark('OpenAllocSpaceEx', c.cr(20, SESS + fhsrc(NFS) + u64(1 << 32) + u32(64, 8),
         u32(0) + FH + u32(1, 0x5a) + u64(1 << 40) + u32(0x77) + exl))
    c.cr(20, SESS + fhsrc(UNC) + u64(0) + u32(64, 8), u32(12))
    mark('GetMapEx', c.cr(21, FH + u32(2) + u64(1 << 32) + u32(64, 8),
         u32(0) + u32(2, 0x5b) + u64(1 << 40) + exl))
    c.cr(21, FH + u32(2) + u64(0) + u32(64, 8), u32(500))
    mark('AllocSpaceEx', c.cr(22, FH + u32(2) + u64(1 << 32) + u32(64, 8),
         u32(0) + u32(2, 0x5c) + u64(1 << 40) + exl))
    c.cr(22, FH + u32(2) + u64(0) + u32(64, 8), u32(79))
    mark('FlushEx', c.cr(23, FH + u32(3) + u32(0x03) + u64(7000) + exl, u32(0, 3)))
    c.cr(23, FH + u32(3) + u32(0x08) + u64(7000) + extlistEx(), u32(501))
    # procedure 24 (FlushGetAttrEx) is in the constants but not the table
    mark('proc 24 (unsupported)', c.cr(24, b'\0' * 8, b''))
    # ---- GetVolumeInfo
    mark('GetVolumeInfo', c.cr(25, u32(0x99, 0, 0),
         u32(0) + hiervol(0x99, 3, 0x1234, [voldesc_disk_sig(1, 0x400, [(0, b'xyz')]),
                                            voldesc_slice(2)])))
    c.cr(25, u32(0x99, 3, 0x1234), u32(0) + hiervol(0x99, 4, 0, []))
    c.cr(25, u32(0x98, 0, 0), u32(13))
    # fix: GetVolumeInfo with a disk whose identifier is a serial
    mark('fix: devSerial NULL pinfo', c.cr(25, u32(1, 0, 0),
         u32(0) + u32(1, 0, 0) + u32(1) + u32(0) + u32(7) + u64(0) + u32(1) +
         u32(0, 0) + opq(b'ABCD')))
    # fix: Mount reply with a third party volume handle
    mark('fix: vmInfo offset', c.cr(3, SESS + u32(0, 4, 5),
         u32(0, 1, 512, 2) + opq(b'vol')))
    # ---- every status in a HeartBeat reply
    mark('statuses', len(c.f) + 1)
    for s in STATUSES:
        c.cr(2, SESS, u32(s))
    # ---- another client port
    c.cr(2, SESS, u32(0), sport=801, dport=4656)
    return marks


def build_malformed(c):
    # Truncated or inconsistent bodies: each reaches an exception.
    c.cr(1, opq('client1.example')[:10], None)
    c.cr(1, opq('client1.example') + u32(1700000000), None)          # timeval short
    c.cr(1, opq('client1.example') + u32(1700000000, 1) + u32(7000),
         u32(0) + SESS[:10])
    c.cr(2, SESS, b'')                                              # empty status
    c.cr(3, SESS + u32(1) + fhsrc(NFS), u32(0) + u32(1, 2) + u32(64))   # vmInfo cut
    c.cr(3, SESS + u32(1) + fhsrc(NFS),
         u32(0, 1, 2, 1, 2) + u32(500))                              # server list too long
    c.cr(3, SESS + u32(1) + fhsrc(NFS),
         u32(0, 1, 2, 0x40, 1, 2, 3, 0xffffff))                      # huge volume list
    c.cr(3, SESS + u32(1) + u32(1) + u32(64), None)                 # NFS handle past end
    c.cr(3, SESS + u32(1) + u32(5, 0) + u32(50), None)              # string past end
    c.cr(3, SESS + u32(1) + u32(2) + b'\0\1', None)                 # CIFS handle short
    c.cr(4, SESS + u32(3), None)                                    # no handle
    c.cr(6, FH, None)
    c.cr(6, SESS + fhsrc(NFS) + u32(0, 64, 8),
         u32(0) + FH + u32(1, 0x55) + u64(100000) + u32(0x77) + u32(1000) + b'\0' * 8)
    c.cr(19, SESS + fhsrc(NFS) + u32(0), None)
    c.cr(21, FH + u32(2), u32(0) + u32(2, 3) + u64(1) + u32(0x7fffffff) + b'\0' * 12)
    c.cr(10, FH + u32(5) + u32(1), None)
    c.cr(12, bytes(range(0x30, 0x40)) + opq(b'plugin args'), None)   # real layout
    c.cr(12, b'\0' * 8, None)
    c.cr(14, opq('c') + u32(1, 2, 3, 4, 5) + opq('Linux'), None)
    c.cr(16, FH + u32(7), u32(0) + u32(7) + attrs()[:50])
    c.cr(25, u32(1, 2), None)
    c.cr(25, u32(0, 0, 0), u32(0) + u32(1, 2, 3, 1) + u32(0, 5))
    c.cr(25, u32(0, 0, 0), u32(0) + u32(1, 2, 3, 2) + u32(0, 5))   # truncated descriptions
    c.cr(25, u32(0, 0, 0), u32(0) + hiervol(1, 2, 3, [u32(2, 1) + u64(1) + u32(0xfffffff)]))
    c.cr(25, u32(0, 0, 0), u32(0) + hiervol(1, 2, 3, [u32(3, 1) + u32(0xfffffff)]))


def main(out):
    verbose = '-v' in sys.argv
    c = Cap()
    marks = build(c)
    write_pcap(os.path.join(out, 'fmp-coverage.pcap'), c.f)
    if verbose:
        for n, f in marks:
            print('%5d  %s' % (f, n))
    print('fmp-coverage.pcap', len(c.f), 'frames')
    m = Cap()
    build_malformed(m)
    write_pcap(os.path.join(out, 'fmp-coverage-malformed.pcap'), m.f)
    print('fmp-coverage-malformed.pcap', len(m.f), 'frames')


if __name__ == '__main__':
    main(sys.argv[1])
