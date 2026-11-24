#!/usr/bin/env python3
# Generates test/captures/pvfs2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic PVFS2 (Parallel Virtual File System) captures.

    mkpvfs2.py <outdir>

writes pvfs2-coverage.pcap (clean: no malformed packets, same result with
tshark -2) and pvfs2-coverage-malformed.pcap (paths only malformed or
non-PVFS input reaches, and the IO tracking reproducer for which one pass
and two passes differ).

Everything is built with struct; nothing comes from a real network.
PVFS2 runs over TCP port 3334 (BMI TCP): a 24 byte BMI header (magic
51903, mode, tag, 64-bit size) followed by the request or response.
"""
import os
import struct
import sys

MAGIC = 51903
IMMED, UNEXP, EAGER, REND = 1, 2, 4, 8

# server operations
(INVALID, CREATE, REMOVE, IO, GETATTR, SETATTR, LOOKUP_PATH, CRDIRENT,
 RMDIRENT, CHDIRENT, TRUNCATE, MKDIR, READDIR, GETCONFIG, WRITE_COMPLETION,
 FLUSH, MGMT_SETPARAM, MGMT_NOOP, STATFS, PERF_UPDATE, MGMT_PERF_MON,
 MGMT_ITERATE_HANDLES, MGMT_DSPACE_INFO_LIST, MGMT_EVENT_MON,
 MGMT_REMOVE_OBJECT, MGMT_REMOVE_DIRENT, MGMT_GET_DIRDATA_HANDLE,
 JOB_TIMER, PROTO_ERROR, GETEATTR, SETEATTR, DELEATTR) = range(32)

# attribute mask bits
A_UID, A_GID, A_PERM, A_ATIME, A_CTIME, A_MTIME, A_TYPE = (1 << i for i in range(7))
A_DIST = 1 << 10
A_DFILES = 1 << 11
A_SIZE = 1 << 15
A_SYMLNK = 1 << 18
A_DIRENT = 1 << 19
A_SYS_SIZE = 1 << 20
A_SYS_LNK = 1 << 24
A_SYS_DFILE = 1 << 25
A_SYS_DIRENT = 1 << 26

EBIT = 1 << 30
FSID = 0x2a9c11f0


# ---------------------------------------------------------------- helpers
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Net:
    """TCP frames with consistent sequence and acknowledgment numbers."""

    def __init__(self):
        self.frames = []
        self.caps = []
        self.seq = {}

    def raw(self, src, dst, sport, dport, payload, flags=0x18, cap=None):
        key = (src, sport)
        seq = self.seq.get(key, 1000)
        self.seq[key] = seq + len(payload) + (1 if flags & 3 else 0)
        ack = self.seq.get((dst, dport), 5000) if flags & 0x10 else 0
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags,
                          65535, 0, 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0, 64, 6,
                         0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = bytes.fromhex('020000000002020000000001' '0800')
        if src[3] == 2:
            eth = bytes.fromhex('020000000001020000000002' '0800')
        fr = eth + ip + tcp
        self.frames.append(fr)
        self.caps.append(len(fr) if cap is None else 54 + cap)

    def handshake(self, c, s, cport, sport):
        self.raw(c, s, cport, sport, b'', 0x02)
        self.raw(s, c, sport, cport, b'', 0x12)
        self.raw(c, s, cport, sport, b'', 0x10)

    def stream(self, src, dst, sport, dport, data, cuts):
        """Send data as segments cut at the given offsets."""
        prev = 0
        for c in list(cuts) + [len(data)]:
            if c > prev:
                self.raw(src, dst, sport, dport, data[prev:c])
            prev = c

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                cl = self.caps[i]
                f.write(struct.pack('<IIII', 1700000000 + i, 0, cl, len(fr)) + fr[:cl])


def u32(v):
    return struct.pack('<I', v & 0xffffffff)


def i32(v):
    return struct.pack('<i', v)


def u64(v):
    return struct.pack('<Q', v)


def fh(n):
    return struct.pack('<Q', 0x0102030400000000 | n)


def pstr(s, tail=None):
    """PVFS string: length, bytes, NUL, padded so that 4+len+1 is a
    multiple of 8.  tail overrides the terminator and padding."""
    if isinstance(s, str):
        s = s.encode()
    full = (4 + len(s) + 1 + 7) & ~7
    body = s + b'\0' * (full - 4 - len(s))
    if tail is not None:
        body = s + tail
    return u32(len(s)) + body


def tm(sec, nsec=0):
    return u32(sec) + u32(nsec)


def dist(name='simple_stripe', strip=65536):
    d = pstr(name)
    if name == 'simple_stripe':
        d += u64(strip)
    return d + b'\0' * 8


def dfiles(n, base=0x40):
    return u32(n) + b''.join(fh(base + i) for i in range(n))


def attr(mask, dtype, tail=b''):
    """object attribute: uid gid perm skip atime mtime ctime mask type tail"""
    return (u32(1000) + u32(100) + u32(0o755) + u32(0) + tm(1700000001, 5)
            + tm(1700000002, 6) + tm(1700000003, 7) + u32(mask) + u32(dtype) + tail)


def attr_meta():
    return attr(A_UID | A_GID | A_PERM | A_TYPE | A_DIST, 1,
                dist() + dfiles(3))


def attr_meta_generic_dist():
    return attr(A_DIST, 1, dist('basic_dist') + dfiles(2))


def attr_dfiles():
    return attr(A_DFILES | A_ATIME | A_MTIME | A_CTIME, 1, dfiles(2))


def attr_data():
    return attr(A_SIZE, 2, u64(123456789))


def attr_symlink():
    return attr(A_SYMLNK, 8, u32(11) + u32(0) + pstr('/target/path'))


def attr_dir():
    return attr(A_DIRENT, 4, u64(42))


def attr_plain():
    return attr(A_SYS_SIZE | A_SYS_LNK | A_SYS_DFILE | A_SYS_DIRENT, 0)


def bmi(mode, tag, body):
    return struct.pack('<IIQQ', MAGIC, mode, tag, len(body)) + body


def req(op, body=b'', ctx=7, uid=1000, gid=100, release=20100, enc=2):
    return (u32(release) + u32(enc) + u32(op) + u32(ctx) + u32(uid) + u32(gid)
            + body)


def resp(op, body=b'', err=0, release=20100, enc=2):
    return u32(release) + u32(enc) + u32(op) + i32(err) + body


def ekeyval(n=2):
    out = u32(n)
    for i in range(n):
        out += pstr('user.key%d' % i) + pstr('value-%d' % i)
    return out


C = (192, 0, 2, 1)
S = (192, 0, 2, 2)
CP = 40100
SP = 3334


class Conv:
    """One TCP connection; each call sends a request and its response."""

    def __init__(self, net, c=C, s=S, cport=CP, sport=SP):
        self.net, self.c, self.s, self.cport, self.sport = net, c, s, cport, sport
        self.tag = 0x1000

    def next_tag(self):
        self.tag += 1
        return (0x11223344 << 32) | self.tag if self.tag & 1 else self.tag

    def to_server(self, mode, tag, body, cuts=()):
        self.net.stream(self.c, self.s, self.cport, self.sport,
                        bmi(mode, tag, body), cuts)

    def to_client(self, mode, tag, body, cuts=()):
        self.net.stream(self.s, self.c, self.sport, self.cport,
                        bmi(mode, tag, body), cuts)

    def txn(self, op, rq, rs, err=0, rmode=IMMED):
        tag = self.next_tag()
        self.to_server(UNEXP, tag, req(op, rq))
        self.to_client(rmode, tag, resp(op, rs, err))
        return tag


# ---------------------------------------------------------------- main
def io_request(io_type, nreq=1, dname='simple_stripe', start=0, size=65536):
    pint = (u64(start) + u32(1) + u32(2) + u64(3) + u64(4) + u64(5) + u64(6)
            + u32(7) + u32(8) + u32(9) + u32(1) + u32(1) + u32(0) + u32(10)
            + u32(11))
    return (fh(0x30) + u32(FSID) + u32(0) + u32(io_type) + u32(2) + u32(0)
            + u32(3) + dist(dname) + u32(nreq) + u32(0) + pint
            + u64(start) + u64(size))


def main_capture():
    net = Net()
    cv = Conv(net)
    net.handshake(C, S, CP, SP)

    def txn(op, rq, rs, err=0, rmode=IMMED):
        return cv.txn(op, rq, rs, err, rmode)

    # ---- every operation
    txn(CREATE, u32(FSID) + u32(1) + u32(0) + u32(2) + fh(0x10) + fh(0x1f)
        + fh(0x20) + fh(0x2f), fh(0x55))
    txn(CREATE, u32(FSID) + u32(2) + u32(0) + u32(0), fh(0x56), rmode=EAGER)
    txn(REMOVE, fh(0x55) + u32(FSID), b'')
    txn(GETATTR, fh(0x57) + u32(FSID) + u32(0x7ffff), attr_meta())
    for a in (attr_meta_generic_dist, attr_dfiles, attr_data, attr_symlink,
              attr_dir, attr_plain):
        txn(GETATTR, fh(0x58) + u32(FSID) + u32(A_TYPE), a())
    txn(SETATTR, fh(0x59) + u32(FSID) + u32(0) + attr_meta(), b'')
    txn(SETATTR, fh(0x59) + u32(FSID) + u32(0) + attr_plain(), b'',
        err=-(EBIT | 13))
    txn(LOOKUP_PATH, pstr('/home/user/file.txt') + u32(FSID) + u32(0) + fh(1)
        + u32(A_TYPE | A_UID),
        u32(0) + u32(2) + fh(0x61) + fh(0x62) + u32(0) + u32(2)
        + attr_meta() + attr_data())
    txn(LOOKUP_PATH, pstr('/missing') + u32(FSID) + u32(0) + fh(1) + u32(0),
        u32(0) + u32(0) + u32(0) + u32(0), err=-(EBIT | 2))
    txn(CRDIRENT, pstr('newfile') + fh(0x71) + fh(0x72) + u32(FSID) + u32(0)
        + tm(10, 1) + tm(11, 2) + tm(12, 3), b'')
    txn(RMDIRENT, pstr('oldfile') + fh(0x72) + u32(FSID) + u32(0)
        + tm(10, 1) + tm(11, 2) + tm(12, 3), fh(0x73))
    txn(CHDIRENT, pstr('renamed') + fh(0x74) + fh(0x72) + u32(FSID)
        + tm(20, 1) + tm(21, 2) + tm(22, 3), fh(0x75))
    txn(TRUNCATE, fh(0x76) + u32(FSID) + u32(0) + u64(4096) + u32(1), b'')
    txn(MKDIR, u32(FSID) + u32(0) + attr_dir() + u32(2) + fh(0x77) + fh(0x78),
        fh(0x79))
    txn(MKDIR, u32(FSID) + u32(0) + attr_plain() + u32(0), fh(0x7a))
    txn(READDIR, fh(0x7b) + u32(FSID) + u32(0) + u32(64),
        u32(3) + u32(0) + u64(0x1122334455) + u32(0) + u32(3)
        + b''.join(pstr(n) + fh(0x90 + i)
                   for i, n in enumerate(('a', 'bb', 'ccc'))))
    txn(READDIR, fh(0x7b) + u32(FSID) + u32(3) + u32(64),
        u32(3) + u32(0) + u64(1) + u32(0) + u32(0))
    txn(FLUSH, fh(0x7c) + u32(FSID) + u32(1), b'')
    txn(MGMT_SETPARAM, u32(FSID) + u32(1) + u64(0xff), u64(0x1))
    txn(MGMT_SETPARAM, u32(FSID) + u32(2) + u32(FSID) + u32(0), u64(2))
    txn(MGMT_SETPARAM, u32(FSID) + u32(3) + fh(0x1) + u64(0), u64(3))
    txn(MGMT_SETPARAM, u32(FSID) + u32(4) + u32(2) + u32(0), u64(1))
    txn(MGMT_SETPARAM, u32(FSID) + u32(5) + u64(1), u64(0))
    txn(MGMT_SETPARAM, u32(FSID) + u32(6) + u64(0xf0f0), u64(0))
    txn(MGMT_SETPARAM, u32(FSID) + u32(0) + u64(0), u64(0))
    txn(STATFS, u32(FSID),
        u32(0) + u32(FSID) + b''.join(u64(1000 * (i + 1)) for i in range(10)))
    txn(MGMT_PERF_MON, u32(5) + u32(3),
        u32(6) + u32(0) + u64(1700000000000) + u64(1700000001000) + u32(0)
        + u32(2)
        + b''.join(u32(1) + u32(i) + u64(1000 + i) + u64(1) + u64(2) + u64(3)
                   + u64(4) for i in range(2)))
    txn(MGMT_ITERATE_HANDLES, u32(FSID) + fh(0x7d),
        u32(9) + u32(3) + fh(0x1) + fh(0x2) + fh(0x3))
    txn(MGMT_DSPACE_INFO_LIST, u32(FSID) + u32(2) + fh(1) + fh(2),
        u32(0) + u32(2)
        + b''.join(u32(0) + fh(i) + u32(2) + u64(512 * i) + u64(4096)
                   + fh(0x100 + i) for i in (1, 2)))
    # "Skip dspace_info_count": the first dspace_info has an error code
    txn(MGMT_DSPACE_INFO_LIST, u32(FSID) + u32(1) + fh(9),
        u32(0) + u32(1) + i32(-(EBIT | 2)) + fh(9) + u32(1) + u64(0)
        + u64(0) + fh(0))
    txn(MGMT_DSPACE_INFO_LIST, u32(FSID) + u32(0), u32(0) + u32(0))
    txn(MGMT_EVENT_MON, u32(10),
        u32(1) + u32(2) + u32(3) + u64(0x1122334455667788) + u32(4) + u32(5)
        + u32(6) + u32(0))
    txn(MGMT_REMOVE_OBJECT, fh(0x7e) + u32(FSID), fh(0x7e) + u32(FSID))
    txn(MGMT_REMOVE_DIRENT, fh(0x7f) + u32(FSID) + u32(0) + pstr('entry'), b'')
    txn(MGMT_GET_DIRDATA_HANDLE, fh(0x80) + u32(FSID), fh(0x81))
    txn(GETEATTR, fh(0x82) + u32(FSID) + u32(0) + ekeyval(2),
        u32(0) + ekeyval(2))
    txn(SETEATTR, fh(0x82) + u32(FSID) + u32(0) + ekeyval(1), b'')
    txn(DELEATTR, fh(0x82) + u32(FSID) + pstr('user.key0') + pstr('x'), b'')
    txn(GETEATTR, fh(0x82) + u32(FSID) + u32(0) + u32(0), u32(0) + u32(0))
    for op in (MGMT_NOOP, PERF_UPDATE, JOB_TIMER, PROTO_ERROR,
               INVALID, 77):
        txn(op, b'', b'')
    txn(MGMT_NOOP, b'', b'', err=-(EBIT | 5), rmode=REND)
    txn(MGMT_NOOP, b'', b'', err=-2, rmode=EAGER)         # unknown error 2
    txn(MGMT_NOOP, b'', b'', err=-(EBIT | 99))             # unknown PVFS error

    # ---- strings: embedded NUL / missing terminator / wraparound length
    # a string whose terminator byte is not NUL: no <TRUNCATED> (3 chars + 'X')
    txn(CRDIRENT, pstr('abc', tail=b'X\0\0\0') + fh(1) + fh(2) + u32(FSID)
        + u32(0) + tm(1) + tm(2) + tm(3), b'')
    # a NUL inside the string
    txn(CRDIRENT, pstr(b'ab\0cd') + fh(1) + fh(2) + u32(FSID) + u32(0)
        + tm(1) + tm(2) + tm(3), b'')
    # an empty string
    txn(CRDIRENT, pstr('') + fh(1) + fh(2) + u32(FSID) + u32(0)
        + tm(1) + tm(2) + tm(3), b'')
    # length 0xffffffff: length + 1 wraps to 0
    txn(CRDIRENT, u32(0xffffffff) + b'\0' * 4 + fh(1) + fh(2) + u32(FSID)
        + u32(0) + tm(1) + tm(2) + tm(3), b'')
    # a string with non-printable characters
    txn(CRDIRENT, pstr(b'a\x01b\x7f\xc3\xa9z') + fh(1) + fh(2) + u32(FSID)
        + u32(0) + tm(1) + tm(2) + tm(3), b'')
    # distributions: the name 'simple_stripe' spelled in upper case, and a
    # name with the length of simple_stripe but other characters
    for nm in ('SIMPLE_STRIPE', 'simple_stripX'):
        d = pstr(nm) + (u64(4096) if nm == 'SIMPLE_STRIPE' else b'') + b'\0' * 8
        txn(GETATTR, fh(3) + u32(FSID) + u32(A_DIST), attr(A_DIST, 1, d + dfiles(1)))

    # ---- IO: tracking of requests, responses and flow data
    # write: request, response, flow data (REND), write completion
    t = cv.next_tag()
    cv.to_server(UNEXP, t, req(IO, io_request(2)))
    cv.to_client(IMMED, t, resp(IO, u64(65536)))
    cv.to_client(REND, t, bytes(range(256)) * 4)
    cv.to_client(IMMED, t, resp(WRITE_COMPLETION, u64(65536)))
    # read with a different distribution: request, response, flow data
    t = cv.next_tag()
    cv.to_server(UNEXP, t, req(IO, io_request(1, 3, 'basic_dist', 4096, 1 << 20)))
    cv.to_client(EAGER, t, resp(IO, u64(1 << 20)))
    cv.to_client(REND, t, b'D' * 3000, cuts=(1400, 2800))
    # read where the flow data frame is the last one with this tag
    t = cv.next_tag()
    cv.to_server(UNEXP, t, req(IO, io_request(1)))
    cv.to_client(IMMED, t, resp(IO, u64(0), err=-(EBIT | 5)))
    cv.to_client(REND, t, b'E' * 16)
    # IO request without a response in the capture; a response without request
    t = cv.next_tag()
    cv.to_server(UNEXP, t, req(IO, io_request(2)))
    cv.to_client(IMMED, cv.next_tag(), resp(IO, u64(5)))

    # ---- getconfig responses
    def getconfig(text, lines=None, total=None):
        if isinstance(text, str):
            text = text.encode()
        if lines is None:
            lines = text.count(b'\n') + text.count(b'\0')
        return u32(total if total is not None else len(text) + 8) \
            + u32(lines) + u32(len(text)) + text

    cfg = ('<Defaults>\n'
           'UnexpectedRequests 50\n'
           'LogFile /var/log/pvfs2-server.log\n'
           '</Defaults>\n'
           '\n'
           '  <Aliases>\n'
           '\tAlias host1 tcp://host1:3334\n'
           '\tAlias host2 tcp://host2:3334\n'
           '</Aliases>\n'
           '<FileSystem>\n'
           'Name pvfs2-fs\n'
           'ID 1234567\n'
           '<MetaHandleRanges>\n'
           'Range host1 4-2147483650\n'
           '</MetaHandleRanges>\n'
           'RootHandle 1048576\n'
           '</FileSystem>\n'
           'Trailing line with no section\n')
    txn(GETCONFIG, b'', getconfig(cfg))
    # a line ended by NUL, a line that starts with punctuation and an
    # empty config
    txn(GETCONFIG, b'', getconfig(b'<A>\nk v\0 \n  ;;x y\n</A>\n'))
    txn(GETCONFIG, b'', getconfig(b'', lines=0, total=4))
    txn(GETCONFIG, b'', u32(0))   # total_bytes < 4: no configuration
    # a configuration of 20 KB over several TCP segments (reassembly)
    big = '<Big>\n' + ''.join('Entry%03d value-%03d with some text\n' % (i, i)
                              for i in range(500)) + '</Big>\n'
    t = cv.next_tag()
    cv.to_server(UNEXP, t, req(GETCONFIG))
    cv.to_client(IMMED, t, resp(GETCONFIG, getconfig(big)),
                 cuts=(100, 1500, 2960, 5000, 9000, 15000))

    # ---- more TCP framing
    # a readdir response with 150 entries split in segments
    names = ['file%04d.dat' % i for i in range(150)]
    body = (u32(1) + u32(0) + u64(77) + u32(0) + u32(len(names))
            + b''.join(pstr(n) + fh(0x1000 + i) for i, n in enumerate(names)))
    t = cv.next_tag()
    cv.to_server(UNEXP, t, req(READDIR, fh(0x7b) + u32(FSID) + u32(0) + u32(200)))
    cv.to_client(IMMED, t, resp(READDIR, body), cuts=(30, 1460, 2920, 4380))
    # two PDUs in one segment, and a PDU that starts at the end of a segment
    t1, t2, t3 = cv.next_tag(), cv.next_tag(), cv.next_tag()
    pdus = (bmi(UNEXP, t1, req(GETATTR, fh(5) + u32(FSID) + u32(A_TYPE)))
            + bmi(UNEXP, t2, req(STATFS, u32(FSID)))
            + bmi(UNEXP, t3, req(FLUSH, fh(6) + u32(FSID) + u32(0))))
    net.stream(C, S, CP, SP, pdus, cuts=(len(pdus) // 3 + 10, 2 * len(pdus) // 3 + 7))
    pdus = (bmi(IMMED, t1, resp(GETATTR, attr_plain()))
            + bmi(IMMED, t2, resp(STATFS, u32(0) + u32(FSID) + b'\0' * 80))
            + bmi(IMMED, t3, resp(FLUSH)))
    net.stream(S, C, SP, CP, pdus, cuts=(60,))

    # a header split in two: first bytes of the second PDU end the segment
    t1, t2 = cv.next_tag(), cv.next_tag()
    pdus = (bmi(UNEXP, t1, req(MGMT_NOOP)) + bmi(UNEXP, t2, req(MGMT_NOOP)))
    first = len(bmi(UNEXP, t1, req(MGMT_NOOP)))
    net.stream(C, S, CP, SP, pdus, cuts=(first + 10,))
    pdus = (bmi(IMMED, t1, resp(MGMT_NOOP)) + bmi(IMMED, t2, resp(MGMT_NOOP)))
    net.stream(S, C, SP, CP, pdus, cuts=())

    # ---- a second connection on a port that PVFS does not own: the
    # heuristic dissector finds it
    cv2 = Conv(net, c=(192, 0, 2, 3), s=(192, 0, 2, 4), cport=41000, sport=5555)
    net.handshake((192, 0, 2, 3), (192, 0, 2, 4), 41000, 5555)
    cv2.txn(STATFS, u32(FSID), u32(0) + u32(FSID) + b'\0' * 80)
    cv2.txn(READDIR, fh(1) + u32(FSID) + u32(0) + u32(8),
            u32(1) + u32(0) + u64(1) + u32(0) + u32(1) + pstr('x') + fh(2))
    return net


# ---------------------------------------------------------------- malformed
def malformed_capture():
    net = Net()
    cv = Conv(net)
    net.handshake(C, S, CP, SP)

    # IO tracking reproducer (one pass and -2 differ): the tag is reused
    TAG = 0x77
    io_req = req(IO, b'\0' * 64)
    net.raw(C, S, CP, SP, bmi(UNEXP, TAG, io_req))
    net.raw(S, C, SP, CP, bmi(IMMED, TAG, resp(IO, u64(16))))
    net.raw(S, C, SP, CP, bmi(REND, TAG, b'F' * 16))
    net.raw(C, S, CP, SP, bmi(UNEXP, TAG, io_req))
    net.raw(S, C, SP, CP, bmi(IMMED, TAG, resp(IO, u64(16))))
    # the huge dspace_info_count (count * 40 overflows an int)
    net.raw(S, C, SP, CP, bmi(IMMED, 0x99, resp(
        MGMT_DSPACE_INFO_LIST, u32(0) + u32(0x04000000) + b'\0' * 40)))
    # getconfig: a 300 byte line, an unterminated "<" token, more lines than
    # data, a line without a newline at the end
    for text, lines in ((b'A' * 300 + b'\n', 1),
                        (b'<Defaults>\nKey Value\n</Defaults>\n<\n', 4),
                        (b'<A>\nx y\n', 5),
                        (b'<A>\nx y', 2),
                        (b'<A>\nx y\n</A>\nleft over\n', 3)):
        data = u32(len(text) + 8) + u32(lines) + u32(len(text)) + text
        net.raw(S, C, SP, CP, bmi(IMMED, 0x9a, resp(GETCONFIG, data)))
    # config claims more bytes than the PDU holds
    net.raw(S, C, SP, CP, bmi(IMMED, 0x9b, resp(
        GETCONFIG, u32(100) + u32(1) + u32(1000) + b'abc\n')))

    # Truncated PDUs: each of these ends in the middle of a field (the BMI
    # size is correct for the truncated body).
    def trunc(op, body, mode=UNEXP, response=False):
        data = resp(op, body) if response else req(op, body)
        net.raw(C if mode == UNEXP else S, S if mode == UNEXP else C,
                CP if mode == UNEXP else SP, SP if mode == UNEXP else CP,
                bmi(mode, cv.next_tag(), data))

    trunc(CREATE, u32(FSID) + u32(1) + u32(0) + u32(1000))        # extents
    trunc(GETATTR, fh(1))
    trunc(SETATTR, fh(1) + u32(FSID) + u32(0) + attr_meta()[:50])
    trunc(LOOKUP_PATH, u32(100) + b'/abc')                        # long string
    trunc(LOOKUP_PATH, u32(3) + b'ab')                            # fill bytes
    trunc(LOOKUP_PATH, u32(3) + b'abc\0')                         # short fill
    trunc(CRDIRENT, pstr('x') + fh(1))
    trunc(MKDIR, u32(FSID) + u32(0) + attr_plain() + u32(100) + fh(1))
    trunc(READDIR, fh(1) + u32(FSID) + u32(0))
    trunc(MGMT_SETPARAM, u32(FSID) + u32(3) + b'\0\0')
    trunc(MGMT_DSPACE_INFO_LIST, u32(FSID) + u32(5000) + fh(1))
    trunc(GETEATTR, fh(1) + u32(FSID) + u32(0) + u32(3) + pstr('k'))
    trunc(IO, io_request(2)[:90])                                  # IO request
    trunc(GETATTR, fh(1) + u32(FSID), response=False)
    # distribution name longer than the PDU
    trunc(SETATTR, fh(1) + u32(FSID) + u32(0)
          + attr(A_DIST, 1, u32(0x7fffffff) + b'abc'))
    trunc(GETATTR, attr_meta()[:40], mode=IMMED, response=True)
    trunc(LOOKUP_PATH, u32(0) + u32(100) + fh(1), mode=IMMED, response=True)
    trunc(LOOKUP_PATH, u32(0) + u32(0) + u32(0) + u32(3) + attr_meta()[:30],
          mode=IMMED, response=True)
    trunc(READDIR, u32(1) + u32(0) + u64(1) + u32(0) + u32(500) + pstr('x'),
          mode=IMMED, response=True)
    trunc(STATFS, u32(0) + u32(FSID) + b'\0' * 30, mode=IMMED, response=True)
    trunc(MGMT_PERF_MON, u32(1) + u32(0) + u64(1) + u64(2) + u32(0) + u32(100)
          + b'\0' * 20, mode=IMMED, response=True)
    trunc(MGMT_ITERATE_HANDLES, u32(1) + u32(9) + fh(1), mode=IMMED,
          response=True)
    trunc(MGMT_EVENT_MON, u32(1) + u32(2), mode=IMMED, response=True)
    trunc(GETEATTR, u32(0) + u32(2) + pstr('k'), mode=IMMED, response=True)
    trunc(CREATE, b'', mode=IMMED, response=True)
    trunc(GETCONFIG, u32(100) + u32(1), mode=IMMED, response=True)
    trunc(LOOKUP_PATH, pstr('abcdefgh')[:-2])                      # cut fill bytes
    # Captures cut by a snap length: the packet is longer than the capture
    full = req(LOOKUP_PATH, pstr('x' * 100) + u32(FSID) + u32(0) + fh(1) + u32(0))
    pdu = bmi(UNEXP, cv.next_tag(), full)
    net.raw(C, S, CP, SP, pdu, cap=24 + 12 + 12 + 4 + 30)          # inside the string
    pdu = bmi(UNEXP, cv.next_tag(), req(LOOKUP_PATH, pstr('abcdefgh') + u32(FSID)
                                        + u32(0) + fh(1) + u32(0)))
    net.raw(C, S, CP, SP, pdu, cap=24 + 12 + 12 + 4 + 9 + 1)       # inside the fill
    net.raw(C, S, CP, SP, pdu, cap=24 + 12 + 12 + 6)               # inside the length
    pdu = bmi(IMMED, cv.next_tag(), resp(GETATTR, attr_meta()))
    net.raw(S, C, SP, CP, pdu, cap=24 + 16 + 20)                   # inside attributes
    # a PDU whose BMI header is complete but the PVFS header is cut
    net.raw(C, S, CP, SP, bmi(UNEXP, 0x55, b'\0' * 6))
    net.raw(S, C, SP, CP, bmi(IMMED, 0x56, b'\0' * 6))
    # flow data shorter than the header lookahead
    t = cv.next_tag()
    net.raw(C, S, CP, SP, bmi(UNEXP, t, req(IO, io_request(2))))
    net.raw(S, C, SP, CP, bmi(IMMED, t, resp(IO, u64(1))))
    net.raw(S, C, SP, CP, bmi(REND, t, b'\0' * 5))

    # Not PVFS: wrong magic, wrong mode, size 0, size too large, header
    # shorter than 24 bytes.  TCP decodes them as data (port 3334 handler
    # returns 0 and the heuristic rejects them too).
    good = req(MGMT_NOOP)
    net.raw(C, S, CP, SP, struct.pack('<IIQQ', 12345, UNEXP, 1, len(good)) + good)
    net.raw(C, S, CP, SP, struct.pack('<IIQQ', MAGIC, 3, 1, len(good)) + good)
    net.raw(C, S, CP, SP, struct.pack('<IIQQ', MAGIC, UNEXP, 1, 0) + good)
    net.raw(C, S, CP, SP, struct.pack('<IIQQ', MAGIC, UNEXP, 1, 1000001) + good)
    net.raw(C, S, CP, SP, struct.pack('<IIQQ', MAGIC, UNEXP, 1, 1 << 32) + good)
    net.raw(C, S, CP, SP, b'\x3f\xca\x00\x00' + b'\0' * 10)
    # a length so large that the header claims 20 more bytes than the
    # segment holds and the next segment does not complete it
    net.raw(C, S, CP, SP, bmi(UNEXP, 9, req(MGMT_NOOP))[:30])
    net.raw(S, C, SP, CP, b'')
    return net


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    n = main_capture()
    n.write(os.path.join(out, 'pvfs2-coverage.pcap'))
    print('pvfs2-coverage.pcap: %d frames' % len(n.frames))
    m = malformed_capture()
    m.write(os.path.join(out, 'pvfs2-coverage-malformed.pcap'))
    print('pvfs2-coverage-malformed.pcap: %d frames' % len(m.frames))


if __name__ == '__main__':
    main()
