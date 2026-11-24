#!/usr/bin/env python3
# Generates the nstrace captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the NetScaler trace coverage captures (synthetic, struct only).

Usage: mknstrace.py <outdir> [-v]

Writes, into <outdir>:
  nstrace-coverage.nstr           NetScaler 2.0 file: record headers 2.0-2.6
  nstrace-coverage-v10.nstr       NetScaler 1.0 file
  nstrace-coverage-v35.nstr       NetScaler 3.5 file: v3.5 records (with
                                  every NS record type) and 3.0 records
  nstrace-coverage-v30.nstr       NetScaler 3.0 file
  nstrace-coverage-malformed.nstr 3.5 file with malformed records
  nstrace-reclen0-loop.nstr       the reproducer of f4e8041e10 (3.5)
  nstrace-trunc-eof.nstr          the reproducer of 63caf4145d wiretap
                                  (record longer than the file)
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []   # (file, first frame, last frame, description)


# ------------------------------------------------------------ Ethernet frames
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def tcp(sport, dport, flags, seq, ack, payload=b''):
    opts = b'\x02\x04\x05\xb4\x04\x02\x01\x03\x03\x07\x01\x01' if flags & 2 else b''     # MSS, NOP, window scale
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload


def eth(payload, etype=0x0800, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'):
    mac = lambda m: bytes(int(x, 16) for x in m.split(':'))
    return mac(dst) + mac(src) + struct.pack('>H', etype) + payload


_FRAMES = [0]


def frame(kind=0, n=0):
    """A small Ethernet frame; kind selects the content; n is ignored (a
    running counter keeps every frame unique)."""
    _FRAMES[0] += 1
    n = _FRAMES[0]
    k = kind % 5
    if k == 0:   # TCP SYN
        return eth(ipv4(6, tcp(40000 + n, 80, 0x02, 1000 + n, 0), ident=n))
    if k == 1:   # TCP with an HTTP request
        req = b'GET /i%d HTTP/1.1\r\nHost: example.invalid\r\n\r\n' % n
        return eth(ipv4(6, tcp(40000 + n, 80, 0x18, 1001 + n, 1, req), ident=n))
    if k == 2:   # UDP DNS query
        q = struct.pack('>HHHHHH', n, 0x8180, 1, 0, 0, 0) + b'\x03www\x07example\x07invalid\x00' + struct.pack('>HH', 1, 1)
        u = struct.pack('>HHHH', 50000 + n, 53, 8 + len(q), 0) + q
        return eth(ipv4(17, u, ident=n))
    if k == 3:   # ICMP echo
        ic = struct.pack('>BBHHH', 0, 0, 0, 1, n) + b'ping'
        ic = ic[:2] + struct.pack('>H', csum(ic)) + ic[4:]
        return eth(ipv4(1, ic, ident=n))
    # ARP request
    arp = struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, b'\x02\0\0\0\0\x01', bytes([192, 0, 2, 1]),
                      b'\0' * 6, bytes([192, 0, 2, 2]))
    return eth(arp, 0x0806, dst='ff:ff:ff:ff:ff:ff')


# ------------------------------------------------------------ record sizes
def v20size(n):
    """Two octet size field of a 3 octet header (type, low, high)."""
    if n < 128:
        return bytes([n, 0])
    return bytes([(n & 0x7f) | 0x80, n >> 7])


def hrtime_usec(us):
    return 0x80000000 | us


# field layouts after the 3 octet header: (name, size)
TIME_REL = [('dev', 1), ('rel', 4)]
TIME_ABS = [('dev', 1), ('abs', 8)]
PART = [('pktsizeorg', 2), ('pktoffset', 2)]
PCB = [('pcb', 4), ('lpcb', 4)]
LAY = {}
LAY[20] = TIME_REL
LAY[21] = LAY[20] + PCB
LAY[22] = LAY[21] + [('vlan', 2)]
LAY[23] = TIME_ABS + PCB + [('vlan', 2), ('core', 2)]
LAY[24] = LAY[23] + [('src', 2), ('dst', 2), ('clflags', 1)]
LAY[25] = LAY[24] + [('svm', 1), ('dvm', 1)]
LAY[26] = LAY[25] + [('res', 1), ('act', 4), ('res32', 12)]
PLAY = {}
for v in (20, 21, 22):
    PLAY[v] = TIME_REL + PART + (PCB if v >= 21 else []) + ([('vlan', 2)] if v >= 22 else [])
PLAY[23] = TIME_ABS + PART + PCB + [('vlan', 2), ('core', 2)]
PLAY[24] = PLAY[23] + [('src', 2), ('dst', 2), ('clflags', 1)]
PLAY[25] = PLAY[24] + [('svm', 1), ('dvm', 1)]
PLAY[26] = PLAY[25] + [('res', 1), ('act', 4), ('res32', 12)]
LAY[30] = TIME_ABS + PCB + [('pktsizeorg', 2), ('vlan', 2), ('core', 2), ('src', 2), ('dst', 2),
                            ('clflags', 1), ('svm', 1), ('dvm', 1), ('res3', 3), ('act', 4), ('res32', 12)]
LAY[35] = TIME_ABS + PCB + [('pktsizeorg', 2), ('vlan', 2), ('core', 2), ('headerlen', 2),
                            ('err', 1), ('app', 1), ('act', 4), ('nextrec', 1)]

# record types: (full TX, TXB, RX, NEWRX) and (part TX, TXB, RX, NEWRX)
FULLT = {20: (0xC0, 0xC1, 0xC2), 21: (0xD0, 0xD1, 0xD2), 22: (0xE0, 0xE1, 0xE2), 23: (0xF0, 0xF1, 0xF2),
         24: (0xF8, 0xF9, 0xFA, 0xFB), 25: (0xB0, 0xB1, 0xB2, 0xB3), 26: (0xA0, 0xA1, 0xA2, 0xA3),
         30: (0xA8, 0xA9, 0xAA, 0xAB), 35: (0xAC, 0xAD, 0xAE, 0xAF)}
PARTT = {20: (0xC4, 0xC5, 0xC6), 21: (0xD4, 0xD5, 0xD6), 22: (0xE4, 0xE5, 0xE6), 23: (0xF4, 0xF5, 0xF6),
         24: (0xFC, 0xFD, 0xFE, 0xFF), 25: (0xB4, 0xB5, 0xB6, 0xB7), 26: (0xA4, 0xA5, 0xA6, 0xA7)}


def build(layout, rtype, vals, tail):
    """3 octet header + fields + tail; the size covers all of it."""
    body = b''
    for name, size in layout:
        v = vals.get(name, 0)
        if isinstance(v, bytes):
            assert len(v) == size, name
            body += v
        else:
            body += int(v).to_bytes(size, 'little')
    total = 3 + len(body) + len(tail)
    return bytes([rtype]) + v20size(total) + body + tail


def pkt2(ver, rtype, part, payload, **kw):
    vals = dict(dev=1, rel=hrtime_usec(100), abs=1700000000 * 10**9 + kw.pop('ns', 0),
                pcb=0x11, lpcb=0x22, vlan=0, core=0, src=0, dst=0, clflags=0,
                pktsizeorg=len(payload), pktoffset=0)
    vals.update(kw)
    svm, dvm = vals.get('svm_name', b''), vals.get('dvm_name', b'')
    if part and ver >= 25:
        vals['pktsizeorg'] = len(svm) + len(dvm) + len(payload)
    if ver >= 25:
        vals['svm'], vals['dvm'] = len(svm), len(dvm)
    tail = (svm + dvm if ver >= 25 else b'') + payload
    return build((PLAY if part else LAY)[ver], rtype, vals, tail)


def pkt30(rtype, payload, **kw):
    vals = dict(dev=1, abs=1700000000 * 10**9, pcb=0x11, lpcb=0x22, pktsizeorg=len(payload),
                vlan=0, core=0, src=0, dst=0, clflags=0)
    vals.update(kw)
    svm, dvm = vals.pop('svm_name', b''), vals.pop('dvm_name', b'')
    vals['svm'], vals['dvm'] = len(svm), len(dvm)
    return build(LAY[30], rtype, vals, svm + dvm + payload)


def pkt35(rtype, records, payload, nextrec=None, **kw):
    """records: list of (type, bytes after the 3 octet record header); the
    chain of next record types is built here. nextrec: the type after the
    last record (default: Ethernet, 0x01)."""
    chain = b''
    types = [t for t, _ in records]
    for i, (t, data) in enumerate(records):
        nxt = types[i + 1] if i + 1 < len(records) else (1 if nextrec is None else nextrec)
        chain += struct.pack('<HB', 3 + len(data), nxt) + data
    first = types[0] if records else (1 if nextrec is None else nextrec)
    # the record header carries type implicitly: the previous record's
    # "next" octet (or fp_nextrectype for the first)
    vals = dict(dev=1, abs=1700000000 * 10**9, pcb=0x11, lpcb=0x22, pktsizeorg=len(payload),
                vlan=0, core=0, headerlen=35 + len(chain), err=0, app=0, act=0, nextrec=first)
    vals.update(kw)
    return build(LAY[35], rtype, vals, chain + payload)


def u32(*v):
    return b''.join(struct.pack('<I', x) for x in v)


# ------------------------------------------------------------ file writers
def pack_pages(records, pagesize, head=b'', pad_last=False):
    pages, cur = [], bytearray(head)
    for r in records:
        if len(cur) + len(r) > pagesize:
            cur += b'\0' * (pagesize - len(cur))
            pages.append(bytes(cur))
            cur = bytearray()
        cur += r
    if pad_last:
        cur += b'\0' * (pagesize - len(cur))
    pages.append(bytes(cur))
    return b''.join(pages)


def sig20(s):
    sb = s.encode() + b'\0'
    return struct.pack('<BBB', 0x01, 3 + len(sb), 0) + sb


def abstime20(t):
    return struct.pack('<BBHI', 0x07, 8, 0, t)    # type, size, rel(2), abs(4)


def reltime20(ms):
    return struct.pack('<BBHI', 0x08, 8, ms, 0)


def write(name, data):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(data)


def note(fname, first, last, text):
    RANGES.append((fname, first, last, text))


class Counter:
    def __init__(self, fname):
        self.n = 0
        self.fname = fname
        self.recs = []

    def add(self, rec, text=None):
        self.recs.append(rec)
        self.n += 1
        return self.n

    def group(self, text):
        first = self.n + 1
        return lambda: note(self.fname, first, self.n, text)


# ------------------------------------------------------------ V2.0 file
def make_v20():
    fn = 'nstrace-coverage.nstr'
    c = Counter(fn)
    recs = [abstime20(1700000000), reltime20(5)]
    k = 0
    for ver in (20, 21, 22, 23, 24, 25, 26):
        g = c.group('record header 2.%d' % (ver - 20))
        kinds = FULLT[ver]
        for i, rt in enumerate(kinds):
            extra = {}
            if ver >= 24:
                extra.update(src=3 + i, dst=4, clflags=[0x00, 0x01, 0x0f, 0xff][i % 4])
            if ver >= 25:
                extra.update(svm_name=b'vm-src%d\0' % i if i % 2 == 0 else b'', dvm_name=b'vm-dst\0' if i else b'')
            if ver >= 26:
                extra.update(act=[0, 0x1f, 0x03, 0x10][i % 4], res=7 if i == 1 else 0)
            if ver >= 22:
                extra.update(vlan=100 + i)
            if ver >= 23:
                extra.update(core=i + 1, ns=1000 * (i + 1))
            f = frame(k, k); k += 1
            c.add(pkt2(ver, rt, False, f, rel=hrtime_usec(100 * (i + 1)), **extra))
        for i, rt in enumerate(PARTT[ver]):
            extra = {}
            if ver >= 24:
                extra.update(src=1, dst=2, clflags=0x05)
            if ver >= 25:
                extra.update(svm_name=b'p-src\0', dvm_name=b'')
            if ver >= 26:
                extra.update(act=0x0f)
            if ver >= 22:
                extra.update(vlan=7)
            if ver >= 23:
                extra.update(core=2, ns=5000 * (i + 1))
            f = frame(k, k); k += 1
            c.add(pkt2(ver, rt, True, f, rel=hrtime_usec(50 * (i + 1)), pktoffset=0, **extra))
        g()
    # relative time units: sec, msec, usec, nsec
    g = c.group('relative time formats')
    for fmt in (0x00000000, 0x40000000, 0x80000000, 0xC0000000):
        f = frame(k, k); k += 1
        c.add(pkt2(21, 0xD2, False, f, rel=fmt | 3))
    g()
    recs += c.recs
    # a second abstime and a reltime record inside the data, then more
    # packets on a second page
    data = pack_pages([sig20('NetScaler V20 Performance Data')] + recs, 8192)
    write(fn, data)
    return c.n


# ------------------------------------------------------------ V1.0 file
def make_v10():
    fn = 'nstrace-coverage-v10.nstr'
    sigrec = struct.pack('<HHBBH', 0x0101, 64, 0, 0, 0) + b'NetScaler Performance Data'.ljust(56, b'\0')
    recs = [sigrec, struct.pack('<HHII', 0x0107, 12, 5, 1700000000),
            struct.pack('<HHII', 0x0108, 12, 5, 0)]
    c = Counter(fn)
    k = 0
    g = c.group('full records 0x0310-0x0312')
    for rt in (0x0310, 0x0311, 0x0312):
        f = frame(k, k); k += 1
        c.add(None)
        recs.append(struct.pack('<HHII', rt, 12 + len(f), k, hrtime_usec(100 * k)) + f)
    g()
    g = c.group('partial records 0x0314-0x0316')
    for rt in (0x0314, 0x0315, 0x0316):
        f = frame(k, k); k += 1
        c.add(None)
        recs.append(struct.pack('<HHIIHH', rt, 16 + len(f), k, hrtime_usec(100 * k), len(f), 0) + f)
    g()
    write(fn, pack_pages(recs, 8192))
    return c.n


# ------------------------------------------------------------ V3.0 / V3.5
TCPDBG = lambda cwnd, rtt, tsr, abort: u32(cwnd, rtt, tsr) + bytes([abort])
INFO = lambda s: s.encode() + b'\0'


def tcpdbg2(flavour):
    return u32(*range(1000, 1009)) + bytes([flavour])      # 9 words + flavour: 40 -3 = 37 octets


def tcpcc(n):
    return u32(*range(100, 100 + n))


def trcdbg(mode):
    return u32(*range(1, 15)) + u32(mode)                    # 14 words + mode word


def make_v35():
    fn = 'nstrace-coverage-v35.nstr'
    c = Counter(fn)
    k = 0
    recs = [abstime20(1700000000)]

    def nxt():
        nonlocal k
        k += 1
        return k
    g = c.group('v3.5 packets without NS records, all four types')
    for rt in FULLT[35]:
        f = frame(k, k); nxt()
        c.add(pkt35(rt, [], f, vlan=10 + k, core=k, act=[0, 0x1f, 0x00080000 | 1, 0x00040000 | 2][k % 4], app=APP_TCP))
    g()
    g = c.group('v3.5 packets: error codes, apps')
    for ec in (0, 1, 2, 3, 4, 5, 6):
        f = frame(k, k); nxt()
        c.add(pkt35(0xAE, [], f, err=ec, app=ec + 1))
    g()
    g = c.group('v3.5 packet: NS records TCP debug, TCP debug 2 (flavours) with TCP CC')
    f = frame(1, 1); nxt()
    c.add(pkt35(0xAC, [(0x80, TCPDBG(10, 20, 30, 2))], f))
    for flav, n in ((0, 0), (1, 1), (2, 4), (3, 5), (4, 6), (5, 5), (6, 0), (7, 0)):
        f = frame(k, k); nxt()
        c.add(pkt35(0xAC, [(0x8B, tcpdbg2(flav)), (0x8C, tcpcc(max(n, 1)))], f))
    g()
    g = c.group('v3.5 packets: trace debug records (modes and apps)')
    for mode, app in ((1, 0x22), (1, 0x21), (1, 0x01), (4, 0x22), (4, 0x21), (4, 0x01), (5, 0x22), (5, 0x21),
                      (0x10, 2), (2, 2), (8, 2), (0, 2)):
        f = frame(k, k); nxt()
        c.add(pkt35(0xAC, [(0x8E, trcdbg(mode))], f, app=app))
    g()
    g = c.group('v3.5 packets: HTTP info, info text, SSL, MPTCP, VM names, cluster')
    f = frame(1, 1); nxt()
    c.add(pkt35(0xAC, [(0x8D, bytes([5]))], f))
    f = frame(1, 1); nxt()
    c.add(pkt35(0xAC, [(0x83, INFO('trace info text'))], f))
    f = frame(1, 1); nxt()
    c.add(pkt35(0xAC, [(0x87, struct.pack('<I', 0x01020304))], f))
    f = frame(1, 1); nxt()
    c.add(pkt35(0xAC, [(0x8A, bytes([3]))], f))
    f = frame(1, 1); nxt()
    c.add(pkt35(0xAC, [(0x84, bytes([6, 6]) + b'src-vm' + b'dst-vm')], f))
    f = frame(1, 1); nxt()
    c.add(pkt35(0xAC, [(0x84, bytes([0, 0]))], f))
    f = frame(1, 1); nxt()
    c.add(pkt35(0xAC, [(0x85, struct.pack('<HHB', 1, 2, 0x1f))], f))
    f = frame(1, 1); nxt()
    c.add(pkt35(0xAC, [(0x85, struct.pack('<HHB', 3, 4, 0x00))], f))
    g()
    g = c.group('v3.5 packets: every record in one chain; SSL internal; HTTP and NULL next record')
    f = frame(0, 3); nxt()
    c.add(pkt35(0xAC, [(0x80, TCPDBG(1, 2, 3, 0)), (0x8B, tcpdbg2(3)), (0x8C, tcpcc(5)),
                       (0x8E, trcdbg(1)), (0x8D, bytes([1])), (0x83, INFO('all')),
                       (0x87, struct.pack('<I', 7)), (0x8A, bytes([1])),
                       (0x84, bytes([2, 2]) + b'abcd')], f))
    f = frame(0, 3); nxt()
    c.add(pkt35(0xAC, [(0x87, struct.pack('<I', 8)), (0x85, struct.pack('<HHB', 1, 1, 1))], f))
    # HTTP next record type: HTTP data follows the NS header directly
    req = b'GET /x HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
    c.add(pkt35(0xAC, [(0x83, INFO('http'))], req, nextrec=0x02)); nxt()
    # NULL next record type: nothing follows
    c.add(pkt35(0xAC, [(0x83, INFO('null'))], b'', nextrec=0x00)); nxt()
    c.add(pkt35(0xAC, [], b'', nextrec=0x00)); nxt()
    g()
    g = c.group('v3.5 packets: unknown record types (loop limit, last-record marker)')
    for ty in (0x81, 0x82, 0x86, 0x88, 0x89):
        f = frame(k, k); nxt()
        c.add(pkt35(0xAC, [(ty, b'\x01\x02\x03\x04')], f))
    f = frame(0, 3); nxt()
    c.add(pkt35(0xAC, [(0x90, b'\x01\x02'), (0x91, b'\x03'), (0xFF, b'\x04\x05\x06')], f))
    f = frame(0, 3); nxt()
    c.add(pkt35(0xAC, [(0x90, b'a')] * 6, f))   # more unknown records than the loop limit
    g()
    g = c.group('v3.0 records (HEADER_VERSION300) in the same file: names, activity bits, plain')
    for i, rt in enumerate(FULLT[30]):
        f = frame(k, k); nxt()
        c.add(pkt30(rt, f, src=1, dst=2, clflags=0x0f, act=[0, 0x1f, 1, 0x10][i], res3=bytes([0, 9 if i == 1 else 0, 0]),
                    svm_name=b'src%d\0' % i, dvm_name=b'dst\0' if i % 2 else b''))
    g()
    for r in c.recs:
        recs.append(r)
    write(fn, pack3(sig_v35(), recs))
    return c.n


APP_TCP = 2


def sig_v35():
    return sig20('Netscaler V35 Performance Data')


def pack3(sig, recs, pagesize=16384):
    return pack_pages([sig] + recs, pagesize, pad_last=True)


def make_v30():
    fn = 'nstrace-coverage-v30.nstr'
    c = Counter(fn)
    recs = [abstime20(1700000000)]
    for i, rt in enumerate(FULLT[30]):
        f = frame(i, i)
        recs.append(pkt30(rt, f, src=5, dst=6, act=i, svm_name=b'a\0', dvm_name=b''))
        c.n += 1
    note(fn, 1, c.n, 'v3.0 records')
    write(fn, pack3(sig20('Netscaler V30 Performance Data'), recs))
    return c.n


# ------------------------------------------------------------ malformed and reproducers
def make_malformed():
    fn = 'nstrace-coverage-malformed.nstr'
    c = Counter(fn)
    recs = [abstime20(1700000000)]
    f = frame(0, 1)
    # record shorter than its 3 octet header: error expert info
    recs.append(build(LAY[35], 0xAC, dict(dev=1, pktsizeorg=len(f), headerlen=35 + 8, nextrec=0x87, pcb=1, lpcb=2),
                      struct.pack('<HBI', 0, 0x87, 0x11223344) + b'\0' * 3 + f)); c.n += 1
    # the same with reclen 2 and an unknown type
    recs.append(build(LAY[35], 0xAC, dict(dev=1, pktsizeorg=len(f), headerlen=35 + 8, nextrec=0x90, pcb=1, lpcb=2),
                      struct.pack('<HB', 2, 0x01) + b'\0' * 5 + f)); c.n += 1
    # a TCP debug record cut short: its 4 octet fields run past the packet
    recs.append(build(LAY[35], 0xAC, dict(dev=1, pktsizeorg=0, headerlen=35 + 8, nextrec=0x8B, pcb=1, lpcb=2),
                      struct.pack('<HB', 8, 0x01) + b'\0' * 5)); c.n += 1
    # VM names record whose lengths run past the record
    recs.append(build(LAY[35], 0xAC, dict(dev=1, pktsizeorg=0, headerlen=35 + 8, nextrec=0x84, pcb=1, lpcb=2),
                      struct.pack('<HB', 8, 0x01) + bytes([200, 200]) + b'\0' * 3)); c.n += 1
    # unknown record with length 3 (no data); record chain longer than the packet
    recs.append(build(LAY[35], 0xAC, dict(dev=1, pktsizeorg=0, headerlen=35 + 3, nextrec=0x90, pcb=1, lpcb=2),
                      struct.pack('<HB', 3, 0x01))); c.n += 1
    # headerlen beyond the packet
    recs.append(build(LAY[35], 0xAC, dict(dev=1, pktsizeorg=len(f), headerlen=900, nextrec=0x01, pcb=1, lpcb=2), f)); c.n += 1
    # trace debug record too short for its mode word
    recs.append(build(LAY[35], 0xAC, dict(dev=1, pktsizeorg=0, headerlen=35 + 10, nextrec=0x8E, pcb=1, lpcb=2),
                      struct.pack('<HB', 10, 0x01) + b'\0' * 7)); c.n += 1
    # a 3.0 record with VM name lengths longer than the packet
    recs.append(build(LAY[30], 0xA8, dict(dev=1, pktsizeorg=len(f), svm=100, dvm=100, pcb=1, lpcb=2), f)); c.n += 1
    note(fn, 1, c.n, 'malformed v3.5/v3.0 records')
    write(fn, pack3(sig_v35(), recs))
    return c.n


def make_malformed_v20():
    fn = 'nstrace-coverage-malformed-v20.nstr'
    f = frame(0, 1)
    # 2.5 record with VM name lengths longer than the packet
    recs = [abstime20(1700000000),
            build(LAY[25], 0xB0, dict(dev=1, svm=200, dvm=200, pcb=1, lpcb=2, abs=1700000000 * 10**9), f),
            build(LAY[26], 0xA0, dict(dev=1, svm=100, dvm=100, abs=1700000000 * 10**9), f)]
    write(fn, pack_pages([sig20('NetScaler V20 Performance Data')] + recs, 8192))
    return 2


def make_expdu():
    """Exported PDU frames that name the "ns" dissector: the record is not a
    NetScaler trace record, so the dissector must decline it (the fix of
    f4e8041e10, which did not check the encapsulation)."""
    def expdu(data):
        name = b'ns'
        tag = struct.pack('>HH', 12, (len(name) + 3) & ~3) + name.ljust((len(name) + 3) & ~3, b'\0')
        return tag + struct.pack('>HH', 0, 0) + data
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252)
    for i, d in enumerate((frame(0, 0), b'\x01\x02\x03\x04' * 8)):
        p = expdu(d)
        out += struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p
    write('nstrace-coverage-expdu.pcap', out)


def make_reproducers():
    make_expdu()
    # f4e8041e10: record length 0, next record the same type
    data = pkt35_reclen0()
    write('nstrace-reclen0-loop.nstr', data)
    # 63caf4145d: a record that claims more than the file holds
    sigstr = b"Netscaler V35 Performance Data\0"
    sig = struct.pack('<BBB', 0x01, 3 + len(sigstr), 0) + sigstr
    total = 1000
    hdr = bytes([0xAC, (total & 0x7f) | 0x80, total >> 7])
    hdr += b'\0' + struct.pack('<Q', 0) + struct.pack('<II', 1, 2)
    hdr += struct.pack('<HHHH', 0, 0, 0, 35) + b'\0\0' + struct.pack('<I', 0) + b'\x00'
    write('nstrace-trunc-eof.nstr', sig + hdr + b'\x41' * 40)


def pkt35_reclen0():
    rec = struct.pack('<HBI', 0, 0x87, 0x11223344)
    return pack3(sig_v35(), [build(LAY[35], 0xAC, dict(dev=0, abs=1700000000 * 10**9, pcb=1, lpcb=2, pktsizeorg=0,
                                                    headerlen=200, nextrec=0x87), rec + b'\0' * 20)])


def main():
    os.makedirs(OUT, exist_ok=True)
    counts = {'v20': make_v20(), 'v10': make_v10(), 'v35': make_v35(), 'v30': make_v30(),
              'malformed': make_malformed(), 'malformed-v20': make_malformed_v20()}
    make_reproducers()
    if VERBOSE:
        for r in RANGES:
            print(*r)
        print(counts)


main()
