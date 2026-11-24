#!/usr/bin/env python3
# Generates test/captures/rtps_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the synthetic RTPS coverage captures (nothing from a real network;
# addresses are 192.0.2.0/24, 233.252.0.0/24, 2001:db8::/32).
# Usage: mkrtps.py <outdir> [-v]
# Needs a tshark (env TSHARK, default the run/ build) to tell which sweep
# frames (PID and submessage sweeps) decode cleanly: the clean ones go to
# the main capture, the others to the malformed capture.
import os
import sys
import struct
import zlib
from rtpslib import align, csum, exppdu, pcap_write, pcapng_write, tcp_frame, Tshark, udp_frame

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
HERE = os.path.dirname(os.path.abspath(__file__))
TSHARK = os.environ.get('TSHARK', os.environ.get('TSHARK', 'tshark'))
ts = Tshark(TSHARK, os.path.join(HERE, 'cfg'))

main = []      # (link, bytes)
mal = []       # (link, bytes)
marks = []     # (name, first frame, last frame) of the main capture
PREFIX = bytes.fromhex('0a0b0c0d0e0f101112131415')
CACHEVER = '3'     # changes whenever the sweeps change


def split_msg(fr):
    """Splits a UDP frame holding an RTPS message into (prefix, header, [submessages])."""
    if fr[12:14] != b'\x08\x00' or fr[23] != 17:
        return None
    pre, p = fr[:42], fr[42:]
    if p[:4] != b'RTPS':
        return None
    hl = 16 if p[4] == 1 else 20
    subs, o = [], hl
    while o + 4 <= len(p):
        le = p[o + 1] & 1
        n = struct.unpack('<H' if le else '>H', p[o + 2:o + 4])[0]
        if n == 0 and p[0 + 4] >= 2 and p[o] not in (1, 9):
            n = len(p) - o - 4
        subs.append(p[o:o + 4 + n])
        o += 4 + n
    return pre, p[:hl], subs


def rebuild(pre, h, subs):
    p = h + b''.join(subs)
    udp_len = 8 + len(p)
    ip = bytearray(pre[14:34])
    ip[2:4] = struct.pack('>H', 20 + udp_len)
    ip[10:12] = b'\0\0'
    ip[10:12] = struct.pack('>H', csum(bytes(ip)))
    udp = bytearray(pre[34:42])
    udp[4:6] = struct.pack('>H', udp_len)
    return (1, pre[:14] + bytes(ip) + bytes(udp) + p)


def settle(start):
    """Frames of main[start:] that are not clean lose their bad submessages to
    the malformed capture."""
    bad = ts.bad(main)
    out = main[:start]
    for i in range(start, len(main)):
        if (i + 1) not in bad:
            out.append(main[i])
            continue
        sp = split_msg(main[i][1])
        if sp is None or len(sp[2]) < 2:
            mal.append(main[i])
            continue
        pre, h, subs = sp
        singles = [rebuild(pre, h, [x]) for x in subs]
        ok = ts.good(singles)
        good = [x for x, g in zip(subs, ok) if g]
        for x, g, f in zip(subs, ok, singles):
            if not g:
                mal.append(f)
        if good:
            comb = rebuild(pre, h, good)
            if ts.good([comb])[0]:
                out.append(comb)
            else:
                out.extend(f for f, g in zip(singles, ok) if g)
    main[:] = out


def mark(name, start, check=True):
    if check:
        m0 = len(mal)
        settle(start)
        if VERBOSE and len(mal) > m0:
            print('   %s: %d frames moved to the malformed capture (malformed frames %d-%d)' % (name, len(mal) - m0, m0 + 1, len(mal)))
    marks.append((name, start + 1, len(main)))


# ---------------------------------------------------------------- builders
def hdr(ver=(2, 3), vendor=0x0101, prefix=PREFIX):
    if ver[0] == 1:
        prefix = prefix[:8]       # RTPS 1.x: 8 octet guid prefix
    return b'RTPS' + bytes(ver) + struct.pack('>H', vendor) + prefix


def sm(sid, flags, body, le=True):
    """A submessage; the E flag is set from le."""
    flags = (flags | 1) if le else (flags & ~1)
    return struct.pack('<BBH' if le else '>BBH', sid, flags, len(body)) + body


def eid(v):
    return struct.pack('>I', v)


def sn(n, le=True):
    return struct.pack('<iI' if le else '>iI', n >> 32, n & 0xffffffff)


def U(fmt, *a):
    return struct.pack(fmt, *a)


def put(frames, data, **kw):
    frames.append((1, udp_frame(data, **kw)))


def pl_param(pid, data, le=True):
    data = align(data)
    return struct.pack('<HH' if le else '>HH', pid, len(data)) + data


def sentinel(le=True):
    return struct.pack('<HH' if le else '>HH', 1, 0)


def cstr(s, le=True):
    raw = s.encode() + b'\0'
    return align(struct.pack('<I' if le else '>I', len(raw)) + raw)


def locator(kind, port, addr, le=True):
    return struct.pack('<ii' if le else '>ii', kind, port) + addr


def v4addr(a):
    return b'\0' * 12 + bytes(int(x) for x in a.split('.'))


def guid(prefix=PREFIX, ent=0x000003c2):
    return prefix + eid(ent)


def encap(kind, opts=0):
    return struct.pack('>HH', kind, opts)


# ---------------------------------------------------------------- shapes
def shapes(le):
    e = '<' if le else '>'
    u32 = lambda *v: struct.pack(e + 'I' * len(v), *v)
    s = []
    s.append(('str', cstr('Alpha', le)))
    s.append(('str2', cstr('', le)))
    s.append(('strs2', u32(2) + cstr('ab', le) + cstr('cde', le)))
    s.append(('strs1', u32(1) + cstr('ab', le)))
    s.append(('time', struct.pack(e + 'iI', 10, 0x80000000)))
    s.append(('u32seq', u32(3, 1, 2, 3)))
    s.append(('u32seq1', u32(1, 7)))
    s.append(('loc4', locator(1, 7400, v4addr('192.0.2.7'), le)))
    s.append(('loc6', locator(2, 7400, bytes(range(16)), le)))
    s.append(('locwan', locator(0x01000000, 7400, v4addr('192.0.2.7'), le)))
    s.append(('loc1', u32(1) + locator(1, 7400, v4addr('192.0.2.7'), le)))
    s.append(('locx', locator(1, 7400, v4addr('192.0.2.7'), le) + u32(0)))
    s.append(('guid', guid()))
    s.append(('guidsn', guid() + sn(5, le)))
    s.append(('guidstr', guid() + cstr('abc', le)))
    s.append(('ip4', bytes((192, 0, 2, 9))))
    s.append(('prop1', u32(1) + cstr('name', le) + cstr('value', le)))
    s.append(('prop2', u32(2) + cstr('n1', le) + cstr('v1', le) + cstr('n2', le) + cstr('v2', le)))
    s.append(('cfp', cstr('cft', le) + cstr('topic', le) + cstr('DDSSQL', le) + cstr('x > 1', le) + u32(1) + cstr('1', le)))
    s.append(('cfp0', cstr('cft', le) + cstr('topic', le) + cstr('DDSSQL', le) + cstr('x > 1', le) + u32(0)))
    s.append(('cfi0', u32(0, 0)))
    s.append(('cfi1', u32(1, 3, 1) + u32(1, 2, 3, 4)))
    s.append(('octs', u32(4) + b'abcd'))
    s.append(('bytes', b'\x01\x02\x03\x04\x05\x06\x07\x08'))
    s.append(('seqloc2', u32(2) + locator(1, 7400, v4addr('192.0.2.7'), le) + locator(1, 7401, v4addr('192.0.2.8'), le)))
    s.append(('ti1', u32(1) + u32(2, 3) + b'\0' * 8))
    for n in (4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 64):
        s.append(('z%d' % n, b'\0' * n))
    return s


# ----------------------------------------------------------------- sweeps
PIDS = sorted(set(list(range(0, 0x90)) + list(range(0x1000, 0x1014)) + list(range(0x4010, 0x4018)) +
                  list(range(0x8000, 0x802c)) + [0x9000, 0xc000]))
PIDS = [p for p in PIDS if p not in (1, 0x3f01, 0x3f02)]


def rtps_data_disc(params, le, ver=(2, 3), vendor=0x0101, writer=0x000100c2, inline=False, seq=1):
    """RTPS_DATA submessage: discovery payload (D) or inline QoS (Q); a DATA submessage for RTPS 1.x."""
    pend = sentinel(le)
    if ver[0] == 1:
        body = eid(0) + eid(writer) + eid(0x00000102) + sn(seq, le) + params + pend
        return hdr(ver, vendor) + sm(0x02, 0x10 if inline else 0x02, body, le)
    if inline:
        body = struct.pack('<HH', 0, 16) if le else struct.pack('>HH', 0, 16)
        body += eid(0) + eid(writer) + sn(seq, le) + params + pend
        return hdr(ver, vendor) + sm(0x15, 0x02, body, le)
    body = struct.pack('<HH', 0, 16) if le else struct.pack('>HH', 0, 16)
    body += eid(0) + eid(writer) + sn(seq, le)
    body += encap(0x0003 if le else 0x0002) + params + pend
    return hdr(ver, vendor) + sm(0x15, 0x04, body, le)


def pid_sweep(label, le, vendor, ver, inline, maxkeep=3, writer=0x000100c2):
    """Returns clean (one-parameter) frames' parameter bytes, per pid."""
    sh = shapes(le)
    cands = []
    for pid in PIDS:
        for name, data in sh:
            cands.append((pid, name, pl_param(pid, data, le)))
    frames = [(1, udp_frame(rtps_data_disc(c[2], le, ver, vendor, writer, inline))) for c in cands]
    ok = ts.good([f for _, f in frames], strict=True)
    raw = set(int(x) for x in ts.run([f for _, f in frames], flt='rtps.parameter_data'))
    keep = {}
    rawkeep = {}
    bad = []
    for i, (c, g, f) in enumerate(zip(cands, ok, frames)):
        if g:
            if (i + 1) in raw:
                rawkeep.setdefault(c[0], c[2])
            else:
                keep.setdefault(c[0], [])
                if len(keep[c[0]]) < maxkeep:
                    keep[c[0]].append(c[2])
        else:
            bad.append(f)
    for pid, p in rawkeep.items():
        if pid not in keep:
            keep[pid] = [p]
    return keep, bad


def packed(label, keep, le, vendor, ver, inline, writer=0x000100c2, limit=1200):
    """Packs the parameters in as few frames as possible; falls back to
    one frame per parameter when a packed frame is not clean."""
    items = [p for pid in sorted(keep) for p in keep[pid]]
    groups, cur, n = [], [], 0
    for it in items:
        if cur and n + len(it) > limit:
            groups.append(cur)
            cur, n = [], 0
        cur.append(it)
        n += len(it)
    if cur:
        groups.append(cur)
    frames = [(1, udp_frame(rtps_data_disc(b''.join(g), le, ver, vendor, writer, inline))) for g in groups]
    ok = ts.good([f for _, f in frames], strict=True)
    # every parameter must show up (a misparsed frame can still end cleanly)
    cnt = {}
    for fnum, vals in ts.table([f for _, f in frames], 'rtps.param.length'):
        cnt[fnum] = len(vals.split(',')) if vals else 0
    ok = [g_ok and cnt.get(i + 1, 0) == len(grp) for i, (g_ok, grp) in enumerate(zip(ok, groups))]
    out_ok, out_bad = [], []
    for g, f, good in zip(groups, frames, ok):
        if good:
            out_ok.append(f)
        else:
            for it in g:
                one = (1, udp_frame(rtps_data_disc(it, le, ver, vendor, writer, inline)))
                out_ok.append(one)
    return out_ok


def cached(key, fn):
    """Runs fn (which appends to main/mal/marks) or replays its cached result: the
    sweeps take minutes and a piece is cheap to redo, so a killed run restarts there.
    The cache is kept in the temporary directory; --resweep ignores it."""
    import pickle
    import tempfile
    cache = os.path.join(tempfile.gettempdir(), 'rtps-sweep-v%s-%s.cache' % (CACHEVER, key))
    if os.path.exists(cache) and '--resweep' not in sys.argv:
        m, l, mk = pickle.load(open(cache, 'rb'))
        off = len(main)
        main.extend(m)
        mal.extend(l)
        marks.extend((n, a + off, b + off) for n, a, b in mk)
        return
    m0, l0, k0 = len(main), len(mal), len(marks)
    fn()
    pickle.dump((main[m0:], mal[l0:], [(n, a - m0, b - m0) for n, a, b in marks[k0:]]), open(cache + '.tmp', 'wb'))
    os.replace(cache + '.tmp', cache)


def build_pid_sweeps():
    cfgs = [
        ('RTI LE discovery', True, 0x0101, (2, 3), False, 3),
        ('RTI BE discovery', False, 0x0101, (2, 3), False, 1),
        ('RTI LE inline QoS', True, 0x0101, (2, 3), True, 2),
        ('RTI Micro LE', True, 0x010a, (2, 3), False, 1),
        ('TOC LE', True, 0x0106, (2, 3), False, 1),
        ('ADL LE', True, 0x0102, (2, 3), False, 1),
        ('other vendor LE', True, 0x010f, (2, 3), False, 1),
        ('RTPS 1.2 LE', True, 0x0101, (1, 2), False, 2),
        ('RTPS 1.2 inline QoS', True, 0x0101, (1, 2), True, 1),
        ('RTPS 1.2 BE', False, 0x0101, (1, 2), False, 1),
    ]
    def one(label, le, vendor, ver, inline, keepn):
        start = len(main)
        keep, bad = pid_sweep(label, le, vendor, ver, inline, keepn)
        main.extend(packed(label, keep, le, vendor, ver, inline))
        mal.extend(bad[::3])
        mark('PID sweep: ' + label, start, False)
    for i, (label, le, vendor, ver, inline, keepn) in enumerate(cfgs):
        cached('pid%d' % i, lambda: one(label, le, vendor, ver, inline, keepn))


# ----------------------------------------------------------- submessage sweep
SUBIDS = list(range(0, 0x20)) + list(range(0x30, 0x35)) + [0x80, 0x81, 0x82, 0x83, 0xc0]


def build_submsg_sweeps():
    def one(label, le, vendor, ver, flagset):
        start = len(main)
        cands = []
        for sid in SUBIDS:
            for flags in flagset:
                for n in (4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 96):
                    cands.append((sid, flags, n))
        frames = [(1, udp_frame(hdr(ver, vendor) + sm(sid, flags, b'\0' * n, le))) for sid, flags, n in cands]
        ok = ts.good([f for _, f in frames], strict=True)
        best = {}
        for c, g in zip(cands, ok):
            if g:
                best[(c[0], c[1])] = c[2]
        items = [sm(k[0], k[1], b'\0' * n, le) for k, n in sorted(best.items())]
        groups = [items[i:i + 8] for i in range(0, len(items), 8)]
        fr = [(1, udp_frame(hdr(ver, vendor) + b''.join(g))) for g in groups]
        ok = ts.good([f for _, f in fr], strict=True)
        for g, f, good in zip(groups, fr, ok):
            if good:
                main.append(f)
            else:
                for it in g:
                    one = (1, udp_frame(hdr(ver, vendor) + it))
                    main.append(one)
        mark('Submessage sweep: ' + label, start, False)
    for i, (label, le, vendor, ver, flagset) in enumerate((
            ('RTPS 2.3 RTI LE', True, 0x0101, (2, 3), (0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x20, 0x30, 0x40, 0x80, 0xfe)),
            ('RTPS 2.3 RTI BE', False, 0x0101, (2, 3), (0x00, 0x02, 0x04, 0x08, 0x0e)),
            ('RTPS 2.3 other vendor', True, 0x010f, (2, 3), (0x00, 0x02, 0x04, 0x0e)),
            ('RTPS 1.2', True, 0x0101, (1, 2), (0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0e, 0x10, 0x1e, 0x20, 0x3e)))):
        cached('sub%d' % i, lambda: one(label, le, vendor, ver, flagset))



# --------------------------------------------------------------- hand-built
def msg(*sms, ver=(2, 3), vendor=0x0101, prefix=PREFIX):
    return hdr(ver, vendor, prefix) + b''.join(sms)


def add(data, **kw):
    main.append((1, udp_frame(data, **kw)))


def addmal(data, **kw):
    mal.append((1, udp_frame(data, **kw)))


def info_ts(le=True, t=(1700000000, 0x40000000)):
    return sm(0x09, 0, struct.pack('<iI' if le else '>iI', *t), le)


ENTITY_IDS = [0x00000000, 0x000001c1, 0x000002c2, 0x000002c7, 0x000003c2, 0x000003c7, 0x000004c2, 0x000004c7,
              0x000100c2, 0x000100c7, 0x000200c2, 0x000200c7, 0x000300c3, 0x000300c4, 0x000301c3, 0x000301c4,
              0xff0300c3, 0xff0300c4, 0xff0301c3, 0xff0301c4, 0x00010082, 0x00010087, 0x00010182, 0x00010187,
              0xff010182, 0xff010187, 0x000201c3, 0x000201c4, 0xff0003c2, 0xff0003c7, 0xff0004c2, 0xff0004c7,
              0xff0200c2, 0xff0200c7, 0xff0202c3, 0xff0202c4, 0xff0101c2, 0xff0101c7, 0x00020082, 0x00020087,
              0x00020182, 0x00020187, 0x000001c2, 0x000001c7, 0x000005c2, 0x000005c7, 0x000006c2, 0x000006c7,
              0x000007c2, 0x000007c7, 0x000008c1, 0x000008c2, 0x000008c7,
              0x000001cb, 0x000001cc, 0x000001cd, 0x000001ce, 0x00000188, 0x00000189, 0x0000018a, 0x0000018b,
              0x0000018c, 0x0000018d, 0x0000018e, 0x0000014b, 0x0000014c, 0x0000014d, 0x0000014e, 0x0000010b,
              0x0000010c, 0x0000010d, 0x0000010e, 0x00000100, 0x00000101, 0x00000102, 0x00000103, 0x00000104,
              0x00000107, 0x00000182, 0x00000183, 0x00000184, 0x00000187, 0x000001c3, 0x000001c4, 0x000001c7,
              0x12345601, 0x123456ff, 0x00000005]


def bitmap(base, bits, le=True, words=None):
    e = '<' if le else '>'
    out = sn(base, le) + struct.pack(e + 'I', bits)
    n = (bits + 31) // 32
    words = words if words is not None else [0x80000000 >> 0] * n
    for w in words[:n]:
        out += struct.pack(e + 'I', w)
    return out


def heartbeat(w, r=0, first=1, last=5, count=1, le=True, flags=0):
    return sm(0x07, flags, eid(r) + eid(w) + sn(first, le) + sn(last, le) + struct.pack('<I' if le else '>I', count), le)


def acknack(w, r=0, base=1, bits=0, words=None, count=1, le=True, flags=0, sid=0x06):
    return sm(sid, flags, eid(r) + eid(w) + bitmap(base, bits, le, words) + struct.pack('<I' if le else '>I', count), le)


def gap(w, r=0, start=1, base=3, bits=0, words=None, le=True):
    return sm(0x08, 0, eid(r) + eid(w) + sn(start, le) + bitmap(base, bits, le, words), le)


def data_std(w, r, seq, payload=b'', q=b'', flags=0x04, le=True, sid=0x15, extra=b'', octq=16):
    e = '<' if le else '>'
    body = struct.pack(e + 'HH', 0, octq) + eid(r) + eid(w) + sn(seq, le) + extra + q + payload
    return sm(sid, flags, body, le)


def basic():
    # --- vendors, versions
    start = len(main)
    for v in (0x0000, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0109, 0x010a, 0x010b,
              0x010c, 0x010d, 0x010e, 0x010f, 0x0110, 0x0111, 0x0112, 0x0113, 0x0114, 0x011c, 0x0999):
        add(msg(info_ts(), vendor=v), dport=7400 + 250 * (v & 7) + 1)
    for ver in ((2, 0), (2, 1), (2, 2), (2, 3), (2, 4), (2, 5), (1, 0), (1, 1), (1, 2)):
        add(msg(info_ts(), ver=ver))
    mark('Vendors and protocol versions', start)
    # --- port mapping: domain / participant / nature
    start = len(main)
    for dp in (7400, 7401, 7410, 7411, 7412, 7413, 7650, 7651, 7660, 7661, 7399, 6500, 65400, 65401, 65410, 65535, 7424, 7425):
        add(msg(info_ts()), dport=dp)
    for dp in (7400, 7401, 7410, 7411, 7412, 7500, 7501, 8400, 6500):
        add(msg(info_ts(), ver=(1, 2)), dport=dp)
    mark('Default port mapping (RTPS 2.x and 1.x)', start)
    # --- PING, RTPX, TCP
    start = len(main)
    add(b'RTPS\x02\x03\x01\x01' + b'NDDSPING' + bytes(range(12)))
    add(b'RTPX\x02\x03\x01\x01' + PREFIX + info_ts(), dport=7400)
    add(b'RTPX\x02\x03\x01\x01' + PREFIX + info_ts(), dport=7650)
    main.append((1, tcp_frame(struct.pack('>I', 20 + 12) + msg(info_ts()), sport=7412, dport=7413)))
    main.append((1, tcp_frame(struct.pack('>I', 20 + 12) + msg(info_ts(), ver=(1, 2)), sport=7412, dport=7413, seq=2000)))
    mark('PING, RTPX, RTPS over TCP', start)
    # --- small submessages
    start = len(main)
    add(msg(sm(0x01, 0, b'\0' * 8), info_ts(), sm(0x01, 0, b'\0' * 4)))
    add(msg(info_ts(), info_ts(False), sm(0x09, 0x02, b''), sm(0x09, 0x02, b'', False)))
    srcver = lambda v, vend: sm(0x0c, 0, b'\0' * 4 + bytes(v) + struct.pack('>H', vend) + PREFIX)
    add(msg(srcver((2, 3), 0x0101), srcver((1, 1), 0x0101), srcver((2, 1), 0x0102)))
    add(msg(srcver((2, 3), 0x0101)))
    add(msg(sm(0x0d, 0, struct.pack('>I', 0xc0000201) + struct.pack('<I', 7411)),
            sm(0x0d, 0x02, struct.pack('>I', 0xc0000201) + struct.pack('<I', 7411) + struct.pack('>I', 0xe9fc0001) + struct.pack('<I', 7400))))
    add(msg(sm(0x0e, 0, PREFIX), sm(0x0e, 0, PREFIX, False)))
    loc = lambda k, p, a: locator(k, p, a)
    add(msg(sm(0x0f, 0, U('<I', 2) + loc(1, 7411, v4addr('192.0.2.2')) + loc(2, 7411, bytes(range(16)))),
            sm(0x0f, 0x02, U('<I', 0))))
    mark('PAD, INFO_*', start)
    # --- entity ids through heartbeats
    start = len(main)
    hbs = [heartbeat(w, r=0x000003c7 if (w & 1) else 0) for w in ENTITY_IDS]
    for i in range(0, len(hbs), 12):
        add(msg(*hbs[i:i + 12]))
    mark('HEARTBEAT with every well-known and many other entity ids', start)
    # --- heartbeat / acknack / gap
    start = len(main)
    W = 0x00000103
    add(msg(heartbeat(W, 0x00000104, 1, 10, 1), heartbeat(W, 0x00000104, 1, 10, 2, flags=0x02),
            heartbeat(W, 0x00000104, 5, 4, 3, flags=0x06), heartbeat(W, 0x00000104, 1, 10, 4, le=False)))
    add(msg(heartbeat(W, 0x00000104, 1, 10, 1), ver=(2, 0)))
    add(msg(sm(0x07, 0, eid(4) + eid(W) + sn(1) + sn(3)), ver=(1, 0)))
    add(msg(acknack(W, 0x00000104, 0, 0), acknack(W, 0x00000104, 7, 0, count=2), acknack(W, 0x00000104, 7, 5, [0x58000000], count=3),
            acknack(W, 0x00000104, 7, 40, [0xffffffff, 0xff000000], count=4, flags=0x02),
            acknack(W, 0x00000104, 7, 5, [0x58000000], count=5, le=False)))
    add(msg(sm(0x06, 0, eid(4) + eid(W) + bitmap(7, 0) + U('<I', 6))))
    addmal(msg(sm(0x06, 0, eid(4) + eid(W) + bitmap(7, 0)), sm(0x06, 0, eid(4) + eid(W) + bitmap(7, 0) + b'\0' * 8)))
    add(msg(gap(W, 0x00000104, 5, 8, 0), gap(W, 0x00000104, 5, 8, 3, [0xa0000000]), gap(W, 0x00000104, 5, 8, 33, [0xffffffff, 0x80000000], le=False)))
    mark('HEARTBEAT, ACKNACK, GAP', start)



# ------------------------------------------------------ DATA and fragments
UW = 0x00000102          # a user writer (with key)
UR = 0x00000107
SPDP = 0x000100c2


def spdp_params(le=True):
    e = '<' if le else '>'
    p = pl_param(0x15, bytes((2, 3, 0, 0)), le) + pl_param(0x16, bytes((1, 1, 0, 0)), le)
    p += pl_param(0x50, guid(ent=0x000001c1), le)
    p += pl_param(0x02, struct.pack(e + 'iI', 100, 0), le)
    p += pl_param(0x32, locator(1, 7410, v4addr('192.0.2.1'), le), le)
    p += pl_param(0x31, locator(1, 7411, v4addr('192.0.2.1'), le), le)
    p += pl_param(0x33, locator(1, 7400, v4addr('233.252.0.1'), le), le)
    p += pl_param(0x58, struct.pack(e + 'I', 0x3f), le)
    p += pl_param(0x62, cstr('Participant A', le), le)
    p += pl_param(0x0f, struct.pack(e + 'i', 0), le)
    return p


def v2data(w, r, seq, payload=b'', q=b'', flags=0x04, le=True, h=None, status=None, suffix=0x00000102, sid=0x02):
    body = eid(r) + eid(w) + sn(seq, le)
    if h is not None:
        body += h
    body += eid(suffix)
    if status is not None:
        body += struct.pack('<I' if le else '>I', status)
    body += q + payload
    return sm(sid, flags, body, le)


def sdata(kind, body=b'', opts=0):
    return struct.pack('>HH', kind, opts) + body


def zlib_sample(raw, kind=0x0001, pad=0, ext=False, bad=False):
    comp = zlib.compress(raw)
    if bad:
        comp = b'\x78\x9c' + b'\xff' * 12
    comp += b'\0' * pad
    opts = 0x04 | pad
    if ext:
        opts = 0x1c | pad
    out = struct.pack('>HH', kind, opts) + struct.pack('>I', len(raw))
    if ext:
        out += struct.pack('>I', 0x01020304)
    return out + comp


def data_forms():
    start = len(main)
    # discovery data from builtin writers, both endiannesses, RTPS_DATA and DATA
    sp = spdp_params(True) + sentinel(True)
    add(msg(info_ts(), data_std(SPDP, 0, 1, sdata(3) + sp, flags=0x05, sid=0x15), info_ts()), dport=7400)
    add(msg(v2data(SPDP, 0, 2, sdata(3) + sp, flags=0x04), v2data(SPDP, 0, 3, sdata(3) + sp, flags=0x06, q=sentinel(True))), dport=7400)
    spb = spdp_params(False) + sentinel(False)
    add(msg(data_std(SPDP, 0, 4, sdata(2) + spb, flags=0x04, sid=0x15, le=False), v2data(SPDP, 0, 5, sdata(2) + spb, flags=0x04, le=False)), dport=7400)
    # DATA flags: H, I, K, Q with serialized key
    h = PREFIX
    add(msg(v2data(UW, UR, 6, sdata(1, b'\x01\x02\x03\x04'), flags=0x04 | 0x08, h=h),
            v2data(UW, UR, 7, sdata(1, b'\x01\x02\x03\x04'), flags=0x04 | 0x10, status=1),
            v2data(UW, UR, 8, sdata(1, b'\x01\x02\x03\x04'), flags=0x04 | 0x02 | 0x10, q=pl_param(0x71, struct.pack('>I', 3)) + sentinel(), status=0)))
    add(msg(sm(0x03, 0x04, eid(UR) + eid(UW) + sn(9) + sdata(1, b'abcd')),
            sm(0x03, 0x06, eid(UR) + eid(UW) + sn(10) + pl_param(0x71, struct.pack('>I', 1)) + sentinel() + sdata(1, b'abcd')),
            sm(0x03, 0x02, eid(UR) + eid(UW) + sn(11) + sentinel())))
    add(msg(sm(0x03, 0x00, eid(UR) + eid(UW) + sn(9) + b'abcd'), ver=(1, 2)))
    # RTPS_DATA with Q, K, D variants and every encapsulation kind
    for kind in (0x0000, 0x0001, 0x0002, 0x0003, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0xc000, 0xc001, 0x1234):
        pay = sdata(kind, b'\x01\x02\x03\x04\x05\x06\x07\x08' if kind not in (2, 3, 10, 11) else pl_param(0x2c, b'abcd', kind & 1 == 1) + sentinel(kind & 1 == 1))
        add(msg(data_std(UW, UR, 20 + kind % 100, pay, flags=0x04, le=kind & 1 == 1 or kind == 0)))
    add(msg(data_std(UW, UR, 40, sdata(1, b'key!'), flags=0x08),
            data_std(UW, UR, 41, sdata(1, b'data'), flags=0x06, q=pl_param(0x71, struct.pack('>I', 0)) + sentinel()),
            data_std(UW, UR, 42, b'', flags=0x02, q=pl_param(0x71, struct.pack('>I', 2)) + sentinel(),),
            data_std(UW, UR, 43, b'', flags=0x00)))
    # RTPS_DATA_SESSION
    add(msg(data_std(UW, UR, 50, sdata(1, b'abcd'), flags=0x04, sid=0x14, extra=sn(7)),
            data_std(UW, UR, 51, b'', flags=0x02, sid=0x14, extra=sn(8), q=pl_param(0x71, struct.pack('>I', 1)) + sentinel()),
            data_std(UW, UR, 52, sdata(1, b'wxyz'), flags=0x04, sid=0x14, extra=sn(9))))
    mark('DATA, NOKEY_DATA, RTPS_DATA, RTPS_DATA_SESSION; encapsulations', start)
    # compressed samples
    start = len(main)
    for raw, k in ((b'\x01\x02\x03\x04' * 20, 0x0001), (spdp_params(True) + sentinel(True), 0x0003), (b'\x01\x02\x03\x04' * 20, 0x0000)):
        add(msg(data_std(UW if k != 3 else SPDP, UR, 60 + k, zlib_sample(raw, k), flags=0x04)))
        add(msg(data_std(UW, UR, 70 + k, zlib_sample(raw, k, pad=2), flags=0x04)))
    add(msg(data_std(UW, UR, 80, zlib_sample(b'\x01\x02\x03\x04' * 20, 1, ext=True), flags=0x04)))
    # BZIP2 / LZ4 are not decompressed
    add(msg(data_std(UW, UR, 81, struct.pack('>HHI', 1, 0x08, 100) + b'BZh9' + b'\0' * 12, flags=0x04),
            data_std(UW, UR, 82, struct.pack('>HHI', 1, 0x10, 100) + b'\x04\x22\x4d\x18' + b'\0' * 12, flags=0x04)))
    mark('Compressed samples (zlib; bzip2 and lz4 are not decompressed)', start)
    addmal(msg(data_std(UW, UR, 83, zlib_sample(b'\x01\x02\x03\x04' * 20, 1, bad=True), flags=0x04)))
    # DATA_FRAG family, reassembly of a discovery sample
    start = len(main)
    full = sdata(3) + spdp_params(True) + sentinel(True)
    F = 64
    nfr = (len(full) + F - 1) // F
    wr = 0x000100c2
    for i in range(nfr):
        chunk = full[i * F:(i + 1) * F]
        body = struct.pack('<HH', 0, 28) + eid(0) + eid(wr) + sn(90) + struct.pack('<IHHI', i + 1, 1, F, len(full)) + chunk
        add(msg(sm(0x16, 0x00, body)), dport=7400)
    # two fragments in one submessage and the rest in a second one
    body = struct.pack('<HH', 0, 28) + eid(0) + eid(wr) + sn(91) + struct.pack('<IHHI', 1, 2, F, len(full)) + full[:2 * F]
    add(msg(sm(0x16, 0, body)))
    body = struct.pack('<HH', 0, 28) + eid(0) + eid(wr) + sn(91) + struct.pack('<IHHI', 3, nfr - 2, F, len(full)) + full[2 * F:]
    add(msg(sm(0x16, 0, body)))
    # session and RTI session fragments, with inline QoS and key flag
    # (the fragments of different samples would be reassembled together: the reassembly is keyed by the
    # addresses only, so every sample that stays incomplete gets its own source address)
    for i, sid in enumerate((0x16, 0x81)):
        body = struct.pack('<HH', 0, 28) + eid(0) + eid(UW) + sn(92) + (sn(5) if sid == 0x81 else b'') + struct.pack('<IHHI', 1, 1, 16, 40) + b'\x00\x01\x00\x00' + b'x' * 12
        add(msg(sm(sid, 0, body)), src='192.0.2.%d' % (30 + i))
    body = struct.pack('<HH', 0, 28) + eid(0) + eid(UW) + sn(93) + struct.pack('<IHHI', 2, 1, 16, 40) + pl_param(0x71, struct.pack('>I', 1)) + sentinel() + b'y' * 16
    add(msg(sm(0x16, 0x02, body)), src='192.0.2.32')
    body = struct.pack('<HH', 0, 28) + eid(0) + eid(UW) + sn(94) + struct.pack('<IHHI', 1, 1, 16, 16) + b'k' * 16
    add(msg(sm(0x16, 0x04, body)), src='192.0.2.33')
    # DATA_FRAG (0x10), NOKEY_DATA_FRAG (0x11), NACK_FRAG, HEARTBEAT_FRAG
    dfr = lambda q, h, payload: eid(0) + eid(UW) + sn(95) + (PREFIX if h else b'') + eid(UW) + struct.pack('<IHHI', 1, 1, 8, 8) + q + payload
    add(msg(sm(0x10, 0x04, dfr(b'', False, b'12345678')), sm(0x10, 0x04, dfr(b'', False, sdata(1, b'abcd'))),
            sm(0x10, 0x02 | 0x04, dfr(pl_param(0x71, struct.pack('>I', 1)) + sentinel(), False, b'12345678')),
            sm(0x10, 0x00, dfr(b'', False, b'')), sm(0x10, 0x04, dfr(b'', False, b'12345678'), False)))
    nk = lambda q, payload: eid(0) + eid(UW) + sn(96) + struct.pack('<IHH', 1, 1, 8) + q + payload
    add(msg(sm(0x11, 0x04, nk(b'', b'12345678')), sm(0x11, 0x06, nk(sentinel(), b'12345678')), sm(0x11, 0x00, nk(b'', b''))))
    nf = lambda base, bits, words, count, le=True: eid(UR) + eid(UW) + sn(97, le) + struct.pack('<II' if le else '>II', base, bits) + b''.join(struct.pack('<I' if le else '>I', w) for w in words) + struct.pack('<I' if le else '>I', count)
    add(msg(sm(0x12, 0, nf(1, 3, [0xe0000000], 1)), sm(0x12, 0, nf(1, 40, [0xffffffff, 0xff000000], 2)),
            sm(0x12, 0, nf(1, 0, [], 3)), sm(0x12, 0, nf(1, 3, [0xe0000000], 4, False), False)))
    hf = lambda le=True: eid(UR) + eid(UW) + sn(98, le) + struct.pack('<II' if le else '>II', 4, 1)
    add(msg(sm(0x13, 0, hf()), sm(0x13, 0, hf(False), False)))
    mark('DATA_FRAG family: reassembly, NACK_FRAG, HEARTBEAT_FRAG', start)
    # AckNack/Heartbeat batch, session, virtual; APP_ACK
    start = len(main)
    hb = lambda le=True: eid(UR) + eid(UW) + sn(1, le) + sn(9, le) + sn(11, le) + sn(19, le) + struct.pack('<I' if le else '>I', 3)
    add(msg(sm(0x19, 0, hb()), sm(0x1b, 0, hb()), sm(0x19, 0, hb(False), False)))
    add(msg(sm(0x17, 0, eid(UR) + eid(UW) + bitmap(3, 4, True, [0xa0000000]) + U('<I', 7)),
            sm(0x1a, 0x02, eid(UR) + eid(UW) + bitmap(3, 0, True) + U('<I', 8))))
    vg = guid(ent=0x00000302)
    sn2 = lambda *a: b''.join(sn(x) for x in a)
    base = eid(UR) + eid(UW)
    add(msg(sm(0x1e, 0x00, base + vg + U('<I', 1) + sn2(1, 5, 1, 5) + U('<I', 1)),
            sm(0x1e, 0x02, base + U('<I', 1) + vg + sn2(1, 5, 1, 5) + U('<I', 2)),
            sm(0x1e, 0x04, base + vg + U('<I', 2) + eid(UW) + U('<I', 1) + sn2(1, 5, 1, 5) + eid(UW + 1) + U('<I', 0) + U('<I', 3)),
            sm(0x1e, 0x08, base + U('<I', 4)),
            sm(0x1e, 0x0c, base + U('<I', 2) + eid(UW) + eid(UW + 1) + U('<I', 5)),
            sm(0x1e, 0x06, base + U('<I', 2) + eid(UW) + U('<I', 1) + vg + sn2(1, 5, 1, 5) + eid(UW + 1) + U('<I', 0) + U('<I', 6))))
    iv = lambda payload: sn(1) + sn(3) + struct.pack('<HH', 0, len(payload)) + payload
    app = lambda n: sm(0x1c, 0, eid(UR) + eid(UW) + U('<i', n) + b''.join(vg + struct.pack('<HH', 1, 0) + sn(1) + sn(3) + struct.pack('<HH', 1, 0) + U('<I', 1) for _ in range(n)) if n else b'')
    add(msg(sm(0x1c, 0, eid(UR) + eid(UW) + U('<i', 1) + vg + struct.pack('<HH', 1, 0) + iv(b'') + U('<I', 1)),
            sm(0x1c, 0, eid(UR) + eid(UW) + U('<i', 1) + vg + struct.pack('<HH', 2, 0) + iv(b'abcd') + iv(b'') + U('<I', 2)),
            sm(0x1d, 0, eid(UR) + eid(UW) + U('<I', 1) + vg + U('<I', 3)),
            sm(0x1d, 0, eid(UR) + eid(UW) + U('<I', 2) + vg + U('<I', 3) + vg + U('<I', 4))))
    mark('HEARTBEAT_BATCH/SESSION/VIRTUAL, ACKNACK_BATCH/SESSION, APP_ACK, APP_ACK_CONF', start)
    # secure submessage framing (no keys), CRC, UDP WAN binding ping, header extension
    start = len(main)
    kinds = (0, 1, 2, 3, 4)
    pre = lambda flags, n=28: sm(0x31, flags, b'\x00\x00\x01' + b'\x04' + b'\x00\x00\x00\x02' + b'\x00\x00\x00\x07' + b'\xaa' * (n - 12))
    add(msg(pre(0x00), pre(0x02), pre(0x04), pre(0x06), sm(0x30, 0, U('>I', 16) + b'\x11' * 16),
            sm(0x32, 0, b'\x22' * 16), sm(0x32, 0, b'\x22' * 16 + U('>I', 0)),
            sm(0x32, 0, b'\x22' * 16 + U('>I', 2) + (b'\x33' * 16 + b'\0\0\0\1') * 2)))
    add(msg(sm(0x33, 0, b'\x00\x00\x01\x04\x00\x00\x00\x02\x00\x00\x00\x07' + b'\xaa' * 16), sm(0x34, 0, b'\x22' * 16),
            sm(0x30, 0x00, U('<I', 16) + b'\x11' * 16, False)))
    add(msg(sm(0x80, 0, U('<I', 7) + U('>I', 0x12345678)), sm(0x80, 0, U('<I', 7) + U('>I', 0x12345678), False)))
    add(msg(sm(0x80, 0, U('<I', 7) + U('>I', 0x12345678)), vendor=0x010f))
    uuid = bytes(range(9))
    add(msg(sm(0x82, 0, U('<I', 7400) + uuid + b'\0\0\0'), sm(0x82, 0x02, U('<I', 7400) + bytes(range(16))),
            sm(0x82, 0x04, U('<I', 7400) + uuid + b'\0\0\0')))
    he = lambda flags, body: sm(0x00, flags, body)
    add(msg(he(0x03, U('<I', 100)), he(0x05, struct.pack('<iI', 5, 6)), he(0x09, U('<I', 7)),
            he(0x11, b'\0' * 8), he(0x21, b'\0' * 4), he(0x61, b'\0' * 16), he(0x41, b'\0' * 8), he(0x81, pl_param(0x2c, b'abcd') + sentinel()),
            he(0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x80, U('<I', 100) + struct.pack('<iI', 5, 6) + U('<I', 7) + b'\0' * 8 + b'\0' * 4 + sentinel()),
            he(0x01, b'')))
    mark('Secure submessage framing, RTI CRC, UDP WAN binding ping, HEADER_EXTENSION', start)



# ------------------------------------------------- typecodes (PID_TYPECODE)
class TB:
    """Typecode builder: alignment is relative to the start of the buffer,
    which is 4-aligned in the packet."""
    def __init__(self, le=True):
        self.b = bytearray()
        self.e = '<' if le else '>'

    def al(self, n):
        self.b += b'\0' * ((-len(self.b)) % n)

    def u8(self, v):
        self.b += struct.pack('B', v)

    def u16(self, v):
        self.al(2)
        self.b += struct.pack(self.e + 'H', v)

    def u32(self, v):
        self.al(4)
        self.b += struct.pack(self.e + 'I', v)

    def i32(self, v):
        self.al(4)
        self.b += struct.pack(self.e + 'i', v)

    def name(self, s):
        self.al(4)
        raw = s.encode() + b'\0'
        self.b += struct.pack(self.e + 'I', len(raw)) + raw

    def header(self, kind, flag=0x80000000):
        self.al(4)
        start = len(self.b)
        self.b += struct.pack(self.e + 'I', kind | flag) + b'\0\0'
        return start

    def close(self, start):
        """Sets the typecode length: end (without padding) - start - 6."""
        n = len(self.b) - start - 6
        self.b[start + 4:start + 6] = struct.pack(self.e + 'H', n)


def tc_prim(t, kind):
    s = t.header(kind)
    t.close(s)


def tc_member(t, name, ptr, bits, key, nested):
    t.al(2)
    p0 = len(t.b)
    t.b += b'\0\0'
    t.name(name)
    t.u8(ptr)
    t.u16(bits)
    t.u8(key)
    nested(t)
    t.b[p0:p0 + 2] = struct.pack(t.e + 'H', len(t.b) - p0 - 2)


def tc_struct(t, name, members, kind=10):
    s = t.header(kind)
    t.name(name)
    t.u32(len(members))
    for m in members:
        tc_member(t, *m)
    t.close(s)


def tc_enum(t, name, items):
    s = t.header(12)
    t.name(name)
    t.u32(len(items))
    for i, n in items:
        t.al(2)
        p0 = len(t.b)
        t.b += b'\0\0'
        t.name(n)
        t.u32(i)
        t.b[p0:p0 + 2] = struct.pack(t.e + 'H', len(t.b) - p0 - 2)
    t.close(s)


def tc_union(t, name, disc, members):
    """disc: ('long',) or ('enum', name, items); members: (name, ptr, labels, nested)."""
    s = t.header(11)
    t.name(name)
    t.u32(0)
    if disc[0] == 'enum':
        ds = t.header(12)
        t.name(disc[1])
        t.b[ds + 4:ds + 6] = struct.pack(t.e + 'H', len(t.b) - ds - 6)
        # skip over the disc body as the dissector does (disc_size from the header)
    else:
        ds = t.header(2)
        t.close(ds)
    t.u32(len(members))
    for mname, ptr, labels, nested in members:
        t.al(2)
        p0 = len(t.b)
        t.b += b'\0\0'
        t.name(mname)
        t.u8(ptr)
        t.u32(len(labels))
        for lb in labels:
            t.i32(lb)
        nested(t)
        t.b[p0:p0 + 2] = struct.pack(t.e + 'H', len(t.b) - p0 - 2)
    t.close(s)


def tc_seq(t, bound, nested):
    s = t.header(14)
    t.u32(bound)
    nested(t)
    t.close(s)


def tc_array(t, dims, nested):
    s = t.header(15)
    t.u32(len(dims))
    for d in dims:
        t.u32(d)
    nested(t)
    t.close(s)


def tc_string(t, bound, wide=False):
    s = t.header(21 if wide else 13)
    t.u32(bound)
    t.close(s)


def tc_alias(t, name):
    s = t.header(16)
    t.name(name)
    t.close(s)


def tc_value(t, name, kind=22):
    s = t.header(kind)
    t.name(name)
    t.close(s)


def prim(kind):
    return lambda t: tc_prim(t, kind)


def typecode_blob(le=True, hack=False):
    t = TB(le)
    P = lambda k: prim(k - 1 if hack else k)
    inner = lambda t: tc_struct(t, 'Inner', [('a', 0, 0xffff, 0, P(2)), ('b', 0, 0xffff, 1, P(1))], 9 if hack else 10)
    mem = [('s', 0, 0xffff, 0, P(1)), ('l', 0, 0xffff, 1, P(2)), ('us', 0, 0xffff, 0, P(3)), ('ul', 0, 0xffff, 0, P(4)),
           ('f', 0, 0xffff, 0, P(5)), ('d', 0, 0xffff, 0, P(6)), ('bo', 0, 0xffff, 0, P(7)), ('c', 0, 0xffff, 0, P(8)),
           ('o', 0, 0xffff, 0, P(9)), ('ll', 0, 0xffff, 0, P(17)), ('ull', 0, 0xffff, 0, P(18)), ('ld', 0, 0xffff, 0, P(19)),
           ('wc', 0, 0xffff, 0, P(20)), ('bf', 0, 5, 0, P(2)), ('ptr', 1, 0xffff, 0, P(2)),
           ('str', 0, 0xffff, 0, lambda t: tc_string(t, 32)), ('wstr', 0, 0xffff, 0, lambda t: tc_string(t, 8, True)),
           ('seq', 0, 0xffff, 0, lambda t: tc_seq(t, 10, P(2))),
           ('seqs', 0, 0xffff, 0, lambda t: tc_seq(t, 4, inner)),
           ('sequ', 0, 0xffff, 0, lambda t: tc_seq(t, 3, lambda t: tc_union(t, 'U3', ('long',), [('xa', 0, [1], P(2))]))),
           ('arr', 0, 0xffff, 0, lambda t: tc_array(t, [2, 3], P(2))),
           ('arr1', 0, 0xffff, 1, lambda t: tc_array(t, [5], P(3))),
           ('en', 0, 0xffff, 0, lambda t: tc_enum(t, 'Color', [(0, 'RED'), (1, 'GREEN'), (5, 'BLUE')])),
           ('al', 0, 0xffff, 0, lambda t: tc_alias(t, 'MyLong')),
           ('val', 0, 0xffff, 0, lambda t: tc_value(t, 'Val')),
           ('valp', 0, 0xffff, 0, lambda t: tc_value(t, 'ValP', 23)),
           ('un', 0, 0xffff, 0, lambda t: tc_union(t, 'U1', ('long',), [('ua', 0, [1, 2], P(2)), ('ub', 1, [3], P(9))])),
           ('ue', 0, 0xffff, 0, lambda t: tc_union(t, 'U2', ('enum', 'Color', []), [('ea', 0, [0], P(2))])),
           ('in', 0, 0xffff, 0, inner)]
    if hack:
        mem = mem[:15] + mem[17:]    # no strings (ids differ)
    tc_struct(t, 'AllTypes', mem, 9 if hack else 10)
    return bytes(t.b)


# ----------------------------------------------- TypeObject v1 (PID_TYPE_OBJECT)
def pv(data):
    return phdr(0, len(align(data))) + align(data)


def phdr(pid, ln, le=True):
    return struct.pack('<HH' if le else '>HH', pid, ln)


class V:
    """Value builder with alignment relative to the parameter value start."""
    def __init__(self, le=True):
        self.b = bytearray()
        self.e = '<' if le else '>'

    def al(self, n):
        self.b += b'\0' * ((-len(self.b)) % n)
        return self

    def u16(self, v):
        self.al(2)
        self.b += struct.pack(self.e + 'H', v)
        return self

    def u32(self, v):
        self.al(4)
        self.b += struct.pack(self.e + 'I', v)
        return self

    def i32(self, v):
        self.al(4)
        self.b += struct.pack(self.e + 'i', v)
        return self

    def u8(self, v):
        self.b += struct.pack('B', v)
        return self

    def tid(self, t):
        if t <= 13:
            self.u16(t).u16(t)
        else:
            self.u16(0x0e)
            self.al(8)
            self.b += struct.pack(self.e + 'Q', t)
        return self

    def string(self, s):
        self.al(4)
        raw = s.encode() + b'\0'
        self.b += struct.pack(self.e + 'I', len(raw)) + raw
        return self

    def out(self, le_hdr=True):
        d = bytes(self.b)
        d += b'\0' * ((-len(d)) % 4)
        return phdr(0, len(d), self.e == '<') + d


def lib_type(tid, name, flags, le=True, annot=True):
    v = V(le).u16(flags).tid(tid).string(name)
    out = v.out()
    a = V(le)
    if annot:
        a.u32(1).tid(4).u32(1).u32(1).u16(4).u16(7)     # one annotation usage
    else:
        a.u32(0)
    return out + a.out()


def member1(mid, t, name, flags=0, le=True):
    v = V(le).u16(flags).al(4).u32(mid).tid(t).string(name)
    out = v.out()
    a = V(le).u32(0)
    return out + a.out()


def el(kind, body, le=True):
    k = V(le).u32(kind).out()
    b = align(body)
    return k + phdr(1, len(b), le) + b + struct.pack('<H' if le else '>H', 0x3f02) + b'\0\0'


def to_enum(tid, name, items, le=True):
    body = lib_type(tid, name, 1, le) + V(le).u32(32).out() + \
        (lambda v: v.out())(V(le))
    v = V(le).u32(len(items))
    for i, n in items:
        v.u32(i).string(n)
    return el(14, lib_type(tid, name, 1, le) + V(le).u32(32).out() + v.out(), le)


def to_alias(tid, name, base, le=True):
    return el(16, lib_type(tid, name, 1, le) + V(le).tid(base).out(), le)


def to_array(tid, name, base, dims, le=True):
    v = V(le).u32(len(dims))
    for d in dims:
        v.u32(d)
    return el(17, lib_type(tid, name, 1, le) + V(le).tid(base).out() + V(le).u8(0).out() + v.out(), le)


def to_seq(tid, name, base, bound, le=True):
    return el(18, lib_type(tid, name, 1, le) + V(le).tid(base).out() + V(le).u8(0).out() + V(le).u32(bound).out(), le)


def to_string(tid, name, bound, le=True):
    return el(19, lib_type(tid, name, 1, le) + V(le).tid(12).out() + V(le).u8(0).out() + V(le).u32(bound).out(), le)


def to_union(tid, name, members, le=True):
    """members: (member id, type id, name, labels, flags); the first is the discriminator."""
    body = lib_type(tid, name, 1, le)
    v = struct.pack('<I' if le else '>I', len(members))
    for mid, t, n, labels, fl in members:
        lab = V(le).u32(len(labels))
        for lb in labels:
            lab.i32(lb)
        v += member1(mid, t, n, fl, le) + lab.out()
    return el(21, body + phdr(0, len(v), le) + v, le)


def to_struct(tid, name, members, flags=1, base=0, le=True, annot=True):
    body = lib_type(tid, name, flags, le, annot)
    body += V(le).tid(base).out()
    mem = V(le).u32(len(members)).out()
    ms = b''.join(member1(mid, t, n, fl, le) for mid, t, n, fl in members)
    v = struct.pack('<I' if le else '>I', len(members)) + ms
    body += phdr(0, len(v), le) + v
    return el(22, body, le)


def to_module(name, inner_elements, le=True):
    v = V(le).string(name)
    lib = V(le).u32(len(inner_elements))
    inner = bytes(v.b) + bytes(b'\0' * ((-len(v.b)) % 4)) + struct.pack('<I' if le else '>I', len(inner_elements)) + b''.join(inner_elements)
    return el(24, inner, le)


def typeobject(elements, top, le=True):
    lib = struct.pack('<I' if le else '>I', len(elements)) + b''.join(elements)
    lib = align(lib)
    out = phdr(0, len(lib), le) + lib
    t = V(le).tid(top).out()
    out += phdr(1, len(t) - 4, le) + t[4:]
    out += struct.pack('<H' if le else '>H', 0x3f02) + b'\0\0'
    return out


# type ids of the user types
T_SENSOR, T_PT, T_COLOR, T_ALIAS, T_SEQ, T_SEQPT, T_ARR, T_STR, T_UN, T_MUT, T_BASE, T_DER = (0x7000 + i for i in range(1, 13))
T_NAMES = {}


def user_typeobject(le=True):
    els = [
        to_enum(T_COLOR, 'Color', [(0, 'RED'), (1, 'GREEN'), (7, 'BLUE')], le),
        to_alias(T_ALIAS, 'MyLong', 5, le),
        to_struct(T_PT, 'Pt', [(1, 5, 'x', 0), (2, 5, 'y', 0)], 1, 0, le),
        to_seq(T_SEQ, 'seq_long', 5, 8, le),
        to_seq(T_SEQPT, 'seq_pt', T_PT, 4, le),
        to_array(T_ARR, 'arr_short', 3, [3], le),
        to_string(T_STR, 'str32', 32, le),
        to_union(T_UN, 'U', [(1, 5, 'disc', [], 0), (2, 5, 'ua', [1], 0), (3, 12, 'ub', [2, 3], 0), (4, 10, 'uc', [], 8)], le),
        to_struct(T_BASE, 'Base', [(1, 5, 'bid', 0)], 1, 0, le),
        to_struct(T_DER, 'Derived', [(1, 6, 'dv', 0)], 1, T_BASE, le),
        to_struct(T_MUT, 'Mut', [(10, 5, 'ma', 0), (11, T_STR, 'mb', 0), (12, 5, 'mo', 2)], 2, 0, le),
        to_module('mod', [to_struct(0x7100, 'InMod', [(1, 5, 'q', 0)], 1, 0, le)], le),
        to_struct(T_SENSOR, 'Sensor', [
            (1, 1, 'b', 0), (2, 2, 'o', 0), (3, 12, 'c', 0), (4, 3, 's', 0), (5, 4, 'us', 0), (6, 5, 'l', 0), (7, 6, 'ul', 0),
            (8, 7, 'll', 0), (9, 8, 'ull', 0), (10, 9, 'f', 0), (11, 10, 'd', 0), (12, 11, 'ld', 0), (13, 14, 'e_unknown', 0),
            (14, T_STR, 'str', 0), (15, T_SEQ, 'sq', 0), (16, T_SEQPT, 'sp', 0), (17, T_ARR, 'arr', 0), (18, T_ALIAS, 'al', 0),
            (19, T_PT, 'pt', 0), (20, T_UN, 'un', 0), (21, T_DER, 'der', 0), (22, T_MUT, 'mut', 0), (23, T_COLOR, 'col', 0),
            (24, 13, 'c32', 0)], 1, 0, le),
    ]
    return typeobject(els, T_SENSOR, le)


def sensor_sample(le=True, big_seq=False, union_case=1):
    e = '<' if le else '>'
    b = bytearray()

    def al(n):
        b.extend(b'\0' * ((-len(b)) % n))

    def p(fmt, *a):
        al(struct.calcsize(e + fmt) if fmt not in ('B',) else 1)
        b.extend(struct.pack(e + fmt, *a))
    p('B', 1); p('B', 7); p('B', 65); p('h', -5); p('H', 6); p('i', -7); p('I', 8)
    p('q', -9); p('Q', 10); p('f', 1.5); p('d', 2.25); al(8); b.extend(bytes(range(16)))
    p('I', 7)                                                    # enum-like member as int32
    al(4); s = b'hello\0'; b.extend(struct.pack(e + 'I', len(s)) + s)
    al(4); n = 20 if big_seq else 3; b.extend(struct.pack(e + 'I', n)); [b.extend(struct.pack(e + 'i', i)) for i in range(n)]
    al(4); b.extend(struct.pack(e + 'I', 12 if big_seq else 2))
    for i in range(12 if big_seq else 2):
        p('i', i); p('i', -i)
    for i in range(3):
        p('h', i)
    p('i', 77)
    p('i', 1); p('i', 2)
    p('i', union_case)
    if union_case == 1:
        p('i', 11)
    elif union_case in (2, 3):
        p('B', 12)
    else:
        p('B', 5)
    p('i', 5); p('I', 6)                                         # Derived: Base then dv
    p('i', 40)                                                   # Mut is mutable: parameter headers follow
    b.extend(b'\0' * 0)
    al(4)
    ma = struct.pack(e + 'i', 99)
    mb = struct.pack(e + 'I', 3) + b'ab\0\0'
    for mid, d in ((10, ma), (11, mb)):
        b.extend(struct.pack(e + 'HH', mid, len(d)) + d)
    b.extend(struct.pack(e + 'HH', 0x3f02, 0))
    p('i', 1)                                                    # col
    p('I', 0x41)
    return bytes(b)


def discovery_pub(typeobj=None, typecode=None, le=True, writer=0x00000102, topic='SensorTopic', typename='Sensor',
                  writer_entity=0x000003c2, extra=b''):
    p = pl_param(0x5a, guid(ent=writer), le) + pl_param(0x05, cstr(topic, le), le) + pl_param(0x07, cstr(typename, le), le)
    if typecode is not None:
        p += pl_param(0x47, typecode, le)
    if typeobj is not None:
        p += pl_param(0x72, typeobj, le)
    p += extra + sentinel(le)
    payload = struct.pack('>HH', 3 if le else 2, 0) + p
    return data_std(writer_entity, 0x000003c7, 1000 + len(payload) % 50, payload, flags=0x05 if le else 0x04, sid=0x15, le=le)


def types_user():
    start = len(main)
    add(msg(discovery_pub(typecode=typecode_blob(True))))
    add(msg(discovery_pub(typecode=typecode_blob(False, False), le=False, writer=0x00000202, topic='T2', typename='AllTypesBE')))
    add(msg(discovery_pub(typecode=typecode_blob(True, True), writer=0x00000302, topic='T3', typename='Hacked')))
    # the typecode with the PID of RTPS 2
    add(msg(data_std(0x000003c2, 0x000003c7, 3, struct.pack('>HH', 3, 0) + pl_param(0x8004, typecode_blob(True)) + sentinel(), flags=0x05)))
    mark('Typecodes (PID_TYPECODE)', start)
    start = len(main)
    # the discovery with the TypeObject, then user samples of the type (needs the user data preference)
    to = user_typeobject(True)
    add(msg(discovery_pub(typeobj=to, writer=0x00000402)))
    for n, kw in enumerate(({}, {'big_seq': True}, {'union_case': 2}, {'union_case': 3}, {'union_case': 9})):
        pay = struct.pack('>HH', 1, 0) + sensor_sample(True, **kw)
        add(msg(data_std(0x00000402, 0x00000107, 2000 + n, pay, flags=0x04)))
    mark('TypeObject (v1) and user data', start)

# --------------------------------------------- XTypes, type lookup, services
class XB:
    """XCDR2 builder with absolute alignment (base = offset of the first byte)."""
    def __init__(self, base):
        self.base = base
        self.b = bytearray()

    def pos(self):
        return self.base + len(self.b)

    def al(self, n):
        self.b += b'\0' * ((-self.pos()) % n)
        return self

    def u8(self, v):
        self.b.append(v)
        return self

    def u16(self, v):
        self.b += struct.pack('<H', v)
        return self

    def u32(self, v):
        self.al(4)
        self.b += struct.pack('<I', v)
        return self

    def dh(self):
        """delimited header (placeholder, 4 aligned); returns a handle."""
        self.al(4)
        h = len(self.b)
        self.b += b'\0\0\0\0'
        return h

    def endh(self, h):
        self.b[h:h + 4] = struct.pack('<I', len(self.b) - h - 4)

    def emh(self, lc=0, mid=1):
        self.al(4)
        self.b += struct.pack('<I', (lc << 28) | mid)
        if lc >= 4:
            self.b += struct.pack('<I', 0)
        if lc == 4:
            self.b += struct.pack('<I', 0)
        return self

    def sn(self, v):
        self.al(4)
        self.b += struct.pack('<iI', v >> 32, v & 0xffffffff)
        return self

    def str_na(self, s):          # string without alignment padding after it
        self.al(4)
        raw = s.encode() + b'\0'
        self.b += struct.pack('<I', len(raw)) + raw
        return self

    def raw(self, d):
        self.b += d
        return self


def tid2(x, kind, **k):
    """Type id v2."""
    if kind in (0x00, 0x01, 0x02, 0x0c, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11):
        x.u8(kind)
    elif kind in (0x70, 0x72):
        x.u8(kind).u8(k.get('bound', 8))
    elif kind in (0x71, 0x73):
        x.u8(kind)
        x.u32(k.get('bound', 300))
    elif kind in (0x80,):
        x.u8(kind).u8(0xf2).u16(0).u8(5)
        tid2(x, *k['elem'])
    elif kind == 0x81:
        x.u8(kind).u8(0xf2).u16(0)
        x.u32(k.get('bound', 1000))
        tid2(x, *k['elem'])
    elif kind in (0x90, 0x91):
        x.u8(kind).u8(0xf2).u16(0)
        bounds = k.get('bounds', [2, 3])
        x.u32(len(bounds))
        for bnd in bounds:
            x.u8(bnd) if kind == 0x90 else x.u32(bnd)
        tid2(x, *k['elem'])
    elif kind == 0xa0:
        x.u8(kind).u8(0xf2).u16(0).u8(7)
        tid2(x, *k['key'])
        x.al(2).u16(0)
        tid2(x, *k['elem'])
    elif kind == 0xa1:
        x.u8(kind).u8(0xf2).u16(0)
        x.u32(70000)
        tid2(x, *k['key'])
        x.u16(0)
        tid2(x, *k['elem'])
    elif kind in (0xf1, 0xf2):
        x.u8(kind).raw(bytes(range(1, 15)))
    elif kind == 0xb0:
        x.u8(kind)
    else:
        x.u8(kind)


def tid_w_size(x, t):
    h = x.dh()
    tid2(x, *t)
    x.al(4).u32(100)
    None


def tid_w_size_b(x, t):
    x.dh()
    tid2(x, *t)
    x.al(4).u32(100)


def complete_detail(x, name):
    x.u8(0).u8(0).str_na(name)


def ann_value(x, kind):
    x.u8(kind)
    if kind in (0x01, 0x0c, 0x02, 0x0d):
        x.u8(1)
    elif kind in (0x03, 0x06):
        x.al(2).raw(struct.pack('<H', 7))
    elif kind in (0x04, 0x07, 0x09):
        x.al(4).raw(struct.pack('<I', 7))
    elif kind in (0x05, 0x08, 0x0a):
        x.al(4).raw(struct.pack('<Q', 7))


ANN_KINDS = [(0x04, 0x00), (0x01, 0x0c), (0x02, 0x0d), (0x03, 0x06), (0x07, 0x09), (0x05, 0x08), (0x0a, 0x20), (0x00, 0x04)]


def member_detail(x, complete, name, variant=0):
    if complete:
        x.str_na(name)
        x.u8(1)                                  # has builtin annotations
        x.al(4)
        x.dh()                                   # object size 0: no "Default" value
        kmin, kmax = ANN_KINDS[variant % len(ANN_KINDS)]
        x.u8(1 if variant % 3 else 0)
        if variant % 3:
            x.str_na('m')                        # unit
        x.u8(1 if kmin else 0)
        if kmin:
            ann_value(x, kmin)                   # min
        x.u8(1 if kmax else 0)
        if kmax:
            ann_value(x, kmax)                   # max
        x.u8(1 if variant % 2 else 0)
        if variant % 2:
            x.str_na('hid')
        x.u8(1 if variant % 4 else 0)            # has custom annotations
        if variant % 4:
            x.dh()
    else:
        x.raw(b'\x11\x22\x33\x44')


def typeobj2(x, complete, kind, body):
    x.u8(0xf2 if complete else 0xf1).u8(kind)
    body(x)


def ob_alias(complete):
    def f(x):
        x.al(2).u16(0x0001)
        x.dh()
        if complete:
            complete_detail(x, 'A')
        x.dh()
        x.u16(0x0002)
        tid2(x, 0x05)
        if complete:
            x.u8(0).u8(0)
    return f


def ob_struct(complete):
    def f(x):
        x.u16(0x0001)
        x.dh()
        tid2(x, 0x00)
        if complete:
            complete_detail(x, 'S')
        x.dh()
        types = (0x05, 0x70, 0x01, 0x0c, 0x03, 0x07, 0x09, 0x0a)
        x.u32(len(types))
        for i, t in enumerate(types):
            x.dh()
            x.u32(i + 1)
            x.u16(0x0004)
            tid2(x, t)
            member_detail(x, complete, 'f%d' % i, i)
    return f


def ob_union(complete):
    def f(x):
        x.u16(0x0001)
        x.dh()
        if complete:
            complete_detail(x, 'U')
        x.dh()
        x.u16(0x0000)
        tid2(x, 0x05)
        if complete:
            x.u8(0).u8(0)
        x.dh()
        x.u32(2)
        for i, labels in enumerate(([1, 2], [])):
            x.dh()
            x.u32(i + 1)
            x.u16(0x0004)
            tid2(x, 0x01)
            x.u32(len(labels))
            for lb in labels:
                x.u32(lb)
            member_detail(x, complete, 'u%d' % i, i + 3)
    return f


def ob_enum(complete):
    def f(x):
        x.u16(0x0001)
        x.dh()
        x.u16(16)
        if complete:
            complete_detail(x, 'E')
        x.dh()
        x.u32(2)
        for i in range(2):
            x.dh()
            x.dh()
            x.u32(i)
            x.u16(0)
            member_detail(x, complete, 'L%d' % i, i + 5)
    return f


TYPEIDS = [(0x01,), (0x05,), (0x0c,), (0x70, ), (0x71,), (0x72,), (0x73,), (0xf1,), (0xf2,), (0xb0,), (0x99,),
           (0x80, {'elem': (0x05,)}), (0x81, {'elem': (0x70,)}), (0x90, {'elem': (0x05,)}), (0x91, {'elem': (0x05,)}),
           (0xa0, {'key': (0x05,), 'elem': (0x71,)}), (0xa1, {'key': (0x05,), 'elem': (0x05,)})]


def tidspec(spec):
    return (spec[0], spec[1]) if len(spec) > 1 else (spec[0], {})


def tid2c(x, spec):
    kind, k = tidspec(spec)
    tid2(x, kind, **k)


def typeinfo_param(base):
    """PID_TYPE_INFORMATION parameter (first in the list so that base = 32)."""
    x = XB(base)
    x.dh()
    for lc in (0, 4):
        x.emh(lc)
        h = x.dh()
        tid2(x, 0xf1)
        x.al(4).u32(120)
        x.u32(2)
        x.dh()
        x.u32(2)
        for t in ((0xf1,), (0xf2,)):
            x.dh()
            tid2(x, t[0])
            x.al(4).u32(90)
    return x


def xtypes():
    start = len(main)
    # PID_TYPE_INFORMATION as the first parameter: the value starts at offset 32 of the submessage
    x = typeinfo_param(32)
    body = bytes(x.b)
    body += b'\0' * ((-len(body)) % 4)
    pl = pl_param(0x75, body) + pl_param(0x5a, guid(ent=0x00000502)) + pl_param(0x05, cstr('XTopic')) + pl_param(0x07, cstr('XType')) + sentinel()
    add(msg(data_std(0x000003c2, 0x000003c7, 3000, struct.pack('>HH', 3, 0) + pl, flags=0x05)))
    # type lookup request / reply, plain and delimited CDR2
    for enc in (7, 9):
        for w in (0x000300c3, 0xff0300c3):
            base = 28
            x = XB(base)
            x.raw(PREFIX).raw(eid(w))
            if enc == 9:
                x.dh()
            x.sn(77)
            x.str_na('xtypes')
            x.dh()
            x.u32(0x05aafb31 if w == 0x000300c3 else 0x018252d3)
            x.dh()
            x.emh(0)
            x.u32(3)
            for t in ((0xf2,), (0xf1,), (0x05,)):
                tid2(x, t[0])
            x.emh(0) if w == 0x000300c3 else None
            fr = []
            pay = struct.pack('>HH', enc, 0)
            if enc == 9:
                # four delimited headers are skipped before the request
                pay += b'\0' * 12
                x = XB(base + 16)
                x.raw(PREFIX).raw(eid(w))
                x.dh()
                x.sn(77)
                x.str_na('xtypes')
                x.dh()
                x.u32(0x05aafb31 if w == 0x000300c3 else 0x018252d3)
                x.dh()
                x.emh(0)
                x.u32(3)
                for t in ((0xf2,), (0xf1,), (0x05,)):
                    tid2(x, t[0])
                x.emh(0) if w == 0x000300c3 else None
                pay = struct.pack('>HH', enc, 0) + b'\0' * 16
                pay = pay[:4] + b'\0' * 16
            pay = struct.pack('>HH', enc, 0) + (b'\0' * 16 if enc == 9 else b'') + bytes(x.b)
            add(msg(data_std(w, 0x000300c4, 3100 + enc + w % 7, pay, flags=0x04)))
    # replies: GET_TYPE_DEPENDENCIES and GET_TYPES
    for enc in (7, 9):
        for deps in (True, False):
            w = 0x000301c3 if enc == 7 else 0xff0301c3
            base = 28 + (16 if enc == 9 else 0)
            x = XB(base)
            x.raw(PREFIX).raw(eid(0x000300c3))
            if enc == 9:
                x.dh()
            x.sn(77)
            x.u32(0)                    # remote exception code
            x.dh()
            x.u32(0x05aafb31 if deps else 0x018252d3)
            x.dh()
            x.u32(0)                    # result
            x.dh()
            x.emh(0)
            if deps:
                x.u32(2)
                for t in ((0xf2,), (0xf1,)):
                    tid_w_size_b(x, t)
                x.emh(0)
            else:
                x.u32(5)
                for i, (comp, kind, body) in enumerate(((True, 0x30, ob_alias(True)), (False, 0x51, ob_struct(False)),
                                                        (True, 0x51, ob_struct(True)), (True, 0x52, ob_union(True)),
                                                        (False, 0x40, ob_enum(False)))):
                    tid2(x, 0xf2 if comp else 0xf1)
                    x.dh()
                    typeobj2(x, comp, kind, body)
                x.emh(0)
                x.u32(2)
                for _ in range(2):
                    tid2(x, 0xf2)
                    x.al(4).u32(0)
                    tid2(x, 0xf1)
            pay = struct.pack('>HH', enc, 0) + (b'\0' * 16 if enc == 9 else b'') + bytes(x.b)
            add(msg(data_std(w, 0x000301c4, 3200 + enc + (1 if deps else 0), pay, flags=0x04)))
    # every kind of type id in a request
    x = XB(28)
    x.raw(PREFIX).raw(eid(0x000300c3))
    x.sn(78)
    x.str_na('ids')
    x.dh()
    x.u32(0x018252d3)
    x.dh()
    x.emh(4)
    x.u32(len(TYPEIDS))
    for spec in TYPEIDS:
        tid2c(x, spec)
    add(msg(data_std(0x000300c3, 0x000300c4, 3150, struct.pack('>HH', 7, 0) + bytes(x.b), flags=0x04)))
    mark('XTypes: PID_TYPE_INFORMATION, TypeLookup requests and replies (TypeObject v2)', start)


def services():
    start = len(main)
    # ParticipantMessageData
    pm = struct.pack('>HH', 1, 0) + PREFIX + struct.pack('>I', 0x00000001) + struct.pack('<I', 6) + b'hello!'
    add(msg(data_std(0x000200c2, 0x000200c7, 3300, pm, flags=0x04)))
    # participant generic message (stateless / volatile secure): data holders
    def holder(cls, props, bprops):
        x = bytearray()
        x += cstr(cls)
        x += U('<I', len(props))
        for n, v in props:
            x += cstr(n) + cstr(v)
        x += U('<I', len(bprops))
        for n, d in bprops:
            x += cstr(n) + U('<I', len(d)) + align(d)
        return bytes(x)
    for w in (0x000201c3, 0xff0202c3):
        body = guid(ent=0x000100c2) + sn(5) + guid(ent=0x000100c2) + sn(4) + guid(ent=0x000100c2) + guid(ent=0x000200c7) + guid(ent=0x000200c2)
        body += cstr('dds.sec.auth_request') + U('<I', 2) + holder('DDS:Auth:PKI-DH', [('dds.cert.sn', 'abc')], [('c.id', b'xyzw')]) + holder('DDS:Access', [], [])
        add(msg(data_std(w, 0x000201c4, 3310 + w % 5, struct.pack('>HH', 1, 0) + body, flags=0x04)))
    # locator ping
    add(msg(data_std(0x00020182, 0x00020187, 3320, struct.pack('>HH', 3, 0) + guid(ent=0x000100c2) + locator(1, 7400, v4addr('192.0.2.5')), flags=0x04)))
    # service requests: topic query, locator reachability, unknown, instance state
    def tq():
        v = struct.pack('>HH', 3, 0)
        sel = cstr('DDSSQL')
        a = phdr(0, len(sel)) + sel
        b = cstr('x > 3')
        b = phdr(1, len(b)) + b
        c = U('<I', 2) + cstr('p0') + cstr('p1') + U('<I', 1)
        c = phdr(2, len(c)) + c
        selection = a + b + c
        v += phdr(0, len(selection)) + selection
        sq = sn(3)
        v += phdr(1, len(sq)) + sq
        tn = cstr('TQTopic')
        v += phdr(2, len(tn)) + tn
        g = guid(ent=0x00000107)
        v += phdr(3, len(g)) + g
        return v
    def lr():
        v = struct.pack('>HH', 3, 0)
        locs = U('<I', 2) + locator(1, 7400, v4addr('192.0.2.5')) + locator(2, 7401, bytes(range(16)))
        return v + phdr(0, len(locs)) + locs
    for sid_, body in ((1, tq()), (2, lr()), (0, U('<I', 4) + b'abcd'), (3, b'\0' * 8 + sn(9) + guid(ent=0x0000018c) + U('<III', 1, 2, 3))):
        if sid_ in (1, 2):
            body = b'\0\0\0\0' + body
        if sid_ == 3:
            body = body
        pay = struct.pack('>HH', 3, 0) + U('<i', sid_) + guid(ent=0x00020082) + body
        add(msg(data_std(0x00020082, 0x00020087, 3330 + sid_, pay, flags=0x04)))
    # InstanceStateDataResponse from a META group writer (builtin type)
    def iud(optional_key=True):
        b = b''
        if optional_key:
            b += phdr(0, 16) + bytes(range(16))
        else:
            b += phdr(0, 0)
        b += U('<II', 5, 7) + sn(4)
        return b
    resp = phdr(0, 4 + 2 * (8 + 16 + 8 + 8)) + U('<I', 2) + iud() + iud(False)
    resp += phdr(1, 4) + U('<I', 0)
    resp += guid(ent=0x0000018c) + guid(ent=0x0000018d) + U('<I', 77) + b'\1'
    add(msg(data_std(0x0000018c, 0x0000018d, 3340, struct.pack('>HH', 1, 0) + resp, flags=0x04)))
    add(msg(data_std(0x0000018d, 0x0000018c, 3341, struct.pack('>HH', 0, 0) + bytes(range(64)), flags=0x04)))
    mark('Built-in writers: participant messages, generic messages, locator ping, service requests, instance state', start)



def extras():
    start = len(main)
    end = struct.pack('<HH', 0x3f02, 0)
    ext = struct.pack('<HHII', 0x3f01, 8, 0x2c, 4) + b'abcd'
    add(rtps_data_disc(ext + pl_param(0x2c, b'abcd') + ext, True))
    add(rtps_data_disc(ext, True, inline=True))
    add(msg(data_std(UW, UR, 4300, sdata(3, ext + pl_param(0x2c, b'abcd') + ext + end), flags=0x04)))
    add(msg(data_std(UW, UR, 4301, sdata(3, pl_param(0x2c, b'abcd') + end), flags=0x04)))
    add(msg(data_std(UW, UR, 4302, sdata(2, pl_param(0x2c, b'abcd', False) + struct.pack('>HH', 0x3f02, 0), ), flags=0x04, le=False)))
    # UDP datagrams that are not RTPS: too short, wrong magic, wrong major version
    main.append((1, udp_frame(b'RTPS\x02\x03\x01\x01\x00\x00')))
    main.append((1, udp_frame(b'RTPT\x02\x03\x01\x01' + PREFIX)))
    main.append((1, udp_frame(b'RTPS\x03\x00\x01\x01' + PREFIX)))
    mark('Parameters with extended ids; datagrams that are not RTPS', start)


# ----------------------------------------------------------- more cases
def status_and_locators():
    start = len(main)
    # info column: every writer with a status info in the inline QoS
    writers = [0x000001c1, 0x000002c2, 0x000003c2, 0x000004c2, 0x000100c2, 0x000200c2, 0x000201c3, 0xff0202c3, 0xff0200c2,
               0xff0003c2, 0xff0004c2, 0x00010082, 0x00010087, 0x00010182, 0x00010187, 0xff010182, 0xff010187, 0x000300c3,
               0x000300c4, 0xff0300c3, 0xff0300c4, 0x000301c3, 0x000301c4, 0xff0301c3, 0xff0301c4, 0xff0101c2, 0x00000102,
               0x000001c3]
    si = lambda v: pl_param(0x71, struct.pack('>I', v)) + sentinel()
    sms = []
    for i, w in enumerate(writers):
        sms.append(data_std(w, 0, 4000 + i, b'', flags=0x02, q=si(i % 5)))
    for i in range(0, len(sms), 10):
        add(msg(*sms[i:i + 10]))
    # DATA without status info in the inline QoS and topic query writers
    add(msg(data_std(0x000003c2, 0, 4100, b'', flags=0x02, q=pl_param(0x2c, b'abcd') + sentinel()),
            data_std(0x000003c2, 0, 4101, b'', flags=0x00)))
    mark('Info column: status info of every well-known writer', start)
    # locators of every kind
    start = len(main)
    L = []
    ip = bytes((192, 0, 2, 33))
    v6 = bytes(range(0x20, 0x30))
    L.append(locator(1, 7400, v4addr('192.0.2.33')))
    L.append(locator(1, 0, v4addr('192.0.2.33')))
    L.append(locator(0x01001001, 7400, v4addr('192.0.2.33')))
    for kind in (8, 9, 10, 11):
        L.append(locator(kind, 7400, b'\0' * 8 + b'\xff\xff' + struct.pack('>H', 7500) + ip))          # IPv4 format
        L.append(locator(kind, 0, v6))                                                                 # IPv6 format
    L.append(locator(0x01000000, 7400, b'\0' * 2 + struct.pack('>I', 0x01020304) + b'\0' * 10))
    L.append(locator(0x01000000, 0, b'\0' * 16))
    L.append(locator(2, 7400, v6))
    L.append(locator(2, 0, v6))
    L.append(locator(6, 7400, v6))
    for fl in (0x00, 0x01, 0x02, 0x03, 0x04, 0x08, 0x0f):
        L.append(locator(0x01000001, 7400, bytes((fl,)) + bytes(range(1, 10)) + struct.pack('>H', 7500) + ip))
    L.append(locator(0x01000001, 7400, bytes((0x02,)) + bytes(range(1, 10)) + struct.pack('>H', 7500) + b'\0' * 4))
    L.append(locator(0x01000001, 0, bytes((0x00,)) + bytes(range(1, 10)) + struct.pack('>H', 7500) + ip))
    L.append(locator(0x7f, 7400, v6))
    params = b''.join(pl_param(0x31, l) for l in L)
    # a few per frame so that the sweeps' frames stay readable
    for i in range(0, len(L), 8):
        add(rtps_data_disc(b''.join(pl_param(0x31, l) for l in L[i:i + 8]), True))
    add(rtps_data_disc(b''.join(pl_param(0x32, l) for l in L[:4]) + b''.join(pl_param(0x33, l) for l in L[4:8]) +
                       b''.join(pl_param(0x48, l) for l in L[8:10]) + b''.join(pl_param(0x2f, l) for l in L[10:12]) +
                       b''.join(pl_param(0x30, l) for l in L[12:14]), True))
    # PID_LOCATOR_FILTER_LIST, PID_UNICAST_LOCATOR_EX, multichannel lists
    mc = lambda ls: U('<I', len(ls)) + b''.join(ls)
    chan = lambda ls, expr: mc(ls) + cstr(expr)
    lfl = U('<i', 2) + cstr('filter') + chan([locator(1, 7400, v4addr('192.0.2.33')), locator(2, 7401, v6), locator(8, 1, v6)], 'a > 1') + chan([], 'b')
    ex = locator(1, 7400, v4addr('192.0.2.33')) + U('<I', 2) + struct.pack('<HH', 3, 7)
    add(rtps_data_disc(pl_param(0x8006, lfl) + pl_param(0x8006, U('<i', 0)) + pl_param(0x8007, ex), True))
    mark('Locators of every kind, locator filter list, locator with encapsulations', start)
    # v1 frames
    start = len(main)
    v1 = lambda *sms: msg(*sms, ver=(1, 2))
    rd, wr = 0x000003c7, 0x000003c2
    pv1 = pl_param(0x16, bytes((1, 1, 0, 0))) + pl_param(0x15, bytes((1, 2, 0, 0))) + pl_param(0x05, cstr('T')) + sentinel()
    for fl in (0x03, 0x03 | 0x04, 0x03 | 0x08, 0x03 | 0x10, 0x03 | 0x20, 0x03 | 0x08 | 0x10 | 0x04):
        hb = b'\0\0\0\1\0\0\0\2' if fl & 0x08 else b''
        body = eid(rd) + eid(wr) + hb + eid(0x00000102) + sn(5)
        if fl & 0x10:
            body += pv1
        if fl & 0x02:
            body += pv1
        add(v1(sm(0x02, fl, body)))
    add(v1(sm(0x02, 0x01, eid(rd) + eid(0x00000102) + eid(0x00000102) + sn(5) + b'abcd')))
    add(v1(sm(0x02, 0x01 | 0x04, eid(rd) + eid(wr) + eid(0x00000102) + sn(5) + pv1)))
    add(v1(sm(0x02, 0x03 | 0x04, eid(rd) + eid(wr) + eid(0x00000102) + sn(5) + pv1)))
    add(v1(sm(0x03, 0x01, eid(rd) + eid(0x00000102) + sn(5) + b'abcd'), sm(0x03, 0x01 | 0x04, eid(rd) + eid(0x00000102) + sn(6) + b'abcd'),
            sm(0x03, 0x03, eid(rd) + eid(0x00000102) + sn(7) + pv1 + b'abcd')))
    add(v1(sm(0x07, 0, eid(rd) + eid(wr) + sn(1) + sn(5)), sm(0x06, 0, eid(rd) + eid(wr) + bitmap(3, 4, True, [0xa0000000]) + U('<I', 2)),
           sm(0x08, 0, eid(rd) + eid(wr) + sn(3) + bitmap(5, 3, True, [0xa0000000])),
           sm(0x0c, 0, b'\0' * 4 + bytes((1, 1)) + struct.pack('>H', 0x0101) + b'\0' * 8), sm(0x0c, 0, b'\x7f\0\0\1' + bytes((1, 0)) + struct.pack('>H', 0x0101) + b'\0' * 8),
           sm(0x0e, 0, b'\x01\x02\x03\x04\x05\x06\x07\x08'), info_ts()))
    mark('RTPS 1.2 submessages', start)


def batches_and_more():
    start = len(main)
    # RTPS_DATA_BATCH
    def sinfo(flags, data_len, ts=None, off=None, qos=None):
        b = struct.pack('>H', flags) + struct.pack('<H', 0) + U('<I', data_len)
        if flags & 0x01:
            b += struct.pack('<iI', 100, 0)
        if flags & 0x04:
            b += U('<I', off or 1)
        if flags & 0x02:
            b += qos
        return b
    samples = [b'\x11\x22\x33\x44', b'\x55\x66\x77\x88\x99\xaa\xbb\xcc', b'k' * 8]
    def batch(wid, infos, payload, enc=1, qos=b'', flags=0x00, seq=4200):
        body = struct.pack('<HH', 0, 28) + eid(UR) + eid(wid) + sn(seq) + sn(seq + 1) + U('<I', 2) + U('<I', len(infos))
        body += qos
        il = b''.join(infos)
        body += U('<I', len(il)) + il
        body += struct.pack('>HH', enc, 0) + payload
        return sm(0x18, flags, body)
    q1 = pl_param(0x71, struct.pack('>I', 1)) + sentinel()
    infos = [sinfo(0x00, 4), sinfo(0x01, 8), sinfo(0x05, 8, off=2), sinfo(0x02, 0, qos=q1), sinfo(0x08 | 0x20, 8)]
    pay = samples[0] + samples[1] + samples[1] + b'' + samples[2]
    add(msg(batch(UW, infos, pay)))
    add(msg(batch(UW, [sinfo(0x00, 4)], samples[0], enc=0, qos=q1, flags=0x02)))
    add(msg(batch(UW, [sinfo(0x00, 4)] * 20, samples[0] * 20, enc=3)))
    add(msg(batch(UW, [sinfo(0x00, 4)], zlib_sample_inner(samples[0]), enc=1)))
    # batches that are cut short: a sample info that does not fit, a sample that does not fit
    addmal(msg(batch(UW, [sinfo(0x05, 8, off=2)] , samples[0], flags=0x00)[:0] or sm(0x18, 0, struct.pack('<HH', 0, 28) + eid(UR) + eid(UW) + sn(4300) + sn(4301) + U('<I', 2) + U('<I', 1) + U('<I', 6) + b'\x00\x05\0\0' + b'\0\0')))
    addmal(msg(batch(UW, [sinfo(0x00, 400)], samples[0])))
    mark('RTPS_DATA_BATCH', start)
    start = len(main)
    # coherent sets: start, members, end (consecutive sequence number / unknown sequence number), PID_END_COHERENT_SET
    cs = lambda n: pl_param(0x56, sn(n, True)) + sentinel()
    ecs = lambda n: pl_param(0x8022, sn(n, True)) + sentinel()
    W = 0x00000302
    add(msg(data_std(W, UR, 100, b'', flags=0x02, q=cs(100)), data_std(W, UR, 101, b'', flags=0x02, q=cs(100)),
            data_std(W, UR, 102, b'', flags=0x02, q=cs(100)), data_std(W, UR, 103, b'', flags=0x02, q=cs(103)),
            data_std(W, UR, 104, b'', flags=0x02, q=cs(103)), data_std(W, UR, 105, b'', flags=0x02, q=pl_param(0x56, struct.pack('<iI', -1, 0)) + sentinel()),
            data_std(W, UR, 106, b'', flags=0x02, q=cs(106)), data_std(W, UR, 107, b'', flags=0x02, q=ecs(106)),
            data_std(W, UR, 108, b'', flags=0x02, q=cs(108)), data_std(W, UR, 109, b'', flags=0x00),
            data_std(W, UR, 110, b'', flags=0x02, q=cs(110)), data_std(W, UR, 111, b'', flags=0x00), data_std(W, UR, 112, b'', flags=0x00)))
    add(msg(data_std(W + 0x100, UR, 5, b'', flags=0x02, q=cs(5)), data_std(W + 0x100, UR, 6, b'', flags=0x02, q=cs(5)),
            data_std(W + 0x100, UR, 7, b'', flags=0x02, q=ecs(5) + b''),
            data_std(W + 0x100, UR, 8, b'', flags=0x02, q=pl_param(0x63, sn(8)) + pl_param(0x8023, sn(8)) + pl_param(0x8024, U('<I', 3)) + sentinel())))
    mark('Coherent sets', start)
    # compressed TypeObject (PID_TYPE_OBJECT_LB)
    start = len(main)
    to = user_typeobject(True)
    comp = zlib.compress(to)
    padded = comp + b'\0' * max(0, len(to) - len(comp))
    lb = lambda cls, body, dsz, csz: pl_param(0x8021, U('<III', cls, dsz, csz) + body)
    add(rtps_data_disc(lb(1, padded, len(to), len(comp)) + pl_param(0x5a, guid(ent=0x00000602)) + pl_param(0x05, cstr('LBTopic')) + pl_param(0x07, cstr('LBType')), True))
    add(rtps_data_disc(lb(0, to, len(to), len(to)) + pl_param(0x5a, guid(ent=0x00000702)) + pl_param(0x05, cstr('LBTopic0')) + pl_param(0x07, cstr('LBType0')), True))
    add(rtps_data_disc(lb(7, b'abcdefgh', 8, 8), True))
    mark('PID_TYPE_OBJECT_LB (compressed and plain TypeObject)', start)


def zlib_sample_inner(raw):
    return struct.pack('>HH', 1, 0x04) + struct.pack('>I', len(raw)) + zlib.compress(raw)

# ------------------------------------------------ reproducers of the fixes
def reproducers():
    import rtps_common as RC
    start = len(main)
    # "RTPS: Guard the TypeObject maps on repeat passes": a sample before its TypeObject
    tid = RC.INSTANCE_STATE_DATA_RESPONSE_TID
    to = RC.type_object([RC.struct_element(tid, [5], name='S')], tid)
    main.append((1, RC.udp_frame(RC.meta_group_data(struct.pack('<i', 0x11223344)))))
    main.append((1, RC.udp_frame(RC.discovery_publication(to))))
    # an ARRAY element with an empty bound sequence (uninitialized bound)
    body = RC.library_type(tid + 1, 'A')
    cid = struct.pack('<HH', 2, 0)
    body += RC.phdr(0, len(cid)) + cid + RC.phdr(0, 4) + b'\0' * 4 + RC.phdr(0, 4) + struct.pack('<I', 0)
    to = RC.type_object([RC.element(17, body)], tid + 1)
    main.append((1, RC.udp_frame(RC.discovery_publication(to))))
    main.append((1, RC.udp_frame(RC.meta_group_data(bytes(range(64))))))
    # dangling RTPS_ROOT_MESSAGE_KEY: Exported PDU naming rtpsvt (the preference makes it a crash)
    m = RC.rtps_header() + struct.pack('<BBH', 0x01, 0x01, 0)
    he = struct.pack('<BBH', 0x00, 0x21, 4) + b'\0' * 4
    vt = struct.pack('>HB', 0x0100, 1) + struct.pack('>HH', 0x00ff, 0) * 8 + struct.pack('>HH', 0x0009, 4) + b'\x01\0\0\0'
    vt += struct.pack('>HH', 0x00c0, len(m)) + m + struct.pack('>HH', 0x0000, 0) + struct.pack('>HH', 0x00c2, len(he)) + he
    main.append(exppdu('rtpsvt', vt))
    mark('Reproducers: TypeObject maps on two passes, array bound, dangling root message (Exported PDU)', start)
    # frames that only error out: they go to the malformed capture
    M_, D_ = 4, 6
    def level():
        b = struct.pack('<IHHI', 10, 0, 0, 0) + struct.pack('<I', M_)
        for j in range(M_):
            b += struct.pack('<HHI', 6, 0, 8 * (M_ - 1 - j))
        return b + struct.pack('<BBHBBH', 0, 0, 0xffff, 0, 0, 0)
    tc = level() * D_ + struct.pack('<IHH', 1, 0, 0)
    pl = struct.pack('>HH', 3, 0) + struct.pack('<HH', 0x47, len(tc)) + tc + struct.pack('<HH', 1, 0)
    mal.append((1, udp_frame(RC.rtps_header() + RC.data_submsg(0x000003c2, pl))))
    lvl = struct.pack('<IHHI', 14, 8, 0, 0)
    sample = struct.pack('>HH', 3, 0) + struct.pack('<HH', 0x47, 12) + lvl * 5000
    mal.append((1, udp_frame(RC.rtps_header() + RC.data_submsg(0x000003c2, sample))))
    N_, DD = 60, 4
    tids = [RC.INSTANCE_STATE_DATA_RESPONSE_TID] + [0x1000 + k for k in range(1, DD)]
    els = [RC.struct_element(tids[k], [tids[k + 1] if k + 1 < DD else 0x4242424242424242] * N_, name='S%d' % k) for k in range(DD)]
    mal.append((1, RC.udp_frame(RC.discovery_publication(RC.type_object(els, tids[0])))))
    mal.append((1, RC.udp_frame(RC.meta_group_data(b'\0' * 8))))
    # nested type ids (PID_TYPE_INFORMATION): one frame deep enough to hit the tree depth limit
    val = struct.pack('<III', 0, 0, 0) + bytes([0x80, 0, 0, 0, 1]) * 12000 + b'\x01\0\0\0\0'
    par = struct.pack('<HH', 0x75, 12) + val + b'\0' * ((-len(val)) % 4)
    mal.append((1, udp_frame(RC.rtps_header() + RC.data_submsg(0x000003c2, struct.pack('>HH', 3, 0) + par + struct.pack('<HH', 1, 0)))))


def build_mal_submsgs():
    """Submessages that are too short for their kind, with the E flag set and clear."""
    for ver, le in (((2, 3), True), ((2, 3), False), ((1, 2), True)):
        items = []
        for sid in SUBIDS:
            for flags in (0x00, 0x0e):
                for n in (0, 4, 12, 20):
                    items.append(sm(sid, flags, b'\0' * n, le))
        for i in range(0, len(items), 6):
            mal.append((1, udp_frame(hdr(ver, 0x0101) + b''.join(items[i:i + 6]))))


if __name__ == '__main__':
    basic()
    data_forms()
    types_user()
    xtypes()
    services()
    status_and_locators()
    batches_and_more()
    extras()
    reproducers()
    build_pid_sweeps()
    build_submsg_sweeps()
    build_mal_submsgs()
    if ts.crashed:
        print('%d candidate frames crashed or ran out of memory (see crashed.pcap)' % len(ts.crashed))
        pcap_write(os.path.join(OUT, 'crashed.pcap'), ts.crashed)
    os.makedirs(OUT, exist_ok=True)
    pcapng_write(os.path.join(OUT, 'rtps-coverage.pcapng'), main)
    pcapng_write(os.path.join(OUT, 'rtps-coverage-malformed.pcapng'), mal)
    if VERBOSE:
        for n, a, b in marks:
            print('%5d-%5d %s' % (a, b, n))
    print('main %d frames, malformed %d frames' % (len(main), len(mal)))
