#!/usr/bin/env python3
# Generates test/captures/eti_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the ETI (Enhanced Trading Interface 10.0) coverage captures.
Usage: mketi.py <outdir> [<packet-eti.c>].  Everything is synthetic.

packet-eti.c is generated from the ETI protocol descriptions.  Its tables
(template id to field list, field usages, enumeration value strings) are
parsed here and the walk of dissect_eti_message() is replayed to build one
well-formed message for every template, so that the capture follows the
dissector exactly instead of repeating the protocol description by hand."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys
import random

SRC = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/packet-eti.c')
src = open(SRC).read()

# ------------------------------------------------------------------ tables
T = {n: i for i, n in enumerate(['EOF', 'PADDING', 'UINT', 'INT', 'UINT_ENUM', 'INT_ENUM', 'COUNTER', 'FIXED_POINT',
                                 'TIMESTAMP_NS', 'CHAR', 'STRING', 'VAR_STRING', 'STRUCT', 'VAR_STRUCT', 'DSCP'])}
Tn = {v: k for k, v in T.items()}
assert re.search(r'enum ETI_Type \{(.*?)\};', src, re.S).group(1).split() == \
    ['ETI_EOF,', 'ETI_PADDING,', 'ETI_UINT,', 'ETI_INT,', 'ETI_UINT_ENUM,', 'ETI_INT_ENUM,', 'ETI_COUNTER,',
     'ETI_FIXED_POINT,', 'ETI_TIMESTAMP_NS,', 'ETI_CHAR,', 'ETI_STRING,', 'ETI_VAR_STRING,', 'ETI_STRUCT,',
     'ETI_VAR_STRUCT,', 'ETI_DSCP'], 'ETI_Type enum changed'

def block(name, start_pat):
    m = re.search(start_pat + r'\s*=\s*\{(.*?)\n\s*\};', src, re.S)
    return m.group(1)

fields = []
for t, co, sz, fh, ett in re.findall(r'\{ ETI_(\w+), (\d+), (\d+), (\w+), (\d+) \}',
                                      block('fields', r'static const struct ETI_Field fields\[\]')):
    fields.append((T[t], int(co), int(sz), fh, int(ett)))
tid2fidx = [int(x) for x in re.findall(r'(-?\d+)(?: /\*[^*]*\*/)?\s*(?:,|$)', block('t', r'static const int16_t tid2fidx\[\]').replace('\n', ' ,'))]
tid2fidx = [int(m) for m in re.findall(r'(?:^|,)\s*(-?\d+)', block('t', r'static const int16_t tid2fidx\[\]').replace('\n', '\n,'))]
tid2uidx = [int(m) for m in re.findall(r'(?:^|,)\s*(-?\d+)', block('t', r'static const int16_t tid2uidx\[\]').replace('\n', '\n,'))]
tid2size = [(int(a), int(b)) for a, b in re.findall(r'\{\s*(\d+),\s*(\d+)\s*\}', block('t', r'static const uint32_t tid2size\[720\]\[2\]'))]
usages = [int(m) for m in re.findall(r'(?:^|,)\s*(\d)\s*//', block('t', r'static const unsigned char usages\[\]').replace('\n', '\n,'))]
tnames = {int(a): b for a, b in re.findall(r'\{ (\d+), "([^"]*)" \}', re.search(r'template_id_vals\[\] = \{(.*?)\};', src, re.S).group(1))}
struct_names = re.search(r'struct_names\[\] = "(.*?)";', src).group(1).split('\\0')
assert len(tid2fidx) == 720 and len(tid2uidx) == 720 and len(tid2size) == 720, (len(tid2fidx), len(tid2uidx), len(tid2size))

# value strings and the hf information of every field handle
vals = {}
for name, body in re.findall(r'static const value_string (\w+)\[\] = \{(.*?)\};', src, re.S):
    vals[name] = [(int(v, 0), s) for v, s in re.findall(r'\{\s*(0x[0-9A-Fa-f]+|\d+),\s*"([^"]*)"\s*\}', body)]
hf = {}
for fh, ft, vs in re.findall(r'\{ &hf_eti\[(\w+)\],\s*\{ "[^"]*", "[^"]*",\s*(FT_\w+), [\w| ]+, (&?\w+(?:\(\w+\))?),', src):
    if vs.startswith('VALS('):
        vn = vs[5:-1]
    elif vs.startswith('&') and vs.endswith('_ext'):
        vn = vs[1:-4]
    else:
        vn = None
    hf[fh] = (ft, vn)

def enum_values(fh, size, signed):
    ft, vn = hf[fh]
    if not vn or vn not in vals:
        return []
    out = [v for v, s in vals[vn] if s != 'NO_VALUE' and s != 'NULL']
    return out

# ------------------------------------------------------------------ message builder
class Opts:
    def __init__(self, **kw):
        self.optional = True       # set optional (usage 1) fields
        self.counter = 'two'       # 'zero', 'one', 'two', 'max', 'novalue'
        self.extra = 0
        self.misuse = None         # 'missing' / 'overused' / 'overflow'
        self.__dict__.update(kw)

def no_value(typ, size):
    if typ in (T['UINT'], T['COUNTER']):
        return b'\xff' * size
    if typ in (T['INT'], T['FIXED_POINT']):
        return b'\x00' * (size - 1) + b'\x80'
    raise ValueError

def build(tid, o, seed=0):
    rnd = random.Random(tid * 1000 + seed)
    fidx = tid2fidx[tid - 10000]
    uidx = tid2uidx[tid - 10000]
    body = bytearray()
    counter = [0] * 8
    top = 1; old_fidx = 0; old_uidx = 0; repeats = 0
    k = [0]
    def nxt():
        k[0] += 1
        return k[0]
    misused = [False]
    while top:
        typ, co, sz, fh, ett = fields[fidx]
        if typ == T['EOF']:
            if repeats:
                repeats -= 1
                fidx = fields[old_fidx][3] if isinstance(fields[old_fidx][3], int) else int(fields[old_fidx][3])
                uidx = old_uidx
            else:
                fidx = old_fidx + 1
                top -= 1
        elif typ in (T['STRUCT'], T['VAR_STRUCT']):
            repeats = counter[co] if typ == T['VAR_STRUCT'] else 1
            if repeats:
                repeats -= 1
                old_fidx = fidx; old_uidx = uidx
                fidx = int(fh)
                top += 1
            else:
                fidx += 1
        elif typ == T['PADDING']:
            body += b'\0' * sz
            fidx += 1
        else:
            u = usages[uidx]
            use = u == 0 or (u == 1 and o.optional)
            if o.misuse == 'missing' and u == 0 and not misused[0] and len(body) > 24 and typ in (T['UINT'], T['INT'], T['STRING']):
                use = False; misused[0] = True
            if o.misuse == 'all':
                use = u != 0
                if u == 2: use = True
            if o.misuse == 'overused' and u == 2 and not misused[0] and typ in (T['UINT'], T['INT']):
                use = True; misused[0] = True
            n = nxt()
            if typ == T['CHAR']:
                vs = enum_values(fh, sz, False)
                body += bytes([vs[n % len(vs)] if vs else 0x41 + n % 26])
            elif typ == T['STRING']:
                if use:
                    s = ('S%d_%s' % (n, fh[:6])).encode()[:sz]
                    body += s + b'\0' * (sz - len(s))
                else:
                    body += b'\0' * sz
            elif typ == T['VAR_STRING']:
                body += ('v%d' % n * 10).encode()[:counter[co]].ljust(counter[co], b'x')
            elif typ == T['COUNTER']:
                m = ett
                mode = o.counter
                if mode == 'novalue':
                    c = None
                elif mode == 'zero': c = min(o.extra, m)
                elif mode == 'one': c = min(1 + o.extra, m)
                elif mode == 'two': c = min(2 + o.extra, m)
                elif mode == 'max': c = m
                if o.misuse == 'overflow' and not misused[0] and m < (255 if sz == 1 else 65534):
                    c = m + 1; misused[0] = True
                    counter[co] = m
                    body += struct.pack('<B' if sz == 1 else '<H', c)
                elif c is None:
                    counter[co] = 0
                    body += b'\xff' * sz
                else:
                    counter[co] = c
                    body += struct.pack('<B' if sz == 1 else '<H', c)
            elif typ == T['UINT']:
                if not use:
                    body += no_value(typ, sz)
                else:
                    mx = 1 << (8 * sz)
                    v = (n * 37 + 1) % (min(mx - 2, 1000000))
                    if sz == 8 and n % 5 == 0:
                        v = (1 << 40) + n
                    body += v.to_bytes(sz, 'little')
            elif typ == T['INT']:
                if not use:
                    body += no_value(typ, sz)
                else:
                    v = (n * 37 + 1) % (min(1 << (8 * sz - 1), 1000000))
                    if n % 3 == 0:
                        v = -v
                    body += v.to_bytes(sz, 'little', signed=True)
            elif typ in (T['UINT_ENUM'], T['INT_ENUM']):
                vs = enum_values(fh, sz, typ == T['INT_ENUM'])
                v = vs[n % len(vs)] if vs else 1
                if not use and vs:
                    nv = [x for x, s in vals[hf[fh][1]] if s == 'NO_VALUE']
                    if nv: v = nv[0]
                body += (v & ((1 << (8 * sz)) - 1)).to_bytes(sz, 'little')
            elif typ == T['FIXED_POINT']:
                if not use:
                    body += no_value(typ, sz)
                else:
                    v = n * 123456789
                    if n % 4 == 0:
                        v = -v
                    if n % 7 == 0:
                        v = (n % 5) + 1        # fewer digits than the decimals
                    body += struct.pack('<q', v)
            elif typ == T['TIMESTAMP_NS']:
                body += struct.pack('<Q', 1700000000_000000000 + n * 1000003) if use or True else b''
            elif typ == T['DSCP']:
                body += bytes([(0x01, 0x02, 0x04, 0x07, 0x00)[n % 5] | (0)])
            else:
                raise ValueError(typ)
            fidx += 1
            uidx += 1
    # BodyLen (first field, 4 octets) and TemplateID (2 octets)
    body[0:4] = struct.pack('<I', len(body))
    body[4:6] = struct.pack('<H', tid)
    return bytes(body)

def build_aligned(tid, **kw):
    """Like build() but adds to the counters until the body length is a multiple of 8
    (variable length strings)."""
    for extra in range(8):
        m = build(tid, Opts(extra=extra, **kw))
        if len(m) % 8 == 0 and tid2size[tid - 10000][0] <= len(m) <= tid2size[tid - 10000][1]:
            return m
    return None

# ------------------------------------------------------------------ packets
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

class Flow:
    def __init__(self, port, n):
        self.cport = 40000 + n; self.sport = port
        self.cip = bytes([192, 0, 2, 1]); self.sip = bytes([192, 0, 2, 2])
        self.cseq = 1000; self.sseq = 5000
        self.ident = 1
        self.pkts = []
        self.syn()
    def seg(self, c2s, flags, payload=b'', seq=None, ack=None, off=0):
        if c2s:
            sip, dip, sp, dp = self.cip, self.sip, self.cport, self.sport
            seq = self.cseq if seq is None else seq; ack = self.sseq if ack is None else ack
            eth = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1])
        else:
            sip, dip, sp, dp = self.sip, self.cip, self.sport, self.cport
            seq = self.sseq if seq is None else seq; ack = self.cseq if ack is None else ack
            eth = bytes([2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2])
        hdr = 5
        opts = b''
        if flags & 0x02:
            opts = struct.pack('!BBHBBBB', 2, 4, 1460, 1, 1, 4, 2); hdr = 7
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0, hdr << 4, flags, 65535, 0, 0) + opts + payload
        ph = sip + dip + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ident, 0x4000, 64, 6, 0, sip, dip)
        self.ident += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pkts.append(eth + b'\x08\x00' + ip + tcp)
    def syn(self):
        self.seg(True, 0x02); self.cseq += 1
        self.seg(False, 0x12); self.sseq += 1
        self.seg(True, 0x10)
    def data(self, c2s, stream, mss=1400, sizes=None):
        """stream: concatenated messages; cut into segments."""
        i = 0; j = 0
        while i < len(stream):
            n = (sizes[j % len(sizes)] if sizes else mss); j += 1
            chunk = stream[i:i + n]; i += n
            self.seg(c2s, 0x18, chunk)
            if c2s: self.cseq += len(chunk)
            else: self.sseq += len(chunk)
    def ack(self, c2s):
        self.seg(c2s, 0x10)
    def fin(self):
        self.seg(True, 0x11); self.cseq += 1
        self.seg(False, 0x11); self.sseq += 1
        self.seg(True, 0x10)

def write_pcap(name, pkts):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

valid = [t for t in range(10000, 10720) if tid2fidx[t - 10000] != -1]
PORTS = (19006, 19043, 19506, 19543)

def is_request(t):
    return tnames[t].endswith('Request') or 'Request' in tnames[t][-12:] or tnames[t].startswith(('Logon', 'Subscribe')) and t % 2 == 0

def capture(msgs_by_flow, mss=1400, sizes=None):
    """msgs_by_flow: {port: (c2s_messages, s2c_messages)}"""
    pk = []
    for n, (port, (c2s, s2c)) in enumerate(msgs_by_flow.items()):
        fl = Flow(port, n)
        if c2s: fl.data(True, b''.join(c2s), mss, sizes)
        if s2c: fl.data(False, b''.join(s2c), mss, sizes)
        fl.ack(True)
        pk += fl.pkts
    return pk

if __name__ == '__main__':
    out = sys.argv[1]
    # ---- main capture: variant A (all optional fields set, groups of two) for every template,
    # variant B (no optional fields, empty groups) and a few special ones
    flows = {p: ([], []) for p in PORTS}
    nmsg = 0
    seen = set()
    def put(m, t, shift=0):
        global nmsg
        if m is None or m in seen:
            return
        seen.add(m)
        flows[PORTS[(t + shift) % 4]][t % 2].append(m)
    for t in valid:
        m = build_aligned(t)
        assert m is not None, (t, tnames[t])
        put(m, t)
    for t in valid:
        put(build_aligned(t, optional=False, counter='zero'), t, 1)
    for t in valid:
        for mode in ('max', 'novalue', 'one'):
            mm = build_aligned(t, counter=mode)
            if mm is not None and len(mm) < 6000 and (t % 9 == 0 or mode == 'novalue' and t % 11 == 0):
                put(mm, t, 2)
    nmsg = len(seen)
    main = capture(flows)
    write_pcap(os.path.join(out, 'eti-coverage.pcap'), main)
    print('main', len(main), 'frames', nmsg, 'messages')

    # ---- malformed capture
    bad_flows = {p: ([], []) for p in PORTS}
    badl = []
    def add(m, i=0):
        bad_flows[PORTS[i % 4]][0].append(m)
    # reproducers / errors
    t0 = valid[0]
    # templates with a missing, an overused value, a counter overflow
    for i, t in enumerate(valid[:400:3]):
        for mis in ('missing', 'overused', 'overflow'):
            mm = build(t, Opts(misuse=mis))
            add(mm, i)
    for i, t in enumerate(valid):
        mm = build_aligned(t, misuse='all')
        if mm is not None:
            add(mm, i)
    # wrong length, unaligned length, unallocated and out of range template ids
    t = valid[3]
    m = bytearray(build(t, Opts()))
    short = bytearray(m[:-8]); short[0:4] = struct.pack('<I', len(short)); add(bytes(short))
    longm = bytearray(m + bytes(8)); longm[0:4] = struct.pack('<I', len(longm)); add(bytes(longm))
    for t2 in valid[:40]:
        if tid2size[t2 - 10000][0] != tid2size[t2 - 10000][1]:
            m2 = bytearray(build(t2, Opts()))
            m2 += bytes(8); m2[0:4] = struct.pack('<I', len(m2)); add(bytes(m2)); break
    un = bytearray(build(t, Opts()) + b'\0' * 3); un[0:4] = struct.pack('<I', len(un)); add(bytes(un))
    for tt in (9999, 10720, 10004, 20000, 0, 65535):
        mm = bytearray(build(t, Opts())); mm[4:6] = struct.pack('<H', tt); add(bytes(mm))
    unalloc = [t for t in range(10000, 10720) if tid2fidx[t - 10000] == -1][:6]
    for tt in unalloc:
        mm = bytearray(build(t, Opts())); mm[4:6] = struct.pack('<H', tt); add(bytes(mm))
    # truncated bodies (body length claims less than the template walks)
    for t2 in valid[::17]:
        mm = bytearray(build(t2, Opts()))
        cut = len(mm) // 2 // 8 * 8
        if cut >= 8:
            mm = mm[:cut]; mm[0:4] = struct.pack('<I', len(mm)); add(bytes(mm), 1)
    # all fields 0xff / all zero / random for a number of templates
    rnd = random.Random(7)
    for t2 in valid[::13]:
        mm = bytearray(build(t2, Opts()))
        for fill in (b'\xff', b'\x00'):
            x = bytearray(fill * len(mm)); x[0:4] = struct.pack('<I', len(mm)); x[4:6] = struct.pack('<H', t2); add(bytes(x), 2)
        x = bytearray(rnd.getrandbits(8) for _ in range(len(mm))); x[0:4] = struct.pack('<I', len(mm)); x[4:6] = struct.pack('<H', t2); add(bytes(x), 3)
    badc = capture(bad_flows)
    write_pcap(os.path.join(out, 'eti-coverage-malformed.pcap'), badc)
    print('malformed', len(badc))
