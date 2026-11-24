#!/usr/bin/env python3
# Generates test/captures/xti_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
# Synthetic XTI (Eurex T7 / Xetra, "Enhanced Cash Trading Interface") capture.
# Usage: mkxti.py <outdir>
# The generator reads the field, usage and template tables out of
# packet-xti.c and walks them the way the dissector does, so every
# message it builds in the main capture is valid for its template.
import struct
import re
import sys
import random
random.seed(38)
SRC = os.environ.get('XTI_C', os.path.join(SRCDIR, 'epan/dissectors/packet-xti.c'))
src = open(SRC).read()
lines = src.split('\n')

def block(pat):
    i = next(k for k, l in enumerate(lines) if re.search(pat, l))
    j = i + 1
    while lines[j].strip() != '};':
        j += 1
    return '\n'.join(lines[i + 1:j])

def ints(b):
    return [int(x) for x in re.findall(r'-?\d+', re.sub(r'/\*.*?\*/', '', re.sub(r'//.*', '', b)))]

enum = re.search(r'enum Field_Handle_Index \{(.*?)\};', src, re.S).group(1)
fh = {n.strip(): k for k, n in enumerate([x for x in re.sub(r'//.*', '', enum).split(',') if x.strip()])}
types = re.search(r'enum ETI_Type \{(.*?)\};', src, re.S)
TN = [x.strip() for x in re.sub(r'//.*', '', types.group(1)).split(',') if x.strip()]
F = []
for m in re.finditer(r'\{\s*(ETI_\w+),\s*(\d+),\s*(\d+),\s*(\w+),\s*(\d+)\s*\}',
                     block(r'static const struct ETI_Field fields')):
    t, c, s, h, e = m.groups()
    F.append((t, int(c), int(s), int(h) if h.isdigit() else fh[h], int(e)))
TF = ints(block(r'tid2fidx\[\]'))
TU = ints(block(r'tid2uidx\[\]'))
US = ints(block(r'usages\[\]'))
TS = ints(block(r'tid2size\[818\]'))
TIDS = [10000 + i for i in range(818) if TF[i] != -1]

# value helpers -------------------------------------------------------
def nov_uint(sz):
    return b'\xff' * sz
def nov_int(sz):
    return b'\x00' * (sz - 1) + b'\x80'

class Gen:
    '''Walk a template like dissect_xti_message and emit its bytes.
    mode: counter policy: 'one', 'zero', 'mid', 'max', 'nov' (0xff).
    usage: 'ok' honours the usage table (no missing/overused warnings),
    'missing' sends NO_VALUE everywhere, 'overused' sets everything.'''
    def __init__(self, tid, mode='one', usage='ok', seed=0, neg=False):
        self.tid, self.mode, self.usage, self.neg = tid, mode, usage, neg
        self.rng = random.Random(tid * 7 + seed)
    def counter_value(self, mx):
        m = self.mode
        if m == 'zero': return 0
        if m == 'one': return min(1, mx)
        if m == 'mid': return min(2 + self.rng.randrange(3), mx)
        if m == 'max': return mx
        if m == 'over': return mx + 1 if mx + 1 < 255 or (mx > 255 and mx < 65534) else mx
        return mx
    def build(self):
        tid = self.tid
        fidx = TF[tid - 10000]; uidx = TU[tid - 10000]
        out = bytearray(); counter = [0] * 8
        top = 1; old_f = old_u = 0; repeats = 0
        n = 0
        while top:
            t, c, s, h, e = F[fidx]
            if t == 'ETI_EOF':
                if repeats:
                    repeats -= 1; fidx = F[old_f][3]; uidx = old_u
                else:
                    fidx = old_f + 1; top -= 1
            elif t in ('ETI_STRUCT', 'ETI_VAR_STRUCT'):
                repeats = counter[c] if t == 'ETI_VAR_STRUCT' else 1
                if repeats:
                    repeats -= 1; old_f = fidx; old_u = uidx; fidx = h; top += 1
                else:
                    fidx += 1
            elif t == 'ETI_PADDING':
                out += b'\0' * s; fidx += 1
            else:
                u = US[uidx]; n += 1
                if self.usage == 'missing': u = 0; sent = True
                elif self.usage == 'overused': u = 1; sent = False
                else: sent = (u == 2)
                if self.usage == 'overused': ovr = True
                else: ovr = False
                if t == 'ETI_CHAR':
                    out += bytes([65 + n % 26]) * s
                elif t == 'ETI_STRING':
                    if sent and not ovr: out += b'\0' * s
                    else:
                        txt = (b'S%d_' % (n % 97)) * 8
                        out += txt[:s - (n % 3)].ljust(s, b'\0')
                elif t == 'ETI_VAR_STRING':
                    out += bytes(97 + (k % 26) for k in range(counter[c]))
                elif t == 'ETI_COUNTER':
                    if self.mode == 'nov':
                        out += nov_uint(s); counter[c] = 0
                    else:
                        v = self.counter_value(e)
                        out += v.to_bytes(s, 'little')
                        counter[c] = min(v, e)
                elif t == 'ETI_UINT':
                    out += nov_uint(s) if sent else ((n * 37 + 1) % (256 ** min(s, 2) - 2)).to_bytes(s, 'little')
                elif t == 'ETI_INT':
                    if sent: out += nov_int(s)
                    else:
                        v = (n * 11 + 3) % 120
                        if self.neg or n % 5 == 0: v = -v
                        out += struct.pack('<q', v)[:s]
                elif t in ('ETI_UINT_ENUM', 'ETI_INT_ENUM'):
                    out += ((n % 3) + 1).to_bytes(s, 'little')
                elif t == 'ETI_FIXED_POINT':
                    if sent: out += nov_int(8)
                    else:
                        v = 12345 * 10 ** (c - 3) + n if c >= 3 else 12345 + n
                        if self.neg or n % 4 == 0: v = -v
                        if n % 7 == 0: v = 5          # shorter than the fraction
                        out += struct.pack('<q', v)
                elif t == 'ETI_TIMESTAMP_NS':
                    out += struct.pack('<Q', 1700000000000000000 + n * 1000000007)
                elif t == 'ETI_DSCP':
                    out += bytes([(n % 8) << 4])
                fidx += 1; uidx += 1
        return bytes(out)

def message(tid, **kw):
    None
    b = bytearray(Gen(tid, **kw).build())
    if not kw.get('raw'):
        # trailing pad: 8-byte alignment and at least the minimum BodyLen
        lo, hi = TS[2 * (tid - 10000)], TS[2 * (tid - 10000) + 1]
        want = max(lo, (len(b) + 7) // 8 * 8)
        b += b'\0' * (min(want, hi) - len(b)) if want > len(b) else b''
    struct.pack_into('<IHH', b, 0, len(b), tid, 0) if len(b) >= 8 else None
    return bytes(b)

def bodylen_ok(tid, n):
    lo, hi = TS[2 * (tid - 10000)], TS[2 * (tid - 10000) + 1]
    return lo <= n <= hi

# packet writer -------------------------------------------------------
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff

class Conn:
    def __init__(self, pk, sport, dport=19042, cip=(192, 0, 2, 1), sip=(192, 0, 2, 2)):
        self.pk = pk; self.sport = sport; self.dport = dport
        self.cip = bytes(cip); self.sip = bytes(sip)
        self.seq = {0: 1000, 1: 5000}; self.n = 0
        self.raw(0, b'', 0x02); self.raw(1, b'', 0x12); self.raw(0, b'', 0x10)
    def raw(self, d, payload, flags=0x18):
        self.n += 1
        sp, dp = (self.sport, self.dport) if d == 0 else (self.dport, self.sport)
        a, b = (self.cip, self.sip) if d == 0 else (self.sip, self.cip)
        opt = b'\x02\x04\x05\xb4' if flags & 2 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], self.seq[1 - d] if flags & 0x10 else 0,
                          0x50 + len(opt) // 4 * 16, flags, 65535, 0, 0) + opt
        syn = 1 if flags & 3 else 0
        self.seq[d] += len(payload) + syn
        tot = 20 + len(tcp) + len(payload)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, self.n, 0, 64, 6, 0, a, b)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pk.append(b'\x02\0\0\0' + ip + tcp + payload)
    def send(self, payload, d=0):
        self.raw(d, payload)

def write(path, pkts, ts0=1700000000):
    with open(path, 'wb') as fo:
        fo.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 0))  # DLT_NULL
        for k, p in enumerate(pkts):
            fo.write(struct.pack('<IIII', ts0 + k // 10, (k % 10) * 1000, len(p), len(p)) + p)

def main(outdir):
    # ---- main capture: valid traffic only
    pk = []
    c = Conn(pk, 40000)
    for t in TIDS:                              # frames: one repeat of each group
        c.send(message(t, mode='one'), d=t % 2)
    for t in TIDS:                              # no group entries
        c.send(message(t, mode='zero'), d=t % 2)
    for t in TIDS:                              # a few entries, negative numbers
        c.send(message(t, mode='mid', neg=True, seed=1), d=1 - t % 2)
    for t in TIDS:                              # every group at its maximum
        c.send(message(t, mode='max', seed=2), d=t % 2)
    # several PDUs in one segment, and a PDU split over segments
    c2 = Conn(pk, 40001)
    three = [message(t, mode='one') for t in TIDS[:3]]
    c2.send(b''.join(three))
    big = max((message(t, mode='max') for t in TIDS), key=len)
    c2.send(big[:2]); c2.send(big[2:5]); c2.send(big[5:len(big) // 2]); c2.send(big[len(big) // 2:])
    m = message(TIDS[10], mode='mid')
    c2.send(m + big[:30]); c2.send(big[30:] + message(TIDS[11], mode='one'))
    write(os.path.join(outdir, 'xti-coverage.pcap'), pk)

    # ---- malformed capture: expert infos, exceptions
    pk = []
    c = Conn(pk, 40002)
    for t in TIDS:
        c.send(message(t, mode='one', usage='missing'))     # required values missing
    for t in TIDS:
        c.send(message(t, mode='one', usage='overused'))    # unused values set
    for t in TIDS:
        c.send(message(t, mode='nov'))                      # counters 0xff (NO_VALUE)
    for t in TIDS:
        c.send(message(t, mode='over'))                     # counter overflow
    for t in TIDS[::3]:
        c.send(message(t, mode='max', usage='missing', neg=True))
    # bad template IDs, bad lengths
    c.send(struct.pack('<IHH', 8, 9999, 0))
    c.send(struct.pack('<IHH', 8, 10818, 0))
    c.send(struct.pack('<IHH', 8, 10900, 0))
    unalloc = next(10000 + i for i in range(818) if TF[i] == -1)
    c.send(struct.pack('<IHH', 8, unalloc, 0))
    VAR = [t for t in TIDS if TS[2 * (t - 10000)] != TS[2 * (t - 10000) + 1]]
    for t in TIDS[:4] + VAR[:4]:
        lo, hi = TS[2 * (t - 10000)], TS[2 * (t - 10000) + 1]
        c.send(struct.pack('<IHH', 8, t, 0) + b'\0' * 8 if lo > 16 else struct.pack('<IHH', 8, t, 0))
        if lo != hi:
            n = hi + 8
            c.send(struct.pack('<IHH', n, t, 0) + b'\0' * (n - 8))   # too long, exceptions or not
        else:
            n = lo + 8
            c.send(struct.pack('<IHH', n, t, 0) + b'\0' * (n - 8))
    c.send(struct.pack('<IHH', 13, TIDS[0], 0) + b'\0' * 5)          # unaligned
    c.send(struct.pack('<IHH', 6, TIDS[0], 0)[:6])                   # BodyLen below the header
    # truncated: BodyLen shorter than the template needs
    for t in TIDS[:20]:
        m = message(t, mode='max')
        n = max(8, (len(m) // 2) // 8 * 8)
        c.send(struct.pack('<IHH', n, t, 0) + m[8:n])
    write(os.path.join(outdir, 'xti-coverage-malformed.pcap'), pk)

if __name__ == '__main__':
    main(sys.argv[1])
