# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Minimal ALIGNED PER encoder (enough for T.124 / T.125 test packets)
class W:
    def __init__(s): s.b = []
    def bit(s, v): s.b.append(1 if v else 0)
    def bits(s, v, n):
        for i in reversed(range(n)): s.b.append((v >> i) & 1)
    def align(s):
        while len(s.b) % 8: s.b.append(0)
    def octets(s, d):
        s.align()
        for x in d: s.bits(x, 8)
    def bytes(s):
        b = list(s.b)
        while len(b) % 8: b.append(0)
        return bytes(int(''.join(map(str, b[i:i+8])), 2) for i in range(0, len(b), 8))
    # lengths and integers
    def length(s, n):
        s.align()
        if n < 128: s.bits(n, 8)
        elif n < 16384: s.bits(0x8000 | n, 16)
        else: raise ValueError('fragmentation not supported')
    def con_int(s, v, lo, hi):
        r = hi - lo + 1
        v -= lo
        assert 0 <= v < r, (v, lo, hi)
        if r == 1: return
        if r <= 255: s.bits(v, (r - 1).bit_length())
        elif r == 256: s.align(); s.bits(v, 8)
        elif r <= 65536: s.align(); s.bits(v, 16)
        else:
            n = max(1, (v.bit_length() + 7) // 8)
            maxn = ((r - 1).bit_length() + 7) // 8
            s.bits(n - 1, (maxn - 1).bit_length())
            s.align(); s.bits(v, 8 * n)
    def uint(s, v, lo=0):
        """semi-constrained INTEGER(lo..MAX)"""
        v -= lo
        n = max(1, (v.bit_length() + 7) // 8)
        s.length(n); s.bits(v, 8 * n)
    def sint(s, v):
        """unconstrained INTEGER"""
        n = 1
        while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))): n += 1
        s.length(n); s.bits(v & ((1 << (8 * n)) - 1), 8 * n)
    def clen(s, n, lo, hi):
        if hi is not None and hi < 65536: s.con_int(n, lo, hi)
        else: s.length(n)
    def boolean(s, v): s.bit(v)
    def enum(s, idx, n, ext=False, extidx=False):
        """ENUMERATED with n root values; ext: extensible"""
        if ext: s.bit(extidx)
        if extidx: s.length_small(idx); return
        s.con_int(idx, 0, n - 1)
    def length_small(s, n):          # normally small non-negative whole number
        if n < 64: s.bit(0); s.bits(n, 6)
        else: raise ValueError
    def choice(s, idx, n, ext=False, extidx=False):
        if ext: s.bit(extidx)
        if extidx: s.length_small(idx); return
        s.con_int(idx, 0, n - 1)
    def octstr(s, d, lo=None, hi=None):
        if lo is not None and lo == hi:
            if lo > 2: s.octets(d)
            else:
                for x in d: s.bits(x, 8)
            return
        if lo is None: s.length(len(d))
        else: s.clen(len(d), lo, hi)
        s.octets(d)
    def oid(s, dotted):
        a = [int(x) for x in dotted.split('.')]
        out = bytes([a[0] * 40 + a[1]])
        for x in a[2:]:
            e = [x & 0x7f]; x >>= 7
            while x: e.append(0x80 | (x & 0x7f)); x >>= 7
            out += bytes(reversed(e))
        s.length(len(out)); s.octets(out)
    def numeric(s, text, lo, hi):
        s.clen(len(text), lo, hi)
        if hi * 4 > 16: s.align()
        for c in text: s.bits(int(c), 4)
    def bmp(s, text, lo, hi):
        s.clen(len(text), lo, hi)
        if hi * 16 > 16: s.align()
        for c in text: s.bits(ord(c), 16)
    def opentype(s, sub):
        s.length(len(sub)); s.octets(sub)
    def ext_additions(s, adds):
        """adds: list of bytes (open type contents) or None for absent additions"""
        n = len(adds)
        s.length_small(n - 1)
        for a in adds: s.bit(a is not None)
        for a in adds:
            if a is not None: s.opentype(a)
