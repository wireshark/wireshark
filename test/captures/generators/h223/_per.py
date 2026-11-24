# Helper module for the h223 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal aligned PER bit writer, enough to build the H.245 and H.225
messages of the coverage captures by hand (no ASN.1 compiler)."""

class PW:
    def __init__(self):
        self.bits = []
    def put(self, v, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((v >> i) & 1)
        return self
    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)
        return self
    def flag(self, b):
        return self.put(1 if b else 0, 1)
    def octets(self, data):
        self.align()
        for b in data:
            self.put(b, 8)
        return self
    def cint(self, v, lo, hi):
        """constrained whole number lo..hi"""
        r = hi - lo + 1
        v -= lo
        assert 0 <= v < r, (v, lo, hi)
        if r == 1:
            return self
        if r <= 255:
            return self.put(v, (r - 1).bit_length())
        if r == 256:
            self.align(); return self.put(v, 8)
        if r <= 65536:
            self.align(); return self.put(v, 16)
        n = max(1, (v.bit_length() + 7) // 8)
        maxn = ((r - 1).bit_length() + 7) // 8
        self.cint(n, 1, maxn)
        self.align()
        return self.put(v, 8 * n)
    def uint(self, v):
        """semi-constrained / unconstrained non-negative: length + octets"""
        n = max(1, (v.bit_length() + 7) // 8)
        self.length(n)
        return self.put(v, 8 * n)
    def length(self, n):
        """unconstrained length determinant (< 16384)"""
        self.align()
        if n < 128:
            return self.put(n, 8)
        return self.put(0x8000 | n, 16)
    def choice(self, idx, nroot, ext=False, extalt=False):
        """CHOICE with nroot root alternatives; ext = type is extensible."""
        if ext:
            self.flag(extalt)
        if extalt:
            return self.small(idx)
        return self.cint(idx, 0, nroot - 1)
    def small(self, n):
        """normally small non-negative whole number"""
        assert n < 64
        return self.put(n, 7)
    def seqext(self, ext=False):
        return self.flag(ext)
    def bytes(self):
        self.align()
        return bytes(int(''.join(map(str, self.bits[i:i + 8])), 2) for i in range(0, len(self.bits), 8))
    def copy_from(self, other):
        """append another (open type) encoding"""
        pass

def open_type(data):
    """length determinant + octets (used for extension additions)"""
    p = PW(); p.length(len(data)); p.octets(data)
    return p
