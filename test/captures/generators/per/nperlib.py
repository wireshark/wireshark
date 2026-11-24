# Helper module for the per capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Minimal aligned-PER writer used by mkngap.py (only what NGAP needs).
class W:
    def __init__(self):
        self.b = []          # list of bits
    def bits(self, v, n):
        for i in range(n - 1, -1, -1):
            self.b.append((v >> i) & 1)
        return self
    def bit(self, v):
        return self.bits(1 if v else 0, 1)
    def align(self):
        while len(self.b) % 8:
            self.b.append(0)
        return self
    def octets(self, data):
        self.align()
        for x in data:
            self.bits(x, 8)
        return self
    def length(self, n):
        self.align()
        if n < 128:
            self.bits(n, 8)
        else:
            self.bits(0x8000 | n, 16)
        return self
    def cint(self, v, lo, hi):
        """Constrained whole number."""
        rng = hi - lo + 1
        v -= lo
        if rng == 1:
            return self
        if rng <= 255:
            return self.bits(v, (rng - 1).bit_length())
        if rng == 256:
            self.align(); return self.bits(v, 8)
        if rng <= 65536:
            self.align(); return self.bits(v, 16)
        nbytes = max(1, (v.bit_length() + 7) // 8)
        maxb = (rng - 1).bit_length() + 7 >> 3
        self.bits(nbytes - 1, (maxb - 1).bit_length())
        self.align()
        return self.bits(v, nbytes * 8)
    def enum(self, idx, nroot, ext=True, extidx=None):
        if ext:
            if extidx is not None:
                self.bit(1)
                # normally small number: 1 bit 0 + 6 bits
                return self.bits(extidx, 7)
            self.bit(0)
        return self.cint(idx, 0, nroot - 1)
    def choice(self, idx, nalt, ext=False):
        if ext:
            self.bit(0)
        return self.cint(idx, 0, nalt - 1)
    def ostr(self, data, lo=None, hi=None):
        if lo is not None and lo == hi:
            if lo > 2:
                self.align()
            for x in data:
                self.bits(x, 8)
            return self
        if lo is None:
            self.length(len(data))
        else:
            self.cint(len(data), lo, hi)
        return self.octets(data) if len(data) else self
    def bstr(self, value, nbits, lo=None, hi=None, ext=False):
        """BIT STRING: value is an int of nbits bits."""
        if ext:
            self.bit(0)
        if lo is not None and lo == hi:
            if nbits > 16:
                self.align()
        else:
            if lo is None:
                self.length(nbits)
            else:
                self.cint(nbits, lo, hi)
            if nbits:
                self.align()
        return self.bits(value, nbits)
    def seq(self, ext, opts):
        """SEQUENCE preamble: ext bit (None = not extensible) + optional bitmap."""
        if ext is not None:
            self.bit(ext)
        for o in opts:
            self.bit(o)
        return self
    def raw(self, data):
        for x in data:
            self.bits(x, 8)
        return self
    def data(self):
        w = self.b + [0] * (-len(self.b) % 8)
        out = bytearray()
        for i in range(0, len(w), 8):
            v = 0
            for k in w[i:i + 8]:
                v = (v << 1) | k
            out.append(v)
        return bytes(out)

def opentype(data):
    """length determinant + contents (as an open type)."""
    return W().length(len(data)).raw(data).data()
