# Helper module for the dcerpc_rdpdr_smartcard capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Minimal NDR (DCE 1.1, NDR20, little endian) encoder for synthetic
# captures.  Values are trees of the node classes below; pointees are
# written after the outermost construct that holds the pointer, in the
# order the pointers appear, each pointee followed by its own pointees
# (the order Wireshark's dissect_deferred_pointers() expects).
import struct

class Node: pass

class P(Node):
    """Primitive: fmt is a struct format char, aligned to its size."""
    def __init__(s, fmt, v): s.fmt, s.v = fmt, v
    def align(s): return struct.calcsize(s.fmt)

def U8(v): return P('B', v)
def U16(v): return P('H', v)
def I16(v): return P('h', v)
def U32(v): return P('I', v)
def I32(v): return P('i', v)
def U64(v): return P('Q', v)
def I64(v): return P('q', v)

class Raw(Node):
    """Bytes inline, no alignment (fixed arrays of uint8)."""
    def __init__(s, b, al=1): s.b, s.al = bytes(b), al
    def align(s): return s.al

class Ptr(Node):
    """Embedded pointer (ref or unique); target None is a NULL pointer."""
    def __init__(s, target, refid=None): s.t, s.refid = target, refid
    def align(s): return 4

class Struct(Node):
    """Members inline.  A conformant array as last member (CArr with
    inline=True) has its max count written before the struct."""
    def __init__(s, *members, al=None): s.m, s.al = members, al
    def align(s):
        return s.al or max([m.align() for m in s.m] or [1])

class CArr(Node):
    """Conformant array: max_count then elements (bytes or nodes)."""
    def __init__(s, elems, count=None):
        s.e = elems if isinstance(elems, (bytes, bytearray)) else list(elems)
        s.count = len(s.e) if count is None else count
    def align(s):
        if isinstance(s.e, (bytes, bytearray)) or not s.e: return 4
        return max(4, max(e.align() for e in s.e))

class CVStr(Node):
    """Conformant varying string: max, offset, actual, then the
    characters, UTF-16 (width 2) or octets (width 1)."""
    def __init__(s, text, maxc=None, off=0, actual=None, nul=False, width=2):
        s.w = width
        s.ch = [ord(c) for c in text] + ([0] if nul else [])
        s.maxc = len(s.ch) if maxc is None else maxc
        s.off, s.actual = off, (len(s.ch) if actual is None else actual)
    def align(s): return 4

class Union(Node):
    """Non-encapsulated union: discriminant (u16 or u32) then arm."""
    def __init__(s, disc, arm, dfmt='H', al=4):
        s.d, s.arm, s.dfmt, s.al = disc, arm, dfmt, al
    def align(s): return max(struct.calcsize(s.dfmt), s.arm.align() if s.arm else 1)

class Writer:
    def __init__(s, prefix=b''):
        s.b = bytearray(prefix)
        s.next_ref = 0x00020000
    def pad(s, n):
        while len(s.b) % n: s.b += b'\0'
    def put(s, fmt, v):
        s.pad(struct.calcsize(fmt)); s.b += struct.pack('<' + fmt, v)

    def enc(s, n, deferred):
        if isinstance(n, P):
            s.put(n.fmt, n.v)
        elif isinstance(n, Raw):
            s.pad(n.al); s.b += n.b
        elif isinstance(n, Ptr):
            if n.t is None:
                s.put('I', 0)
            else:
                r = n.refid
                if r is None:
                    r = s.next_ref; s.next_ref += 4
                s.put('I', r)
                deferred.append(n.t)
        elif isinstance(n, Struct):
            last = n.m[-1] if n.m else None
            if isinstance(last, CArr):
                s.put('I', last.count)
            s.pad(n.align())
            for m in n.m:
                if m is last and isinstance(m, CArr):
                    s.enc_carr_body(m, deferred)
                else:
                    s.enc(m, deferred)
        elif isinstance(n, CArr):
            s.put('I', n.count)
            s.enc_carr_body(n, deferred)
        elif isinstance(n, CVStr):
            s.put('I', n.maxc); s.put('I', n.off); s.put('I', n.actual)
            for c in n.ch: s.put('H' if n.w == 2 else 'B', c)
        elif isinstance(n, Union):
            s.put(n.dfmt, n.d)
            s.pad(n.al)
            if n.arm is not None:
                s.enc(n.arm, deferred)
        else:
            raise TypeError(n)

    def enc_carr_body(s, n, deferred):
        if isinstance(n.e, (bytes, bytearray)):
            s.b += n.e
        else:
            for e in n.e: s.enc(e, deferred)

    def top(s, n):
        """Encode n and then, recursively, its pointees."""
        d = []
        s.enc(n, d)
        for t in d:
            s.top(t)
        return s

def ndr(node, prefix=b''):
    return bytes(Writer(prefix).top(node).b)
