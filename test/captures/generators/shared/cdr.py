# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""CDR / GIOP builders shared by mkgiop.py and mkgias.py (struct only)."""
import struct
import zlib


class CDR:
    """CDR writer. 'base' is the absolute offset (from the start of the GIOP
    message) of the first byte, so alignment matches the wire."""
    def __init__(self, base=12, le=False):
        self.b = bytearray(); self.base = base; self.le = le
        self.e = '<' if le else '>'

    def pos(self):
        return len(self.b) + self.base

    def align(self, n):
        while self.pos() % n:
            self.b.append(0)
        return self

    def octet(self, v): self.b.append(v & 0xff); return self
    def boolean(self, v): self.b.append(1 if v else 0); return self
    def char(self, v): self.b.append(v & 0xff); return self
    def short(self, v): self.align(2); self.b += struct.pack(self.e + 'h', v); return self
    def ushort(self, v): self.align(2); self.b += struct.pack(self.e + 'H', v); return self
    def long(self, v): self.align(4); self.b += struct.pack(self.e + 'i', v); return self
    def ulong(self, v): self.align(4); self.b += struct.pack(self.e + 'I', v); return self
    def longlong(self, v): self.align(8); self.b += struct.pack(self.e + 'q', v); return self
    def ulonglong(self, v): self.align(8); self.b += struct.pack(self.e + 'Q', v); return self
    def float(self, v): self.align(4); self.b += struct.pack(self.e + 'f', v); return self
    def double(self, v): self.align(8); self.b += struct.pack(self.e + 'd', v); return self

    def string(self, s):
        s = (s.encode() if isinstance(s, str) else s) + b'\0'
        self.ulong(len(s)); self.b += s
        return self

    def empty_string(self):
        return self.ulong(0)

    def seq(self, data):
        self.ulong(len(data)); self.b += data
        return self

    def raw(self, data):
        self.b += data
        return self

    def bytes(self):
        return bytes(self.b)


def encap(build, le=False):
    """An encapsulation: endianness octet then build(CDR) with its own alignment."""
    e = CDR(0, le)
    e.octet(1 if le else 0)
    build(e)
    return e.bytes()


def giop(minor, msgtype, body, le=False, flags=0, major=1, magic=b'GIOP', size=None):
    if minor == 0:
        fl = 1 if le else 0
    else:
        fl = (1 if le else 0) | flags
    n = len(body) if size is None else size
    return magic + bytes([major, minor, fl, msgtype]) + struct.pack('<I' if le else '>I', n) + bytes(body)


# ---- service contexts ----
def svc_codeset(c, char=0x00010001, wchar=0x00010109):
    c.ulong(1)
    c.seq(encap(lambda e: e.ulong(char).ulong(wchar), c.le))

def svc_rtprio(c, prio=17):
    c.ulong(0x0a)
    c.seq(encap(lambda e: e.short(prio), c.le))

def svc_unknown(c, sid, data=b'abc\x01'):
    c.ulong(sid)
    c.seq(bytes([1 if c.le else 0]) + data)

def svc_empty(c, sid):
    c.ulong(sid)
    c.ulong(0)

def svc_list(c, items):
    c.ulong(len(items))
    for it in items:
        it(c)


# ---- IOR ----
def iiop_profile(host='demo.example.test', port=2809, key=b'KEYA', minor=0, comps=(), le=False):
    def b(e):
        e.octet(1).octet(minor)
        e.string(host)
        e.ushort(port)
        e.seq(key)
        if minor >= 1:
            e.ulong(len(comps))
            for tag, data in comps:
                e.ulong(tag)
                e.seq(data)
    return encap(b, le)

def ior(c, type_id, profiles):
    """profiles: list of (tag, profile_data_bytes)"""
    c.string(type_id)
    c.ulong(len(profiles))
    for tag, data in profiles:
        c.ulong(tag)
        c.seq(data)


# ---- messages ----
def request_10(rid, key, op, args=b'', minor=0, le=False, ctx=None, principal=b'', resp=1,
               miop=None, args_fn=None):
    """GIOP 1.0 / 1.1 Request body"""
    c = CDR(12, le)
    svc_list(c, ctx or [])
    c.ulong(rid)
    c.octet(resp)
    if minor > 0:
        c.raw(b'\0\0\0')
    if miop is not None:
        c.raw(b'MIOP')
        c.ulong(3); c.seq(miop)
    else:
        c.seq(key)
    c.string(op)
    c.seq(principal)
    if args_fn:
        args_fn(c)
    c.raw(args)
    return c

def request_12(rid, target, op, args_fn=None, le=False, ctx=None, flags=3, pad=True):
    """target: ('key', bytes) | ('profile', bytes) | ('ref', index, bytes) | ('other', disc)"""
    c = CDR(12, le)
    c.ulong(rid)
    c.octet(flags)
    c.raw(b'\0\0\0')
    if target[0] == 'key':
        c.ushort(0); c.seq(target[1])
    elif target[0] == 'profile':
        c.ushort(1); c.ulong(target[1]); c.seq(target[2])
    elif target[0] == 'ref':
        c.ushort(2); c.ulong(target[1]); target[2](c)
    else:
        c.ushort(target[1])
    c.string(op)
    svc_list(c, ctx or [])
    if args_fn:
        c.align(8)
        args_fn(c)
    return c

def reply_10(rid, status, body_fn=None, le=False, ctx=None):
    c = CDR(12, le)
    svc_list(c, ctx or [])
    c.ulong(rid)
    c.ulong(status)
    if body_fn:
        body_fn(c)
    return c

def reply_12(rid, status, body_fn=None, le=False, ctx=None):
    c = CDR(12, le)
    c.ulong(rid)
    c.ulong(status)
    svc_list(c, ctx or [])
    c.align(8)
    if body_fn:
        body_fn(c)
    return c

def sys_exc(c, repoid='IDL:omg.org/CORBA/OBJECT_NOT_EXIST:1.0', minor=0x4f4d0002, completed=1):
    c.string(repoid); c.ulong(minor); c.ulong(completed)


# ---- TypeCodes ----
# kinds
(tk_null, tk_void, tk_short, tk_long, tk_ushort, tk_ulong, tk_float, tk_double, tk_boolean,
 tk_char, tk_octet, tk_any, tk_TypeCode, tk_Principal, tk_objref, tk_struct, tk_union, tk_enum,
 tk_string, tk_sequence, tk_array, tk_alias, tk_except, tk_longlong, tk_ulonglong, tk_longdouble,
 tk_wchar, tk_wstring, tk_fixed, tk_value, tk_value_box, tk_native, tk_abstract_interface) = range(33)

def tc_simple(c, kind):
    c.ulong(kind)

def tc_with_encap(c, kind, build):
    c.ulong(kind)
    c.seq(encap(build, c.le))

def tc_string(c, maxlen=0):
    c.ulong(tk_string); c.ulong(maxlen)

def tc_wstring(c, maxlen=0):
    c.ulong(tk_wstring); c.ulong(maxlen)

def tc_fixed(c, digits, scale):
    c.ulong(tk_fixed); c.ushort(digits); c.short(scale)

def tc_objref(c, repoid='IDL:demo/Obj:1.0', name='Obj'):
    tc_with_encap(c, tk_objref, lambda e: e.string(repoid).string(name))

def tc_native(c, repoid='IDL:demo/Nat:1.0', name='Nat'):
    tc_with_encap(c, tk_native, lambda e: e.string(repoid).string(name))

def tc_abstract(c, repoid='IDL:demo/Abs:1.0', name='Abs'):
    tc_with_encap(c, tk_abstract_interface, lambda e: e.string(repoid).string(name))

def tc_struct(c, members, repoid='IDL:demo/S:1.0', name='S'):
    def b(e):
        e.string(repoid).string(name).ulong(len(members))
        for n, f in members:
            e.string(n); f(e)
    tc_with_encap(c, tk_struct, b)

def tc_except(c, members, repoid='IDL:demo/X:1.0', name='X'):
    def b(e):
        e.string(repoid).string(name).ulong(len(members))
        for n, f in members:
            e.string(n); f(e)
    tc_with_encap(c, tk_except, b)

def tc_union(c, disc, labels, default_used=-1, repoid='IDL:demo/U:1.0', name='U'):
    """disc: fn writing the discriminant typecode; labels: [(label_fn, name, tc_fn)]"""
    def b(e):
        e.string(repoid).string(name)
        disc(e)
        e.long(default_used)
        e.ulong(len(labels))
        for lf, n, f in labels:
            lf(e); e.string(n); f(e)
    tc_with_encap(c, tk_union, b)

def tc_enum(c, names, repoid='IDL:demo/E:1.0', name='E'):
    def b(e):
        e.string(repoid).string(name).ulong(len(names))
        for n in names:
            e.string(n)
    tc_with_encap(c, tk_enum, b)

def tc_sequence(c, elem, maxlen=0):
    def b(e):
        elem(e); e.ulong(maxlen)
    tc_with_encap(c, tk_sequence, b)

def tc_array(c, elem, length):
    def b(e):
        elem(e); e.ulong(length)
    tc_with_encap(c, tk_array, b)

def tc_alias(c, inner, repoid='IDL:demo/A:1.0', name='A'):
    def b(e):
        e.string(repoid).string(name); inner(e)
    tc_with_encap(c, tk_alias, b)

def tc_value(c, members, repoid='IDL:demo/V:1.0', name='V', modifier=0, base=None):
    def b(e):
        e.string(repoid).string(name).short(modifier)
        (base or (lambda x: tc_simple(x, tk_null)))(e)
        e.ulong(len(members))
        for n, f, vis in members:
            e.string(n); f(e); e.short(vis)
    tc_with_encap(c, tk_value, b)

def tc_value_box(c, inner, repoid='IDL:demo/VB:1.0', name='VB'):
    def b(e):
        e.string(repoid).string(name); inner(e)
    tc_with_encap(c, tk_value_box, b)

def S(kind):
    return lambda e: tc_simple(e, kind)
