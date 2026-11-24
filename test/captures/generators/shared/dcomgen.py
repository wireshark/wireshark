# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""DCOM and WMIO encoding helpers for the IWbemServices coverage
generator: ORPCTHIS/ORPCTHAT with extents, OBJREF (standard, handler,
custom) with STDOBJREF and DUALSTRINGARRAY, and MS-WMIO class objects.
Everything is built with struct; the NDR parts go into an rpcgen.NDR
buffer so the alignment is relative to the stub start."""

import struct

from rpcgen import uuid_bytes

IID_WMIO = 'dc12a681-737f-11cf-884d-00aa004b2e24'      # IWbemClassObject
IID_IWBEMSERVICES = '9556dc99-828c-11cf-a37e-00aa003240c7'
IID_IUNKNOWN = '00000000-0000-0000-c000-000000000046'
UUID_DEBUG_EXT = 'f1f19680-4d2a-11ce-a66a-0020af6e72f4'  # registered names
UUID_EXT_ERROR_EXT = 'f1f19681-4d2a-11ce-a66a-0020af6e72f4'
UUID_NULL = '00000000-0000-0000-0000-000000000000'
CID = '6c0d47a4-1f43-4b1e-9b5c-0d1d2b7e8a11'            # causality id


def extents(n, ext):
    """ORPC_EXTENT_ARRAY behind a unique pointer, as dissect_dcom_extent()
    reads it. ext is None (NULL pointer), 'noarray' (array pointer NULL)
    or a list of None (NULL extent) / (guid, data)."""
    n.ptr(ext is not None)
    if ext is None:
        return
    if ext == 'noarray':
        n.u32(0)
        n.u32(0)
        n.ptr(False)
        return
    n.u32(len(ext))
    n.u32(0)
    n.ptr(True)
    n.u32(len(ext))                     # array size
    for e in ext:
        n.ptr(e is not None)
    for e in ext:
        if e is None:
            continue
        guid, data = e
        n.u32(len(data) + 8)
        n.guid(guid)
        n.u32(len(data))
        n.raw(data)


def orpcthis(n, ext=None, flags=0, ver=(5, 7)):
    n.u16(ver[0])
    n.u16(ver[1])
    n.u32(flags)
    n.u32(0)
    n.guid(CID)
    extents(n, ext)


def orpcthat(n, ext=None, flags=0):
    n.u32(flags)
    extents(n, ext)


def wide(s):
    return s.encode('utf-16-le') + b'\0\0'


def dualstringarray(n, bindings, security):
    """DUALSTRINGARRAY: the WORDs follow the data representation, the
    strings are always UTF-16LE (dcom_tvb_get_nwstringz0())."""
    sb = b''
    for tower, addr in bindings:
        sb += struct.pack(n.e + 'H', tower) + wide(addr)
    sb += b'\0\0'
    sec = b''
    for authn, authz, princ in security:
        sec += struct.pack(n.e + 'HH', authn, authz) + wide(princ)
    sec += b'\0\0'
    n.u16((len(sb) + len(sec)) // 2)
    n.u16(len(sb) // 2)
    n.raw(sb + sec)


def stdobjref(n, oxid, oid, ipid, flags=0, refs=5):
    n.u32(flags)
    n.u32(refs)
    n.align(4)
    n.raw(struct.pack(n.e + 'QQ', oxid, oid))
    n.guid(ipid)


DSA_DEFAULT = ([(7, '192.0.2.60'), (7, 'srv01.example.com')],
               [(10, 0xffff, ''), (9, 0, 'host/srv01.example.com')])


def objref(n, kind, iid, **kw):
    """OBJREF 'MEOW'. kind: 'std', 'handler', 'custom' or an integer
    flags value that is none of them."""
    n.u32(0x574f454d)
    flags = {'std': 1, 'handler': 2, 'custom': 4}.get(kind, kind)
    n.u32(flags)
    n.guid(iid)
    if kind in ('std', 'handler'):
        stdobjref(n, kw.get('oxid', 0x1111222233334444), kw.get('oid', 0x5555666677778888),
                  kw.get('ipid', '00007c04-0aa8-1234-5678-9abcdef01234'))
        if kind == 'handler':
            n.guid(kw.get('clsid', '8bc3f05e-d86b-11d0-a075-00c04fb68820'))
        dualstringarray(n, *kw.get('dsa', DSA_DEFAULT))
    elif kind == 'custom':
        payload = kw.get('payload', b'')
        n.guid(kw.get('clsid', '4590f812-1d3a-11d0-891f-00aa004b2e24'))
        n.u32(0)                        # cbExtension
        n.u32(len(payload))             # size
        n.raw(payload)


def class_object(n, **kw):
    """IWbemClassObject in NDR: count, then the conformant byte array
    (max_count, octets) that holds an OBJREF."""
    from rpcgen import NDR
    n.align(4)
    o = NDR(n.le, False, base=len(n.b) + n.base + 8)
    objref(o, **kw)
    data = o.bytes()
    n.u32(len(data))
    n.u32(len(data))
    n.raw(data)


# ---------------------------------------------------------------- WMIO
# Everything in MS-WMIO is little endian, whatever the NDR byte order.
CIM = dict(SINT16=2, SINT32=3, REAL32=4, REAL64=5, STRING=8, BOOLEAN=11, OBJECT=13,
           SINT8=16, UINT8=17, UINT16=18, UINT32=19, SINT64=20, UINT64=21,
           DATETIME=101, REFERENCE=102, CHAR16=103)
ARRAY = 0x2000
DICT = 0x80000000   # dictionary string reference
NULLREF = 0xffffffff


def es(s, uni=False):
    """Encoded-String: flag, characters, NUL"""
    if uni:
        return b'\x01' + s.encode('utf-16-le') + b'\0\0'
    return b'\x00' + s.encode('latin-1') + b'\0'


class Heap:
    def __init__(self):
        self.b = bytearray()

    def add(self, data):
        off = len(self.b)
        self.b += data
        return off

    def s(self, text, uni=False):
        return self.add(es(text, uni))


def qual(name, ctype, value=b'', flavor=0):
    return struct.pack('<IBI', name, flavor, ctype) + value


def qset(quals):
    body = b''.join(quals)
    return struct.pack('<I', 4 + len(body)) + body


def classpart(name, heap, deriv=(), quals=(), props=(), nd=b'', heap_msb=False):
    """ClassPart. name: heap reference of the class name; deriv: list
    of (string, unicode); quals: encoded qualifiers; props: list of
    (name reference, PropertyInfo heap offset)."""
    dl = b''
    for s, u in deriv:
        e = es(s, u)
        dl += e + struct.pack('<I', len(e))
    body = struct.pack('<I', 4 + len(dl)) + dl
    body += qset(quals)
    body += struct.pack('<I', len(props)) + b''.join(struct.pack('<II', a, b) for a, b in props)
    body += nd
    body += struct.pack('<I', len(heap.b) | (0x80000000 if heap_msb else 0)) + bytes(heap.b)
    return struct.pack('<IBII', 13 + len(body), 0, name, len(nd)) + body


def propertyinfo(ctype, order, quals, vt=0, origin=0):
    return struct.pack('<IHII', ctype, order, vt, origin) + qset(quals)


def methodspart(methods=(), mheap=b''):
    """methods: list of (name ref, flags, origin, qualifiers, in, out),
    the references relative to the method heap data"""
    m = len(methods)
    d = b''.join(struct.pack('<IB3xIIII', *x) for x in methods)
    return struct.pack('<IHH', 8 + 24 * m + 4 + len(mheap), m, 0) + d + struct.pack('<I', len(mheap)) + mheap


def minimal_class():
    """ClassPart without a name, derivation, qualifiers or properties"""
    return classpart(NULLREF, Heap())


def objectblock(flags, parent=None, current=None, deco=None):
    b = bytes([flags])
    if deco:
        b += deco
    if flags & 0x01:
        b += parent + current
    return b


def encoded_object(block):
    """EncodingLength + ObjectBlock, as in a method signature"""
    return struct.pack('<I', 4 + len(block)) + block


def wmio(block, signature=0x12345678):
    return struct.pack('<II', signature, 8 + len(block)) + block
