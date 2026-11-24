# Helper module for the dcom_ifaces capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""DCOM encoders for the DCOM coverage generators (mkdcom.py, mkdcomifaces.py): ORPCTHIS /
ORPCTHAT with extents, OBJREF (standard, handler, custom), STDOBJREF,
DUALSTRINGARRAY, MInterfacePointer, BSTR, VARIANT, SAFEARRAY and the
MS-DCOM activation properties (type serialization version 1). Derived
from dcomgen.py of the IWbemServices coverage directory.

Everything goes into one rpcgen.NDR buffer per stub, so the alignment is
relative to the stub start, as the dissector computes it; sizes that are
only known afterwards are patched in."""

import struct

UUID_NULL = '00000000-0000-0000-0000-000000000000'
UUID_DEBUG_EXT = 'f1f19680-4d2a-11ce-a66a-0020af6e72f4'
UUID_EXT_ERROR_EXT = 'f1f19681-4d2a-11ce-a66a-0020af6e72f4'
CID = '6c0d47a4-1f43-4b1e-9b5c-0d1d2b7e8a11'            # causality id

IID_IUNKNOWN = '00000000-0000-0000-c000-000000000046'
IID_ISTORAGE = '0000000b-0000-0000-c000-000000000046'
IID_IDISPATCH = '00020400-0000-0000-c000-000000000046'
IID_ITYPEINFO = '00020401-0000-0000-c000-000000000046'
IID_ICLASSFACTORY = '00000001-0000-0000-c000-000000000046'
IID_ACTPROPS_IN = '000001a2-0000-0000-c000-000000000046'
IID_ACTPROPS_OUT = '000001a3-0000-0000-c000-000000000046'
IID_ICONTEXT = '000001c0-0000-0000-c000-000000000046'
CLSID_ACTPROPS_IN = '00000338-0000-0000-c000-000000000046'
CLSID_ACTPROPS_OUT = '00000339-0000-0000-c000-000000000046'
CLSID_CONTEXT_MARSHALER = '0000033b-0000-0000-c000-000000000046'
CLSID_SPECIAL_SYSTEM_PROPS = '000001b9-0000-0000-c000-000000000046'
CLSID_INSTANTIATION_INFO = '000001ab-0000-0000-c000-000000000046'
CLSID_ACT_CONTEXT_INFO = '000001a5-0000-0000-c000-000000000046'
CLSID_SECURITY_INFO = '000001a6-0000-0000-c000-000000000046'
CLSID_SERVER_LOCATION_INFO = '000001a4-0000-0000-c000-000000000046'
CLSID_SCM_REQUEST_INFO = '000001aa-0000-0000-c000-000000000046'
CLSID_PROPS_OUT_INFO = '00000339-0000-0000-c000-000000000046'
CLSID_SCM_REPLY_INFO = '000001b6-0000-0000-c000-000000000046'
CLSID_INSTANCE_INFO = '000001ad-0000-0000-c000-000000000046'
CLSID_UNKNOWN_PROP = '5a5a5a5a-1234-4321-abcd-0123456789ab'
IPID_REMUNKNOWN = '00000131-1234-5678-cafe-000000000046'


def patch32(n, pos, v):
    n.b[pos:pos + 4] = struct.pack(n.e + 'I', v)


def hole32(n):
    """A DWORD to patch later; returns its position"""
    n.u32(0)
    return len(n.b) - 4


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
    """UTF-16LE with NUL: the DCOM strings are always read as
    little endian octet pairs (dcom_tvb_get_nwstringz0())"""
    if isinstance(s, bytes):
        return s + b'\0\0'
    return s.encode('utf-16-le') + b'\0\0'


def dualstringarray(n, bindings, security):
    """DUALSTRINGARRAY: the WORDs follow the data representation, the
    strings are UTF-16LE."""
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


def dsa_conformant(n, bindings, security):
    """max_count (wNumEntries) and the DUALSTRINGARRAY, as behind a pointer"""
    pos = hole32(n)
    start = len(n.b)
    dualstringarray(n, bindings, security)
    patch32(n, pos, (len(n.b) - start - 4) // 2)


DSA_DEFAULT = ([(7, '192.0.2.60'), (7, 'srv01.example.com')],
               [(10, 0xffff, ''), (9, 0, 'host/srv01.example.com')])


def stdobjref(n, oxid, oid, ipid, flags=0, refs=5):
    n.u32(flags)
    n.u32(refs)
    n.raw(struct.pack(n.e + 'QQ', oxid, oid))
    n.guid(ipid)


def objref(n, kind, iid, **kw):
    """OBJREF 'MEOW'. kind: 'std', 'handler', 'custom' or an integer
    flags value. For 'custom', payload is bytes or a function that
    writes the object data into n."""
    n.u32(0x574f454d)
    flags = {'std': 1, 'handler': 2, 'custom': 4}.get(kind, kind)
    n.u32(flags)
    n.guid(iid)
    if kind in ('std', 'handler'):
        stdobjref(n, kw.get('oxid', 0x1111222233334444), kw.get('oid', 0x5555666677778888),
                  kw.get('ipid', '00007c04-0aa8-1234-5678-9abcdef01234'),
                  kw.get('sorf', 0), kw.get('refs', 5))
        if kind == 'handler':
            n.guid(kw.get('clsid', '8bc3f05e-d86b-11d0-a075-00c04fb68820'))
        dualstringarray(n, *kw.get('dsa', DSA_DEFAULT))
    elif kind == 'custom':
        payload = kw.get('payload', b'')
        n.guid(kw.get('clsid', UUID_NULL))
        n.u32(kw.get('cbext', 0))           # cbExtension
        pos = hole32(n)                     # size
        start = len(n.b)
        if callable(payload):
            payload(n)
        else:
            n.raw(payload)
        patch32(n, pos, len(n.b) - start)


def minterfacepointer(n, **kw):
    """MInterfacePointer: max_count, ulCntData, OBJREF octets"""
    n.align(4)
    p1 = hole32(n)
    p2 = hole32(n)
    start = len(n.b)
    objref(n, **kw)
    patch32(n, p1, len(n.b) - start)
    patch32(n, p2, len(n.b) - start)


def pminterfacepointer(n, **kw):
    if not kw:
        n.ptr(False)
        return
    n.ptr(True)
    minterfacepointer(n, **kw)


def bstr(n, s, maxcount=None):
    """BSTR (FLAGGED_WORD_BLOB): max count, byte length, count, UTF-16LE"""
    data = s if isinstance(s, bytes) else s.encode('utf-16-le')
    chars = len(data) // 2
    n.u32(chars if maxcount is None else maxcount)
    n.u32(len(data))
    n.u32(chars)
    n.raw(data)


def lpwstr(n, s):
    """conformant varying string with NUL, UTF-16LE"""
    data = wide(s)
    n.u32(len(data) // 2)
    n.u32(0)
    n.u32(len(data) // 2)
    n.raw(data)


# ---------------------------------------------------------------- VARIANT
VT = dict(EMPTY=0, NULL=1, I2=2, I4=3, R4=4, R8=5, CY=6, DATE=7, BSTR=8, DISPATCH=9,
          ERROR=10, BOOL=11, VARIANT=12, UNKNOWN=13, I1=16, UI1=17, UI2=18, UI4=19,
          I8=20, UI8=21, ARRAY=0x2000, BYREF=0x4000)


def variant(n, vt, value=None, vt16=None, size=None):
    """VARIANT as dissect_dcom_VARIANT() reads it (8-aligned): size, RPC
    reserved, VarType, three reserved WORDs, 32-bit VarType, data"""
    n.align(8)
    n.u32(size if size is not None else 0x20)
    n.u32(0)
    n.u16(vt if vt16 is None else vt16)
    n.u16(0)
    n.u16(0)
    n.u16(0)
    n.u32(vt)
    base = vt & ~VT['BYREF']
    if vt & VT['BYREF']:
        n.ptr(True)
    e = n.e
    if base == VT['EMPTY']:
        pass
    elif base == VT['BOOL']:
        n.u16(value)
    elif base in (VT['I1'], VT['UI1']):
        n.u8(value & 0xff)
    elif base in (VT['I2'], VT['UI2']):
        n.u16(value & 0xffff)
    elif base in (VT['I4'], VT['UI4'], VT['ERROR']):
        n.u32(value & 0xffffffff)
    elif base in (VT['I8'], VT['UI8'], VT['CY']):
        n.u64(value & 0xffffffffffffffff)
    elif base == VT['R4']:
        n.align(4)
        n.raw(struct.pack(e + 'f', value))
    elif base in (VT['R8'], VT['DATE']):
        n.align(8)
        n.raw(struct.pack(e + 'd', value))
    elif base == VT['BSTR']:
        n.ptr(value is not None)
        if value is not None:
            bstr(n, value)
    elif base == VT['DISPATCH']:
        n.ptr(value is not None)
        if value is not None:
            minterfacepointer(n, **value)
    elif base == VT['ARRAY']:
        safearray(n, **value)
    elif base == VT['VARIANT']:
        n.ptr(value is not None)
        if value is not None:
            variant(n, *value)
    elif base == VT['UNKNOWN']:
        n.ptr(value)
    else:
        raise ValueError(vt)


def safearray(n, vt, elems, dims=((None, 0),), features=0x0080, size=None, vt16=None):
    """SAFEARRAY as dissect_dcom_SAFEARRAY() reads it: two pointers,
    dims, features, element size, locks, VarType 16 and 32, elements,
    a pointer, the bounds, the array size and the elements"""
    esize = {VT['I1']: 1, VT['I2']: 2, VT['I4']: 4, VT['ERROR']: 4, VT['BSTR']: 4,
             VT['I8']: 8}.get(vt, 4) if size is None else size
    n.ptr(True)
    n.ptr(True)
    n.u32(len(dims))
    n.u16(len(dims))
    n.u16(features)
    n.u32(esize)
    n.u16(0)
    n.u16(vt if vt16 is None else vt16)
    n.u32(vt)
    n.u32(len(elems))
    n.ptr(True)
    for cnt, low in dims:
        n.u32(len(elems) if cnt is None else cnt)
        n.u32(low)
    n.u32(len(elems))
    if vt == VT['BSTR']:
        for s in elems:
            n.ptr(s is not None)
        for s in elems:
            if s is not None:
                bstr(n, s)
        return
    for v in elems:
        if vt == VT['I1']:
            n.u8(v & 0xff)
        elif vt == VT['I2']:
            n.u16(v & 0xffff)
        elif vt in (VT['I4'], VT['ERROR']):
            n.u32(v & 0xffffffff)
        elif vt == VT['I8']:
            n.u64(v & 0xffffffffffffffff)
        else:
            raise ValueError(vt)


# ---------------------------------------------------- activation properties
def typesz_hdr(n, le=True):
    """Common type serialization header (always little endian) and the
    private header; returns the position of the object buffer length."""
    n.u8(1)
    n.u8(0x10 if le else 0x00)
    n.raw(struct.pack('<HI', 8, 0xcccccccc))
    pos = hole32(n)
    n.u32(0)
    return pos


def property_blob(n, fn, le=True, pad=8, extra=0):
    """One activation property: headers, fn(n) for the body, padding to
    a multiple of pad; returns the size to put in the custom header."""
    start = len(n.b)
    pos = typesz_hdr(n, le)
    body = len(n.b)
    fn(n)
    while (len(n.b) - start) % pad:
        n.u8(0)
    n.raw(b'\0' * extra)
    patch32(n, pos, len(n.b) - body)
    return len(n.b) - start


class RawProp:
    """An activation property whose body is written by fn without the
    type serialization headers: a nested ACTIVATION_BLOB, as for a
    property with the CLSID of ActivationPropertiesIn/Out."""
    def __init__(self, fn):
        self.fn = fn


def activation_blob(n, props, le=True, clsinfo=UUID_NULL, extra_ids=(), extra_sizes=(),
                    dstctx=2):
    """ACTIVATION_BLOB as dissect_dcom_ActivationProperties() reads it:
    total size, reserved, the custom header (with the property CLSID and
    size arrays) and the properties. props: list of (clsid, fn) where fn
    writes the property body (headers are added) or None for a property
    of size 0. extra_ids / extra_sizes are appended to the arrays only."""
    tot = hole32(n)
    n.u32(0)
    start = len(n.b)
    objlen = typesz_hdr(n, le)
    hdr = len(n.b)
    tot2 = hole32(n)
    hsize = hole32(n)
    n.u32(0)                                # reserved
    n.u32(dstctx)
    ids = [c for c, f in props] + list(extra_ids)
    n.u32(len(ids))
    n.guid(clsinfo)
    n.ptr(True)
    n.ptr(True)
    n.ptr(False)
    n.u32(len(ids))
    for c in ids:
        n.guid(c)
    sizes_pos = []
    n.u32(len(props) + len(extra_sizes))
    for _ in props:
        sizes_pos.append(hole32(n))
    for s in extra_sizes:
        n.u32(s)
    while (len(n.b) - start) % 8:
        n.u8(0)
    patch32(n, hsize, len(n.b) - start)
    patch32(n, objlen, len(n.b) - hdr)
    for (c, f), sp in zip(props, sizes_pos):
        if f is None:
            patch32(n, sp, 0)
            continue
        if isinstance(f, RawProp):          # body without headers
            st = len(n.b)
            f.fn(n)
            while (len(n.b) - st) % 8:
                n.u8(0)
            patch32(n, sp, len(n.b) - st)
            continue
        if isinstance(f, tuple):            # (fn, extra padding octets)
            sz = property_blob(n, f[0], le, extra=f[1])
        else:
            sz = property_blob(n, f, le)
        patch32(n, sp, sz)
    patch32(n, tot, len(n.b) - start)
    patch32(n, tot2, len(n.b) - start)
