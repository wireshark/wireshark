#!/usr/bin/env python3
# Generates test/captures/dcom_ifaces_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the DCOM interface dissectors that the
DCOM core capture (dcom_coverage.pcap.gz) leaves out or does not finish:

- packet-dcom-typeinfo.c (ITypeInfo): GetTypeAttr, GetFuncDesc,
  GetNames and GetDocumentation, with TYPEATTR, FUNCDESC, ELEMDESC,
  TYPEDESC (plain, VT_PTR, VT_SAFEARRAY, VT_CARRAY, VT_USERDEFINED,
  nested pointers), PARAMDESC and PARAMDESCEX (with and without a
  default VARIANT), little and big endian;
- packet-dcom-sysact.c (ISystemActivator): activation blobs whose
  properties are again ActivationPropertiesIn / ActivationPropertiesOut
  blobs, five levels deep, the moderate case of "DCOM: Limit nested
  activation properties" (the self-referencing reproducer
  sysact_actprops_recursion.py goes into the malformed capture);
- packet-dcom-dispatch.c (IDispatch): an Invoke request with rgvarg
  VARIANTs.

Connection-oriented DCE/RPC over TCP between a client 192.0.2.50 and a
server 192.0.2.60, one connection per interface (version 0.0, NDR).
Port 135 is registered for DCE/RPC and the DCE/RPC heuristic on TCP
finds the other connections, so no Decode As is needed. Every packet is
built with struct (rpcgen.py, dcomlib.py, copied from the DCOM coverage
directory); nothing comes from a real network.

Usage: mkdcomifaces.py <output directory>

Writes:
  dcom-ifaces-coverage.pcap            the main capture
  dcom-ifaces-coverage-malformed.pcap  paths that only malformed input reaches
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

HERE = os.path.dirname(os.path.abspath(__file__))
from rpcgen import TCP, RPC, NDR, pcap  # noqa: E402
import dcomlib as d
from dcomlib import VT  # noqa: E402
import sysact_actprops_recursion as repro

UUID_SYSACT = '000001a0-0000-0000-c000-000000000046'
UUID_DISPATCH = '00020400-0000-0000-c000-000000000046'
UUID_TYPEINFO = '00020401-0000-0000-c000-000000000046'
V0 = (0, 0)

CLSID_APP = '13709620-c279-11ce-a49e-444553540000'
IPID_A = '00007c04-0aa8-1234-5678-9abcdef01234'
IPID_B = '00007c04-0aa8-1234-5678-9abcdef05678'
IPID_TI = '00009801-0aa8-1234-5678-9abcdef0a401'
OXID_A = 0x1111222233334444
OID_A = 0x5555666677778888
DSA_SRV = ([(7, '192.0.2.60'), (7, 'srv01.example.com')],
           [(10, 0xffff, ''), (9, 0, 'host/srv01.example.com')])

# VARTYPEs in a TYPEDESC
VT_I4, VT_BSTR, VT_VARIANT, VT_HRESULT = 3, 8, 12, 25
VT_PTR, VT_SAFEARRAY, VT_CARRAY, VT_USERDEFINED = 26, 27, 28, 29


def stub(le, fn):
    n = NDR(le)
    fn(n)
    return n.bytes()


class Conn:
    """One TCP connection bound to one interface."""
    def __init__(self, frames, port, uuid, ver=V0, le=True, sport=135):
        self.t = TCP(frames, port, sport=sport)
        self.r = RPC(self.t, uuid, ver, le=le)
        self.le = le
        self.r.bind(b'135\0' if sport == 135 else b'49155\0')

    def call(self, opnum, req, resp, obj=None):
        rq = stub(self.le, req) if callable(req) else req
        rs = stub(self.le, resp) if callable(resp) else resp
        self.r.call(opnum, rq, rs, obj)

    def close(self):
        self.t.fin()


def std(ipid=IPID_A, iid=d.IID_IUNKNOWN, kind='std', **kw):
    return dict(kind=kind, iid=iid, ipid=ipid, oxid=OXID_A, oid=OID_A, dsa=DSA_SRV, **kw)


# ----------------------------------------------------------- ITypeInfo
# The flat part of a structure is written first and returns the writers
# of its deferred pointees (NDR embedded pointers); write_deferred()
# writes them depth first, as the dissector reads them.
def write_deferred(n, lst):
    for f in lst:
        write_deferred(n, f(n) or [])


def typedesc(n, td):
    """TYPEDESC as dissect_typeinfo_TYPEDESC() reads it: the union tag,
    the union arm (a pointer to a TYPEDESC for VT_PTR and VT_SAFEARRAY,
    a HREFTYPE for VT_USERDEFINED, nothing for VT_CARRAY, which is not
    implemented, and the others) and the VARTYPE. td is a VARTYPE or a
    tuple (VT_PTR / VT_SAFEARRAY, inner td) / (VT_USERDEFINED, href)."""
    vt = td[0] if isinstance(td, tuple) else td
    n.align(4)
    n.u16(vt)
    deferred = []
    if vt in (VT_PTR, VT_SAFEARRAY):
        n.ptr(True)
        inner = td[1]
        deferred.append(lambda n: typedesc(n, inner))
    elif vt == VT_USERDEFINED:
        n.u32(td[1])
    n.u16(vt)
    return deferred


def paramdescex(n, default):
    """PARAMDESCEX: cBytes, a pointer and the default VARIANT"""
    n.align(4)
    n.u32(24)
    n.ptr(default is not None)
    if default is not None:
        d.variant(n, *default)


def paramdesc(n, flags, pdex):
    """PARAMDESC: pointer to PARAMDESCEX, wParamFlags. pdex is None (NULL
    pointer), 'nodefault' (PARAMDESCEX without VARIANT) or the VARIANT
    (vt, value) of the default value."""
    n.align(4)
    n.ptr(pdex is not None)
    n.u16(flags)
    if pdex is None:
        return []
    return [lambda n: paramdescex(n, None if pdex == 'nodefault' else pdex)]


def elemdesc(n, td, flags=0, pdex=None):
    n.align(4)
    deferred = typedesc(n, td)
    deferred += paramdesc(n, flags, pdex)
    return deferred


def elemdesc_array(params):
    def f(n):
        n.u32(len(params))
        deferred = []
        for p in params:
            deferred += elemdesc(n, *p)
        return deferred
    return f


def funcdesc(n, memid, params, func, funckind=1, invkind=1, callconv=4, opt=0, vft=28,
             funcflags=0):
    """FUNCDESC: memid, lReserved1, pointer to the ELEMDESC array of the
    parameters, funckind, invkind, callconv, cParams, cParamsOpt, oVft,
    cReserved2, the ELEMDESC of the function and wFuncFlags"""
    n.u32(memid)
    n.u32(0)
    n.ptr(params is not None)
    n.u32(funckind)
    n.u32(invkind)
    n.u32(callconv)
    n.u16(len(params or []))
    n.u16(opt)
    n.u16(vft)
    n.u16(0)
    deferred = [elemdesc_array(params)] if params is not None else []
    deferred += elemdesc(n, *func)
    n.u16(funcflags)
    return deferred


def typeattr(n, guid, typekind, tdesc, flags, lcid=0x409, nfuncs=7, nvars=0, nimpl=1,
             vft=56, align=4, size=4, ver=(1, 0)):
    """TYPEATTR as dissect_typeinfo_TYPEATTR() reads it"""
    n.guid(guid)
    n.u32(lcid)
    n.u32(0)
    n.u32(0)
    n.u32(0)
    n.u32(0)
    n.u32(size)
    n.u32(typekind)
    n.u16(nfuncs)
    n.u16(nvars)
    n.u16(nimpl)
    n.u16(vft)
    n.u16(align)
    n.u16(flags)
    n.u16(ver[0])
    n.u16(ver[1])
    deferred = typedesc(n, tdesc)
    n.u32(0)
    n.u16(0)
    return deferred


def toplevel(n, flat):
    """a unique top level pointer to a structure; flat is None for NULL"""
    n.ptr(flat is not None)
    if flat is not None:
        write_deferred(n, flat(n))


def typeinfo(frames, le=True, port=50501):
    c = Conn(frames, port, UUID_TYPEINFO, le=le, sport=49155)
    this = lambda n: d.orpcthis(n)

    def ta_rs(flat, hr=0):
        return lambda n: (d.orpcthat(n), toplevel(n, flat), n.u32(0), n.u32(hr))

    # GetTypeAttr: every TYPEKIND, the type flags one by one and all
    # together, every TYPEDESC arm for tdescAlias
    attrs = [
        (0, VT_I4, 0x0000, 0x0000),                                 # TKIND_ENUM
        (1, (VT_USERDEFINED, 0x00000102), 0x0001 | 0x0002, 0x0400),  # RECORD
        (2, (VT_PTR, VT_BSTR), 0x0004 | 0x0008, 0x0800),             # MODULE
        (3, (VT_SAFEARRAY, VT_VARIANT), 0x0010 | 0x0020 | 0x0040, 0x0000),  # INTERFACE
        (4, (VT_PTR, (VT_PTR, (VT_USERDEFINED, 0x00000203))), 0x1140, 0x0409),  # DISPATCH
        (5, VT_CARRAY, 0x0080 | 0x0100 | 0x0200, 0x0409),           # COCLASS
        (6, (VT_PTR, (VT_SAFEARRAY, VT_I4)), 0x0400 | 0x0800 | 0x4000, 0x0409),  # ALIAS
        (7, VT_I4, 0x5fff, 0x0409),                                 # UNION, every flag
        (8, VT_HRESULT, 0x0000, 0x1234),                            # unknown TYPEKIND, LCID
    ]
    for kind, td, flags, lcid in attrs:
        guid = '%08x-1111-2222-3333-444455556666' % (0x00020400 + kind)
        c.call(3, this, ta_rs(lambda n, g=guid, k=kind, t=td, f=flags, l=lcid:
                              typeattr(n, g, k, t, f, lcid=l, nfuncs=k, nvars=k + 1)),
               obj=IPID_TI)
    c.call(3, this, ta_rs(None, 0x8000ffff), obj=IPID_TI)

    # GetFuncDesc
    def fd_rq(index):
        return lambda n: (d.orpcthis(n), n.u32(index))

    def fd_rs(flat, hr=0):
        return lambda n: (d.orpcthat(n), toplevel(n, flat), n.u32(0), n.u32(hr))

    params = [
        (VT_I4, 0x0001),                                            # [in] long
        ((VT_PTR, VT_BSTR), 0x0002 | 0x0008),                       # [out, retval] BSTR*
        ((VT_USERDEFINED, 0x00000304), 0x0001 | 0x0010 | 0x0020, (VT['I4'], 42)),  # [in, optional, defaultvalue(42)]
        ((VT_SAFEARRAY, VT_VARIANT), 0x0004 | 0x0040, 'nodefault'),  # lcid, custom data
        (VT_CARRAY, 0x0001 | 0x0010 | 0x0020, (VT['BSTR'], 'default')),
        ((VT_PTR, (VT_PTR, VT_I4)), 0x0003),                        # [in, out] long**
    ]
    c.call(5, fd_rq(0), fd_rs(lambda n: funcdesc(n, 0x60020000, params, (VT_HRESULT,), opt=2,
                                                funcflags=0x1fff)), obj=IPID_TI)
    # a dispatch property get without parameters returning a nested
    # pointer with a PARAMDESCEX
    c.call(5, fd_rq(1), fd_rs(lambda n: funcdesc(
        n, 0x00000000, None, ((VT_PTR, (VT_PTR, (VT_USERDEFINED, 0x405))), 0x0008, (VT['I2'], 7)),
        funckind=4, invkind=2, callconv=1, vft=0, funcflags=0x0040)), obj=IPID_TI)
    # an empty parameter array, a property put with one plain parameter
    c.call(5, fd_rq(2), fd_rs(lambda n: funcdesc(n, 0x22e, [], (VT_HRESULT,), invkind=8,
                                                funcflags=0x0001 | 0x0400)), obj=IPID_TI)
    c.call(5, fd_rq(3), fd_rs(lambda n: funcdesc(n, 0x22f, [(VT_BSTR, 0x0001)], (VT_I4,),
                                                invkind=4, callconv=0)), obj=IPID_TI)
    c.call(5, fd_rq(99), fd_rs(None, 0x8002802b), obj=IPID_TI)

    # GetNames
    def names_rq(memid, maxn):
        return lambda n: (d.orpcthis(n), n.u32(memid), n.u32(maxn))

    def names_rs(names, hr=0):
        def f(n):
            d.orpcthat(n)
            n.u32(len(names) + 2)               # max count (cMaxNames)
            n.u32(0)                            # offset
            n.u32(len(names))                   # actual count
            for s in names:
                n.ptr(s is not None)
            for s in names:
                if s is not None:
                    d.bstr(n, s)
            n.u32(len(names))
            n.u32(hr)
        return f
    c.call(7, names_rq(0x60020000, 5), names_rs(['Open', 'FileName', None, 'ReadOnly']),
           obj=IPID_TI)
    c.call(7, names_rq(0x7fffffff, 1), names_rs([], 0x8002802b), obj=IPID_TI)

    # GetDocumentation
    def doc_rq(memid, flags):
        return lambda n: (d.orpcthis(n), n.u32(memid), n.u32(flags))

    def doc_rs(name, docstr, ctx, helpfile, hr=0):
        def f(n):
            d.orpcthat(n)
            for v in (name, docstr, ctx, helpfile):
                n.ptr(v is not None)
                if v is None:
                    continue
                if isinstance(v, int):
                    n.u32(v)
                else:
                    d.bstr(n, v)
            n.u32(hr)
        return f
    c.call(12, doc_rq(0xffffffff, 0xf),
           doc_rs('Document', 'A Word document', 0x00012345, 'C:\\help\\vbawd10.chm'), obj=IPID_TI)
    c.call(12, doc_rq(0x60020000, 0x1), doc_rs('Open', None, None, None), obj=IPID_TI)
    c.call(12, doc_rq(0x60020001, 0x6), doc_rs(None, 'Opens a file', 7, None), obj=IPID_TI)
    c.call(12, doc_rq(0x7fffffff, 0x0), doc_rs(None, None, None, None, 0x8002802b), obj=IPID_TI)
    c.close()


# ----------------------------------------------------------- ISystemActivator
def p_location(name):
    def f(n):
        n.ptr(True)
        n.u32(0x1234)
        n.u32(0x5678)
        n.u32(0)
        n.wstr(name)
    return f


def p_special():
    def f(n):
        n.u32(1)
        n.u32(0)
        n.u32(0)
        n.u32(0)
        n.u32(2)
        n.guid(d.UUID_NULL)
        n.u32(0)
        n.u32(0x14)
        n.u32(0)
        for _ in range(8):
            n.u32(0)
    return f


def p_instantiation(iids, clsid=CLSID_APP):
    def f(n):
        n.guid(clsid)
        n.u32(0x14)
        n.u32(0x00000002)
        n.u32(0)
        n.u32(len(iids))
        n.u32(0)
        n.ptr(True)
        n.u32(0)
        n.u16(5)
        n.u16(7)
        n.u32(len(iids))
        for i in iids:
            n.guid(i)
    return f


def p_scmrequest(protseqs=(7,)):
    def f(n):
        n.ptr(False)
        n.ptr(True)
        n.u32(2)
        n.u16(len(protseqs))
        n.ptr(True)
        n.u32(len(protseqs))
        for p in protseqs:
            n.u16(p)
    return f


def p_propsout(iids, hrs, ptrs):
    def f(n):
        n.u32(len(iids))
        n.ptr(True)
        n.ptr(True)
        n.ptr(True)
        n.u32(len(iids))
        for i in iids:
            n.guid(i)
        n.u32(len(hrs))
        for h in hrs:
            n.u32(h)
        n.u32(len(ptrs))
        for p in ptrs:
            n.ptr(p is not None)
        for p in ptrs:
            if p is not None:
                d.minterfacepointer(n, **p)
    return f


def p_scmreply():
    def f(n):
        n.ptr(False)
        n.ptr(True)
        n.raw(struct.pack(n.e + 'Q', OXID_A))
        n.ptr(True)
        n.guid(d.IPID_REMUNKNOWN)
        n.u32(10)
        n.u16(5)
        n.u16(7)
        d.dsa_conformant(n, *DSA_SRV)
    return f


def nested_props(levels, le, out=False):
    """The properties of an activation blob whose middle property is
    another ActivationPropertiesIn (Out) blob, levels deep. Each blob has
    a ServerLocationInfo "level-N" (a PropsOutInfo in a response) before
    the nested blob and a further property after it, so the dissector
    has to come back to the outer property list."""
    nested_id = d.IID_ACTPROPS_OUT if out else d.IID_ACTPROPS_IN
    if out:
        first = (d.CLSID_PROPS_OUT_INFO,
                 p_propsout([d.IID_IUNKNOWN], [levels], [std(ipid=IPID_A)] if levels == 0 else [None]))
        last = (d.CLSID_SCM_REPLY_INFO, p_scmreply())
    else:
        first = (d.CLSID_SERVER_LOCATION_INFO, p_location('level-%d' % levels))
        last = (d.CLSID_SCM_REQUEST_INFO, p_scmrequest())
    if levels == 0:
        if out:
            return [first, last]
        return [(d.CLSID_SPECIAL_SYSTEM_PROPS, p_special()), first,
                (d.CLSID_INSTANTIATION_INFO, p_instantiation([d.IID_IUNKNOWN, d.IID_IDISPATCH])),
                last]
    inner = nested_props(levels - 1, le, out)
    blob = d.RawProp(lambda n: d.activation_blob(n, inner, le=le))
    return [first, (nested_id, blob), last]


def actprops(props, out=False, le=True):
    def payload(n):
        d.activation_blob(n, props, le=le)
    return dict(kind='custom', iid=d.IID_ACTPROPS_OUT if out else d.IID_ACTPROPS_IN,
                clsid=d.CLSID_ACTPROPS_OUT if out else d.CLSID_ACTPROPS_IN, payload=payload)


def sysact_nested(frames, le=True, port=50502, levels=5):
    """RemoteCreateInstance whose activation blob holds five nested
    ActivationPropertiesIn blobs, answered with an activation blob that
    holds one nested ActivationPropertiesOut blob"""
    c = Conn(frames, port, UUID_SYSACT, le=le)

    def rq(n):
        d.orpcthis(n)
        n.ptr(False)
        d.pminterfacepointer(n, **actprops(nested_props(levels, le), le=le))

    def rs(n):
        d.orpcthat(n)
        d.pminterfacepointer(n, **actprops(nested_props(1, le, out=True), out=True, le=le))
        n.u32(0)
    c.call(4, rq, rs)
    c.close()


# ----------------------------------------------------------- IDispatch
def dispatch_rgvarg(frames, port=50503):
    """IDispatch Invoke with one rgvarg VARIANT. The dissector does not
    move past the rgvarg VARIANTs (the offset assignment after the loop
    is commented out), so the VarRef fields that follow are read from the
    VARIANT itself: its size is read as cVarRef, the RPC reserved DWORD
    (0) as the rgVarRefIdx count, the 16-bit VarType 2 as the rgVarRef
    count, and the two reserved WORDs and the 32-bit VarType (VT_EMPTY,
    0) as two NULL VarRef pointers. The request then ends where the
    VARIANT ends, so it decodes without a long frame."""
    c = Conn(frames, port, UUID_DISPATCH, sport=49155)

    def rq(n):
        d.orpcthis(n, [None])                   # an extent array puts the VARIANT at 8
        n.u32(0x3e8)
        n.guid(d.UUID_NULL)
        n.u32(0x409)
        n.u32(1)                                # DISPATCH_METHOD
        n.ptr(True)                             # rgvarg
        n.ptr(False)                            # rgdispidNamedArgs
        n.u32(1)
        n.u32(0)
        n.u32(1)                                # array size
        n.ptr(True)
        assert len(n.b) % 8 == 0                # no padding before the VARIANT
        d.variant(n, VT['EMPTY'], vt16=2, size=0x18)
    rs = lambda n: (d.orpcthat(n), n.ptr(False), n.u16(0), n.u16(0), n.ptr(False), n.ptr(False),
                    n.ptr(False), n.u32(0), n.u32(0), n.u32(0), n.u32(0), n.u32(0), n.u32(0),
                    n.u32(0))
    c.call(6, rq, rs, obj=IPID_B)
    c.close()


# ----------------------------------------------------------- malformed
def malformed(frames):
    # the reproducer of "DCOM: Limit nested activation properties": an
    # ActivationPropertiesIn property that loops back to its own blob
    # (stops at the dissection depth limit with the fix), and the fan
    # variant with ten properties per level
    for mode, port in (('wrap', 50301), ('fan', 50302)):
        t = TCP(frames, port, sport=135)
        r = RPC(t, UUID_SYSACT, V0)
        r.bind(b'135\0')
        n = NDR()
        d.orpcthis(n)
        n.ptr(True)
        n.align(4)
        p1 = d.hole32(n)
        p2 = d.hole32(n)
        s = len(n.b)
        n.u32(0x574f454d)
        n.u32(4)
        n.guid(d.IID_ACTPROPS_IN)
        n.guid(d.CLSID_ACTPROPS_IN)
        n.u32(0)
        n.u32(0x200)
        if mode == 'wrap':
            repro.blob(n, 1, 0xfffffff8)
        else:
            for _ in range(40):
                st = len(n.b)
                repro.blob(n, 10, 0)
                hs = len(n.b) - (st + 8)
                n.b[st + 8 + 16 + 4:st + 8 + 16 + 8] = struct.pack('<I', hs)
            n.raw(b'\0' * 64)
        d.patch32(n, p1, len(n.b) - s)
        d.patch32(n, p2, len(n.b) - s)
        r.request(3, n.bytes())
        t.fin()

    # ITypeInfo: responses cut short, a name count larger than the data
    c = Conn(frames, 50304, UUID_TYPEINFO, sport=49155)
    full = stub(True, lambda n: (d.orpcthat(n), toplevel(n, lambda n: funcdesc(
        n, 1, [(VT_I4, 1, (VT['I4'], 1))], (VT_HRESULT,))), n.u32(0), n.u32(0)))
    c.call(5, lambda n: (d.orpcthis(n), n.u32(0)), full[:-20], obj=IPID_TI)
    full = stub(True, lambda n: (d.orpcthat(n), toplevel(n, lambda n: typeattr(
        n, d.UUID_NULL, 4, (VT_PTR, VT_I4), 0)), n.u32(0), n.u32(0)))
    c.call(3, lambda n: d.orpcthis(n), full[:-14], obj=IPID_TI)
    c.call(7, lambda n: (d.orpcthis(n), n.u32(0), n.u32(1)),
           lambda n: (d.orpcthat(n), n.u32(0x40000000), n.u32(0), n.u32(0x40000000), n.ptr(True),
                      n.u32(0)), obj=IPID_TI)
    c.call(12, lambda n: (d.orpcthis(n), n.u32(0), n.u32(0xf)),
           lambda n: (d.orpcthat(n), n.ptr(True), n.u32(5000), n.u32(10000), n.u32(5000),
                      n.raw(b'A\0' * 4)), obj=IPID_TI)
    c.close()


def main(outdir):
    frames = []
    typeinfo(frames)
    typeinfo(frames, le=False, port=50511)
    sysact_nested(frames)
    sysact_nested(frames, le=False, port=50512)
    dispatch_rgvarg(frames)
    pcap(os.path.join(outdir, 'dcom-ifaces-coverage.pcap'), frames)

    bad = []
    malformed(bad)
    pcap(os.path.join(outdir, 'dcom-ifaces-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
