#!/usr/bin/env python3
# Generates test/captures/dcom_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DCOM dissectors:
packet-dcom.c (ORPCTHIS/ORPCTHAT, extents, OBJREF, STDOBJREF,
CUSTOBJREF, DUALSTRINGARRAY, MInterfacePointer, BSTR, LPWSTR, VARIANT,
SAFEARRAY, HRESULT), packet-dcom-sysact.c (ISystemActivator and the
activation properties), packet-dcom-remunkn.c (IRemUnknown,
IRemUnknown2), packet-dcom-oxid.c (IOXIDResolver), and through them
packet-dcom-remact.c (IRemoteActivation), packet-dcom-dispatch.c
(IDispatch, which carries VARIANT, SAFEARRAY and BSTR) and
packet-dcom-provideclassinfo.c.

Connection-oriented DCE/RPC over TCP between a client 192.0.2.50 and a
server 192.0.2.60: each connection binds to one interface and sends
requests that the server answers. The DCE/RPC heuristic on TCP finds
the PDUs (and port 135 is registered for DCE/RPC), so no Decode As is
needed. Every packet is built with struct (rpcgen.py, dcomlib.py);
nothing comes from a real network.

The reproducers of "DCOM: Limit nested OBJREFs, register custom
marshalers for every packet" (dcom_objref_recursion.py with a nesting
of 8 and dcom_marshaler_2pass.py, helpers dcom_lib.py and
dcom_bdef_rpclib.py) are included with their own client ports; the
deep recursion (1000 nested OBJREFs) goes into the malformed capture.

Usage: mkdcom.py <output directory>

Writes:
  dcom-coverage.pcap            the main capture
  dcom-coverage-malformed.pcap  paths that only malformed input reaches
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from rpcgen import TCP, RPC, NDR, pcap  # noqa: E402
import dcomlib as d
from dcomlib import VT  # noqa: E402
import dcom_bdef_rpclib

UUID_REMACT = '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57'
UUID_SYSACT = '000001a0-0000-0000-c000-000000000046'
UUID_OXID = '99fcfec4-5260-101b-bbcb-00aa0021347a'
UUID_REMUNK = '00000131-0000-0000-c000-000000000046'
UUID_REMUNK2 = '00000143-0000-0000-c000-000000000046'
UUID_DISPATCH = '00020400-0000-0000-c000-000000000046'
UUID_PROVIDECLASSINFO = 'b196b283-bab4-101a-b69c-00aa00341d07'
V0 = (0, 0)

CLSID_APP = '13709620-c279-11ce-a49e-444553540000'     # an application class
IPID_OBJ = '0000a404-0c60-1234-8899-aabbccddeeff'
IPID_A = '00007c04-0aa8-1234-5678-9abcdef01234'
IPID_B = '00007c04-0aa8-1234-5678-9abcdef05678'
IPID_C = '00009801-0aa8-1234-5678-9abcdef09abc'
IPID_Z = '0000f00d-0aa8-1234-5678-9abcdef0f00d'
OXID_A = 0x1111222233334444
OID_A = 0x5555666677778888

EXT3 = [None, ('01020304-0506-0708-090a-0b0c0d0e0f10', b'\xde\xad\xbe\xef\x01\x02\x03\x04'),
        (d.UUID_DEBUG_EXT, b'dbg\0')]

DSA_SRV = ([(7, '192.0.2.60'), (7, 'srv01.example.com'), (0x1f, '192.0.2.60[593]')],
           [(10, 0xffff, ''), (9, 0, 'host/srv01.example.com'), (16, 2, 'srv01$')])
DSA_MULTI = ([(7, '192.0.2.60'), (7, '192.0.2.61'), (0x55, b'\x01\x02\xff\x00'),
              (8, '198.51.100.7')], [(0xffff, 1, 'NT AUTHORITY')])
DSA_EMPTY = ([], [])
DSA_M2 = ([(7, '192.0.2.61')], [(10, 0xffff, '')])


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


def std(ipid=IPID_A, iid=d.IID_IUNKNOWN, oxid=OXID_A, oid=OID_A, dsa=DSA_SRV, kind='std', **kw):
    return dict(kind=kind, iid=iid, ipid=ipid, oxid=oxid, oid=oid, dsa=dsa, **kw)


# ----------------------------------------------------------- IRemoteActivation
def remact(frames, le=True, port=50101):
    """IRemoteActivation RemoteActivation. The first request has an
    object storage that is a custom OBJREF for IStorage holding a
    standard OBJREF: it comes before any ISystemActivator call, so it is
    decoded in the first pass only with the fix."""
    c = Conn(frames, port, UUID_REMACT, le=le)

    def storage(n):
        d.objref(n, **std(ipid=IPID_C, iid=d.IID_ISTORAGE, dsa=DSA_SRV))

    def rq1(n):
        d.orpcthis(n, EXT3)
        n.guid(CLSID_APP)
        n.ptr(True)
        d.bstr(n, 'C:\\docs\\report.doc')
        d.pminterfacepointer(n, kind='custom', iid=d.IID_ISTORAGE,
                             clsid='00000320-0000-0000-c000-000000000046', payload=storage)
        n.u32(2)                            # client impersonation level
        n.u32(0)                            # mode
        n.u32(2)                            # interfaces
        n.ptr(True)
        n.u32(2)
        n.guid(d.IID_IUNKNOWN)
        n.guid(d.IID_IDISPATCH)
        n.u16(2)
        n.u32(2)
        n.u16(7)
        n.u16(0x1f)

    def rs1(n):
        d.orpcthat(n)
        n.raw(struct.pack(n.e + 'Q', OXID_A))
        n.ptr(True)
        d.dsa_conformant(n, *DSA_SRV)
        n.guid(d.IPID_REMUNKNOWN)
        n.u32(10)                           # authn hint
        n.u16(5)
        n.u16(7)
        n.u32(0)                            # HRESULT
        n.u32(3)
        n.ptr(True)
        n.ptr(False)
        n.ptr(True)
        d.minterfacepointer(n, **std(ipid=IPID_A))
        d.minterfacepointer(n, **std(ipid=IPID_B, iid=d.IID_IDISPATCH))
        n.u32(3)
        n.u32(0)
        n.u32(0x80004002)                   # E_NOINTERFACE
        n.u32(0x00000001)                   # S_FALSE
        n.u32(0)

    def rq2(n):
        d.orpcthis(n, 'noarray')
        n.guid('99999999-8888-7777-6666-555555555555')
        n.ptr(False)
        n.ptr(False)
        n.u32(3)
        n.u32(1)
        n.u32(1)
        n.ptr(False)
        n.u16(0)
        n.u32(0)

    def rs2(n):
        d.orpcthat(n)
        n.raw(struct.pack(n.e + 'Q', 0))
        n.ptr(False)
        n.guid(d.UUID_NULL)
        n.u32(0)
        n.u16(5)
        n.u16(7)
        n.u32(0x80040154)                   # REGDB_E_CLASSNOTREG
        n.u32(0)
        n.u32(0)
        n.u32(0x80040154)

    c.call(0, rq1, rs1)
    c.call(0, rq2, rs2)
    c.close()


# ----------------------------------------------------------- ISystemActivator
def p_instantiation(iids, clsid=CLSID_APP):
    def f(n):
        n.guid(clsid)
        n.u32(0x14)                         # CLSCTX_LOCAL_SERVER|REMOTE_SERVER
        n.u32(0x00000002)                   # ACTVFLAGS_DISABLE_AAA
        n.u32(0)
        n.u32(len(iids))
        n.u32(0)
        n.ptr(True)
        n.u32(0)                            # entire size, patched by nobody
        n.u16(5)
        n.u16(7)
        n.u32(len(iids))
        for i in iids:
            n.guid(i)
    return f


def icontext(n):
    n.u16(1)
    n.u16(0)
    n.guid('2c4f3f8b-6e2e-4c31-9f0e-1a2b3c4d5e6f')
    n.u32(2)                                # MarshalByValue
    n.u32(0)
    n.u32(0)
    n.u32(0)
    n.u32(0)
    n.u32(1)
    n.u32(1)


def p_actctx(client=True, proto=True):
    def f(n):
        n.u32(0)                            # client OK
        n.u32(0)
        n.u32(0)
        n.u32(0)
        n.ptr(client)
        n.ptr(proto)
        if client:
            d.minterfacepointer(n, kind='custom', iid=d.IID_ICONTEXT,
                                clsid=d.CLSID_CONTEXT_MARSHALER, payload=icontext)
    return f


def p_security(name='srv01.example.com'):
    def f(n):
        n.u32(0)                            # authentication flags
        n.ptr(True)
        n.ptr(False)
        n.u32(0)                            # COSERVERINFO reserved
        n.ptr(name is not None)
        n.ptr(False)
        n.u32(0)
        if name is not None:
            n.wstr(name)
    return f


def p_location(name='srv01'):
    def f(n):
        n.ptr(name is not None)
        n.u32(0x1234)
        n.u32(0x5678)
        n.u32(0)
        if name is not None:
            n.wstr(name)
    return f


def p_scmrequest(protseqs=(7, 0x1f)):
    def f(n):
        n.ptr(False)
        n.ptr(True)
        n.u32(2)                            # client impersonation level
        n.u16(len(protseqs))
        n.ptr(True)
        n.u32(len(protseqs))
        for p in protseqs:
            n.u16(p)
    return f


def p_special():
    def f(n):
        n.u32(1)                            # session id
        n.u32(0)
        n.u32(0)
        n.u32(0)
        n.u32(2)                            # default authentication level
        n.guid(d.UUID_NULL)
        n.u32(0)
        n.u32(0x14)
        n.u32(0)
        for _ in range(8):
            n.u32(0)
    return f


def p_instance(filename='C:\\docs\\report.doc'):
    def f(n):
        n.ptr(True)
        n.u32(0x12)                         # mode
        n.ptr(True)                         # ROT data (not dissected)
        n.ptr(True)
        n.wstr(filename)
        d.minterfacepointer(n, **std(ipid=IPID_C, iid=d.IID_ISTORAGE))
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


def p_scmreply(dsa=DSA_SRV):
    def f(n):
        n.ptr(False)
        n.ptr(True)
        n.raw(struct.pack(n.e + 'Q', OXID_A))
        n.ptr(dsa is not None)
        n.guid(d.IPID_REMUNKNOWN)
        n.u32(10)
        n.u16(5)
        n.u16(7)
        if dsa is not None:
            d.dsa_conformant(n, *dsa)
    return f


def props_in_full():
    return [(d.CLSID_SPECIAL_SYSTEM_PROPS, p_special()),
            (d.CLSID_INSTANTIATION_INFO, p_instantiation([d.IID_IUNKNOWN, d.IID_IDISPATCH])),
            (d.CLSID_ACT_CONTEXT_INFO, p_actctx()),
            (d.CLSID_SECURITY_INFO, p_security()),
            (d.CLSID_SERVER_LOCATION_INFO, p_location()),
            (d.CLSID_SCM_REQUEST_INFO, p_scmrequest()),
            (d.CLSID_INSTANCE_INFO, p_instance())]


def actprops(props, out=False, le=True, **kw):
    def payload(n):
        d.activation_blob(n, props, le=le, **kw)
    return dict(kind='custom', iid=d.IID_ACTPROPS_OUT if out else d.IID_ACTPROPS_IN,
                clsid=d.CLSID_ACTPROPS_OUT if out else d.CLSID_ACTPROPS_IN, payload=payload)


def props_out_full():
    return [(d.CLSID_PROPS_OUT_INFO,
             p_propsout([d.IID_IUNKNOWN, d.IID_IDISPATCH, d.IID_ITYPEINFO],
                        [0, 0, 0x80004002],
                        [std(ipid=IPID_A), std(ipid=IPID_B, iid=d.IID_IDISPATCH,
                                               kind='handler', sorf=0x1000), None])),
            (d.CLSID_SCM_REPLY_INFO, p_scmreply())]


def sysact(frames, le=True, port=50102):
    c = Conn(frames, port, UUID_SYSACT, le=le)

    def create_rq(props, ext=None, **kw):
        def f(n):
            d.orpcthis(n, ext)
            n.ptr(False)                    # pUnkOuter
            d.pminterfacepointer(n, **actprops(props, le=le, **kw))
        return f

    def create_rs(props, hr=0, **kw):
        def f(n):
            d.orpcthat(n)
            if props is None:
                n.ptr(False)
            else:
                d.pminterfacepointer(n, **actprops(props, out=True, le=le, **kw))
            n.u32(hr)
        return f

    def getclass_rq(props):
        def f(n):
            d.orpcthis(n)
            d.pminterfacepointer(n, **actprops(props, le=le))
        return f

    def getclass_rs(props, hr=0):
        def f(n):
            d.orpcthat(n)
            if props is None:
                n.ptr(False)
            else:
                d.pminterfacepointer(n, **actprops(props, out=True, le=le))
            n.u32(hr)
        return f

    # RemoteCreateInstance with every property
    c.call(4, create_rq(props_in_full(), EXT3, clsinfo=CLSID_APP), create_rs(props_out_full()))
    # RemoteGetClassObject
    c.call(3, getclass_rq([(d.CLSID_INSTANTIATION_INFO, p_instantiation([d.IID_ICLASSFACTORY])),
                           (d.CLSID_SCM_REQUEST_INFO, p_scmrequest((7,)))]),
           getclass_rs([(d.CLSID_PROPS_OUT_INFO,
                         p_propsout([d.IID_ICLASSFACTORY], [0], [std(ipid=IPID_B)])),
                        (d.CLSID_SCM_REPLY_INFO, p_scmreply())]))
    if le:
        # NULL pointers in the properties, an unknown property, a
        # property of size 0 before the same property with its size
        c.call(4, create_rq([(d.CLSID_SPECIAL_SYSTEM_PROPS, None),
                             (d.CLSID_SPECIAL_SYSTEM_PROPS, p_special()),
                             (d.CLSID_UNKNOWN_PROP, lambda n: n.raw(b'\x55' * 12)),
                             (d.CLSID_ACT_CONTEXT_INFO, p_actctx(False, False)),
                             (d.CLSID_SECURITY_INFO, p_security(None)),
                             (d.CLSID_SERVER_LOCATION_INFO, p_location(None))]),
               create_rs(None, 0x80070005))
        # eleven properties: only ten are kept
        many = [(d.CLSID_UNKNOWN_PROP, lambda n: n.u32(i)) for i in range(10)]
        many.append((d.CLSID_SCM_REQUEST_INFO, None))
        c.call(4, create_rq(many), create_rs([(d.CLSID_SCM_REPLY_INFO, p_scmreply(None))]))
        # every property type with a size of 0 before the same property,
        # and properties with unused octets at the end
        c.call(4, create_rq([(d.CLSID_INSTANTIATION_INFO, None),
                             (d.CLSID_INSTANTIATION_INFO, p_instantiation([d.IID_IUNKNOWN])),
                             (d.CLSID_ACT_CONTEXT_INFO, None),
                             (d.CLSID_ACT_CONTEXT_INFO, (p_actctx(False, False), 8)),
                             (d.CLSID_SECURITY_INFO, None),
                             (d.CLSID_SECURITY_INFO, p_security()),
                             (d.CLSID_SERVER_LOCATION_INFO, None),
                             (d.CLSID_SERVER_LOCATION_INFO, (p_location(), 8)),
                             (d.CLSID_SPECIAL_SYSTEM_PROPS, (p_special(), 8))]),
               create_rs([(d.CLSID_PROPS_OUT_INFO, None),
                          (d.CLSID_PROPS_OUT_INFO, p_propsout([d.IID_IUNKNOWN], [0],
                                                              [std(ipid=IPID_A)])),
                          (d.CLSID_SCM_REPLY_INFO, None),
                          (d.CLSID_SCM_REPLY_INFO, p_scmreply())]))
        c.call(4, create_rq([(d.CLSID_SCM_REQUEST_INFO, None),
                             (d.CLSID_SCM_REQUEST_INFO, p_scmrequest()),
                             (d.CLSID_INSTANCE_INFO, None),
                             (d.CLSID_INSTANCE_INFO, p_instance()),
                             (d.UUID_NULL, lambda n: n.u32(0))]),
               create_rs(None, 0x80070005))
        # more CLSIDs than sizes and more sizes than CLSIDs
        c.call(3, getclass_rq([(d.CLSID_INSTANTIATION_INFO, p_instantiation([]))]),
               getclass_rs(None, 0x80080004))
    c.close()


def sysact_mismatch(frames, port=50104):
    """property CLSID and size arrays of different lengths"""
    c = Conn(frames, port, UUID_SYSACT)

    def rq(n):
        d.orpcthis(n)
        d.pminterfacepointer(n, **actprops([(d.CLSID_SERVER_LOCATION_INFO, p_location())],
                                           extra_ids=[d.CLSID_UNKNOWN_PROP]))

    def rs(n):
        d.orpcthat(n)
        d.pminterfacepointer(n, **actprops([(d.CLSID_SCM_REPLY_INFO, p_scmreply())], out=True,
                                           extra_sizes=[0]))
        n.u32(0)
    c.call(3, rq, rs)
    c.close()


# ----------------------------------------------------------- IOXIDResolver
def oxid(frames, le=True, port=50105):
    c = Conn(frames, port, UUID_OXID, le=le)
    e = '<' if le else '>'

    def q(v):
        return lambda n: n.raw(struct.pack(n.e + 'Q', v))

    # ResolveOxid (no dissector for it): OXID, requested protseqs
    c.call(0, struct.pack(e + 'QHxxIHH', OXID_A, 2, 2, 7, 0x1f), struct.pack(e + 'II', 0, 0x80070005))

    def ping_rq(n):
        n.raw(struct.pack(n.e + 'Q', 0x0123456789abcdef))
    c.call(1, ping_rq, lambda n: n.u32(0))

    def cping_rq(add, dele):
        def f(n):
            n.raw(struct.pack(n.e + 'Q', 0x0123456789abcdef))
            n.u16(7)
            n.u16(len(add))
            n.u16(len(dele))
            n.ptr(bool(add))
            if add:
                n.u32(len(add))
                for o in add:
                    n.raw(struct.pack(n.e + 'Q', o))
            n.ptr(bool(dele))
            if dele:
                n.u32(len(dele))
                for o in dele:
                    n.raw(struct.pack(n.e + 'Q', o))
        return f

    def cping_rs(n):
        n.raw(struct.pack(n.e + 'Q', 0x0123456789abcdef))
        n.u16(2)
        n.u32(0)
    c.call(2, cping_rq([OID_A, OID_A + 1], [OID_A + 2]), cping_rs)
    c.call(2, cping_rq([], []), cping_rs)
    c.call(3, b'', lambda n: n.u32(0))      # ServerAlive

    def r2_rq(protseqs):
        def f(n):
            n.raw(struct.pack(n.e + 'Q', OXID_A))
            n.u16(len(protseqs))
            n.u32(len(protseqs))
            for p in protseqs:
                n.u16(p)
        return f

    def r2_rs(ok):
        def f(n):
            n.ptr(ok)
            if ok:
                d.dsa_conformant(n, *DSA_MULTI)
                n.guid(d.IPID_REMUNKNOWN)
                n.u32(9)
                n.u16(5)
                n.u16(7)
                n.u32(0)
            else:
                n.u32(0x80010113)           # RPC_E_INVALID_IPID
        return f
    c.call(4, r2_rq([7, 8, 9]), r2_rs(True))
    c.call(4, r2_rq([]), r2_rs(False))

    def alive2_rs(dsa):
        def f(n):
            n.u16(5)
            n.u16(7)
            n.raw(struct.pack(n.e + 'Q', 0))
            d.dualstringarray(n, *dsa)
            n.raw(struct.pack(n.e + 'Q', 0))    # read without alignment
        return f
    c.call(5, b'', alive2_rs(DSA_SRV))
    c.call(5, b'', alive2_rs(DSA_EMPTY))
    c.close()


# ----------------------------------------------------------- IRemUnknown(2)
def remunk(frames, uuid=UUID_REMUNK, le=True, port=50107):
    c = Conn(frames, port, uuid, le=le, sport=49155)

    def qi_rq(ipid, iids, refs=5):
        def f(n):
            d.orpcthis(n)
            n.guid(ipid)
            n.u32(refs)
            n.u16(len(iids))
            n.u32(len(iids))
            for i in iids:
                n.guid(i)
        return f

    def qi_rs(results, hr=0):
        def f(n):
            d.orpcthat(n)
            n.ptr(bool(results))
            n.u32(len(results))
            for r_hr, oxid_, oid_, ipid in results:
                n.u32(r_hr)
                n.ptr(True)
                d.stdobjref(n, oxid_, oid_, ipid)
            n.u32(hr)
        return f

    obj = d.IPID_REMUNKNOWN
    c.call(3, qi_rq(IPID_A, [d.IID_IDISPATCH, d.IID_ITYPEINFO,
                             '8e4b2c11-0d3f-4a55-9a0e-1b2c3d4e5f60']),
           qi_rs([(0, OXID_A, OID_A, IPID_B), (0, OXID_A, OID_A, IPID_B),
                  (0x80004002, 0, 0, d.UUID_NULL)]), obj=obj)
    # a new object on the same machine, an OXID of 0, more results than IIDs
    c.call(3, qi_rq(IPID_B, [d.IID_IDISPATCH, d.IID_ITYPEINFO]),
           qi_rs([(0, 0, OID_A, IPID_Z), (0, OXID_A, OID_A + 1, IPID_C),
                  (0, OXID_A, OID_A, IPID_A)]), obj=obj)
    # 100 IIDs: too many to remember for the response
    c.call(3, qi_rq(IPID_A, ['%08x-0000-0000-c000-000000000046' % (0x100 + i) for i in range(100)]),
           qi_rs([(0, OXID_A, OID_A, IPID_C)], 0x80004002), obj=obj)
    c.call(3, qi_rq(IPID_A, []), qi_rs([], 0x80004003), obj=obj)
    # RemAddRef (no dissector for it)
    addref = stub(le, lambda n: (d.orpcthis(n), n.u16(1), n.u32(1), n.guid(IPID_A), n.u32(1), n.u32(0)))
    c.call(4, addref, stub(le, lambda n: (d.orpcthat(n), n.ptr(True), n.u32(1), n.u32(0), n.u32(0))),
           obj=obj)

    def rel_rq(refs):
        def f(n):
            d.orpcthis(n)
            n.ptr(bool(refs))
            n.u32(len(refs))
            for ipid, pub, priv in refs:
                n.guid(ipid)
                n.u32(pub)
                n.u32(priv)
        return f

    def simple_rs(hr):
        def f(n):
            d.orpcthat(n)
            n.u32(hr)
        return f
    c.call(5, rel_rq([(IPID_A, 5, 0)]), simple_rs(0), obj=obj)
    c.call(5, rel_rq([(IPID_B if i % 2 else IPID_C, i + 1, i) for i in range(11)]),
           simple_rs(0x80010108), obj=obj)
    c.call(5, rel_rq([]), simple_rs(1), obj=obj)
    if uuid == UUID_REMUNK2:
        # RemQueryInterface2 (no dissector for it)
        c.call(6, stub(le, lambda n: (d.orpcthis(n), n.guid(IPID_A), n.u16(1), n.u32(1),
                                      n.guid(d.IID_IDISPATCH))),
               stub(le, lambda n: (d.orpcthat(n), n.ptr(True), n.u32(1), n.u32(0), n.u32(0))),
               obj=obj)
    c.close()


# ----------------------------------------------------------- IDispatch
def variants_in():
    disp = std(ipid=IPID_B, iid=d.IID_IDISPATCH, dsa=([(7, '192.0.2.60')], []))
    return [
        (VT['EMPTY'],), (VT['BOOL'], 0xffff), (VT['BOOL'], 0), (VT['I1'], -5), (VT['UI1'], 200),
        (VT['I2'], -300), (VT['UI2'], 60000), (VT['I4'], -70000), (VT['UI4'], 4000000000),
        (VT['I8'], -5000000000000), (VT['UI8'], 1 << 63), (VT['R4'], 1.5), (VT['R8'], 2.25), (VT['DATE'], 45000.5),
        (VT['BSTR'], 'Hello, DCOM'), (VT['BSTR'], None), (VT['BSTR'], b'\x01\x00\xff\xfe'),
        (VT['BSTR'], 'line1\r\nline2'), (VT['ERROR'], 0x80020005),
        (VT['BYREF'] | VT['I4'], 42, VT['BYREF'] | VT['I4']),
        (VT['BYREF'] | VT['BSTR'], 'by reference', VT['BYREF'] | VT['BSTR']),
        (VT['VARIANT'], (VT['I2'], 7)),
        (VT['BYREF'] | VT['VARIANT'], (VT['VARIANT'], (VT['BSTR'], 'nested')),
         VT['BYREF'] | VT['VARIANT']),
        (VT['VARIANT'], None),
        (VT['UNKNOWN'], True), (VT['UNKNOWN'], False),
        (VT['DISPATCH'], disp), (VT['DISPATCH'], None),
        (VT['ARRAY'], dict(vt=VT['I4'], elems=[1, -2, 3]), VT['ARRAY'] | VT['I4']),
        (VT['ARRAY'], dict(vt=VT['BSTR'], elems=['one', None, 'three'], features=0x0180),
         VT['ARRAY'] | VT['BSTR']),
        (VT['ARRAY'], dict(vt=VT['I1'], elems=[1, 2, 3], features=0x0091), VT['ARRAY'] | VT['I1']),
        (VT['ARRAY'], dict(vt=VT['I2'], elems=[-1, 2], dims=((1, 0), (2, 5)), features=0x0fff),
         VT['ARRAY'] | VT['I2']),
        (VT['ARRAY'], dict(vt=VT['I8'], elems=[1 << 40, -1]), VT['ARRAY'] | VT['I8']),
        (VT['ARRAY'], dict(vt=VT['ERROR'], elems=[0, 0x80020009]), VT['ARRAY'] | VT['ERROR']),
        (VT['ARRAY'], dict(vt=VT['I4'], elems=[], dims=()), VT['ARRAY']),
        (VT['I4'], 1, 0x0fff),              # a VarType name that is not known
        (VT['CY'], 123456789), (VT['CY'], -15000),
    ]


def var(n, v):
    if len(v) == 1:
        d.variant(n, v[0])
    elif len(v) == 2:
        d.variant(n, v[0], v[1])
    else:
        d.variant(n, v[0], v[1], vt16=v[2])


def dispatch(frames, le=True, port=50108):
    c = Conn(frames, port, UUID_DISPATCH, le=le, sport=49155)
    c.call(3, lambda n: d.orpcthis(n), lambda n: (d.orpcthat(n), n.u32(1), n.u32(0)), obj=IPID_B)

    def gti_rq(n):
        d.orpcthis(n)
        n.u32(0)
        n.u32(0x409)
    c.call(4, gti_rq, lambda n: (d.orpcthat(n), n.ptr(True),
                                 d.minterfacepointer(n, **std(ipid=IPID_C, iid=d.IID_ITYPEINFO)),
                                 n.u32(0)), obj=IPID_B)
    c.call(4, gti_rq, lambda n: (d.orpcthat(n), n.ptr(False), n.u32(0x8002801d)), obj=IPID_B)

    def names_rq(names):
        def f(n):
            d.orpcthis(n)
            n.guid(d.UUID_NULL)
            n.u32(len(names))
            for nm in names:
                n.ptr(nm is not None)
            for nm in names:
                if nm is not None:
                    d.lpwstr(n, nm)
            n.u32(len(names))
            n.u32(0x409)
        return f

    def names_rs(ids, hr=0):
        def f(n):
            d.orpcthat(n)
            n.u32(len(ids))
            for i in ids:
                n.u32(i)
            n.u32(hr)
        return f
    c.call(5, names_rq(['Visible', 'Open', 'FileName']), names_rs([0x22e, 0x3e8, 0x3e9]), obj=IPID_B)
    c.call(5, names_rq(['NoSuchName', None]), names_rs([0xffffffff, 0xffffffff], 0x80020006),
           obj=IPID_B)

    def inv_rq(dispid, flags, args, named, refs):
        def f(n):
            d.orpcthis(n)
            n.u32(dispid)
            n.guid(d.UUID_NULL)
            n.u32(0x409)
            n.u32(flags)
            n.ptr(args is not None)
            n.ptr(named is not None)
            n.u32(len(args or []))
            n.u32(len(named or []))
            if args is not None:
                n.u32(len(args))
                for _ in args:
                    n.ptr(False)            # see README: the dissector reads on here
            if named is not None:
                n.u32(len(named))
                for i in named:
                    n.u32(i & 0xffffffff)
            n.u32(len(refs))
            n.u32(len(refs))
            for i in range(len(refs)):
                n.u32(i)
            n.u32(len(refs))
            for v in refs:
                n.ptr(v is not None)
            for v in refs:
                if v is not None:
                    var(n, v)
        return f

    def inv_rs(result, exc, refs, hr=0, argerr=0):
        def f(n):
            d.orpcthat(n)
            n.ptr(result is not None)
            if result is not None:
                var(n, result)
            code, src, desc, helpf, scode = exc
            n.u16(code)
            n.u16(0)
            n.ptr(src is not None)
            n.ptr(desc is not None)
            n.ptr(helpf is not None)
            n.u32(0x1234)
            n.u32(0)
            n.u32(0)
            n.u32(scode)
            for s in (src, desc, helpf):
                if s is not None:
                    d.bstr(n, s)
            n.u32(argerr)
            n.u32(len(refs))
            for v in refs:
                n.ptr(v is not None)
            for v in refs:
                if v is not None:
                    var(n, v)
            n.u32(hr)
        return f

    vin = variants_in()
    no_exc = (0, None, None, None, 0)
    c.call(6, inv_rq(0x3e8, 1, [1, 2], [0xfffffffd], vin + [None]),
           inv_rs((VT['BSTR'], 'done'), no_exc, vin[:12] + [None]), obj=IPID_B)
    c.call(6, inv_rq(0x22e, 2, None, None, []), inv_rs((VT['BOOL'], 0xffff), no_exc, []), obj=IPID_B)
    c.call(6, inv_rq(0x3e9, 4 | 8, [1], [0xfffffffd], [(VT['BSTR'], 'C:\\docs\\report.doc')]),
           inv_rs(None, (0x3ec, 'Word', 'The file could not be found.', 'C:\\help\\word.chm',
                         0x80020009), [], 0x80020009, 1), obj=IPID_B)
    c.call(6, inv_rq(0x3ea, 0, None, None, [(VT['I4'], 1)]),
           inv_rs((VT['EMPTY'],), (0, 'Excel', None, None, 0x80020005), [(VT['I4'], 2)], 0x80020005),
           obj=IPID_B)
    c.close()


def provideclassinfo(frames, port=50110):
    c = Conn(frames, port, UUID_PROVIDECLASSINFO, sport=49155)
    c.call(3, lambda n: d.orpcthis(n),
           lambda n: (d.orpcthat(n), d.pminterfacepointer(n, **std(ipid=IPID_C, iid=d.IID_ITYPEINFO)),
                      n.u32(0)), obj=IPID_B)
    c.call(3, lambda n: d.orpcthis(n), lambda n: (d.orpcthat(n), n.ptr(False), n.u32(0x80004001)),
           obj=IPID_B)
    # an OBJREF of a second machine (the first string binding is
    # 192.0.2.61), and a custom OBJREF with a NULL IID
    c.call(3, lambda n: d.orpcthis(n),
           lambda n: (d.orpcthat(n), d.pminterfacepointer(n, **std(ipid=IPID_C, iid=d.IID_ITYPEINFO,
                                                                   dsa=DSA_M2, oid=OID_A + 7)),
                      n.u32(0)), obj=IPID_B)
    c.call(3, lambda n: d.orpcthis(n),
           lambda n: (d.orpcthat(n), d.pminterfacepointer(n, kind='custom', iid=d.UUID_NULL,
                                                           payload=b''), n.u32(0)), obj=IPID_B)
    c.close()


# ----------------------------------------------------------- reproducers
def repro_recursion(frames, n_nest, port=50411):
    """dcom_objref_recursion.py with N nested custom OBJREFs for IStorage
    (the payload is built exactly as the reproducer builds it)"""
    from dcom_lib import guid_le, orpcthis as r_orpcthis, call_frag, IID_ISTORAGE, NULL_GUID, UUID_ISYSACT
    one = struct.pack('<II', 0x574f454d, 4) + guid_le(IID_ISTORAGE) + guid_le(NULL_GUID) + struct.pack('<II', 0, 0)
    objref = one * n_nest + struct.pack('<II', 0x574f454d, 0) + guid_le(NULL_GUID)
    req = r_orpcthis() + struct.pack('<III', 0x00020000, len(objref), len(objref)) + objref
    t = dcom_bdef_rpclib.TCP(frames, port, sport=135)
    r = dcom_bdef_rpclib.RPC(t, uuid=UUID_ISYSACT, ver=(0, 0))
    r.bind()
    call_frag(r, 3, req)
    t.fin()


def repro_marshaler_2pass(frames, port=50412):
    """dcom_marshaler_2pass.py: an IWbemServices GetObject request with
    an [in] WMIO object (custom OBJREF) before any IWbemServices reply"""
    from dcom_lib import guid_le, orpcthis as r_orpcthis, orpcthat as r_orpcthat, IID_WMIO, NULL_GUID, \
        UUID_IWBEMSERVICES
    wmio = struct.pack('<I', 0x12345678) + b'\0' * 12
    objref = struct.pack('<II', 0x574f454d, 4) + guid_le(IID_WMIO) + guid_le(NULL_GUID)
    objref += struct.pack('<II', 0, len(wmio)) + wmio
    s = struct.pack('<II', 0x00020000, 0x00020004) + struct.pack('<II', len(objref), len(objref)) + objref
    s += b'\0' * ((-len(s)) % 4)
    req = r_orpcthis() + struct.pack('<I', 0) + struct.pack('<I', 0) + struct.pack('<II', 0, 0)
    req += s + struct.pack('<I', 0)
    resp = r_orpcthat() + struct.pack('<I', 0) + struct.pack('<I', 0) + struct.pack('<I', 0)
    t = dcom_bdef_rpclib.TCP(frames, port)
    r = dcom_bdef_rpclib.RPC(t, uuid=UUID_IWBEMSERVICES, ver=(0, 0))
    r.bind()
    r.call(6, req, resp)
    t.fin()


# ----------------------------------------------------------- malformed
def malformed(frames):
    """Connections whose packets only decode as malformed: one call per
    problem, each answered so the next request is matched."""
    # IDispatch: VARIANTs the dissector cannot handle
    c = Conn(frames, 50201, UUID_DISPATCH, sport=49155)

    def inv(refs, raw_tail=b''):
        def f(n):
            d.orpcthis(n)
            n.u32(1)
            n.guid(d.UUID_NULL)
            n.u32(0x409)
            n.u32(1)
            n.ptr(False)
            n.ptr(False)
            n.u32(0)
            n.u32(0)
            n.u32(len(refs))
            n.u32(len(refs))
            for i in range(len(refs)):
                n.u32(i)
            n.u32(len(refs))
            for _ in refs:
                n.ptr(True)
            for v in refs:
                if callable(v):
                    v(n)
                else:
                    var(n, v)
            n.raw(raw_tail)
        return f
    ok = lambda n: (d.orpcthat(n), n.ptr(False), n.u16(0), n.u16(0), n.ptr(False), n.ptr(False),
                    n.ptr(False), n.u32(0), n.u32(0), n.u32(0), n.u32(0), n.u32(0), n.u32(0), n.u32(0))
    # VT_NULL and a SAFEARRAY of VT_R8: "to be done", 10000 octets
    c.call(6, inv([lambda n: (n.align(8), n.u32(0x18), n.u32(0), n.u16(1), n.u16(0), n.u16(0),
                              n.u16(0), n.u32(1))]), ok)
    # a SAFEARRAY whose 32-bit VarType is VT_R8
    def sa_r8_real(n):
        n.align(8)
        n.u32(0x30)
        n.u32(0)
        n.u16(VT['ARRAY'] | VT['R8'])
        n.u16(0)
        n.u16(0)
        n.u16(0)
        n.u32(VT['ARRAY'])
        n.ptr(True)
        n.ptr(True)
        n.u32(1)
        n.u16(1)
        n.u16(0x80)
        n.u32(8)
        n.u16(0)
        n.u16(VT['R8'])
        n.u32(VT['R8'])
        n.u32(1)
        n.ptr(True)
        n.u32(1)
        n.u32(0)
        n.u32(1)
        n.raw(struct.pack('<d', 1.0))
    c.call(6, inv([sa_r8_real]), ok)
    # BSTR whose character count wraps the offset back before the BSTR,
    # and one whose end is beyond INT_MAX
    def bstr_count(cnt, data):
        def f(n):
            n.align(8)
            n.u32(0x20)
            n.u32(0)
            n.u16(VT['BSTR'])
            n.u16(0)
            n.u16(0)
            n.u16(0)
            n.u32(VT['BSTR'])
            n.ptr(True)
            n.u32(cnt)
            n.u32(len(data))
            n.u32(cnt)
            n.raw(data)
        return f
    c.call(6, inv([bstr_count(0x7ffffffa, 'Hi\0'.encode('utf-16-le'))]), ok)
    c.call(6, inv([bstr_count(0x40000000, 'Hi\0'.encode('utf-16-le'))]), ok)

    # 600 nested VT_VARIANTs: the dissection depth limit
    def deep(n, k=600):
        for _ in range(k):
            n.align(8)
            n.u32(0x20)
            n.u32(0)
            n.u16(VT['VARIANT'])
            n.u16(0)
            n.u16(0)
            n.u16(0)
            n.u32(VT['VARIANT'])
            n.ptr(True)
        d.variant(n, VT['I4'], 1)
    c.call(6, inv([deep]), ok)
    # the request ends inside the VARIANT array
    c.call(6, stub(True, inv([(VT['I4'], 1), (VT['BSTR'], 'cut')]))[:-10], ok)
    c.close()

    # OBJREF and DUALSTRINGARRAY problems (IProvideClassInfo responses)
    c = Conn(frames, 50202, UUID_PROVIDECLASSINFO, sport=49155)
    req = lambda n: d.orpcthis(n)
    full = stub(True, lambda n: (d.orpcthat(n), d.pminterfacepointer(n, **std()), n.u32(0)))
    c.call(3, req, full[:60])                       # OBJREF cut short
    nodsa = stub(True, lambda n: (d.orpcthat(n), n.ptr(True), n.u32(200), n.u32(200),
                                  n.u32(0x574f454d), n.u32(1), n.guid(d.IID_IUNKNOWN),
                                  d.stdobjref(n, OXID_A, OID_A, IPID_A), n.u16(40), n.u16(30),
                                  n.u16(7), n.raw('192.0.2.60'.encode('utf-16-le'))))
    c.call(3, req, nodsa)                           # string binding without terminator
    nosec = stub(True, lambda n: (d.orpcthat(n), n.ptr(True), n.u32(200), n.u32(200),
                                  n.u32(0x574f454d), n.u32(1), n.guid(d.IID_IUNKNOWN),
                                  d.stdobjref(n, OXID_A, OID_A, IPID_A), n.u16(40), n.u16(2),
                                  n.u16(0), n.u16(10), n.u16(0xffff), n.raw('ab'.encode('utf-16-le'))))
    c.call(3, req, nosec)                           # security binding without terminator
    # ORPCTHIS whose extent array is larger than the stub
    c.call(3, lambda n: (d.orpcthis(n, [None]), n.b.__setitem__(slice(-8, -4), struct.pack('<I', 5000))),
           full)
    # extent data larger than the stub
    c.call(3, lambda n: (d.orpcthis(n, [(d.UUID_DEBUG_EXT, b'abcd')]),
                         n.b.__setitem__(slice(-8, -4), struct.pack('<I', 0x10000))), full)
    c.close()

    # IRemUnknown: counts larger than the data
    c = Conn(frames, 50203, UUID_REMUNK, sport=49155)
    c.call(5, lambda n: (d.orpcthis(n), n.ptr(True), n.u32(1000), n.guid(IPID_A), n.u32(1), n.u32(0)),
           lambda n: (d.orpcthat(n), n.u32(0)), obj=d.IPID_REMUNKNOWN)
    c.call(3, lambda n: (d.orpcthis(n), n.guid(IPID_A), n.u32(1), n.u16(1), n.u32(70000)),
           lambda n: (d.orpcthat(n), n.ptr(True), n.u32(1000), n.u32(0)), obj=d.IPID_REMUNKNOWN)
    c.close()

    # IOXIDResolver: a ComplexPing with more OIDs than present
    c = Conn(frames, 50204, UUID_OXID)
    c.call(2, lambda n: (n.raw(struct.pack('<Q', 1)), n.u16(1), n.u16(50), n.u16(0), n.ptr(True),
                         n.u32(50), n.raw(struct.pack('<Q', 1))), lambda n: n.u32(0))
    c.close()

    # ISystemActivator: a known property of size 0 at the end of the
    # blob, and a blob shorter than its custom header
    c = Conn(frames, 50205, UUID_SYSACT)

    def gc(props, **kw):
        return lambda n: (d.orpcthis(n), d.pminterfacepointer(n, **actprops(props, **kw)))
    c.call(3, gc([(d.CLSID_SERVER_LOCATION_INFO, p_location()), (d.CLSID_INSTANCE_INFO, None)]),
           lambda n: (d.orpcthat(n), n.ptr(False), n.u32(0)))
    cut = stub(True, gc(props_in_full()))
    c.call(3, cut[:400], lambda n: (d.orpcthat(n), n.ptr(False), n.u32(0)))
    c.close()

    # the reproducer of the stack overflow: 1000 nested custom OBJREFs
    repro_recursion(frames, 1000, port=50411)


def main(outdir):
    frames = []
    remact(frames)
    repro_marshaler_2pass(frames)
    sysact(frames)
    sysact(frames, le=False, port=50103)
    sysact_mismatch(frames)
    repro_recursion(frames, 8)
    oxid(frames)
    oxid(frames, le=False, port=50106)
    remunk(frames)
    remunk(frames, UUID_REMUNK2, port=50109)
    dispatch(frames)
    dispatch(frames, le=False, port=50111)
    provideclassinfo(frames)
    pcap(os.path.join(outdir, 'dcom-coverage.pcap'), frames)

    bad = []
    malformed(bad)
    pcap(os.path.join(outdir, 'dcom-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
