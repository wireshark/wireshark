#!/usr/bin/env python3
# Generates test/captures/giop_coverage.pcap.gz, giop_ior.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-giop.c.  Usage: mkgiop.py <outdir> [-v]
Writes giop-coverage.pcap(.gz), giop-coverage-malformed.pcap and giop_ior.txt."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import zlib
import util as u
from cdr import (
    CDR, encap, giop, iiop_profile, ior, reply_10, reply_12, request_10, request_12, S,
    svc_codeset, svc_empty, svc_rtprio, svc_unknown, sys_exc, tc_abstract, tc_alias, tc_array,
    tc_enum, tc_except, tc_fixed, tc_native, tc_objref, tc_sequence, tc_string, tc_struct,
    tc_union, tc_value, tc_value_box, tc_wstring, tk_any, tk_boolean, tk_char, tk_double,
    tk_fixed, tk_float, tk_long, tk_longdouble, tk_longlong, tk_null, tk_octet, tk_Principal,
    tk_short, tk_TypeCode, tk_ulong, tk_ulonglong, tk_ushort, tk_void, tk_wchar,
)

NS_REPO = 'IDL:CosNaming/NamingContext:1.0'
KEYA = b'KEYA'
FILEKEY = b'FILEKEY1'
IOR_FILE_KEY = b'FILEKEY1'


def mkior(c, type_id=NS_REPO, key=KEYA, host='ns.example.test', port=2809):
    ior(c, type_id, [(0, iiop_profile(host, port, key, 0)),
                     (0, iiop_profile('h2.example.test', 2810, key + b'2', 2, comps=[(1, b'\0\0\0\0'), (0x4f4d4701, b'abc')])),
                     (1, bytes([0]) + b'multiple components'),
                     (0x12345678, b'\0proprietary\0'),
                     (2, b'')])


def mkior_hex(type_id, key, host='ior.example.test', port=2811, minor=0, le=False):
    c = CDR(0, le)
    c.octet(1 if le else 0)
    ior(c, type_id, [(0, iiop_profile(host, port, key, minor, comps=[(0x1234, b'xy')] if minor else (), le=le))])
    return 'IOR:' + c.bytes().hex()


def write_ior_file(path):
    lines = [mkior_hex(NS_REPO, FILEKEY, minor=0),
             mkior_hex('IDL:Tango/Device_4:1.0', b'TANGOKEY', minor=1, le=True),
             mkior_hex('IDL:GIAS/CatalogMgr:1.0', b'GIASCAT', minor=2),
             'IOR:00000000',                    # no usable IOR (type id missing: exception, ignored)
             'IOR:zz',                            # not hex
             mkior_hex('IDL:short/Obj:1.0', b'K')[:30],   # truncated IOR
             '']
    with open(path, 'w') as f:
        f.write('\n'.join(lines))


def svc_codeset_extra(c):
    c.ulong(1)
    c.seq(encap(lambda e: e.ulong(0x00010001).ulong(0x00010109).raw(b'\1\2\3\4'), c.le))


def tango_args(any_fn, source=1, clnt=None):
    def f(c):
        c.string('GetStatus')
        any_fn(c)
        c.ulong(source)
        if clnt is None:
            c.ulong(7)
        else:
            c.ulong(0); c.ulong(clnt)
    return f


def tango_req(rid, any_fn, key=b'dev', minor=2, le=False, source=1, clnt=None, ctx=None):
    if minor == 2:
        return request_12(rid, ('key', key), 'command_inout_4', tango_args(any_fn, source, clnt), le, ctx)
    return request_10(rid, key, 'command_inout_4', minor=minor, le=le, ctx=ctx, args_fn=tango_args(any_fn, source, clnt))


def tango_rep(rid, any_fn, minor=2, le=False):
    if minor == 2:
        return reply_12(rid, 0, any_fn, le)
    return reply_10(rid, 0, any_fn, le)


def any_of(tcfn, datafn=None):
    def f(c):
        tcfn(c)
        if datafn:
            datafn(c)
    return f


def typecode_cases(minor=2, le=False):
    """list of (name, any_fn)"""
    cs = []
    simple = [('s', S(tk_short)), ('l', S(tk_long)), ('us', S(tk_ushort)), ('ul', S(tk_ulong)),
              ('f', S(tk_float)), ('d', S(tk_double)), ('b', S(tk_boolean)), ('c', S(tk_char)),
              ('o', S(tk_octet)), ('ll', S(tk_longlong)), ('ull', S(tk_ulonglong))]
    def simple_data(c):
        c.short(-5).long(-70000).ushort(65000).ulong(4000000000).float(1.5).double(-2.25)
        c.boolean(True).char(0x41).octet(200).longlong(-(1 << 40)).ulonglong(1 << 50)
    cs.append(('simple_struct', any_of(lambda c: tc_struct(c, simple, 'IDL:demo/Simple:1.0', 'Simple'), simple_data)))
    cs.append(('null', any_of(S(tk_null))))
    cs.append(('void', any_of(S(tk_void))))
    for k, name, d in ((tk_short, 'short', lambda c: c.short(-3)), (tk_long, 'long', lambda c: c.long(-9)),
                       (tk_ushort, 'ushort', lambda c: c.ushort(3)), (tk_ulong, 'ulong', lambda c: c.ulong(9)),
                       (tk_float, 'float', lambda c: c.float(3.5)), (tk_double, 'double', lambda c: c.double(7.25)),
                       (tk_boolean, 'boolean', lambda c: c.boolean(False)), (tk_char, 'char', lambda c: c.char(0x7a)),
                       (tk_octet, 'octet', lambda c: c.octet(9)), (tk_longlong, 'longlong', lambda c: c.longlong(-1)),
                       (tk_ulonglong, 'ulonglong', lambda c: c.ulonglong(2))):
        cs.append((name, any_of(S(k), d)))
    # any in any, TypeCode in any
    cs.append(('any_any', any_of(S(tk_any), lambda c: (S(tk_ulong)(c), c.ulong(77)))))
    cs.append(('any_typecode', any_of(S(tk_TypeCode), lambda c: tc_string(c, 10))))
    cs.append(('principal', any_of(S(tk_Principal))))
    cs.append(('objref', any_of(lambda c: tc_objref(c))))
    cs.append(('native', any_of(lambda c: tc_native(c))))
    cs.append(('abstract', any_of(lambda c: tc_abstract(c))))
    cs.append(('longdouble', any_of(S(tk_longdouble))))
    cs.append(('fixed', any_of(lambda c: tc_fixed(c, 5, 2))))
    cs.append(('string', any_of(lambda c: tc_string(c, 32), lambda c: c.string('hello typecode'))))
    cs.append(('string_empty', any_of(lambda c: tc_string(c, 0), lambda c: c.ulong(0))))
    cs.append(('wstring', any_of(lambda c: tc_wstring(c, 0),
                                 lambda c: (c.ulong(4 if minor == 2 else 2), c.raw(b'\0A\0B')))))
    cs.append(('wchar', any_of(S(tk_wchar),
                               lambda c: (c.octet(2), c.raw(b'\0Z')) if minor == 2 else c.raw(b'\0Z'))))
    cs.append(('enum', any_of(lambda c: tc_enum(c, ['RED', 'GREEN', 'BLUE']), lambda c: c.ulong(1))))
    cs.append(('enum_out_of_range', any_of(lambda c: tc_enum(c, ['A', 'B']), lambda c: c.ulong(9))))
    cs.append(('seq_long', any_of(lambda c: tc_sequence(c, S(tk_long), 0), lambda c: (c.ulong(3), c.long(1), c.long(2), c.long(3)))))
    cs.append(('seq_bounded', any_of(lambda c: tc_sequence(c, S(tk_ushort), 8), lambda c: (c.ulong(2), c.ushort(5), c.ushort(6)))))
    cs.append(('seq_empty', any_of(lambda c: tc_sequence(c, S(tk_long), 0), lambda c: c.ulong(0))))
    cs.append(('seq_string', any_of(lambda c: tc_sequence(c, lambda e: tc_string(e, 0), 0),
                                    lambda c: (c.ulong(2), c.string('one'), c.string('two')))))
    cs.append(('array', any_of(lambda c: tc_array(c, S(tk_ushort), 3), lambda c: (c.ushort(1), c.ushort(2), c.ushort(3)))))
    cs.append(('array_of_struct', any_of(
        lambda c: tc_array(c, lambda e: tc_struct(e, [('x', S(tk_octet)), ('y', S(tk_octet))], 'IDL:demo/P:1.0', 'P'), 2),
        lambda c: (c.octet(1), c.octet(2), c.octet(3), c.octet(4)))))
    cs.append(('alias', any_of(lambda c: tc_alias(c, S(tk_ulong)), lambda c: c.ulong(123))))
    cs.append(('alias_alias', any_of(lambda c: tc_alias(c, lambda e: tc_alias(e, lambda x: tc_string(x, 0), 'IDL:demo/B:1.0', 'B')),
                                     lambda c: c.string('aliased'))))
    cs.append(('nested_struct', any_of(
        lambda c: tc_struct(c, [('a', lambda e: tc_struct(e, [('i', S(tk_long)), ('s', lambda x: tc_string(x, 0))], 'IDL:demo/In:1.0', 'In')),
                                ('e', lambda e: tc_enum(e, ['X', 'Y'])),
                                ('q', lambda e: tc_sequence(e, S(tk_octet), 0)),
                                ('t', S(tk_TypeCode)),
                                ('n', S(tk_any)),
                                ('arr', lambda e: tc_array(e, S(tk_octet), 2))], 'IDL:demo/Out:1.0', 'Out'),
        lambda c: (c.long(5), c.string('in'), c.ulong(1), c.ulong(2), c.octet(7), c.octet(8),
                   S(tk_double)(c), S(tk_long)(c), c.long(11), c.octet(1), c.octet(2)))))
    cs.append(('union', any_of(lambda c: tc_union(
        c, S(tk_long), [(lambda e: e.long(1), 'one', S(tk_short)), (lambda e: e.long(2), 'two', lambda x: tc_string(x, 0))]))))
    cs.append(('union_enum_disc', any_of(lambda c: tc_union(
        c, lambda e: tc_enum(e, ['P', 'Q']), [(lambda e: e.ulong(0), 'p', S(tk_octet)), (lambda e: e.ulong(1), 'q', S(tk_double))], 1))))
    cs.append(('except', any_of(lambda c: tc_except(c, [('why', lambda e: tc_string(e, 0)), ('code', S(tk_long))]))))
    cs.append(('value', any_of(lambda c: tc_value(c, [('a', S(tk_long), 1), ('b', lambda e: tc_string(e, 0), 0)], base=lambda e: tc_value(e, [], 'IDL:demo/VBase:1.0', 'VBase', 1)))))
    cs.append(('value_box', any_of(lambda c: tc_value_box(c, S(tk_long)))))
    cs.append(('struct_empty', any_of(lambda c: tc_struct(c, []))))
    cs.append(('enum_empty', any_of(lambda c: tc_enum(c, []), lambda c: c.ulong(0))))
    return cs


def tcp_msg(conn, msg, direction, seg=None):
    if direction == 'c':
        conn.send(msg) if seg is None else conn.csegs(msg, seg)
    else:
        conn.recv(msg) if seg is None else conn.ssegs(msg, seg)


def main_frames(ior_txt_keys=True):
    o = []
    # ===== A: TCP, GIOP 1.0, big endian =====
    A = u.Conn(o, 40000, 2809)
    def pair(conn, rid, req, rep, minor, le=False, seg=None):
        tcp_msg(conn, giop(minor, 0, req.bytes(), le), 'c', seg)
        tcp_msg(conn, giop(minor, 1, rep.bytes(), le), 's', seg)
    # _is_a, with service contexts (CodeSet, RT priority, unknown OMG, vendor, empty)
    ctx = [lambda c: svc_codeset(c), lambda c: svc_rtprio(c), lambda c: svc_unknown(c, 7),
           lambda c: svc_unknown(c, 0x49534f05, b'vendor'), lambda c: svc_empty(c, 8),
           lambda c: svc_unknown(c, 9, b''), lambda c: svc_codeset_extra(c), lambda c: svc_unknown(c, 1, b'')]
    tcp_msg(A, giop(0, 0, request_10(1, b'KEY1', '_is_a', ctx=ctx, principal=b'root\0',
                                     args_fn=lambda c: c.string(NS_REPO)).bytes()), 'c')
    tcp_msg(A, giop(0, 1, reply_10(1, 0, lambda c: c.boolean(True), ctx=[lambda c: svc_codeset(c)]).bytes()), 's')
    # resolve + Reply with an IOR (learns KEYA)
    def name_args(c):
        c.ulong(2); c.string('a'); c.string('kind'); c.string('b'); c.string('')
    tcp_msg(A, giop(0, 0, request_10(2, b'NS', 'resolve', args_fn=name_args).bytes()), 'c')
    tcp_msg(A, giop(0, 1, reply_10(2, 0, lambda c: mkior(c)).bytes()), 's')
    # explicit CosNaming requests to KEYA
    tcp_msg(A, giop(0, 0, request_10(3, KEYA, 'list', args_fn=lambda c: c.ulong(10)).bytes()), 'c')
    def list_rep(c):
        c.ulong(0); c.string(''); c.ulong(0)
    tcp_msg(A, giop(0, 1, reply_10(3, 0, list_rep).bytes()), 's')
    tcp_msg(A, giop(0, 0, request_10(4, KEYA, 'destroy', resp=0).bytes()), 'c')
    tcp_msg(A, giop(0, 0, request_10(5, KEYA, 'destroy').bytes()), 'c')
    # every reply status for request 5
    def nf_exc(c):
        c.string('IDL:omg.org/CosNaming/NamingContext/NotFound:1.0')
        c.ulong(1); c.ulong(1); c.string('a'); c.string('k')
    tcp_msg(A, giop(0, 1, reply_10(5, 1, nf_exc).bytes()), 's')            # USER_EXCEPTION
    tcp_msg(A, giop(0, 1, reply_10(5, 1, lambda c: c.ulong(0)).bytes()), 's')    # USER_EXCEPTION, empty id
    tcp_msg(A, giop(0, 1, reply_10(5, 2, lambda c: sys_exc(c)).bytes()), 's')    # SYSTEM_EXCEPTION
    tcp_msg(A, giop(0, 1, reply_10(5, 3, lambda c: mkior(c, key=b'FWD1')).bytes()), 's')   # LOCATION_FORWARD
    tcp_msg(A, giop(0, 1, reply_10(5, 4, lambda c: mkior(c, key=b'FWD2')).bytes()), 's')   # LOCATION_FORWARD_PERM
    tcp_msg(A, giop(0, 1, reply_10(5, 5, lambda c: c.ushort(1)).bytes()), 's')    # NEEDS_ADDRESSING_MODE
    tcp_msg(A, giop(0, 1, reply_10(5, 9, lambda c: c.raw(b'unknown status body')).bytes()), 's')
    tcp_msg(A, giop(0, 1, reply_10(5, 9, None).bytes()), 's')     # no body
    tcp_msg(A, giop(0, 1, reply_10(5, 0, None).bytes()), 's')     # NO_EXCEPTION, no body
    tcp_msg(A, giop(0, 1, reply_10(99, 0, lambda c: c.raw(b'xx')).bytes()), 's')  # reply to unknown request
    # CancelRequest, LocateRequest/Reply 1.0
    tcp_msg(A, giop(0, 2, CDR(12).ulong(5).bytes()), 'c')
    tcp_msg(A, giop(0, 3, CDR(12).ulong(6).seq(KEYA).bytes()), 'c')
    tcp_msg(A, giop(0, 3, CDR(12).ulong(7).seq(b'').bytes()), 'c')
    for st in (0, 1):
        tcp_msg(A, giop(0, 4, CDR(12).ulong(6).ulong(st).bytes()), 's')
    c = CDR(12); c.ulong(6).ulong(2); mkior(c, key=b'LOC1'); tcp_msg(A, giop(0, 4, c.bytes()), 's')
    c = CDR(12); c.ulong(6).ulong(3); mkior(c, key=b'LOC2'); tcp_msg(A, giop(0, 4, c.bytes()), 's')
    c = CDR(12); c.ulong(6).ulong(4); sys_exc(c); tcp_msg(A, giop(0, 4, c.bytes()), 's')
    c = CDR(12); c.ulong(6).ulong(5); c.ushort(2); tcp_msg(A, giop(0, 4, c.bytes()), 's')
    c = CDR(12); c.ulong(6).ulong(9); tcp_msg(A, giop(0, 4, c.bytes()), 's')
    # CloseConnection, MessageError, Fragment (size 0)
    tcp_msg(A, giop(0, 5, b''), 'c')
    tcp_msg(A, giop(0, 6, b''), 's')
    tcp_msg(A, giop(0, 7, b''), 's')
    # unknown message type
    tcp_msg(A, giop(0, 9, b'\0\0\0\1'), 's')
    A.fin()

    # ===== B: TCP, GIOP 1.1, little endian =====
    B = u.Conn(o, 40001, 2809)
    tcp_msg(B, giop(1, 0, request_10(1, b'DEVB', 'get_name', minor=1, le=True, ctx=[lambda c: svc_codeset(c), lambda c: svc_rtprio(c, -3)],
                                    principal=b'\x01\x02pri').bytes(), le=True), 'c')
    tcp_msg(B, giop(1, 1, reply_10(1, 0, lambda c: c.string('device-name'), le=True).bytes(), le=True), 's')
    # MIOP prefixed request (UIPMC profile)
    tcp_msg(B, giop(1, 0, request_10(2, b'', 'miop_op', minor=1, le=True, miop=b'\0\1\2\3\4\5').bytes(), le=True), 'c')
    # long operation name, empty operation
    tcp_msg(B, giop(1, 0, request_10(3, b'DEVB', 'x' * 120, minor=1, le=True).bytes(), le=True), 'c')
    tcp_msg(B, giop(1, 0, request_10(4, b'DEVB', '', minor=1, le=True).bytes(), le=True), 'c')
    # request with an empty object key
    tcp_msg(B, giop(1, 0, request_10(5, b'', 'op_nokey', minor=1, le=True).bytes(), le=True), 'c')
    # 1.1 locate request/reply and cancel (LE)
    tcp_msg(B, giop(1, 3, CDR(12, True).ulong(9).seq(b'DEVB').bytes(), le=True), 'c')
    c = CDR(12, True); c.ulong(9).ulong(2); mkior(c, key=b'B-LOC'); tcp_msg(B, giop(1, 4, c.bytes(), le=True), 's')
    tcp_msg(B, giop(1, 2, CDR(12, True).ulong(9).bytes(), le=True), 'c')
    # Reply with every status, LE
    for st, fn in ((2, lambda c: sys_exc(c, 'IDL:omg.org/CORBA/COMM_FAILURE:1.0', 3, 2)),
                   (3, lambda c: mkior(c, key=b'BFWD')), (5, lambda c: c.ushort(0)),
                   (1, lambda c: (c.string('IDL:demo/Err:1.0'), c.raw(b'\0\0\0\1')))):
        tcp_msg(B, giop(1, 1, reply_10(1, st, fn, le=True).bytes(), le=True), 's')
    tcp_msg(B, giop(1, 6, b'', le=True), 's')
    B.fin()

    # ===== C: TCP, GIOP 1.2, big endian =====
    C = u.Conn(o, 40002, 2809)
    ctx12 = [lambda c: svc_codeset(c), lambda c: svc_unknown(c, 0x4f4d4701)]
    def nargs(c):
        c.ulong(1); c.string('svc'); c.string('')
    tcp_msg(C, giop(2, 0, request_12(1, ('key', KEYA), 'resolve', nargs, ctx=ctx12).bytes()), 'c')
    tcp_msg(C, giop(2, 1, reply_12(1, 0, lambda c: mkior(c, key=b'C-OBJ'), ctx=[lambda c: svc_rtprio(c)]).bytes()), 's')
    # request without arguments (no alignment), with all response flags
    for rid, fl in ((2, 0), (3, 1), (4, 3), (5, 2)):
        tcp_msg(C, giop(2, 0, request_12(rid, ('key', b'C-OBJ'), 'ping', None, flags=fl).bytes()), 'c')
    # empty key address
    tcp_msg(C, giop(2, 0, request_12(6, ('key', b''), 'ping').bytes()), 'c')
    # profile address, reference address, unknown address disposition
    prof = iiop_profile('p.example.test', 2810, b'PKEY', 1, comps=[(7, b'zz')])
    tcp_msg(C, giop(2, 0, request_12(7, ('profile', 0, prof), 'ping').bytes()), 'c')
    tcp_msg(C, giop(2, 0, request_12(8, ('ref', 0, lambda c: mkior(c, key=b'RKEY')), 'ping').bytes()), 'c')
    tcp_msg(C, giop(2, 0, request_12(9, ('other', 5), 'ping').bytes()), 'c')
    # replies of every status
    tcp_msg(C, giop(2, 1, reply_12(2, 2, lambda c: sys_exc(c)).bytes()), 's')
    tcp_msg(C, giop(2, 1, reply_12(3, 3, lambda c: mkior(c, key=b'C-FWD')).bytes()), 's')
    tcp_msg(C, giop(2, 1, reply_12(4, 4, lambda c: mkior(c, key=b'C-FWDP')).bytes()), 's')
    tcp_msg(C, giop(2, 1, reply_12(5, 5, lambda c: c.ushort(2)).bytes()), 's')
    tcp_msg(C, giop(2, 1, reply_12(5, 1, lambda c: c.string('IDL:demo/UserEx:1.0')).bytes()), 's')
    tcp_msg(C, giop(2, 1, reply_12(5, 0, None).bytes()), 's')
    tcp_msg(C, giop(2, 1, reply_12(5, 8, lambda c: c.raw(b'status eight')).bytes()), 's')
    # Cancel, Locate (key, profile, reference), LocateReply
    tcp_msg(C, giop(2, 2, CDR(12).ulong(5).bytes()), 'c')
    c = CDR(12); c.ulong(20).ushort(0).seq(b'C-OBJ'); tcp_msg(C, giop(2, 3, c.bytes()), 'c')
    c = CDR(12); c.ulong(21).ushort(1).ulong(0).seq(prof); tcp_msg(C, giop(2, 3, c.bytes()), 'c')
    c = CDR(12); c.ulong(22).ushort(2).ulong(1); mkior(c, key=b'LREF'); tcp_msg(C, giop(2, 3, c.bytes()), 'c')
    c = CDR(12); c.ulong(23).ushort(7); tcp_msg(C, giop(2, 3, c.bytes()), 'c')
    for st, fn in ((0, None), (1, None), (2, lambda c: mkior(c, key=b'L-FWD')), (3, lambda c: mkior(c, key=b'L-FWDP')),
                   (4, lambda c: sys_exc(c)), (5, lambda c: c.ushort(1)), (6, None)):
        c = CDR(12); c.ulong(20).ulong(st)
        c.align(8)
        if fn: fn(c)
        tcp_msg(C, giop(2, 4, c.bytes()), 's')
    # fragmented Request: first fragment (flag 0x02), two Fragment messages, last one without the flag
    def args30(c): c.string('part-one'); c.string('part-two ' * 3)
    full = request_12(30, ('key', b'C-OBJ'), 'fragmented', args30).bytes()
    hdr = len(request_12(30, ('key', b'C-OBJ'), 'fragmented', None).bytes())
    cut1 = (hdr + 12 + 7) // 8 * 8 - 12
    cut2 = cut1 + 17
    tcp_msg(C, giop(2, 0, full[:cut1], flags=2), 'c')
    tcp_msg(C, giop(2, 7, struct.pack('>I', 30) + full[cut1:cut2], flags=2), 'c')
    tcp_msg(C, giop(2, 7, struct.pack('>I', 30) + full[cut2:]), 'c')
    # fragmented Reply, in the other direction; the middle fragment is delivered twice
    rfull = reply_12(30, 0, lambda c: c.string('fragmented reply ' * 5)).bytes()
    tcp_msg(C, giop(2, 1, rfull[:16], flags=2), 's')
    tcp_msg(C, giop(2, 7, struct.pack('>I', 30) + rfull[16:48], flags=2), 's')
    tcp_msg(C, giop(2, 7, struct.pack('>I', 30) + rfull[48:]), 's')
    # GIOP messages in TCP segments: split anywhere, two in one segment, header split
    m1 = giop(2, 0, request_12(40, ('key', b'C-OBJ'), 'split_me', lambda c: c.string('x' * 200)).bytes())
    tcp_msg(C, m1, 'c', seg=70)
    m2 = giop(2, 0, request_12(41, ('key', b'C-OBJ'), 'two_a').bytes())
    m3 = giop(2, 0, request_12(42, ('key', b'C-OBJ'), 'two_b').bytes())
    C.send(m2 + m3)
    m4 = giop(2, 0, request_12(43, ('key', b'C-OBJ'), 'hdr_split').bytes())
    C.send(m4[:5], psh=False); C.send(m4[5:])
    C.send(m2 + m4[:30], psh=False); C.send(m4[30:])
    # ZIOP: compressed body, zlib and raw deflate, and the ZIOP "supported" flag
    zb = request_12(50, ('key', b'C-OBJ'), 'compressed', lambda c: c.string('abc' * 50)).bytes()
    tcp_msg(C, giop(2, 0, zlib.compress(zb, 9), flags=0x08), 'c')
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    tcp_msg(C, giop(2, 0, co.compress(zb) + co.flush(), flags=0x08 | 0x04), 'c')
    tcp_msg(C, giop(2, 0, request_12(51, ('key', b'C-OBJ'), 'ziop_supported').bytes(), flags=0x04), 'c')
    zr = reply_12(50, 0, lambda c: c.string('zreply' * 30)).bytes()
    tcp_msg(C, giop(2, 1, zlib.compress(zr, 9), flags=0x08), 's')
    # _is_a in GIOP 1.2 (type id after the header, no sub-dissector involved)
    tcp_msg(C, giop(2, 0, request_12(60, ('key', b'C-OBJ'), '_is_a', lambda c: c.string(NS_REPO)).bytes()), 'c')
    tcp_msg(C, giop(2, 1, reply_12(60, 0, lambda c: c.boolean(False)).bytes()), 's')
    # a ZIOP header (the separate ZIOP dissector) inside a stream that was identified as GIOP
    C.send(b'ZIOP' + bytes([1, 2, 0, 0]) + struct.pack('>I', 8) + struct.pack('>HHI', 1, 0, 1000)[:8])
    # CloseConnection / MessageError in 1.2
    tcp_msg(C, giop(2, 5, b''), 's')
    tcp_msg(C, giop(2, 6, b''), 's')
    C.fin()

    # ===== D: TCP, GIOP 1.2 little endian, fragments, IORs =====
    D = u.Conn(o, 40003, 2809)
    tcp_msg(D, giop(2, 0, request_12(1, ('key', KEYA), 'resolve', nargs, le=True).bytes(), le=True), 'c')
    tcp_msg(D, giop(2, 1, reply_12(1, 0, lambda c: mkior(c, key=b'D-OBJ'), le=True).bytes(), le=True), 's')
    full = request_12(2, ('key', b'D-OBJ'), 'fragle', lambda c: c.string('little ' * 12), le=True).bytes()
    hdr = len(request_12(2, ('key', b'D-OBJ'), 'fragle', None, le=True).bytes())
    cut = (hdr + 12 + 7) // 8 * 8 - 12
    tcp_msg(D, giop(2, 0, full[:cut], le=True, flags=2), 'c')
    tcp_msg(D, giop(2, 7, struct.pack('<I', 2) + full[cut:], le=True), 'c')
    c = CDR(12, True); c.ulong(3).ulong(1); c.align(8); tcp_msg(D, giop(2, 4, c.bytes(), le=True), 's')
    tcp_msg(D, giop(2, 1, reply_12(2, 2, lambda c: sys_exc(c), le=True).bytes(), le=True), 's')
    tcp_msg(D, giop(2, 1, reply_12(2, 5, lambda c: c.ushort(0), le=True).bytes(), le=True), 's')
    # IORs with LE encapsulation, a profile longer than needed, zero profiles, empty type id
    def le_ior(c):
        ior(c, 'IDL:le/Obj:1.0', [(0, iiop_profile('le.example.test', 9999, b'LEKEY', 2, comps=[(3, b'q')], le=True))])
    tcp_msg(D, giop(2, 1, reply_12(2, 3, le_ior, le=True).bytes(), le=True), 's')
    tcp_msg(D, giop(2, 1, reply_12(2, 3, lambda c: ior(c, '', []), le=True).bytes(), le=True), 's')
    D.fin()

    # ===== E: DIOP (UDP): typecodes / any through the Tango heuristic =====
    rid = 100
    for minor, le in ((2, False), (2, True), (1, False), (0, False)):
        for name, anyfn in typecode_cases(minor, le):
            if le is True and name not in ('simple_struct', 'nested_struct', 'seq_string', 'enum', 'wstring', 'union', 'alias_alias'):
                continue
            if minor < 2 and name not in ('simple_struct', 'wchar', 'wstring', 'enum', 'seq_string', 'any_typecode', 'string'):
                continue
            rid += 1
            req = tango_req(rid, anyfn, minor=minor, le=le, clnt=(5 if name == 'simple_struct' else None))
            o.append(u.udp(40100 + minor, 40200, giop(minor, 0, req.bytes(), le)))
    # Tango replies carrying an any, matched with requests on the same UDP endpoints
    for k, (name, anyfn) in enumerate(typecode_cases(2, False)[:12]):
        rid += 1
        req = tango_req(rid, lambda c: S(tk_null)(c))
        o.append(u.udp(40300, 40200, giop(2, 0, req.bytes())))
        o.append(u.udp(40200, 40300, giop(2, 1, tango_rep(rid, anyfn).bytes()), src='192.0.2.2', dst='192.0.2.1'))
    # Reply with an LE any, 1.0 and 1.1
    for minor in (0, 1):
        rid += 1
        req = tango_req(rid, lambda c: S(tk_null)(c), minor=minor, le=True)
        o.append(u.udp(40301, 40200, giop(minor, 0, req.bytes(), True)))
        anyfn = any_of(lambda c: tc_struct(c, [('n', S(tk_long)), ('t', lambda e: tc_string(e, 0))]),
                       lambda c: (c.long(1), c.string('le reply')))
        o.append(u.udp(40200, 40301, giop(minor, 1, tango_rep(rid, anyfn, minor, True).bytes(), True), src='192.0.2.2', dst='192.0.2.1'))
    # DIOP (UDP) basic: request/reply, CosNaming through the heuristic, locate, ZIOP
    o.append(u.udp(40400, 40401, giop(2, 0, request_12(1, ('key', b'UDPKEY'), 'resolve', nargs).bytes())))
    o.append(u.udp(40401, 40400, giop(2, 1, reply_12(1, 0, lambda c: mkior(c, key=b'UDP-OBJ')).bytes()), src='192.0.2.2', dst='192.0.2.1'))
    o.append(u.udp(40400, 40401, giop(2, 0, request_12(2, ('key', b'UDP-OBJ'), 'next_n', lambda c: c.ulong(3)).bytes())))
    o.append(u.udp(40400, 40401, giop(2, 3, CDR(12).ulong(3).ushort(0).seq(b'UDP-OBJ').bytes())))
    o.append(u.udp(40400, 40401, giop(2, 0, zlib.compress(request_12(4, ('key', b'UDP-OBJ'), 'udp_ziop', lambda c: c.string('u' * 100)).bytes()), flags=0x08)))
    # object keys that giop_ior.txt (giop.ior_txt preference) maps to a repository id: with the file
    # the explicit CosNaming / Tango dissectors take these requests although a trailing octet makes
    # the heuristic probe reject them
    o.append(u.udp(40600, 40601, giop(2, 0, request_12(1, ('key', FILEKEY), 'resolve', lambda c: (c.ulong(0), c.octet(0xaa))).bytes())))
    o.append(u.udp(40600, 40601, giop(2, 0, request_12(2, ('key', b'TANGOKEY'), 'command_inout_4',
             lambda c: (tango_args(any_of(S(tk_null)))(c), c.octet(0xaa))).bytes())))
    return o


def mal_frames():
    o = []
    D = lambda b, sp=40500: o.append(u.udp(sp, 40501, b))
    # unsupported versions, unknown magic-like, message size too big, ZIOP failures
    D(giop(0, 0, b'\0' * 16, major=2))
    D(giop(3, 0, b'\0' * 16))
    D(giop(2, 0, b'\0' * 20, size=0x7fffffff))
    D(b'GIOP' + bytes([1, 2, 0, 0]) + struct.pack('<I', 0x10000000) + b'\0' * 8)      # size looks little endian
    D(giop(2, 0, b'not a zlib stream at all', flags=0x08))
    D(giop(2, 0, zlib.compress(b'\0' * 100)[:12], flags=0x08))                          # truncated zlib stream
    D(giop(2, 0, b'', flags=0x08, size=4))                                              # ZIOP flag, no payload
    # decompression bomb: ~11 MiB of zeros in about 11 KB (over the 10 MiB limit)
    co = zlib.compressobj(9)
    z = b''.join(co.compress(b'\0' * (1 << 20)) for _ in range(11)) + co.flush()
    o.append(u.udp(40502, 40501, giop(2, 0, z, flags=0x08)))
    # Request with lengths larger than the packet
    D(giop(0, 0, CDR(12).ulong(0).ulong(1).octet(1).raw(b'\0\0\0').ulong(1000).raw(b'abc').bytes()))         # object key length
    D(giop(1, 0, request_10(1, b'k', 'op', minor=1, principal=b'').bytes()[:-4] + struct.pack('>I', 5000)))   # principal length
    D(giop(2, 0, CDR(12).ulong(1).octet(3).raw(b'\0\0\0').ushort(0).ulong(9999).raw(b'x').bytes()))          # KeyAddr length
    D(giop(0, 3, CDR(12).ulong(1).ulong(4000).raw(b'ab').bytes()))                                           # locate key length
    # IOR problems: profile data longer than packet, sequence/component lengths too big, bad minor
    c = CDR(12); c.ulong(0).ulong(1).ulong(0)
    c.string('IDL:x:1.0'); c.ulong(1); c.ulong(1); c.ulong(3000); c.raw(b'abc')
    D(giop(0, 1, c.bytes()))
    c = CDR(12); c.ulong(0).ulong(2).ulong(3)
    c.string('IDL:x:1.0'); c.ulong(1)
    c.ulong(0); c.seq(encap(lambda e: e.octet(1).octet(0).string('h').ushort(1).ulong(5000)))
    D(giop(0, 1, c.bytes()))
    c = CDR(12); c.ulong(0).ulong(3).ulong(3)
    c.string('IDL:x:1.0'); c.ulong(1)
    c.ulong(0); c.seq(encap(lambda e: e.octet(1).octet(7).string('h').ushort(1).seq(b'k')))
    D(giop(0, 1, c.bytes()))
    c = CDR(12); c.ulong(0).ulong(4).ulong(3)
    c.string('IDL:x:1.0'); c.ulong(1)
    c.ulong(0); c.seq(encap(lambda e: (e.octet(1).octet(2).string('h').ushort(1).seq(b'k'), e.ulong(1), e.ulong(9), e.ulong(8000))))
    D(giop(0, 1, c.bytes()))
    # locate reply: forward without an IOR; fragment whose first fragment was never seen
    D(giop(0, 4, CDR(12).ulong(6).ulong(2).bytes()))
    D(giop(2, 7, struct.pack('>I', 77) + b'orphan'))
    D(giop(1, 7, CDR(12).raw(b'\x06\0\0\0frag-tail').bytes()))
    # truncated messages
    full = request_12(1, ('key', b'abcdef'), 'truncate_me', lambda c: c.string('x' * 40)).bytes()
    D(giop(2, 0, full[:30]))
    D(giop(2, 0, full[:12]))
    D(giop(2, 1, CDR(12).ulong(1).bytes()))
    D(giop(0, 1, reply_10(9, 2, lambda c: c.string('IDL:short')).bytes()[:-6]))
    D(giop(2, 7, b'\0\0'))
    D(giop(2, 4, b'\0\0\0\1'))
    D(giop(2, 2, b'\0'))
    # TypeCode problems in Tango requests: unknown TCKind, union member, truncated struct members,
    # deep recursion, sequence bound smaller than the data
    def req(any_fn, rid, minor=2, sp=40510):
        o.append(u.udp(sp, 40511, giop(minor, 0, tango_req(rid, any_fn, minor=minor).bytes())))
    req(lambda c: c.ulong(99), 1)
    req(lambda c: c.ulong(0x7fffffff), 2)
    req(lambda c: (tc_struct(c, [('u', lambda e: tc_union(e, S(tk_long), [(lambda x: x.long(1), 'a', S(tk_short))])),
                                  ('l', S(tk_long))]), c.long(4)), 3)
    req(lambda c: (tc_sequence(c, S(tk_octet), 2), c.ulong(5), c.raw(b'abcde')), 4)
    req(lambda c: (tc_sequence(c, S(tk_long), 0), c.ulong(500000), c.long(1)), 5)
    req(lambda c: tc_struct(c, [('m', S(tk_long))] * 3), 6)
    req(lambda c: (tc_enum(c, ['a']), ), 7)
    def deep(n):
        def f(e):
            if n == 0:
                S(tk_long)(e)
            else:
                tc_alias(e, deep(n - 1))
        return f
    req(lambda c: (deep(130)(c), c.long(1)), 8)
    def deepseq(n):
        def f(e):
            if n == 0:
                S(tk_long)(e)
            else:
                tc_sequence(e, deepseq(n - 1), 0)
        return f
    req(lambda c: (deepseq(120)(c), c.raw(b'\0' * 64)), 9)
    # an any inside an any inside ... (data recursion)
    def anydeep(c, n):
        if n == 0:
            S(tk_long)(c); c.long(1)
        else:
            S(tk_any)(c); anydeep(c, n - 1)
    req(lambda c: anydeep(c, 130), 10)
    req(lambda c: (tc_struct(c, [('a', S(tk_any)), ('b', S(tk_long))]), S(tk_TypeCode)(c)), 11)
    req(lambda c: (tc_alias(c, S(tk_long)), ), 12)                       # data missing
    req(lambda c: (tc_array(c, S(tk_long), 0xffff), c.long(1)), 13)       # array longer than data
    req(lambda c: (S(tk_fixed)(c), c.ushort(5), c.short(2), ), 14)
    req(lambda c: (tc_value(c, [('a', S(tk_long), 0)]), c.long(1)), 15)
    # wstring length > 200 and longer than the data, sequences/arrays/unions that consume no data
    req(lambda c: (tc_wstring(c, 0), c.ulong(300), c.raw(b'\0A' * 5)), 16)
    req(lambda c: (tc_wstring(c, 0), c.ulong(100), c.raw(b'\0A' * 5)), 17)
    req(lambda c: (tc_sequence(c, S(tk_null), 0), c.ulong(3)), 18)
    req(lambda c: (tc_array(c, S(tk_void), 3), ), 19)
    req(lambda c: (tc_struct(c, [('u', lambda e: tc_array(e, S(tk_null), 2))]), ), 20)
    req(lambda c: (tc_union(c, S(tk_void), [(lambda e: None, 'a', S(tk_short)), (lambda e: None, 'b', S(tk_short))]), c.long(1)), 21)
    # Reply status that needs the request first (unmatched), user exception id too long
    o.append(u.udp(40520, 40521, giop(2, 1, reply_12(3, 1, lambda c: c.string('E' * 300)).bytes())))
    o.append(u.udp(40520, 40521, giop(2, 1, reply_12(3, 1, lambda c: c.ulong(100000)).bytes())))
    return o


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_frames()
    u.write_pcap(os.path.join(out, 'giop-coverage.pcap'), m)
    u.gz(os.path.join(out, 'giop-coverage.pcap'))
    mm = mal_frames()
    u.write_pcap(os.path.join(out, 'giop-coverage-malformed.pcap'), mm)
    write_ior_file(os.path.join(out, 'giop_ior.txt'))
    if '-v' in sys.argv:
        print(len(m), len(mm))
