#!/usr/bin/env python3
# Generates test/captures/ndps_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the NDPS coverage captures.  Usage: mkndps.py <outdir>
Writes ndps-coverage.pcap (main) and ndps-coverage-malformed.pcap.
Everything is synthetic; addresses are from 192.0.2.0/24 and IPX
networks 0x0000000a/0x0000000b."""
import struct
import sys
import os
from netlib import Conn, ipx_spx, write_pcap

def u32(x): return struct.pack('!I', x)
def u16(x): return struct.pack('!H', x)
def u64(x): return struct.pack('!Q', x)

# --- NDPS primitives -------------------------------------------------------
def strn(s, uni=False):
    """ndps_string: length, bytes.  Lengths are made multiples of 4 so that
    the dissector's alignment guess (offset % 4) adds nothing."""
    if s == '' or s is None:
        return u32(0)
    if uni:
        b = (s + '\0').encode('utf-16-le')
        if len(b) % 4:
            b += b'\0\0'
    else:
        b = s.encode() + b'\0'
        b += b'\0' * ((-len(b)) % 4)
        if len(b) % 2 == 0 and b[1] == 0:
            raise ValueError('ASCII string would look Unicode')
    return u32(len(b)) + b

# object identifier: length n, then type 6, length n-2, n-6 filler bytes and
# the 4 octet label value; one pad octet when n is odd
LABELS = {  # length -> label values of the table the dissector uses
    9: (0x00000001, 0x01000006), 10: (0x00000600, 0x00000601), 11: (0x00060001, 0x00060002),
    12: (0x06328105, 0x06328106), 13: (0x01040000, 0x01040001), 14: (0x04000000, 0x04000001),
    15: (0x00000000, 0x0003024C), 16: (0x01008102, 0x01008103), 17: (0x01050101, 0x01050102),
    18: (0x21018102, 0x21018120)}
def oid(n=15, label=0, idx=None, unknown=False):
    if n == 0:
        return u32(0)
    if idx is not None:
        label = LABELS[n][idx]
    if unknown:
        label = 0x7fff1234
    body = bytes([6, n - 2]) + b'\x2b\x06\x01\x04\x01\x81'[:n - 6] + b'\0' * max(0, n - 6 - 6) + u32(label)
    body = body[:n]
    assert len(body) == n, (n, len(body))
    return u32(n) + body + (b'\0' if n % 2 else b'')
OID_SECLEVEL = oid(15, 0x0003024C)
OID_OBJCLASS = oid(15, 0)      # lengths 11, 12, 15 and 16 keep everything 4 octet aligned
OID_STATE = oid(11, 0x00060001)
OID_X = oid(16, 0x01008102)

def nameorid(kind=1, o=None, name='local'):
    if kind == 1:
        return u32(1) + (o if o is not None else OID_OBJCLASS)
    if kind == 2:
        return u32(2) + strn(name)
    return u32(kind)
def qname(t=1, a='Printer1', b='tree1'):
    if t == 0:
        return u32(0)
    if t == 1:
        return u32(1) + strn(a)
    return u32(t) + strn(a) + strn(b)
def objident(t, long=False, **k):
    """objectidentification"""
    if t == 0: return u32(0) + strn('Printer') + u32(1)
    if t == 1: return u32(1) + strn('Printer') + u32(2)
    if t == 2: return u32(2) + OID_OBJCLASS
    if t == 3: return u32(3) + strn('ObjName') + (nameorid(2) if long else b'')   # the dissector only reads the name when the offset is within the remaining length
    if t == 4: return u32(4) + nameorid(1)
    if t == 5: return u32(5) + strn('Simple')
    if t == 6: return u32(6) + strn('PrnConfig')
    if t == 7: return u32(7) + qname(2)
    if t == 8: return u32(8) + strn('Event') + OID_OBJCLASS + u32(3)
    return u32(t)
def paddr(t=0):
    if t == 0:
        return u32(0) + u32(12) + b'\0\0\0\x0a\x02\0\0\0\0\x01\x04\x50'
    if t == 1:
        return u32(1) + u32(6) + u16(515) + b'\xc0\0\x02\x0a' + b'\0\0'
    return u32(t) + u32(4) + b'\xde\xad\xbe\xef'
def addritem(t):
    if t <= 7: return u32(t) + qname(2)
    if t <= 12: return u32(t) + strn('addr')
    if t == 13 or t == 14: return u32(t) + u32(1)
    if t == 15: return u32(t) + paddr(0)
    return u32(t) + strn('other')
def event_prof_event(a=1, b=0):
    tail = {0: u32(1) + OID_STATE, 1: OID_STATE, 2: u32(2) + OID_STATE + OID_X + u32(0)}[b]
    return u32(7) + OID_OBJCLASS + objident(2) + u32(1) + u32(b) + tail

def attr(t, **k):
    """attribute_value(): the type word and the value."""
    A = u32(t)
    S, N, O = strn, nameorid, oid
    n64 = u64(0x0102030405060708)
    if t == 0: return A + u32(0)
    if t in (1, 2, 3, 6, 40, 50, 58, 102, 103, 108): return A + S('text value')
    if t in (4, 5, 38): return A + N(k.get('nid', 1))
    if t == 39: return A + u32(3) + N(1) + N(2) + N(3)
    if t in (7, 79): return A + S('dn string') + N(2)
    if t == 8: return A + u32(2) + S('dn1') + N(1) + S('dn2') + N(2)
    if t in (9, 10, 11, 13, 15, 18, 19, 35, 57, 72, 95): return A + u32(k.get('v', 7))
    if t in (12, 14): return A + u32(4) + u32(42)
    if t in (16, 17): return A + u32(1) + u32(100)
    if t in (20, 22, 24, 31, 29): return A + n64
    if t in (21, 23, 30): return A + u32(2) + n64 + n64
    if t in (25, 26, 32, 33): return A + n64 + n64
    if t in (27, 28): return A + n64
    if t == 34: return A + u32(1)
    if t == 36: return A + OID_OBJCLASS
    if t == 37: return A + u32(2) + OID_OBJCLASS + OID_STATE
    if t == 41: return A + u32(2) + S('rdn1') + S('rdn2')
    if t == 42: return A + u32(1)
    if t == 43: return A + n64 + n64
    if t == 44: return A + (u32(0) + n64 if k.get('v', 0) == 0 else u32(1) + N(1)) + u32(1) + n64
    if t == 45: return A + (u32(1) + N(1) if k.get('v', 1) == 1 else u32(0) + n64 + n64) + u32(1) + n64
    if t == 46: return A + (u32(0) + u32(2) + n64 + n64 if k.get('v', 0) == 0 else u32(1) + N(2)) + u32(1) + n64
    if t == 47: return A + n64 * 4
    if t == 48: return A + u32(2) + n64 * 4 + n64 * 4
    if t == 49: return A + u32(2)
    if t == 51: return A + (u32(0) + u32(5) if k.get('v', 0) == 0 else u32(1) + OID_STATE)
    if t == 52: return A + OID_STATE + u32(9)
    if t == 53: return A + (u32(0) + u32(5) if k.get('v', 0) == 0 else u32(1) + N(1))
    if t == 54: return A + (u32(0) + OID_STATE if k.get('v', 0) == 0 else u32(1) + u32(5))
    if t == 55:
        return (A + u32(5) + u32(1) + qname(2) + u32(4) + u32(9) + u32(7) + N(1) + u32(3)
                + addritem(2) + addritem(9) + addritem(15)
                + u32(3) + event_prof_event(0, 0) + event_prof_event(0, 1) + event_prof_event(0, 2))
    if t in (56, 63, 66): return A + u32(6) + b'abcd'  # the dissector skips length+2 from the length word
    if t == 59:
        v = k.get('v', 0)
        if v <= 3: return A + u32(v) + S('deliv')
        if v == 4: return A + u32(4) + S('dnstring') + N(2)
        if v in (5, 6): return A + u32(v) + OID_STATE + qname(2)
        return A + u32(v)
    if t == 60: return A + objident(k.get('v', 0), long=k.get('long', False))
    if t == 61: return A + OID_STATE + N(1) + addritem(1) + u32(5) + N(2)
    if t == 62: return A + OID_STATE + u32(1) + u32(5)
    if t == 64: return A + OID_STATE + u32(9)
    if t == 65: return A + OID_STATE + u32(2) + u32(4) + u32(1) + u32(4) + u32(2)
    if t == 67: return A + u32(1) + OID_STATE + u32(2) + u32(38) + N(1) + u32(36) + OID_STATE
    if t in (68, 71):
        if t == 68: return A + (u32(0) + N(1) if k.get('v', 0) == 0 else u32(1) + S('res'))
        return A + u32(2) + u32(0) + N(1) + u32(1) + S('res')
    if t == 69: return A + N(1) + N(2)
    if t == 70: return A + S('font1') + S('font2')
    if t == 73:
        i1 = u32(1) + u32(0) + u32(3) + u32(1) + u32(1) + S('pg')
        i2 = u32(0) + u32(2) + N(1) + u32(0) + u32(2) + N(2)
        return A + u32(2) + i1 + i2
    if t == 74:
        v = k.get('v', 0)
        if v == 0: return A + u32(0) + N(1)
        return A + u32(1) + S('mediasel') + u32(2) + (u32(1) + u32(0) + u32(3)) + (u32(1) + u32(1) + S('xy'))
    if t == 75:
        if k.get('v', 0) == 0: return A + u32(0) + u32(4) + b'\1\2\3\4'
        return A + u32(1) + S('docref') + N(2)
    if t == 76: return A + (u32(0) + OID_STATE if k.get('v', 0) == 0 else u32(1) + n64 + n64)
    if t in (77, 78): return A + u32(3)
    if t == 80:
        if k.get('v', 0) == 0:
            return A + N(1) + u32(0) + u32(0) + OID_STATE + u32(1) + n64 * 4
        if k.get('v') == 2:
            return A + N(1) + u32(0) + u32(1) + n64 * 2 + u32(1) + n64 * 4
        return A + N(1) + u32(1) + n64 * 6 + u32(1) + n64 * 4
    if t == 81: return A + N(1) + N(2)
    if t == 82: return A + u32(2) + u32(1) + u32(2) + u32(2) + u32(1)
    if t == 83: return A + u32(2)
    if t == 84: return A + OID_STATE + u32(1) + u32(9)
    if t == 85: return A + OID_STATE + u32(2) + u32(4) + u32(1) + u32(4) + u32(2) + u32(1) + u32(4) + u32(7)
    if t == 86:
        v = k.get('v', 0)
        return A + u32(v) + ({0: u32(2), 1: N(1), 2: u32(1) + u32(4)}.get(v, b''))
    if t in (87, 88): return A + S('pco') + u32(3)
    if t == 89: return A + S('pcfg') + qname(2)
    if t == 90: return A + S('typed') + u32(1) + u32(30)
    if t == 91: return A + u32(1) + u32(4) + b'\xc0\0\x02\x01'
    if t in (92,):
        v = k.get('v', 1)
        if v == 1: return A + u32(1) + N(1)
        if v == 0: return A + u32(0) + n64 + n64
        return A + u32(v) + u32(5) + u32(6)
    if t == 93: return A + N(1) + u32(5) + u32(6)
    if t == 94: return A + u32(0) + N(1) + u32(1) + u32(1) + OID_STATE + objident(2) + u32(3) + u32(2) + u32(0) + N(2)
    if t == 96: return A + qname(2)
    if t == 97: return A + u32(2) + qname(1) + qname(2)
    if t == 98:
        if k.get('v', 0) == 0: return A + u32(0) + N(1)
        return A + u32(1) + OID_STATE + u32(2) + N(1) + N(2)
    if t == 99: return A + u32(2) + S('Type1') + S('Manuf1') + S('inf1') + S('Type2') + S('Manuf2') + S('inf2') + u32(3)
    if t == 100: return A + S('pa1') + OID_STATE + u32(4)
    if t == 101: return A + qname(2) + qname(1)
    if t == 104: return A + u32(k.get('v', 0)) + u32(11)
    if t == 105: return A + u32(2) + S('po1') + u32(1) + S('po2') + u32(2)
    if t == 106: return A + u32(4) + b'abcd' + u32(4) + b'wxyz'
    if t == 107: return A + u32(4) + b'abcd' + u32(1) + u32(2)
    if t == 109:
        v = k.get('v', 0)
        h = u32(5) + u32(1) + qname(2) + u32(4) + b'\0\0\0\0' + u32(9) + N(1)
        if v <= 2: d = u32(v) + S('dtext')
        elif v == 3: d = u32(3) + u32(4) + b'wxyz'
        elif v == 4: d = u32(4) + S('dnstr') + N(2)
        else: d = u32(v) + OID_STATE + qname(2)
        tail = (u32(2) + S('ev1') + OID_STATE + u32(1) + S('ev2') + OID_STATE + u32(2)
                + OID_STATE + qname(1) + u32(2) + OID_STATE + OID_X + u32(1) + u32(2) + u32(3) + S('pa'))
        return A + h + d + tail
    return A  # unknown type: nothing follows

ATTR_TYPES = list(range(0, 110)) + [110, 200]


# --- request bodies ---------------------------------------------------------------
SID = u32(0x1234)
JOB = strn('Printer1') + u32(7)
N1, N2 = nameorid(1), nameorid(2)
def CA(*attrs): return u32(len(attrs)) + b''.join(attrs)
def attrs(*a): return u32(len(a)) + b''.join(a)
def cred(t):
    t = [0, 1, 2, 3, 33, 34, 4, 9][t] if t < 8 else t
    if t == 0: return u32(0) + strn('user1') + u32(2) + u32(4) + b'pwd1' + u32(4) + b'pwd2'
    if t == 1: return u32(1) + u32(8) + b'certcert'
    if t == 2: return u32(2) + strn('server1') + b'\0\0' + u16(5)
    if t == 3: return u32(3) + strn('server2') + u16(5) + strn('user2') + b'\0\0'
    if t == 33: return u32(3) + strn('') + b'\0\0' + b'\0\0' + b'\0\0' + u16(6) + strn('user3')   # NDPS 1.0/1.1 forms
    if t == 34: return u32(3) + strn('server3') + b'\0\0' + u16(7) + strn('user4')
    if t == 4: return u32(4) + strn('server4') + b'\0\0' + u16(8) + strn('user4') + b'\0' * 8 + u32(3) + strn('pa4') + strn('tree4')
    return u32(t)
def bindsec(n=2): return u32(n) + u32(4) * n
def eos_fix(ev=2):
    out = u32(ev)
    for i in range(ev):
        k = 1 + (i % 2)
        out += u32(7) + OID_OBJCLASS + objident(2) + u32(1) + u32(k) + ({1: OID_STATE, 2: u32(2) + OID_STATE + OID_X}[k])
    return out
def ctx(): return u32(4) + b'ctxt' + u32(1)
def listprof(variant):
    if variant == 0: return u32(0) + qname(2) + u32(0) + u32(2) + u32(4) + u32(1) + u32(4) + u32(2) + u32(1) + u32(1) + u32(9)
    if variant == 1: return u32(0) + qname(1) + u32(1) + qname(2) + N2 + u32(3) + u32(2) + u32(0)
    return u32(1) + ctx()
def transfer_method(n=2):
    return u32(n) + b''.join(OID_X + attrs(attr(1), attr(11)) + u32(1) for _ in range(n))

def print_req(func, v=0):
    P = {}
    if func == 1: return cred(v)
    if func == 2: return cred(v) + u32(1) + bindsec(2) + qname(2)
    if func == 3: return SID
    if func == 4:
        if v == 0:
            return (SID + u32(0) + strn('PrintAgent') + u32(1) + transfer_method(2)
                    + u32(2) + OID_X + OID_STATE + u32(2) + u32(0)
                    + u32(2) + u32(2) + u32(0) + u32(4) + b'\xde\xad\xbe\xef'
                    + u32(0) + u32(2) + u32(1) + strn('docref1') + nameorid(2) + b''
                    + u32(0) + u32(1) + OID_STATE + attrs(attr(1)) + u32(1) + attrs(attr(1), attr(34)))
        if v == 1:
            return (SID + u32(1) + strn('PrintAgent') + u32(5) + u32(1) + u32(1) + OID_X
                    + u32(0) + u32(2) + OID_X + OID_STATE + u32(1) + attrs(attr(1), attr(11)))
        return SID + u32(2) + strn('PrintAgent') + u32(5)
    if func == 5: return SID + strn('PrintAgent') + u32(7) + u32(1) + attrs(attr(11), attr(1)) + attrs(attr(34))
    if func == 6: return SID + strn('PrintAgent') + u32(7) + u32(1) + u32(1) + N2 + u32(0) + u32(5)
    if func == 7:
        if v == 0: return SID + u32(0) + u32(4) + b'ctxt' + u32(1) + attrs(attr(1), attr(11))
        # specification: object class, 4 unknown octets, scope [, options, filter, limits], 4 unknown octets, attributes
        if v == 1: return SID + u32(1) + OID_STATE + u32(0) + u32(0) + u32(0) + u32(2) + OID_STATE + OID_X + u32(0) + CA(attr(1))
        if v == 3: return SID + u32(1) + OID_STATE + u32(0) + u32(0) + u32(0) + u32(0)
        return (SID + u32(1) + OID_STATE + u32(0) + u32(1) + u32(2) + objident(5) + objident(6) + u32(1) + u32(30) + u32(100)
                + u32(0) + u32(2) + OID_STATE + OID_X + u32(0) + CA(attr(11)))
    if func == 8: return SID + JOB + N1 + CA(attr(1))
    if func == 9:
        if v == 0: return SID + u32(0) + JOB + N1 + JOB + CA(attr(1))
        return SID + u32(1) + strn('PrintAgent') + N2 + JOB + CA(attr(11))
    if func == 10:
        if v == 0: return SID + u32(0) + JOB + N1 + CA(attr(1))
        return SID + u32(1) + strn('PrintAgent') + N2 + CA(attr(11))
    if func == 11: return SID + JOB + N1 + CA(attr(1))
    if func == 12: return SID + N1 + CA(attr(1))
    if func == 13: return SID + OID_X + objident(0) + u32(1) + objident(1) + attrs(attr(1), attr(11)) + CA(attr(1))
    if func == 14: return SID + OID_X + objident(2) + CA(attr(1))
    if func in (15, 16): return SID + N1 + CA(attr(1))
    if func == 17:
        return (SID + qname(2) + addritem(2) + u32(1) + u32(2)
                + b''.join(JOB + u32(1) + attrs(attr(1)) + attrs(attr(11)) for _ in range(2))
                + N1 + CA(attr(1)))
    if func == 18: return SID + OID_X + objident(4) + attrs(attr(1), attr(11)) + CA(attr(1))
    if func in (19, 30): return SID + u32(1) + strn('PrintAgent') + N1 + CA(attr(1))
    if func == 20: return SID + strn('PrintAgent') + N1 + CA(attr(1))
    if func == 21: return SID + JOB + JOB + CA(attr(1))
    if func in (22, 23): return SID + N1 + CA(attr(1))
    if func == 24: return SID + u32(1) + u32(8) + b'datadata'
    if func == 25: return SID + OID_X + CA(attr(1))
    if func == 26:
        return (SID + u32(5) + u32(1) + qname(2) + strn('supplier1') + u32(4) + N1
                + u32(3) + addritem(2) + addritem(9) + addritem(15) + eos_fix(2) + qname(1))
    if func == 27: return SID + u32(5)
    if func == 28:
        if v == 0: return (SID + u32(5) + u32(1) + u32(4) + b'sup1' + u32(1) + u32(3) + u32(1) + N2 + u32(1) + paddr(0) + eos_fix(1))
        return SID + u32(5) + u32(0) + u32(0) + u32(0) + u32(0) + eos_fix(2)
    if func == 29: return SID + listprof(v)
    if func == 31: return SID + N1 + CA(attr(1))
    if func == 32: return SID + u32(1) + strn('dsinfo1') + qname(2)
    if func == 33: return SID + N1 + CA(attr(1))
    if func == 34: return u32(8) + b'guid1234' if v == 0 else u32(0)
    if func == 35:
        return (SID + u32(5) + u32(1) + qname(2) + strn('supplier1') + u32(4) + N1
                + u32(2) + addritem(2) + addritem(9) + eos_fix(2) + qname(1)
                + u32(2) + OID_STATE + OID_X + u32(60) + u32(1) + u32(86400) + strn('lease1'))
    if func == 36: return SID + listprof(v)
    return b'\0' * 64

NV = {  # (program, function) -> number of variants
}
def variants_print(func):
    return {1: 8, 2: 8, 4: 3, 7: 4, 9: 2, 10: 2, 28: 2, 29: 3, 34: 2, 36: 3}.get(func, 1)

def resfile_input(v):
    if v == 0: return u32(0) + u32(1) + strn('prndir') + strn('prnfile')
    if v == 1: return u32(1) + strn('vendor') + strn('prnfile')
    if v == 2: return u32(2) + strn('banner')
    if v == 3: return u32(3) + u32(1) + u32(2) + strn('fontfile')
    if v == 4: return u32(4) + u32(1) + strn('archdir') + u32(2)
    if v == 5: return u32(5) + u32(1) + strn('archdir') + u32(2)
    return u32(9)

def list_resources(v):
    base = u32(100) + u32(1) + u32(v)
    pid = u32(4) + b'pid1'
    t = {0: u32(1), 1: b'', 2: strn('shortdef'), 3: u32(2), 4: u32(3) + u32(1),
         5: u32(1) + strn('a1') + strn('b1') + strn('c1') + pid, 12: u32(1) + strn('a1') + strn('b1') + strn('c1') + pid,
         9: u32(1) + strn('a1') + strn('b1') + strn('c1') + pid,
         6: strn('a1') + u32(0) + strn('b1') + strn('c1') + strn('d1') + pid, 10: strn('a1') + u32(0) + strn('b1') + strn('c1') + strn('d1') + pid,
         7: u32(1) + u32(2) + strn('font1'), 8: strn('a1') + strn('b1') + strn('c1'),
         11: strn('a1') + strn('b1') + strn('c1'), 13: strn('a1') + strn('b1') + strn('c1'), 14: b''}.get(v, b'')
    return base + t

def get_resfile(v):
    base = u32(1) + u32(v)
    if v == 0: return base + u32(1) + strn('prndir') + strn('prnfile')
    if v == 1: return base + strn('vendor') + strn('prnfile')
    if v == 2: return base + strn('banner')
    if v == 3: return base + u32(1) + u32(2) + strn('fontfile')
    return base + u32(1) + strn('archdir') + u32(2)

def other_req(prog, func, v=0):
    if func == 1 and prog in (0x060977, 0x060978, 0x060979, 0x06097a):
        return cred(v) + u32(1) + bindsec(2)
    if prog == 0x06097b and func == 1: return cred(v)
    if func == 2: return b''
    if prog == 0x060977:
        if func == 3: return u32(1)
        if func == 4: return u32(2) + u32(2) + u32(4) + b'parm' + u32(4) + b'par2'
        if func == 5: return u32(1)
        return b''
    if prog == 0x060978:
        if func == 3: return server_entry()
        if func == 5: return strn('registry1') + paddr(0)
        if func == 7: return u32(2) + server_entry() + server_entry(1) + u32(1) + server_entry()
        if func in (8, 9, 10):
            return {0: u32(0) + u32(1) + u32(7), 1: u32(0) + u32(0), 2: u32(1) + ctx()}[v]
        return b''
    if prog == 0x060979:
        if func == 3: return strn('supplier1') + u32(2) + qname(2) + qname(1)
        if func == 4: return SID
        if func == 5:
            return (SID + qname(2) + u32(5) + u32(1) + qname(2) + u32(4) + u32(7) + u32(4) + N1 + u32(3)
                    + addritem(2) + addritem(9) + addritem(15) + eos_fix(2))
        if func == 6: return SID + u32(5)
        if func == 7:
            if v == 0: return SID + u32(5) + u32(1) + u32(4) + b'sup1' + u32(1) + u32(3) + u32(1) + N2 + u32(1) + paddr(1) + eos_fix(1)
            return SID + u32(5) + u32(0) + u32(0) + u32(0) + u32(0) + eos_fix(1)
        if func == 8: return SID + listprof(v)
        if func == 9:
            n = 1 + v
            it = u32(7) + OID_OBJCLASS + objident(2) + OID_STATE + OID_OBJCLASS + objident(4) + OID_X + u32(n) \
                + b''.join(attr(1 + i * 10) for i in range(n)) + strn('desc1') + u32(1700000000)
            return SID + u32(n) + it * n
        if func == 11:
            dest = N1 + u32(6) + paddr(0)
            attrlist = u32(2) + attr(1) + attr(11)
            return (u32(2) + dest + dest + strn('src1') + u32(7) + OID_OBJCLASS + objident(2) + OID_STATE
                    + OID_OBJCLASS + objident(4) + OID_X + attrlist + strn('desc2') + u32(1700000000) + qname(2))
        if func == 12: return strn('method1')
        if func == 13: return N1
        if func == 14: return {0: u32(0) + u32(1) + u32(9) + u32(3), 1: u32(1) + ctx(), 2: u32(0) + u32(0) + u32(3)}[v]
        if func == 15: return N1 + u32(3)
        return b''
    if prog == 0x06097a:
        if func == 3:
            return u32(1) + u32(1) + u32(1700000000) + resfile_input(v) + u32(2) + u32(4) + b'abcd' + u32(8) + b'efghijkl'
        if func == 4: return resfile_input(v)
        if func == 5: return list_resources(v)
        if func == 6: return get_resfile(v)
        if func == 7: return u32(1) + resfile_input(v)
        if func == 10: return u32(3)
        return b''
    if prog == 0x06097b:
        sup = SID + u32(4) + b'sup1' + u32(3) + OID_OBJCLASS + objident(2) + OID_STATE + OID_OBJCLASS + objident(4) + OID_X
        if func == 3: return u32(2) + (sup + attr(1) + strn('dsc') + u32(1700000000) + qname(2)) * 2
        if func == 4:
            return u32(1) + sup + u32(2) + attr(11) + attr(1) + strn('dsc') + u32(1700000000) + qname(1)
    return b'\0' * 64

def server_entry(kind=0):
    infos = [u32(2) + u32(0x01020304), u32(3) + u32(1), u32(4) + strn('infostring'), u32(5) + strn('infobytes')]
    if kind == 1:
        infos = [u32(0) + b'\x01', u32(1) + b'\x00\x02', u32(0) + b'\x03']
    return strn('server-a') + u32(1) + paddr(1) + u32(len(infos)) + b''.join(infos)

def variants_other(prog, func):
    if prog in (0x060977, 0x060978, 0x060979, 0x06097a, 0x06097b) and func == 1: return 8
    if prog == 0x060978 and func in (8, 9, 10): return 3
    if prog == 0x060979 and func in (7, 8, 14): return 3
    if prog == 0x060979 and func == 9: return 2
    if prog == 0x06097a and func == 3: return 6
    if prog == 0x06097a and func in (4, 7): return 7
    if prog == 0x06097a and func == 5: return 15
    if prog == 0x06097a and func == 6: return 5
    return 1


# --- reply bodies ---------------------------------------------------------------
def ndps_error_struct(kind, ext=False):
    """ndps_error(): problem type then the structure of that kind"""
    pt = u32(0 if not ext else 1)
    stdext = (u32(0) + u32(3)) if not ext else (u32(1) + OID_X)
    if kind == 0:
        return u32(0) + (u32(0) + u32(2) if not ext else u32(1) + OID_X) + N1
    if kind == 1:
        return u32(1) + stdext + objident(2) + attr(1) + u32(1) + u32(2) + u32(3) + strn('otherstr')
    if kind in (2, 3, 7):
        return u32(kind) + stdext + objident(2)
    if kind == 4:
        return u32(4) + stdext + objident(2) + attr(11)
    if kind == 5:
        return u32(5) + u32(1 if ext else 0) + OID_X + objident(2)   # the dissector reads no problem type here
    if kind == 6:
        return u32(6) + u32(2) + (u32(0) + u32(3) + attr(1)) + (u32(1) + OID_X + attr(11))
    return u32(kind)
def RC(code=0): return u32(code) + (u32(9) if code else b'')
def addr_items(): return u32(3) + addritem(2) + addritem(9) + addritem(15)
def ld(data=b'abcd'): return u32(len(data)) + data       # length word and data
def printdef(v=0):
    item = lambda s: u32(1) + strn(s)
    return item('Manuf') + item('PType') + item('file.inf')

def print_rep(func, v=0):
    """body after error_val; v selects error or alternative layouts"""
    err = (v == 99)
    E = ndps_error_struct(v - 100, False) if v >= 100 and v < 108 else (ndps_error_struct(v - 200, True) if v >= 200 else b'')
    if func == 1: return SID + (E + SID if E else b'') + qname(2)
    if func == 2: return SID + (E + SID + strn('PrintAgent') if E else b'')
    if func == 3: return b''
    if func == 4: return strn('PrintAgent') + u32(7) + E
    if func in (5, 6, 8, 11, 13): return attrs(attr(1), attr(11)) + E
    if func == 7:
        r1 = objident(2) + u32(1) + OID_X + u32(1) + attr(11) + u32(0) + OID_OBJCLASS
        r2 = b'\0\0' + objident(2) + u32(1) + OID_STATE + b'\0\0' + u32(1) + attr(11) + u32(0) + OID_X
        n = 2 if v == 1 else 1
        return (u32(100) + u32(2) + u32(4) + u32(8) + u32(0) + u32(8) + u32(1)
                + u32(n) + r1 + (r2 if n == 2 else b'') + E)
    if func in (9, 10): return strn('PrintAgent') + u32(7) + attrs(attr(1), attr(34)) + E
    if func in (12, 14, 15, 16, 18, 19, 20, 24, 25, 27, 28, 30, 31, 32, 33): return E
    if func == 17:
        job = lambda: strn('PrintAgent') + u32(7)
        return u32(2) + (job() + job() + attrs(attr(1)) ) * 2 + E
    if func == 21: return attrs(attr(1), attr(11)) + E
    if func in (22, 23): return u32(2) + attr(1) + attr(11) + E
    if func == 26: return u32(5) + E
    if func == 29:
        return (ld() + u32(5) + u32(1) + qname(2) + ld() + u32(4) + N1 + addr_items() + eos_fix(2) + ld() + E)
    if func == 34: return qname(2) + E
    if func == 35: return u32(5) + u32(3600) + E
    if func == 36:
        ev = (u32(5) + u32(1) + qname(2) + strn('supplier1') + u32(4) + N1 + addr_items() + eos_fix(2) + qname(1)
              + u32(2) + OID_STATE + OID_X + u32(60) + u32(1) + u32(86400) + strn('uri1') + ld())
        # the error is read inside the loop over the events
        return (u32(1) + ev + E) if E else (u32(2) + ev + ev)
    return E

def other_rep(prog, func, v=0, rc=0):
    if prog == 0x060977:
        if func in (1, 2, 4, 5, 6): return RC(rc)
        if func == 3: return u32(2) + u32(1) + u32(1) + u32(2) + u32(0) + RC(rc)
        if func == 7: return u32(1) + strn('broker1') + strn('tree1') + RC(rc)
        return b''
    if prog == 0x060978:
        if func == 1: return u32(2) + ld(b'\0\0\0\0')
        if func in (3, 4, 5, 6, 7): return RC(rc)
        if func in (8, 9): return u32(2) + server_entry() + server_entry(1) + ld() + RC(rc)
        if func == 10: return u32(2) + (u32(1) + strn('registry1') + paddr(1)) * 2 + ld() + RC(rc)
        if func == 11: return qname(2) + RC(rc)
        if func == 12: return u32(1) + u32(1700000000) + RC(rc)
        return b''
    if prog == 0x060979:
        if func == 1: return u32(2) + ld(b'\0\0\0\0')
        if func == 3: return SID + eos_fix(2) + RC(rc)
        if func in (4, 11, 13): return RC(rc)
        if func == 5: return u32(5) + eos_fix(2) + RC(rc)
        if func in (6, 7, 9): return eos_fix(1) + RC(rc)
        if func == 8:
            return (u32(4) + u32(5) + u32(1) + qname(2) + ld() + u32(4) + N1 + addr_items() + eos_fix(2) + ld() + RC(rc))
        if func == 10: return ld() + RC(rc)
        if func == 12: return N1 + RC(rc)
        if func == 14:
            return u32(2) + (N1 + strn('method1') + strn('1.0') + strn('file1') + u32(1)) * 2 + RC(rc)
        if func == 15: return N1 + strn('method1') + strn('1.0') + strn('file1') + u32(1) + addr_items() + RC(rc)
        if func == 16: return u32(1) + strn('notify1') + strn('tree1') + RC(rc)
        if func == 17: return u32(1) + u32(1700000000) + RC(rc)
        return b''
    if prog == 0x06097a:
        if func == 1: return ld(b'\0\0\0\0')
        if func in (3, 4): return RC(rc)
        if func == 5:
            if v == 99: return u32(5)
            return u32(0) + u32(1) + u32(v) + RES_LIST_REP(v)
        if func == 6: return u32(0) + u32(1) + u32(1700000000) + b'file data bytes'
        if func == 7: return u32(0) + u32(1700000000)
        if func == 8: return qname(2) + u32(0)
        if func == 9: return u32(1) + u32(1700000000) + RC(rc)
        if func == 10: return u32(0) + u32(3)
        return b''
    if prog == 0x06097b:
        if func == 1: return u32(0)
        if func in (3, 4):
            if v == 99: return u32(5)
            return u32(0) + u32(2) + u32(8) + u32(0) + u32(4)
        return b''
    return b''

def RES_LIST_REP(v):
    s = strn
    one = lambda x: u32(1) + s(x)
    if v in (0, 1, 2):
        defs = (one('Manuf') + one('PType') + one('file.inf')) * 2
        if v == 2:   # the old format: an item word of 0 is followed by 2 octets that are skipped
            defs = one('Manuf') + one('PType') + b'\0\0' + u32(1) + s('file.inf') + b'\0\0'
        return u32(2 if v < 2 else 1) + defs
    if v in (3, 4, 7): return u32(2) + s('name1') + s('name2')
    if v in (5, 12, 9): return u32(2) + (s('file1') + s('dir1') + s('inf1')) * 2
    if v == 6:
        return (u32(1) + s('prnfile') + s('prndir') + s('inf1')
                + u32(2) + (s('deffile') + u32(2) + s('key31a') + s('key31b') + u32(1) + s('key95a')) * 2)
    if v == 10: return s('deffile2') + u32(2) + (u32(1) + u32(2) + s('keya') + s('keyb')) * 2
    if v in (8, 11, 13): return u32(2) + (s('manuf1') + s('type1') + s('file1') + s('dir1') + u32(1) + u32(4096)) * 2
    if v == 14: return u32(3) + u32(1) + u32(2) + u32(3)
    return b''
RES_VARIANTS = 15

# --- PDUs ---------------------------------------------------------------------
PROGS = {0x060976: 'print', 0x060977: 'broker', 0x060978: 'registry', 0x060979: 'notify',
         0x06097a: 'resman', 0x06097b: 'delivery'}
FUNCS = {0x060976: 36, 0x060977: 8, 0x060978: 12, 0x060979: 17, 0x06097a: 10, 0x06097b: 4}

def pdu_req(xid, prog, func, body, ver=1):
    b = struct.pack('!IIIIII', xid, 0, 2, prog, ver, func) + b'\0' * 16 + body
    return u16(0x8000) + u16(len(b)) + b
def pdu_rep(xid, body, accept=0):
    b = struct.pack('!III', xid, 1, accept) + (b'\0' * 8 if accept == 0 else u32(0) + u32(1)) + body
    return u16(0x8000) + u16(len(b)) + b

class Tcp:
    def __init__(self, frames, cport, sport=3014, c='192.0.2.10', s='192.0.2.20'):
        self.conn = Conn(frames, c, s, cport, sport)
    def send(self, pdu, to_server=True, **k):
        (self.conn.c2s if to_server else self.conn.s2c)(pdu)

CNET, SNET = b'\0\0\0\x0a', b'\0\0\0\x0b'
CNODE, SNODE = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'
class Spx:
    """One SPX connection over IPX; sockets: client high, server one of the NDPS sockets."""
    def __init__(self, frames, csock=0x4000, ssock=0x90b2, cid=0x1111, sid=0x2222):
        self.f = frames
        self.cli = (CNET, CNODE, csock)
        self.srv = (SNET, SNODE, ssock)
        self.cid, self.sid = cid, sid
        self.cseq = self.sseq = 0
    def send(self, pdu, to_server=True, eom=True):
        if to_server:
            self.f.append(ipx_spx(self.cli, self.srv, 0x10 if eom else 0, self.cid, self.sid, self.cseq, 0, pdu))
            self.cseq += 1
        else:
            self.f.append(ipx_spx(self.srv, self.cli, 0x10 if eom else 0, self.sid, self.cid, self.sseq, 0, pdu))
            self.sseq += 1

def build_main():
    f = []
    xid = 0x1000
    t = Tcp(f, 41000)
    def rpc(prog, func, req, rep, accept=0, tail=True):
        nonlocal xid
        xid += 1
        t.send(pdu_req(xid, prog, func, req + b'\0' * 8))
        if rep is not None:
            t.send(pdu_rep(xid, rep + (b'\0' * 8 if tail else b''), accept), to_server=False)
        return xid
    def repbody(prog, func, err, body):
        pre = (u32(0) + u32(0)) if func in (1, 2) else b''
        return pre + u32(err) + body
    for prog, nf in FUNCS.items():
        for func in range(0, nf + 1):
            nv = variants_print(func) if prog == 0x060976 else variants_other(prog, func)
            for v in range(nv):
                body = print_req(func, v) if prog == 0x060976 else other_req(prog, func, v)
                if prog == 0x060976:
                    rb = print_rep(func, 1 if (func == 7 and v == 1) else 0)
                else:
                    rb = other_rep(prog, func, v if (func == 5 and prog == 0x06097a) else 0)
                rpc(prog, func, body, repbody(prog, func, 0, rb))
    # --- every attribute value type, in Create requests
    nvar = {4: 2, 5: 2, 38: 2, 44: 2, 45: 2, 46: 2, 51: 2, 53: 2, 54: 2, 59: 8, 60: 9, 68: 2, 74: 2, 75: 2,
            76: 2, 80: 3, 86: 4, 92: 3, 98: 2, 104: 3, 109: 7}
    vals = []
    for ty in ATTR_TYPES:
        for v in range(nvar.get(ty, 1)):
            kw = {'v': v}
            if ty in (4, 5, 38): kw = {'nid': v + 1}
            vals.append(attr(ty, **kw))
    for i in range(0, len(vals), 8):
        chunk = vals[i:i + 8]
        if chunk[-1] == u32(0):          # a Null value must not be last: it reads the next word
            chunk.append(attr(11))
        rpc(0x060976, 13, SID + OID_X + objident(0) + u32(1) + objident(1) + attrs(*chunk) + CA(attr(1)),
            repbody(0x060976, 13, 0, print_rep(13)))
    # an Object Name whose name or ID is read: the offset is less than the remaining length
    rpc(0x060976, 13, SID + OID_X + objident(0) + u32(1) + objident(1) + attrs(attr(60, v=3, long=True)) + CA(attr(1)) + b'\0' * 700,
        repbody(0x060976, 13, 0, print_rep(13)))
    # a security level attribute: the value is shown as a security level
    sec_body = (SID + u32(0) + strn('PrintAgent') + u32(1) + u32(1) + OID_SECLEVEL + u32(1) + attr(11, v=2) + u32(1)
            + u32(0) + u32(0) + u32(0) + u32(0) + u32(0) + u32(0) + u32(0))
    rpc(0x060976, 4, sec_body, repbody(0x060976, 4, 0, print_rep(4)))

    # --- object identifiers of every length, known and unknown labels (type 36)
    oids = []
    for n in range(8, 21):
        for idx in (0, 1):
            if n in LABELS:
                oids.append(u32(36) + oid(n, idx=idx))
        oids.append(u32(36) + oid(n, unknown=True))
    for i in range(0, len(oids), 8):
        rpc(0x060976, 13, SID + OID_X + objident(0) + u32(1) + objident(1) + attrs(*oids[i:i + 8]) + CA(attr(1)),
            repbody(0x060976, 13, 0, print_rep(13)))

    # --- more than 100 items: the loops stop with a "Truncated" expert info
    N = 101
    def big(unit): return u32(N) + unit * N
    rpc(0x060976, 1, u32(0) + strn('user1') + big(u32(0)), repbody(0x060976, 1, 0, print_rep(1)))
    rpc(0x060976, 2, cred(2) + u32(1) + big(u32(0)) + qname(2), repbody(0x060976, 2, 0, print_rep(2)))
    rpc(0x060976, 5, SID + strn('PrintAgent') + u32(7) + u32(1) + big(u32(0)) + attrs(attr(34)),
        repbody(0x060976, 5, 0, print_rep(5)))
    rpc(0x060976, 8, SID + JOB + N1 + big(attr(0)), repbody(0x060976, 8, 0, print_rep(8)))
    for ty, unit in ((39, u32(0)), (8, None), (37, u32(0)), (41, strn('')), (97, u32(0))):
        if unit is None:
            body = u32(8) + u32(N) + (strn('dn') + u32(0)) * N
        else:
            body = u32(ty) + big(unit)
        rpc(0x060976, 13, SID + OID_X + objident(0) + u32(1) + objident(1) + u32(1) + body + CA(attr(1)),
            repbody(0x060976, 13, 0, print_rep(13)))
    rpc(0x060978, 3, strn('server-a') + u32(1) + paddr(1) + big(u32(2) + u32(0)), repbody(0x060978, 3, 0, other_rep(0x060978, 3)))

    # --- more truncated item counts (requests and replies)
    for prog in (0x060977, 0x060978, 0x060979, 0x06097a):
        rpc(prog, 1, cred(2) + u32(1) + big(u32(0)) + qname(0), repbody(prog, 1, 0, u32(1) + u32(0)))
    rpc(0x060977, 4, u32(2) + big(u32(0)), repbody(0x060977, 4, 0, RC(0)))
    rpc(0x060979, 3, strn('supplier1') + big(u32(0)), repbody(0x060979, 3, 0, other_rep(0x060979, 3)))
    rpc(0x060976, 5, SID + strn('PrintAgent') + u32(7) + u32(1) + attrs(attr(1)) + big(u32(0)),
        repbody(0x060976, 5, 0, big(u32(0))))
    rpc(0x060977, 3, u32(1), repbody(0x060977, 3, 0, big(u32(1) + u32(1)) + RC(0)))
    rpc(0x060978, 1, cred(2) + u32(1) + bindsec(1), repbody(0x060978, 1, 0, big(u32(0))))
    rpc(0x060979, 1, cred(2) + u32(1) + bindsec(1), repbody(0x060979, 1, 0, big(u32(0))))
    for ty in (3, 4, 7):
        rpc(0x06097a, 5, list_resources(ty), repbody(0x06097a, 5, 0, u32(0) + u32(1) + u32(ty) + big(strn(''))))
    for func in (9, 10, 21, 22):
        rpc(0x060976, func, print_req(func, 0), repbody(0x060976, func, 0, strn('PrintAgent') + u32(7) + big(u32(0))))
    rpc(0x060976, 17, print_req(17), repbody(0x060976, 17, 0, big(b'\0' * 20)))
    # --- Unicode strings, an empty server name, address items of the remaining types
    rpc(0x060976, 4, SID + u32(2) + strn('PrintAgent', uni=True) + u32(5), repbody(0x060976, 4, 0, strn('Agent', uni=True) + u32(7)))
    rpc(0x060978, 3, strn('') + u32(1) + paddr(2) + u32(0), repbody(0x060978, 3, 0, RC(0)))
    rpc(0x060978, 5, strn('registry1') + paddr(5) + u32(0), repbody(0x060978, 5, 0, RC(0)))
    rpc(0x060976, 26, (SID + u32(5) + u32(1) + qname(2) + strn('supplier1') + u32(4) + N1
                       + u32(5) + addritem(13) + addritem(14) + addritem(16) + addritem(17) + addritem(0)
                       + eos_fix(1) + qname(1)), repbody(0x060976, 26, 0, u32(5)))

    # --- error replies of every kind (ndps_error())
    for func in (4, 5, 7, 9, 11, 13, 17, 21, 22, 26, 29, 35, 36):
        for kind in range(8):
            v = 100 + kind if (kind + func) % 2 else 200 + kind
            req = print_req(func, 0)
            rpc(0x060976, func, req, repbody(0x060976, func, 1, print_rep(func, v)))
    for func in (1, 2):
        rpc(0x060976, func, print_req(func, 0), repbody(0x060976, func, 1, print_rep(func, 100 + func)))
    rpc(0x060976, 14, print_req(14), repbody(0x060976, 14, 1, ndps_error_struct(8)))
    rpc(0x060976, 15, print_req(15), repbody(0x060976, 15, 1, ndps_error_struct(6, True)))
    # error and return codes
    rpc(0x060976, 12, print_req(12), u32(1) + u32(1), tail=False)                    # an error with no data
    rpc(0x060976, 16, print_req(16), u32(1) + u32(0x01000005), tail=False)           # a known error code, no data
    for prog, func in ((0x060977, 3), (0x060978, 8), (0x060979, 8)):
        rpc(prog, func, other_req(prog, func), u32(0) + other_rep(prog, func, 0, 0x01000004))
    rpc(0x060977, 6, b'', u32(0) + RC(0x01000002))
    rpc(0x060977, 4, other_req(0x060977, 4), u32(0) + RC(0x0100000a))
    rpc(0x06097a, 5, other_req(0x06097a, 5, 0), u32(0) + other_rep(0x06097a, 5, 99))
    for func in (3, 4):
        rpc(0x06097b, func, other_req(0x06097b, func), u32(0) + other_rep(0x06097b, func, 99))
    rpc(0x06097a, 6, other_req(0x06097a, 6, 0), u32(0) + u32(7))
    rpc(0x06097a, 7, other_req(0x06097a, 7, 0), u32(0) + u32(7))
    rpc(0x06097a, 10, other_req(0x06097a, 10, 0), u32(0) + u32(7))
    rpc(0x06097a, 1, other_req(0x06097a, 1, 0), None)
    # accept status of the Bind replies
    for acc in (1, 2, 3, 4, 5, 77):
        rpc(0x060976, 2, print_req(2, 0), u32(acc) + u32(0) + u32(0), accept=0)
    xid += 1
    t.send(pdu_req(xid, 0x060976, 3, SID + b'\0' * 8))
    t.send(pdu_rep(xid, u32(0) + u32(0), accept=1), to_server=False)      # RPC denied
    xid += 1
    t.send(pdu_rep(xid, u32(0) + u32(0) + u32(0)), to_server=False)       # a reply without request
    xid += 1
    t.send(pdu_req(xid, 0x060979, 0, b'\0' * 8))                          # function 0, the "None" function
    xid += 1
    t.send(pdu_req(xid, 0x060999, 1, b'\0' * 24))                         # unknown program
    xid += 1
    t.send(pdu_req(xid, 0x060976, 99, b'\0' * 24))                        # unknown function
    xid += 1
    t.send(pdu_req(xid, 0x06097a, 99, b'\0' * 24))
    xid += 1
    t.send(pdu_req(xid, 0x06097b, 99, b'\0' * 24))
    for pg in (0x060977, 0x060978, 0x060979):
        xid += 1
        t.send(pdu_req(xid, pg, 99, b'\0' * 24))
    # a packet that is neither request nor reply
    b = struct.pack('!III', 0x7777, 5, 0) + b'\0' * 40
    t.send(u16(0x8000) + u16(len(b)) + b)
    # the label of an earlier attribute does not carry over into the next packet
    rpc(0x060976, 4, sec_body, repbody(0x060976, 4, 0, print_rep(4)))
    rpc(0x060976, 7, SID + u32(0) + u32(4) + b'ctxt' + u32(1) + attrs(attr(11, v=2), attr(11, v=3)),
        repbody(0x060976, 7, 0, print_rep(7)))
    # a PDU split over TCP segments and several PDUs in one segment
    xid += 1
    p = pdu_req(xid, 0x060976, 3, SID + b'\0' * 8)
    t.conn.c2s(p[:21]); t.conn.c2s(p[21:])
    xid += 1
    p1 = pdu_req(xid, 0x060976, 3, SID + b'\0' * 8)
    xid += 1
    p2 = pdu_req(xid, 0x060976, 7, SID + u32(0) + u32(0) + u32(1) + u32(0) + u32(0))
    t.conn.c2s(p1 + p2)
    t.conn.fin()

    # --- NDPS over SPX/IPX: the six registered sockets, fragmented messages
    sx = [0x90b2, 0x90b3, 0x90b4, 0x90b5, 0x90b6, 0x90b7]
    cases = [(0x060976, 1, 0), (0x060977, 3, 0), (0x060978, 8, 0), (0x060979, 8, 0), (0x06097a, 5, 0), (0x06097b, 4, 0)]
    for sock, (prog, func, v) in zip(sx, cases):
        sp = Spx(f, csock=0x4100 + sock - 0x90b2, ssock=sock, cid=0x1200 + sock - 0x90b2, sid=0x2200 + sock - 0x90b2)
        xid += 1
        body = print_req(func, v) if prog == 0x060976 else other_req(prog, func, v)
        rb = print_rep(func) if prog == 0x060976 else other_rep(prog, func, 0, 0)
        sp.send(pdu_req(xid, prog, func, body + b'\0' * 8))
        sp.send(pdu_rep(xid, repbody(prog, func, 0, rb) + b'\0' * 8), to_server=False)
    sp = Spx(f, csock=0x4000, ssock=0x90b2, cid=0x1111, sid=0x2222)
    xid += 1
    sp.send(pdu_req(xid, 0x060976, 3, SID + b'\0' * 8))
    sp.send(pdu_rep(xid, u32(0) + b'\0' * 12), to_server=False)
    # a request in three SPX packets (without end of message in the first two)
    xid += 1
    big_req = pdu_req(xid, 0x060976, 13, SID + OID_X + objident(0) + u32(1) + objident(1)
                      + attrs(*[attr(1), attr(11), attr(34), attr(2), attr(36)] * 4) + CA(attr(1)))
    n = len(big_req)
    sp.send(big_req[:90], eom=False)
    sp.send(big_req[90:200], eom=False)
    sp.send(big_req[200:])
    # the reply in two packets
    rep = pdu_rep(xid, repbody(0x060976, 13, 0, attrs(*[attr(1), attr(11)] * 12)) )
    sp.send(rep[:80], to_server=False, eom=False)
    sp.send(rep[80:], to_server=False)
    # an ordinary message afterwards, and another fragmented one
    xid += 1
    sp.send(pdu_req(xid, 0x060976, 3, SID + b'\0' * 8))
    sp.send(pdu_rep(xid, u32(0) + b'\0' * 12), to_server=False)
    xid += 1
    r3 = pdu_req(xid, 0x060976, 7, SID + u32(0) + u32(4) + b'ctxt' + u32(1) + attrs(*[attr(1)] * 12))
    sp.send(r3[:60], eom=False)
    sp.send(r3[60:])
    # a packet whose type is neither request nor reply is shown as continuation data
    b = struct.pack('!III', 0x7778, 5, 0) + b'\0' * 40
    sp.send(u16(0x8000) + u16(len(b)) + b)
    # the reproducer of "NDPS: Keep the fragment state per frame": a request, its reply and a
    # trailing unfinished fragment; an earlier complete frame must not change when redissected
    sp2 = Spx(f, csock=0x4000, ssock=0x90b2, cid=0x1111, sid=0x2222)
    sp2.cseq = 10; sp2.sseq = 10
    req = u16(0x8000) + u16(0) + struct.pack('!IIIIII', 0x1234, 0, 2, 0x060976, 1, 1) + b'\0' * 16 + b'\0' * 64
    req = req[:2] + u16(len(req) - 4) + req[4:]
    rp = struct.pack('!III', 0x1234, 1, 0) + b'\0' * 8 + struct.pack('!II', 0, 0) + b'\0' * 32
    rp = u16(0x8000) + u16(len(rp)) + rp
    sp2.send(req)
    sp2.send(rp, to_server=False)
    sp2.send(b'\0' * 32, eom=False)
    return f

def build_malformed():
    """Truncated and inconsistent PDUs: every request and reply cut short."""
    f = []
    xid = 0x5000
    t = Tcp(f, 42000)
    def trunc(b, num, den=2):
        return b[:max(1, len(b) * num // den)]
    for prog, nf in FUNCS.items():
        for func in range(1, nf + 1):
            nv = variants_print(func) if prog == 0x060976 else variants_other(prog, func)
            for v in range(min(nv, 3)):
                req = print_req(func, v) if prog == 0x060976 else other_req(prog, func, v)
                rb = print_rep(func) if prog == 0x060976 else other_rep(prog, func, v if (func == 5 and prog == 0x06097a) else 0)
                pre = (u32(0) + u32(0)) if func in (1, 2) else b''
                xid += 1
                t.send(pdu_req(xid, prog, func, trunc(req, 2, 3)))
                t.send(pdu_rep(xid, trunc(pre + u32(0) + rb, 2, 3)), to_server=False)
                xid += 1
                t.send(pdu_req(xid, prog, func, trunc(req, 1, 3)))
                t.send(pdu_rep(xid, trunc(pre + u32(0) + rb, 1, 3)), to_server=False)
    # error structures cut short
    for kind in range(8):
        for ext in (False, True):
            xid += 1
            t.send(pdu_req(xid, 0x060976, 4, print_req(4, 2)))
            e = ndps_error_struct(kind, ext)
            t.send(pdu_rep(xid, u32(1) + strn('PrintAgent') + u32(7) + e[:len(e) // 2]), to_server=False)
    # attribute values cut short
    for ty in ATTR_TYPES:
        a = attr(ty, v=0)
        if len(a) > 8:
            xid += 1
            t.send(pdu_req(xid, 0x060976, 13, (SID + OID_X + objident(0) + u32(1) + objident(1)
                   + u32(1) + a[:len(a) - 4])))
    # a PDU shorter than its header, a huge item count, a negative-looking length
    t.send(u16(0x8000) + u16(8) + b'\0' * 8)
    xid += 1
    t.send(pdu_req(xid, 0x060976, 13, SID + OID_X + objident(0) + u32(1) + objident(1) + u32(0xfffffff0)))
    xid += 1
    t.send(pdu_req(xid, 0x06097a, 3, u32(1) + u32(1) + u32(1) + resfile_input(2) + u32(1) + u32(0x7ffffff0) + b'\0' * 8))
    xid += 1
    t.send(pdu_req(xid, 0x060976, 4, SID + u32(0) + strn('PrintAgent') + u32(1) + transfer_method(1) + u32(1) + OID_X
                   + u32(1) + u32(0) + u32(1) + u32(0) + u32(0xfffffff0)))
    t.conn.fin()
    return f

if __name__ == '__main__':
    out = sys.argv[1]
    m = build_main()
    write_pcap(os.path.join(out, 'ndps-coverage.pcap'), m)
    x = build_malformed()
    write_pcap(os.path.join(out, 'ndps-coverage-malformed.pcap'), x)
    print(len(m), len(x))
