#!/usr/bin/env python3
# Generates test/captures/dcerpc_lsa_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""mkdcerpc_lsa.py <outdir>: synthetic captures for the LSA DCE/RPC
dissector (packet-dcerpc-lsa.c) and the EFS policy blob it hands to
packet-gpef.c.

Every packet is built with struct. The NDR stubs are marshalled by a small
encoder driven by the Pidl NDR tree of lsa.idl (written by
shared/ndrdump.pl from epan/dissectors/pidl/lsa/lsa.idl), following the layout the
Pidl-generated Wireshark dissector reads. Addresses are from 192.0.2.0/24.

Writes dcerpc_lsa-coverage.pcap and dcerpc_lsa-coverage-malformed.pcap.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

import json
import struct
from pidljson import pidl_ndr_json

HERE = os.path.dirname(os.path.abspath(__file__))

UUID_LSA = '12345778-1234-abcd-ef00-0123456789ab'
UUID_NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
UUID_NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'


# ------------------------------------------------------------------ pcap/TCP
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


class TCP:
    """One TCP connection with a handshake; seq/ack kept per side."""
    MSS = 1460

    def __init__(self, frames, cport, sport=49155,
                 cip=(192, 0, 2, 50), sip=(192, 0, 2, 60)):
        self.frames = frames
        self.c = (bytes(cip), cport)
        self.s = (bytes(sip), sport)
        self.cseq, self.sseq = 0x10000000 + cport * 7, 0x20000000 + cport * 11
        self.seg(True, b'', 0x02)
        self.cseq += 1
        self.seg(False, b'', 0x12)
        self.sseq += 1
        self.seg(True, b'', 0x10)

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.cseq if from_client else self.sseq
        ack = 0 if flags == 0x02 else (self.sseq if from_client else self.cseq)
        opts = struct.pack('>BBH', 2, 4, self.MSS) if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', src[1], dst[1], seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        ph = src[0] + dst[0] + struct.pack('>BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000, 64, 6, 0,
                         src[0], dst[0])
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        mc, ms = bytes.fromhex('020000000050'), bytes.fromhex('020000000060')
        eth = (ms + mc) if from_client else (mc + ms)
        self.frames.append(eth + b'\x08\x00' + ip + tcp + payload)
        if from_client:
            self.cseq += len(payload)
        else:
            self.sseq += len(payload)

    def send(self, from_client, data):
        for i in range(0, len(data), self.MSS):
            self.seg(from_client, data[i:i + self.MSS])

    def fin(self):
        self.seg(True, b'', 0x11)
        self.cseq += 1
        self.seg(False, b'', 0x11)
        self.sseq += 1
        self.seg(True, b'', 0x10)


# ------------------------------------------------------------------ DCE/RPC
class RPC:
    def __init__(self, tcp, le=True, ndr64=False):
        self.tcp, self.le, self.ndr64 = tcp, le, ndr64
        self.e = '<' if le else '>'
        self.call_id = 0

    def uuid_bytes(self, u):
        h = u.replace('-', '')
        a, b, c = int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)
        return struct.pack(self.e + 'IHH', a, b, c) + bytes.fromhex(h[16:])

    def pdu(self, ptype, body, call_id, flags=0x03):
        drep = bytes([0x10 if self.le else 0x00, 0, 0, 0])
        hdr = struct.pack(self.e + 'BBBB', 5, 0, ptype, flags) + drep
        hdr += struct.pack(self.e + 'HHI', 16 + len(body), 0, call_id)
        return hdr + body

    def bind(self):
        self.call_id += 1
        ts = (UUID_NDR64, 1) if self.ndr64 else (UUID_NDR, 2)
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0) + struct.pack(self.e + 'B3x', 1)
        body += struct.pack(self.e + 'HBx', 0, 1) + self.uuid_bytes(UUID_LSA)
        body += struct.pack(self.e + 'I', 0)
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(True, self.pdu(11, body, self.call_id))
        sec = b'49155\0'
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0x12345) + struct.pack(self.e + 'H', len(sec)) + sec
        body += b'\0' * ((-(16 + len(body))) % 4)
        body += struct.pack(self.e + 'B3x', 1) + struct.pack(self.e + 'HH', 0, 0)
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(False, self.pdu(12, body, self.call_id))

    def frags(self, ptype, stub, hdr, maxfrag):
        """Split a stub into fragments of at most maxfrag octets."""
        parts = [stub[i:i + maxfrag] for i in range(0, len(stub), maxfrag)] or [b'']
        out = b''
        for i, p in enumerate(parts):
            flags = (0x01 if i == 0 else 0) | (0x02 if i == len(parts) - 1 else 0)
            out += self.pdu(ptype, hdr(len(stub)) + p, self.call_id, flags)
        return out

    def call(self, opnum, req, resp, maxfrag=1 << 20):
        self.call_id += 1
        self.tcp.send(True, self.frags(0, req, lambda n: struct.pack(self.e + 'IHH', n, 0, opnum), maxfrag))
        if resp is not None:
            self.tcp.send(False, self.frags(2, resp, lambda n: struct.pack(self.e + 'IHBB', n, 0, 0, 0), maxfrag))


# ------------------------------------------------------------------ NDR types
IDL = json.load(open(pidl_ndr_json('lsa')))[0]
TYPES = {t['NAME']: t['DATA'] for t in IDL['TYPES']}
FUNCS = {f['OPNUM']: f for f in IDL['FUNCTIONS']}
FUNC_BY_NAME = {f['NAME']: f for f in IDL['FUNCTIONS']}


def enum_values(t):
    vals = []
    cur = -1
    known = {}
    for el in t['ELEMENTS']:
        name, _, v = el.partition('=')
        name = name.strip()
        if v:
            v = v.strip()
            for k, kv in known.items():
                v = v.replace(k, str(kv))
            cur = eval(v)
        else:
            cur += 1
        known[name] = cur
        vals.append((name, cur))
    return vals


def bitmap_values(t):
    return [int(el.split('(')[1].split(')')[0], 16) for el in (t.get('ELEMENTS') or [])]


# The base types the Wireshark generator and lsa.cnf use for these
BASE = {'uint8': 'uint8', 'uint16': 'uint16', 'uint32': 'uint32', 'hyper': 'hyper',
        'uint3264': 'uint3264', 'uint1632': 'uint1632', 'NTSTATUS': 'uint32'}
ACCESS_MASKS = ('lsa_PolicyAccessMask', 'lsa_AccountAccessMask', 'lsa_SecretAccessMask',
                'lsa_TrustedAccessMask')


class Ndr:
    """NDR marshalling as the Pidl-generated Wireshark dissector reads it."""

    def __init__(self, le=True, ndr64=False):
        self.le, self.ndr64 = le, ndr64
        self.e = '<' if le else '>'
        self.buf = bytearray()
        self.ref = 0x00020000
        self.pending = None

    # primitives
    def align(self, a):
        if a == 5:
            a = 8 if self.ndr64 else 4
        elif a == 3:
            a = 4 if self.ndr64 else 2
        while len(self.buf) % a:
            self.buf.append(0)

    def prim(self, kind, v):
        if kind == 'uint3264':
            kind = 'hyper' if self.ndr64 else 'uint32'
        if kind == 'uint1632':
            kind = 'uint32' if self.ndr64 else 'uint16'
        fmt, size = {'uint8': ('B', 1), 'uint16': ('H', 2), 'uint32': ('I', 4), 'hyper': ('Q', 8)}[kind]
        self.align(size)
        self.buf += struct.pack(self.e + fmt, v)

    def referent(self, nonnull):
        if not nonnull:
            self.prim('uint3264', 0)
            return
        self.prim('uint3264', self.ref)
        self.ref += 4

    def defer(self, fn):
        self.pending.append(fn)

    def run_deferred(self, lst):
        for fn in lst:
            sub = []
            saved, self.pending = self.pending, sub
            fn()
            self.pending = saved
            self.run_deferred(sub)

    def top(self, fn):
        """Marshal one function parameter and then its deferred pointees."""
        lst = []
        self.pending = lst
        fn()
        self.pending = None
        self.run_deferred(lst)

    # elements
    def element(self, levels, idx, val, elname=''):
        lv = levels[idx]
        t = lv['TYPE']
        if t == 'POINTER':
            if lv.get('LEVEL') == 'TOP' and lv['POINTER_TYPE'] == 'ref':
                self.defer(lambda: self.element(levels, idx + 1, val, elname))
            else:
                self.referent(val is not None)
                if val is not None:
                    self.defer(lambda: self.element(levels, idx + 1, val, elname))
        elif t == 'ARRAY':
            if isinstance(val, str):
                units = list(val.encode('utf-16-le'))
                val = [units[i] | (units[i + 1] << 8) for i in range(0, len(units), 2)]
                if lv['IS_ZERO_TERMINATED']:
                    val.append(0)
            if lv['IS_FIXED']:
                assert len(val) == int(lv['SIZE_IS'])
            else:
                if lv['IS_CONFORMANT'] and not getattr(self, '_hoisted', None) is lv:
                    # lsa.cnf reads the EFS blob size as a uint32 also in NDR64
                    self.prim('uint32' if elname == 'efs_blob' else 'uint3264', len(val))
                if lv['IS_VARYING']:
                    self.prim('uint3264', 0)
                    self.prim('uint3264', len(val))
            for v in val:
                self.element(levels, idx + 1, v, elname)
        elif t == 'SWITCH':
            self.element(levels, idx + 1, val, elname)
        elif t == 'DATA':
            self.data(lv['DATA_TYPE'], val)
        else:
            raise ValueError(t)

    def data(self, name, val):
        if name in BASE:
            self.prim(BASE[name], val)
        elif name == 'NTTIME_hyper':
            self.prim('hyper', val)
        elif name == 'GUID':
            self.align(4)
            self.buf += val
        elif name == 'policy_handle':
            self.align(4)
            self.buf += val
        elif name == 'dom_sid2':
            self.prim('uint3264', sid_count(val))
            self.buf += sid_bytes(val)
        elif name in ('sec_desc_buf', 'security_descriptor'):
            # lsa.cnf cnf_dissect_sec_desc_buf: length, pointer, length, SD
            sd = val
            self.prim('uint32', len(sd) if sd is not None else 0)
            self.referent(sd is not None)
            if sd is not None:
                def pointee():
                    self.prim('uint32', len(sd))
                    self.buf += sd
                self.defer(pointee)
        elif name in TYPES:
            t = TYPES[name]
            if t['TYPE'] in ('ENUM', 'BITMAP'):
                self.prim(BASE[t['BASE_TYPE']], val)
            elif t['TYPE'] == 'STRUCT':
                self.struct(name, t, val)
            elif t['TYPE'] == 'UNION':
                self.union(name, t, val)
            else:
                raise ValueError(name)
        else:
            raise ValueError(name)

    def struct(self, name, t, val):
        fix_counts(t['ELEMENTS'], val)
        # NDR: the max_count of a conformant array embedded in a struct
        # comes first, before the struct (where the dissector reads it)
        last = t['ELEMENTS'][-1] if t['ELEMENTS'] else None
        hoist = None
        if last is not None:
            lv0 = last['LEVELS'][0]
            if lv0['TYPE'] == 'ARRAY' and lv0['IS_CONFORMANT'] and not lv0['IS_FIXED'] and last['NAME'] != 'efs_blob':
                hoist = lv0
                v = val[last['NAME']]
                if isinstance(v, str):
                    n = len(v.encode('utf-16-le')) // 2 + (1 if lv0['IS_ZERO_TERMINATED'] else 0)
                else:
                    n = len(v)
                self.prim('uint3264', n)
        self.align(t['ALIGN'])
        saved = getattr(self, '_hoisted', None)
        for el in t['ELEMENTS']:
            self._hoisted = hoist if el is last else None
            self.element(el['LEVELS'], 0, val[el['NAME']], el['NAME'])
        self._hoisted = saved
        if self.ndr64:
            self.align(t['ALIGN'])

    def union(self, name, t, val):
        level, arm = val
        st = t['SWITCH_TYPE']
        if st in TYPES:
            st = TYPES[st]['BASE_TYPE']
        self.prim(st, level)
        self.align(t['ALIGN'])
        el = union_arm(t, level)
        if el is not None and el['TYPE'] != 'EMPTY':
            self.element(el['LEVELS'], 0, arm, el['NAME'])


def union_cases(t):
    """[(level, element)] for every case of a union (default as None)."""
    out = []
    for el in t['ELEMENTS']:
        c = el['CASE']
        if c == 'default':
            out.append((None, el))
            continue
        c = c[len('case '):]
        v = None
        for et in TYPES.values():
            if et['TYPE'] == 'ENUM':
                for n, ev in enum_values(et):
                    if n == c:
                        v = ev
        if v is None:
            v = int(c, 0)
        out.append((v, el))
    return out


def union_arm(t, level):
    dflt = None
    for v, el in union_cases(t):
        if v is None:
            dflt = el
        elif v == level:
            return el
    return dflt


def array_len(levels, val):
    """Length of the array an element holds (after its pointers)."""
    for lv in levels:
        if lv['TYPE'] == 'POINTER':
            if val is None:
                return 0, None
            continue
        if lv['TYPE'] == 'ARRAY':
            if isinstance(val, str):
                return len(val.encode('utf-16-le')) // 2, lv
            return len(val), lv
        return None, None
    return None, None


def fix_counts(elements, val, names=None):
    """Set count/size/length/switch fields from the arrays and unions."""
    for el in elements:
        if el['NAME'] not in val:
            continue
        v = val[el['NAME']]
        n, lv = array_len(el['LEVELS'], v)
        if lv is not None and not lv['IS_FIXED'] and not lv['IS_ZERO_TERMINATED']:
            for expr in (lv['SIZE_IS'], lv['LENGTH_IS']):
                if expr.endswith('/2'):
                    val[expr[:-2]] = 2 * n
                else:
                    val[expr.lstrip('*')] = n
        elif lv is not None and n == 0 and lv['IS_ZERO_TERMINATED'] is None:
            pass
        for l2 in el['LEVELS']:
            if l2['TYPE'] == 'SWITCH':
                inner = v
                if inner is not None:
                    val[l2['SWITCH_IS'].lstrip('*')] = inner[0]


# ------------------------------------------------------------------ values
def sid_parse(s):
    p = s.split('-')
    return int(p[1]), int(p[2]), [int(x) for x in p[3:]]


def sid_count(s):
    return len(sid_parse(s)[2])


def sid_bytes(s):
    rev, auth, subs = sid_parse(s)
    return struct.pack('<BB', rev, len(subs)) + auth.to_bytes(6, 'big') + \
        b''.join(struct.pack('<I', x) for x in subs)


DOM = 'S-1-5-21-1004336348-1177238915-682003330'


def ace(atype, flags, mask, sid):
    body = struct.pack('<I', mask) + sid_bytes(sid)
    return struct.pack('<BBH', atype, flags, 4 + len(body)) + body


def acl(aces):
    body = b''.join(aces)
    return struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body


def secdesc():
    """Self-relative security descriptor with owner, group, SACL, DACL."""
    owner = sid_bytes(DOM + '-500')
    group = sid_bytes(DOM + '-513')
    sacl = acl([ace(2, 0xc0, 0x000f0fff, 'S-1-1-0')])
    dacl = acl([ace(0, 0x00, 0x000f1fff, DOM + '-500'),
                ace(1, 0x02, 0x00000003, 'S-1-5-32-544')])
    off = 20
    o_own, o_grp = off, off + len(owner)
    o_sacl = o_grp + len(group)
    o_dacl = o_sacl + len(sacl)
    hdr = struct.pack('<BBHIIII', 1, 0, 0x8014, o_own, o_grp, o_sacl, o_dacl)
    return hdr + owner + group + sacl + dacl


# ---- a minimal DER X.509 certificate for the EFS keys (synthetic)
def der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82, n >> 8, n & 0xff])
    return bytes([tag]) + ln + body


def oid(s):
    p = [int(x) for x in s.split('.')]
    out = bytes([40 * p[0] + p[1]])
    for x in p[2:]:
        enc = [x & 0x7f]
        x >>= 7
        while x:
            enc.insert(0, 0x80 | (x & 0x7f))
            x >>= 7
        out += bytes(enc)
    return der(0x06, out)


def name(cn):
    return der(0x30, der(0x31, der(0x30, oid('2.5.4.3') + der(0x0c, cn.encode()))))


def certificate(cn, serial):
    alg = der(0x30, oid('1.2.840.113549.1.1.11') + der(0x05, b''))
    rsakey = der(0x30, der(0x02, b'\x00' + bytes((0xc1 + i) & 0xff for i in range(64))) + der(0x02, b'\x01\x00\x01'))
    spki = der(0x30, der(0x30, oid('1.2.840.113549.1.1.1') + der(0x05, b'')) + der(0x03, b'\x00' + rsakey))
    tbs = der(0x30, der(0xa0, der(0x02, b'\x02')) + der(0x02, bytes([serial])) + alg + name('EFS Recovery CA') +
              der(0x30, der(0x17, b'230101000000Z') + der(0x17, b'330101000000Z')) + name(cn) + spki)
    return der(0x30, tbs + alg + der(0x03, b'\x00' + bytes(64)))


def efskey(sid, cert):
    """MS-GPEF EfsKey: length1, length2, sid offset, reserved, cert length,
    cert offset, reserved 0x20, SID, certificate (offsets from length2)."""
    sidb = sid_bytes(sid)
    sid_off = 24
    cert_off = sid_off + len(sidb)
    rest = struct.pack('<IIIIII', 0x14, sid_off, 0, len(cert), cert_off, 0x20) + sidb + cert
    return struct.pack('<I', 4 + len(rest)) + rest


def efsblob(keys):
    return struct.pack('<II', 0x00010001, len(keys)) + b''.join(keys)


EFSBLOB = efsblob([efskey(DOM + '-500', certificate('Administrator', 1)),
                   efskey(DOM + '-1104', certificate('EFS Recovery', 2))])

STRINGS = ['EXAMPLE', 'Administrator', 'example.test', 'SeBackupPrivilege', 'TRUSTED',
           'trusted.example.test', 'G$EFS', 'Backup Operators']


class Filler:
    """Default values for any IDL type: 'rich' (every pointer set, arrays
    of two, every bitmap bit) or 'min' (NULL pointers, empty arrays, no
    bits). Union arms rotate so that repeated calls reach every arm."""

    def __init__(self, variant):
        self.rich = variant == 'rich'
        self.n = 0
        self.rot = {}

    def counter(self):
        self.n += 1
        return self.n

    def string(self):
        return STRINGS[self.counter() % len(STRINGS)]

    def element(self, levels, idx, owner=None, elname=None):
        lv = levels[idx]
        t = lv['TYPE']
        if t == 'POINTER':
            if lv['POINTER_TYPE'] == 'ref' or self.rich:
                return self.element(levels, idx + 1, owner, elname)
            return None
        if t == 'ARRAY':
            nxt = levels[idx + 1]
            dt = nxt.get('DATA_TYPE')
            if lv['IS_FIXED']:
                return [(i * 7 + 1) & 0xff for i in range(int(lv['SIZE_IS']))]
            if dt == 'uint16' and nxt['TYPE'] == 'DATA':
                if owner == 'lsa_BinaryString':
                    return [0x1234, 0x5678] if self.rich else []
                return self.string()
            if dt == 'uint8' and nxt['TYPE'] == 'DATA':
                if elname == 'efs_blob':
                    return list(EFSBLOB)
                if owner in ('lsa_AsciiString', 'lsa_AsciiStringLarge'):
                    return list(self.string().encode())
                return list(bytes(range(1, 9))) if self.rich else []
            n = 2 if self.rich else 0
            if elname == 'entries' and owner and owner.startswith('lsa_ForestTrustInformation'):
                n = 5 if self.rich else 0
            return [self.element(levels, idx + 1, owner, elname) for _ in range(n)]
        if t == 'SWITCH':
            return self.element(levels, idx + 1, owner, elname)
        return self.data(lv['DATA_TYPE'], owner, elname)

    def data(self, name, owner=None, elname=None):
        if name in ('uint8', 'uint16', 'uint32', 'uint3264', 'uint1632'):
            return self.counter() & 0xff
        if name == 'hyper':
            return 0x0000000100000000 + self.counter()
        if name == 'NTSTATUS':
            return 0
        if name == 'NTTIME_hyper':
            return 133500000000000000 + self.counter() * 10000000
        if name == 'GUID':
            return bytes(range(0xa0, 0xb0))
        if name == 'policy_handle':
            return bytes(4) + bytes(range(0x70, 0x80))
        if name == 'dom_sid2':
            return DOM + '-%d' % (1000 + self.counter())
        if name in ('sec_desc_buf', 'security_descriptor'):
            return secdesc()
        t = TYPES[name]
        if t['TYPE'] == 'ENUM':
            vals = enum_values(t)
            i = self.rot.get(name, 0)
            self.rot[name] = i + 1
            return vals[i % len(vals)][1]
        if t['TYPE'] == 'BITMAP':
            if not self.rich:
                return 0
            if name in ACCESS_MASKS:
                return 0x130f0000 | sum(set(bitmap_values(t)))
            v = 0
            for b in bitmap_values(t):
                v |= b
            return v | 0x40000000
        if t['TYPE'] == 'STRUCT':
            return {el['NAME']: self.element(el['LEVELS'], 0, name, el['NAME']) for el in t['ELEMENTS']}
        if t['TYPE'] == 'UNION':
            cases = union_cases(t)
            i = self.rot.get(name, 0)
            self.rot[name] = i + 1
            level, el = cases[i % len(cases)]
            if level is None:
                level = 3        # default arm of lsa_ForestTrustData: binary data
            return self.union_arm(t, level, el)
        raise ValueError(name)

    def union_arm(self, t, level, el=None):
        if el is None:
            el = union_arm(t, level)
        if el is None or el['TYPE'] == 'EMPTY':
            return (level, None)
        return (level, self.element(el['LEVELS'], 0, None, el['NAME']))


# ------------------------------------------------------------------ calls
def marshal(func, direction, vals, le, ndr64):
    """Marshal the [in] or [out] parameters of a function (and the status)."""
    n = Ndr(le, ndr64)
    els = [e for e in func['ELEMENTS'] if direction in e['DIRECTION']]
    fix_counts(func['ELEMENTS'], vals)
    for e in els:
        n.top(lambda e=e: n.element(e['LEVELS'], 0, vals[e['NAME']], e['NAME']))
    if direction == 'out' and func.get('RETURN_TYPE'):
        n.prim('uint32', vals.get('result', 0))
    return bytes(n.buf)


def default_vals(func, variant, filler=None):
    f = filler or Filler(variant)
    vals = {}
    for e in func['ELEMENTS']:
        vals[e['NAME']] = f.element(e['LEVELS'], 0, None, e['NAME'])
    return vals


def call_pair(func, vals, le, ndr64):
    """Request and response stubs. Shared [in,out] values are used both ways."""
    return marshal(func, 'in', vals, le, ndr64), marshal(func, 'out', vals, le, ndr64)


def union_param(func):
    """(element, union type) of the function's switched union, if any."""
    for e in func['ELEMENTS']:
        for lv in e['LEVELS']:
            if lv['TYPE'] == 'DATA' and lv['DATA_TYPE'] in TYPES and TYPES[lv['DATA_TYPE']]['TYPE'] == 'UNION':
                return e, TYPES[lv['DATA_TYPE']]
    return None, None


HANDLE_OUT = {'OpenPolicy': 'P', 'OpenPolicy2': 'P', 'OpenPolicy3': 'P',
              'CreateAccount': 'A', 'OpenAccount': 'A',
              'CreateSecret': 'S', 'OpenSecret': 'S',
              'CreateTrustedDomain': 'D', 'OpenTrustedDomain': 'D',
              'OpenTrustedDomainByName': 'D', 'CreateTrustedDomainEx': 'D',
              'CreateTrustedDomainEx2': 'D', 'CreateTrustedDomainEx3': 'D'}
HANDLE_IN = {'QueryTrustedDomainInfo': 'D', 'SetInformationTrustedDomain': 'D',
             'CloseTrustedDomainEx': 'D',
             'EnumPrivsAccount': 'A', 'AddPrivilegesToAccount': 'A',
             'RemovePrivilegesFromAccount': 'A', 'GetSystemAccessAccount': 'A',
             'SetSystemAccessAccount': 'A', 'SetSecret': 'S', 'QuerySecret': 'S'}


class Handles:
    """Policy handles of one connection. Every open returns a new handle
    (a handle value opened again without a close would keep its type on
    the old instance in Wireshark's handle table)."""

    def __init__(self, base):
        self.base, self.n, self.cur = base, 0, {}

    def new(self, kind):
        self.n += 1
        h = b'\0' * 4 + kind.encode() + bytes([self.base, self.n >> 8, self.n & 0xff]) + bytes(range(0x10, 0x1c))
        self.cur[kind] = h
        return h


def set_handles(func, vals, hs):
    short = func['NAME'][4:]
    for e in func['ELEMENTS']:
        if e['TYPE'] == 'policy_handle':
            if e['DIRECTION'] == ['out']:
                vals[e['NAME']] = hs.new(HANDLE_OUT.get(short, 'P'))
            else:
                vals[e['NAME']] = hs.cur[HANDLE_IN.get(short, 'P')]


# a minimal variant of every union arm for one function per union
MIN_ARMS = ('lsa_QueryInfoPolicy', 'lsa_QueryTrustedDomainInfo', 'lsa_QueryDomainInformationPolicy')


def calls_for(func, variant, hs, all_arms=True):
    """[(vals)] for one function: one call per union arm, or one."""
    out = []
    e, ut = union_param(func)
    if e is not None and all_arms and (variant == 'rich' or func['NAME'] in MIN_ARMS):
        for level, el in union_cases(ut):
            f = Filler(variant)
            vals = default_vals(func, variant, f)
            if level is None:
                level = 3
            # the union sits behind the pointer levels of the element
            vals[e['NAME']] = f.union_arm(ut, level, el)
            out.append(vals)
    else:
        out.append(default_vals(func, variant))
    for vals in out:
        set_handles(func, vals, hs)
        vals['result'] = 0 if variant == 'rich' else 0xc0000022
        if not func['ELEMENTS']:
            vals['result'] = 0xc0000002     # STATUS_NOT_IMPLEMENTED
    return out


OPEN_ORDER = ['lsa_OpenPolicy2', 'lsa_CreateAccount', 'lsa_OpenSecret', 'lsa_OpenTrustedDomain']


def connection(F, cport, le, ndr64, variants, all_arms, extra=True):
    t = TCP(F, cport)
    r = RPC(t, le, ndr64)
    hs = Handles(cport & 0xff)
    r.bind()

    def open_all():
        for nm in OPEN_ORDER:
            func = FUNC_BY_NAME[nm]
            vals = calls_for(func, 'rich', hs, False)[0]
            r.call(func['OPNUM'], *call_pair(func, vals, le, ndr64))
    open_all()
    for variant in variants:
        print('port %d: %s calls from frame %d' % (cport, variant, len(F) + 1))
        for opnum in sorted(FUNCS):
            func = FUNCS[opnum]
            if not func['ELEMENTS'] and not (extra and variant == variants[0]):
                continue
            for vals in calls_for(func, variant, hs, all_arms):
                r.call(opnum, *call_pair(func, vals, le, ndr64))
    if extra:
        # QuerySecurity and SetSecObj on new policy, account, secret and
        # trusted domain handles and on an unknown handle: the access rights
        # in the security descriptor follow the type of the handle
        print('port %d: security descriptors from frame %d' % (cport, len(F) + 1))
        open_all()
        unknown = b'\0' * 4 + b'U' + bytes(15)
        for h in [hs.cur[k] for k in 'PASD'] + [unknown]:
            for nm in ('lsa_QuerySecurity', 'lsa_SetSecObj'):
                func = FUNC_BY_NAME[nm]
                vals = calls_for(func, 'rich', hs, False)[0]
                vals['handle'] = h
                r.call(func['OPNUM'], *call_pair(func, vals, le, ndr64))
        # a fragmented request and response (LookupSids2 with many SIDs)
        print('port %d: fragmented call from frame %d' % (cport, len(F) + 1))
        func = FUNC_BY_NAME['lsa_LookupSids2']
        vals = calls_for(func, 'rich', hs, False)[0]
        vals['sids'] = {'num_sids': 0, 'sids': [{'sid': DOM + '-%d' % (2000 + i)} for i in range(40)]}
        vals['names'] = {'count': 0, 'names': [
            {'sid_type': 1, 'name': {'length': 0, 'size': 0, 'string': 'user%02d' % i},
             'sid_index': 0, 'unknown': 0} for i in range(40)]}
        r.call(func['OPNUM'], *call_pair(func, vals, le, ndr64), maxfrag=400)
        # close the handles
        print('port %d: closes from frame %d' % (cport, len(F) + 1))
        for k in 'ASDP':
            func = FUNC_BY_NAME['lsa_CloseTrustedDomainEx' if k == 'D' else 'lsa_Close']
            vals = {'handle': hs.cur[k], 'result': 0}
            r.call(func['OPNUM'], *call_pair(func, vals, le, ndr64))
    t.fin()
    print('port %d: ends at frame %d' % (cport, len(F)))


# ------------------------------------------------------------------ malformed
def malformed(F):
    le, ndr64 = True, False
    hs = Handles(0x99)
    H_POLICY = hs.new('P')
    t = TCP(F, 50100)
    r = RPC(t)
    r.bind()
    # reproducer lsa_secdesc_wrap.py: sec_desc_buf length 0xfffffff0
    sd = struct.pack('<HHIIII', 1, 0x8004, 0, 0, 0, 0)
    resp = struct.pack('<III', 0x00020000, len(sd), 0x00020004) + struct.pack('<I', 0xfffffff0) + sd + \
        struct.pack('<I', 0)
    r.call(3, H_POLICY + struct.pack('<I', 4), resp)
    # reproducer lsa_efsblob_loop.py: EFS blob with key count 0xffffffff and
    # an EfsKey of length 0
    sid = struct.pack('<BB', 1, 1) + b'\0\0\0\0\0\x05' + struct.pack('<I', 32)
    key = struct.pack('<IIIIII', 0, 0, 24, 0, 2, 36) + struct.pack('<I', 0x20) + sid + b'\x30\x00'
    blob = struct.pack('<II', 0x00010001, 0xffffffff) + key
    resp = struct.pack('<IH', 0x00020000, 2) + b'\0\0' + struct.pack('<II', len(blob), 0x00020004)
    resp += struct.pack('<I', len(blob)) + blob
    resp += b'\0' * ((-len(resp)) % 4) + struct.pack('<I', 0)
    r.call(53, H_POLICY + struct.pack('<H', 2), resp)
    # EFS key longer than the blob
    k = efskey(DOM + '-500', certificate('Administrator', 1))
    bad = struct.pack('<II', 0x00010001, 1) + struct.pack('<I', len(k) + 100) + k[4:]
    func = FUNC_BY_NAME['lsa_QueryDomainInformationPolicy']
    vals = calls_for(func, 'rich', hs)[1]
    vals['info'] = (2, {'blob_size': 0, 'efs_blob': list(bad)})
    r.call(53, *call_pair(func, vals, le, ndr64))
    # EFS blob with a key count beyond the keys, and a bad certificate
    k2 = efskey(DOM + '-500', b'\x30\x03\x02\x01')
    bad = struct.pack('<II', 0x00010001, 3) + k2
    vals['info'] = (2, {'blob_size': 0, 'efs_blob': list(bad)})
    r.call(53, *call_pair(func, vals, le, ndr64))
    # efs blob size beyond the stub
    vals['info'] = (2, {'blob_size': 0, 'efs_blob': list(EFSBLOB)})
    req, resp = call_pair(func, vals, le, ndr64)
    r.call(53, req, resp[:40])
    # sec_desc_buf longer than the stub, and a bogus SD
    func = FUNC_BY_NAME['lsa_SetSecObj']
    vals = calls_for(func, 'rich', hs, False)[0]
    req, resp = call_pair(func, vals, le, ndr64)
    r.call(4, req[:-20], resp)
    vals['sdbuf'] = struct.pack('<HHIIII', 1, 0x8004, 4, 8, 12, 16)
    r.call(4, *call_pair(func, vals, le, ndr64))
    # every function's request and response cut short
    for opnum in sorted(FUNCS):
        func = FUNCS[opnum]
        if not func['ELEMENTS']:
            continue
        vals = calls_for(func, 'rich', hs, False)[0]
        req, resp = call_pair(func, vals, le, ndr64)
        r.call(opnum, req[:len(req) // 2], resp[:len(resp) // 2])
    # unknown union levels
    for nm in ('lsa_QueryInfoPolicy', 'lsa_QueryTrustedDomainInfo', 'lsa_QueryDomainInformationPolicy'):
        func = FUNC_BY_NAME[nm]
        vals = calls_for(func, 'rich', hs, False)[0]
        e, ut = union_param(func)
        vals[e['NAME']] = (99, None)
        r.call(func['OPNUM'], *call_pair(func, vals, le, ndr64))
    t.fin()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    F = []
    # NDR little endian: every opnum, every union arm, rich and minimal values
    connection(F, 50001, True, False, ('rich', 'min'), True)
    # NDR big endian and NDR64: every opnum and union arm with rich values
    connection(F, 50002, False, False, ('rich',), True, extra=False)
    connection(F, 50003, True, True, ('rich',), True, extra=False)
    write_pcap(os.path.join(out, 'dcerpc_lsa-coverage.pcap'), F)
    M = []
    malformed(M)
    write_pcap(os.path.join(out, 'dcerpc_lsa-coverage-malformed.pcap'), M)


if __name__ == '__main__':
    main()
