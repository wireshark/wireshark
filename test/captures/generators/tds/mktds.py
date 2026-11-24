#!/usr/bin/env python3
# Generates test/captures/tds_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic TDS coverage captures (nothing comes from a network).

    python3 mktds.py <outdir> [-v]

writes tds-coverage.pcap (decodes cleanly) and tds-coverage-malformed.pcap
(error paths).  Every packet is built with struct; the addresses are from
192.0.2.0/24.  -v prints the frame ranges of every section.
"""
import struct
import sys
import os

# --------------------------------------------------------------------------
# pcap / TCP writer
# --------------------------------------------------------------------------


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


class Pcap:
    def __init__(self):
        self.pkts = []
        self.sections = []

    def section(self, name):
        self.sections.append((len(self.pkts) + 1, name))

    def add(self, pkt):
        self.pkts.append(pkt)

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)

    def ranges(self):
        out = []
        for i, (first, name) in enumerate(self.sections):
            last = self.sections[i + 1][0] - 1 if i + 1 < len(self.sections) else len(self.pkts)
            out.append((first, last, name))
        return out


class Conn:
    """One TCP connection; c() sends from the client, s() from the server."""

    def __init__(self, cap, cport, sport=1433, cip='192.0.2.1', sip='192.0.2.2'):
        self.cap = cap
        self.cip = bytes(map(int, cip.split('.')))
        self.sip = bytes(map(int, sip.split('.')))
        self.cport = cport
        self.sport = sport
        self.seq = {0: 1000, 1: 5000}
        self.ipid = 1

    def _send(self, from_client, payload, flags=0x18):
        d = 0 if from_client else 1
        src, dst = (self.cip, self.sip) if from_client else (self.sip, self.cip)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], self.seq[1 - d], 0x50, flags, 65535, 0, 0)
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        c = csum(ph + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), self.ipid, 0, 64, 6, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        mac_c = b'\x02\0\0\0\0\x01'
        mac_s = b'\x02\0\0\0\0\x02'
        eth = (mac_s + mac_c if from_client else mac_c + mac_s) + b'\x08\x00'
        self.cap.add(eth + ip + tcp + payload)
        self.seq[d] += len(payload)

    def c(self, payload, *more):
        self._send(True, payload + b''.join(more))

    def s(self, payload, *more):
        self._send(False, payload + b''.join(more))

    def csplit(self, payload, *cuts):
        self._split(True, payload, cuts)

    def ssplit(self, payload, *cuts):
        self._split(False, payload, cuts)

    def _split(self, from_client, payload, cuts):
        pos = 0
        for cut in list(cuts) + [len(payload)]:
            self._send(from_client, payload[pos:cut])
            pos = cut


# --------------------------------------------------------------------------
# generic helpers
# --------------------------------------------------------------------------

def u16(s):
    return s.encode('utf-16-le')


def nl(ptype, payload, status=1, ch=0, pn=1, win=0):
    """Netlib (TDS packet) header and payload."""
    return struct.pack('>BBHHBB', ptype, status, 8 + len(payload), ch, pn, win) + payload


Q_BATCH, Q_LOGIN, Q_RPC, Q_RESP, Q_RAW, Q_ATTN, Q_BULK = 1, 2, 3, 4, 5, 6, 7
Q_TRANSMGR, Q_TDS5, Q_LOGIN7, Q_SSPI, Q_PRELOGIN = 14, 15, 16, 17, 18

COLL = bytes([0x09, 0x04, 0xd0, 0x00, 0x34])   # collation: LCID, flags, sort id


class Fmt:
    """Byte order and character encoding of a conversation."""

    def __init__(self, le=True, ch='u16'):
        self.le = le
        self.ch = ch
        self.e = '<' if le else '>'

    def p2(self, v):
        return struct.pack(self.e + 'H', v)

    def p4(self, v):
        return struct.pack(self.e + 'I', v)

    def s(self, text):
        if self.ch == 'u16':
            return text.encode('utf-16-le')
        if self.ch == 'ebcdic':
            return text.encode('cp037')
        return text.encode('ascii')

    def bvc(self, text):          # 1 byte length (characters) + string
        return bytes([len(text)]) + self.s(text)

    def luc(self, text):          # 1 byte length prefix in bytes (FT_UINT_STRING)
        d = self.s(text)
        return bytes([len(d)]) + d

    def luc2(self, text):         # 2 byte length prefix in bytes
        d = self.s(text)
        return self.p2(len(d)) + d


F7 = Fmt(True, 'u16')


def tok2(tok, body, f=F7):
    """Token with a 2-byte length field."""
    return bytes([tok]) + f.p2(len(body)) + body


# --------------------------------------------------------------------------
# TDS 7 client messages
# --------------------------------------------------------------------------

def allhdr(kind='trans', rc=1):
    if kind == 'none':
        return b''
    h = struct.pack('<IHQI', 18, 2, 0, rc)
    if kind == 'notif':
        h = struct.pack('<IH', 14, 1) + b'\x04\x00' + b'\x01\x00' + b'\x00\x00' + b'\x00\x00'
    if kind == 'both':
        h = struct.pack('<IHQI', 18, 2, 0, rc) + struct.pack('<IH', 14, 1) + b'\0' * 8
    if kind == 'unknown':
        h = struct.pack('<IHQI', 18, 2, 0, rc) + struct.pack('<IH', 22, 3) + b'\0' * 16
    return struct.pack('<I', 4 + len(h)) + h


def prelogin(opts):
    n = len(opts)
    hl = n * 5 + 1
    hdr = b''
    data = b''
    for tok, d in opts:
        hdr += struct.pack('>BHH', tok, hl + len(data), len(d))
        data += d
    return hdr + b'\xff' + data


def pl_version(v, sub=0):
    return (0, struct.pack('>I', v) + struct.pack('<H', sub))


PL_ALL = [pl_version(0x0f000000, 4000), (1, b'\x00'), (2, b'MSSQLServer\0'),
          (3, struct.pack('>I', 4242)), (4, b'\x01'), (5, bytes(range(36))),
          (6, b'\x01'), (7, bytes(range(32)))]


def obf_pw(pw):
    out = b''
    for ch in u16(pw):
        out += bytes([(((ch << 4) & 0xf0) | (ch >> 4)) ^ 0xa5])
    return out


def login7(ver, user='sa', pw='Pa55', host='client1', app='tdsapp', srv='sqlhost',
           lib='tdslib', loc='us_english', db='master', sspi=b'', pktsize=4096,
           empty_fields=False):
    fields = [u16(host), u16(user), obf_pw(pw), u16(app), u16(srv), b'', u16(lib), u16(loc), u16(db)]
    if empty_fields:
        fields = [u16(host), u16(user), b'', u16(app), u16(srv), b'', u16(lib), u16(loc), u16(db)]
    base = 94
    offs = []
    lens = b''
    data = b''
    for fld in fields:
        offs.append(base + len(data))
        lens += struct.pack('<HH', base + len(data), len(fld) // 2)
        data += fld
    sspi_off = base + len(data)
    data += sspi
    total = base + len(data)
    hdr = struct.pack('<III', total, ver, pktsize) + struct.pack('>I', 0x07000000)
    hdr += struct.pack('<II', 4321, 0) + bytes([0xe0, 0x03, 0x00, 0x00]) + struct.pack('<iI', -60, 0x00d00409)
    tail = b'\x02\0\0\0\0\x01' + struct.pack('<HH', sspi_off, len(sspi)) + struct.pack('<HH', base, 0)
    tail += struct.pack('<HH', base, 0) + struct.pack('<I', 0)
    return hdr + lens + tail + data


NTLM_NEG = b'NTLMSSP\0' + struct.pack('<IIHHIHHI', 1, 0xe2088297, 0, 0, 32, 0, 0, 32)
NTLM_CHAL = (b'NTLMSSP\0' + struct.pack('<I', 2) + struct.pack('<HHI', 0, 0, 48) +
             struct.pack('<I', 0xe2898215) + bytes(range(1, 9)) + b'\0' * 8 + struct.pack('<HHI', 0, 0, 48))
NTLM_AUTH = (b'NTLMSSP\0' + struct.pack('<I', 3) + struct.pack('<HHI', 0, 0, 64) * 6 +
             struct.pack('<I', 0xe2888215))
SPNEGO_RESP = bytes([0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00])


# ---- type info / column definitions shared by COLMETADATA and RPC ----

def t_fixed(t):
    return bytes([t])


def t_bl(t, size):
    return bytes([t, size])


def t_num(t, size, prec, scale):
    return bytes([t, size, prec, scale])


def t_scale(t, scale):
    return bytes([t, scale])


def t_large(t, size):
    return bytes([t]) + struct.pack('<H', size)


def t_largec(t, size):
    return bytes([t]) + struct.pack('<H', size) + COLL


def colmeta(cols, old=False, flags=0x0009):
    """COLMETADATA token; cols = [(name, typeinfo)]; old: 16 bit user type (TDS 7.1)."""
    b = struct.pack('<H', len(cols))
    for name, ti in cols:
        b += (struct.pack('<H', 0) if old else struct.pack('<I', 0))
        b += struct.pack('<H', flags) + ti + bytes([len(name)]) + u16(name)
    return b'\x81' + b


def plp(chunks, total='sum'):
    if total == 'null':
        return b'\xff' * 8
    tl = sum(len(c) for c in chunks) if total == 'sum' else (0xfffffffffffffffe if total == 'unk' else total)
    b = struct.pack('<Q', tl)
    for c in chunks:
        b += struct.pack('<I', len(c)) + c
    return b + struct.pack('<I', 0)


def us(b):                     # 2-byte length + bytes
    return struct.pack('<H', len(b)) + b


def b16(t):                    # B_VARCHAR: 1-byte character count + UTF-16
    return bytes([len(t)]) + u16(t)


def bl(b):                     # 1-byte length + bytes
    return bytes([len(b)]) + b


def textval(data, ptr=bytes(range(16)), ts=bytes(range(8)), null=False):
    return bytes([len(ptr)]) + ptr + ts + (struct.pack('<I', 0xffffffff) if null else struct.pack('<I', len(data)) + data)


def textval_be(f, data, ptr=bytes(range(16)), ts=bytes(range(8))):
    return bytes([len(ptr)]) + ptr + ts + f.p4(len(data)) + data


def done(tok, status, cmd, rows, wide=True, f=F7):
    b = f.p2(status) + f.p2(cmd)
    b += struct.pack('<Q', rows) if wide else f.p4(rows)
    return bytes([tok]) + b


def msgtoken(tok, num, state, cls, msg, srv, proc, line, f=F7, wide=True):
    body = f.p4(num) + bytes([state, cls]) + f.p2(len(msg)) + f.s(msg) + f.bvc(srv) + f.bvc(proc)
    body += f.p4(line) if wide else f.p2(line)
    return tok2(tok, body, f)


def envchg(typ, new=b'', old=b'', f=F7):
    return tok2(0xe3, bytes([typ]) + new + old, f)


def loginack(ver, prog='Microsoft SQL Server', pv=0x0f000fa0, f=F7):
    body = bytes([1]) + struct.pack('>I', ver) + f.bvc(prog) + struct.pack('>I', pv)
    return tok2(0xad, body, f)


def returnstatus(v, f=F7):
    return b'\x79' + f.p4(v & 0xffffffff)


# --------------------------------------------------------------------------
# TDS 7 result sets
# --------------------------------------------------------------------------

def int_row(*vals):
    return b'\xd1' + b''.join(vals)


def nbc_row(nulls, vals):
    """NBCROW: bitmap of null columns, then the values of the others."""
    n = len(vals)
    bm = bytearray((n + 7) // 8)
    for i in nulls:
        bm[i // 8] |= 1 << (i % 8)
    return b'\xd2' + bytes(bm) + b''.join(v for i, v in enumerate(vals) if i not in nulls)


DT8 = struct.pack('<iI', 44000, 1200000)
DT4 = struct.pack('<HH', 43000, 600)


def rs_fixed():
    cols = [('c_null', t_fixed(0x1f)), ('c_int1', t_fixed(0x30)), ('c_bit', t_fixed(0x32)),
            ('c_int2', t_fixed(0x34)), ('c_int4', t_fixed(0x38)), ('c_dt4', t_fixed(0x3a)),
            ('c_flt4', t_fixed(0x3b)), ('c_money', t_fixed(0x3c)), ('c_dt', t_fixed(0x3d)),
            ('c_flt8', t_fixed(0x3e)), ('c_mon4', t_fixed(0x7a)), ('c_int8', t_fixed(0x7f))]
    vals = [b'', b'\x07', b'\x01', struct.pack('<h', -5), struct.pack('<i', 123456), DT4,
            struct.pack('<f', 1.5), struct.pack('<II', 0, 12345678), DT8, struct.pack('<d', 2.5),
            struct.pack('<I', 31415926), struct.pack('<q', -9876543210)]
    return colmeta(cols), [int_row(*vals), nbc_row([0, 3, 6, 9], vals)]


def rs_bytelen():
    cols = [('g', t_bl(0x24, 16)), ('n', t_bl(0x26, 4)), ('b', t_bl(0x68, 1)), ('f', t_bl(0x6d, 8)),
            ('m', t_bl(0x6e, 8)), ('d', t_bl(0x6f, 8))]
    g = bl(bytes(range(16)))
    rows = [
        int_row(g, bl(struct.pack('<i', 77)), bl(b'\x01'), bl(struct.pack('<d', 3.25)),
                bl(struct.pack('<II', 0, 5000)), bl(DT8)),
        int_row(b'\x00', bl(b'\x05'), b'\x00', bl(struct.pack('<f', 0.5)),
                bl(struct.pack('<I', 7000)), bl(DT4)),
        int_row(g, bl(struct.pack('<h', -2)), bl(b'\x00'), b'\x00', b'\x00', b'\x00'),
        int_row(g, bl(struct.pack('<q', 1 << 40)), b'\x00', b'\x00', b'\x00', b'\x00'),
        int_row(g, b'\x00', b'\x00', b'\x00', b'\x00', b'\x00'),
    ]
    return colmeta(cols), rows


def rs_dec_char():
    cols = [('dec', t_num(0x6a, 9, 18, 2)), ('num', t_num(0x6c, 5, 9, 0)), ('ch', t_bl(0x2f, 10)),
            ('vch', t_bl(0x27, 10)), ('bin', t_bl(0x2d, 8)), ('vbin', t_bl(0x25, 8))]
    rows = [
        int_row(bl(b'\x01' + struct.pack('<Q', 12345)), bl(b'\x00' + struct.pack('<I', 99)),
                bl(u16('abc')), bl(u16('de')), bl(b'\x01\x02\x03'), bl(b'\xaa\xbb')),
        int_row(bl(b'\x00' + struct.pack('<Q', 5)), b'\x00', b'\x00', b'\x00', b'\x00', b'\x00'),
        int_row(bl(b'\x01' + bytes(range(1, 17))), bl(b'\x01' + struct.pack('<I', 1)),
                bl(b''), bl(b''), bl(b''), bl(b'')),
        int_row(b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00'),
    ]
    return colmeta(cols), rows


def rs_dates():
    cols = [('dn', t_fixed(0x28)), ('tn', t_scale(0x29, 3)), ('d2a', t_scale(0x2a, 2)),
            ('d2b', t_scale(0x2a, 4)), ('d2c', t_scale(0x2a, 7)), ('dto', t_scale(0x2b, 7)),
            ('dtp', t_scale(0x2b, 2))]
    days = struct.pack('<I', 738000)[:3]
    rows = [
        int_row(bl(days), bl(struct.pack('<I', 3600000)), bl(struct.pack('<I', 360000)[:3] + days),
                bl(struct.pack('<I', 36000000) + days), bl(struct.pack('<Q', 360000000000)[:5] + days),
                bl(struct.pack('<Q', 360000000000)[:5] + days + struct.pack('<h', 120)),
                bl(struct.pack('<I', 360000)[:3] + days + struct.pack('<h', -300))),
        int_row(b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00'),
        int_row(bl(b'\x01\x02'), bl(struct.pack('<Q', 1)[:5]), b'\x00', b'\x00', b'\x00', b'\x00', b'\x00'),
    ]
    return colmeta(cols), rows


def rs_large():
    cols = [('bvb', t_large(0xa5, 8000)), ('bvc', t_largec(0xa7, 100)), ('bb', t_large(0xad, 16)),
            ('bc', t_largec(0xaf, 16)), ('nv', t_largec(0xe7, 200)), ('nc', t_largec(0xef, 20))]
    nul = struct.pack('<H', 0xffff)
    rows = [
        int_row(us(b'\x01\x02\x03'), us(b'hello'), us(bytes(range(16))), us(b'padded          '),
                us(u16('wide text')), us(u16('nchar'))),
        int_row(nul, nul, nul, nul, nul, nul),
        int_row(us(b''), us(b''), us(b''), us(b''), us(b''), us(b'')),
    ]
    return colmeta(cols), rows


def rs_plp():
    cols = [('vcm', t_largec(0xa7, 0xffff)), ('nvm', t_largec(0xe7, 0xffff)), ('vbm', t_large(0xa5, 0xffff)),
            ('xml', bytes([0xf1, 0])), ('udt', None)]
    udt = (bytes([0xf0]) + struct.pack('<H', 100) + bytes([2]) + u16('db') + bytes([3]) + u16('dbo') +
           bytes([4]) + u16('geom') + struct.pack('<H', 9) + u16('Assembly1'))
    cols[4] = ('udt', udt)
    one = [b'abc', u16('wide'), b'\x01\x02', b'<a/>', b'\x09\x08']
    rows = [
        int_row(*[plp([v]) for v in one]),
        int_row(*[plp([v[:1], v[1:]], 'unk') for v in one]),
        int_row(*[plp([], 'null') for v in one]),
        int_row(*[plp([], 0) for v in one]),
        int_row(*[plp([], 'unk') for v in one]),
        int_row(*[plp([v], 3) for v in one]),
        int_row(plp([], 4), plp([], 4), plp([], 4), plp([], 4), plp([], 4)),
    ]
    return colmeta(cols), rows


def rs_xml_schema():
    xml = (bytes([0xf1, 1]) + bytes([2]) + u16('db') + bytes([3]) + u16('dbo') + bytes([0]) + bytes([4]) + u16('coll'))
    xml2 = (bytes([0xf1, 1]) + bytes([0]) + bytes([0]) + bytes([3]) + u16('xml') + bytes([0]))
    udt = bytes([0xf0]) + struct.pack('<H', 8) + bytes([0, 0, 0]) + struct.pack('<H', 0)
    cols = [('x1', xml), ('x2', xml2), ('u', udt)]
    rows = [int_row(plp([b'<x/>']), plp([b'<y/>']), plp([b'\x01']))]
    return colmeta(cols), rows


def tblname(parts, newfmt=True):
    if newfmt:
        b = bytes([len(parts)])
        for p in parts:
            b += struct.pack('<H', len(p)) + u16(p)
        return b
    p = parts[0] if parts else ''
    return struct.pack('<H', len(p)) + u16(p)


def rs_text(newfmt=True):
    txt = bytes([0x23]) + struct.pack('<I', 2000000000) + COLL + tblname(['dbo', 'tbl'], newfmt)
    ntx = bytes([0x63]) + struct.pack('<I', 2000000000) + COLL + tblname(['t'], newfmt)
    img = bytes([0x22]) + struct.pack('<I', 2000000000) + tblname(['db', 'dbo', 'i'], newfmt)
    ssv = bytes([0x62]) + struct.pack('<I', 8009)
    cols = [('txt', txt), ('ntx', ntx), ('img', img), ('ssv', ssv)]
    rows = [
        int_row(textval(b'text value'), textval(u16('ntext value')), textval(b'\x00\x01\x02'), textval(b'\x01\x02')),
        int_row(textval(b'', null=True), textval(b'', null=True), textval(b'', null=True), textval(b'', null=True)),
    ]
    return colmeta(cols, old=not newfmt), rows


def result(rs, status=0x10, rows=2, wide=True):
    meta, rws = rs
    return meta + b''.join(rws) + done(0xfd, status, 0xc1, rows, wide=wide)


# --------------------------------------------------------------------------
# RPC parameters
# --------------------------------------------------------------------------

def rpc_param(name, ti, val, status=0):
    return bytes([len(name)]) + u16(name) + bytes([status]) + ti + val


def rpc_named(name, opts=0, params=b''):
    return struct.pack('<H', len(name)) + u16(name) + struct.pack('<H', opts) + params


def rpc_id(pid, opts=0, params=b''):
    return struct.pack('<HHH', 0xffff, pid, opts) + params


RPC_PARAMS = [
    ('@i1', t_fixed(0x30), b'\x05'), ('@bit', t_fixed(0x32), b'\x01'),
    ('@i2', t_fixed(0x34), struct.pack('<h', 300)), ('@i4', t_fixed(0x38), struct.pack('<i', 70000)),
    ('@i8', t_fixed(0x7f), struct.pack('<q', 1 << 40)), ('@r', t_fixed(0x3b), struct.pack('<f', 2.0)),
    ('@f', t_fixed(0x3e), struct.pack('<d', 6.5)), ('@mn', t_fixed(0x3c), struct.pack('<II', 0, 20000)),
    ('@m4', t_fixed(0x7a), struct.pack('<I', 10000)), ('@dt', t_fixed(0x3d), DT8), ('@d4', t_fixed(0x3a), DT4),
    ('@in', t_bl(0x26, 4), bl(struct.pack('<i', 5))), ('@inull', t_bl(0x26, 8), b'\x00'),
    ('@bn', t_bl(0x68, 1), bl(b'\x01')), ('@fn', t_bl(0x6d, 8), bl(struct.pack('<d', 1.0))),
    ('@mon', t_bl(0x6e, 8), bl(struct.pack('<II', 0, 100))), ('@dtn', t_bl(0x6f, 8), bl(DT8)),
    ('@g', t_bl(0x24, 16), bl(bytes(range(16)))),
    ('@dec', t_num(0x6a, 9, 18, 2), bl(b'\x01' + struct.pack('<Q', 12345))),
    ('@numf', t_num(0x6c, 5, 9, 3), bl(b'\x00' + struct.pack('<I', 99))),
    ('@dn', t_fixed(0x28), bl(struct.pack('<I', 738000)[:3])),
    ('@tn', t_scale(0x29, 3), bl(struct.pack('<I', 3600000))),
    ('@d2', t_scale(0x2a, 3), bl(struct.pack('<I', 36000000) + struct.pack('<I', 738000)[:3])),
    ('@dto', t_scale(0x2b, 3), bl(struct.pack('<I', 36000000) + struct.pack('<I', 738000)[:3] + struct.pack('<h', 60))),
    ('@bvc', t_largec(0xa7, 50), us(b'varchar')), ('@bvb', t_large(0xa5, 50), us(b'\x01\x02')),
    ('@bb', t_large(0xad, 8), us(b'\x01' * 8)), ('@bc', t_largec(0xaf, 8), us(b'char    ')),
    ('@nv', t_largec(0xe7, 100), us(u16('nvarchar'))), ('@nc', t_largec(0xef, 10), us(u16('nchar'))),
    ('@nvnull', t_largec(0xe7, 100), struct.pack('<H', 0xffff)),
    ('@vcm', t_largec(0xa7, 0xffff), plp([b'varchar', b'(max)'])),
    ('@nvm', t_largec(0xe7, 0xffff), plp([u16('nvarchar'), u16('(max)')], 'unk')),
    ('@vbm', t_large(0xa5, 0xffff), plp([], 'null')),
    ('@vbe', t_large(0xa5, 0xffff), plp([], 0)),
    ('@ch', t_bl(0x2f, 10), bl(u16('ab'))), ('@vch', t_bl(0x27, 10), bl(u16('cd'))),
    ('@bin', t_bl(0x2d, 8), bl(b'\x01\x02')), ('@vbin', t_bl(0x25, 8), bl(b'\x03')),
    ('@txt', bytes([0x23]) + struct.pack('<I', 100) + COLL, struct.pack('<I', 4) + b'text'),
    ('@ntx', bytes([0x63]) + struct.pack('<I', 100) + COLL, struct.pack('<I', 4) + u16('nt')),
    ('@img', bytes([0x22]) + struct.pack('<I', 100), struct.pack('<I', 3) + b'img'),
    ('@imgnull', bytes([0x22]) + struct.pack('<I', 100), struct.pack('<I', 0xffffffff)),
    ('@ssv', bytes([0x62]) + struct.pack('<I', 8009), struct.pack('<I', 2) + b'\x38\x00'),
]


def rpc_all_params():
    out = b''
    for i, (n, ti, v) in enumerate(RPC_PARAMS):
        out += rpc_param(n, ti, v, status=[0, 1, 2, 3][i % 4])
    return out


# --------------------------------------------------------------------------
# Sybase / TDS 4.2 / 5.0 messages
# --------------------------------------------------------------------------

def padname(s, n):
    return s.encode('ascii').ljust(n, b'\0')[:n] + bytes([len(s)])


def login45(ver, int2=2, int4=0, ch=6, d8=9, d4=17, host='sybclient', user='sa', pw='secret',
            progname='ctlib', caps=None, rempw=((b'SRV', b'pw'),), bad_len=False):
    b = padname(host, 30) + padname(user, 30) + padname(pw, 30) + padname('1234', 30)
    b += bytes([int2, int4, ch, 10, d8, 1, 0, 0x81, 1]) + struct.pack('>I', 512) + b'\0\0\0'
    b += padname('isql', 30) + padname('SYBSRV', 30)
    rp = b''
    for s, p in rempw:
        rp += bytes([len(s) & 0xff]) + s + bytes([len(p) & 0xff]) + p
    rp = rp[:255]
    b += rp.ljust(255, b'\0') + bytes([len(rp)])
    b += struct.pack('>I', ver)
    b += padname(progname, 10) + struct.pack('>I', 0x0f000000)
    b += bytes([0, 1, d4])
    b += padname('us_english', 30) + b'\x01' + b'\0\0' + b'\x01\x00\x01' + b'\1\2\3\4\5\6' + b'\0\0'
    b += padname('iso_1', 30) + b'\x01' + padname('512', 6) + b'\0\0\0\0'
    if bad_len:
        b = b[:30] + bytes([200]) + b[31:]
    if caps:
        b += caps
    return b


def capability(req=bytes([0xff] * 11), resp=bytes([0x0f] * 9), f=Fmt(False, 'ascii'), extra=b'', pad=b''):
    body = bytes([1, len(req)]) + req + bytes([2, len(resp)]) + resp + extra + pad
    return b'\xe2' + f.p2(len(body)) + body


def lang(text, status=0, f=Fmt(False, 'ascii')):
    return b'\x21' + f.p4(1 + len(text)) + bytes([status]) + text.encode('ascii')


def dbrpc(name, opts=2, f=Fmt(False, 'ascii')):
    body = bytes([len(name)]) + name.encode('ascii') + f.p2(opts)
    return b'\xe6' + f.p2(len(body)) + body


def fmt_col(name, ctype, f, csize=None, status=0, utype=0, loc=b'', two=False):
    b = bytes([len(name)]) + name.encode('ascii')
    b += (f.p4(status) if two else bytes([status])) + f.p4(utype) + bytes([ctype])
    if csize is not None:
        b += (f.p4(csize) if ctype in (0xaf, 0xe1) else bytes([csize]))
    b += bytes([len(loc)]) + loc
    return b


def paramfmt(cols, f, two=False):
    body = f.p2(len(cols)) + b''.join(cols)
    if two:
        return b'\x20' + f.p4(len(body)) + body
    return b'\xec' + f.p2(len(body)) + body


def curdeclare(name, stmt, f, opts=0x01, ncols=0, colname=''):
    body = bytes([len(name)]) + name.encode() + bytes([opts, 0]) + f.p2(len(stmt)) + stmt.encode() + bytes([ncols])
    if ncols:
        body += bytes([len(colname)]) + colname.encode()
    return b'\x86' + f.p2(len(body)) + body


def curopen(cid, f, name='', status=0):
    body = f.p4(cid) + (bytes([len(name)]) + name.encode() if cid == 0 else b'') + bytes([status])
    return b'\x84' + f.p2(len(body)) + body


def curfetch(cid, f, ftype=1, rowcnt=0, name=''):
    body = f.p4(cid) + (bytes([len(name)]) + name.encode() if cid == 0 else b'') + bytes([ftype])
    if ftype >= 5:
        body += f.p4(rowcnt)
    return b'\x82' + f.p2(len(body)) + body


def curclose(cid, f, name='', dealloc=1):
    body = f.p4(cid) + (bytes([len(name)]) + name.encode() if cid == 0 else b'') + bytes([dealloc])
    return b'\x80' + f.p2(len(body)) + body


def curinfo(cid, cmd, status, f, name='', rowcnt=None):
    body = f.p4(cid) + (bytes([len(name)]) + name.encode() if cid == 0 else b'') + bytes([cmd]) + f.p2(status)
    if rowcnt is not None:
        body += f.p4(rowcnt)
    return b'\x83' + f.p2(len(body)) + body


def eed(f, num=208, state=1, cls=16, sqlstate=b'42S02', status=0, trans=0, msg='Msg text', srv='SYB', proc='proc1', line=7):
    body = f.p4(num) + bytes([state, cls]) + bl(sqlstate) + bytes([status]) + f.p2(trans) + f.luc2(msg)
    body += f.luc(srv) + f.luc(proc) + f.p2(line)
    return b'\xe5' + f.p2(len(body)) + body


def rowfmt(cols, f):
    body = f.p2(len(cols)) + b''.join(cols)
    return b'\xee' + f.p2(len(body)) + body


def rowfmt2(cols, f):
    body = f.p2(len(cols)) + b''.join(cols)
    return b'\x61' + f.p4(len(body)) + body


def rf_col(name, ctype, f, csize=None, prec=None, scale=None, status=0, loc=b'', tname=None):
    b = bytes([len(name)]) + name.encode() + bytes([status]) + f.p4(0) + bytes([ctype])
    if tname is not None:
        b += f.p4(csize or 0) + f.p2(len(tname)) + tname.encode()
    elif csize is not None:
        b += f.p4(csize) if ctype in (0xaf, 0xe1) else bytes([csize])
    if prec is not None:
        b += bytes([prec, scale])
    return b + bytes([len(loc)]) + loc


def rf2_col(label, cat, sch, tab, name, ctype, f, csize=None, prec=None, scale=None, loc=b'', tname=None):
    b = b''
    for s in (label, cat, sch, tab, name):
        b += bytes([len(s)]) + s.encode()
    b += f.p4(0) + f.p4(0) + bytes([ctype])
    if tname is not None:
        b += f.p4(csize or 0) + f.p2(len(tname)) + tname.encode()
    elif csize is not None:
        b += f.p4(csize) if ctype in (0xaf, 0xe1) else bytes([csize])
    if prec is not None:
        b += bytes([prec, scale])
    return b + bytes([len(loc)]) + loc


def sy_done(tok, status, f, rows=1):
    return bytes([tok]) + f.p2(status) + f.p2(0x00c1) + f.p4(rows)


def sy_msg(f, mid=5):
    return b'\x65' + bytes([4, 0]) + f.p2(mid)


def col_name_tok(names, f):
    body = b''.join(bytes([len(n)]) + n.encode() for n in names)
    return b'\xa0' + f.p2(len(body)) + body


def colfmt_tok(cols, f):
    body = b''
    for ctype, csize, tname in cols:
        body += f.p4(0x00000001) + bytes([ctype])
        if tname is not None:
            body += f.p4(csize) + f.p2(len(tname)) + tname.encode()
        elif csize is not None:
            body += bytes([csize])
    return b'\xa1' + f.p2(len(body)) + body


def control_tok(fmts, f):
    body = b''.join(bytes([len(s)]) + s.encode() for s in fmts)
    return b'\xae' + f.p2(len(body)) + body


# --------------------------------------------------------------------------
# the captures
# --------------------------------------------------------------------------

def build_main(cap):
    port = [49000]

    def conn(sport=1433):
        port[0] += 1
        return Conn(cap, port[0], sport)

    # ===================================================================
    cap.section('TDS 7.4 session: prelogin, login (NTLM), SQL batches')
    c = conn()
    c.c(nl(Q_PRELOGIN, prelogin(PL_ALL)))
    c.s(nl(Q_RESP, prelogin([pl_version(0x10000000, 1000), (1, b'\x00'), (2, b'\x00'), (3, b''), (4, b'\x00')])))
    # a TLS ClientHello carried in a prelogin packet (the handshake of an encrypted login)
    hello = (b'\x03\x03' + bytes(range(32)) + b'\x00' + struct.pack('>H', 4) + b'\xc0\x2f\x00\x9c' + b'\x01\x00')
    hs = b'\x01' + struct.pack('>I', len(hello))[1:] + hello
    c.c(nl(Q_PRELOGIN, b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs))
    # the same handshake record split over two Netlib buffers: reassembled before TLS sees it
    hello2 = (b'\x03\x03' + bytes(range(32, 64)) + b'\x00' + struct.pack('>H', 6) + b'\x13\x01\xc0\x2f\x00\x9c' + b'\x01\x00' +
              struct.pack('>H', 8) + struct.pack('>HH', 0x000d, 4) + struct.pack('>HBB', 2, 4, 1))
    hs2 = b'\x01' + struct.pack('>I', len(hello2))[1:] + hello2
    rec2 = b'\x16\x03\x03' + struct.pack('>H', len(hs2)) + hs2
    c.c(nl(Q_PRELOGIN, rec2[:40], status=0, pn=1))
    c.c(nl(Q_PRELOGIN, rec2[40:], status=1, pn=2))
    # TDS 8 style records: TLS application data carried directly
    c.s(b'\x17\x03\x03' + struct.pack('>H', 20) + bytes(range(20)))
    c.c(b'\x17\x03\x03' + struct.pack('>H', 12) + bytes(range(12)))
    c.c(nl(Q_PRELOGIN, prelogin([pl_version(0x0e000000, 1), (1, b'\x00')])))
    c.c(nl(Q_LOGIN7, login7(0x74000004, pw='caf\u00e9', sspi=NTLM_NEG)))
    c.s(nl(Q_RESP, b'\xed' + struct.pack('<H', len(NTLM_CHAL)) + NTLM_CHAL))
    c.c(nl(Q_SSPI, NTLM_AUTH))
    c.s(nl(Q_RESP, b'\xed' + struct.pack('<H', 0)))
    # NTLM carried in a second login, SPNEGO and GSS-API in the SSPI token
    c.c(nl(Q_SSPI, SPNEGO_RESP))
    c.s(nl(Q_RESP, b'\xed' + struct.pack('<H', len(SPNEGO_RESP)) + SPNEGO_RESP))
    envs = [
        envchg(1, b16('master'), b16('tempdb')),
        envchg(2, b16('us_english'), b16('german')),
        envchg(3, b16('iso_1'), b16('cp850')),
        envchg(4, b16('4096'), b16('8192')),
        envchg(5, b16('1033'), b'\x00'),
        envchg(6, b16('196609'), b'\x00'),
        envchg(7, bytes([5]) + COLL, bytes([5]) + COLL),
        envchg(7, bytes([5]) + COLL, b'\x00'),
        envchg(8, bl(b'\x00\x00\x00\x00\x00\x00\x00\x01'), b'\x00'),
        envchg(9, b'\x00', bl(b'\x00\x00\x00\x00\x00\x00\x00\x01')),
        envchg(10, b'\x00', bl(b'\x00\x00\x00\x00\x00\x00\x00\x02')),
        envchg(11, b'\x00', bl(b'\x01\x02\x03')),
        envchg(12, bl(b'\x05\x06'), b'\x00'),
        envchg(13, b16('mirror'), b'\x00'),
        envchg(15, b'', b'\x00'),
        envchg(16, bl(b'\x07\x08\x09'), b'\x00'),
        envchg(17, b'\x00', bl(b'\x00\x00\x00\x00\x00\x00\x00\x03')),
        envchg(18, b'\x00', b'\x00'),
        envchg(19, b16('instance1'), b'\x00'),
        envchg(20),
        envchg(14),
    ]
    c.s(nl(Q_RESP, b''.join(envs)))
    feat = (bytes([0x01]) + struct.pack('<I', 3) + b'\x01\x02\x03' + bytes([0x09]) + struct.pack('<I', 0) +
            bytes([0xff]))
    sess = struct.pack('<I', 0) + b''
    st1 = bytes([1, 3]) + b'abc'
    st2 = bytes([2, 0xff, 5, 0]) + b'\x00\x05xyz'
    body = struct.pack('<IB', 9, 0) + st1  # seqno(4) + status(1) + state
    sess_tok = b'\xe4' + struct.pack('<I', 4 + 1 + len(st1) + 0) + struct.pack('<I', 7) + b'\x01' + st1
    sess_tok2 = b'\xe4' + struct.pack('<I', 4 + 1 + len(st2)) + struct.pack('<I', 8) + b'\x00' + st2
    c.s(nl(Q_RESP, msgtoken(0xab, 5701, 2, 0, "Changed database context to 'master'.", 'SQLHOST', '', 1) +
           msgtoken(0xab, 5703, 1, 0, 'Changed language setting.', 'SQLHOST', 'proc', 3) +
           loginack(0x74000004) + b'\xae' + feat + sess_tok + sess_tok2 +
           done(0xfd, 0, 0, 0)))
    c.c(nl(Q_BATCH, allhdr() + u16('select @@version')))
    c.s(nl(Q_RESP, result(rs_fixed())))
    c.c(nl(Q_BATCH, allhdr('notif') + u16('select 1')))
    c.c(nl(Q_BATCH, allhdr('both') + u16('select 2')))
    c.c(nl(Q_BATCH, u16('select 4 -- no ALL_HEADERS')))
    c.s(nl(Q_RESP, result(rs_bytelen(), rows=5)))

    cap.section('TDS 7.4: result sets, tokens')
    c.c(nl(Q_BATCH, allhdr() + u16('select * from dectypes')))
    c.s(nl(Q_RESP, result(rs_dec_char(), rows=4)))
    c.s(nl(Q_RESP, result(rs_dates(), rows=3)))
    c.s(nl(Q_RESP, result(rs_large(), rows=3)))
    c.s(nl(Q_RESP, result(rs_plp(), rows=7)))
    c.s(nl(Q_RESP, result(rs_xml_schema(), rows=1)))
    c.s(nl(Q_RESP, result(rs_text(), rows=2)))
    # tokens: ORDER, OFFSET, RETURNSTATUS, DONEPROC, DONEINPROC, ERROR
    toks = (b'\xa9' + struct.pack('<H', 4) + struct.pack('<HH', 1, 2) +
            b'\x78' + struct.pack('<HH', 3, 4) +
            msgtoken(0xaa, 208, 1, 16, 'Invalid object name', 'SQLHOST', 'proc1', 3) +
            done(0xff, 0x0001, 0xc1, 3) + returnstatus(-6) +
            done(0xfe, 0x0100, 0xc2, 1) + done(0xfd, 0x0002, 0xc3, 0) + done(0xfd, 0x0020, 0xc3, 0) +
            done(0xfd, 0xffff & 0x0e1f, 0xc3, 1 << 33) + b'\xa4')
    c.s(nl(Q_RESP, toks))
    c.c(nl(Q_ATTN, b'', status=1))
    c.s(nl(Q_RESP, done(0xfd, 0x0020, 0, 0), status=3))
    c.c(nl(Q_TRANSMGR, allhdr() + struct.pack('<H', 5) + b'\x00\x01'))
    c.c(nl(Q_TRANSMGR, allhdr() + struct.pack('<H', 6)))
    c.c(nl(Q_BULK, b'\x81\x01\x00' + bytes(10)))
    c.c(nl(Q_RAW, b'raw'))

    cap.section('TDS 7.4: RPC')
    c.c(nl(Q_RPC, allhdr() + rpc_named('sp_executesql', 0x0003, rpc_all_params()[:0]) +
           rpc_param('@stmt', t_largec(0xe7, 4000), us(u16('select @a')), 0) +
           rpc_param('', t_fixed(0x38), struct.pack('<i', 1), 0) + b'\x80' +
           rpc_id(10, 0x0004, rpc_param('@p', t_fixed(0x38), struct.pack('<i', 2))) + b'\xff' +
           rpc_id(11)))
    c.c(nl(Q_RPC, allhdr() + rpc_named('allparams', 0, rpc_all_params())))
    c.s(nl(Q_RESP, returnstatus(0) + done(0xfe, 0x0000, 0xc1, 0)))
    c.c(nl(Q_RPC, rpc_named('noheaders', 0, rpc_param('@x', t_fixed(0x38), struct.pack('<i', 9)))))
    c.c(nl(Q_RPC, allhdr()))

    cap.section('TDS 7.4: multi-buffer messages and TCP segmentation')
    q = u16('select 1 -- ' + 'x' * 40)
    c.c(nl(Q_BATCH, allhdr() + q[:30], status=0, pn=1))
    c.c(nl(Q_BATCH, q[30:60], status=0, pn=2))
    c.c(nl(Q_BATCH, q[60:], status=1, pn=3))
    r = result(rs_fixed())
    c.s(nl(Q_RESP, r[:40], status=0, pn=1))
    c.s(nl(Q_RESP, r[40:], status=1, pn=2))
    big = nl(Q_BATCH, allhdr() + u16('select ' + 'y' * 300))
    c.csplit(big, 5, 60, 200)
    two = nl(Q_BATCH, allhdr() + u16('select 11')) + nl(Q_BATCH, allhdr() + u16('select 12'))
    c.c(two)
    # a PDU whose first buffer is cut after the netlib header
    c.csplit(nl(Q_BATCH, allhdr() + u16('select 13')), 8, 20)
    c.c(nl(Q_BATCH, allhdr() + u16('select 14'), status=0x41))
    c.c(nl(Q_BATCH, allhdr() + u16('select 15'), status=0x40))   # invalid status: shown as data
    c.c(nl(19, b'abc'))
    c.c(nl(Q_BATCH, b'x', status=0x00, pn=0, ch=7))

    cap.section('TDS 7.1 (16 bit user types, 32 bit row counts)')
    c = conn()
    c.c(nl(Q_PRELOGIN, prelogin([pl_version(0x08000000), (1, b'\x02')])))
    c.s(nl(Q_RESP, prelogin([pl_version(0x080000c2), (1, b'\x02')])))
    c.c(nl(Q_LOGIN7, login7(0x71000001, pw='x')))
    c.s(nl(Q_RESP, loginack(0x71000001, 'Microsoft SQL Server', 0x080000c2)))
    c.c(nl(Q_BATCH, allhdr('none') + u16('select a from t')))
    f71 = F7
    c.s(nl(Q_RESP, msgtoken(0xaa, 102, 1, 15, 'Incorrect syntax', 'S', 'p', 1, wide=False) +
           msgtoken(0xab, 103, 1, 0, 'info', 'S', '', 1, wide=False) +
           result(rs_text(newfmt=False), rows=2, wide=False) +
           done(0xfe, 0, 0, 1, wide=False) + done(0xff, 0, 0, 1, wide=False) + returnstatus(0)))

    for ver, lv, pre, name in ((0x72090002, 0x09000577, 0x09000000, '7.2'),
                               (0x730a0003, 0x0a000640, 0x0a000000, '7.3A'),
                               (0x730b0003, 0x0a320640, 0x0a320000, '7.3B')):
        cap.section('TDS %s' % name)
        c = conn()
        c.c(nl(Q_PRELOGIN, prelogin([pl_version(pre), (1, b'\x00')])))
        c.s(nl(Q_RESP, prelogin([pl_version(lv), (1, b'\x00')])))
        c.c(nl(Q_LOGIN7, login7(ver, sspi=b'\x60\x03\x06\x01\x2a' if name == '7.3B' else b'')))
        c.s(nl(Q_RESP, loginack(ver, 'Microsoft SQL Server', lv)))
        c.s(nl(Q_RESP, result(rs_fixed()) + result(rs_text(), rows=2)))
        c.c(nl(Q_BATCH, allhdr() + u16('select 1')))

    cap.section('TDS 7.0 and prelogin-less 7.4 logins')
    c = conn()
    c.c(nl(Q_PRELOGIN, prelogin([pl_version(0x0700026f), (1, b'\x00')])))
    c.s(nl(Q_RESP, prelogin([pl_version(0x0700026f), (1, b'\x00')])))
    c = conn()
    c.c(nl(Q_LOGIN7, login7(0x07000000)))
    c.s(nl(Q_RESP, loginack(0x07000000, 'Microsoft SQL Server', 0x07000000)))
    c.s(nl(Q_RESP, msgtoken(0xab, 5701, 2, 0, 'Changed database context', 'S', '', 1, wide=False) +
           b'\xa9' + struct.pack('<H', 2) + bytes([1, 2]) +
           envchg(1, b16('db'), b16('old')) + returnstatus(3) +
           done(0xfd, 0, 0, 5, wide=False) + b'\x7c' + bytes(range(8))))
    c.c(nl(Q_BATCH, allhdr('none') + u16('select 70')))
    c = conn()
    c.c(nl(Q_LOGIN7, login7(0x70000000, empty_fields=True)))     # not a table value: default case
    c.s(nl(Q_RESP, loginack(0x70000000)))
    c = conn()
    c.c(nl(Q_LOGIN7, login7(0x07010000)))
    c.s(nl(Q_RESP, loginack(0x07010000)))
    c.c(nl(Q_PRELOGIN, prelogin([(2, b'inst\0'), (1, b'\x03')])))
    c.s(nl(Q_RESP, prelogin([(1, b'\x03')])))
    c = conn()
    c.c(nl(Q_PRELOGIN, prelogin([pl_version(0x05000000)])))
    c.s(nl(Q_RESP, prelogin([pl_version(0x05000000)])))
    c.c(nl(Q_LOGIN7, login7(0x1234)))
    c.s(nl(Q_RESP, loginack(0x1234)))

    # ===================================================================
    cap.section('Sybase TDS 5.0, big endian')
    f5 = Fmt(False, 'ascii')
    c = conn()
    cap5 = capability(f=f5, extra=bytes([3, 1, 0, 1, 12]) + bytes(range(12)))
    c.c(nl(Q_LOGIN, login45(0x05000000, caps=cap5)))
    c.s(nl(Q_RESP, loginack_sybase(f5) + envchg(1, bl(b'newdb'), bl(b'olddb'), f=f5) +
           sy_done(0xfd, 0, f5, 0)))
    c.c(nl(Q_TDS5, lang('select * from t', 0)))
    c.c(nl(Q_TDS5, lang('select @a', 1) + paramfmt([fmt_col('@a', 0x38, f5)], f5) + b'\xd7' + f5.p4(7)))
    c.c(nl(Q_TDS5, dbrpc('sp_help', 3) +
           paramfmt([fmt_col('@i', 0x38, f5), fmt_col('@s', 0xaf, f5, csize=40, loc=b'loc'),
                     fmt_col('@v', 0x27, f5, csize=10), fmt_col('@t', 0x3d, f5)], f5) +
           b'\xd7' + f5.p4(7) + f5.p4(5) + b'hello' + bytes([3]) + b'abc' + f5.p4(44000) + f5.p4(1200)))
    c.c(nl(Q_TDS5, dbrpc('sp_x', 1) +
           paramfmt([fmt_col('@a', 0x38, f5, two=True), fmt_col('@b', 0x26, f5, csize=4, two=True),
                     fmt_col('@c', 0xaf, f5, csize=40, two=True, loc=b'ab')], f5, two=True) +
           b'\xd7' + f5.p4(7) + bl(f5.p4(8)) + f5.p4(2) + b'hi'))
    # fixed size tokens in a request
    c.c(nl(Q_TDS5, b'\x79' + f5.p4(0) + b'\x7c' + bytes(8) + b'\xfd' + f5.p2(0) + f5.p2(0) + f5.p4(0) +
           b'\xfe' + f5.p2(0) + f5.p2(0) + f5.p4(0) + b'\xff' + f5.p2(0) + f5.p2(0) + f5.p4(0) +
           b'\x78' + f5.p4(0) + b'\x71\x00'))
    c.c(nl(Q_TDS5, b'\x71\x00'))
    c.c(nl(Q_TDS5, b'\x01' + f5.p2(3) + b'abc' + lang('x')))     # unknown token with a 2 byte length
    c.c(nl(Q_TDS5, b'\x65' + bytes([3, 0, 0, 5])))
    # a large tokenized request over two TCP segments
    c.csplit(nl(Q_TDS5, lang('select ' + 'z' * 100)), 30)

    cap.section('Sybase 5.0: cursors')
    # One cursor per connection, named in the tokens: the dissector keeps a single
    # cursor record per conversation, and a cursor id is only shown with the
    # cursor name on the second pass (see the README).
    rf2_ab = rowfmt2([rf2_col('', '', '', 'tab', 'a', 0x38, f5), rf2_col('lbl', '', '', '', 'b', 0x27, f5, csize=20)], f5)
    rf_ab = rowfmt([rf_col('a', 0x38, f5), rf_col('b', 0x27, f5, csize=20)], f5)

    def row_ab(a, b):
        return b'\xd1' + f5.p4(a) + bl(b)

    # the other tokens of the request that declares the cursor name it
    c.c(nl(Q_TDS5, curdeclare('cur1', 'select a, b from t', f5, 0x1f, 1, 'b') + curopen(0, f5, name='other1') +
           curopen(5, f5) + curfetch(0, f5, 1, name='cur1') + curinfo(0, 4, 0, f5, name='cur1') +
           curclose(0, f5, name='cur1')))
    c.s(nl(Q_RESP, curinfo(0, 3, 0x0047, f5, name='cur1') + rf2_ab + sy_done(0xfd, 0x10, f5, 0)))
    c.c(nl(Q_TDS5, curopen(0, f5, name='cur1', status=1)))
    c.c(nl(Q_TDS5, curfetch(0, f5, 1, name='cur1')))
    c.c(nl(Q_TDS5, curfetch(0, f5, 5, 3, name='cur1')))
    c.c(nl(Q_TDS5, curfetch(0, f5, 6, 2, name='cur1')))
    c.s(nl(Q_RESP, row_ab(2, b'zz') + row_ab(3, b'') + sy_done(0xfd, 0x10, f5, 2)))
    c.c(nl(Q_TDS5, curinfo(0, 4, 0, f5, name='cur1')))
    c.s(nl(Q_RESP, curinfo(0, 3, 0x0400, f5, name='cur1') + sy_done(0xfd, 0, f5, 0)))
    c.c(nl(Q_TDS5, curclose(0, f5, name='cur1', dealloc=1)))
    c.c(nl(Q_TDS5, curclose(0, f5, name='cur1', dealloc=0)))
    # a cursor whose row format arrives as ROWFMT
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x05000000, caps=capability(f=f5))))
    c.s(nl(Q_RESP, loginack_sybase(f5)))
    c.c(nl(Q_TDS5, curdeclare('cur2', 'select 2', f5)))
    c.s(nl(Q_RESP, curinfo(0, 3, 0x0003, f5, name='cur2') + rf_ab + sy_done(0xfd, 0x10, f5, 0)))
    c.c(nl(Q_TDS5, curfetch(0, f5, 1, name='cur2')))
    c.s(nl(Q_RESP, row_ab(4, b'q') + sy_done(0xfd, 0x10, f5, 1)))
    c.c(nl(Q_TDS5, curfetch(0, f5, 4, name='cur2')))
    c.s(nl(Q_RESP, rf_ab + row_ab(5, b'r') + sy_done(0xfd, 0x10, f5, 1)))

    cap.section('Sybase 5.0: result sets, row formats, parameters')
    # a new connection: after a cursor every ROW token uses the row format of the current cursor
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x05000000, caps=capability(f=f5, resp=bytes(range(9))))))
    c.s(nl(Q_RESP, loginack_sybase(f5)))
    sg = f5
    nul = b'\x00'
    spec = [
        # name, ctype, rowfmt keywords, row 1, row 2
        ('i1', 0x30, {}, b'\x07', b'\xff'),
        ('i2', 0x34, {}, sg.p2(300), sg.p2(1)),
        ('i4', 0x38, {}, sg.p4(70000), sg.p4(2)),
        ('i8', 0x7f, {}, struct.pack('<q', 99), struct.pack('<q', -1)),
        ('rl', 0x3b, {}, struct.pack('<f', 1.5), struct.pack('<f', -1.5)),
        ('f8', 0x3e, {}, struct.pack('<d', 2.5), struct.pack('<d', 0.0)),
        ('bit', 0x32, {}, b'\x01', b'\x00'),
        ('dt', 0x3d, {}, sg.p4(44000) + sg.p4(1200), sg.p4(0) + sg.p4(0)),
        ('dt4', 0x3a, {}, sg.p2(43000) + sg.p2(600), sg.p2(0) + sg.p2(0)),
        ('mny', 0x3c, {}, sg.p4(0) + sg.p4(5000), sg.p4(0) + sg.p4(0)),
        ('mny4', 0x7a, {}, sg.p4(10000), sg.p4(0)),
        ('guid', 0x24, dict(csize=16), bl(bytes(range(16))), nul),
        ('intn', 0x26, dict(csize=4), bl(sg.p4(5)), nul),
        ('fltn', 0x6d, dict(csize=8), bl(struct.pack('<d', 1.0)), nul),
        ('mnyn', 0x6e, dict(csize=8), bl(sg.p4(0) + sg.p4(100)), nul),
        ('dtn', 0x6f, dict(csize=8), bl(sg.p4(44000) + sg.p4(100)), nul),
        ('bitn', 0x68, dict(csize=1), bl(b'\x01'), nul),
        ('chr', 0x2f, dict(csize=20), bl(b'char text'), bl(b'')),
        ('vch', 0x27, dict(csize=10), bl(b'vc'), bl(b'')),
        ('bin', 0x2d, dict(csize=8), bl(b'\x01\x02'), bl(b'')),
        ('vbin', 0x25, dict(csize=8), bl(b'\x03'), bl(b'')),
        ('num', 0x3f, dict(csize=7, prec=12, scale=2), bl(b'\x01' + bytes([0, 0, 0x01, 0xe2, 0x40])), nul),
        ('dec', 0x37, dict(csize=5, prec=5, scale=0), bl(b'\x00' + sg.p4(123)), bl(b'\x01' + sg.p4(0))),
        ('lchr', 0xaf, dict(csize=500), sg.p4(4) + b'long', sg.p4(0)),
        ('lbin', 0xe1, dict(csize=500, status=1), sg.p4(3) + b'\x01\x02\x03', sg.p4(0)),
        ('txt', 0x23, dict(csize=100000, tname='db..t'), nul, textval_be(sg, b'text')),
        ('img', 0x22, dict(csize=100000, tname='db..i', loc=b'x'), textval_be(sg, b'\x01\x02', ptr=b'p'), nul),
    ]
    cols = [rf_col(n, t, sg, **kw) for n, t, kw, r1, r2 in spec]
    rows = [b'\xd1' + b''.join(s[3] for s in spec), b'\xd1' + b''.join(s[4] for s in spec)]
    c.s(nl(Q_RESP, rowfmt(cols, sg) + rows[0] + rows[1] +
           b'\xa9' + sg.p2(2) + bytes([1, 2]) + sy_done(0xff, 0x11, sg, 2) + b'\x79' + sg.p4(0) +
           sy_done(0xfe, 0, sg, 0) + b'\x7c' + bytes(range(8)) + sy_msg(sg) +
           eed(sg) + eed(sg, msg='another message', srv='', proc='')))
    c.s(nl(Q_RESP, msgtoken(0xaa, 2601, 1, 14, 'Duplicate key', 'SYB', 'p', 3, f=sg, wide=False) +
           msgtoken(0xab, 5701, 1, 10, 'Changed db', 'SYB', '', 1, f=sg, wide=False) +
           sy_done(0xfd, 0x0102, sg, 0)))
    spec2 = [
        (('lbl', 'cat', 'sch', 'tab', 'a'), 0x38, {}, sg.p4(5), sg.p4(6)),
        (('', '', 'sch', 'tab', 'b'), 0x27, dict(csize=10), bl(b'abc'), bl(b'')),
        (('', '', '', 'tab', 'c'), 0x3f, dict(csize=7, prec=10, scale=3), bl(b'\x01' + bytes([0, 0, 0, 0x30, 0x39])), nul),
        (('', '', '', '', 'd'), 0xaf, dict(csize=100), sg.p4(2) + b'xy', sg.p4(0)),
        (('only', '', '', '', ''), 0x23, dict(csize=1000, tname='tt'), nul, nul),
        (('', '', '', '', 'e'), 0x2f, dict(csize=5, loc=b'loc'), bl(b'abcde'), bl(b'')),
    ]
    c.s(nl(Q_RESP, rowfmt2([rf2_col(*n, t, sg, **kw) for n, t, kw, r1, r2 in spec2], sg) +
           b'\xd1' + b''.join(s[3] for s in spec2) + b'\xd1' + b''.join(s[4] for s in spec2) +
           sy_done(0xfd, 0, sg, 2)))
    c.s(nl(Q_RESP, paramfmt([fmt_col('@ret', 0x38, sg), fmt_col('@name', 0x27, sg, csize=20, loc=b'l')], sg) +
           b'\xd7' + sg.p4(8) + bl(b'out') +
           paramfmt([fmt_col('@r', 0x38, sg, two=True)], sg, two=True) + b'\xd7' + sg.p4(9) +
           b'\x79' + sg.p4(0) + sy_done(0xfe, 0, sg, 0)))
    c.s(nl(Q_RESP, msgtoken(0xaa, 1, 1, 1, 'e', 's', 'p', 1, f=sg, wide=False)))
    c.s(nl(Q_RESP, envchg(1, bl(b'newdb'), bl(b'olddb'), f=sg) + envchg(3, bl(b'iso_1'), bl(b'x'), f=sg) +
           envchg(4, bl(b'512'), bl(b'256'), f=sg)))
    c.s(nl(Q_RESP, sy_done(0xfd, 0x0001, sg, 3)))
    c.s(nl(Q_RESP, sy_done(0xfd, 0x0001, sg, 3), status=0, pn=0, ch=0))
    c.s(nl(Q_RESP, sy_done(0xfd, 0x0000, sg, 4), status=1, pn=0, ch=0))

    c.s(nl(Q_RESP, rowfmt([rf_col('', 0x38, sg), rf_col('', 0x27, sg, csize=5)], sg) +
           b'\xd1' + sg.p4(1) + bl(b'ab') + sy_done(0xfd, 0, sg, 1)))
    # a connection that starts with a cursor description: no cursor table yet,
    # and date encodings that are neither time first nor date first
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x05000000, d8=0, d4=0)))
    c.s(nl(Q_RESP, loginack_sybase(f5)))
    c.s(nl(Q_RESP, curinfo(7, 3, 0x0003, f5) + rowfmt([rf_col('d8', 0x3d, sg), rf_col('d4', 0x3a, sg)], sg) +
           b'\xd1' + sg.p4(44000) + sg.p4(1200) + sg.p2(43000) + sg.p2(600) + sy_done(0xfd, 0, sg, 1)))
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x05000000, ch=0)))
    c.s(nl(Q_RESP, loginack_sybase(f5)))
    c.s(nl(Q_RESP, msgtoken(0xab, 7, 1, 1, 'unknown char encoding', 'SRV', 'proc', 1, f=sg, wide=False) +
           rowfmt([rf_col('c', 0x2f, sg, csize=4)], sg) + b'\xd1' + bl(b'abcd') + sy_done(0xfd, 0, sg, 1)))

    # ===================================================================
    cap.section('Sybase 5.0, little endian, time-first dates')
    fl = Fmt(True, 'ascii')
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x05000000, int2=3, int4=1, ch=6, d8=8, d4=16, pw='', caps=capability(f=fl), rempw=())))
    c.s(nl(Q_RESP, loginack_sybase(fl, ver=0x05000000)))
    c.c(nl(Q_TDS5, lang('select dt', 1, f=fl)))
    c.s(nl(Q_RESP, rowfmt([rf_col('dt', 0x3d, fl), rf_col('d4', 0x3a, fl), rf_col('s', 0x2f, fl, csize=5),
                           rf_col('n', 0x3f, fl, csize=5, prec=7, scale=3)], fl) +
           b'\xd1' + fl.p4(1200) + fl.p4(44000) + fl.p2(600) + fl.p2(43000) + bl(b'abc') +
           bl(b'\x01' + b'\x00\x00\x30\x39') +
           sy_done(0xfd, 0, fl, 1)))
    c.s(nl(Q_RESP, rowfmt([rf_col('i', 0x38, fl)], fl) + b'\xd1' + fl.p4(77) + sy_done(0xfd, 0, fl, 1)))

    cap.section('TDS 4.2 and TDS 4.6')
    f4 = Fmt(True, 'ascii')
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x04020000, int2=3, int4=1, ch=6, d8=9, d4=17)))
    c.s(nl(Q_RESP, loginack_sybase(f4, ver=0x04020000)))
    c.c(nl(Q_BATCH, b'select a, b from t'))
    c.s(nl(Q_RESP, col_name_tok(['a', 'b', '', 'img', 'dec'], f4) +
           colfmt_tok([(0x38, None, None), (0x27, 20, None), (0x6a, 5, None), (0x22, 1000, 'dbo.t'), (0x6c, 5, None)], f4) +
           b'\xd1' + f4.p4(1) + bl(b'abc') + bl(b'\x01' + f4.p4(5)) + b'\x00' +
           bl(b'\x01' + f4.p4(6)) +
           b'\xa9' + f4.p2(2) + bytes([1, 2]) + control_tok(['fmt1', 'f2'], f4) +
           sy_done(0xfd, 0x10, f4, 1) + sy_done(0xfe, 0, f4, 0)))
    c.s(nl(Q_RESP, msgtoken(0xab, 1, 1, 1, 'info 4.2', 'S', 'p', 1, f=f4, wide=False) +
           b'\x79' + f4.p4(0) + b'\x7c' + bytes(8)))
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x04060000, int2=3, int4=1, ch=6, d8=9, d4=17)))
    c.s(nl(Q_RESP, loginack_sybase(f4, ver=0x04060000)))

    cap.section('TDS 4.x with EBCDIC strings')
    fe = Fmt(False, 'ebcdic')
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x04020000, int2=2, int4=0, ch=7, d8=8, d4=16)))
    c.s(nl(Q_RESP, msgtoken(0xab, 7, 1, 1, 'ebcdic info', 'SRV', 'proc', 1, f=fe, wide=False)))
    c.s(nl(Q_RESP, colfmt_tok([(0x2f, 8, None)], fe) +
           b'\xd1' + bl('text'.encode('cp037')) + sy_done(0xfd, 0, fe, 1)))

    # ===================================================================
    cap.section('Heuristic detection on other ports')
    # only the first packet of a conversation is recognised: the heuristic
    # accepts LOGIN7 (7.0/8.0 versions), TDS4/5 login and a first Language token
    c = conn(sport=31433)
    c.c(nl(Q_LOGIN7, login7(0x70000000, srv='alt')))
    c.s(nl(Q_RESP, loginack(0x70000000)))
    c = conn(sport=31434)
    c.c(nl(Q_LOGIN, login45(0x05000000, caps=capability(f=f5))))
    c.s(nl(Q_RESP, loginack_sybase(f5)))
    c = conn(sport=31435)
    c.c(nl(Q_TDS5, lang('select first', f=Fmt(True, 'ascii'))))
    c.s(nl(Q_RESP, sy_done(0xfd, 0, f5, 0)))
    c = conn(sport=31436)
    c.c(nl(Q_LOGIN, login45(0x05000000, bad_len=True)))      # heuristic rejects: not TDS
    c.c(nl(Q_BATCH, u16('select 1')))
    c = conn(sport=2433)
    c.c(nl(Q_BATCH, allhdr() + u16('select 2433')))
    # first packets the heuristic rejects (they stay plain TCP payload)
    rejects = [
        nl(Q_LOGIN, login45(0x05000000)[:300]),             # shorter than a TDS4/5 login
        nl(Q_LOGIN, login45(0x06000000)),                   # major version 6
        nl(Q_LOGIN7, login7(0x74000004)),                   # LOGIN7 other than 7.0 and 8.0
        nl(Q_LOGIN7, b'\x01\x02\x03'),                       # short LOGIN7
        nl(Q_TDS5, b'\x65\x00\x00\x00\x00'),               # first token is not a language token
        nl(Q_TDS5, b''),                                    # tokenized request without a token
        nl(Q_BATCH, u16('x')),                              # another packet type on another port
        b'\x04\x01\x00\x04\x00\x00\x00\x00',                  # length less than the header
        nl(0x30, b'abc'),                                   # unknown packet type
        nl(Q_BATCH, b'abc', status=0x07),                   # invalid status
        b'\x01\x01\x00',                                    # shorter than the header
    ]
    for off in (30, 61, 92, 123):                           # name lengths longer than the fields
        bad = bytearray(login45(0x05000000))
        bad[off] = 99
        rejects.append(nl(Q_LOGIN, bytes(bad)))
    for i, pkt in enumerate(rejects):
        conn(sport=31440 + i).c(pkt)

    cap.section('In-order reassembly (reproducer of the two pass bug)')
    c = conn()
    qq = 'select 1'.encode('utf-16-le')
    c.c(nl(1, qq, status=0x01, pn=1))   # single buffer query, dissected directly
    c.c(nl(1, qq, status=0x00, pn=0))   # first fragment of an in-order message
    c.c(nl(1, qq, status=0x01, pn=0))   # last fragment
    c.c(nl(1, qq, status=0x01, pn=1))   # single buffer after the flag is set

    cap.section('Session Multiplex Protocol carrying TDS')
    c = conn()

    def smp(flags, sid, seq, wnd, payload=b''):
        return b'\x53' + bytes([flags]) + struct.pack('<HIII', sid, 16 + len(payload), seq, wnd) + payload

    c.c(smp(0x01, 0, 0, 4))
    c.s(smp(0x02, 0, 0, 4))
    c.c(smp(0x08, 0, 1, 4, nl(Q_BATCH, allhdr() + u16('select smp'))))
    c.s(smp(0x08, 0, 1, 4, nl(Q_RESP, result(rs_fixed()))))
    c.c(smp(0x04, 0, 2, 4))

    # Sybase conversation with a TLS handshake record in a TDS packet
    cap.section('TDS 7.4 over TLS records')
    c = conn()
    c.c(nl(Q_PRELOGIN, prelogin([pl_version(0x0f000000), (1, b'\x01')])))
    c.s(nl(Q_RESP, prelogin([pl_version(0x0f000000), (1, b'\x01')])))
    c.c(nl(Q_PRELOGIN, b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs))
    c.s(nl(Q_RESP, b'\x16\x03\x03\x00\x04\x02\x00\x00\x00'))
    c.s(b'\x17\x03\x03' + struct.pack('>H', 30) + bytes(30))
    return cap


def loginack_sybase(f, ver=0x05000000, prog='SYBSRV', pv=0x0f000000):
    body = bytes([5]) + struct.pack('>I', ver) + bytes([len(prog)]) + prog.encode() + struct.pack('>I', pv)
    return b'\xad' + f.p2(len(body)) + body


def build_malformed(cap):
    port = [48000]

    def conn(sport=1433):
        port[0] += 1
        return Conn(cap, port[0], sport)

    cap.section('Messages before the login: their decoding depends on the pass')
    c = conn()
    c.c(nl(Q_BATCH, u16('select 5 from noconv')))
    c.s(nl(Q_RESP, result(rs_fixed())))
    c.c(nl(Q_LOGIN7, login7(0x07010000)))
    c.s(nl(Q_RESP, loginack(0x07010000)))

    cap.section('ALL_HEADERS errors')
    c = conn()
    # reproducer of the endless loop: header length 0xfffffff8 wraps the offset
    wrap = struct.pack('<I', 0x1c) + struct.pack('<IH', 0xfffffff8, 2) + b'\0' * 18
    c.c(nl(Q_BATCH, wrap + u16('select 1')))
    c.c(nl(Q_BATCH, struct.pack('<I', 2) + u16('select 2')))                 # total length < 4
    c.c(nl(Q_BATCH, struct.pack('<IIH', 10, 0, 2) + b'\0' * 6 + u16('x')))  # empty header
    bad18 = struct.pack('<I', 4 + 14) + struct.pack('<IH', 10, 2) + bytes(8)
    c.c(nl(Q_BATCH, bad18 + u16('x')))                                       # transaction header of 10
    c.c(nl(Q_BATCH, struct.pack('<I', 40) + struct.pack('<IH', 18, 2) + bytes(12) + u16('select 7')))
    c.c(nl(Q_BATCH, struct.pack('<I', 30) + struct.pack('<IH', 18, 2) + bytes(12) + bytes(2) + u16('select 7')))
    c.c(nl(Q_RPC, wrap + rpc_named('x')))
    c.c(nl(Q_TRANSMGR, wrap + b'\0\0'))
    c.c(nl(Q_TRANSMGR, struct.pack('<H', 7)))
    c.c(nl(Q_TRANSMGR, b''))
    c.c(nl(Q_BATCH, b''))
    c.c(nl(Q_BATCH, b'x'))
    c.c(nl(Q_BATCH, allhdr('unknown') + u16('select 3')))

    cap.section('TDS 7.4 column and value errors')
    c = conn()
    c.c(nl(Q_LOGIN7, login7(0x74000004)))
    c.s(nl(Q_RESP, loginack(0x74000004)))
    cols = [('g', t_bl(0x24, 16)), ('n', t_bl(0x26, 4)), ('b', t_bl(0x68, 1)), ('f', t_bl(0x6d, 8))]
    meta = colmeta(cols)
    c.s(nl(Q_RESP, meta + int_row(bl(b'\x01\x02'), bl(b'\x01\x02\x03'), bl(b'\x01\x02'), bl(b'\x01\x02\x03'))))
    c.s(nl(Q_RESP, colmeta([('t', t_scale(0x29, 7))]) + int_row(bl(bytes(8))) + done(0xfd, 0, 0, 0)))
    c.s(nl(Q_RESP, colmeta([('t', t_scale(0x29, 7))]) + int_row(bl(bytes(5))) + done(0xfd, 0, 0, 0)))
    c.s(nl(Q_RESP, colmeta([('m', t_bl(0x6e, 8))]) + int_row(bl(b'\x01\x02')) + done(0xfd, 0, 0, 0)))
    c.s(nl(Q_RESP, colmeta([('m', t_bl(0x6f, 8))]) + int_row(bl(b'\x01\x02')) + done(0xfd, 0, 0, 0)))
    c.s(nl(Q_RESP, colmeta([('d', t_fixed(0x28))]) + int_row(bl(b'\x01')) + done(0xfd, 0, 0, 0)))
    c.s(nl(Q_RESP, colmeta([('v', t_largec(0xa7, 0xffff))]) + int_row(plp([b'ab'], 9)) + done(0xfd, 0, 0, 0)))
    c.s(nl(Q_RESP, colmeta([('v', t_largec(0xa7, 0xffff))]) + int_row(plp([b'ab', b'cd'], 'unk'))[:-2]))
    c.s(nl(Q_RESP, colmeta([('x', bytes([0xa5, 0, 0]))]) + int_row(us(b'ab')[:3])))
    c.s(nl(Q_RESP, colmeta([('x', t_fixed(0x38))] * 300)))
    c.s(nl(Q_RESP, struct.pack('<B', 0xd1)))
    c.s(nl(Q_RESP, b'\xaa\x05\x00'))
    c.s(nl(Q_RESP, b'\xfd\x00'))
    c.s(nl(Q_RESP, colmeta([('x', bytes([0x77]))])))
    c.s(nl(Q_RESP, b'\xe2' + struct.pack('<H', 0)))
    c.s(nl(Q_RESP, b'\xa1' + struct.pack('<H', 0)))
    c.s(nl(Q_RESP, b'\xa9' + struct.pack('<H', 0) + b'\xff\xff'))
    # unknown type in an RPC parameter
    c.c(nl(Q_RPC, allhdr() + rpc_named('bad', 0, rpc_param('@x', bytes([0x77]), b''))))
    # XML and UDT: the dissector reads a 4 byte length after the type, the protocol has other type info
    c.c(nl(Q_RPC, allhdr() + rpc_named('xml', 0, rpc_param('@x', bytes([0xf1]) + struct.pack('<I', 0xffffffff), plp([b'<a/>'])) +
                                       rpc_param('@u', bytes([0xf0]) + struct.pack('<I', 0xffffffff), plp([b'\x01'])))))
    c.c(nl(Q_RPC, allhdr() + rpc_named('nameshort')[:6]))
    c.c(nl(Q_RPC, allhdr() + rpc_named('p', 0, rpc_param('@x', t_largec(0xe7, 100), us(u16('ab'))[:3]))))
    c.c(nl(Q_BATCH, allhdr() + u16('select 1')[:5]))
    # bad PRELOGIN, LOGIN7 and token streams
    c.c(nl(Q_PRELOGIN, bytes([0, 0, 50, 0, 6])))
    c.c(nl(Q_PRELOGIN, bytes([0, 0, 9, 0, 6, 0xff, 1, 2, 3, 4, 5, 6])))
    c.s(nl(Q_RESP, bytes([0, 0, 9, 0xff, 0xff, 0xff, 1, 2, 3, 4])))
    c.s(nl(Q_RESP, bytes([9, 0, 6, 0, 1, 0xff, 0])))
    c.s(nl(Q_RESP, bytes([0, 0, 6, 0, 6, 0xff, 1, 2, 3, 4, 5, 6])))
    c.c(nl(Q_LOGIN7, login7(0x74000004)[:60]))
    c.c(nl(Q_LOGIN7, login7(0x74000004, sspi=b'\x60\x03\x06\x01\x2a')))
    c.c(nl(Q_LOGIN7, login7(0x74000004, sspi=b'\x05\x01\x02')))
    c.s(nl(Q_RESP, b'\xed' + struct.pack('<H', 3) + b'\x01\x02\x03'))
    c.s(nl(Q_RESP, b'\xe4' + struct.pack('<I', 20) + struct.pack('<I', 1) + b'\x00' + bytes([1, 0xff, 9, 9]) + b'ab'))
    c.s(nl(Q_RESP, b'\xae' + bytes([1, 5, 0, 0, 0]) + b'ab'))
    c.s(nl(Q_RESP, b'\xe3\x03\x00\x07\x05'))
    c.s(nl(Q_RESP, b'\xa9\x01\x00'))
    c.s(nl(Q_RESP, b'\xe3\x03\x00\x01\x09' + u16('abcdefghi')[:4]))

    cap.section('Cursors: several declares in one connection (the decoding depends on the pass)')
    f5 = Fmt(False, 'ascii')
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x05000000)))
    c.s(nl(Q_RESP, loginack_sybase(f5)))
    rf_ab = rowfmt([rf_col('a', 0x38, f5), rf_col('b', 0x27, f5, csize=20)], f5)
    c.c(nl(Q_TDS5, curdeclare('cur1', 'select 1', f5)))
    c.s(nl(Q_RESP, curinfo(5, 3, 0x0003, f5, rowcnt=10) + rf_ab + sy_done(0xfd, 0, f5, 0)))
    c.c(nl(Q_TDS5, curopen(5, f5, status=1)))
    c.c(nl(Q_TDS5, curfetch(5, f5, 1)))
    c.s(nl(Q_RESP, b'\xd1' + f5.p4(1) + bl(b'xy') + sy_done(0xfd, 0x10, f5, 1)))
    c.c(nl(Q_TDS5, curfetch(5, f5, 5, 3)))
    c.c(nl(Q_TDS5, curfetch(0, f5, 1, name='cur1')))
    c.c(nl(Q_TDS5, curfetch(0, f5, 1, name='wrong')))
    c.c(nl(Q_TDS5, curinfo(5, 4, 0, f5)))
    c.s(nl(Q_RESP, curinfo(5, 3, 0x0400, f5) + sy_done(0xfd, 0, f5, 0)))
    c.c(nl(Q_TDS5, curclose(5, f5, dealloc=1)))
    c.c(nl(Q_TDS5, curclose(77, f5)))
    c.s(nl(Q_RESP, curinfo(5, 3, 0x0004, f5) + sy_done(0xfd, 0, f5, 0)))
    c.c(nl(Q_TDS5, curdeclare('cur2', 'select 2', f5)))
    c.c(nl(Q_TDS5, curdeclare('cur3', 'select 2', f5, 0x02)))
    c.s(nl(Q_RESP, curinfo(6, 3, 0x0001, f5) + sy_done(0xfd, 0, f5, 0)))
    c.s(nl(Q_RESP, curinfo(6, 3, 0x0001, f5) + curinfo(8, 3, 0x0001, f5) + curinfo(6, 3, 0x0001, f5)))
    c.c(nl(Q_TDS5, curfetch(6, f5, 2)))
    c.c(nl(Q_TDS5, curdeclare('n1', 'select 1', f5) + curopen(0, f5, name='other7') +
           curfetch(0, f5, 1, name='cur7') + curinfo(0, 4, 0, f5, name='cur7') + curclose(0, f5, name='x7')))
    c.s(nl(Q_RESP, curinfo(40, 3, 0x0001, f5)))
    c.c(nl(Q_TDS5, curdeclare('n1', 'select 1', f5)))
    c.c(nl(Q_TDS5, curclose(5, f5) + curdeclare('n2', 'select 2', f5)))
    c.s(nl(Q_RESP, curinfo(20, 3, 0x0003, f5) +
           rowfmt2([rf2_col('', '', '', 'tab', 'c1', 0x38, f5), rf2_col('lbl', '', '', '', 'c2', 0x27, f5, csize=8)], f5) +
           b'\xd1' + f5.p4(1) + bl(b'ab') + sy_done(0xfd, 0x10, f5, 1)))
    c.c(nl(Q_TDS5, curfetch(20, f5, 1)))
    c.s(nl(Q_RESP, b'\xd1' + f5.p4(2) + bl(b'cd') + sy_done(0xfd, 0x10, f5, 1)))
    c.s(nl(Q_RESP, rowfmt([rf_col('x', 0x38, f5)], f5) + b'\xd1' + f5.p4(2) + sy_done(0xfd, 0, f5, 1)))

    cap.section('Sybase token errors')
    c = conn()
    c.c(nl(Q_LOGIN, login45(0x05000000, caps=capability(pad=b''))))   # a well formed token: last capability flagged
    c.s(nl(Q_RESP, sy_done(0xfd, 0, Fmt(False, 'ascii'), 0) + capability(pad=b'') + sy_done(0xfd, 0, Fmt(False, 'ascii'), 0)))
    c.c(nl(Q_LOGIN, login45(0x05000000, caps=capability(extra=b'\x01\xff' + b'\x01' * 4))))
    f5 = Fmt(False, 'ascii')
    c.s(nl(Q_RESP, loginack_sybase(f5)))
    c.s(nl(Q_RESP, b'\xe2' + f5.p2(8) + bytes([1, 200, 1, 2, 3, 4])))
    c.s(nl(Q_RESP, b'\xe2' + f5.p2(4) + bytes([1, 11, 0xff, 0xff])))
    c.s(nl(Q_RESP, b'\xe2' + f5.p2(4) + bytes([9, 2, 0xff, 0xff])))
    c.s(nl(Q_RESP, b'\x01\x02\x03'))
    c.s(nl(Q_RESP, rowfmt([rf_col('i', 0x38, f5)], f5) + b'\xd1'))
    c.s(nl(Q_RESP, b'\xaf' + f5.p2(1)))
    c.s(nl(Q_RESP, rowfmt([rf_col('x%d' % i, 0x38, f5) for i in range(300)], f5)))
    c.s(nl(Q_RESP, col_name_tok(['x'] * 300, f5)))
    c.s(nl(Q_RESP, colfmt_tok([(0x38, None, None)] * 300, f5)))
    c.s(nl(Q_RESP, control_tok(['x'] * 300, f5)))
    c.s(nl(Q_RESP, paramfmt([fmt_col('p%d' % i, 0x38, f5) for i in range(300)], f5)))
    c.s(nl(Q_RESP, paramfmt([fmt_col('p%d' % i, 0x38, f5, two=True) for i in range(300)], f5, two=True)))
    c.s(nl(Q_RESP, rowfmt2([rf2_col('', '', '', '', 'c%d' % i, 0x38, f5) for i in range(300)], f5)))
    c.s(nl(Q_RESP, b'\xd1' + f5.p4(1)))
    c.c(nl(Q_TDS5, lang('x', 0)[:3]))
    c.c(nl(Q_TDS5, b'\x01\xff\xff\xff\xff'))
    c.c(nl(Q_TDS5, b'\x21\xff\xff\xff\xff\x00'))
    c.c(nl(Q_TDS5, b'\x21\xff\xff\xff\xfa\x00'))      # token size -1
    c.c(nl(Q_TDS5, b'\x21' + f5.p4(0) + b'\x00'))
    c.c(nl(Q_TDS5, b'\x00' + f5.p2(0)))
    c.c(nl(Q_TDS5, paramfmt([fmt_col('p%d' % i, 0x38, f5) for i in range(300)], f5)))
    c.c(nl(Q_TDS5, paramfmt([fmt_col('p%d' % i, 0x38, f5, two=True) for i in range(300)], f5, two=True)))
    # tokens of requests in a response: not dissected
    for tok in (curclose(5, f5), curdeclare('c', 's', f5), curfetch(5, f5), curopen(5, f5), dbrpc('p'), b'\x71\x00',
                b'\x78' + f5.p4(0)):
        c.s(nl(Q_RESP, tok))
    c.c(nl(Q_TDS5, curdeclare('c', 'select', f5, 0, 0)[:6]))
    c.c(nl(Q_TDS5, curfetch(0, f5, 1, name='abc')))
    c.s(nl(Q_RESP, curinfo(0, 3, 1, f5, name='zzz')))
    c.c(nl(Q_TDS5, curfetch(0, f5, 1, name='abc')))
    c.c(nl(Q_TDS5, curfetch(0, f5, 1, name='different')))
    c.c(nl(Q_TDS5, b'\x6f'))
    cap.section('TDS 4 login errors')
    c = conn()
    b = login45(0x05000000)
    bad = bytearray(b)
    for off in (30, 61, 92, 123, 170, 201, 472, 510, 555, 563):    # name lengths past the fields
        bad[off] = 99
    c.c(nl(Q_LOGIN, bytes(bad)))
    rp = bytearray(b)
    rp[457] = 10        # remote password length
    rp[202] = 200       # server name length past it
    c.c(nl(Q_LOGIN, bytes(rp)))
    rp = bytearray(b)
    rp[457] = 10
    rp[202] = 2
    rp[205] = 200       # password length past it
    c.c(nl(Q_LOGIN, bytes(rp)))
    c.c(nl(Q_LOGIN, b))
    c.c(nl(Q_LOGIN, b[:100]))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    cap = Pcap()
    build_main(cap)
    cap.write(os.path.join(out, 'tds-coverage.pcap'))
    if '-v' in sys.argv:
        print('main: %d frames' % len(cap.pkts))
        for a, b, n in cap.ranges():
            print('  %d-%d  %s' % (a, b, n))
    cap2 = Pcap()
    build_malformed(cap2)
    cap2.write(os.path.join(out, 'tds-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        print('malformed: %d frames' % len(cap2.pkts))
        for a, b, n in cap2.ranges():
            print('  %d-%d  %s' % (a, b, n))


if __name__ == '__main__':
    main()
