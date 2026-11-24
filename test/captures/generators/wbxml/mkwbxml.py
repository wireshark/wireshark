#!/usr/bin/env python3
# Generates test/captures/wbxml_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the WBXML coverage captures. Usage: mkwbxml.py <outdir> [packet-wbxml.c]
Everything is synthetic. The WBXML documents are built from the token tables
of packet-wbxml.c (read from the source file,
epan/dissectors/packet-wbxml.c) so that every code
page of every supported content type is used; the carrying HTTP/1.1
responses (TCP port 80) and WSP datagrams (UDP 9200) are built with struct."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import sys
import re

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
SRC = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/packet-wbxml.c')

# ------------------------------------------------------------ token tables
src = open(SRC).read()
src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
src = re.sub(r'//[^\n]*', '', src)
VS = {}
for m in re.finditer(r'static const value_string (\w+)\[\]\s*=\s*\{(.*?)\n\};', src, re.S):
    VS[m.group(1)] = [(int(v, 0), s) for v, s in re.findall(
        r'\{\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}', m.group(2))]
VVS = {}
for m in re.finditer(r'static const value_valuestring (\w+)\[\]\s*=\s*\{(.*?)\n\};', src, re.S):
    VVS[m.group(1)] = [(int(a), b) for a, b in re.findall(r'\{\s*(\d+)\s*,\s*(\w+)\s*\}', m.group(2))]
DEC = {}
for m in re.finditer(r'static const wbxml_decoding (\w+) = \{(.*?)\n\};', src, re.S):
    mm = re.match(r'\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*\{[^}]*\}\s*,(.*)', m.group(2), re.S)
    ids = [x.strip() for x in mm.group(3).split(',') if x.strip()]
    DEC[m.group(1)] = dict(name=mm.group(1), abbrev=mm.group(2), funcs=ids[0:4],
                           glob=ids[4], tags=ids[5], astart=ids[6], avalue=ids[7])
PUBID = {}
for m in re.finditer(r'\{\s*(0x[0-9A-Fa-f]+)\s*,\s*&(decode_\w+)\s*\}', src):
    PUBID[m.group(2)] = int(m.group(1), 0)


def pages(table, lo, hi):
    """{codepage: [tokens]} of a value_valuestring table; tokens in [lo, hi)."""
    if table == 'NULL' or table not in VVS:
        return {}
    r = {}
    for cp, ref in VVS[table]:
        if ref in VS:
            t = sorted(set(v for v, s in VS[ref] if lo <= v < hi and s))
            if t:
                r[cp] = t
    return r


def tag_pages(d):
    return pages(d['tags'], 5, 0x40)


def astart_pages(d):
    return pages(d['astart'], 5, 0x80)


def avalue_pages(d):
    return pages(d['avalue'], 0x80, 0x100)


# ------------------------------------------------------------ encoder
def uv(n):
    out = [n & 0x7f]
    n >>= 7
    while n:
        out.append(0x80 | (n & 0x7f))
        n >>= 7
    return bytes(reversed(out))


END, ENTITY, STR_I, LITERAL, PI, STR_T = 1, 2, 3, 4, 0x43, 0x83
OPAQUE = 0xC3
ST = b'var\0lit\0abc\0long-literal-name\0'      # string table used by the extras
ST_VAR, ST_LIT, ST_ABC, ST_LONG = 0, 4, 8, 12


def stri(s):
    return bytes([STR_I]) + s.encode() + b'\0'


def header(ver=3, pubid=2, charset=106, strtbl=ST, lit=None):
    b = bytes([ver])
    if pubid:
        b += uv(pubid)
    else:
        b += b'\0' + uv(lit or 0)
    if ver:
        b += uv(charset)
    return b + uv(len(strtbl)) + strtbl


class Doc:
    """Body builder that remembers the code page state (the dissector keeps
    it for the whole document, also after leaving an element)."""
    def __init__(self):
        self.t = 0
        self.a = 0

    def st(self, cp):
        if cp == self.t:
            return b''
        self.t = cp
        return b'\0' + bytes([cp])

    def sa(self, cp):
        if cp == self.a:
            return b''
        self.a = cp
        return b'\0' + bytes([cp])


def opaque(data):
    return bytes([OPAQUE]) + uv(len(data)) + data


def broad(d, ver=3, with_extras=True):
    """A body that uses every tag token, every attribute start and value token
    of the decoding d: tags in four shapes (empty, content, attributes,
    both), all attributes in one dump element."""
    D = Doc()
    tp, ap, vp = tag_pages(d), astart_pages(d), avalue_pages(d)
    out = b''
    root_cp = min(tp) if tp else 0
    root = tp[root_cp][0] if tp else 5
    out += D.st(root_cp) + bytes([0x40 | root])
    n = 0
    for cp in sorted(tp):
        for tok in tp[cp]:
            out += D.st(cp)
            k = n % 4
            n += 1
            if k == 0:
                out += bytes([tok])
            elif k == 1:
                out += bytes([0x40 | tok]) + stri('c%d' % n) + bytes([END])
            elif k == 2:
                out += bytes([0x80 | tok]) + one_attr(D, ap, vp, n) + bytes([END])
            else:
                out += bytes([0xC0 | tok]) + one_attr(D, ap, vp, n) + bytes([END]) + stri('c%d' % n) + bytes([END])
    # every attribute start and value in one list
    if tp and (ap or vp):
        out += D.st(root_cp) + bytes([0x80 | root])
        for cp in sorted(set(ap) | set(vp)):
            out += D.sa(cp)
            vals = vp.get(cp, [])
            for i, tok in enumerate(ap.get(cp, [])):
                out += bytes([tok])
                if vals:
                    out += bytes([vals[i % len(vals)]])
            for tok in vals:
                out += bytes([tok])
        out += bytes([END])
    if with_extras:
        out += extras(D, d, ver)
    out += bytes([END])
    return out


def one_attr(D, ap, vp, n):
    if not ap:
        return b''
    cp = sorted(ap)[n % len(ap)]
    toks = ap[cp]
    out = D.sa(cp) + bytes([toks[n % len(toks)]])
    if vp.get(cp):
        out += bytes([vp[cp][n % len(vp[cp])]])
    return out


def first_tag(d):
    tp = tag_pages(d)
    if not tp:
        return 0, 5
    cp = min(tp)
    return cp, tp[cp][0]


def first_attr(d):
    ap = astart_pages(d)
    if not ap:
        return None
    cp = min(ap)
    return cp, ap[cp][0]


def extras(D, d, ver):
    """Global tokens in the tag and attribute states."""
    o = b''
    o += stri('text') + bytes([ENTITY]) + uv(0x20ac)
    o += b'\x40ext-i-0\0\x41ext-i-1\0\x42ext-i-2\0'
    o += b'\x80' + uv(ST_VAR) + b'\x81' + uv(ST_LIT) + b'\x82' + uv(ST_ABC)
    o += bytes([STR_T]) + uv(ST_ABC)
    o += b'\xc0\xc1\xc2'
    fa = first_attr(d)
    tcp, ttok = first_tag(d)
    # literal tags: LITERAL, LITERAL_C, LITERAL_A, LITERAL_AC
    o += bytes([LITERAL]) + uv(ST_LIT)
    o += bytes([0x44]) + uv(ST_LIT) + stri('literal content') + bytes([END])
    attrs = (bytes([LITERAL]) + uv(ST_LONG) + stri('v') + bytes([ENTITY]) + uv(65) +
             b'\x40ai\0\x80' + uv(ST_VAR) + b'\x83' + uv(ST_ABC) + b'\xc0' + b'\x02' + uv(300) +
             b'\x41ai1\0\x81' + uv(ST_LIT) + b'\x42ai2\0\x82' + uv(ST_ABC) + b'\xc1\xc2')
    o += bytes([0x84]) + uv(ST_LIT) + attrs + bytes([END])
    o += bytes([0xC4]) + uv(ST_LIT) + attrs + bytes([END]) + stri('content') + bytes([END])
    # a known tag with an attribute list that starts with a switch page
    if fa:
        o += D.st(tcp) + bytes([0x80 | ttok]) + D.sa(fa[0]) + bytes([fa[1]]) + bytes([END])
    # opaque data in every state: known tag, literal tag, known attribute, literal attribute
    if ver:
        o += D.st(tcp) + bytes([0x40 | ttok]) + opaque(b'\x01\x02\x03') + bytes([END])
        o += bytes([0x44]) + uv(ST_LIT) + opaque(b'\x04\x05') + bytes([END])
        if fa:
            o += D.st(tcp) + bytes([0xC0 | ttok]) + D.sa(fa[0]) + bytes([fa[1]]) + opaque(b'\x06\x07') + bytes([END]) + bytes([END])
        o += bytes([0xC4]) + uv(ST_LIT) + bytes([LITERAL]) + uv(ST_LIT) + opaque(b'\x08') + bytes([END]) + bytes([END])
    return o


# ------------------------------------------------------------ opaque handlers
def func_body(name):
    m = re.search(r'static char \*\s*' + name + r'\s*\(.*?\n\}\n', src, re.S)
    return m.group(0) if m else None


def binary_cases(name):
    """[(codepage, token, kind)] of an opaque_binary function."""
    body = func_body(name)
    res, cp, pend = [], 0, []
    for line in body.splitlines():
        m = re.search(r'case (\d+):', line)
        if m:
            cp = int(m.group(1))
            pend = []
            continue
        m = re.search(r'case 0x([0-9A-Fa-f]+):', line)
        if m:
            pend.append(int(m.group(1), 16))
            continue
        kind = None
        if 'wv_integer_from_opaque' in line:
            kind = 'int'
        elif 'wv_datetime_from_opaque' in line:
            kind = 'wvdt'
        elif 'date_time_from_opaque' in line:
            kind = 'dt'
        if kind:
            res += [(cp, t, kind) for t in pend]
            pend = []
    return res


def literal_names(name):
    """[(name, kind)] of an opaque_literal function."""
    body = func_body(name)
    parts = body.split('else if')
    res = []
    for i, p in enumerate(parts):
        names = re.findall(r'strcmp\(token, "([^"]+)"\)', p)
        kind = 'int' if i == 0 and 'wv_' in body else ('wvdt' if 'wv_' in body else 'dt')
        res += [(n, kind) for n in names]
    return res


def wv_datetime(year, month, day, hour, minute, second, tz):
    """WV-CSP DateTime: 00YYYYYY YYYYYYMM MMDDDDDh hhhhmmmm mmssssss ZZZZZZZZ"""
    v = (year << 34) | (month << 30) | (day << 25) | (hour << 20) | (minute << 14) | (second << 8) | tz
    return v.to_bytes(6, 'big')


def op_data(kind, valid, n):
    if kind == 'int':
        return bytes(range(1, 1 + (n % 4 + 1))) if valid else bytes(5)
    if kind == 'wvdt':
        return wv_datetime(2002, 12, 31, 17, 34, 56, 0x5a) if valid else bytes(3)
    return bytes([0x20, 0x01, 0x12, 0x31, 0x12, 0x34, 0x56][:4 + n % 4]) if valid else bytes(2)


def opaque_tag_doc(d, fname_bin, fname_lit, valid):
    """Known tags (code page, token) and literal tag names that the opaque
    handlers decode, each with an OPAQUE child; also tokens and names that
    they do not handle."""
    D = Doc()
    cp0, root = first_tag(d)
    o = D.st(cp0) + bytes([0x40 | root])
    names = literal_names(fname_lit) if fname_lit else []
    names = names + [('other', 'int')]
    strtbl = b''.join(n.encode() + b'\0' for n, k in names)
    offs, off = {}, 0
    for n, k in names:
        offs[n] = off
        off += len(n) + 1
    for i, (cp, tok, kind) in enumerate(binary_cases(fname_bin)):
        for rep in (range(4) if kind == 'dt' and valid else range(1)):
            o += D.st(cp) + bytes([0x40 | tok]) + opaque(op_data(kind, valid, i + rep)) + bytes([END])
    for cp in range(12):                                 # tokens the handler does not know
        o += D.st(cp) + bytes([0x40 | 0x3f]) + opaque(b'\x01\x02') + bytes([END])
    for i, (n, kind) in enumerate(names):
        for rep in (range(4) if kind == 'dt' and valid else range(1)):
            o += bytes([0x44]) + uv(offs[n]) + opaque(op_data(kind, valid, i + rep)) + bytes([END])
    o += bytes([END])
    return strtbl, o


def opaque_attr_doc(d, pubid, fname_bin, fname_lit, valid):
    """SI / EMN: attribute values as OPAQUE (known attribute start and literal)."""
    D = Doc()
    cp0, root = first_tag(d)
    names = literal_names(fname_lit)
    strtbl = b''.join(n.encode() + b'\0' for n, k in names) + b'other\0'
    offs, off = {}, 0
    for n, k in names + [('other', 'dt')]:
        offs[n] = off
        off += len(n) + 1
    o = bytes([0x40 | root])
    for i, (cp, tok, kind) in enumerate(binary_cases(fname_bin)):
        for rep in range(4):
            o += bytes([0xC0 | root]) + D.sa(cp) + bytes([tok]) + opaque(op_data(kind, valid, i + rep)) + bytes([END]) + bytes([END])
    for cp in range(1, 4):                               # code pages the handler does not know
        o += bytes([0xC0 | root]) + D.sa(cp) + bytes([0x05]) + opaque(b'\x01\x02') + bytes([END]) + bytes([END])
    fa = first_attr(d)
    o += bytes([0xC0 | root]) + D.sa(0) + bytes([0x7f if not fa else fa[1] + 1]) + opaque(b'\x01') + bytes([END]) + bytes([END])
    for i, (n, kind) in enumerate(names + [('other', 'dt')]):
        for rep in range(4):
            o += bytes([0xC0 | root]) + bytes([LITERAL]) + uv(offs[n]) + opaque(op_data(kind, valid, i + rep)) + bytes([END]) + bytes([END])
    o += bytes([END])
    return strtbl, o


# ------------------------------------------------------------ transport
def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


PKTS = []
CIP, SIP = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
CMAC, SMAC = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'


def ip_frame(from_client):
    src, dst = (CIP, SIP) if from_client else (SIP, CIP)
    smac, dmac = (CMAC, SMAC) if from_client else (SMAC, CMAC)
    return src, dst, smac, dmac


class Tcp:
    n = 0

    def __init__(self, sport=80):
        Tcp.n += 1
        self.cport, self.sport = 40000 + Tcp.n, sport
        self.cseq, self.sseq = 1000, 5000
        self._seg(True, b'', 0x02)
        self.cseq += 1
        self._seg(False, b'', 0x12)
        self.sseq += 1
        self._seg(True, b'', 0x10)

    def _seg(self, from_client, payload, flags=0x18):
        src, dst, smac, dmac = ip_frame(from_client)
        if from_client:
            sp, dp, seq, ack = self.cport, self.sport, self.cseq, self.sseq
        else:
            sp, dp, seq, ack = self.sport, self.cport, self.sseq, self.cseq
        opts = b'\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02\x01\x01' if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags != 0x02 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        PKTS.append(dmac + smac + b'\x08\x00' + ip + tcp)

    def send(self, from_client, payload, maxseg=1400):
        for i in range(0, max(len(payload), 1), maxseg):
            chunk = payload[i:i + maxseg]
            self._seg(from_client, chunk)
            if from_client:
                self.cseq += len(chunk)
            else:
                self.sseq += len(chunk)

    def http(self, ctype, body, path='/x', method='GET', extra=b'', reqbody=None):
        """One request and its response (keep-alive)."""
        if reqbody is None:
            self.send(True, method.encode() + b' ' + path.encode() +
                      b' HTTP/1.1\r\nHost: example.invalid\r\n\r\n')
        else:
            self.send(True, method.encode() + b' ' + path.encode() +
                      b' HTTP/1.1\r\nHost: example.invalid\r\nContent-Type: ' + ctype.encode() +
                      b'\r\nContent-Length: %d\r\n\r\n' % len(reqbody) + reqbody)
        self.send(False, b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype.encode() + extra +
                  b'\r\nContent-Length: %d\r\n\r\n' % len(body) + body)


def udp_frame(sport, dport, payload, from_client=True):
    src, dst, smac, dmac = ip_frame(from_client)
    if not from_client:
        sport, dport = dport, sport
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', csum(ph + udp) or 0xffff) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    PKTS.append(dmac + smac + b'\x08\x00' + ip + udp)


def write(fname, pkts):
    with open(os.path.join(OUT, fname), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


# ------------------------------------------------------------ content
# public id -> (decoding, a HTTP content type)
CT = {
    'decode_wmlc_10': 'application/vnd.wap.wmlc', 'decode_wmlc_11': 'application/vnd.wap.wmlc',
    'decode_wmlc_12': 'application/vnd.wap.wmlc', 'decode_wmlc_13': 'application/vnd.wap.wmlc',
    'decode_sic_10': 'application/vnd.wap.sic', 'decode_slc_10': 'application/vnd.wap.slc',
    'decode_coc_10': 'application/vnd.wap.coc', 'decode_provc_10': 'application/vnd.wap.connectivity-wbxml',
    'decode_emnc_10': 'application/vnd.wap.wbxml', 'decode_channelc_10': 'application/vnd.uplanet.channel-wbxml',
    'decode_nokiaprovc_70': 'application/vnd.nokia.syncset+wbxml',
    'decode_syncmlc_10': 'application/vnd.syncml+wbxml', 'decode_syncmlc_11': 'application/vnd.syncml+wbxml',
    'decode_syncmlc_12': 'application/vnd.syncml.dm+wbxml',
    'decode_wv_cspc_10': 'application/vnd.wv.csp.wbxml', 'decode_wv_cspc_11': 'application/vnd.wv.csp.wbxml',
    'decode_wv_cspc_12': 'application/vnd.wv.csp.wbxml', 'decode_wv_cspc_13': 'application/vnd.wv.csp.wbxml',
}
MAPS = [k for k in PUBID]                        # every map with a public id

t = Tcp()
# ---- 1: every map with a registered public id, all code pages (one doc each)
for i, k in enumerate(MAPS):
    d = DEC[k]
    ver = [3, 3, 2, 1][i % 4]
    h = header(ver=ver, pubid=PUBID[k], charset=[106, 4, 3, 106][i % 4])
    t.http(CT[k], h + broad(d, ver))

# ---- 2: maps that only exist for a media type (public id unknown, 1)
t.http('application/vnd.ms-sync.wbxml', header(pubid=1) + broad(DEC['decode_mssync_10']))
t.http('application/vnd.ms-sync', header(ver=2, pubid=1) + broad(DEC['decode_mssync_10']))
t.http('application/x-wap-prov.browser-settings', header(pubid=1) + broad(DEC['decode_nokiaprovc_70']))
t.http('application/x-wap-prov.browser-bookmarks', header(pubid=1) + broad(DEC['decode_nokiaprovc_70']))
t.http('application/x-prov.syncset+wbxml', header(pubid=1) + broad(DEC['decode_nokiaprovc_70']))
# the same by a literal public identifier (string table)
lit = b'-//EXAMPLE//DTD ACTIVESYNC//EN\0'
t.http('application/vnd.ms-sync.wbxml', header(pubid=0, lit=0, strtbl=lit + ST) + broad(DEC['decode_mssync_10']),
       path='/literal-public-id')
# WV-CSP discriminator: the first bytes of the body choose the version
for ver, magic in (('1.0', b'\xfe\x05'), ('1.1', b'\xc9\x05'), ('1.2', b'\xc9\x08'), ('1.3', b'\xc9\x0b'), ('?', b'\xc9\x09')):
    body = magic + b'\x03' + (b'1.' + (ver[-1:].encode() if ver != '?' else b'9')) + b'\0'
    body += b'\x01'                                         # end of the attribute list
    body += b'\x45' + bytes([END])                          # a tag with content
    body += bytes([END])
    t.http('application/vnd.wv.csp.wbxml', header(pubid=1) + body, path='/wv-' + ver)
# unknown content type: no token mapping (generic tags and attributes)
body = b'\xc5' + b'\x06\x85' + b'\x03a\0' + b'\x01' + b'\x46\x01' + b'\x07' + b'\x01'
t.http('application/vnd.wap.wbxml', header(pubid=1) + body, path='/generic')
t.http('application/foo+wbxml', header(pubid=1) + body, path='/suffix')                 # media_type.suffix
t.http('application/vnd.wap.wbxml', header(ver=1, pubid=1) + b'\x45' + opaque(b'abc') + b'\xc5\x05\x85' + opaque(b'xy') + b'\x01\x01', path='/generic-opaque')
# generic body with the global tokens
dg = {'tags': 'NULL', 'astart': 'NULL', 'avalue': 'NULL'}
Dg = Doc()
t.http('application/vnd.wap.wbxml', header(pubid=1) + b'\x45' + extras(Dg, dg, 3) + b'\x01', path='/generic-extras')

# ---- 3: opaque values of the WV-CSP, SI and EMN handlers, valid and invalid
t2 = Tcp()
for k, fb, fl in (('decode_wv_cspc_10', 'wv_csp10_opaque_binary_tag', 'wv_csp10_opaque_literal_tag'),
                  ('decode_wv_cspc_11', 'wv_csp11_opaque_binary_tag', 'wv_csp11_opaque_literal_tag'),
                  ('decode_wv_cspc_12', 'wv_csp12_opaque_binary_tag', 'wv_csp12_opaque_literal_tag'),
                  ('decode_wv_cspc_13', 'wv_csp13_opaque_binary_tag', 'wv_csp13_opaque_literal_tag')):
    for valid in (True, False):
        strtbl, o = opaque_tag_doc(DEC[k], fb, fl, valid)
        t2.http('application/vnd.wv.csp.wbxml', header(pubid=PUBID[k], strtbl=strtbl or b'x\0') + o,
                path='/%s-%s' % (k[7:], 'ok' if valid else 'bad'))
for k, fb, fl in (('decode_sic_10', 'sic10_opaque_binary_attr', 'sic10_opaque_literal_attr'),
                  ('decode_emnc_10', 'emnc10_opaque_binary_attr', 'emnc10_opaque_literal_attr')):
    for valid in (True, False):
        strtbl, o = opaque_attr_doc(DEC[k], PUBID[k], fb, fl, valid)
        t2.http('application/vnd.wap.wbxml', header(pubid=PUBID[k], strtbl=strtbl) + o,
                path='/%s-%s' % (k[7:], 'ok' if valid else 'bad'))

# ---- 4: header variants, string table, charsets, version 1.0, odd tokens
t3 = Tcp()
wml = DEC['decode_wmlc_11']
t3.http('application/vnd.wap.wmlc', header(ver=0, pubid=4, strtbl=ST) + b'\x7f' + b'\xc3\x03abc' + b'\x01', path='/v10-reserved2-tag')
t3.http('application/vnd.wap.wmlc', header(ver=0, pubid=4, strtbl=ST) + b'\xff\x00\x11' + b'\x05' + b'\xc3' + b'\x01', path='/v10-reserved2-attr')
t3.http('application/vnd.wap.wmlc', header(ver=0, pubid=4, strtbl=ST) + b'\x7f\x01', path='/v10-plain')
t3.http('application/vnd.wap.wmlc', header(ver=3, pubid=4, charset=0) + b'\x7f\x01', path='/charset0')
t3.http('application/vnd.wap.wmlc', header(ver=3, pubid=4, charset=1015, strtbl='utf16'.encode('utf-16-be') + b'\0\0')
        + b'\x7f\x03' + 'u16'.encode('utf-16-be') + b'\0\0' + b'\x01', path='/utf16')
t3.http('application/vnd.wap.wmlc', header(ver=3, pubid=4, strtbl=b'a\0b\0c\0\xe2\x82\xac\0') + b'\x7f\x83\x06\x01', path='/strtbl')
t3.http('application/vnd.wap.wmlc', b'\x09\x04\x6a\x00\x7f\x01', path='/unknown-version')
t3.http('application/vnd.wap.wmlc', header(pubid=4) + b'\x7f\x02' + uv(0x20ac) + b'\x01', path='/entity')
# an attribute list that ends the document with an invalid token (stops parsing)
t3.http('application/vnd.wap.wmlc', header(pubid=4) + b'\xff\x00\x11\x43\x01', path='/attr-invalid-token')
# a processing instruction (the dissector starts its attribute list at the PI token)
t3.http('application/vnd.wap.wmlc', header(pubid=4, strtbl=ST) + b'\x43\x04' + uv(ST_LIT) + b'\x03v\0\x01\x7f\x01', path='/pi')
# unused code page of a content type; undefined tokens
t3.http('application/vnd.wap.wmlc', header(pubid=4) + b'\x7f\x00\x09\x3a\x00\x00\x3a\x01', path='/unmapped')
t3.http('application/vnd.wap.wmlc', header(pubid=4) + b'\xff\x00\x07\x05\x99\x01\x01', path='/unmapped-attr')

# ---- 5: recursion depth: just under and just past the limit of 255
for n in (254, 255, 256, 300):
    t3.http('application/vnd.wap.wmlc', header(pubid=4) + b'\x7f' * n + b'\x01' * n, path='/depth-%d' % n)

# ---- 6: two WBXML bodies in one frame (multipart), the reproducer of the depth wrap
HDR = b'\x03\x04\x6a\x00'
doc = HDR + b'\x67' + b'\x67\x01' + b'\x01'
mp = (b'--XX\r\nContent-Type: application/vnd.wap.wbxml\r\n\r\n' + doc +
      b'\r\n--XX\r\nContent-Type: application/vnd.wap.wbxml\r\n\r\n' + doc +
      b'\r\n--XX--\r\n')
t3.http('multipart/mixed; boundary=XX', mp, path='/multipart')
# negative check of the attribute OPAQUE case: a literal attribute start with opaque data
doc2 = HDR + b'\xa7' + b'\xc3\x03\x05\x06\x07' + b'\x01'
t3.http('application/vnd.wap.wbxml', doc2, path='/attr-opaque-first')

# ---- 7: WSP (UDP 9200), connectionless: Reply and Push carry the content
# type as inline text; a Get carries Profile-Diff (WBXML, UAProf)
def wsp_reply(tid, ctype, body, pdu=4):
    ct = ctype.encode() + b'\0'
    if pdu == 4:
        return bytes([tid, 4, 0x20]) + uv(len(ct)) + ct + body
    return bytes([tid, pdu]) + uv(len(ct)) + ct + body


up = DEC['decode_uaprof_wap_248']
uapdoc = header(ver=3, pubid=1, strtbl=b'') + broad(up, 3, with_extras=False)
# Profile-Diff = well known header 0x36 (0xb6), value with length
hdr_b = b'\xb6' + b'\x1f' + uv(len(uapdoc)) + uapdoc
uri = b'http://example.invalid/'
udp_frame(40000, 9200, bytes([1, 0x40]) + uv(len(uri)) + uri + hdr_b, True)
udp_frame(40000, 9200, wsp_reply(1, 'application/vnd.wap.wmlc', header(pubid=4) + broad(DEC['decode_wmlc_11'], 3, False)), False)
udp_frame(40001, 9200, wsp_reply(2, 'application/vnd.wap.sic', header(pubid=5) + broad(DEC['decode_sic_10'], 3, False), 6), False)
udp_frame(40001, 9200, wsp_reply(3, 'application/vnd.wap.slc', header(pubid=6) + broad(DEC['decode_slc_10'], 3, False), 6), False)
udp_frame(40001, 9200, wsp_reply(4, 'application/vnd.wap.wta-eventc', header(pubid=1) + b'\x45\x01', 6), False)
# a Get with Profile-Diff whose value is not valid WBXML (version 9)
bad = b'\x09\x01\x6a\x00\x45\x01'
hb = b'\xb6' + bytes([len(bad)]) + bad
udp_frame(40000, 9200, bytes([5, 0x40]) + uv(len(uri)) + uri + hb, True)

write('wbxml-coverage.pcap', PKTS)
print('main', len(PKTS), 'packets')

# ------------------------------------------------------------ malformed capture
PKTS.clear()
Tcp.n = 100
m = Tcp()
W = 'application/vnd.wap.wmlc'
m.http(W, header(pubid=4)[:2], path='/short-header')                       # header cut
m.http(W, header(pubid=4)[:-1], path='/short-strtbl')                      # string table length without data
m.http(W, header(pubid=4, strtbl=b'abc') + b'\x7f', path='/no-end')        # tag without END, string table without NUL
m.http(W, header(pubid=4) + b'\x7f\x03abc', path='/short-string')          # STR_I without terminator
m.http(W, header(pubid=4) + b'\x7f\x83\x7f\x01', path='/strtbl-index-out-of-range')
m.http(W, header(pubid=4) + b'\x7f\x02\xff\xff\xff\xff\xff\x7f\x01', path='/oversized-uintvar-entity')
m.http(W, b'\x03\x84\x80\x80\x80\x80\x00\x6a\x00\x7f\x01', path='/oversized-uintvar-publicid')
m.http(W, header(pubid=4) + b'\x7f\xc3\xff\xff\xff\xff\x7f\x01', path='/opaque-length-huge')
m.http(W, header(pubid=4) + b'\x7f\xc3\x7f\x01', path='/opaque-length-past-end')
m.http(W, header(pubid=4) + b'\xff\x00\x11\x05\xc3\x7f', path='/attr-opaque-past-end')
m.http(W, header(pubid=4) + b'\xff\x00\x11\x05\x02\xff\xff\xff\xff\xff\x7f\x01\x01', path='/attr-oversized-entity')
m.http(W, header(pubid=4) + b'\xff\x00\x11\x04\x7f\x01', path='/attr-literal-index-past-end')
m.http(W, header(pubid=4) + b'\xff\x00\x11\x83\x7f\x01', path='/attr-strt-past-end')
m.http(W, header(pubid=4) + b'\xff\x00\x11\x80\xff\xff\xff\xff\x7f\x01', path='/attr-ext-t-huge')
m.http(W, header(pubid=4) + b'\x7f\x84\xff\xff\xff\xff\x7f', path='/literal-index-huge')
m.http(W, header(ver=0, pubid=4) + b'\x7f\xc3', path='/v10-reserved2-last')
m.http('application/vnd.wv.csp.wbxml', header(pubid=0x10) + b'\x45\xc3\x02', path='/wv-opaque-cut')
m.http('application/vnd.wap.wbxml', header(pubid=0x4000), path='/pubid-unknown-no-body')
m.http('application/vnd.wap.wbxml', header(pubid=0, lit=0x7f, strtbl=b'ab\0') + b'\x45\x01', path='/literal-pubid-past-table')
m.http(W, header(ver=3, pubid=4, charset=106, strtbl=ST) + b'\x7f' + b'\x00', path='/switch-page-cut')
m.http(W, header(pubid=4) + b'\x7f\xff\x00', path='/attr-switch-cut')
write('wbxml-coverage-malformed.pcap', PKTS)
print('malformed', len(PKTS), 'packets')
