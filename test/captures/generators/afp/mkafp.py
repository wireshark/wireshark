#!/usr/bin/env python3
# AFP coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AFP (epan/dissectors/packet-afp.c): Apple Filing Protocol over DSI on
TCP port 548.

A client (192.0.2.1) talks to a server (192.0.2.2).  Every AFP request is a
DSI Command (or Write) with a request ID and every reply carries the ID of
its request, which is how packet-afp.c pairs them: it keeps the command of
the request in a hash and decodes the reply by that command.

Usage: mkafp.py [<output directory>]

Writes:
  afp-coverage.pcap            DSI GetStatus with the AFP server status, a
                               login with each UAM, the volume, directory,
                               file, fork, desktop, comment, icon, mapping,
                               extended attribute, ACL and session calls
                               with their replies, volume, file and
                               directory bitmaps with names at an offset,
                               Spotlight RPCs (big and little endian,
                               every query type, nested FileMeta) and
                               replies with error codes
  afp-coverage-malformed.pcapng  paths that end in an exception or an
                               expert info (port reuse, Spotlight ToC
                               errors, too many ACL entries, ...)

Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, Pcapng, exported_pdu  # noqa: E402
from pktlib import TcpConn, pcap  # noqa: E402

CLIENT = (192, 0, 2, 1)
SERVER = (192, 0, 2, 2)
PORT = 548

# AFP commands
(BYTELOCK, CLOSEVOL, CLOSEDIR, CLOSEFORK, COPYFILE, CREATEDIR, CREATEFILE, DELETE,
 ENUMERATE, FLUSH, FLUSHFORK) = range(1, 12)
GETFORKPARAM, GETSRVINFO, GETSRVPARAM, GETVOLPARAM, LOGIN, LOGINCONT, LOGOUT = 14, 15, 16, 17, 18, 19, 20
MAPID, MAPNAME, MOVE, OPENVOL, OPENDIR, OPENFORK, READ, RENAME = 21, 22, 23, 24, 25, 26, 27, 28
SETDIRPARAM, SETFILEPARAM, SETFORKPARAM, SETVOLPARAM, WRITE = 29, 30, 31, 32, 33
GETFLDRPARAM, SETFLDRPARAM, CHANGEPW, GETUSERINFO, GETSRVRMSG = 34, 35, 36, 37, 38
CREATEID, DELETEID, RESOLVEID, EXCHANGEFILE, CATSEARCH = 39, 40, 41, 42, 43
OPENDT, CLOSEDT, GETICON, GTICNINFO, ADDAPPL, RMVAPPL, GETAPPL = 48, 49, 51, 52, 53, 54, 55
ADDCMT, RMVCMT, GETCMT = 56, 57, 58
BYTELOCK_EXT, READ_EXT, WRITE_EXT, LOGIN_EXT, GETSESSTOKEN, DISCTOLDSESS = 59, 60, 61, 63, 64, 65
ENUMERATE_EXT, CATSEARCH_EXT, ENUMERATE_EXT2 = 66, 67, 68
GETEXTATTR, SETEXTATTR, REMOVEATTR, LISTEXTATTR, GETACL, SETACL, ACCESS = 69, 70, 71, 72, 73, 74, 75
SPOTLIGHTRPC, SYNCDIR, SYNCFORK, ZZZ, ADDICON = 76, 78, 79, 122, 192

# AFP error codes (as DSI error codes)
ERR_ACCESS, ERR_AUTHCONT, ERR_PARAM, ERR_NOOBJ, ERR_MISC = -5000, -5001, -5019, -5018, -5014
ERR_EOF = -5034


def H(*v):
    return struct.pack('!%dH' % len(v), *v)


def I(*v):
    return struct.pack('!%dI' % len(v), *v)


def Q(*v):
    return struct.pack('!%dQ' % len(v), *v)


def pstr(s):
    if isinstance(s, str):
        s = s.encode()
    return bytes([len(s)]) + s


def path(name, ptype=2):
    """AFP path: type 1 (short) and 2 (long) have a one octet length, type 3
    (UTF-8) a hint and a two octet length."""
    if isinstance(name, str):
        name = name.encode()
    if ptype == 3:
        return bytes([3]) + I(0x08000103) + H(len(name)) + name
    return bytes([ptype, len(name)]) + name


def even(b):
    """Pad to an even length: the dissector aligns on its own offset, which
    counts from the first octet of the AFP command or reply data."""
    return bytes(b) + (b'\0' if len(b) & 1 else b'')


def vd(vol=1, did=2):
    return H(vol) + I(did)


# ---------------------------------------------------------------------------
# DSI

def dsi(flags, cmd, reqid, code, payload):
    return struct.pack('!BBHiII', flags, cmd, reqid, code, len(payload), 0) + payload


class Session:
    def __init__(self, cport=49152, nxt=1):
        self.c = TcpConn(cport, PORT, a=CLIENT, b=SERVER)
        self.frames = []
        self.nxt = nxt

    def request(self, body, dsi_cmd=2, offset=0, reqid=None):
        rid = self.nxt if reqid is None else reqid
        self.nxt += 1
        self.frames.append(self.c.send(dsi(0, dsi_cmd, rid, offset, body)))
        return rid

    def reply(self, rid, body=b'', err=0, dsi_cmd=2):
        self.frames.append(self.c.send(dsi(1, dsi_cmd, rid, err, body), True))

    def cmd(self, body, rep=None, err=0):
        """A DSI Command: the request and, unless rep is None, its reply."""
        rid = self.request(bytes(body))
        if rep is not None:
            self.reply(rid, bytes(rep), err)
        return rid

    def write(self, head, data, rep=None, err=0):
        """A DSI Write: the AFP part is 'head', the data follows."""
        rid = self.request(bytes(head) + data, dsi_cmd=6, offset=len(head))
        if rep is not None:
            self.reply(rid, bytes(rep), err, dsi_cmd=6)
        return rid


# ---------------------------------------------------------------------------
# AFP server status (DSI GetStatus reply)

def server_status(flags=0x8fff, full=True):
    name = pstr('Synthetic AFP Server')
    fixed = 10 + len(name)
    fixed += fixed & 1
    for bit in (0x10, 0x20, 0x100, 0x200):
        if flags & bit:
            fixed += 2
    mach = pstr('Xserve')
    vers = bytes([3]) + pstr('AFP2.2') + pstr('AFPX03') + pstr('AFP3.1')
    uams = bytes([3]) + pstr('No User Authent') + pstr('DHCAST128') + pstr('DHX2')
    icon = bytes(i & 0xff for i in range(256))
    sig = bytes(range(0x10, 0x20))
    addrs = [
        bytes([6, 1]) + bytes([192, 0, 2, 2]),
        bytes([8, 2]) + bytes([192, 0, 2, 2]) + H(548),
        bytes([6, 3]) + H(1000) + bytes([42, 4]),
        bytes([2 + 15, 4]) + b'afp.example.com',
        bytes([2 + 9, 5]) + b'192.0.2.2',
        bytes([2, 4]),
        bytes([18, 6]) + bytes.fromhex('20010db8000000000000000000000002'),
        bytes([20, 7]) + bytes.fromhex('20010db8000000000000000000000002') + H(548),
        bytes([4, 9]) + b'\xaa\xbb',
    ]
    addr = bytes([len(addrs)]) + b''.join(addrs)
    dirs = bytes([2]) + pstr('afpserver/afp.example.com@EXAMPLE.COM') + pstr('LDAP')
    utf8 = 'Synthetic AFP Server é'.encode()
    utf8 = H(len(utf8)) + utf8
    var = b''
    offs = {}
    if full:
        items = (('mach', mach), ('vers', vers), ('uams', uams), ('icon', icon),
                 ('sig', sig), ('addr', addr), ('dirs', dirs), ('utf8', utf8))
    else:
        items = (('vers', vers), ('uams', uams))
    for k, v in items:
        offs[k] = fixed + len(var)
        var += v
    hdr = H(offs.get('mach', 0), offs.get('vers', 0), offs.get('uams', 0), offs.get('icon', 0), flags) + name
    if len(hdr) & 1:
        hdr += b'\0'
    for bit, k in ((0x10, 'sig'), (0x20, 'addr'), (0x100, 'dirs'), (0x200, 'utf8')):
        if flags & bit:
            hdr += H(offs.get(k, 0))
    assert len(hdr) == fixed
    return hdr + var


# ---------------------------------------------------------------------------
# Bitmaps with parameters

def params(bm, kind, name=None, uname=None, prodos=False, short=0):
    """The parameters of a file ('f') or directory ('d') bitmap, with the
    long and UTF-8 names stored after the fixed fields at the offsets
    packed into them (relative to the start of the parameters)."""
    fixed = b''
    lpos = upos = None
    for bit in range(16):
        if not bm & (1 << bit):
            continue
        if bit == 0:
            fixed += H(0x0102)
        elif bit == 1:
            fixed += I(2)
        elif bit in (2, 3, 4):
            fixed += I(0x2a000000 + bit * 86400)
        elif bit == 5:
            fixed += b'TEXTttxt' + bytes(24)
        elif bit == 6:
            lpos = len(fixed)
            fixed += H(0)
        elif bit == 7:
            fixed += H(short)
        elif bit == 8:
            fixed += I(0x1234)
        elif kind == 'f' and bit == 9:
            fixed += I(1000)
        elif kind == 'f' and bit == 10:
            fixed += I(2000)
        elif kind == 'f' and bit == 11:
            fixed += Q(1 << 33)
        elif kind == 'f' and bit == 12:
            fixed += H(0)
        elif kind == 'f' and bit == 14:
            fixed += Q(1 << 34)
        elif kind == 'd' and bit == 9:
            fixed += H(5)
        elif kind == 'd' and bit == 10:
            fixed += I(501)
        elif kind == 'd' and bit == 11:
            fixed += I(20)
        elif kind == 'd' and bit == 12:
            fixed += I(0x80ff0f07)
        elif bit == 13:
            upos = len(fixed)
            fixed += H(0) + bytes(4)
        elif bit == 15:
            fixed += I(501, 20, 0o100644) + I(0x0707)
    var = b''
    if lpos is not None:
        fixed = fixed[:lpos] + H(len(fixed) + len(var)) + fixed[lpos + 2:]
        var += pstr(name or 'file.txt')
        var += b'\0' * (len(var) & 1)
    if upos is not None:
        if prodos:
            fixed = fixed[:upos] + b'\x00\x00' + fixed[upos + 2:]
        else:
            n = (uname or 'file é.txt').encode()
            fixed = fixed[:upos] + H(len(fixed) + len(var)) + fixed[upos + 2:]
            var += I(0x08000103) + H(len(n)) + n
            var += b'\0' * (len(var) & 1)
    return fixed + var


# Volume bitmap bits
VOL_ALL = 0x0fff


def vol_params(bm, name='Synthetic Volume', pad=0):
    """Volume parameters; the name is at the offset in the parameters."""
    fixed = b''
    npos = None
    if bm & 1:
        fixed += H(0x1fff)
    if bm & 2:
        fixed += H(1)
    if bm & 4:
        fixed += I(0x2a000000)
    if bm & 8:
        fixed += I(0x2a000100)
    if bm & 0x10:
        fixed += I(0x80000000)
    if bm & 0x20:
        fixed += H(7)
    if bm & 0x40:
        fixed += I(1 << 20)
    if bm & 0x80:
        fixed += I(1 << 24)
    if bm & 0x100:
        npos = len(fixed)
        fixed += H(0)
    if bm & 0x200:
        fixed += Q(1 << 36)
    if bm & 0x400:
        fixed += Q(1 << 40)
    if bm & 0x800:
        fixed += I(4096)
    if npos is not None:
        fixed = fixed[:npos] + H(len(fixed) + pad) + fixed[npos + 2:]
        fixed += bytes(pad) + pstr(name)
    return fixed


# ---------------------------------------------------------------------------
# Spotlight RPC data

SQ_NULL, SQ_COMPLEX, SQ_BOOL, SQ_DATA, SQ_UUID = 0x0000, 0x0200, 0x0100, 0x0700, 0x0e00
SQ_INT64, SQ_FLOAT, SQ_DATE, SQ_CNIDS = 0x8400, 0x8500, 0x8600, 0x8700
CPX_ARRAY, CPX_STRING, CPX_UTF16, CPX_DICT, CPX_CNIDS, CPX_FILEMETA = 0x0a00, 0x0c00, 0x1c00, 0x0d00, 0x1a00, 0x1b00
SPOTLIGHT_TIME_DELTA = 280878921600


class Spotlight:
    """Builds a Spotlight RPC blob: 'md031234' (big endian) or its reverse,
    the offsets, the query items and the table of contents of the complex
    types.  Nodes:
      ('null', n) ('bool', v) ('int', [..]) ('float', [..]) ('uuid', [16 bytes ..])
      ('date', [unix seconds ..]) ('cnids', unknown1, unknown2, [ids])
      ('str', s) ('u16', s) ('arr', [nodes]) ('dict', [nodes])
      ('meta', blob) ('cnidscpx', [nodes])
    """
    def __init__(self, big=True):
        self.big = big
        self.e = '>' if big else '<'
        self.toc = []
        self.q = b''

    def w(self, v):
        return struct.pack(self.e + 'Q', v)

    def item(self, count, typ, words):
        return self.w((count << 32) | typ << 16 | words)

    def enc(self, node):
        k = node[0]
        if k == 'null':
            self.q += self.item(node[1], SQ_NULL, 1)
        elif k == 'bool':
            self.q += self.item(node[1], SQ_BOOL, 1)
        elif k == 'int':
            self.q += self.item(len(node[1]), SQ_INT64, 1 + len(node[1])) + b''.join(self.w(x) for x in node[1])
        elif k == 'float':
            self.q += self.item(len(node[1]), SQ_FLOAT, 1 + len(node[1])) \
                + b''.join(struct.pack(self.e + 'd', x) for x in node[1])
        elif k == 'uuid':
            self.q += self.item(len(node[1]), SQ_UUID, 1 + 2 * len(node[1])) + b''.join(node[1])
        elif k == 'date':
            self.q += self.item(len(node[1]), SQ_DATE, 1 + len(node[1])) \
                + b''.join(self.w((s + SPOTLIGHT_TIME_DELTA) << 24) for s in node[1])
        elif k == 'cnids':
            ids = node[3]
            self.q += self.item(0, SQ_CNIDS, 2 + len(ids))
            self.q += self.w((node[2] << 32) | node[1] << 16 | len(ids)) + b''.join(self.w(x) for x in ids)
        elif k == 'cnidsempty':
            self.q += self.item(0, SQ_CNIDS, 1)
        elif k in ('str', 'u16'):
            s = node[1].encode('utf-8') if k == 'str' else b'\xfe\xff' + node[1].encode('utf-16-be')
            pad = -len(s) % 8
            if k == 'str' and not pad:
                pad = 8
            padded = s + b'\0' * pad
            idx = self.toc_add(8 - pad, CPX_STRING if k == 'str' else CPX_UTF16)
            self.q += self.item(idx, SQ_COMPLEX, 1)
            self.q += self.item(0, SQ_DATA, 1 + len(padded) // 8) + padded
        elif k in ('arr', 'dict'):
            idx = self.toc_add(len(node[1]), CPX_ARRAY if k == 'arr' else CPX_DICT)
            self.q += self.item(idx, SQ_COMPLEX, 1)
            for ch in node[1]:
                self.enc(ch)
        elif k == 'cnidscpx':
            idx = self.toc_add(len(node[1]), CPX_CNIDS)
            self.q += self.item(idx, SQ_COMPLEX, 1)
            for ch in node[1]:
                self.enc(ch)
        elif k == 'meta':
            blob = node[1] + b'\0' * (-len(node[1]) % 8)
            idx = self.toc_add(1, CPX_FILEMETA)
            self.q += self.item(idx, SQ_COMPLEX, 1)
            self.q += self.item(0, SQ_DATA, 1 + len(blob) // 8) + blob
        elif k == 'metaempty':
            idx = self.toc_add(1, CPX_FILEMETA)
            self.q += self.item(idx, SQ_COMPLEX, 1)
            self.q += self.item(0, SQ_DATA, 1)
        elif k == 'raw':
            self.q += node[1]
        else:
            raise ValueError(k)

    def toc_add(self, count, typ):
        self.toc.append((count, typ))
        return len(self.toc)

    def build(self, nodes, toc_extra=(), qwords=None, tocwords=None, toccount=None, tochdr=0):
        for n in nodes:
            self.enc(n)
        toc = self.w((len(self.toc) + len(toc_extra) + 1 if toccount is None else toccount) | tochdr) \
            + b''.join(self.w((c << 32) | t << 16 | (i + 1)) for i, (c, t) in enumerate(self.toc)) \
            + b''.join(self.w(x) for x in toc_extra)
        magic = b'md031234' if self.big else b'md031234'[::-1]
        hi = (len(self.q) + 8) // 8 if tocwords is None else tocwords
        lo = (8 + len(self.q) + len(toc)) // 8 if qwords is None else qwords
        return magic + self.w((hi << 32) | lo) + self.q + toc


TOC_UNKNOWN = (0x5566 << 16) | (0x11223344 << 32)


def sl_query(big=True):
    """A typical Spotlight search request: an array with a dictionary of
    query parameters in it."""
    s = Spotlight(big)
    return s.build(tochdr=0 if big else TOC_UNKNOWN, nodes=[
        ('arr', [
            ('str', 'openQuery'),
            ('int', [1, 2, 3]),
            ('bool', 1),
            ('bool', 0),
            ('null', 1),
            ('dict', [
                ('str', 'kMDQueryString'),
                ('u16', 'kMDItemFSName == "*.txt"'),
                ('str', 'kMDQueryScopes'),
                ('arr', [('str', '/Volumes/Share')]),
            ]),
            ('float', [1.5, -2.25]),
            ('uuid', [bytes(range(16)), bytes(range(16, 32))]),
            ('date', [1700000000, 1700086400]),
            ('cnidscpx', [('cnids', 1, 2, [101, 102, 103])]),
            ('cnidsempty',),
            ('null', 3),
        ]),
    ])


def sl_filemeta(big=True):
    inner = Spotlight(big).build([('arr', [('str', 'kMDItemDisplayName'), ('str', 'readme.txt')])])
    return Spotlight(big).build([('arr', [('str', 'fileMeta'), ('meta', inner), ('metaempty',)])])


def sl_reply(big=True):
    return Spotlight(big).build([('arr', [
        ('str', 'results'), ('int', [4, 5]), ('cnids', 0, 0, [7, 8]),
        ('arr', [('str', 'a'), ('str', 'b')]),
    ])])


# ---------------------------------------------------------------------------
# The calls

def srv_params(s):
    # 2-3: FPGetSrvrParms; one volume name is 255 octets, which wrapped the
    # length of the entry
    vols = [(0x80, 'Macintosh HD'), (0x00, 'x' * 255), (0x40, 'Public'), (0xc0, 'Both')]
    body = I(0x2a000000) + bytes([len(vols)])
    for flags, name in vols:
        body += bytes([flags]) + pstr(name)
    s.cmd([GETSRVPARAM, 0], body)
    s.cmd([GETSRVPARAM, 0], I(0x2a000100) + bytes([0]))


def login_ext(uam, ptype, dirname):
    if ptype == 3:
        d = bytes([3]) + H(len(dirname)) + dirname.encode()
    else:
        d = bytes([ptype]) + (pstr(dirname) if ptype in (1, 2) else b'')
    return bytes([LOGIN_EXT, 0]) + H(0) + pstr('AFP3.3') + pstr(uam) + bytes([3]) + H(5) + b'frank' + d


def login(s):
    # FPLogin: UAM "Cleartxt passwrd" with user and password
    b = bytes([LOGIN]) + pstr('AFP2.2') + pstr('Cleartxt passwrd') + pstr('alice')
    s.cmd(even(b) + b'secret\0\0', b'', ERR_AUTHCONT)
    # DHCAST128: the parameters are the random number
    b = bytes([LOGIN]) + pstr('AFPX03') + pstr('DHCAST128') + pstr('bob')
    s.cmd(even(b) + bytes(range(16)), bytes(range(32)), ERR_AUTHCONT)
    # a prefix of a UAM name is not that UAM
    b = bytes([LOGIN]) + pstr('AFP3.1') + pstr('Cleartxt') + pstr('carol')
    s.cmd(even(b) + b'secret\0\0', b'', 0)
    # a UAM with a 0 length name
    b = bytes([LOGIN]) + pstr('AFP2.2') + pstr('') + pstr('dave')
    s.cmd(b, b'', 0)
    # "2-Way Randnum exchange"
    b = bytes([LOGIN]) + pstr('AFP2.2') + pstr('2-Way Randnum exchange') + pstr('erin')
    s.cmd(even(b) + bytes(8), b'', ERR_AUTHCONT)
    # FPLogin "No User Authent": a user name that is not needed, then a
    # password
    b = bytes([LOGIN]) + pstr('AFP2.2') + pstr('No User Authent') + pstr('guest')
    s.cmd(even(b) + b'password', b'', 0)
    # FPLoginExt with a Unicode directory path, and each other path type.
    # The UAM parameters (the 16 octet random number of DHCAST128, the 8
    # octet password of Cleartxt passwrd) start at an even or an odd
    # offset, where one octet of padding comes first; the tails are long
    # enough for either.
    for uam, ptype, dirname, odd, tail in (
            ('DHCAST128', 3, 'cn=users', 0, bytes(range(16))),
            ('DHCAST128', 3, 'cn=users', 1, bytes(range(17))),
            ('Cleartxt passwrd', 2, 'LDAP', 0, bytes(16)),
            ('Cleartxt passwrd', 2, 'LDAP', 1, bytes(17)),
            ('2-Way Randnum exchange', 1, 'dir', 0, bytes(16)),
            ('DHX2', 9, '', 0, bytes(16)),
            ('Client Krb v2', 3, 'dir', 1, bytes(9))):
        b = login_ext(uam, ptype, dirname)
        if (len(b) & 1) != odd:
            b = login_ext(uam, ptype, dirname + 'x')
        s.cmd(b + tail, b'', ERR_AUTHCONT)
    s.cmd([LOGINCONT, 0, 0, 1, 0, 0], bytes(range(8)))
    s.cmd([CHANGEPW, 0] + [0] * 4, b'', ERR_ACCESS)
    s.cmd([LOGOUT, 0], b'')


def volumes(s):
    # FPOpenVol: bitmap, volume name, volume password
    s.cmd(bytes([OPENVOL, 0]) + H(VOL_ALL) + pstr('Synthetic Volume') + b'volpass\0',
          H(VOL_ALL) + vol_params(VOL_ALL, pad=2))
    s.cmd(bytes([OPENVOL, 0]) + H(0x0121) + pstr('Public'),
          H(0x0121) + vol_params(0x0121, 'Public'))
    # the name offset is where the name is, even with something before it
    s.cmd(bytes([OPENVOL, 0]) + H(0x0100) + pstr('Odd'), H(0x0100) + vol_params(0x0100, 'Odd', pad=3))
    # FPGetVolParms: request and reply, all bits and a few
    s.cmd(bytes([GETVOLPARAM, 0]) + H(1) + H(VOL_ALL), H(VOL_ALL) + vol_params(VOL_ALL))
    s.cmd(bytes([GETVOLPARAM, 0]) + H(1) + H(0x01a5), H(0x01a5) + vol_params(0x01a5, pad=4))
    s.cmd(bytes([GETVOLPARAM, 0]) + H(2) + H(0x0820), H(0x0820) + vol_params(0x0820))
    # FPSetVolParms: backup date
    s.cmd(bytes([SETVOLPARAM, 0]) + H(1) + H(0x0010) + I(0x2a000200), b'')
    s.cmd(bytes([FLUSH, 0]) + H(1), b'')
    s.cmd(bytes([OPENDT, 0]) + H(1), H(0x4321))
    s.cmd(bytes([CLOSEDT, 0]) + H(0x4321), None)
    s.cmd(bytes([CLOSEVOL, 0]) + H(1), b'')
    s.cmd(bytes([CLOSEVOL, 0]) + H(9), b'', ERR_PARAM)


F_ATTR, F_PDID, F_CD, F_MD, F_BD, F_FI, F_LN, F_SN, F_FID, F_DFL, F_RFL, F_EDFL, F_LL, F_U8, F_ERFL, F_UP = \
    [1 << i for i in range(16)]
FALL = 0xffff & ~F_LL
D_OFF, D_OWN, D_GRP, D_AR = 1 << 9, 1 << 10, 1 << 11, 1 << 12
DALL = 0xffff & ~(1 << 14)


def files(s):
    vol, did = 1, 2
    # FPOpenFork: data fork, with each access bit; the reply has the
    # parameters of the file bitmap
    fb = F_ATTR | F_PDID | F_CD | F_MD | F_BD | F_FI | F_LN | F_SN | F_FID | F_DFL | F_RFL
    s.cmd(bytes([OPENFORK, 0]) + vd(vol, did) + H(fb) + H(0x0003) + path('file.txt'),
          H(fb) + H(5) + params(fb, 'f'))
    s.cmd(bytes([OPENFORK, 0x80]) + vd(vol, did) + H(F_EDFL | F_U8) + H(0x000c) + path('rsrc'),
          H(F_EDFL | F_U8) + H(6) + params(F_EDFL | F_U8, 'f'))
    s.cmd(bytes([OPENFORK, 0]) + vd(vol, did) + H(F_ERFL | F_UP) + H(0x0030) + path('uni é', 3),
          H(F_ERFL | F_UP) + H(0) + params(F_ERFL | F_UP, 'f'))
    s.cmd(bytes([OPENFORK, 0]) + vd(vol, did) + H(0) + H(0) + path('missing'), b'', ERR_NOOBJ)
    # reads and writes
    s.cmd([READ, 0] + list(H(5) + I(0, 16) + b'\x80\x0a'), bytes(range(16)))
    s.cmd([READ, 0] + list(H(5) + I(0, 16) + b'\x00\x00'), b'', ERR_EOF)
    s.cmd([READ_EXT, 0] + list(H(5) + Q(0, 1 << 32)), bytes(8))
    s.write([WRITE, 0x80] + list(H(5) + I(0, 24)), bytes(range(24)), I(24))
    s.write([WRITE_EXT, 0] + list(H(5) + Q(1 << 32, 8)), b'12345678', Q(1 << 32 | 8))
    s.cmd([BYTELOCK, 0x80] + list(H(5) + I(0, 100)), I(0))
    s.cmd([BYTELOCK, 0x01] + list(H(5) + I(0, 100)), None)
    s.cmd([BYTELOCK_EXT, 0x00] + list(H(5) + Q(0, 1 << 33)), Q(0))
    s.cmd([BYTELOCK_EXT, 0x81] + list(H(5) + Q(0, 1 << 33)), Q(1 << 32), 0)
    s.cmd([GETFORKPARAM, 0] + list(H(5) + H(fb)), H(fb) + params(fb, 'f'))
    s.cmd([RESOLVEID, 0] + list(H(1) + I(0x1234) + H(fb)), H(fb) + params(fb, 'f'))
    s.cmd([SETFORKPARAM, 0] + list(H(5) + H(F_DFL) + I(4096)), b'')
    s.cmd([SETFORKPARAM, 0] + list(H(5) + H(F_EDFL) + Q(1 << 33)), b'')
    s.cmd([SETFORKPARAM, 0] + list(H(5) + H(F_ERFL) + Q(1 << 34)), b'')
    s.cmd([SYNCFORK, 0] + list(H(5)), b'')
    s.cmd([FLUSHFORK, 0] + list(H(5)), b'')
    s.cmd([CLOSEFORK, 0] + list(H(5)), b'')
    s.cmd([SYNCDIR, 0] + list(vd(vol, did) + I(2)), b'')
    s.cmd([GETFORKPARAM, 0] + list(H(0) + H(fb)), b'', ERR_PARAM)


def dirs_and_names(s):
    vol, did = 1, 2
    # FPGetFileDirParms: a file and a directory in the reply
    fb, db = F_ATTR | F_PDID | F_CD | F_FI | F_LN | F_FID | F_DFL | F_UP, DALL
    s.cmd(bytes([GETFLDRPARAM, 0]) + vd(vol, did) + H(fb) + H(db) + path('name.txt'),
          H(fb) + H(db) + bytes([0, 0]) + params(fb, 'f'))
    s.cmd(bytes([GETFLDRPARAM, 0]) + vd(vol, did) + H(fb) + H(db) + path('dir'),
          H(fb) + H(db) + bytes([0x80, 0]) + params(db, 'd', 'dir'))
    s.cmd(bytes([GETFLDRPARAM, 0]) + vd(vol, did) + H(F_FID) + H(8 | 1 << 13) + path('ué', 3),
          H(F_FID) + H(8 | 1 << 13) + bytes([0x80, 0]) + params(8 | 1 << 13, 'd', uname='dir é'))
    # the ProDOS information block
    s.cmd(bytes([GETFLDRPARAM, 0]) + vd(vol, did) + H(F_U8) + H(0) + path(''),
          H(F_U8) + H(0) + bytes([0, 0]) + params(F_U8, 'f', prodos=True))
    # a short name (type 1) path
    s.cmd(bytes([GETFLDRPARAM, 0]) + vd(vol, did) + H(F_FID) + H(0) + path('SHORT', 1),
          H(F_FID) + H(0) + bytes([0, 0]) + params(F_FID, 'f'))
    # FPSetFileDirParms, FPSetFileParms, FPSetDirParms
    b = bytes([SETFLDRPARAM, 0]) + vd(vol, did) + H(F_ATTR | F_CD | F_MD | F_BD | F_FI) + path('f')
    s.cmd(even(b) + params(F_ATTR | F_CD | F_MD | F_BD | F_FI, 'f'), b'')
    b = bytes([SETFILEPARAM, 0]) + vd(vol, did) + H(F_ATTR | F_MD | F_FI | F_UP) + path('f')
    s.cmd(even(b) + params(F_ATTR | F_MD | F_FI | F_UP, 'f'), b'')
    b = bytes([SETDIRPARAM, 0]) + vd(vol, did) + H(1 | 4 | 1 << 10 | 1 << 11 | 1 << 12 | 1 << 15) + path('d')
    s.cmd(even(b) + params(1 | 4 | 1 << 10 | 1 << 11 | 1 << 12 | 1 << 15, 'd') + I(0), b'')
    # create, delete, rename, move, copy, exchange
    s.cmd([CREATEDIR, 0] + list(vd(vol, did) + path('newdir')), I(0x2000))
    s.cmd([CREATEFILE, 0x80] + list(vd(vol, did) + path('newfile')), b'')
    s.cmd([CREATEFILE, 0] + list(vd(vol, did) + path('newfile', 3)), b'', ERR_PARAM)
    s.cmd([DELETE, 0] + list(vd(vol, did) + path('old')), b'')
    s.cmd([RENAME, 0] + list(vd(vol, did) + path('old name') + path('new name')), b'')
    s.cmd([MOVE, 0] + list(vd(vol, did) + I(9) + path('src') + path('') + path('moved')), I(0x77))
    s.cmd([EXCHANGEFILE, 0] + list(vd(vol, did) + I(9) + path('one') + path('two')), b'')
    s.cmd([COPYFILE, 0] + list(vd(1, 2) + vd(2, 3) + path('src') + path('dstdir') + path('copy')), b'')
    s.cmd([CREATEID, 0] + list(vd(vol, did) + path('idfile')), I(0x1234))
    s.cmd([DELETEID, 0] + list(H(vol) + I(0x1234)), b'')
    s.cmd([CLOSEDIR, 0] + [0] * 6, b'')
    s.cmd([OPENDIR, 0] + [0] * 6, b'')
    s.cmd([GETSRVINFO, 0], b'')
    s.cmd([ZZZ, 0] + [0, 0, 0, 0], b'')
    s.cmd([0xfe, 0, 1, 2], b'', -5002)
    s.cmd([GETSRVPARAM, 0], b'', 12345)


def record(flag, p, ext, add=0):
    """One enumerate (add=0) or catalog search (add=2) record: size, flag,
    parameters, padded to an even length.  The size of a search record does
    not count its own header."""
    hdr = 4 if ext else 2
    total = hdr + len(p)
    total += total & 1
    size = total - add * (2 if ext else 1)
    if ext:
        return H(size) + bytes([flag, 0]) + p + b'\0' * (total - hdr - len(p))
    return bytes([size, flag]) + p + b'\0' * (total - hdr - len(p))


def enumerate_(s):
    vol, did = 1, 2
    fb = F_ATTR | F_PDID | F_CD | F_FI | F_LN | F_FID | F_DFL | F_RFL
    db = 1 | 2 | 4 | 1 << 6 | 8 | 1 << 9 | 1 << 10 | 1 << 11 | 1 << 12
    ub = F_U8 | F_ATTR | F_FID
    for cmd, ext in ((ENUMERATE, 0), (ENUMERATE_EXT, 1)):
        recs = b''.join(record(flag, params(bm, kind, name), ext)
                        for flag, bm, kind, name in ((0, fb, 'f', 'a.txt'), (0x80, db, 'd', 'subdir'),
                                                     (0, fb, 'f', 'odd')))
        s.cmd(bytes([cmd, 0]) + vd(vol, did) + H(fb) + H(db) + H(10) + H(4) + H(4096) + path('folder'),
              H(fb) + H(db) + H(3) + recs)
        # a file only reply, and a request for names with an offset
        s.cmd(bytes([cmd, 0]) + vd(vol, did) + H(ub) + H(0) + H(3) + H(1) + H(4096) + path('f2'),
              H(ub) + H(0) + H(1) + record(0, params(ub, 'f', uname='\u00fcber.txt'), ext))
    # records with every field and no name
    fb2 = F_ATTR | F_PDID | F_CD | F_MD | F_BD | F_FI | F_SN | F_FID | F_DFL | F_RFL | F_EDFL | F_LL | F_ERFL | F_UP
    db2 = 1 | 2 | 4 | 8 | 0x10 | 0x20 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x8000
    for cmd, ext in ((ENUMERATE, 0), (ENUMERATE_EXT, 1)):
        recs = record(0, params(fb2, 'f'), ext) + record(0x80, params(db2, 'd'), ext)
        s.cmd(bytes([cmd, 0]) + vd(vol, did) + H(fb2) + H(db2) + H(10) + H(1) + H(4096) + path('all'),
              H(fb2) + H(db2) + H(2) + recs)
    # a record whose long name offset is 0 has no name
    for cmd, ext in ((ENUMERATE, 0), (ENUMERATE_EXT, 1)):
        p0 = b'\0\0' + params(F_LN | F_FID, 'f')[2:]
        s.cmd(bytes([cmd, 0]) + vd(vol, did) + H(F_LN | F_FID) + H(0) + H(10) + H(1) + H(4096) + path('noname'),
              H(F_LN | F_FID) + H(0) + H(1) + record(0, p0, ext))
    # a record of size 0 ends the list
    s.cmd(bytes([ENUMERATE, 0]) + vd(vol, did) + H(F_FID) + H(0) + H(3) + H(1) + H(4096) + path('z'),
          H(F_FID) + H(0) + H(2) + bytes([0, 0, 0, 0]))
    # FPEnumerateExt2
    s.cmd(bytes([ENUMERATE_EXT2, 0]) + vd(vol, did) + H(fb) + H(db) + H(10) + I(1) + I(65536) + path('folder', 3),
          H(fb) + H(db) + H(1) + record(0, params(fb, 'f', 'e.txt'), 1))
    s.cmd(bytes([ENUMERATE_EXT2, 0]) + vd(vol, did) + H(fb) + H(db) + H(10) + I(1) + I(65536) + path('empty'),
          H(fb) + H(db) + H(0))
    s.cmd(bytes([ENUMERATE, 0]) + vd(vol, did) + H(fb) + H(db) + H(10) + H(1) + H(4096) + path('none'),
          b'', ERR_NOOBJ)


def catsearch(s):
    vol = 1
    fb, db = F_ATTR | F_LN | F_DFL, 1 | 1 << 6

    def spec(rb, ext, name):
        p = params(rb & 0xffff, 'f', name)
        return (H(len(p)) if ext else bytes([len(p), 0])) + p

    for cmd, ext in ((CATSEARCH, 0), (CATSEARCH_EXT, 1)):
        for f_, d_, rb in ((fb, db, 0x0041 | 0x1000), (fb, 0, 0x0041 | 0x200 | 0x400 | 0x800 | 0x4000 | 0x80000000),
                           (0, db, 0x0041 | 0x200 | 0x2000)):
            body = bytes([cmd, 0]) + H(vol) + I(5, 0) + bytes(16) + H(f_) + H(d_) + I(rb)
            body += spec(rb, ext, 'a') + spec(rb, ext, 'z')
            recs = b''.join(record(flag, params(bm, kind, nm), ext, 2)
                            for flag, bm, kind, nm in ((0, fb, 'f', 'hit.txt'), (0x80, db, 'd', 'hitdir')))
            s.cmd(body, bytes(range(16)) + H(fb) + H(db) + I(2) + recs, 0)
    s.cmd(bytes([CATSEARCH_EXT, 0]) + H(vol) + I(5, 0) + bytes(16) + H(0) + H(0) + I(0) + spec(0, 1, '') + spec(0, 1, ''),
          bytes(16) + H(0) + H(0) + I(0))


def desktop(s):
    ref = 0x1234
    # comments, with the Vol and Did in the Info column in one pass and two
    s.cmd([GETCMT, 0] + list(H(ref) + I(0x5678) + path('cmt')), pstr('a comment'))
    s.cmd([RMVCMT, 0] + list(H(0x2222) + I(0x3333) + path('gone')), b'')
    b = bytes([ADDCMT, 0]) + H(ref) + I(0x4444) + path('with comment')
    s.cmd(even(b) + pstr('the new comment'), b'')
    b = bytes([ADDCMT, 0]) + H(ref) + I(0x4444) + path('odd')
    s.cmd(even(b) + pstr(''), b'')
    # icons and applications
    s.cmd([GETICON, 0] + list(H(ref) + b'ttxt' + b'TEXT' + bytes([1, 0]) + H(256)), bytes(range(128)) * 2)
    s.cmd([GTICNINFO, 0] + list(H(ref) + b'ttxt' + H(1)), I(7) + b'TEXT' + bytes([1, 0]) + H(256))
    s.cmd([ADDICON, 0] + list(H(ref) + b'ttxt' + b'TEXT' + bytes([1, 0]) + I(7) + H(256)), b'')
    s.cmd([ADDAPPL, 0] + list(H(ref) + I(2) + b'ttxt' + I(0x1001) + path('SimpleText')), b'')
    s.cmd([RMVAPPL, 0] + list(H(ref) + I(2) + b'ttxt' + path('SimpleText')), b'')
    s.cmd([GETAPPL, 0] + list(H(ref) + b'ttxt' + H(1) + H(F_PDID)), I(0x1001))
    # user information and ID mapping
    s.cmd([GETUSERINFO, 1] + list(I(0) + H(7)), H(7) + I(501) + I(20) + bytes(range(16)))
    s.cmd([GETUSERINFO, 0] + list(I(0) + H(1)), H(1) + I(501))
    s.cmd([GETUSERINFO, 0] + list(I(0) + H(2)), H(2) + I(20))
    for t in (1, 2, 3, 4):
        s.cmd([MAPID, t] + list(I(501)), pstr('alice') if t < 3 else H(5) + b'alice')
    s.cmd([MAPID, 3] + list(I(502)), bytes([0, 5]) + b'bob  ' + b'xx')      # not what the length says
    s.cmd([MAPID, 5] + list(bytes(range(16))), I(3) + I(501) + H(5) + b'alice')
    s.cmd([MAPID, 6] + list(bytes(range(16))), H(0) + H(0) + I(501) + H(3) + b'bob')
    s.cmd([MAPID, 1] + list(I(0)), b'', ERR_NOOBJ)
    s.cmd([MAPNAME, 1] + list(pstr('alice')), I(501))
    s.cmd([MAPNAME, 2] + list(pstr('staff')), I(20))
    s.cmd([MAPNAME, 5] + list(H(5) + b'alice'), bytes(range(16)))
    s.cmd([MAPNAME, 6] + list(H(5) + b'staff'), bytes(range(16, 32)))
    # server messages
    s.cmd([GETSRVRMSG, 0] + list(H(1) + H(3)), H(1) + H(3) + H(5) + b'hello')
    s.cmd([GETSRVRMSG, 0] + list(H(0) + H(1)), H(0) + H(1) + bytes([4]) + b'login')
    s.cmd([GETSRVRMSG, 0] + list(H(0) + H(0)), H(0) + H(0) + bytes([0]))
    s.cmd([GETSRVRMSG, 0] + list(H(1) + H(2)), H(1) + H(2) + H(0))
    # session tokens
    s.cmd([DISCTOLDSESS, 0] + list(H(3) + I(4) + b'tokn'), b'')
    s.cmd([GETSESSTOKEN, 0] + list(H(0)), I(4) + b'tokn')
    s.cmd([GETSESSTOKEN, 0] + list(H(8)), I(2) + b'tk')
    s.cmd([GETSESSTOKEN, 0] + list(H(1) + I(4) + b'tokn'), I(4) + b'tokn')
    s.cmd([GETSESSTOKEN, 0] + list(H(3) + I(4) + I(1700000000) + b'tokn'), I(0))
    s.cmd([GETSESSTOKEN, 0] + list(H(4) + I(4) + I(1700000000) + b'tokn'), I(4) + b'tokn')


def extattrs(s):
    vol, did = 1, 2

    def an(name):
        n = name.encode()
        return H(len(n)) + n

    b = bytes([GETEXTATTR, 0]) + vd(vol, did) + H(0x0001) + Q(0, 1 << 20) + I(65536) + path('file')
    b = even(b) + an('com.apple.FinderInfo')
    s.cmd(b, H(0) + I(8) + bytes(8))
    b = even(bytes([GETEXTATTR, 0]) + vd(vol, did) + H(0) + Q(0, 100) + I(0) + path('other')) + an('user.x')
    s.cmd(b, b'', ERR_NOOBJ)
    b = even(bytes([SETEXTATTR, 0]) + vd(vol, did) + H(0x0006) + Q(0) + path('file')) + an('user.comment')
    s.cmd(b + I(5) + b'hello', b'')
    s.cmd(even(bytes([REMOVEATTR, 0]) + vd(vol, did) + H(0x0002) + path('file')) + an('user.comment'), b'')
    s.cmd(bytes([LISTEXTATTR, 0]) + vd(vol, did) + H(0x0001) + H(10) + I(0) + I(4096) + path('file'),
          H(0) + I(20) + b'user.a\0com.apple.xx\0')
    s.cmd(bytes([LISTEXTATTR, 0]) + vd(vol, did) + H(0x0001) + H(10) + I(0) + I(0) + path('file'),
          H(1) + I(24))


def acls(s):
    vol, did = 1, 2
    uu, gu = bytes(range(16)), bytes(range(16, 32))
    def ace(i):
        return bytes([i]) * 16 + I(1 if i == 0 else 0x20 | i, 0x07ff0000 | i * 5)

    acl = I(2, 0) + ace(0) + ace(1)
    s.cmd(bytes([GETACL, 0]) + vd(vol, did) + H(0x1f) + I(4096) + path('file'), H(0x07) + uu + gu + acl)
    s.cmd(bytes([GETACL, 0]) + vd(vol, did) + H(0x01) + I(4096) + path('file'), H(0x01) + uu)
    s.cmd(bytes([GETACL, 0]) + vd(vol, did) + H(0x02) + I(4096) + path('file'), H(0x02) + gu)
    s.cmd(bytes([GETACL, 0]) + vd(vol, did) + H(0x04) + I(4096) + path('file'), H(0x04) + I(0, 0))
    s.cmd(bytes([GETACL, 0]) + vd(vol, did) + H(0x04) + I(4096) + path('file'), b'', ERR_ACCESS)
    b = bytes([SETACL, 0]) + vd(vol, did) + H(0x0017) + path('files')
    s.cmd(even(b) + uu + gu + I(1, 0) + ace(3), b'')
    b = bytes([SETACL, 0]) + vd(vol, did) + H(0x0008) + path('file')
    s.cmd(even(b), b'')
    b = bytes([ACCESS, 0]) + vd(vol, did) + H(0) + uu + I(0x00000001 | 0x04 | 0x80000000) + path('file')
    s.cmd(b, b'')


def spotlight(s):
    vol = 1
    flags = I(0)

    def req(cmd, rest=b''):
        return bytes([SPOTLIGHTRPC, 0]) + H(vol) + flags + I(cmd) + I(0) + rest

    # get volume path
    s.cmd(req(4, b'/Volumes/Share\0'), I(1) + I(0) + b'/srv/share\0')
    # get volume id
    s.cmd(req(2), I(0x00100000))
    # the search: request and reply in both byte orders
    for big in (True, False):
        q = sl_query(big)
        s.cmd(req(3, I(0x0020) + I(len(q)) + q), I(0) + sl_reply(big))
    # FileMeta with a nested blob
    for big in (True, False):
        q = sl_filemeta(big)
        s.cmd(req(3, I(0) + I(len(q)) + q), I(0) + sl_filemeta(big))
    # an unknown command
    s.cmd(req(9, bytes(4)), b'')


def odd_names(s):
    # a UTF-8 name offset that points into the offset field itself
    s.cmd([GETFORKPARAM, 0] + list(H(5) + H(F_U8)), H(F_U8) + H(1) + I(0x08000103) + H(3) + b'abc')
    # a path type that is none of the three
    s.cmd([DELETE, 0] + list(vd(1, 2) + bytes([9, 3]) + b'abc'), b'')


def misc(s):
    # a reply whose request was never captured
    s.reply(999, bytes([0]) * 4)
    # a no body reply for a command that normally has one, and reply data
    # that is longer than the dissector reads
    s.cmd([CLOSEVOL, 0, 0, 1], b'\xde\xad\xbe\xef')


def main_frames():
    s = Session()
    # DSI: GetStatus, OpenSession
    rid = s.request(b'', dsi_cmd=3, offset=0)
    s.reply(rid, server_status(), dsi_cmd=3)
    rid = s.request(b'', dsi_cmd=3)
    s.reply(rid, server_status(flags=0, full=False), dsi_cmd=3)
    # the offsets that follow a name of even length are aligned one by one
    for flags in (0x20, 0x100, 0x200):
        rid = s.request(b'', dsi_cmd=3)
        s.reply(rid, server_status(flags=flags), dsi_cmd=3)
    rid = s.request(bytes([1, 4]) + I(1024), dsi_cmd=4)
    s.reply(rid, bytes([0, 4]) + I(0x100000), dsi_cmd=4)
    # the Vol and Did of the comment request come from its own packet
    s.cmd([GETCMT, 0] + list(H(1) + I(2) + path('cmt')), pstr('first comment'))
    s.cmd([DELETE, 0] + list(vd(0x1234, 0x5678) + path('del')), b'')
    srv_params(s)
    login(s)
    volumes(s)
    files(s)
    dirs_and_names(s)
    enumerate_(s)
    catsearch(s)
    desktop(s)
    extattrs(s)
    acls(s)
    spotlight(s)
    odd_names(s)
    misc(s)
    rid = s.request(b'', dsi_cmd=1)
    s.reply(rid, b'', dsi_cmd=1)
    # a second connection that uses the request IDs of the first one: the
    # calls are told apart by connection
    s2 = Session(49154, nxt=7)
    s2.cmd([GETSRVPARAM, 0], I(0x2a000200) + bytes([1, 0x80]) + pstr('Other'))
    s2.cmd([CLOSEVOL, 0] + list(H(3)), b'')
    # UAM parameters of the UAMs that have them, and a login without a user
    # name (these were decoded with the UAM test inverted)
    s2.cmd(even(login_ext('Cleartxt passwrd', 2, 'LDAP')) + b'password', b'')
    s2.cmd(even(login_ext('DHCAST128', 2, 'LDAP')) + bytes(range(16)), b'')
    s2.cmd(even(login_ext('2-Way Randnum exchange', 1, 'dir')), b'')
    s2.cmd(bytes([LOGIN]) + pstr('AFP2.2') + pstr('No User Authent'), b'')
    s2.cmd(even(bytes([LOGIN]) + pstr('AFP2.2') + pstr('Cleartxt passwrd') + pstr('alice')) + b'secret\0\0', b'')
    return s.frames + s2.frames


def malformed_frames():
    s = Session(49153)
    f = s.frames
    # 1-2: a request ID that is reused for another command
    rid = s.cmd([DELETE, 0] + list(vd(1, 2) + path('x')), b'')
    s.request(bytes([CLOSEVOL, 0]) + H(1), reqid=rid)

    def item(n, t, w):
        return struct.pack('>Q', (n << 32) | t << 16 | w)

    def sl(blob):
        s.cmd(bytes([SPOTLIGHTRPC, 0]) + H(1) + I(0) + I(3) + I(0) + I(0) + I(len(blob)) + blob, None)

    z = struct.pack('>Q', 0)
    # Spotlight: a complex string whose inner length word is 0
    sl(Spotlight(True).build([('raw', item(1, SQ_COMPLEX, 1) + z + z)], toc_extra=[(CPX_STRING << 16) | 1]))
    # a complex item with a ToC index that is out of range
    sl(Spotlight(True).build([('raw', item(0x40000001, SQ_COMPLEX, 1) + z + z)], toc_extra=[(CPX_ARRAY << 16) | 1]))
    # ToC offset 0, query length 0, ToC offset past the end, query length past the end
    sl(b'md031234' + struct.pack('>Q', 0))
    sl(b'md031234' + struct.pack('>Q', 1 << 32))
    sl(b'md031234' + struct.pack('>Q', (0x40000000 << 32) | 4) + bytes(16))
    sl(b'md031234' + struct.pack('>Q', (1 << 32) | 0x80000000) + bytes(16))
    # a ToC that says it has no entries
    sl(Spotlight(True).build([('null', 1)], toccount=0))
    # NULL items with a subquery count above the query count, with a count
    # above 20, and a date count above the limit
    sl(Spotlight(True).build([('arr', [('null', 30)])]))
    sl(Spotlight(True).build([('arr', [('null', 25)] + [('bool', 1)] * 30)]))
    sl(Spotlight(True).build([('arr', [('date', list(range(1700000000, 1700000030)))])]))
    # an unknown type, then an item of length 0 that stops the loop
    sl(Spotlight(True).build([('raw', item(0, 0x1234, 1) + item(0, 0, 0))]))
    # little endian
    sl(Spotlight(False).build([('arr', [('null', 2)])]))
    # too many ACL entries
    s.cmd(bytes([GETACL, 0]) + vd(1, 2) + H(4) + I(4096) + path('file'), H(4) + I(501, 0) + bytes(24 * 2))
    # a server status cut short
    rid = s.request(b'', dsi_cmd=3)
    s.reply(rid, server_status()[:30], dsi_cmd=3)
    # truncated requests and replies
    s.cmd([GETFLDRPARAM, 0] + list(vd(1, 2)), b'')
    s.cmd([OPENVOL, 0], H(VOL_ALL) + b'\0')
    s.cmd([ENUMERATE, 0] + list(vd(1, 2) + H(F_FID) + H(0) + H(1) + H(1) + H(1) + path('f')),
          H(F_FID) + H(0) + H(3) + bytes([6, 0]) + bytes(4))
    s.cmd([CATSEARCH_EXT, 0] + list(H(1) + I(1, 0) + bytes(16) + H(0) + H(0) + I(0) + H(0xfffe) + bytes(4)), b'')
    s.cmd([MAPNAME, 5] + list(H(400)), b'')
    s.cmd([GETSESSTOKEN, 0] + list(H(1) + I(0x7fffffff)), b'')
    s.cmd([LISTEXTATTR, 0] + list(vd(1, 2) + H(1) + H(1) + I(0) + I(0) + path('f')), H(0) + I(0xffffffff))
    s.cmd([SETEXTATTR, 0] + list(vd(1, 2) + H(6) + Q(0) + path('f') + H(1) + b'a' + I(0xfffffff0)), b'')
    s.cmd([GETSRVPARAM, 0], I(0) + bytes([1, 0x80, 200]) + b'ab')
    return f


def write_malformed(path_, frames):
    """pcapng: the Ethernet frames, then an Exported PDU frame that hands
    data to the AFP dissector by name (it is not called by DSI then and
    refuses data it was not given)."""
    w = Pcapng()
    eth_if = w.interface(LINKTYPE_ETHERNET)
    exp_if = w.interface(LINKTYPE_WIRESHARK_UPPER_PDU)
    for i, fr in enumerate(frames):
        w.packet(eth_if, fr, ts=(1700000000 + i, 1000 * i))
    w.packet(exp_if, exported_pdu(bytes([GETSRVPARAM, 0]), proto='afp'), ts=(1700000000 + len(frames), 0))
    w.write(path_)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'afp-coverage.pcap'), main_frames())
    write_malformed(os.path.join(out, 'afp-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
