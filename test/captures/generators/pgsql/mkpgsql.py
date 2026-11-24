#!/usr/bin/env python3
# Generates test/captures/pgsql_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the PostgreSQL (packet-pgsql.c) coverage captures.
Usage: mkpgsql.py <outdir>
Everything is built with struct; there are no keys or ciphertext. The GSS-API
frames carry made-up, unsealed or opaque (all zero) tokens."""
import struct
import sys
import os

pk = struct.pack
frames = []          # all frames of the capture being built
T0 = [1700000000]

class Conn:
    """One TCP connection, client port cport, server port 5432 (or sport)."""
    n = 0
    def __init__(self, out, cport=None, sport=5432, v6=False):
        Conn.n += 1
        self.out = out
        self.cport = cport or 40000 + Conn.n
        self.sport = sport
        self.cip = bytes([192, 0, 2, 10 + Conn.n])
        self.sip = bytes([192, 0, 2, 1])
        self.cseq = 1000
        self.sseq = 5000
        self.ipid = 1
        self.syn()

    def _tcp(self, srv, flags, payload, seq=None, ack=None):
        if srv:
            sp, dp, s, a = self.sport, self.cport, self.sseq, self.cseq
            sip, dip, smac, dmac = self.sip, self.cip, 2, 1
        else:
            sp, dp, s, a = self.cport, self.sport, self.cseq, self.sseq
            sip, dip, smac, dmac = self.cip, self.sip, 1, 2
        if seq is not None: s = seq
        tcp = pk('>HHIIBBHHH', sp, dp, s, a, 0x50, flags, 65535, 0, 0) + payload
        ip = pk('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ipid, 0, 64, 6, 0, sip, dip)
        self.ipid += 1
        eth = bytes([2, 0, 0, 0, 0, dmac, 2, 0, 0, 0, 0, smac]) + b'\x08\x00'
        pkt = eth + ip + tcp
        T0[0] += 1
        self.out.append((T0[0], pkt))

    def syn(self):
        self._tcp(False, 0x02, b'')
        self.cseq += 1
        self._tcp(True, 0x12, b'')
        self.sseq += 1
        self._tcp(False, 0x10, b'')

    def send(self, srv, payload):
        self._tcp(srv, 0x18, payload)
        if srv: self.sseq += len(payload)
        else: self.cseq += len(payload)

    def c(self, *msgs): self.send(False, b''.join(msgs))
    def s(self, *msgs): self.send(True, b''.join(msgs))

def M(t, body=b''):
    return t + pk('>I', 4 + len(body)) + body

def z(s):
    return s.encode() + b'\0'

def startup(params, ver=0x30000, term=True):
    b = pk('>I', ver)
    for k, v in params:
        b += z(k) + z(v)
    if term: b += b'\0'
    return pk('>I', 4 + len(b)) + b

def row_desc(fields):
    b = pk('>H', len(fields))
    for name, toid, col, typ, tlen, mod, fmt in fields:
        b += z(name) + pk('>IhIhih', toid, col, typ, tlen, mod, fmt)
    return M(b'T', b)

def data_row(cols):
    b = pk('>H', len(cols))
    for c in cols:
        if c is None: b += pk('>i', -1)
        else: b += pk('>i', len(c)) + c
    return M(b'D', b)

def error(kind, fields):
    b = b''.join(k.encode() + z(v) for k, v in fields) + b'\0'
    return M(kind, b)

def auth(t, extra=b''):
    return M(b'R', pk('>I', t) + extra)

# logical replication ---------------------------------------------------
def xlog(logical, ws=0x1000, we=0x2000):
    return M(b'd', b'w' + pk('>QQQ', ws, we, 0x2b5c7e9a1f40) + logical)

def keepalive(reply=1):
    return M(b'd', b'k' + pk('>QQB', 0x3000, 0x2b5c7e9a1f40, reply))

def tdata(cols):
    """cols: list of None (NULL), 'u' (unchanged), ('t', b), ('b', b)"""
    b = pk('>H', len(cols))
    for c in cols:
        if c is None: b += b'n'
        elif c == 'u': b += b'u'
        else: b += c[0].encode() + pk('>I', len(c[1])) + c[1]
    return b

TS = 0x2b5c7e9a1f40
def lmsg(t, body): return t.encode() + body

class Out:
    def __init__(self): self.f = []

def write_pcap(fname, fl):
    out = [pk('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
    for ts, pkt in fl:
        out.append(pk('<IIII', ts, 0, len(pkt), len(pkt)) + pkt)
    open(fname, 'wb').write(b''.join(out))

def pcapng_block(t, body):
    body += bytes(-len(body) % 4)
    return pk('<II', t, len(body) + 12) + body + pk('<I', len(body) + 12)

def write_pcapng(fname, fl, expdu=()):
    """Ethernet frames on interface 0, Exported PDU frames (name, payload)
    on interface 1."""
    out = [pcapng_block(0x0A0D0D0A, pk('<IHHq', 0x1A2B3C4D, 1, 0, -1)),
           pcapng_block(1, pk('<HHI', 1, 0, 65535)),
           pcapng_block(1, pk('<HHI', 252, 0, 65535))]
    allf = [(ts, 0, p) for ts, p in fl]
    t = fl[-1][0] + 1
    for name, payload in expdu:
        nm = name.encode(); nm += bytes(-len(nm) % 4)
        hdr = pk('>HH', 12, len(nm)) + nm + pk('>HH', 0, 0)
        allf.append((t, 1, hdr + payload)); t += 1
    for ts, ifc, p in allf:
        out.append(pcapng_block(6, pk('<IIIII', ifc, (ts * 1000000) >> 32, (ts * 1000000) & 0xffffffff, len(p), len(p)) + p))
    open(fname, 'wb').write(b''.join(out))

def tls_client_hello():
    ext = b''
    body = pk('>H', 0x0303) + bytes(32) + b'\0' + pk('>H', 2) + pk('>H', 0x1301) + b'\1\0' + pk('>H', len(ext)) + ext
    hs = b'\x01' + pk('>I', len(body))[1:] + body
    return b'\x16\x03\x01' + pk('>H', len(hs)) + hs

def ntlm_negotiate():
    return b'NTLMSSP\0' + pk('<IIHHIHHI', 1, 0x00088207, 0, 0, 0, 0, 0, 0)

def gss_wrap_token(payload, sealed, ec=0):
    """RFC 4121 WRAP token header (no OID header), then payload and a fixed
    12 byte filler for the checksum. Not encrypted."""
    flags = 0x02 if sealed else 0x00
    return pk('>HBBHHQ', 0x0504, flags, 0xff, ec, 0, 7) + payload + bytes(12)

def build_main(f):
    # --- 1. Plain connection: SSL refused, startup, MD5 auth, queries ----
    c = Conn(f)
    c.c(pk('>II', 8, 80877103))                                  # SSLRequest
    c.s(b'N')                                                    # refused
    c.c(startup([('user', 'alice'), ('database', 'shop'), ('application_name', 'psql'),
                 ('client_encoding', 'UTF8')]))
    c.s(auth(5, b'\x01\x02\x03\x04'))                            # MD5 + salt
    c.c(M(b'p', z('md5' + 'a' * 32)))                            # password
    c.s(auth(0),                                                 # success
        M(b'S', z('server_version') + z('16.2')),
        M(b'S', z('client_encoding') + z('UTF8')),
        M(b'K', pk('>II', 4242, 0xdeadbeef)),
        M(b'Z', b'I'))
    c.c(M(b'Q', z('SELECT id, name, price FROM items WHERE price > 10')))
    c.s(row_desc([('id', 16385, 1, 23, 4, -1, 0), ('name', 16385, 2, 25, -1, -1, 0),
                  ('price', 16385, 3, 1700, -1, 0x00060002, 1)]),
        data_row([b'1', b'widget', b'12.50']),
        data_row([b'2', b'', b'0.00']),                           # empty value
        M(b'C', z('SELECT 2')),
        M(b'Z', b'I'))
    # extended protocol, several messages in one segment
    c.c(M(b'P', z('stmt1') + z('SELECT $1::int, $2::text') + pk('>HII', 2, 23, 25)),
        M(b'B', z('portal1') + z('stmt1') + pk('>HHH', 2, 0, 1) + pk('>H', 2) +
          pk('>i', 2) + b'42' + pk('>i', -1) + pk('>HHH', 2, 0, 1)),
        M(b'D', b'P' + z('portal1')),
        M(b'E', z('portal1') + pk('>I', 0)),
        M(b'S'))
    c.s(M(b'1'), M(b'2'),
        M(b'T', pk('>H', 0)), M(b'n'),
        M(b'D', pk('>H', 0)),
        M(b'C', z('SELECT 1')), M(b'Z', b'T'))
    c.c(M(b'D', b'S' + z('stmt1')), M(b'E', z('portal1') + pk('>I', 5)), M(b'H'))
    c.s(M(b't', pk('>HII', 2, 23, 25)), M(b'T', pk('>H', 0)), M(b's'), M(b'3'))
    c.c(M(b'C', b'S' + z('stmt1')), M(b'C', b'P' + z('portal1')), M(b'S'))
    c.s(M(b'3'), M(b'3'), M(b'I'), M(b'Z', b'E'))
    # asynchronous messages, error and notice with every field code
    c.s(M(b'A', pk('>I', 4243) + z('events') + z('hello')),
        M(b'A', pk('>I', 4243) + z('events') + z('')))
    fields = [('S', 'ERROR'), ('V', 'ERROR'), ('C', '23505'),
              ('M', 'duplicate key value violates unique constraint'),
              ('D', 'Key (id)=(1) already exists.'), ('H', 'use another id'),
              ('P', '15'), ('p', '3'), ('q', 'SELECT 1'), ('W', 'SQL statement'),
              ('s', 'public'), ('t', 'items'), ('c', 'id'), ('d', 'int4'),
              ('n', 'items_pkey'), ('F', 'nbtinsert.c'), ('L', '666'), ('R', '_bt_check_unique')]
    c.s(error(b'E', fields))
    c.s(error(b'N', [('S', 'NOTICE'), ('C', '00000'), ('M', 'table does not exist, skipping')]))
    c.s(error(b'E', []))                                          # empty error
    # function call and response
    c.c(M(b'F', pk('>IH', 1299, 1) + pk('>H', 0) + pk('>H', 2) + pk('>i', 4) + pk('>I', 7) +
          pk('>i', -1) + pk('>H', 1)))
    c.s(M(b'V', pk('>i', 4) + pk('>I', 99)), M(b'V', pk('>i', 0)), M(b'Z', b'I'))
    # copy
    c.c(M(b'Q', z("COPY items TO STDOUT")))
    c.s(M(b'H', pk('>BHHHH', 0, 3, 0, 0, 1)),
        M(b'd', b'1\twidget\t12.50\n'),
        M(b'c'), M(b'C', z('COPY 1')), M(b'Z', b'I'))
    c.c(M(b'Q', z("COPY items FROM STDIN")))
    c.s(M(b'G', pk('>BHH', 0, 1, 0)))
    c.c(M(b'd', b'3\tgadget\t1.00\n'), M(b'c'))
    c.c(M(b'f', z('abort copy')))
    c.s(M(b'W', pk('>BHH', 1, 1, 1)))
    c.s(M(b'Z', b'I'))
    # negotiate protocol version
    c.c(startup([('user', 'bob'), ('_pq_.test', 'on')], ver=0x30002))
    c.s(M(b'v', pk('>II', 0, 2) + z('_pq_.test') + z('_pq_.other')),
        M(b'v', pk('>II', 2, 0)))
    # segmented message: type+length split, then the rest
    q = M(b'Q', z('SELECT now()'))
    c.send(False, q[:3]); c.send(False, q[3:])
    c.c(M(b'X'))
    # unknown message types in both directions
    c.c(M(b'x', b'abc'))
    c.s(M(b'y', b'abc'))
    # a segment with a non-printable first byte, no PGSQL in it
    c.s(b'\x01\x02\x03')

    # --- 2. Other authentication methods ---------------------------------
    c = Conn(f)
    c.c(startup([('user', 'carol'), ('database', 'x')], ver=0x30000))
    c.s(auth(3))                                                  # plaintext
    c.c(M(b'p', z('secret')))
    c.s(auth(4, b'ab'))                                           # crypt, salt 2
    c.s(auth(2), auth(6), auth(1))                                # krb5, scm, krb4
    c.s(auth(0), M(b'Z', b'I'))

    # SASL (SCRAM) exchange
    c = Conn(f)
    c.c(startup([('user', 'dave')]))
    c.s(auth(10, z('SCRAM-SHA-256-PLUS') + z('SCRAM-SHA-256') + b'\0'))
    cfm = b'n,,n=,r=fyko+d2lbbFgONRv9qkxdawL'
    c.c(M(b'p', z('SCRAM-SHA-256') + pk('>i', len(cfm)) + cfm))   # initial response
    c.s(auth(11, b'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096'))
    c.c(M(b'p', b'c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j'))
    c.s(auth(12, b'v=rmF9pqV8S7suAoZWja4dJRkFsKQ='))
    c.s(auth(0), M(b'Z', b'I'))
    c.s(auth(11))                                                 # empty continue
    c.s(auth(12))
    # SASL initial response without data
    c = Conn(f)
    c.c(startup([('user', 'dave')]))
    c.s(auth(10, z('SCRAM-SHA-256') + b'\0'))
    c.c(M(b'p', z('SCRAM-SHA-256') + pk('>i', 0)))

    # GSSAPI / SSPI authentication
    c = Conn(f)
    c.c(startup([('user', 'erin@EXAMPLE.COM')]))
    c.s(auth(7))
    c.c(M(b'p', b'\x60\x06\x06\x02\x2a\x03' + b'\0\1\2\3'))      # GSS response
    c.c(M(b'p', gss_wrap_token(b'inner data', False)))            # CFX wrap token
    c.s(auth(8, b'\xa1\x03\x0a\x01\x00' + b'\0' * 4))             # GSS continue
    c.c(M(b'p', ntlm_negotiate()))                                # NTLMSSP
    c.s(auth(9))                                                  # SSPI
    c.c(M(b'p', b'\x60\x06\x06\x02\x2a\x03'))
    c.s(auth(0), M(b'Z', b'I'))

    # --- 3. SSLRequest accepted, then TLS ---------------------------------
    c = Conn(f)
    c.c(pk('>II', 8, 80877103))
    c.s(b'S')
    c.c(tls_client_hello())
    # SSLRequest answered by an ErrorResponse (server without SSL)
    c = Conn(f)
    c.c(pk('>II', 8, 80877103))
    c.s(error(b'E', [('S', 'FATAL'), ('M', 'SSL is not supported')]))
    c.c(startup([('user', 'x')]))
    # SSLRequest with an unexpected answer
    c = Conn(f)
    c.c(pk('>II', 8, 80877103))
    c.s(b'?')
    # direct SSL: the client starts with a TLS ClientHello
    c = Conn(f)
    c.c(tls_client_hello())

    # --- 4. GSSENCRequest ------------------------------------------------
    c = Conn(f)
    c.c(pk('>II', 8, 80877104))
    c.s(b'G')
    for srv, payload in ((False, M(b'Q', z('SELECT 1'))), (True, M(b'Z', b'I'))):
        tok = gss_wrap_token(payload, False)
        c.send(srv, pk('>I', len(tok)) + tok)                       # signed only
    tok = gss_wrap_token(bytes(48), True)
    c.send(False, pk('>I', len(tok)) + tok)                         # sealed, no key
    tok = gss_wrap_token(b'', False)
    c.send(True, pk('>I', len(tok)) + tok)                          # no payload
    # GSSENCRequest refused / error
    c = Conn(f)
    c.c(pk('>II', 8, 80877104))
    c.s(b'N')
    c.c(startup([('user', 'x')]))
    c = Conn(f)
    c.c(pk('>II', 8, 80877104))
    c.s(error(b'E', [('S', 'FATAL'), ('M', 'GSSAPI is not supported')]))
    c = Conn(f)
    c.c(pk('>II', 8, 80877104))
    c.s(b'!')

    # --- 5. CancelRequest and a startup with an unknown version -----------
    c = Conn(f)
    c.c(pk('>IIII', 16, 80877102, 4242, 0xdeadbeef))
    c = Conn(f)
    c.c(startup([('user', 'x')], ver=0x20000))                      # not v3
    c.c(startup([('user', 'x'), ('database', 'y')], term=False))    # no final NUL
    c.c(pk('>II', 12, 0x30000) + b'\0\0\0\0')                       # empty params
    c.c(pk('>II', 8, 0x30000))                                      # no params
    c.c(pk('>II', 13, 0x30000) + z('user'))                         # name without value

    # --- 6. Replication: XLogData with every logical message ---------------
    c = Conn(f)
    c.c(startup([('user', 'repl'), ('replication', 'database'), ('database', 'shop')]))
    c.s(auth(0), M(b'Z', b'I'))
    c.c(M(b'Q', z('START_REPLICATION SLOT s LOGICAL 0/0')))
    c.s(M(b'W', pk('>BH', 0, 0)))
    c.s(keepalive(1), keepalive(0))
    cols = [('t', b'42'), ('b', b'\x00\x01'), None, 'u']
    rel = lmsg('R', pk('>I', 16384) + z('public') + z('items') + b'd' + pk('>H', 2) +
               b'\x01' + z('id') + pk('>Ii', 23, -1) +
               b'\x00' + z('name') + pk('>Ii', 25, -1))
    c.s(xlog(lmsg('B', pk('>QQI', 0x5000, TS, 801))),
        xlog(rel),
        xlog(lmsg('Y', pk('>I', 16500) + z('public') + z('mood'))),
        xlog(lmsg('I', pk('>I', 16384) + b'N' + tdata(cols))),
        xlog(lmsg('U', pk('>I', 16384) + b'N' + tdata([('t', b'43'), ('t', b'x')]))),
        xlog(lmsg('U', pk('>I', 16384) + b'K' + tdata([('t', b'42')]) + b'N' + tdata([('t', b'43'), ('t', b'y')]))),
        xlog(lmsg('U', pk('>I', 16384) + b'O' + tdata([('t', b'42'), None]) + b'N' + tdata([('t', b'43'), 'u']))),
        xlog(lmsg('D', pk('>I', 16384) + b'K' + tdata([('t', b'43')]))),
        xlog(lmsg('D', pk('>I', 16384) + b'O' + tdata([('t', b'43'), ('b', b'ab')]))),
        xlog(lmsg('T', pk('>IB', 2, 3) + pk('>II', 16384, 16385))),
        xlog(lmsg('M', b'\x01' + pk('>Q', 0x5100) + z('myprefix') + pk('>i', 5) + b'hello')),
        xlog(lmsg('O', pk('>Q', 0x5200) + z('origin1'))),
        xlog(lmsg('C', b'\x00' + pk('>QQQ', 0x5300, 0x5400, TS))))
    # prepared transaction messages
    gid = z('gid-1')
    c.s(xlog(lmsg('b', pk('>QQQI', 0x6000, 0x6100, TS, 802) + gid)),
        xlog(lmsg('P', b'\x00' + pk('>QQQI', 0x6000, 0x6100, TS, 802) + gid)),
        xlog(lmsg('K', b'\x00' + pk('>QQQI', 0x6000, 0x6100, TS, 802) + gid)),
        xlog(lmsg('r', b'\x00' + pk('>QQQQI', 0x6100, 0x6200, TS, TS + 1000, 802) + gid)))
    # streamed transactions: Start, messages with an xid, Stop, in one
    # segment and in separate ones
    c.s(xlog(lmsg('S', pk('>IB', 900, 1))),
        xlog(lmsg('R', pk('>II', 900, 16384) + z('public') + z('items') + b'd' + pk('>H', 1) +
                  b'\x01' + z('id') + pk('>Ii', 23, -1))),
        xlog(lmsg('Y', pk('>II', 900, 16500) + z('public') + z('mood'))),
        xlog(lmsg('I', pk('>II', 900, 16384) + b'N' + tdata([('t', b'1')]))),
        xlog(lmsg('U', pk('>II', 900, 16384) + b'N' + tdata([('t', b'2')]))),
        xlog(lmsg('D', pk('>II', 900, 16384) + b'K' + tdata([('t', b'2')]))),
        xlog(lmsg('T', pk('>IIB', 900, 1, 0) + pk('>I', 16384))),
        xlog(lmsg('M', pk('>I', 900) + b'\x00' + pk('>Q', 0x7000) + z('p') + pk('>i', 2) + b'hi')),
        xlog(lmsg('E', b'')))
    c.s(xlog(lmsg('I', pk('>I', 16384) + b'N' + tdata([('t', b'3')]))))   # not streamed again
    c.s(xlog(lmsg('S', pk('>IB', 901, 0))))
    c.s(xlog(lmsg('I', pk('>II', 901, 16384) + b'N' + tdata([('t', b'4')]))))
    c.s(xlog(lmsg('E', b'')))
    c.s(xlog(lmsg('c', pk('>IBQQQ', 900, 0, 0x7100, 0x7200, TS))),
        xlog(lmsg('A', pk('>II', 901, 902))),
        xlog(lmsg('A', pk('>II', 901, 902) + pk('>QQ', 0x7300, TS))),
        xlog(lmsg('p', b'\x00' + pk('>QQQI', 0x7400, 0x7500, TS, 903) + z('gid-2'))))
    # physical replication WAL data: unknown logical type
    c.s(xlog(b'\x7f\x00\x01\x02\x03'))
    # copy data from the server that is neither XLogData nor keepalive
    c.s(M(b'd', b'Zunknown copy data'))
    # frontend copy data: standby status, hot standby feedback, other
    c.c(M(b'd', b'r' + pk('>QQQQB', 0x3000, 0x3000, 0x3000, TS, 0)),
        M(b'd', b'h' + pk('>QIIII', TS, 700, 1, 650, 1)),
        M(b'd', b'?other'))
    c.c(M(b'c'))
    c.s(M(b'c'), M(b'C', z('COPY 0')), M(b'Z', b'I'))

def build_malformed(f):
    # Error/Notice with every field code. The dissector skips one byte
    # after each field (see README), so each field is followed by a pad byte
    # to get the field codes dispatched; not realistic data.
    c = Conn(f)
    c.c(startup([('user', 'x')]))
    c.s(auth(0), M(b'Z', b'I'))
    fl = [('S', 'ERROR'), ('C', '23505'), ('M', 'dup'), ('D', 'detail'), ('H', 'hint'),
          ('P', '15'), ('p', '3'), ('q', 'SELECT 1'), ('W', 'where'), ('s', 'public'),
          ('t', 'items'), ('c', 'id'), ('d', 'int4'), ('n', 'pkey'), ('F', 'file.c'),
          ('L', '666'), ('R', 'routine'), ('V', 'ERROR')]
    c.s(M(b'E', b''.join(k.encode() + z(v) + b'x' for k, v in fl) + b'\0'))
    c.s(M(b'N', b''.join(k.encode() + z(v) + b'x' for k, v in fl) + b'\0'))
    c = Conn(f)
    c.c(startup([('user', 'x')]))
    c.s(auth(0), M(b'Z', b'I'))
    # truncated messages (length field larger than the data is reassembly;
    # these have a length that is too small for the contents)
    c.s(M(b'T', pk('>H', 3) + z('a')))                 # row description cut short
    c.s(M(b'D', pk('>H', 2) + pk('>i', 10) + b'ab'))   # data row cut short
    c.s(data_row([b'1', None, b'x']))                  # NULL column: length read as unsigned
    c.s(M(b'V', pk('>i', -1)))                         # NULL function result, same
    c.s(xlog(lmsg('D', pk('>I', 16384))))              # delete without a tuple
    c.s(M(b'R'))                                       # auth request without type
    c.s(M(b'K', b'\0\0'))
    c.s(M(b'Z'))
    c.s(M(b'v', pk('>II', 1, 5) + z('x')))             # more options than present
    c.s(M(b'E', b'S' + b'ERROR'))                      # field without terminator
    c.s(M(b'A', b'\0\0'))
    c.s(M(b'H', pk('>BH', 0, 9) + b'\0\0'))
    c.s(M(b'V', pk('>i', 100) + b'ab'))
    c.s(M(b'd', b'w' + pk('>Q', 1)))                   # XLogData cut short
    c.s(M(b'd', b'k'))
    c.s(xlog(lmsg('R', pk('>I', 16384) + b'public')))
    c.s(xlog(lmsg('I', pk('>I', 16384) + b'N' + pk('>H', 5) + b't')))
    c.s(xlog(lmsg('B', b'\0\0')))
    c.s(xlog(lmsg('T', pk('>IB', 50, 0) + b'\0\0\0\1')))
    c.c(M(b'Q', b'unterminated'))
    c.c(M(b'P', z('s') + z('q') + pk('>H', 9) + b'\0\0'))
    c.c(M(b'B', z('p') + z('s') + pk('>H', 9) + b'\0\0'))
    c.c(M(b'E', b'abc'))
    c.c(M(b'F', b'\0\0\0\1'))
    c.c(M(b'D'))
    c.c(M(b'p'))
    c.c(M(b'd', b'r' + b'\0' * 5))
    c.c(M(b'd', b'h'))
    c.c(pk('>II', 8, 0x30000)[:7])                      # short startup (truncated capture)
    # a non-printable byte in the middle of the stream, after PGSQL was seen
    c.s(b'\x01\x02\x03\x04\x05\x06')
    c.c(b'\x00\x00\x00\x01\x80')
    # absurd lengths wrap to zero in the PDU length callback
    c.s(b'Z' + pk('>I', 0xfffffffc))
    c.s(b'\x00\xff\xff\xff\xff\x00\x00\x00\x00')
    # GSS wrap with no complete token
    g = Conn(f)
    g.c(pk('>II', 8, 80877104)); g.s(b'G')
    g.c(pk('>I', 6) + b'\xff\xff\xff\xff\xff\xff')       # not a GSS token
    g.c(pk('>I', 40) + b'\x05\x04')                      # truncated
    g.s(pk('>I', 0xffffffff) + b'abcd')
    # truncated SASL and GSS auth
    s = Conn(f)
    s.c(startup([('user', 'x')]))
    s.s(auth(10, z('SCRAM-SHA-256') + b'\0'))
    s.c(M(b'p', z('SCRAM-SHA-256') + pk('>i', -1)))       # no initial response
    s.c(M(b'p', z('SCRAM-SHA-256') + pk('>i', 100) + b'ab'))
    s.c(M(b'p', b'noterm'))
    s.s(auth(11, b'ab'))
    s.s(auth(8, b'ab'))
    s.s(auth(5, b'ab'))
    s.s(auth(10, b'abc'))

def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    f = []; build_main(f)
    tok = gss_wrap_token(M(b'Q', z('SELECT 3')), False)
    write_pcapng(os.path.join(out, 'pgsql-coverage.pcapng'), f, [
        ('pgsql.gssapi', pk('>I', len(tok)) + tok),
        ('pgsql', startup([('user', 'x')])),
        ('pgsql', M(b'Q', z('SELECT 2')))])
    T0[0] = 1700100000
    f = []; build_malformed(f)
    write_pcap(os.path.join(out, 'pgsql-coverage-malformed.pcap'), f)

main()
