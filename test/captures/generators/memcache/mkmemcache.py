#!/usr/bin/env python3
# Generates test/captures/memcache_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Memcache dissector
(packet-memcache.c: the binary protocol and the text protocol).

Memcache is registered by default on TCP and UDP port 11211.  The first
octet decides: 0x80/0x81 is the binary protocol, anything else the text
protocol.  Every packet is built with struct; nothing comes from a real
network (192.0.2.0/24).

Usage: mkmemcache.py <output directory>
  memcache-coverage.pcap            text and binary protocol over TCP
                                    (with reassembly) and UDP: every
                                    command and response, key/extras/value
                                    rules of every binary opcode, statuses
  memcache-coverage-malformed.pcap  invalid text lines and binary frames
"""
import os
import struct
import sys

CMAC = bytes.fromhex('020000000001')
SMAC = bytes.fromhex('020000000002')
CIP = bytes([192, 0, 2, 1])
SIP = bytes([192, 0, 2, 2])


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip_frame(proto, l4, c2s=True, ipid=[1]):
    sip, dip = (CIP, SIP) if c2s else (SIP, CIP)
    smac, dmac = (CMAC, SMAC) if c2s else (SMAC, CMAC)
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(l4), ipid[0], 0x4000, 64, proto, 0) + sip + dip
    ipid[0] += 1
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return dmac + smac + b'\x08\x00' + ip + l4


def udp(payload, c2s=True, cport=40300, sport=11211):
    sp, dp = (cport, sport) if c2s else (sport, cport)
    l4 = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    return ip_frame(17, l4, c2s)


class Tcp:
    def __init__(self, frames, cport, sport=11211):
        self.f, self.cport, self.sport = frames, cport, sport
        self.cseq, self.sseq = 100, 900

    def seg(self, c2s, flags, payload=b''):
        opts = b''
        if flags & 2:
            opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1)
        if c2s:
            sp, dp, seq, ack = self.cport, self.sport, self.cseq, self.sseq
        else:
            sp, dp, seq, ack = self.sport, self.cport, self.sseq, self.cseq
        if flags == 2:
            ack = 0
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        sip, dip = (CIP, SIP) if c2s else (SIP, CIP)
        ph = sip + dip + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        self.f.append(ip_frame(6, t, c2s))
        n = len(payload) + (1 if flags & 3 else 0)
        if c2s:
            self.cseq += n
        else:
            self.sseq += n

    def handshake(self):
        self.seg(True, 2)
        self.seg(False, 0x12)
        self.seg(True, 0x10)

    def data(self, c2s, payload):
        self.seg(c2s, 0x18, payload)
        self.seg(not c2s, 0x10)


# ---------------------------------------------------------------- binary
OPS = dict(GET=0x00, SET=0x01, ADD=0x02, REPLACE=0x03, DELETE=0x04, INCR=0x05,
           DECR=0x06, QUIT=0x07, FLUSH=0x08, GETQ=0x09, NOOP=0x0a, VERSION=0x0b,
           GETK=0x0c, GETKQ=0x0d, APPEND=0x0e, PREPEND=0x0f, STAT=0x10,
           SETQ=0x11, ADDQ=0x12, REPLACEQ=0x13, DELETEQ=0x14, INCRQ=0x15,
           DECRQ=0x16, QUITQ=0x17, FLUSHQ=0x18, APPENDQ=0x19, PREPENDQ=0x1a)


def bin_msg(op, key=b'', extras=b'', value=b'', request=True, status=0, opaque=0,
            cas=0, magic=None, body_len=None, dtype=0, keylen=None):
    if magic is None:
        magic = 0x80 if request else 0x81
    if body_len is None:
        body_len = len(extras) + len(key) + len(value)
    if keylen is None:
        keylen = len(key)
    return struct.pack('>BBHBBHIIQ', magic, op, keylen, len(extras), dtype,
                       status, body_len, opaque, cas) + extras + key + value


FLAGS_EXP = struct.pack('>II', 0xdeadbeef, 3600)
FLAGS = struct.pack('>I', 0x12345678)
DELTA = struct.pack('>QQI', 5, 100, 0)


def binary_messages():
    """Valid requests and responses of every opcode (key, extras, value as
    the protocol requires), then the cases with a status."""
    m = []
    k, v = b'user:42', b'hello world'
    for name in ('GET', 'GETQ', 'GETK', 'GETKQ'):
        op = OPS[name]
        m.append(bin_msg(op, key=k, opaque=op))
        resp_key = k if name.startswith('GETK') else b''
        m.append(bin_msg(op, key=resp_key, extras=FLAGS, value=v, request=False, cas=7, opaque=op))
    for name in ('SET', 'ADD', 'REPLACE', 'SETQ', 'ADDQ', 'REPLACEQ'):
        op = OPS[name]
        m.append(bin_msg(op, key=k, extras=FLAGS_EXP, value=v, cas=3, opaque=op))
        m.append(bin_msg(op, request=False, cas=9, opaque=op))
    for name in ('APPEND', 'PREPEND', 'APPENDQ', 'PREPENDQ'):
        op = OPS[name]
        m.append(bin_msg(op, key=k, value=b'-more', opaque=op))
        m.append(bin_msg(op, request=False, cas=10, opaque=op))
    for name in ('DELETE', 'DELETEQ'):
        op = OPS[name]
        m.append(bin_msg(op, key=k, opaque=op))
        m.append(bin_msg(op, request=False, opaque=op))
    for name in ('INCR', 'DECR', 'INCRQ', 'DECRQ'):
        op = OPS[name]
        m.append(bin_msg(op, key=b'counter', extras=DELTA, opaque=op))
        m.append(bin_msg(op, value=struct.pack('>Q', 105), request=False, opaque=op))
    for name in ('FLUSH', 'FLUSHQ'):
        op = OPS[name]
        m.append(bin_msg(op, opaque=op))
        m.append(bin_msg(op, extras=struct.pack('>I', 30), opaque=op))
        m.append(bin_msg(op, request=False, opaque=op))
    for name in ('QUIT', 'QUITQ', 'NOOP'):
        op = OPS[name]
        m.append(bin_msg(op, opaque=op))
        m.append(bin_msg(op, request=False, opaque=op))
    m.append(bin_msg(OPS['VERSION']))
    m.append(bin_msg(OPS['VERSION'], value=b'1.6.21', request=False))
    m.append(bin_msg(OPS['STAT']))
    m.append(bin_msg(OPS['STAT'], key=b'pid', value=b'1234', request=False))
    m.append(bin_msg(OPS['STAT'], key=b'items', request=True))
    m.append(bin_msg(OPS['STAT'], request=False))
    # statuses: with a body, each known status, an unknown status, a status without body
    for st in (1, 2, 3, 4, 5, 0x81, 0x82):
        m.append(bin_msg(OPS['GET'], value=b'error text %d' % st, request=False, status=st))
    m.append(bin_msg(OPS['SET'], value=b'unknown status', request=False, status=0x1234))
    m.append(bin_msg(OPS['GET'], request=False, status=1))
    # an opcode that is not defined, with and without extras, as request and response
    m.append(bin_msg(0x55, key=b'k', extras=b'\x01\x02\x03\x04', value=b'v'))
    m.append(bin_msg(0x55, key=b'k', value=b'v', request=False))
    # a datatype other than raw bytes
    m.append(bin_msg(OPS['SET'], key=k, extras=FLAGS_EXP, value=b'{}', dtype=1))
    # a large value
    m.append(bin_msg(OPS['SET'], key=b'big', extras=FLAGS_EXP, value=bytes(range(256)) * 12))
    return m


def binary_illegal():
    """Combinations the dissector flags (expert warnings, still decoded)."""
    m = []
    k, v = b'user:42', b'hello'
    m.append(bin_msg(OPS['GET'], key=k, extras=b'\x00' * 4))                 # request with extras
    m.append(bin_msg(OPS['GET'], key=k, value=v))                             # request with value
    m.append(bin_msg(OPS['GET'], request=False, value=v))                     # response without extras
    m.append(bin_msg(OPS['GET']))                                             # request without key
    m.append(bin_msg(OPS['SET'], key=k, value=v))                             # request without extras
    m.append(bin_msg(OPS['SET'], key=k, extras=FLAGS_EXP))                    # request without value
    m.append(bin_msg(OPS['SET'], key=k, extras=FLAGS_EXP, value=v, request=False))  # response with all
    m.append(bin_msg(OPS['INCR'], key=k, value=b'x'))                         # increment without extras, with value
    m.append(bin_msg(OPS['INCR'], key=k, extras=DELTA, request=True, value=b'x'))
    m.append(bin_msg(OPS['INCR'], extras=DELTA, request=False, value=struct.pack('>Q', 1)))
    m.append(bin_msg(OPS['DELETE'], key=k, extras=b'\x00' * 4, value=v))
    m.append(bin_msg(OPS['DELETE'], request=False, key=k))
    m.append(bin_msg(OPS['QUIT'], key=k, extras=b'\x00' * 4, value=v))
    m.append(bin_msg(OPS['VERSION'], key=k, extras=b'\x00' * 4))
    m.append(bin_msg(OPS['NOOP'], key=k, value=v))
    m.append(bin_msg(OPS['STAT'], extras=b'\x00' * 4))
    m.append(bin_msg(OPS['APPEND'], key=k, extras=b'\x00' * 4))
    m.append(bin_msg(OPS['FLUSH'], key=k, value=v))
    m.append(bin_msg(OPS['SET'], request=True, status=5, key=k, extras=FLAGS_EXP, value=v))   # reserved field not 0
    m.append(bin_msg(OPS['FLUSH'], extras=b'\x00' * 8))                        # extras longer than the expiration
    m.append(bin_msg(OPS['SET'], key=k, extras=FLAGS_EXP + b'\x00' * 4, value=v))  # extras longer than flags and expiration
    return m


def binary_exceptions():
    """Frames that end in an exception."""
    m = []
    m.append(bin_msg(OPS['SET'], extras=b'\x01\x02\x03', value=b'v'))         # extras shorter than the flags
    m.append(bin_msg(OPS['INCR'], value=b'1234', request=False))              # response value not 8 octets
    m.append(bin_msg(OPS['GET'], key=b'k', body_len=2, keylen=8))              # key longer than the body
    m.append(bin_msg(OPS['GET'], request=False, extras=FLAGS, body_len=2))     # body shorter than the extras
    m.append(bin_msg(OPS['SET'], key=b'k', extras=FLAGS_EXP, value=b'v', body_len=0))
    return m


# ---------------------------------------------------------------- text
def text_requests():
    r = []
    r.append(b'set key1 0 0 5\r\nhello\r\n')
    r.append(b'set key2 123 3600 11 noreply\r\nhello world\r\n')
    r.append(b'add key3 0 0 3\r\nabc\r\n')
    r.append(b'replace key1 1 2 4\r\nnew1\r\n')
    r.append(b'append key1 0 0 2\r\n!!\r\n')
    r.append(b'prepend key1 0 0 2\r\n>>\r\n')
    r.append(b'cas key1 0 0 3 987654321\r\nabc\r\n')
    r.append(b'cas key1 0 0 3 987654321 noreply\r\nabc\r\n')
    r.append(b'set empty 0 0 0\r\n\r\n')
    r.append(b'get key1\r\n')
    r.append(b'get key1 key2 key3\r\n')
    r.append(b'gets key1 key2\r\n')
    r.append(b'delete key1\r\n')
    r.append(b'delete key1 10\r\n')
    r.append(b'delete key1 noreply\r\n')
    r.append(b'incr counter 5\r\n')
    r.append(b'incr counter 5 noreply\r\n')
    r.append(b'decr counter 3\r\n')
    r.append(b'stats\r\n')
    r.append(b'stats items\r\n')
    r.append(b'flush_all\r\n')
    r.append(b'flush_all 10\r\n')
    r.append(b'flush_all noreply\r\n')
    r.append(b'flush_all 10 noreply\r\n')
    r.append(b'version\r\n')
    r.append(b'quit\r\n')
    return r


def text_responses():
    r = []
    for w in (b'STORED', b'NOT_STORED', b'EXISTS', b'NOT_FOUND', b'DELETED', b'OK', b'END'):
        r.append(w + b'\r\n')
    r.append(b'VALUE key1 0 5\r\nhello\r\nEND\r\n')
    r.append(b'VALUE key1 5 5\r\nhello\r\nVALUE key2 0 11\r\nhello world\r\nEND\r\n')
    r.append(b'VALUE key1 0 5 12345\r\nhello\r\nEND\r\n')
    r.append(b'VALUE key1 0 5 12345\r\nhello\r\nVALUE key2 7 3 99\r\nabc\r\nEND\r\n')
    r.append(b'VERSION 1.6.21\r\n')
    r.append(b'STAT pid 1234\r\nSTAT uptime 5\r\nSTAT version 1.6.21\r\nEND\r\n')
    r.append(b'STAT items:1:number 5\r\nSTAT items:1:age 100\r\nSTAT items:2:number 7\r\nEND\r\n')
    r.append(b'STAT 1:chunk_size 96\r\nSTAT 1:chunks_per_page 10922\r\nSTAT active_slabs 1\r\nEND\r\n')
    r.append(b'VALUE key1 0 0\r\n\r\nEND\r\n')
    return r


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    f = []
    # ---- text over TCP: requests and responses in separate segments
    t = Tcp(f, 40201)
    t.handshake()
    for r in text_requests():
        t.data(True, r)
    for r in text_responses():
        t.data(False, r)
    # reassembly: the header split, a data block split, header and data in two segments
    t.data(True, b'get ke')
    t.data(True, b'y1\r\n')
    t.data(True, b'set big 0 0 3000\r\n')
    t.data(True, b'x' * 1400)
    t.data(True, b'y' * 1600 + b'\r\n')
    t.data(True, b'set split 0 0 10\r\n01234')
    t.data(True, b'56789\r\n')
    t.data(False, b'VALUE big 0 3000\r\n' + b'z' * 1200)
    t.data(False, b'z' * 1800 + b'\r\nEND\r\n')
    # two commands in one segment, a command and a continuation
    t.data(True, b'get a\r\nget b\r\n')
    t.data(True, b'set pipe 0 0 2\r\nab\r\nget pipe\r\n')
    # unknown line (continuation), blank lines
    t.data(True, b'hello there\r\n')
    # the huge length reproducers (content length + 2 wrapped around)
    t.data(True, b'set huge 0 0 4294967295\r\nabc\r\n')
    t.data(False, b'VALUE huge 0 4294967295\r\nabc\r\n')
    # ---- the gets response with a cas unique (the fix) over UDP
    f.append(udp(b'gets foo\r\n'))
    f.append(udp(b'VALUE foo 0 3 12345\r\nabc\r\nEND\r\n', c2s=False))
    for r in text_requests()[:12]:
        f.append(udp(r))
    for r in text_responses()[:12]:
        f.append(udp(r, c2s=False))
    # ---- binary over TCP
    b = Tcp(f, 40202)
    b.handshake()
    msgs = binary_messages()
    for i, mm in enumerate(msgs):
        b.data(mm[0] == 0x80, mm)
    # two binary PDUs in one segment, one PDU over two segments
    b.data(True, bin_msg(OPS['GET'], key=b'a') + bin_msg(OPS['GET'], key=b'b'))
    big = bin_msg(OPS['SET'], key=b'split', extras=FLAGS_EXP, value=b'v' * 100)
    b.data(True, big[:30])
    b.data(True, big[30:])
    for mm in binary_illegal():
        b.data(mm[0] == 0x80, mm)
    # ---- binary over UDP
    for mm in msgs[:20]:
        f.append(udp(mm, c2s=mm[0] == 0x80))
    for mm in binary_illegal()[:6]:
        f.append(udp(mm))
    # an increment response whose value is not 8 octets, with octets after it in the datagram
    f.append(udp(bin_msg(OPS['INCR'], value=b'abcd', request=False) + b'trailing', c2s=False))
    pcap(os.path.join(out, 'memcache-coverage.pcap'), f)

    # ---- malformed / invalid
    g = []
    t = Tcp(g, 40203)
    t.handshake()
    for r in (b'set\r\n', b'set key\r\n', b'set key 0\r\n', b'set key 0 0\r\n',
              b'set key 123456 0 5\r\nhello\r\n',            # flags too long
              b'set key 0 12345678901 5\r\nhello\r\n',      # exptime too long
              b'set key 0 0 12345678901\r\n',                # bytes too long
              b'cas key 0 0 3\r\nabc\r\n',                   # cas without unique
              b'cas key 0 0 3 123456789012345678901\r\nabc\r\n',
              b'incr\r\n', b'incr key\r\n', b'incr key 5 bogus\r\n', b'incr key 5 noreply extra\r\n',
              b'delete\r\n', b'delete key 12345678901\r\n', b'delete key 10 bogus\r\n',
              b'stats a b\r\n', b'flush_all 12345678901\r\n', b'flush_all 10 bogus\r\n',
              b'version extra\r\n', b'quit now\r\n', b'get\r\n'):
        t.data(True, r)
    for r in (b'VALUE\r\n', b'VALUE key\r\n', b'VALUE key 0\r\n', b'VALUE key 123456 5\r\nhello\r\nEND\r\n',
              b'VALUE key 0 12345678901\r\n', b'VALUE key 0 5 123456789012345678901\r\nhello\r\n',
              b'VALUE key 0 5 1 extra\r\nhello\r\n', b'BOGUS key 0 5\r\n',
              b'VERSION\r\n', b'VERSION 1.0 extra\r\n',
              b'STAT\r\n', b'STAT pid\r\nEND\r\n', b'STAT a:b:c:d 1\r\nEND\r\n', b'STAT items:99999999999:x 1\r\nEND\r\n',
              b'STAT :x 1\r\nEND\r\n', b'STAT 99999999999:x 1\r\nEND\r\n', b'STAT items:1:x\r\nEND\r\n',
              b'STAT items:1:x 1\r\nJUNK\r\n', b'STAT 1:x\r\nEND\r\n', b'STAT 1:\r\nEND\r\n', b'STAT items::x 1\r\nEND\r\n',
              b'STAT pid 1\r\n', b'STAT 1:x 1 extra\r\nEND\r\n'):
        t.data(False, r)
    # a request that cannot be decoded, a data block shorter than announced
    t.data(True, b'set short 0 0 50\r\nabc')
    t.data(True, b'set neg 0 0 abc\r\n')
    t.data(False, b'VALUE k 0 5\r\nhello\r\n\r\n')
    t.data(False, b'VALUE \r\n')
    t.data(False, b'VERSION  \r\n')
    b = Tcp(g, 40204)
    b.handshake()
    for mm in binary_exceptions():
        b.data(mm[0] == 0x80, mm)
    # a binary frame with a body length of 0xffffffff (the length wrapped around)
    b.data(True, bin_msg(OPS['GET'], key=b'k', body_len=0xffffffff))
    b.data(True, bin_msg(OPS['GET'], key=b'k', body_len=0xfffffff0))
    # the same over UDP
    for mm in binary_exceptions():
        g.append(udp(mm, c2s=mm[0] == 0x80, cport=40205))
    # an unknown magic over UDP and TCP is the text protocol
    g.append(udp(b'\x7f\x00\x00\x00', cport=40206))
    # a binary frame shorter than the header
    g.append(udp(bin_msg(OPS['GET'], key=b'k')[:20], cport=40207))
    pcap(os.path.join(out, 'memcache-coverage-malformed.pcap'), g)


if __name__ == '__main__':
    main()
