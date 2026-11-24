#!/usr/bin/env python3
# Generates test/captures/openwire_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OpenWire (ActiveMQ) coverage captures: mkopenwire.py <outdir>.
OpenWire has no default port. The TCP heuristic finds a connection from its
first PDU (WireFormatInfo, a KeepAlive or a Response), and the conversation
keeps the dissector. The commands use the loose encoding; stream 2 uses
caching (cached objects are sent inline and by id), stream 3 uses tight
encoding (not supported by the dissector, a note).

The encoder follows the field tables of dissect_openwire_command()."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from wslib import pcap, TCP, gz

# type codes of objects
QUEUE, TOPIC, TEMPQ, TEMPT = 100, 101, 102, 103
MSGID, LTX, XATX = 110, 111, 112
CONN, SESS, CONS, PROD, BROKER = 120, 121, 122, 123, 124
MSG, BYTES, MAPM, OBJM, STREAM, TEXT, BLOB = 23, 24, 25, 26, 27, 28, 29

class Enc:
    def __init__(self, caching=False):
        self.caching = caching
        self.cid = 0

    # ---- primitives
    def s(self, text, nullable=True):
        t = text.encode() if isinstance(text, str) else text
        if text is None:
            return b'\x00'
        return (b'\x01' if nullable else b'') + struct.pack('>H', len(t)) + t

    def S(self, text):
        return self.s(text, False)

    def b(self, v=1, nullable=False):
        return (b'\x01' if nullable else b'') + bytes([v])

    def i(self, v=1):
        return struct.pack('>I', v)

    def l(self, v=1):
        return struct.pack('>Q', v)

    def y(self, v=1, nullable=False):
        return (b'\x01' if nullable else b'') + bytes([v])

    # ---- objects, in the order the dissector reads their fields
    def body(self, tc):
        if tc == CONN or tc == BROKER:
            return self.s('ID:host-%d' % tc)
        if tc == SESS:
            return self.s('ID:host-120') + self.l(7)
        if tc in (CONS, PROD):
            return self.s('ID:host-120') + self.l(8) + self.l(9)
        if tc == MSGID:
            return self.cached(PROD) + self.l(42) + self.l(43)
        if tc == LTX:
            return self.l(99) + self.cached(CONN)
        if tc == XATX:
            return self.i(1) + b'\x01' + struct.pack('>I', 4) + b'gtrn' + b'\x01' + struct.pack('>I', 3) + b'bqu'
        if tc in (QUEUE, TOPIC, TEMPQ, TEMPT):
            return self.s('queue://test.%d' % tc)
        raise ValueError(tc)

    def obj(self, tc, null=False):
        """NESTED nullable object (also CACHED without caching)."""
        if null:
            return b'\x00'
        if tc in (MSG, BYTES, MAPM, OBJM, STREAM, TEXT, BLOB):
            return b'\x01' + bytes([tc]) + self.i(self.cid + 1) + b'\x01' + self.message(tc)
        return b'\x01' + bytes([tc]) + self.body(tc)

    def cached(self, tc, null=False, ref=None):
        if not self.caching:
            return self.obj(tc, null)
        if ref is not None:                        # a reference by id
            return b'\x00' + struct.pack('>H', ref)
        if null:
            return b'\x01' + b'\x00\x01' + b'\x00'
        return b'\x01' + struct.pack('>H', 1 + tc % 200) + b'\x01' + bytes([tc]) + self.body(tc)

    def oa(self, items=(), null=False):
        if null:
            return b'\x00'
        return b'\x01' + struct.pack('>H', len(items)) + b''.join(self.obj(t) for t in items)

    def throwable(self, depth=1, null=False, cause=True):
        if null:
            return b'\x00'
        out = b'\x01' + self.s('java.lang.Exception') + self.s('failure') + struct.pack('>H', depth)
        for k in range(depth):
            out += self.s('org.example.Cls%d' % k) + self.s('method') + self.s('Cls.java') + self.i(10 + k)
        if depth > 0:
            out += (self.throwable(0) if cause else b'\x00')
        return out

    def inner(self, null=False):
        if null:
            return b'\x00'
        return b'\x01' + bytes([30]) + self.i(5) + b'\x00' + self.i(77)       # an inner Response

    # ---- maps and message bodies
    def value(self, kind):
        if kind == 'bool': return b'\x01' + b'\x01'
        if kind == 'byte': return b'\x02' + b'\x05'
        if kind == 'char': return b'\x03' + b'\x00A'
        if kind == 'short': return b'\x04' + struct.pack('>H', 7)
        if kind == 'int': return b'\x05' + self.i(12345)
        if kind == 'long': return b'\x06' + self.l(1 << 40)
        if kind == 'double': return b'\x07' + struct.pack('>d', 1.5)
        if kind == 'float': return b'\x08' + struct.pack('>f', 2.5)
        if kind == 'string': return b'\x09' + self.S('text value')
        if kind == 'bytes': return b'\x0a' + struct.pack('>I', 3) + b'abc'
        if kind == 'map': return b'\x0b' + self.map([('inner', 'int')])
        if kind == 'null': return b'\x00'
        if kind == 'bigstring': return b'\x0d' + struct.pack('>I', 5) + b'large'
        raise ValueError(kind)

    def map(self, entries):
        return struct.pack('>I', len(entries)) + b''.join(self.S(k) + self.value(v) for k, v in entries)

    ALL = ['bool', 'byte', 'char', 'short', 'int', 'long', 'double', 'float', 'string', 'bytes', 'map', 'null', 'bigstring']

    def message(self, mt, body=None, props=None, with_prefix=True):
        """Message fields. For the top-level message commands the command id
        and response flag are already in the command header."""
        out = b''
        if with_prefix:
            out += b''
        out += self.cached(PROD) + self.cached(QUEUE) + self.cached(LTX) + self.cached(QUEUE, null=True)
        out += self.obj(MSGID) + self.cached(QUEUE, null=True)
        out += self.s('group-1') + self.i(3) + self.s('corr-1') + self.b(1)
        out += self.l(0) + self.y(4) + self.obj(QUEUE) + self.l(1700000000000) + self.s('type')
        if body is None:
            body = b''
            if mt == TEXT:
                body = struct.pack('>I', 11) + b'hello world'
            elif mt == MAPM:
                body = self.map([('a', 'int'), ('b', 'string')])
            elif mt == STREAM:
                body = self.value('int') + self.value('string') + self.value('bool')
            elif mt in (BYTES, OBJM, BLOB):
                body = b'\xac\xed\x00\x05payload'
        out += (b'\x01' + struct.pack('>I', len(body)) + body) if body is not False else b'\x00'
        if props is None:
            props = self.map([('JMSXGroupID', 'string'), ('count', 'int')])
        out += (b'\x01' + struct.pack('>I', len(props)) + props) if props is not False else b'\x00'
        out += self.inner(True) + self.cached(CONS, null=True)
        out += self.b(0) + self.i(0) + self.oa([BROKER]) + self.l(0) + self.s('user') + self.b(0) + self.b(1)
        out += self.oa([BROKER, BROKER]) + self.l(1) + self.l(2)
        return out

def msg_cmd(code, payload, cid=1, resp=1):
    p = bytes([code]) + struct.pack('>I', cid) + bytes([resp]) + payload
    return struct.pack('>I', len(p)) + p

def wireformat(version=12, extra=None):
    mp = Enc().map(extra or [('CacheEnabled', 'bool'), ('TightEncodingEnabled', 'bool'), ('MaxInactivityDuration', 'long'),
                             ('StackTraceEnabled', 'bool'), ('TcpNoDelayEnabled', 'bool')])
    p = b'\x01' + b'ActiveMQ' + struct.pack('>I', version) + b'\x01' + struct.pack('>I', len(mp)) + mp
    return struct.pack('>I', len(p)) + p

def commands(e):
    """One frame payload per command, covering the whole field table."""
    f = []
    f.append(msg_cmd(10, b'', 2, 0))                                           # KeepAlive
    f.append(msg_cmd(3, e.cached(CONN) + e.s('client-1') + e.s('pw') + e.s('user') + e.oa([BROKER]) + e.b(0) + e.b(1) + e.b(0) + e.b(1) + e.b(0), 3))
    f.append(msg_cmd(3, e.cached(CONN) + e.s(None) + e.s(None) + e.s(None) + e.oa(null=True) + e.b(0) + e.b(0) + e.b(0) + e.b(0) + e.b(0), 4))
    f.append(msg_cmd(4, e.cached(SESS), 5))                                      # SessionInfo
    f.append(msg_cmd(4, e.cached(SESS, null=True), 6))
    f.append(msg_cmd(8, e.cached(CONN) + e.cached(QUEUE) + e.y(0) + e.l(0) + e.oa([BROKER]), 7))   # DestinationInfo
    f.append(msg_cmd(8, e.cached(CONN) + e.cached(TOPIC) + e.y(1) + e.l(5000) + e.oa(null=True), 8))
    f.append(msg_cmd(5, e.cached(CONS) + e.b(0) + e.cached(QUEUE) + e.i(1000) + e.i(0) + e.b(1) + e.s('JMSType = 1') + e.s('sub') +
                     e.b(0) + e.b(0) + e.b(0) + e.y(5, True) + e.oa([BROKER]) + e.obj(TOPIC) + e.b(0) + e.b(1) + e.b(0) + e.oa([CONS]), 9))
    f.append(msg_cmd(5, e.cached(CONS) + e.b(1) + e.cached(TEMPQ) + e.i(1) + e.i(1) + e.b(0) + e.s(None) + e.s(None) +
                     e.b(1) + e.b(1) + e.b(1) + e.b(0, True)[:0] + b'\x00' + e.oa(null=True) + b'\x00' + e.b(0) + e.b(0) + e.b(0) + e.oa(null=True), 10))
    f.append(msg_cmd(6, e.cached(PROD) + e.cached(QUEUE) + e.oa([BROKER]) + e.b(1) + e.i(65536), 11))   # ProducerInfo
    f.append(msg_cmd(6, e.cached(PROD) + e.cached(TEMPT) + e.oa(null=True) + e.b(0) + e.i(0), 12))
    f.append(msg_cmd(17, e.obj(QUEUE) + e.b(0) + e.obj(CONS) + e.i(10) + e.b(1) + e.b(0) + e.b(1), 13))   # ConsumerControl
    f.append(msg_cmd(17, e.obj(QUEUE, True) + e.b(0) + e.obj(CONS, True) + e.i(0) + e.b(0) + e.b(0) + e.b(0), 14))
    f.append(msg_cmd(18, e.b(1, True) + e.b(0) + e.b(1) + e.b(0) + e.b(1) + e.s('tcp://a:1,tcp://b:2') + e.s('tcp://c:3') + e.b(1), 15))   # ConnectionControl
    f.append(msg_cmd(18, b'\x00' + e.b(0) + e.b(0) + e.b(0) + e.b(0) + e.s(None) + e.s(None) + e.b(0), 16))
    f.append(msg_cmd(2, e.cached(BROKER) + e.s('tcp://broker:61616') + e.oa([]) + e.s('broker1') + e.b(0) + e.b(1) + e.b(0) + e.b(0) + e.b(1)
                     + e.l(3) + e.s('http://broker/upload') + e.s('k=v'), 17))   # BrokerInfo
    for ttype in range(7):                                                         # TransactionInfo, all types
        f.append(msg_cmd(7, e.cached(CONN) + (e.cached(LTX) if ttype % 2 == 0 else e.cached(XATX)) + e.y(ttype), 18 + ttype))
    f.append(msg_cmd(7, e.cached(CONN) + e.cached(LTX), 30))                      # without the type octet
    f.append(msg_cmd(19, e.obj(PROD) + e.i(1024), 31))                             # ProducerAck
    f.append(msg_cmd(12, e.cached(CONS) + e.l(77), 32))                            # RemoveInfo
    f.append(msg_cmd(9, e.cached(CONN) + e.s('durable-1') + e.s('client-1'), 33))  # RemoveSubscriptionInfo
    f.append(msg_cmd(21, e.cached(CONS) + e.cached(QUEUE) + e.obj(TEXT) + e.i(0), 34))   # MessageDispatch with a text message
    f.append(msg_cmd(21, e.cached(CONS) + e.cached(QUEUE) + e.obj(MAPM) + e.i(1), 35))
    f.append(msg_cmd(21, e.cached(CONS) + e.cached(QUEUE) + e.obj(MSG, True) + e.i(0), 36))
    f.append(msg_cmd(22, e.cached(QUEUE) + e.cached(LTX, null=True) + e.cached(CONS) + e.y(2) + e.obj(MSGID) + e.obj(MSGID) + e.i(5), 37))   # MessageAck
    f.append(msg_cmd(20, e.cached(CONS) + e.cached(QUEUE) + e.l(1000) + e.s('corr') + e.obj(MSGID), 38))   # MessagePull
    f.append(msg_cmd(30, e.i(5), 39, 0))                                           # Response
    f.append(msg_cmd(32, e.i(6) + e.inner(), 40, 0))                               # DataResponse
    f.append(msg_cmd(32, e.i(6) + e.inner(True), 41, 0))
    f.append(msg_cmd(31, e.i(7) + e.throwable(2), 42, 0))                          # ExceptionResponse with a stack trace
    f.append(msg_cmd(31, e.i(8) + e.throwable(0), 43, 0))
    f.append(msg_cmd(31, e.i(8) + e.throwable(null=True), 44, 0))
    f.append(msg_cmd(16, e.throwable(1) + e.obj(CONN), 45, 0))                     # ConnectionError
    f.append(msg_cmd(14, e.s('shutdown'), 46))                                     # ControlCommand
    f.append(msg_cmd(15, b'', 47))                                                 # FlushCommand
    f.append(msg_cmd(11, b'', 48))                                                 # ShutdownInfo
    f.append(msg_cmd(40, b'\x01\x02\x03', 49))                                     # command that is not supported
    # the seven message types as commands
    for mt in (MSG, BYTES, MAPM, OBJM, STREAM, TEXT, BLOB):
        f.append(msg_cmd(mt, e.message(mt), 50 + mt))
    # message variations: no body or properties, a large map of all value types, a stream of all value types
    f.append(msg_cmd(TEXT, e.message(TEXT, body=False, props=False), 80))
    f.append(msg_cmd(MAPM, e.message(MAPM, body=e.map([('k%d' % n, k) for n, k in enumerate(Enc.ALL)])), 81))
    f.append(msg_cmd(STREAM, e.message(STREAM, body=b''.join(e.value(k) for k in Enc.ALL)), 82))
    f.append(msg_cmd(MSG, e.message(MSG, body=False, props=e.map([('x', 'int')])), 83))
    f.append(msg_cmd(MAPM, e.message(MAPM, body=e.map([('nested', 'map')])), 84))
    f.append(msg_cmd(30, e.i(9), 85, 0))
    return f

def main(out):
    fr = []
    # stream 1: loose encoding, no caching
    c = TCP('192.0.2.1', 40700, '192.0.2.2', 61616)
    fr += c.handshake()
    e = Enc()
    fr.append(c.c2s(wireformat()))
    fr.append(c.s2c(wireformat(extra=[('CacheEnabled', 'bool')])))
    cmds = commands(e)
    for k, m in enumerate(cmds):
        fr.append(c.c2s(m) if k % 3 else c.s2c(m))
    # two commands in one segment; a big one over three segments
    fr.append(c.c2s(msg_cmd(10, b'', 90, 0) + msg_cmd(30, e.i(1), 91, 0)))
    big = msg_cmd(TEXT, e.message(TEXT, body=struct.pack('>I', 3000) + b'x' * 3000), 92)
    fr.append(c.c2s(big[:7]))
    fr.append(c.c2s(big[7:1500]))
    fr.append(c.c2s(big[1500:]))
    # stream 2: caching
    c2 = TCP('192.0.2.1', 40701, '192.0.2.3', 61616)
    fr += c2.handshake()
    e2 = Enc(caching=True)
    fr.append(c2.c2s(wireformat()))
    cm = commands(e2)
    for k, m in enumerate(cm):
        fr.append(c2.c2s(m) if k % 3 else c2.s2c(m))
    # references by cached id
    fr.append(c2.c2s(msg_cmd(4, e2.cached(SESS, ref=5), 200)))
    fr.append(c2.c2s(msg_cmd(5, e2.cached(CONS, ref=3) + e2.b(0) + e2.cached(QUEUE, ref=2) + e2.i(1) + e2.i(1) + e2.b(0) + e2.s(None) + e2.s(None) +
                             e2.b(0) + e2.b(0) + e2.b(0) + e2.y(0, True) + e2.oa(null=True) + e2.obj(TOPIC, True) + e2.b(0) + e2.b(0) + e2.b(0) + e2.oa(null=True), 201)))
    # stream 3: tight encoding (11 octet KeepAlive), commands are not decoded
    c3 = TCP('192.0.2.1', 40702, '192.0.2.4', 61616)
    fr += c3.handshake()
    ka = struct.pack('>I', 7) + bytes([10]) + struct.pack('>I', 1) + b'\x00' + b'\x00'
    fr.append(c3.c2s(ka))
    fr.append(c3.c2s(struct.pack('>I', 20) + bytes([3]) + struct.pack('>I', 2) + b'\x00' + bytes(14)))
    fr.append(c3.s2c(struct.pack('>I', 11) + bytes([30]) + struct.pack('>I', 2) + b'\x00' + struct.pack('>I', 2) + b'\x00'))
    # stream 4: starts with a 14 octet Response; a command id above 2**24 means tight encoding
    c4 = TCP('192.0.2.1', 40703, '192.0.2.5', 61616)
    fr += c4.handshake()
    fr.append(c4.c2s(msg_cmd(30, e.i(1), 1, 0)))
    fr.append(c4.c2s(msg_cmd(4, e.cached(SESS), 0x02000001)))
    fr.append(c4.c2s(msg_cmd(30, e.i(2), 0x02000002, 0)))
    # stream 5: not OpenWire (nothing for the heuristic to find: other lengths, wrong command, wrong magic)
    c5 = TCP('192.0.2.1', 40704, '192.0.2.6', 61616)
    fr += c5.handshake()
    fr.append(c5.c2s(struct.pack('>I', 7) + bytes([10, 0, 0, 0, 1, 0])))             # 10 octets, KeepAlive length mismatch
    fr.append(c5.c2s(struct.pack('>I', 9) + bytes([30, 0, 0, 0, 1, 0, 0, 0, 1])))      # 13 octets: Response but not 14
    fr.append(c5.c2s(struct.pack('>I', 16) + bytes([30]) + bytes(15)))                 # 20 octets: no magic
    fr.append(c5.c2s(struct.pack('>I', 9) + bytes([1]) + b'ActiveXX' ))                # wrong magic
    pcap(os.path.join(out, 'openwire-coverage.pcap'), fr)
    gz(os.path.join(out, 'openwire-coverage.pcap'))
    pcap(os.path.join(out, 'openwire-coverage-malformed.pcap'), malformed())

def malformed():
    fr = []
    e = Enc()
    c = TCP('192.0.2.1', 40710, '192.0.2.2', 61616)
    fr += c.handshake()
    fr.append(c.c2s(wireformat()))
    # bad booleans (2 and 255)
    fr.append(c.c2s(msg_cmd(18, b'\x01\x02' + e.b(0) + e.b(0) + e.b(0) + e.b(0) + e.s(None) + e.s(None) + e.b(0), 300)))
    fr.append(c.c2s(msg_cmd(30, e.i(1), 301, 255)))
    fr.append(c.c2s(msg_cmd(3, e.cached(CONN) + e.s('c') + e.s('p') + e.s('u') + e.oa([]) + e.b(0) + e.b(7) + e.b(0) + e.b(0) + e.b(0), 302)))
    # an object type the dissector does not know, in an array and as a nested value
    fr.append(c.c2s(msg_cmd(3, e.cached(CONN) + e.s('c') + e.s('p') + e.s('u') + b'\x01\x00\x01' + b'\x01\x99' + b'\x01\x02\x03\x04' + e.b(0) + e.b(0) + e.b(0) + e.b(0) + e.b(0), 303)))
    # truncated commands: every field table cut in the middle
    for m in commands(e)[:60:3]:
        cut = max(10, len(m) - 7)
        fr.append(c.c2s(struct.pack('>I', cut - 4) + m[4:cut]))
    # a command with extra octets at the end, and one that is too short for the command fields
    fr.append(c.c2s(msg_cmd(30, e.i(1) + b'extra', 304, 0)))
    fr.append(c.c2s(struct.pack('>I', 6) + bytes([30]) + b'\x00\x00\x00\x01\x00'[:5]))
    # unknown stream value type in a map message and in a stream message
    fr.append(c.c2s(msg_cmd(STREAM, e.message(STREAM, body=b'\x63\x00\x01'), 305)))
    fr.append(c.c2s(msg_cmd(MAPM, e.message(MAPM, body=struct.pack('>I', 3) + e.S('k') + b'\x63'), 306)))
    # a map with a length larger than its content; a string longer than the data
    fr.append(c.c2s(msg_cmd(MAPM, e.message(MAPM, body=struct.pack('>I', 5000) + e.S('k') + e.value('int')), 307)))
    fr.append(c.c2s(msg_cmd(14, b'\x01\xff\xff' + b'abc', 308)))
    # object array with a huge count, throwable with a deep stack trace count
    fr.append(c.c2s(msg_cmd(6, e.cached(PROD) + e.cached(QUEUE) + b'\x01\xff\xff' + e.obj(BROKER), 309)))
    fr.append(c.c2s(msg_cmd(31, e.i(1) + b'\x01\x01\x00\x01a\x01\x00\x01b\xff\xff', 310, 0)))
    # byte array length larger than the data
    fr.append(c.c2s(msg_cmd(TEXT, e.message(TEXT)[:-60] + struct.pack('>I', 1 << 30), 311)))
    return fr

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
