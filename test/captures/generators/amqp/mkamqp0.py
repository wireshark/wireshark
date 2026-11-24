#!/usr/bin/env python3
# Generates test/captures/amqp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the AMQP 0-8, 0-9, 0-9-1 and
0-10 parts of the AMQP dissector (packet-amqp.c).

All packets are built from scratch with struct; no captured traffic is
used. Clients in 10.0.0.0/24 talk to brokers in 10.0.0.0/24 on TCP port
5672 (the AMQP 1.0 coverage capture uses 10.1.0.0/24, so the two can be
merged with mergecap -a).

Usage: mkamqp0.py <output directory>

Writes:
  amqp0-coverage.pcap            every class, method, content header
                                 property, field table type, 0-10
                                 control, command and struct, split and
                                 joined frames, channel and delivery
                                 tracking (frame ranges in the README)
  amqp0-coverage-malformed.pcap  paths that end in an exception or an
                                 error expert info, bad packing flags,
                                 and structured random frames in the
                                 style of fuzz_amqp09.py and
                                 fuzz_amqp010.py (fixed seeds)
"""

import random
import struct
import sys

AMQP_PORT = 5672


def ip(last):
    return (10, 0, 0, last)


# --------------------------------------------------------------------------
# pcap writer (Ethernet / IPv4 / TCP)

def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, src, dst, sport, dport, seq, ack, flags, payload=b''):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''  # MSS, SACK permitted
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', ip_checksum(pseudo + hdr + payload)) + hdr[18:]
        l4 = hdr + payload
        assert 20 + len(l4) <= 65535
        iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                          0x4000, 64, 6, 0, bytes(src), bytes(dst))
        iph = iph[:10] + struct.pack('>H', ip_checksum(iph)) + iph[12:]
        eth = b'\x02\x00\x00\x00\x00' + bytes([dst[3]]) + b'\x02\x00\x00\x00\x00' + bytes([src[3]]) + b'\x08\x00'
        self.frames.append(eth + iph + l4)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class TcpStream:
    """A TCP connection from a client to a broker with correct sequence
    numbers. handshake=False starts it in the middle, as if the capture
    had been started late."""
    def __init__(self, cap, client, broker, cport, handshake=True):
        self.cap, self.client, self.broker, self.cport = cap, client, broker, cport
        self.cseq, self.sseq = 1000 + cport, 500000 + cport
        if handshake:
            cap.tcp(client, broker, cport, AMQP_PORT, self.cseq, 0, 0x02)
            cap.tcp(broker, client, AMQP_PORT, cport, self.sseq, self.cseq + 1, 0x12)
            self.cseq += 1
            self.sseq += 1
            cap.tcp(client, broker, cport, AMQP_PORT, self.cseq, self.sseq, 0x10)

    def c(self, *datas):
        """Send each argument as one TCP segment from the client."""
        for data in datas:
            self.cap.tcp(self.client, self.broker, self.cport, AMQP_PORT, self.cseq, self.sseq, 0x18, data)
            self.cseq += len(data)

    def s(self, *datas):
        """Send each argument as one TCP segment from the broker."""
        for data in datas:
            self.cap.tcp(self.broker, self.client, AMQP_PORT, self.cport, self.sseq, self.cseq, 0x18, data)
            self.sseq += len(data)

    def close(self):
        self.cap.tcp(self.client, self.broker, self.cport, AMQP_PORT, self.cseq, self.sseq, 0x11)
        self.cseq += 1
        self.cap.tcp(self.broker, self.client, AMQP_PORT, self.cport, self.sseq, self.cseq, 0x11)
        self.sseq += 1
        self.cap.tcp(self.client, self.broker, self.cport, AMQP_PORT, self.cseq, self.sseq, 0x10)


def split(data, *cuts):
    """Split data at the given offsets, for PDUs spread over segments."""
    out, last = [], 0
    for c in cuts:
        out.append(data[last:c])
        last = c
    return out + [data[last:]]


def chunks(data, size):
    return [data[i:i + size] for i in range(0, len(data), size)]


def u8(v):  return struct.pack('>B', v)
def u16(v): return struct.pack('>H', v)
def u32(v): return struct.pack('>I', v)
def u64(v): return struct.pack('>Q', v)
def i8(v):  return struct.pack('>b', v)
def i16(v): return struct.pack('>h', v)
def i32(v): return struct.pack('>i', v)
def i64(v): return struct.pack('>q', v)


def b(v):
    return v.encode() if isinstance(v, str) else v


def bits(*flags):
    """Pack AMQP bit arguments into one octet, first argument in bit 0."""
    v = 0
    for n, f in enumerate(flags):
        if f:
            v |= 1 << n
    return u8(v)


# --------------------------------------------------------------------------
# AMQP 0-9 encoding

def sstr(v):
    v = b(v)
    return u8(len(v)) + v


def lstr(v):
    v = b(v)
    return u32(len(v)) + v


def table(*entries):
    """Field table from (name, value) pairs; values are made by fv_*()."""
    body = b''.join(sstr(n) + v for n, v in entries)
    return u32(len(body)) + body


def fv_I(v):  return b'I' + i32(v)
def fv_D(scale, v): return b'D' + u8(scale) + u32(v)
def fv_S(v):  return b'S' + lstr(v)
def fv_T(v):  return b'T' + u64(v)
def fv_F(*entries): return b'F' + table(*entries)
def fv_V():   return b'V'
def fv_t(v):  return b't' + u8(v)
def fv_b(v):  return b'b' + i8(v)
def fv_B(v):  return b'B' + u8(v)
def fv_s(v):  return b's' + i16(v)
def fv_u(v):  return b'u' + u16(v)
def fv_i(v):  return b'i' + u32(v)
def fv_l(v):  return b'l' + i64(v)
def fv_f(v):  return b'f' + struct.pack('>f', v)
def fv_d(v):  return b'd' + struct.pack('>d', v)
def fv_x(v):  return b'x' + lstr(v)


def fv_A(*values):
    body = b''.join(values)
    return b'A' + u32(len(body)) + body


def every_type_table():
    """A field table with every field type, nested tables and arrays."""
    return table(
        ('product', fv_S('SyntheticMQ')),
        ('version', fv_S('0.9.1-test')),
        ('int32', fv_I(-123456)),
        ('decimal', fv_D(2, 31415)),
        ('timestamp', fv_T(1700000000)),
        ('capabilities', fv_F(('publisher_confirms', fv_t(1)),
                              ('exchange_exchange_bindings', fv_t(1)),
                              ('basic.nack', fv_t(1)),
                              ('consumer_cancel_notify', fv_t(0)),
                              ('nested', fv_F(('depth', fv_B(2)))))),
        ('void', fv_V()),
        ('bool', fv_t(1)),
        ('int8', fv_b(-5)),
        ('uint8', fv_B(250)),
        ('int16', fv_s(-30000)),
        ('uint16', fv_u(65000)),
        ('uint32', fv_i(4000000000)),
        ('int64', fv_l(-9000000000000)),
        ('float', fv_f(1.5)),
        ('double', fv_d(-2.25)),
        ('array', fv_A(fv_S('a'), fv_I(7), fv_A(fv_t(0), fv_V()), fv_F(('k', fv_S('v'))))),
        ('empty_array', fv_A()),
        ('empty_table', fv_F()),
        ('bytes', fv_x(b'\x00\x01\x02\xff')),
    )


def frame09(ftype, ch, payload):
    return u8(ftype) + u16(ch) + u32(len(payload)) + payload + b'\xce'


def method(ch, cls, mth, args=b''):
    return frame09(1, ch, u16(cls) + u16(mth) + args)


def header(ch, cls, body_size, flags, props, weight=0):
    return frame09(2, ch, u16(cls) + u16(weight) + u64(body_size) + u16(flags) + props)


def body(ch, data):
    return frame09(3, ch, b(data))


def heartbeat():
    return frame09(8, 0, b'')


CONNECTION, CHANNEL, ACCESS, EXCHANGE, QUEUE, BASIC = 10, 20, 30, 40, 50, 60
FILE, STREAM, TX, DTX, TUNNEL, CONFIRM = 70, 80, 90, 100, 110, 85


def basic_props(content_type=None, all_props=False, headers=None):
    """Basic content header property flags and list. all_props sets every
    one of the 14 properties."""
    if not all_props:
        if content_type is None:
            return 0x1000, u8(2)   # only delivery-mode
        return 0x8000, sstr(content_type)
    props = (sstr(content_type or 'text/plain') + sstr('identity') +
             (headers or table(('x-trace', fv_S('abc')), ('x-retry', fv_I(3)))) +
             u8(2) + u8(9) + sstr('corr-1') + sstr('reply.queue') + sstr('60000') +
             sstr('msg-0001') + u64(1700000001) + sstr('order.created') + sstr('guest') +
             sstr('mkamqp0') + sstr('cluster-a'))
    return 0xfffc, props


def file_props():
    props = (sstr('application/octet-stream') + sstr('gzip') +
             table(('x-file', fv_S('report'))) + u8(5) + sstr('reply.files') +
             sstr('file-msg-1') + sstr('report.pdf') + u64(1700000002) + sstr('cluster-f'))
    return 0xff80, props


def stream_props():
    props = (sstr('video/mp4') + sstr('identity') + table(('x-stream', fv_I(1))) +
             u8(4) + u64(1700000003))
    return 0xf800, props


def tunnel_props():
    props = table(('x-tunnel', fv_S('t1'))) + sstr('proxy-1') + sstr('data-1') + u8(1) + u8(0)
    return 0xf800, props


# --------------------------------------------------------------------------
# AMQP 0-10 encoding

def str8(v):
    v = b(v)
    return u8(len(v)) + v


def str16(v):
    v = b(v)
    return u16(len(v)) + v


vbin8 = str8
vbin16 = str16


def vbin32(v):
    v = b(v)
    return u32(len(v)) + v


def map010(*entries):
    """0-10 map from (name, type code, encoded value) triples."""
    body = u32(len(entries)) + b''.join(str8(n) + u8(t) + v for n, t, v in entries)
    return u32(len(body)) + body


def arr010(atype, *elems):
    body = u8(atype) + u32(len(elems)) + b''.join(elems)
    return u32(len(body)) + body


def str16_array(*strs):
    return arr010(0x95, *[str16(s) for s in strs])


def struct32(cls, code, rest):
    body = u8(cls) + u8(code) + rest
    return u32(len(body)) + body


def seqset(*pairs):
    data = b''.join(u32(a) + u32(z) for a, z in pairs)
    return u16(len(data)) + data


def pack(f1, f2=0):
    return u8(f1) + u8(f2)


def frame010(ftype, payload, ch=0, pos=0x0f, track=0):
    return u8(pos) + u8(ftype) + u16(12 + len(payload)) + u8(0) + u8(track) + u16(ch) + u32(0) + payload


def control(cls, mth, args=b'\0\0', ch=0):
    return frame010(0, u8(cls) + u8(mth) + args, ch=ch, track=0)


def command(cls, mth, args=b'\0\0', ch=1, sync=0, pos=0x0f):
    return frame010(1, u8(cls) + u8(mth) + u8(1) + u8(sync) + args, ch=ch, pos=pos, track=1)


C10_CONNECTION, C10_SESSION, C10_EXECUTION, C10_MESSAGE, C10_TX, C10_DTX = 1, 2, 3, 4, 5, 6
C10_EXCHANGE, C10_QUEUE, C10_FILE, C10_STREAM = 7, 8, 9, 10


def every_type_map():
    """A 0-10 map with every type the dissector knows, the composite types
    and types it only skips by length."""
    return map010(
        ('bin8', 0x00, b'\xab'),
        ('int8', 0x01, i8(-3)),
        ('uint8', 0x02, u8(200)),
        ('char', 0x04, b'Z'),
        ('boolean', 0x08, u8(1)),
        ('false', 0x08, u8(0)),
        ('bin16', 0x10, b'\x01\x02'),
        ('int16', 0x11, i16(-1234)),
        ('uint16', 0x12, u16(54321)),
        ('bin32', 0x20, b'\xde\xad\xbe\xef'),
        ('int32', 0x21, i32(-7654321)),
        ('uint32', 0x22, u32(3000000000)),
        ('vbin8', 0x80, vbin8(b'\x10\x20\x30')),
        ('str16', 0x95, str16('hello 0-10')),
        ('map', 0xa8, map010(('inner', 0x02, u8(1)))),
        ('list', 0xa9, u32(6) + u32(1) + u8(0x02) + u8(7)),
        ('array', 0xaa, str16_array('x', 'y')),
        # Types the dissector does not decode, skipped by their length
        ('bin8-other', 0x03, b'\x00'),
        ('bin64', 0x30, u64(1)),
        ('bin128', 0x40, bytes(16)),
        ('bin256', 0x50, bytes(32)),
        ('bin512', 0x60, bytes(64)),
        ('bin1024', 0x70, bytes(128)),
        ('vbin8-other', 0x81, vbin8(b'ab')),
        ('vbin16', 0x90, vbin16(b'abc')),
        ('vbin32', 0xa0, vbin32(b'abcd')),
        ('struct32', 0xab, vbin32(b'\x04\x05\x00\x00')),
        ('reserved', 0xb0, bytes(9)),
        ('dec32', 0xc0, bytes(5)),
    )


def xid(fmt=1, gid=b'global-1', bid=b'branch-1'):
    x = pack(0x07) + u32(fmt) + vbin8(gid) + vbin8(bid)
    return u16(len(x)) + x


def delivery_properties(ttl=60000):
    return struct32(4, 1, pack(0xff, 0x0f) + u8(9) + u8(2) + u64(ttl) + u64(1700000004) +
                    u64(1700003600) + str8('amq.direct') + str8('rk.orders') +
                    str16('resume-1') + u64(30000))


def fragment_properties():
    return struct32(4, 2, pack(0x07) + u64(4096))


def message_properties(content_type='application/json'):
    reply_to = pack(0x03) + str8('amq.direct') + str8('reply.rk')
    return struct32(4, 3, pack(0xff, 0x01) + u64(26) + bytes(range(16)) + vbin16(b'corr-10') +
                    u16(len(reply_to)) + reply_to + str8(content_type) + str8('utf-8') +
                    vbin16(b'guest') + vbin16(b'mkamqp0') +
                    map010(('x-count', 0x22, u32(1)), ('x-name', 0x95, str16('n'))))


def file_properties():
    return struct32(9, 1, pack(0xff, 0x01) + str8('application/pdf') + str8('identity') +
                    map010(('x-pages', 0x12, u16(12))) + u8(3) + str8('reply.files') +
                    str8('file-10') + str8('doc.pdf') + u64(1700000005) + str8('cluster-10'))


def stream_properties():
    return struct32(10, 1, pack(0x1f) + str8('audio/ogg') + str8('identity') +
                    map010(('x-rate', 0x22, u32(44100))) + u8(1) + u64(1700000006))


# --------------------------------------------------------------------------
# Main capture: AMQP 0-9 (protocol header 1-1-0-9), every class and method

def amqp09_every_method(cap):
    st = TcpStream(cap, ip(1), ip(2), 40001)
    st.c(b'AMQP\x01\x01\x00\x09')
    st.s(method(0, CONNECTION, 10, u8(0) + u8(9) + every_type_table() +
                lstr('PLAIN AMQPLAIN') + lstr('en_US')))
    st.c(method(0, CONNECTION, 11, table(('product', fv_S('mkamqp0')), ('platform', fv_S('Python'))) +
                sstr('PLAIN') + lstr(b'\0guest\0guest') + sstr('en_US')))
    st.s(method(0, CONNECTION, 20, lstr('challenge-data')))
    st.c(method(0, CONNECTION, 21, lstr('response-data')))
    st.s(method(0, CONNECTION, 30, u16(2047) + u32(131072) + u16(60)))
    st.c(method(0, CONNECTION, 31, u16(2047) + u32(131072) + u16(60)))
    st.c(method(0, CONNECTION, 40, sstr('/') + sstr('') + bits(1)))
    st.s(method(0, CONNECTION, 41, sstr('10.0.0.2:5672')))
    st.s(heartbeat())
    st.c(heartbeat())
    # Channel class on channel 1
    st.c(method(1, CHANNEL, 10, sstr('')))
    st.s(method(1, CHANNEL, 11, lstr('channel-id-1')))
    st.c(method(1, CHANNEL, 20, bits(1)))
    st.s(method(1, CHANNEL, 21, bits(1)))
    st.c(method(1, CHANNEL, 50, lstr('channel-id-1')))
    st.c(method(1, CHANNEL, 60))
    st.s(method(1, CHANNEL, 70))
    st.s(method(1, CHANNEL, 80))
    # Access
    st.c(method(1, ACCESS, 10, sstr('/data') + bits(1, 0, 1, 1, 1)))
    st.s(method(1, ACCESS, 11, u16(101)))
    # Exchange
    st.c(method(1, EXCHANGE, 10, u16(101) + sstr('orders') + sstr('topic') + bits(0, 1, 0, 0, 0) +
                table(('alternate-exchange', fv_S('unrouted')))))
    st.s(method(1, EXCHANGE, 11))
    st.c(method(1, EXCHANGE, 30, u16(0) + sstr('orders.eu') + sstr('orders') + sstr('eu.#') + bits(0) +
                table(('x-match', fv_S('all')))))
    st.s(method(1, EXCHANGE, 31))
    st.c(method(1, EXCHANGE, 40, u16(0) + sstr('orders.eu') + sstr('orders') + sstr('eu.#') + bits(0) + table()))
    st.s(method(1, EXCHANGE, 51))
    st.c(method(1, EXCHANGE, 20, u16(0) + sstr('orders.old') + bits(1, 0)))
    st.s(method(1, EXCHANGE, 21))
    # Queue
    st.c(method(1, QUEUE, 10, u16(101) + sstr('q.orders') + bits(0, 1, 0, 0, 0) +
                table(('x-message-ttl', fv_I(60000)), ('x-queue-type', fv_S('classic')))))
    st.s(method(1, QUEUE, 11, sstr('q.orders') + u32(5) + u32(1)))
    st.c(method(1, QUEUE, 20, u16(101) + sstr('q.orders') + sstr('orders') + sstr('order.*') + bits(0) + table()))
    st.s(method(1, QUEUE, 21))
    st.c(method(1, QUEUE, 50, u16(101) + sstr('q.orders') + sstr('orders') + sstr('order.old') + table()))
    st.s(method(1, QUEUE, 51))
    st.c(method(1, QUEUE, 30, u16(101) + sstr('q.orders') + bits(0)))
    st.s(method(1, QUEUE, 31, u32(5)))
    st.c(method(1, QUEUE, 40, u16(101) + sstr('q.tmp') + bits(1, 1, 0)))
    st.s(method(1, QUEUE, 41, u32(0)))
    # Basic: qos, consume, cancel
    st.c(method(1, BASIC, 10, u32(0) + u16(10) + bits(0)))
    st.s(method(1, BASIC, 11))
    st.c(method(1, BASIC, 20, u16(101) + sstr('q.orders') + sstr('ctag-1') + bits(0, 0, 1, 0) +
                table(('x-priority', fv_I(5)))))
    st.s(method(1, BASIC, 21, sstr('ctag-1')))
    # Publish with every basic property, header and body in one segment
    flags, props = basic_props('Application/JSON', all_props=True)
    js = b'{"order": 1, "items": ["a", "b"], "total": 9.5}'
    st.c(method(1, BASIC, 40, u16(101) + sstr('orders') + sstr('order.created') + bits(1, 0)) +
         header(1, BASIC, len(js), flags, props) + body(1, js))
    # Return (NO_ROUTE 312, a warning) with its content
    st.s(method(1, BASIC, 50, u16(312) + sstr('NO_ROUTE') + sstr('orders') + sstr('order.created')) +
         header(1, BASIC, len(js), *basic_props('application/json')) + body(1, js))
    # Deliver, then a client ack
    st.s(method(1, BASIC, 60, sstr('ctag-1') + u64(1) + bits(0) + sstr('orders') + sstr('order.created')) +
         header(1, BASIC, len(js), *basic_props('application/json')) + body(1, js))
    st.c(method(1, BASIC, 80, u64(1) + bits(0)))
    # Get, Get-Ok, Get-Empty, Reject
    st.c(method(1, BASIC, 70, u16(101) + sstr('q.orders') + bits(0)))
    txt = b'plain text body\n'
    st.s(method(1, BASIC, 71, u64(2) + bits(1) + sstr('orders') + sstr('order.text') + u32(3)) +
         header(1, BASIC, len(txt), *basic_props('text/plain')) + body(1, txt))
    st.c(method(1, BASIC, 90, u64(2) + bits(1)))
    st.c(method(1, BASIC, 70, u16(101) + sstr('q.empty') + bits(1)))
    st.s(method(1, BASIC, 72, sstr('')))
    # Recover-Async, Recover, Recover-Ok
    st.c(method(1, BASIC, 100, bits(1)))
    st.c(method(1, BASIC, 110, bits(1)))
    st.s(method(1, BASIC, 111))
    st.c(method(1, BASIC, 30, sstr('ctag-1') + bits(0)))
    st.s(method(1, BASIC, 31, sstr('ctag-1')))
    # File class on channel 2
    st.c(method(2, CHANNEL, 10, sstr('')))
    st.s(method(2, CHANNEL, 11, lstr('')))
    st.c(method(2, FILE, 10, u32(65536) + u16(4) + bits(1)))
    st.s(method(2, FILE, 11))
    st.c(method(2, FILE, 20, u16(101) + sstr('q.files') + sstr('ftag-1') + bits(1, 0, 1, 0) +
                table(('x-filter', fv_S('*.pdf')))))
    st.s(method(2, FILE, 21, sstr('ftag-1')))
    st.c(method(2, FILE, 40, sstr('file-1') + u64(12)))
    st.s(method(2, FILE, 41, u64(0)))
    st.c(method(2, FILE, 50) + header(2, FILE, 12, *file_props()) + body(2, b'%PDF-1.4 ...'))
    st.c(method(2, FILE, 60, u16(101) + sstr('files') + sstr('report') + bits(1, 1) + sstr('file-1')))
    st.s(method(2, FILE, 70, u16(313) + sstr('NO_CONSUMERS') + sstr('files') + sstr('report')))
    st.s(method(2, FILE, 80, sstr('ftag-1') + u64(7) + bits(0) + sstr('files') + sstr('report') + sstr('file-1')))
    st.c(method(2, FILE, 90, u64(7) + bits(0)))
    st.c(method(2, FILE, 100, u64(8) + bits(1)))
    st.c(method(2, FILE, 30, sstr('ftag-1') + bits(0)))
    st.s(method(2, FILE, 31, sstr('ftag-1')))
    # Stream class on channel 3
    st.c(method(3, STREAM, 10, u32(0) + u16(100) + u32(25) + bits(0)))
    st.s(method(3, STREAM, 11))
    st.c(method(3, STREAM, 20, u16(101) + sstr('q.video') + sstr('stag-1') + bits(0, 1, 0) + table()))
    st.s(method(3, STREAM, 21, sstr('stag-1')))
    st.c(method(3, STREAM, 40, u16(101) + sstr('video') + sstr('cam.1') + bits(0, 0)) +
         header(3, STREAM, 8, *stream_props()) + body(3, b'\x00\x00\x00\x18ftyp'[:8]))
    st.s(method(3, STREAM, 50, u16(312) + sstr('NO_ROUTE') + sstr('video') + sstr('cam.1')))
    st.s(method(3, STREAM, 60, sstr('stag-1') + u64(3) + sstr('video') + sstr('q.video')) +
         header(3, STREAM, 4, 0x0000, b'') + body(3, b'\x01\x02\x03\x04'))
    st.c(method(3, STREAM, 30, sstr('stag-1') + bits(0)))
    st.s(method(3, STREAM, 31, sstr('stag-1')))
    # Tx, Dtx, Tunnel on channel 4
    for m in (10, 11, 20, 21, 30, 31):
        (st.c if m % 2 == 0 else st.s)(method(4, TX, m))
    st.c(method(4, DTX, 10))
    st.s(method(4, DTX, 11))
    st.c(method(4, DTX, 20, sstr('dtx-id-1')))
    st.s(method(4, DTX, 21))
    st.c(method(4, TUNNEL, 10, table(('proxy', fv_S('p1')), ('hops', fv_B(2)))) +
         header(4, TUNNEL, 5, *tunnel_props()) + body(4, b'hello'))
    # Channel.Close with an error (406 PRECONDITION_FAILED) and a normal one
    st.c(method(4, CHANNEL, 40, u16(406) + sstr('PRECONDITION_FAILED') + u16(DTX) + u16(20)))
    st.s(method(4, CHANNEL, 41))
    st.c(method(3, CHANNEL, 40, u16(200) + sstr('Goodbye') + u16(0) + u16(0)))
    st.s(method(3, CHANNEL, 41))
    # Flow control from the broker
    st.s(method(0, CONNECTION, 60, sstr('low on memory')))
    st.s(method(0, CONNECTION, 61))
    # A frame split after 5 octets: dissect_amqp() asks for more data
    hb = method(1, BASIC, 10, u32(0) + u16(20) + bits(1))
    st.c(*split(hb, 5))
    st.s(method(1, BASIC, 11))
    # A frame split over three segments, and two frames with a third split
    big = b'x' * 3000
    st.c(*split(method(1, BASIC, 40, u16(0) + sstr('') + sstr('big') + bits(0, 0)) +
                header(1, BASIC, len(big), *basic_props('application/octet-stream')) +
                body(1, big), 40, 1500, 2960))
    # Connection.Close with an error, and Close-Ok
    st.s(method(0, CONNECTION, 50, u16(320) + sstr('CONNECTION_FORCED - shutdown') + u16(0) + u16(0)))
    st.c(method(0, CONNECTION, 51))
    st.close()


# Main capture: AMQP 0-9-1 (RabbitMQ style header 0-0-9-1, which the
# dissector does not recognise; the version is found from the next frame),
# publisher confirms, consumer acks, content-type body dissection.

def amqp091_confirms(cap):
    st = TcpStream(cap, ip(3), ip(2), 40002)
    st.c(b'AMQP\x00\x00\x09\x01')
    st.s(method(0, CONNECTION, 10, u8(0) + u8(9) +
                table(('product', fv_S('RabbitMQ')), ('capabilities', fv_F(('basic.nack', fv_t(1))))) +
                lstr('PLAIN') + lstr('en_US')))
    st.c(method(0, CONNECTION, 11, table() + sstr('PLAIN') + lstr(b'\0guest\0guest') + sstr('en_US')))
    st.s(method(0, CONNECTION, 30, u16(0) + u32(131072) + u16(0)))
    st.c(method(0, CONNECTION, 31, u16(0) + u32(131072) + u16(0)) +
         method(0, CONNECTION, 40, sstr('/') + sstr('') + bits(0)))
    st.s(method(0, CONNECTION, 41, sstr('')))
    st.c(method(1, CHANNEL, 10, sstr('')))
    st.s(method(1, CHANNEL, 11, lstr('')))
    # Publisher confirms on channel 1
    st.c(method(1, CONFIRM, 10, bits(0)))
    st.s(method(1, CONFIRM, 11))
    msgs = [b'{"n": %d}' % n for n in range(1, 6)]
    for m in msgs:   # five publishes, numbered 1-5
        st.c(method(1, BASIC, 40, u16(0) + sstr('amq.direct') + sstr('jobs') + bits(0, 0)) +
             header(1, BASIC, len(m), *basic_props('application/json')) + body(1, m))
    st.s(method(1, BASIC, 80, u64(2) + bits(1)))    # ack 1 and 2 (multiple)
    st.s(method(1, BASIC, 120, u64(3) + bits(0, 1)))  # nack 3
    st.s(method(1, BASIC, 80, u64(5) + bits(1)))    # ack 4 and 5 (multiple)
    st.s(method(1, BASIC, 80, u64(99) + bits(0)))   # ack of an unknown tag
    # Consumer on channel 2: deliveries acked one by one, multiple, nack
    st.c(method(2, CHANNEL, 10, sstr('')))
    st.s(method(2, CHANNEL, 11, lstr('')))
    st.c(method(2, BASIC, 20, u16(0) + sstr('jobs') + sstr('') + bits(0, 0, 0, 0) + table()))
    st.s(method(2, BASIC, 21, sstr('amq.ctag-XYZ')))
    for tag in range(1, 5):
        m = msgs[tag - 1]
        st.s(method(2, BASIC, 60, sstr('amq.ctag-XYZ') + u64(tag) + bits(0) + sstr('amq.direct') + sstr('jobs')) +
             header(2, BASIC, len(m), *basic_props('application/json')) + body(2, m))
    st.c(method(2, BASIC, 80, u64(1) + bits(0)))
    st.c(method(2, BASIC, 120, u64(3) + bits(1, 1)))  # nack 2 and 3
    st.c(method(2, BASIC, 90, u64(4) + bits(0)))      # reject 4
    # Content without content-type, a body on a channel without any header,
    # and a content-type no dissector registers
    st.s(method(2, BASIC, 60, sstr('amq.ctag-XYZ') + u64(5) + bits(1) + sstr('amq.direct') + sstr('jobs')) +
         header(2, BASIC, 4, *basic_props(None)) + body(2, b'\x00\x01\x02\x03'))
    st.c(method(2, BASIC, 80, u64(5) + bits(0)))
    st.s(body(7, b'orphan body'))
    st.s(method(2, BASIC, 60, sstr('amq.ctag-XYZ') + u64(6) + bits(0) + sstr('amq.direct') + sstr('jobs')) +
         header(2, BASIC, 3, *basic_props('application/x-unknown')) + body(2, b'abc'))
    st.c(method(2, BASIC, 80, u64(0) + bits(1)))       # multiple ack of everything (tag 0)
    # Content split over several body frames
    parts = [b'{"part": 1, ', b'"more": "', b'yes"}']
    st.s(method(2, BASIC, 60, sstr('amq.ctag-XYZ') + u64(7) + bits(0) + sstr('amq.direct') + sstr('jobs')) +
         header(2, BASIC, sum(map(len, parts)), *basic_props('text/plain')) +
         b''.join(body(2, p) for p in parts))
    st.c(method(2, BASIC, 80, u64(7) + bits(0)))
    st.c(method(2, CHANNEL, 40, u16(200) + sstr('bye') + u16(0) + u16(0)))
    st.s(method(2, CHANNEL, 41))
    st.c(method(0, CONNECTION, 50, u16(200) + sstr('Goodbye') + u16(0) + u16(0)))
    st.s(method(0, CONNECTION, 51))
    st.close()


# Main capture: AMQP 0-8 (header 1-1-8-0, not recognised; frames are found
# to be 0-9 by the frame end octet) and a redirect.

def amqp08_redirect(cap):
    st = TcpStream(cap, ip(4), ip(2), 40003)
    st.c(b'AMQP\x01\x01\x08\x00')
    st.s(method(0, CONNECTION, 10, u8(8) + u8(0) + table(('product', fv_S('OpenAMQ'))) +
                lstr('PLAIN') + lstr('en_US')))
    st.c(method(0, CONNECTION, 11, table() + sstr('PLAIN') + lstr(b'\0guest\0guest') + sstr('en_US')))
    st.s(method(0, CONNECTION, 30, u16(256) + u32(65536) + u16(0)))
    st.c(method(0, CONNECTION, 31, u16(256) + u32(65536) + u16(0)))
    st.c(method(0, CONNECTION, 40, sstr('/') + sstr('cluster') + bits(0)))
    st.s(method(0, CONNECTION, 42, sstr('10.0.0.12:5672') + sstr('10.0.0.12:5672,10.0.0.13:5672')))
    st.close()


# Main capture: version negotiation. The client asks for 0-11, which the
# dissector does not know; the broker answers with the 0-9 header it
# supports, which sets the version, and closes.

def version_negotiation(cap):
    st = TcpStream(cap, ip(5), ip(2), 40004)
    st.c(b'AMQP\x01\x01\x00\x0b')
    st.s(b'AMQP\x01\x01\x00\x09')
    st.close()


# Main capture: a 0-9 connection captured mid-way (no protocol header)

def amqp09_midstream(cap):
    st = TcpStream(cap, ip(6), ip(2), 40005, handshake=False)
    js = b'{"late": true}'
    st.s(method(5, BASIC, 60, sstr('ctag-late') + u64(41) + bits(0) + sstr('') + sstr('late')) +
         header(5, BASIC, len(js), *basic_props('application/json')) + body(5, js))
    st.c(method(5, BASIC, 80, u64(41) + bits(0)))
    st.s(heartbeat())


# --------------------------------------------------------------------------
# Main capture: AMQP 0-10, every control, command and struct

def amqp010_every_method(cap):
    st = TcpStream(cap, ip(7), ip(8), 40010)
    st.c(b'AMQP\x01\x01\x00\x0a')
    st.s(b'AMQP\x01\x01\x00\x0a')
    # connection controls
    st.s(control(1, 1, pack(0x07) + every_type_map() + str16_array('PLAIN', 'ANONYMOUS') +
                 str16_array('en_US')))
    st.c(control(1, 2, pack(0x0f) + map010(('qpid.client_process', 0x95, str16('mkamqp0')),
                                           ('qpid.client_pid', 0x21, i32(4242)),
                                           # dec64 is 9 octets; the dissector skips 5 (last entry)
                                           ('dec64', 0xd0, bytes(9))) +
                 str8('PLAIN') + vbin32(b'\0guest\0guest') + str8('en_US')))
    st.s(control(1, 3, pack(0x01) + vbin32(b'challenge')))
    st.c(control(1, 4, pack(0x01) + vbin32(b'response')))
    st.s(control(1, 5, pack(0x0f) + u16(32767) + u16(65535) + u16(0) + u16(120)))
    st.c(control(1, 6, pack(0x07) + u16(32767) + u16(65535) + u16(60)))
    st.c(control(1, 7, pack(0x07) + str8('/') + str16_array('cap1', 'cap2')))
    st.s(control(1, 8, pack(0x01) + str16_array('amqp:tcp:10.0.0.8:5672')))
    st.s(control(1, 10))  # heartbeat
    # session controls
    st.c(control(2, 1, pack(0x03) + vbin16(b'session-1'), ch=1))
    st.s(control(2, 2, pack(0x01) + vbin16(b'session-1'), ch=1))
    st.c(control(2, 5, pack(0x01) + u32(600), ch=1))
    st.s(control(2, 6, pack(0x01) + u32(600), ch=1))
    st.c(control(2, 7, pack(0x03) + u32(0) + u64(0), ch=1))
    frag = struct32(4, 4, pack(0x01) + seqset((0, 1)))
    st.s(control(2, 8, pack(0x03) + seqset((0, 0), (5, 9)) + arr010(0xab, frag, frag), ch=1))
    st.s(control(2, 9, pack(0x03) + seqset((0, 3)) + arr010(0xab), ch=1))
    st.s(control(2, 10, pack(0x03) + seqset((0, 4)), ch=1))
    st.c(control(2, 11, pack(0x01) + seqset((0, 4)), ch=1))
    st.c(control(2, 12, pack(0x07), ch=1))
    st.s(control(2, 13, pack(0x01) + seqset((10, 12)), ch=1))
    # execution commands
    st.c(command(3, 1, pack(0), sync=1))
    results = [
        struct32(4, 4, pack(0x01) + seqset((1, 3))),
        struct32(4, 5, pack(0x01) + u64(1024)),
        struct32(6, 1, b'\0\0' + u16(0)),
        struct32(6, 3, b'\0\0' + arr010(0xab, struct32(6, 1, b'\0\0' + u16(3)),
                                        struct32(6, 1, b'\0\0' + u16(4)))),
        struct32(6, 3, b'\0\0' + arr010(0x95, str16('xid-a'), str16('xid-b'))),
        struct32(7, 1, pack(0x0f) + str8('topic') + map010(('alternate-exchange', 0x95, str16('ae')))),
        struct32(7, 2, u8(0x1f)),
        struct32(8, 1, pack(0xff) + str8('q.orders') + str8('ae') +
                 map010(('x-max-length', 0x22, u32(1000))) + u32(17) + u32(2)),
        struct32(9, 1, pack(0xff, 0x01) + str8('a') + str8('b') + map010() + u8(1) + str8('c') +
                 str8('d') + str8('e') + u64(1) + str8('f')),
        struct32(10, 1, pack(0x1f) + str8('a') + str8('b') + map010() + u8(1) + u64(2)),
    ]
    for n, r in enumerate(results):
        st.s(command(3, 2, pack(0x03) + u32(n) + r))
    for cls in range(1, 11):
        st.s(command(3, 3, pack(0x7f) + u16(404) + u32(7) + u8(cls) + u8(1) + u8(0) +
                     str16('not-found: no such queue') + map010(('reason', 0x95, str16('gone')))))
    # message commands
    st.c(command(4, 7, pack(0xff) + str8('q.orders') + str8('dest-1') + u8(0) + u8(0) +
                 str16('resume-1') + u64(5000) + map010()))
    st.c(command(4, 9, pack(0x03) + str8('dest-1') + u8(1)))
    st.c(command(4, 10, pack(0x07) + str8('dest-1') + u8(0) + u32(100)))
    st.c(command(4, 10, pack(0x07) + str8('dest-1') + u8(1) + u32(0xffffffff)))
    # message.transfer: command, header and body segments, the body over
    # three frames, all in one TCP segment
    js = b'{"id": 10, "status": "ok"}'
    st.s(command(4, 1, pack(0x07) + str8('dest-1') + u8(0) + u8(0), pos=0x0b) +
         frame010(2, delivery_properties() + fragment_properties() + message_properties(),
                  ch=1, pos=0x03, track=1) +
         frame010(3, js[:10], ch=1, pos=0x02, track=1) +
         frame010(3, js[10:20], ch=1, pos=0x00, track=1) +
         frame010(3, js[20:], ch=1, pos=0x05, track=1))
    # a transfer split over segments, a frame cut in its header
    data = (command(4, 1, pack(0x07) + str8('dest-1') + u8(1) + u8(1), pos=0x0b) +
            frame010(2, delivery_properties(0) + message_properties('text/plain'), ch=1, pos=0x03, track=1) +
            frame010(3, b'second message body', ch=1, pos=0x07, track=1))
    st.s(*split(data, 6, 30, len(data) - 8))
    st.c(command(4, 2, pack(0x01) + seqset((5, 6))))
    st.c(command(4, 3, pack(0x07) + seqset((7, 7)) + u16(1) + str8('unroutable')))
    st.c(command(4, 4, pack(0x03) + seqset((8, 8))))
    st.c(command(4, 5, pack(0x01) + seqset((9, 9))))
    st.s(command(3, 2, pack(0x03) + u32(20) + struct32(4, 4, pack(0x01) + seqset((9, 9)))))
    st.c(command(4, 6, pack(0x03) + str8('dest-1') + str16('resume-1')))
    st.s(command(3, 2, pack(0x03) + u32(21) + struct32(4, 5, pack(0x01) + u64(0))))
    st.c(command(4, 11, pack(0x01) + str8('dest-1')))
    st.c(command(4, 12, pack(0x01) + str8('dest-1')))
    st.c(command(4, 8, pack(0x01) + str8('dest-1')))
    # tx commands
    st.c(command(5, 1, pack(0)))
    st.c(command(5, 2, pack(0)))
    st.c(command(5, 3, pack(0)))
    st.c(command(5, 2, pack(0), sync=1))
    # dtx commands
    st.c(command(6, 1, pack(0)))
    st.c(command(6, 2, pack(0x07) + xid()))
    st.c(command(6, 3, pack(0x07) + xid()))
    st.c(command(6, 7, pack(0x01) + xid()))
    st.c(command(6, 4, pack(0x03) + xid()))
    st.c(command(6, 5, pack(0x01) + xid()))
    st.c(command(6, 6, pack(0x01) + xid()))
    st.c(command(6, 8, pack(0)))
    st.c(command(6, 9, pack(0x01) + xid(fmt=0, gid=b'g', bid=b'')))
    st.c(command(6, 10, pack(0x03) + xid() + u32(300)))
    # exchange commands
    st.c(command(7, 1, pack(0x7f) + str8('orders') + str8('topic') + str8('ae') +
                 map010(('x-ttl', 0x22, u32(10)))))
    st.c(command(7, 2, pack(0x03) + str8('orders.old')))
    st.c(command(7, 3, pack(0x01) + str8('orders'), sync=1))
    st.c(command(7, 4, pack(0x0f) + str8('q.orders') + str8('orders') + str8('order.#') +
                 map010(('x-match', 0x95, str16('any')))))
    st.c(command(7, 5, pack(0x07) + str8('q.orders') + str8('orders') + str8('order.old')))
    st.c(command(7, 6, pack(0x0f) + str8('orders') + str8('q.orders') + str8('order.#') + map010(), sync=1))
    # queue commands
    # void is 0 octets; the dissector skips 5 (last entry)
    st.c(command(8, 1, pack(0x7f) + str8('q.orders') + str8('ae') + map010(('x-ttl', 0x22, u32(60)),
                                                                        ('void', 0xf0, b''))))
    st.c(command(8, 2, pack(0x07) + str8('q.tmp')))
    st.c(command(8, 3, pack(0x01) + str8('q.orders')))
    st.c(command(8, 4, pack(0x01) + str8('q.orders'), sync=1))
    # file commands
    st.c(command(9, 1, pack(0x07) + u32(65536) + u16(4)))
    st.s(command(9, 2, pack(0)))
    st.c(command(9, 3, pack(0x7f) + str8('q.files') + str8('ftag') + map010(('x-f', 0x08, u8(1)))))
    st.s(command(9, 4, pack(0x01) + str8('ftag')))
    st.c(command(9, 6, pack(0x03) + str8('file-1') + u64(4096)))
    st.s(command(9, 7, pack(0x01) + u64(1024)))
    st.c(command(9, 8, pack(0)) + frame010(2, file_properties(), ch=1, pos=0x03, track=1) +
         frame010(3, b'%PDF', ch=1, pos=0x07, track=1))
    st.c(command(9, 9, pack(0x1f) + str8('files') + str8('report') + str8('file-1')))
    st.s(command(9, 10, pack(0x0f) + u16(312) + str8('NO_ROUTE') + str8('files') + str8('report')))
    st.s(command(9, 11, pack(0x3f) + str8('ftag') + u64(3) + str8('files') + str8('report') + str8('file-1')))
    st.c(command(9, 12, pack(0x03) + u64(3)))
    st.c(command(9, 13, pack(0x03) + u64(4)))
    st.c(command(9, 5, pack(0x01) + str8('ftag')))
    # stream commands
    st.c(command(10, 1, pack(0x0f) + u32(0) + u16(10) + u32(25)))
    st.s(command(10, 2, pack(0)))
    st.c(command(10, 3, pack(0x3f) + str8('q.video') + str8('stag') + map010(('x-s', 0x02, u8(1)))))
    st.s(command(10, 4, pack(0x01) + str8('stag')))
    st.c(command(10, 6, pack(0x0f) + str8('video') + str8('cam.1')) +
         frame010(2, stream_properties(), ch=1, pos=0x03, track=1) +
         frame010(3, b'\x00\x01\x02\x03', ch=1, pos=0x07, track=1))
    st.s(command(10, 7, pack(0x0f) + u16(312) + str8('NO_ROUTE') + str8('video') + str8('cam.1')))
    st.s(command(10, 8, pack(0x0f) + str8('stag') + u64(9) + str8('video') + str8('q.video')))
    st.c(command(10, 5, pack(0x01) + str8('stag')))
    # session end, connection redirect and close
    st.c(control(2, 3, pack(0x01) + vbin16(b'session-1'), ch=1))
    st.s(control(2, 4, pack(0x03) + vbin16(b'session-1') + u8(0), ch=1))
    st.s(control(1, 9, pack(0x03) + str16('amqp:tcp:10.0.0.18:5672') + str16_array('amqp:tcp:10.0.0.18:5672')))
    st.c(control(1, 11, pack(0x03) + u16(200) + str8('ok')))
    st.s(control(1, 12))
    st.close()


# Main capture: a 0-10 connection captured mid-way

def amqp010_midstream(cap):
    st = TcpStream(cap, ip(9), ip(8), 40011, handshake=False)
    st.s(command(4, 1, pack(0x07) + str8('late') + u8(1) + u8(1), pos=0x0b, ch=2) +
         frame010(2, delivery_properties(), ch=2, pos=0x03, track=1) +
         frame010(3, b'late body', ch=2, pos=0x07, track=1))
    st.c(command(4, 2, pack(0x01) + seqset((100, 100)), ch=2))


# --------------------------------------------------------------------------
# Malformed capture

def malformed_09(cap):
    st = TcpStream(cap, ip(21), ip(2), 41001)
    st.c(b'AMQP\x01\x01\x00\x09')
    # unknown method in every class, an unknown class
    for cls in (CONNECTION, CHANNEL, ACCESS, EXCHANGE, QUEUE, BASIC, FILE, STREAM, TX, DTX, TUNNEL, CONFIRM):
        st.c(method(1, cls, 999))
    st.c(method(1, 999, 10))
    # unknown content header class, OOB, trace and unknown frame types
    st.c(header(1, CONNECTION, 0, 0, b''))
    for ft in (4, 5, 6, 7, 99):
        st.c(frame09(ft, 1, b'\x00\x01'))
    # field tables: an unknown type, each type cut short, a name longer
    # than the table, a table that ends after a name, nested too deep
    st.c(method(1, TUNNEL, 10, table(('bad', b'Z\x00'))))
    for t, need in ((b'I', 4), (b'D', 5), (b'S', 4), (b'T', 8), (b'F', 4), (b't', 1), (b'b', 1),
                    (b'B', 1), (b's', 2), (b'u', 2), (b'i', 4), (b'l', 8), (b'f', 4), (b'd', 8),
                    (b'A', 4), (b'x', 4)):
        st.c(method(1, TUNNEL, 10, table(('short', t + b'\x00' * (need - 1)))))
    st.c(method(1, TUNNEL, 10, table(('f', b'F' + u32(100) + b'abc'))))
    st.c(method(1, TUNNEL, 10, table(('a', b'A' + u32(100) + b'abc'))))
    st.c(method(1, TUNNEL, 10, table(('a', b'A' + u32(2) + b'Z\0'))))
    st.c(method(1, TUNNEL, 10, u32(5) + u8(10) + b'abcd'))
    st.c(method(1, TUNNEL, 10, u32(4) + sstr('abc')))
    nested = fv_I(1)
    for _ in range(200):
        nested = fv_F(('n', nested))
    st.c(method(1, TUNNEL, 10, table(('deep', nested))))
    deep_arr = fv_I(1)
    for _ in range(200):
        deep_arr = fv_A(deep_arr)
    st.c(method(1, TUNNEL, 10, table(('deeparr', deep_arr))))
    # method arguments cut short (exceptions)
    st.c(method(1, BASIC, 40, u16(0) + u8(50)))
    st.c(method(1, CONNECTION, 10, u8(0) + u8(9) + u32(1000)))
    st.c(header(1, BASIC, 10, 0xfffc, sstr('x')))
    # a frame length over 1 MB is clamped
    st.c(u8(3) + u16(1) + u32(0x7fffffff) + b'\x00' * 32)
    st.close()


def malformed_010(cap):
    st = TcpStream(cap, ip(22), ip(8), 41010)
    st.c(b'AMQP\x01\x01\x00\x0a')
    # bad packing flags for every control, command and struct
    for m in range(1, 13):
        st.c(control(1, m, pack(0xff, 0x01) + bytes(64)))
    for m in range(1, 14):
        st.c(control(2, m, pack(0xfe if m == 2 else 0xff, 0x01) + bytes(64), ch=1))
    for cls, n in ((3, 3), (4, 12), (6, 10), (7, 6), (8, 4), (9, 13), (10, 8)):
        for m in range(1, n + 1):
            st.c(command(cls, m, pack(0x80 if (cls, m) == (4, 7) else 0xff, 0x01) + bytes(64)))
    for s in (struct32(4, 1, pack(0, 0xf0) + bytes(40)), struct32(4, 2, pack(0xff, 1) + bytes(8)),
              struct32(4, 3, pack(0, 0x02)), struct32(7, 1, pack(0, 0xf0)), struct32(8, 1, pack(0, 1)),
              struct32(9, 1, pack(0, 0x02)), struct32(10, 1, pack(0xff, 1) + bytes(40)),
              struct32(4, 3, pack(0x08) + u16(2) + pack(0xff, 1))):
        st.c(command(3, 2, pack(0x02) + s))
    # unknown method in every class, unknown struct codes and classes
    for cls in range(1, 11):
        st.c((control if cls <= 2 else command)(cls, 99, pack(0)))
    for cls, code in ((4, 9), (6, 2), (7, 9), (8, 9), (9, 9), (10, 9), (11, 1)):
        st.c(frame010(2, struct32(cls, code, pack(0)), ch=1, track=1))
    # exception with an invalid class code, invalid session headers
    st.c(command(3, 3, pack(0x0c) + u8(42) + u8(1)))
    st.c(frame010(1, b'\x07\x03\x02\x00' + pack(0x01) + str8('x')))
    st.c(frame010(1, b'\x07\x03\x01\x02' + pack(0x01) + str8('x')))
    st.c(frame010(1, b'\x05\x01\x01\x00\x01\x02'))
    # sizes over 64K, struct lengths over the frame, an unknown array type,
    # odd sequence sets, a subscribe map (misparsed: the size is read as
    # the entry count), unknown command class and frame type
    st.c(control(1, 1, pack(0x01) + u32(0x10000) + u32(0)))
    st.c(command(3, 2, pack(0x02) + u32(500) + b'\x04\x04' + pack(0)))
    st.c(command(3, 2, pack(0x02) + u32(0x20000) + b'\x04\x04' + pack(0)))
    st.c(frame010(2, u32(100) + b'\x04\x01' + pack(0), ch=1, track=1))
    st.c(control(1, 1, pack(0x02) + arr010(0x02, u8(1))))
    st.c(control(2, 8, pack(0x02) + u32(5) + u8(0xab) + u32(1) + u32(300) + b'\x04\x04', ch=1))
    st.c(command(4, 2, pack(0x01) + u16(6) + u32(1) + u16(2)))
    st.c(command(4, 2, pack(0x01) + u16(4) + u32(1) + u32(0)))
    st.c(command(4, 7, pack(0x80) + map010(('k', 0x02, u8(1)), ('l', 0x95, str16('v')))))
    st.c(command(3, 3, pack(0x40) + u32(100) + u32(10) + str8('a') + u8(0x02)))
    st.c(control(1, 1, pack(0x01) + map010(('m', 0x95, u16(500) + b'x'))))
    st.c(frame010(1, b'\x2a\x01\x01\x00\x00\x00'))
    st.c(frame010(9, b'\x00\x00'))
    # struct32 nested too deep (dtx recover-result arrays)
    s = struct32(6, 1, b'\0\0' + u16(0))
    for _ in range(120):
        a = arr010(0xab, s)
        s = struct32(6, 3, b'\0\0' + a)
    st.c(frame010(2, s, ch=1, track=1))
    # maps longer than the frame
    big = u32(1000) + u32(0)
    for cls, m, f, pre in ((4, 7, 0x80, b''), (7, 1, 0x40, b''), (7, 4, 0x08, b''), (7, 6, 0x08, b''),
                           (8, 1, 0x40, b''), (9, 3, 0x40, b''), (10, 3, 0x20, b'')):
        st.c(command(cls, m, pack(f) + pre + big))
    for sc, f1, f2 in ((3, 0, 0x01), (1, 0x04, 0)):
        st.c(frame010(2, u32(12) + bytes([4 if sc == 3 else 9, sc]) + pack(f1, f2) + big, ch=1, track=1))
    st.c(frame010(2, u32(12) + b'\x0a\x01' + pack(0x04) + big, ch=1, track=1))
    # truncated arguments (exceptions)
    st.c(control(1, 2, pack(0x0f) + u32(0)))
    st.c(command(4, 1, pack(0x07) + u8(40)))
    st.close()


def fuzz_09(cap, seed, convs):
    """Structured random 0-9-1 frames, as fuzz_amqp09.py."""
    rnd = random.Random(seed)

    def rs():
        s = bytes(rnd.randrange(97, 123) for _ in range(rnd.randrange(8)))
        return bytes([len(s)]) + s

    def fval(d):
        t = rnd.choice(b'ABDFISTVbdfilstux?')
        if t == ord('?'):
            return bytes([rnd.randrange(256)])
        m = {ord('I'): 4, ord('D'): 5, ord('T'): 8, ord('t'): 1, ord('b'): 1, ord('B'): 1, ord('s'): 2,
             ord('u'): 2, ord('i'): 4, ord('l'): 8, ord('f'): 4, ord('d'): 8, ord('V'): 0}
        if t in m:
            return bytes([t]) + bytes(rnd.randrange(256) for _ in range(m[t]))
        if t in (ord('S'), ord('x')):
            s = rs()
            n = len(s) if rnd.random() < .9 else rnd.randrange(1 << 32)
            return bytes([t]) + u32(n) + s
        if t == ord('F'):
            return b'F' + tbl(d + 1)
        bb = b''.join(fval(d + 1) for _ in range(rnd.randrange(4))) if d < 8 else b''
        n = len(bb) if rnd.random() < .9 else rnd.randrange(1 << 32)
        return b'A' + u32(n) + bb

    def tbl(d):
        bb = b''.join(rs() + fval(d) for _ in range(rnd.randrange(4))) if d < 8 else b''
        n = len(bb) if rnd.random() < .9 else rnd.choice([rnd.randrange(1 << 32),
                                                           (len(bb) + rnd.randrange(-3, 4)) & 0xffffffff])
        return u32(n) + bb

    def tok():
        r = rnd.random()
        if r < .25: return rs()
        if r < .4: return tbl(0)
        if r < .5: return u64(rnd.randrange(1 << 64))
        if r < .7: return u16(rnd.randrange(1 << 16))
        if r < .85: return u8(rnd.randrange(256))
        return u32(rnd.randrange(1 << 32))

    classes = {10: range(10, 62), 20: range(10, 81), 30: [10, 11], 40: range(10, 52), 50: range(10, 52),
               60: range(10, 121), 70: range(10, 101), 80: range(10, 61), 85: [10, 11], 90: range(10, 32),
               100: range(10, 22), 110: [10]}

    def frm():
        r = rnd.random()
        ch = rnd.randrange(3)
        if r < .7:
            c = rnd.choice(list(classes))
            m = rnd.choice([x for x in classes[c] if x % 10 in (0, 1)] or [1])
            p = u16(c) + u16(m) + b''.join(tok() for _ in range(rnd.randrange(10)))
            ft = 1
        elif r < .85:
            c = rnd.choice([60, 70, 80, 110])
            p = u16(c) + u16(0) + u64(rnd.randrange(100)) + u16(rnd.randrange(1 << 16)) + \
                b''.join(tok() for _ in range(rnd.randrange(12)))
            ft = 2
        else:
            p = bytes(rnd.randrange(256) for _ in range(rnd.randrange(20)))
            ft = 3
        return u8(ft) + u16(ch) + u32(len(p)) + p + b'\xce'

    for conv in range(convs):
        st = TcpStream(cap, ip(30 + conv), ip(2), 42000 + conv + seed * 10)
        st.c(b'AMQP\x01\x01\x00\x09')
        for _ in range(30):
            pl = b''.join(frm() for _ in range(rnd.randrange(1, 4)))
            (st.c if rnd.randrange(2) else st.s)(pl)
        st.close()


def fuzz_010(cap, seed, convs):
    """Structured random 0-10 frames, as fuzz_amqp010.py."""
    rnd = random.Random(seed)

    def s8():
        s = bytes(rnd.randrange(97, 123) for _ in range(rnd.randrange(6)))
        return bytes([len(s)]) + s

    def s16():
        s = bytes(rnd.randrange(97, 123) for _ in range(rnd.randrange(6)))
        return u16(len(s)) + s

    def mapv():
        ents = b''
        n = rnd.randrange(5)
        for _ in range(n):
            t = rnd.choice([0x00, 0x01, 0x02, 0x08, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x80, 0x90, 0x95,
                            0xa0, 0xa8, 0xab, 0xc0, 0xd0, 0xf0, 0xa9, 0xaa, rnd.randrange(256)])
            v = bytes(rnd.randrange(256) for _ in range(rnd.randrange(10)))
            if t in (0xa8, 0xa9, 0xaa):
                v = u32(len(v) if rnd.random() < .8 else rnd.randrange(1 << 32)) + v
            ents += s8() + bytes([t]) + v
        bd = u32(n if rnd.random() < .9 else rnd.randrange(1 << 32)) + ents
        return u32(len(bd) if rnd.random() < .9 else rnd.randrange(1 << 32)) + bd

    def arr(d):
        t = rnd.choice([0x95, 0xab, rnd.randrange(256)])
        n = rnd.randrange(5)
        bb = b''.join(s16() if t == 0x95 else st32(d + 1) for _ in range(n))
        bd = bytes([t]) + u32(n if rnd.random() < .9 else rnd.randrange(1 << 32)) + bb
        return u32(len(bd)) + bd

    def st32(d):
        cc = rnd.choice([(4, 1), (4, 2), (4, 3), (4, 4), (4, 5), (6, 1), (6, 3), (7, 1), (7, 2), (8, 1),
                         (9, 1), (10, 1), (rnd.randrange(256), rnd.randrange(256))])
        inner = bytes(cc) + u16(rnd.randrange(1 << 16))
        if cc == (6, 3) and d < 10:
            inner = bytes(cc) + b'\0\0' + arr(d)
        else:
            inner += b''.join(tok(d) for _ in range(rnd.randrange(8)))
        return u32(len(inner) if rnd.random() < .9 else rnd.randrange(1 << 32)) + inner

    def tok(d=0):
        r = rnd.random()
        if r < .2: return s8()
        if r < .3: return s16()
        if r < .4: return mapv()
        if r < .45 and d < 10: return arr(d)
        if r < .5 and d < 10: return st32(d)
        if r < .6: return u64(rnd.randrange(1 << 64))
        if r < .75: return u16(rnd.randrange(1 << 16))
        if r < .85: return u8(rnd.randrange(256))
        return u32(rnd.randrange(1 << 32))

    def frm():
        ft = rnd.choice([0, 1, 1, 1, 2, 3])
        if ft in (0, 1):
            cl = rnd.randrange(1, 11)
            p = bytes([cl, rnd.randrange(1, 14)])
            if ft == 1:
                p += b'\x01\x00'
            p += u16(rnd.randrange(1 << 16)) + b''.join(tok() for _ in range(rnd.randrange(10)))
        elif ft == 2:
            p = b''.join(st32(0) for _ in range(rnd.randrange(4)))
        else:
            p = bytes(rnd.randrange(256) for _ in range(rnd.randrange(20)))
        return frame010(ft, p, ch=rnd.randrange(3))

    for conv in range(convs):
        st = TcpStream(cap, ip(40 + conv), ip(8), 43000 + conv + seed * 10)
        st.c(b'AMQP\x01\x01\x00\x0a')
        for _ in range(30):
            st.c(b''.join(frm() for _ in range(rnd.randrange(1, 4))))
        st.close()


def build_main():
    cap = Pcap()
    for gen in (amqp09_every_method, amqp091_confirms, amqp08_redirect, version_negotiation,
                amqp09_midstream, amqp010_every_method, amqp010_midstream):
        gen(cap)
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main().write(out + '/amqp0-coverage.pcap')
    bad = Pcap()
    malformed_09(bad)
    malformed_010(bad)
    fuzz_09(bad, 1, 4)
    fuzz_010(bad, 2, 4)
    bad.write(out + '/amqp0-coverage-malformed.pcap')


if __name__ == '__main__':
    main()
