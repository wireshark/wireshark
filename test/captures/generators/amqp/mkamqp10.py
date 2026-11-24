#!/usr/bin/env python3
# Generates test/captures/amqp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the AMQP 1.0 part of the
Wireshark AMQP dissector (epan/dissectors/packet-amqp.c).

Every packet is built from scratch with struct; no captured traffic is used.
All hosts are in 10.1.0.0/24 (the AMQP 0-x coverage capture uses
10.0.0.0/24), the broker listens on TCP port 5672.

Usage: mkamqp10.py <output directory>

Writes:
  amqp10-coverage.pcap            the main capture, decodes without
                                  malformed packets or error expert infos
  amqp10-coverage-malformed.pcap  paths that end in an exception or an
                                  error expert info (including the
                                  reproducers of the boolean and timestamp
                                  field type assertions)
"""

import struct
import sys
import os

PORT = 5672

# --------------------------------------------------------------------------
# pcap writer (Ethernet / IPv4 / TCP)


def ip_checksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, src, dst, sport, dport, seq, ack, flags, payload=b''):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', ip_checksum(pseudo + hdr + payload)) + hdr[18:]
        l4 = hdr + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, 6, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        eth = b'\x02\x00\x00\x01\x00' + bytes([dst[3]]) + b'\x02\x00\x00\x01\x00' + bytes([src[3]]) + b'\x08\x00'
        self.frames.append(eth + ip + l4)

    def write(self, path):
        out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
        t = 1760000000
        for i, f in enumerate(self.frames):
            out += struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f
        with open(path, 'wb') as fh:
            fh.write(out)


class Conn:
    """A TCP connection with a handshake and correct sequence numbers.
    c(data) sends from the client, s(data) from the broker."""
    def __init__(self, cap, client, server=2, cport=40000, sport=PORT, handshake=True):
        self.cap = cap
        self.ca, self.sa = (10, 1, 0, client), (10, 1, 0, server)
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000 + cport, 7000 + cport * 3
        if handshake:
            cap.tcp(self.ca, self.sa, cport, sport, self.cseq, 0, 0x02)
            cap.tcp(self.sa, self.ca, sport, cport, self.sseq, self.cseq + 1, 0x12)
            self.cseq += 1
            self.sseq += 1
            cap.tcp(self.ca, self.sa, cport, sport, self.cseq, self.sseq, 0x10)

    def c(self, data):
        self.cap.tcp(self.ca, self.sa, self.cport, self.sport, self.cseq, self.sseq, 0x18, data)
        self.cseq += len(data)

    def s(self, data):
        self.cap.tcp(self.sa, self.ca, self.sport, self.cport, self.sseq, self.cseq, 0x18, data)
        self.sseq += len(data)

    def close(self):
        self.cap.tcp(self.ca, self.sa, self.cport, self.sport, self.cseq, self.sseq, 0x11)
        self.cseq += 1
        self.cap.tcp(self.sa, self.ca, self.sport, self.cport, self.sseq, self.cseq, 0x11)
        self.sseq += 1
        self.cap.tcp(self.ca, self.sa, self.cport, self.sport, self.cseq, self.sseq, 0x10)


# --------------------------------------------------------------------------
# AMQP 1.0 type encoding (OASIS AMQP 1.0 part 1)

NULL = b'\x40'
TRUE = b'\x41'
FALSE = b'\x42'


def boolean(v):   return b'\x56' + bytes([1 if v else 0])
def ubyte(v):     return b'\x50' + struct.pack('>B', v)
def ushort(v):    return b'\x60' + struct.pack('>H', v)
def uint(v):      return b'\x70' + struct.pack('>I', v)
def smalluint(v): return b'\x52' + struct.pack('>B', v)
UINT0 = b'\x43'
def ulong(v):     return b'\x80' + struct.pack('>Q', v)
def smallulong(v): return b'\x53' + struct.pack('>B', v)
ULONG0 = b'\x44'
def byte(v):      return b'\x51' + struct.pack('>b', v)
def short(v):     return b'\x61' + struct.pack('>h', v)
def int_(v):      return b'\x71' + struct.pack('>i', v)
def smallint(v):  return b'\x54' + struct.pack('>b', v)
def long_(v):     return b'\x81' + struct.pack('>q', v)
def smalllong(v): return b'\x55' + struct.pack('>b', v)
def float_(v):    return b'\x72' + struct.pack('>f', v)
def double(v):    return b'\x82' + struct.pack('>d', v)
def decimal32(b): return b'\x74' + b
def decimal64(b): return b'\x84' + b
def decimal128(b): return b'\x94' + b
def char(c):      return b'\x73' + struct.pack('>I', ord(c))
def timestamp(ms): return b'\x83' + struct.pack('>q', ms)
def uuid(b):      return b'\x98' + b
def vbin8(b):     return b'\xa0' + struct.pack('>B', len(b)) + b
def vbin32(b):    return b'\xb0' + struct.pack('>I', len(b)) + b
def str8(s):      s = s.encode(); return b'\xa1' + struct.pack('>B', len(s)) + s
def str32(s):     s = s.encode(); return b'\xb1' + struct.pack('>I', len(s)) + s
def sym8(s):      s = s.encode(); return b'\xa3' + struct.pack('>B', len(s)) + s
def sym32(s):     s = s.encode(); return b'\xb3' + struct.pack('>I', len(s)) + s

LIST0 = b'\x45'


def list8(*items):
    body = b''.join(items)
    return b'\xc0' + struct.pack('>BB', len(body) + 1, len(items)) + body


def list32(*items):
    body = b''.join(items)
    return b'\xd0' + struct.pack('>II', len(body) + 4, len(items)) + body


def map8(*pairs):
    body = b''.join(k + v for k, v in pairs)
    return b'\xc1' + struct.pack('>BB', len(body) + 1, 2 * len(pairs)) + body


def map32(*pairs):
    body = b''.join(k + v for k, v in pairs)
    return b'\xd1' + struct.pack('>II', len(body) + 4, 2 * len(pairs)) + body


def array8(ctor, *elems):
    """ctor: element constructor (type code, or descriptor + type code);
    elems: element values without constructor."""
    body = ctor + b''.join(elems)
    return b'\xe0' + struct.pack('>BB', len(body) + 1, len(elems)) + body


def array32(ctor, *elems):
    body = ctor + b''.join(elems)
    return b'\xf0' + struct.pack('>II', len(body) + 4, len(elems)) + body


def described(code, value):
    """Described type with a smallulong descriptor."""
    return b'\x00\x53' + bytes([code]) + value


def sym_array(*names):
    return array8(b'\xa3', *[struct.pack('>B', len(n)) + n.encode() for n in names])


# descriptor codes
ERROR, HEADER, DELIVERY_ANN, MESSAGE_ANN, PROPERTIES, APP_PROPERTIES = 0x1d, 0x70, 0x71, 0x72, 0x73, 0x74
DATA, SEQUENCE, VALUE, FOOTER = 0x75, 0x76, 0x77, 0x78
RECEIVED, ACCEPTED, REJECTED, RELEASED, MODIFIED = 0x23, 0x24, 0x25, 0x26, 0x27
SOURCE, TARGET = 0x28, 0x29
DELETE_ON_CLOSE, DELETE_ON_NO_LINKS, DELETE_ON_NO_MESSAGES, DELETE_ON_NO_LINKS_OR_MESSAGES = 0x2b, 0x2c, 0x2d, 0x2e
COORDINATOR, DECLARE, DISCHARGE, DECLARED, TRANSACTIONAL_STATE = 0x30, 0x31, 0x32, 0x33, 0x34

OPEN, BEGIN, ATTACH, FLOW, TRANSFER, DISPOSITION, DETACH, END, CLOSE = range(0x10, 0x19)
SASL_MECHANISMS, SASL_INIT, SASL_CHALLENGE, SASL_RESPONSE, SASL_OUTCOME = range(0x40, 0x45)

HDR_AMQP = b'AMQP\x00\x01\x00\x00'
HDR_TLS = b'AMQP\x02\x01\x00\x00'
HDR_SASL = b'AMQP\x03\x01\x00\x00'


def frame(body, ftype=0, channel=0, ext=b''):
    """AMQP 1.0 frame: size, doff, type, channel, extended header, body."""
    assert len(ext) % 4 == 0
    doff = 2 + len(ext) // 4
    return struct.pack('>IBBH', 8 + len(ext) + len(body), doff, ftype, channel) + ext + body


def perf(code, args, channel=0, payload=b''):
    """Performative: described list (0x00 0x53 code) + args + payload."""
    return frame(b'\x00\x53' + bytes([code]) + args + payload, 0, channel)


def sasl(code, args):
    return frame(b'\x00\x53' + bytes([code]) + args, 1, 0)


def error(cond, desc=None, info=None):
    items = [sym8(cond)]
    if desc is not None or info is not None:
        items.append(str8(desc) if desc is not None else NULL)
    if info is not None:
        items.append(info)
    return described(ERROR, list8(*items))


UUID1 = bytes.fromhex('0123456789abcdef0123456789abcdef')
UUID2 = bytes.fromhex('f47ac10b58cc4372a5670e02b2c3d479')
T0 = 1760000000123          # ms since the epoch


def properties(message_id=None, to=None, correlation_id=None, full=False):
    """properties section; full=True fills in all 13 fields."""
    if full:
        return described(PROPERTIES, list8(
            message_id if message_id is not None else smallulong(7),
            vbin8(b'guest'),
            str8(to or 'queue://orders'),
            str8('new order'),
            str8('queue://replies'),
            correlation_id if correlation_id is not None else str8('corr-1'),
            sym8('application/json'),
            sym8('identity'),
            timestamp(T0 + 3600000),
            timestamp(T0),
            str8('group-a'),
            smalluint(3),
            str8('group-replies')))
    items = [message_id if message_id is not None else NULL, NULL, str8(to) if to else NULL]
    if correlation_id is not None:
        items += [NULL, NULL, correlation_id]
    return described(PROPERTIES, list8(*items))


# --------------------------------------------------------------------------
# main capture


def build_main():
    cap = Pcap()
    port = [41000]

    def conn(client, **kw):
        port[0] += 1
        return Conn(cap, client, cport=port[0], **kw)

    # ---- 1: SASL PLAIN, then a full AMQP session with every performative.
    # Client 10.1.0.1 -> broker 10.1.0.2
    a = conn(1)
    a.c(HDR_SASL)
    a.s(HDR_SASL)
    a.s(sasl(SASL_MECHANISMS, list8(sym_array('PLAIN', 'ANONYMOUS', 'EXTERNAL'))))
    a.c(sasl(SASL_INIT, list8(sym8('PLAIN'), vbin8(b'\0guest\0guest'), str8('broker.example'))))
    a.s(sasl(SASL_CHALLENGE, list8(vbin8(b'challenge-data'))))
    a.c(sasl(SASL_RESPONSE, list8(vbin32(b'response-data'))))
    a.s(sasl(SASL_OUTCOME, list8(ubyte(0), vbin8(b'welcome'))))
    a.c(HDR_AMQP)
    a.s(HDR_AMQP)
    # open with all ten fields; locales and capabilities as arrays and as
    # single symbols (the *_sym synonym fields)
    a.c(perf(OPEN, list8(
        str8('client-container-1'),
        str8('broker.example'),
        uint(65536),
        ushort(255),
        uint(30000),
        sym8('en-US'),
        sym_array('en-US', 'de-DE'),
        sym8('ANONYMOUS-RELAY'),
        sym_array('DELAYED_DELIVERY', 'SHARED-SUBS'),
        map8((sym8('product'), str8('synthetic-client')),
             (sym8('version'), str8('1.0')),
             (sym8('platform'), NULL)))))
    a.s(perf(OPEN, list8(
        str8('broker-container'),
        NULL,
        smalluint(255),
        ushort(1023),
        UINT0,
        sym_array('en-US'),
        sym8('en-US'),
        sym_array('ANONYMOUS-RELAY', 'SHARED-SUBS'),
        sym8('DELAYED_DELIVERY'),
        map8((sym8('product'), str8('synthetic-broker'))),
        str8('extra eleventh field'))))   # more fields than open defines
    # begin with all eight fields
    a.c(perf(BEGIN, list8(NULL, uint(1), uint(2048), uint(2048), uint(255),
                          sym8('cap-a'), sym_array('cap-b', 'cap-c'),
                          map8((sym8('session-prop'), smallint(-5)))), channel=0))
    a.s(perf(BEGIN, list8(UINT0, smalluint(1), smalluint(200), uint(2048), smallulong(7),
                          sym_array('cap-a'), sym8('cap-b'), map8())))
    # attach (sender) with full source and target
    source = described(SOURCE, list8(
        str8('queue://orders'),
        smalluint(2),                    # unsettled-state
        sym8('link-detach'),
        smalluint(60),
        TRUE,
        map8((sym8('lifetime-policy'), described(DELETE_ON_CLOSE, LIST0)),
             (sym8('x-opt-ttl'), uint(1000))),
        sym8('move'),
        map8((sym8('selector'), b'\x00\xa3' + struct.pack('>B', 33) + b'apache.org:selector-filter:string' + str8("colour = 'red'"))),
        described(ACCEPTED, LIST0),
        sym_array('amqp:accepted:list', 'amqp:rejected:list', 'amqp:released:list', 'amqp:modified:list'),
        sym8('queue')))
    target = described(TARGET, list8(
        str8('queue://orders'),
        UINT0,
        sym8('session-end'),
        UINT0,
        FALSE,
        map8((sym8('lifetime-policy'), described(DELETE_ON_NO_LINKS, LIST0))),
        sym_array('queue', 'topic')))
    a.c(perf(ATTACH, list32(
        str8('sender-link-1'),
        UINT0,
        FALSE,                           # role: sender
        ubyte(2),                        # mixed
        ubyte(1),                        # second
        source,
        target,
        map8((vbin8(b'tag-1'), described(ACCEPTED, LIST0)),
             (vbin8(b'tag-2'), NULL)),
        TRUE,
        uint(0),
        ulong(1048576),
        sym8('cap-x'),
        sym_array('cap-y'),
        map8((sym8('link-prop'), TRUE)))))
    a.s(perf(ATTACH, list8(
        str8('sender-link-1'),
        smalluint(0),
        TRUE,                            # role: receiver
        UINT0,
        UINT0,
        described(SOURCE, list8(str8('queue://orders'))),
        described(TARGET, list8(str8('queue://orders'), NULL, NULL, NULL, TRUE,
                                map8((sym8('lifetime-policy'), described(DELETE_ON_NO_MESSAGES, LIST0))))),
        NULL,
        boolean(False),
        NULL,
        ULONG0,
        sym_array('cap-x'),
        NULL,
        NULL)))
    # flow with all eleven fields
    a.s(perf(FLOW, list8(uint(1), uint(2048), uint(1), uint(2048), UINT0, uint(0),
                         uint(100), uint(5), boolean(True), FALSE,
                         map8((sym8('flow-prop'), sym8('x'))))))
    a.c(perf(FLOW, list8(smalluint(1), smalluint(200), UINT0, smalluint(200), smalluint(0),
                         smalluint(1), UINT0, NULL, FALSE, TRUE)))
    # transfer with every message section
    msg = (described(HEADER, list8(TRUE, ubyte(4), smalluint(200), FALSE, uint(0))) +
           described(DELIVERY_ANN, map8((sym8('x-opt-delivery-ann'), str8('da')))) +
           described(MESSAGE_ANN, map8((sym8('x-opt-partition-key'), str8('p1')),
                                       (smallulong(42), int_(-42)),
                                       (sym8('x-opt-enqueued-time'), timestamp(T0)))) +
           properties(full=True) +
           described(APP_PROPERTIES, map8((str8('colour'), str8('red')),
                                          (str8('size'), long_(1234567890123)),
                                          (str8('weight'), double(2.5)))) +
           described(DATA, vbin8(b'{"order": 1, "item": "widget"}')) +
           described(FOOTER, map8((sym8('x-opt-crc'), uint(0xdeadbeef)))))
    a.c(perf(TRANSFER, list8(UINT0, UINT0, vbin8(b'\x00\x00\x00\x01'), UINT0, FALSE, FALSE,
                             ubyte(0), NULL, FALSE, FALSE, TRUE), payload=msg))
    # amqp-sequence and amqp-value bodies, settled
    a.c(perf(TRANSFER, list8(UINT0, smalluint(1), vbin8(b'\x02'), uint(0), TRUE),
             payload=described(HEADER, list8(NULL, NULL, NULL, TRUE, smalluint(1))) +
             described(SEQUENCE, list8(str8('one'), int_(2), double(3.0))) +
             described(SEQUENCE, list8(TRUE, NULL))))
    a.c(perf(TRANSFER, list8(UINT0, smalluint(2), vbin8(b'\x03'), uint(0)),
             payload=properties(message_id=str8('msg-string-id'), to='queue://orders',
                                correlation_id=uuid(UUID2)) +
             described(VALUE, str8('hello amqp-value'))))
    a.c(perf(TRANSFER, list8(UINT0, smalluint(3), vbin8(b'\x04'), uint(0)),
             payload=properties(message_id=uuid(UUID1), to='queue://orders',
                                correlation_id=vbin8(b'\x01\x02\x03')) +
             described(VALUE, map8((str8('k'), str8('v'))))))
    a.c(perf(TRANSFER, list8(UINT0, smalluint(4), vbin8(b'\x05'), uint(0)),
             payload=properties(message_id=vbin8(b'binary-id'), to='queue://orders',
                                correlation_id=smallulong(9)) +
             described(VALUE, NULL)))
    a.c(perf(TRANSFER, list8(UINT0, smalluint(5), vbin8(b'\x06'), uint(0)),
             payload=properties(message_id=UINT0, to='queue://orders',
                                correlation_id=ULONG0) +
             described(VALUE, list8(uint(1), uint(2)))))
    # disposition with every delivery state / outcome
    a.s(perf(DISPOSITION, list8(TRUE, UINT0, uint(0), TRUE, described(ACCEPTED, LIST0), FALSE)))
    a.s(perf(DISPOSITION, list8(TRUE, smalluint(1), NULL, FALSE,
                                described(RECEIVED, list8(uint(2), smallulong(128))))))
    a.s(perf(DISPOSITION, list8(TRUE, smalluint(2), NULL, TRUE,
                                described(REJECTED, list8(error(
                                    'amqp:invalid-field', 'bad field',
                                    map8((sym8('field'), str8('colour')))))))))
    a.s(perf(DISPOSITION, list8(TRUE, smalluint(3), NULL, TRUE, described(RELEASED, LIST0))))
    a.s(perf(DISPOSITION, list8(TRUE, smalluint(4), smalluint(5), TRUE,
                                described(MODIFIED, list8(TRUE, FALSE,
                                                          map8((sym8('x-opt-retry'), uint(1))))),
                                TRUE)))
    a.s(perf(DISPOSITION, list8(TRUE, smalluint(5), NULL, TRUE,
                                described(MODIFIED, list8(boolean(False), boolean(True))))))
    # detach, end and close, with errors
    a.c(perf(DETACH, list8(UINT0, TRUE)))
    a.s(perf(DETACH, list8(UINT0, TRUE, error('amqp:link:detach-forced', 'forced'))))
    a.c(perf(END, LIST0))
    a.s(perf(END, list8(error('amqp:session:window-violation'))))
    a.c(perf(CLOSE, list8(NULL)))
    a.s(perf(CLOSE, list8(error('amqp:connection:forced', 'shutting down',
                                map8((sym8('network-host'), str8('10.1.0.2')),
                                     (sym8('port'), uint(5672)))))))
    a.close()

    # ---- 2: SASL outcomes auth, sys, sys-perm, sys-temp and an unknown
    # code; ANONYMOUS init with only the mechanism; empty mechanisms list
    for code in (1, 2, 3, 4, 7):
        b = conn(3)
        b.c(HDR_SASL)
        b.s(HDR_SASL)
        b.s(sasl(SASL_MECHANISMS, list8(sym8('ANONYMOUS'))))
        b.c(sasl(SASL_INIT, list8(sym8('ANONYMOUS'))))
        b.s(sasl(SASL_OUTCOME, list8(ubyte(code))))
        b.close()

    # ---- 3: protocol header for TLS, in both directions, then the
    # connection ends (the TLS handshake is not part of this capture)
    t = conn(4)
    t.c(HDR_TLS)
    t.s(HDR_TLS)
    t.close()

    # ---- 4: framing and TCP reassembly: several frames in one segment,
    # a frame over three segments, a split inside the frame header, empty
    # (keep-alive) frames, an extended header (doff 3), channel 5, and a
    # message sent as a multi-frame transfer
    f = conn(5)
    f.c(HDR_AMQP)
    f.s(HDR_AMQP)
    f.c(perf(OPEN, list32(str8('reassembly-client'), str8('broker.example'), uint(512))))
    f.s(perf(OPEN, list8(str8('broker-container'), NULL, uint(512))) +
        perf(BEGIN, list8(ushort(5), uint(1), uint(100), uint(100)), channel=5))
    f.c(perf(BEGIN, list8(NULL, uint(1), uint(100), uint(100)), channel=5))
    # keep-alive frames: one alone, two in one segment
    f.c(frame(b''))
    f.s(frame(b'') + frame(b''))
    # extended header (doff 3, four octets ignored)
    f.c(frame(b'\x00\x53\x12' + list8(str8('receiver-link'), uint(1), TRUE, NULL, NULL,
                                       described(SOURCE, list8(str8('topic://news'))),
                                       described(TARGET, LIST0)),
              0, 5, ext=b'\x00\x00\x00\x00'))
    f.s(perf(ATTACH, list8(str8('receiver-link'), uint(1), FALSE, NULL, NULL,
                           described(SOURCE, list8(str8('topic://news'))),
                           described(TARGET, LIST0), NULL, NULL, uint(0)), channel=5))
    f.c(perf(FLOW, list8(uint(1), uint(100), uint(1), uint(100), uint(1), uint(0), uint(10)), channel=5))
    # a multi-frame transfer (more=true, split at section boundaries)
    big = bytes(range(256)) * 3
    t1 = perf(TRANSFER, list8(uint(1), uint(0), vbin8(b'big-1'), uint(0), FALSE, TRUE), channel=5,
              payload=described(HEADER, list8(TRUE)) +
              properties(message_id=str8('big-message'), to='topic://news'))
    t2 = perf(TRANSFER, list8(uint(1), NULL, NULL, NULL, NULL, TRUE), channel=5,
              payload=described(DATA, vbin32(big)))
    t3 = perf(TRANSFER, list8(uint(1), NULL, NULL, NULL, NULL, FALSE), channel=5,
              payload=described(DATA, vbin8(b'tail of the message')) +
              described(FOOTER, map8((sym8('x-opt-part'), uint(3)))))
    f.s(t1)
    # t2 (about 790 octets) over three segments, the first split inside
    # the frame header
    f.s(t2[:5])
    f.s(t2[5:400])
    f.s(t2[400:])
    # t3 and the next transfer in one segment, the second cut and finished
    # in the next segment
    t4 = perf(TRANSFER, list8(uint(1), uint(1), vbin8(b'abort'), uint(0), FALSE, TRUE), channel=5,
              payload=described(DATA, vbin8(b'partial')))
    t5 = perf(TRANSFER, list8(uint(1), uint(1), NULL, NULL, NULL, FALSE, NULL, NULL, FALSE, TRUE), channel=5)
    f.s(t3 + t4[:20])
    f.s(t4[20:] + t5)
    # a resumed delivery with a received state
    f.s(perf(TRANSFER, list8(uint(1), uint(2), vbin8(b'resume'), uint(0), FALSE, FALSE, NULL,
                             described(RECEIVED, list8(UINT0, ULONG0)), TRUE), channel=5,
             payload=described(VALUE, str8('resumed'))))
    f.c(perf(DISPOSITION, list8(TRUE, uint(0), uint(2), TRUE, described(ACCEPTED, LIST0)), channel=5))
    f.c(perf(DETACH, list8(uint(1), TRUE), channel=5))
    f.s(perf(DETACH, list8(uint(1), TRUE), channel=5))
    f.c(perf(END, LIST0, channel=5))
    f.s(perf(END, LIST0, channel=5))
    f.c(perf(CLOSE, LIST0))
    f.s(perf(CLOSE, LIST0))
    f.close()

    # ---- 5: a connection captured in the middle (no protocol header,
    # no handshake): the version is found from the frame
    m = conn(6, handshake=False)
    m.c(perf(FLOW, list8(uint(10), uint(100), uint(10), uint(100), uint(0), uint(4), uint(50))))
    m.s(perf(TRANSFER, list8(uint(0), uint(9), vbin8(b'mid'), uint(0), TRUE),
             payload=described(VALUE, sym8('mid-stream'))))
    m.close()

    # ---- 6: transactions: coordinator target, declare, declared,
    # transactional state, discharge
    x = conn(7)
    x.c(HDR_AMQP)
    x.s(HDR_AMQP)
    x.c(perf(OPEN, list8(str8('tx-client'))))
    x.s(perf(OPEN, list8(str8('tx-broker'))))
    x.c(perf(BEGIN, list8(NULL, uint(0), uint(100), uint(100))))
    x.s(perf(BEGIN, list8(ushort(0), uint(0), uint(100), uint(100))))
    x.c(perf(ATTACH, list8(str8('txn-ctrl'), UINT0, FALSE, NULL, NULL,
                           described(SOURCE, list8(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                                   sym_array('amqp:accepted:list', 'amqp:rejected:list'))),
                           described(COORDINATOR, list8(sym_array('amqp:local-transactions',
                                                                  'amqp:multi-txns-per-ssn'))))))
    x.s(perf(ATTACH, list8(str8('txn-ctrl'), UINT0, TRUE, NULL, NULL, NULL,
                           described(COORDINATOR, list8(sym8('amqp:local-transactions'))))))
    x.s(perf(FLOW, list8(uint(0), uint(100), uint(0), uint(100), UINT0, uint(0), uint(10))))
    x.c(perf(TRANSFER, list8(UINT0, UINT0, vbin8(b'\x00'), uint(0)),
             payload=described(DECLARE, list8(NULL))))   # see README: not inside amqp-value
    x.s(perf(DISPOSITION, list8(TRUE, UINT0, NULL, TRUE, described(DECLARED, list8(vbin8(b'txn-0001'))))))
    x.c(perf(TRANSFER, list8(smalluint(1), smalluint(1), vbin8(b'\x01'), uint(0), FALSE, FALSE, NULL,
                             described(TRANSACTIONAL_STATE, list8(vbin8(b'txn-0001'), NULL))),
             payload=described(VALUE, str8('in a transaction'))))
    x.s(perf(DISPOSITION, list8(TRUE, smalluint(1), NULL, FALSE,
                                described(TRANSACTIONAL_STATE, list8(vbin8(b'txn-0001'),
                                                                     described(ACCEPTED, LIST0))))))
    x.c(perf(TRANSFER, list8(UINT0, smalluint(2), vbin8(b'\x02'), uint(0)),
             payload=described(DISCHARGE, list8(vbin8(b'txn-0001'), FALSE))))
    x.c(perf(TRANSFER, list8(UINT0, smalluint(3), vbin8(b'\x03'), uint(0)),
             payload=described(DISCHARGE, list8(vbin8(b'txn-0002'), boolean(True)))))
    x.s(perf(DISPOSITION, list8(TRUE, smalluint(2), smalluint(3), TRUE, described(ACCEPTED, LIST0))))
    # remaining lifetime policy
    x.c(perf(ATTACH, list8(str8('dyn'), smalluint(1), TRUE, NULL, NULL,
                           described(SOURCE, list8(NULL, NULL, NULL, NULL, TRUE,
                                                   map8((sym8('lifetime-policy'),
                                                         described(DELETE_ON_NO_LINKS_OR_MESSAGES, LIST0))))),
                           described(TARGET, LIST0))))
    x.c(perf(CLOSE, LIST0))
    x.s(perf(CLOSE, LIST0))
    x.close()

    # ---- 7: every primitive type encoding, in custom lists (amqp-sequence),
    # maps (application-properties), arrays and as described values
    p = conn(8)
    p.c(HDR_AMQP)
    p.s(HDR_AMQP)
    p.c(perf(OPEN, list8(str8('types-client'))))
    p.c(perf(BEGIN, list8(NULL, uint(0), uint(100), uint(100))))
    p.c(perf(ATTACH, list8(str8('types'), UINT0, FALSE, NULL, NULL, NULL,
                           described(TARGET, list8(str8('queue://types'))))))
    all_types = [
        NULL, TRUE, FALSE, boolean(True), boolean(False),
        ubyte(200), ushort(60000), uint(4000000000), smalluint(17), UINT0,
        ulong(0x1122334455667788), smallulong(99), ULONG0,
        byte(-100), short(-30000), int_(-2000000000), smallint(-17),
        long_(-0x112233445566778), smalllong(-99),
        float_(1.5), double(-2.25),
        decimal32(b'\x22\x50\x00\x01'), decimal64(b'\x22\x38\x00\x00\x00\x00\x00\x01'),
        decimal128(b'\x22\x08' + bytes(13) + b'\x01'),
        char('A'), char('€'), timestamp(T0), timestamp(-1000), uuid(UUID1),
        vbin8(b'\x00\x01\x02'), vbin32(b'\xff' * 3), vbin8(b''),
        str8('short string'), str32('long-form string'), str8(''),
        sym8('symbol'), sym32('long-form-symbol'),
        LIST0, list8(), list8(uint(1), str8('nested')), list32(sym8('in-list32')),
        map8(), map8((sym8('k'), sym8('v'))), map32((str8('k32'), uint(32))),
        array8(b'\x70', struct.pack('>I', 1), struct.pack('>I', 2)),
        array32(b'\xa1', b'\x02ab', b'\x02cd'),
    ]
    p.c(perf(TRANSFER, list8(UINT0, UINT0, vbin8(b'types-1'), uint(0), TRUE),
             payload=described(SEQUENCE, list32(*all_types))))
    # the same values in a map, keyed by every fixed type that can be a key
    keys = [NULL, TRUE, FALSE, boolean(True), ubyte(1), ushort(2), uint(3), smalluint(4), UINT0,
            ulong(5), smallulong(6), ULONG0, byte(-1), short(-2), int_(-3), smallint(-4),
            long_(-5), smalllong(-6), float_(0.5), double(0.25), decimal32(bytes(4)),
            decimal64(bytes(8)), decimal128(bytes(16)), char('k'), timestamp(T0), uuid(UUID2),
            vbin8(b'key'), vbin32(b'key32'), str8('key'), str32('key32'), sym8('key'), sym32('key32')]
    pairs = [(k, all_types[i % len(all_types)]) for i, k in enumerate(keys)]
    p.c(perf(TRANSFER, list8(UINT0, smalluint(1), vbin8(b'types-2'), uint(0), TRUE),
             payload=described(APP_PROPERTIES, map32(*pairs)) +
             described(VALUE, TRUE)))
    # arrays of every fixed-width and variable-width element type
    arrays = [
        array8(b'\x56', b'\x01', b'\x00'),
        array8(b'\x50', b'\x01', b'\x02', b'\x03'),
        array8(b'\x60', struct.pack('>H', 1000), struct.pack('>H', 2000)),
        array8(b'\x52', b'\x05'),
        array8(b'\x80', struct.pack('>Q', 1), struct.pack('>Q', 2)),
        array8(b'\x53', b'\x07', b'\x08'),
        array8(b'\x51', b'\xff'),
        array8(b'\x61', struct.pack('>h', -1)),
        array8(b'\x71', struct.pack('>i', -2), struct.pack('>i', 3)),
        array8(b'\x54', b'\xfe'),
        array8(b'\x81', struct.pack('>q', -3)),
        array8(b'\x55', b'\xfd'),
        array8(b'\x72', struct.pack('>f', 0.75)),
        array8(b'\x82', struct.pack('>d', 1e100)),
        array8(b'\x74', bytes(4)),
        array8(b'\x84', bytes(8)),
        array8(b'\x94', bytes(16)),
        array8(b'\x73', struct.pack('>I', ord('x')), struct.pack('>I', ord('y'))),
        array8(b'\x83', struct.pack('>q', T0), struct.pack('>q', T0 + 1)),
        array8(b'\x98', UUID1, UUID2),
        array8(b'\xa0', b'\x02\xaa\xbb'),
        array32(b'\xb0', struct.pack('>I', 2) + b'\xcc\xdd'),
        array8(b'\xa1', b'\x03abc', b'\x03def'),
        array32(b'\xb1', struct.pack('>I', 3) + b'ghi'),
        array8(b'\xa3', b'\x03jkl'),
        array32(b'\xb3', struct.pack('>I', 3) + b'mno'),
        array8(b'\x70'),                          # empty array
        array8(b'\xc0', b'\x03\x01\x52\x07'),     # array of one list
        array8(b'\xc1', b'\x05\x02\xa3\x01k\x41'),  # array of one map
        array8(b'\xe0', b'\x03\x01\x50\x09'),     # array of one array
        # array of one described error (descriptor in the constructor)
        array8(b'\x00\x53\x1d\xc0', struct.pack('>BB', 4, 1) + sym8('x')),
        # array of accepted outcomes with a symbolic descriptor
        array8(b'\x00\xa3\x12amqp:accepted:list\xc0', struct.pack('>BB', 1, 0)),
    ]
    p.c(perf(TRANSFER, list8(UINT0, smalluint(2), vbin8(b'types-3'), uint(0), TRUE),
             payload=described(SEQUENCE, list32(*arrays))))
    # descriptor encodings: ulong, symbol (sym8, sym32), ulong0, ushort,
    # uint, uuid, and the 0x?f extension form
    descr = [
        b'\x00\x80' + struct.pack('>Q', 0x77) + str8('ulong descriptor'),
        b'\x00\xa3\x15amqp:amqp-value:*****' + str8('sym8 descriptor'),
        b'\x00\xb3' + struct.pack('>I', 19) + b'example:custom:list' + list8(uint(1)),
        b'\x00\x44' + str8('ulong0 descriptor'),
        b'\x00\x60\x00\x77' + str8('ushort descriptor'),
        b'\x00\x70\x00\x00\x00\x77' + str8('uint descriptor'),
        b'\x00\x98' + UUID1 + str8('uuid descriptor'),
        b'\x00\x5f\x01\x77' + str8('extension descriptor'),
        b'\x00\x53\x24' + LIST0,                  # accepted, outside a state field
        b'\x00\x53\x99' + str8('unknown descriptor code'),
    ]
    p.c(perf(TRANSFER, list8(UINT0, smalluint(3), vbin8(b'types-4'), uint(0), TRUE),
             payload=described(SEQUENCE, list32(*descr))))
    # amqp-value with a map, a list32, a map32, an array32 body; data
    # section holding a map (data is FT_BYTES)
    p.c(perf(TRANSFER, list8(UINT0, smalluint(4), vbin8(b'types-5'), uint(0), TRUE),
             payload=described(VALUE, map32((sym8('a'), list32(uint(1), map32((sym8('b'), array32(b'\x50', b'\x01')))))))
             + described(DATA, vbin32(b'data in vbin32'))
             + described(DATA, map8((sym8('map'), str8('in data'))))))
    # fields encoded with less common types: ulong0 maxMessageSize,
    # str32 subject, decimal user-id, smallulong handle, list32/map32 in
    # performatives
    p.c(perf(ATTACH, list32(str8('types-2'), smallulong(1), FALSE, UINT0, UINT0, NULL,
                            described(TARGET, list32(str8('queue://types'))), map32(),
                            NULL, uint(0), ULONG0, NULL, NULL, map32((sym8('p'), NULL)))))
    p.c(perf(TRANSFER, list8(smallulong(1), UINT0, decimal32(b'\x01\x02\x03\x04'), uint(0), TRUE),
             payload=described(PROPERTIES, list8(NULL, decimal64(bytes(8)), NULL, str32('subject in str32'))) +
             described(VALUE, ULONG0)))
    # a described type whose value is an array instead of a list: the
    # array elements take the field names of the described list (source:
    # address, terminus-durable)
    p.c(perf(ATTACH, list8(str8('types-3'), smalluint(2), FALSE, NULL, NULL,
                           described(SOURCE, array8(b'\xa1', b'\x0dqueue://array')),
                           described(TARGET, array8(b'\x52', b'\x01')))))
    p.c(perf(CLOSE, LIST0))
    p.close()

    # ---- 8: message decoding by topic (the "Message Decoding" UAT,
    # amqp.message_decode_table): transfers to different "to" addresses
    # with a JSON body; see runcov.sh for the table entries
    d = conn(9)
    d.c(HDR_AMQP)
    d.s(HDR_AMQP)
    d.c(perf(OPEN, list8(str8('decode-client'))))
    d.c(perf(BEGIN, list8(NULL, uint(0), uint(100), uint(100))))
    d.c(perf(ATTACH, list8(str8('anon'), UINT0, FALSE, NULL, NULL, NULL, described(TARGET, LIST0))))
    for i, to in enumerate(('sensors/equal', 'x/contains-me/y', 'prefix/abc', 'abc.suffix',
                            'regex-42', 'nomatch', 'ab')):
        d.c(perf(TRANSFER, list8(UINT0, smalluint(i), vbin8(bytes([i])), uint(0), TRUE),
                 payload=properties(message_id=smallulong(i), to=to) +
                 described(DATA, vbin8(b'{"topic": "%s", "value": %d}' % (to.encode(), i)))))
    # data without a properties section
    d.c(perf(TRANSFER, list8(UINT0, smalluint(9), vbin8(b'\x09'), uint(0), TRUE),
             payload=described(DATA, vbin8(b'{"no": "to"}'))))
    d.c(perf(CLOSE, LIST0))
    d.close()

    # ---- 9: a protocol header of an unknown AMQP version
    u = conn(10)
    u.c(b'AMQP\x00\x00\x00\x07')
    u.close()

    return cap


# --------------------------------------------------------------------------
# malformed capture: one connection per case, protocol header and frame in
# one segment each


def build_malformed():
    cap = Pcap()
    port = [42000]

    def case(*frames, header=HDR_AMQP):
        port[0] += 1
        c = Conn(cap, 20, server=21, cport=port[0], handshake=False)
        if header:
            c.c(header)
        for fr in frames:
            c.c(fr)

    def open_with(*items):
        return perf(OPEN, list8(str8('a'), *items))

    # Branch fix reproducers (mkamqp_bool_assert.py and
    # mkamqp_time_assert.py): boolean and timestamp for maxFrameSize
    case(perf(OPEN, list8(str8('a'), NULL, TRUE)))
    case(perf(OPEN, list8(str8('a'), NULL, timestamp(0))))
    # false for an integer field, timestamp for a string field
    case(perf(OPEN, list8(str8('a'), NULL, FALSE)))
    case(perf(OPEN, list8(str8('a'), timestamp(T0))))
    # uint0 for a boolean field (dissect_amqp_1_0_zero default)
    case(perf(ATTACH, list8(str8('l'), UINT0, UINT0)))
    # ulong into an FT_UINT8 synonym (messageId) and a 4-octet uint into
    # FT_UINT8 header ttl
    case(perf(TRANSFER, list8(UINT0, UINT0, vbin8(b'1'), uint(0), TRUE),
              payload=described(HEADER, list8(TRUE, ubyte(4), uint(60000))) +
              properties(message_id=ulong(123456789))))
    # performative arguments that are not a list
    case(perf(OPEN, map8()))
    case(perf(TRANSFER, str8('not a list')))
    # list count larger than its size; list cut short
    case(perf(OPEN, b'\xc0\x01\x05'))
    case(perf(OPEN, b'\xc0\x10\x05' + str8('a')))
    # map with an odd count, count larger than size, unknown key type
    case(open_with(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, b'\xc1\x01\x01'))
    case(open_with(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, b'\xc1\x01\x04'))
    case(open_with(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                   b'\xc1\x05\x02' + LIST0 + str8('v')))
    # array count larger than size; array cut short
    case(open_with(NULL, NULL, NULL, NULL, b'\xe0\x02\x09\xa3'))
    case(open_with(NULL, NULL, NULL, NULL, b'\xe0\x40\x05\xa3\x01a'))
    # array of zero-width elements: count larger than size, and a valid
    # array of two "true" whose elements are each taken as one octet
    case(open_with(NULL, NULL, NULL, NULL, b'\xe0\x02\x04\x40'))
    case(open_with(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, b'\xe0\x02\x02\x41'))
    # an array of two nulls followed by two octets of padding that the
    # size includes: the padding is taken as the (zero-width) elements
    case(open_with(NULL, NULL, NULL, NULL, b'\xe0\x04\x02\x40\x00\x00', sym8('in')))
    # array of two lists: the second is read from the wrong offset
    case(open_with(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                   b'\xe0\x07\x02\xc0' + b'\x02\x01\x41' + b'\x02\x01\x42'))
    # unknown type codes in a list, as a section, as a map value
    case(open_with(b'\x01'))
    case(perf(TRANSFER, list8(UINT0, UINT0, vbin8(b'1'), uint(0)), payload=b'\x02\x03'))
    case(open_with(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, map8((sym8('k'), b'\x0f'))))
    # unknown performative, SASL method and frame type
    case(frame(b'\x00\x53\x20' + LIST0))
    case(frame(b'\x00\x53\x50' + LIST0, 1), header=HDR_SASL)
    case(frame(b'\x00\x53\x10' + LIST0, 5))
    # a TLS frame type in a frame (not a protocol header)
    case(frame(b'\x00\x53\x10' + LIST0, 2))
    # doff 0: the frame header is taken as the body (size 0x1045 makes
    # it an open with list0 arguments)
    case(struct.pack('>IBBH', 0x1045, 0, 0, 0) + bytes(0x1045 - 8))
    # doff larger than the frame size
    case(struct.pack('>IBBH', 8, 4, 0, 0))
    # truncated values: str8 longer than the frame, vbin32, uuid
    case(open_with(b'\xa1\x40ab'))
    case(open_with(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, map8((sym8('k'), b'\xb0\x00\x00\x10\x00'))))
    case(perf(TRANSFER, list8(UINT0, UINT0, vbin8(b'1')), payload=b'\x00\x53\x75\xa0\x20'))
    case(perf(TRANSFER, list8(UINT0, UINT0, vbin8(b'1')), payload=b'\x00\x53\x73\xc0\x12\x01\x98\x01'))
    # a list32 that claims more than the frame
    case(perf(OPEN, b'\xd0\x00\x00\x10\x00\x00\x00\x00\x02' + str8('a')))
    # a described value inside a described value (the spec-conform
    # transaction declare: amqp-value holding a declare)
    case(perf(TRANSFER, list8(UINT0, UINT0, vbin8(b'1'), uint(0)),
              payload=described(VALUE, described(DECLARE, list8(NULL)))))
    # deep nesting of lists (past the 500 dissection depth limit)
    case(perf(TRANSFER, list8(UINT0, UINT0, vbin8(b'1')),
              payload=described(SEQUENCE, b'\xc0\xff\x01' * 600 + b'\x40')))
    # garbage after the protocol header, no header at all
    case(b'\x00\x00\x00\x08\x02\x00\x00\x00' + b'\x00\x00\x00\x09\x02\x00\x00\x00\x00', header=None)
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main().write(os.path.join(out, 'amqp10-coverage.pcap'))
    build_malformed().write(os.path.join(out, 'amqp10-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
