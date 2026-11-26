#!/usr/bin/env python3
# AllJoyn coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AllJoyn (packet-alljoyn.c): a client (192.0.2.1) and a router
(192.0.2.2) talk the AllJoyn message protocol on TCP and UDP port 9955
(with and without the ARDP transport) and the name service protocol on port
9956.

Usage: mkalljoyn.py [<output directory>]

Writes:
  alljoyn-coverage.pcap            connect byte and SASL commands, every
                                   message type, flag, header field and
                                   argument type, both byte orders, TCP
                                   reassembly, ARDP connections and
                                   fragments, name service version 0 and 1
                                   queries and advertisements, and the
                                   reproducers of the decoding fixes
  alljoyn-coverage-malformed.pcap  paths that end in an exception or a
                                   BAD DATA message

Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import (TCP_ACK, TCP_SYN, TcpFlow, eth, ipv4, tcp,  # noqa: E402
                    udp, write_pcap)

CLIENT = '192.0.2.1'
ROUTER = '192.0.2.2'
MSG_PORT = 9955
NS_PORT = 9956

CALL, REPLY, ERROR, SIGNAL = 1, 2, 3, 4
NO_REPLY, NO_AUTOSTART, ALLOW_REMOTE, SESSIONLESS, GLOBAL, COMPRESSED, ENCRYPTED = \
    0x01, 0x02, 0x04, 0x10, 0x20, 0x40, 0x80

# header field codes
OBJ_PATH, INTERFACE, MEMBER, ERROR_NAME, REPLY_SERIAL, DESTINATION, SENDER, SIGNATURE, \
    HANDLES, TIMESTAMP, TTL, COMPRESSION, SESSION = 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x11, 0x12, 0x13

SYN_OPTIONS = bytes.fromhex('020405b404020101')


# ---------------------------------------------------------------- encoding

def split_types(sig):
    """Split a signature into its complete types."""
    out, i = [], 0
    while i < len(sig):
        j = i
        while sig[j] == 'a':
            j += 1
        if sig[j] in '({':
            close = ')' if sig[j] == '(' else '}'
            depth = 0
            while True:
                if sig[j] in '({':
                    depth += 1
                elif sig[j] in ')}':
                    depth -= 1
                j += 1
                if depth == 0:
                    break
        else:
            j += 1
        out.append(sig[i:j])
        i = j
    return out


ALIGN = {'b': 4, 'n': 2, 'q': 2, 'i': 4, 'u': 4, 'h': 4, 'x': 8, 't': 8, 'd': 8, 's': 4,
         'a': 4, '(': 8, '{': 8}
# the dissector pads the first element of an array only for these
ELEM_PAD = {'b': 4, 'n': 2, 'q': 2, 'i': 4, 'u': 4, 'x': 8, 't': 8, 'd': 8, '(': 8, '{': 8}


def encode(buf, e, typ, value):
    """Append one value of the complete type typ to buf (alignment relative
    to the start of buf). e is '<' or '>'."""
    t = typ[0]
    if t in ALIGN:
        buf += b'\0' * (-len(buf) % ALIGN[t])
    if t == 'y':
        buf += struct.pack('B', value)
    elif t == 'b':
        buf += struct.pack(e + 'I', value)
    elif t in 'nqiuhxtd':
        buf += struct.pack(e + {'n': 'h', 'q': 'H', 'i': 'i', 'u': 'I', 'h': 'I', 'x': 'q',
                                't': 'Q', 'd': 'd'}[t], value)
    elif t == 's':
        d = value.encode()
        buf += struct.pack(e + 'I', len(d)) + d + b'\0'
    elif t == 'o':
        d = value.encode()
        buf += struct.pack(e + 'I', len(d)) + d + b'\0'
    elif t == 'g':
        d = value.encode()
        buf += struct.pack('B', len(d)) + d + b'\0'
    elif t == 'v':
        vsig, vval = value
        d = vsig.encode()
        buf += struct.pack('B', len(d)) + d + b'\0'
        for ty, v in zip(split_types(vsig), vval):
            encode(buf, e, ty, v)
    elif t == 'a':
        elem = typ[1:]
        lenpos = len(buf)
        buf += b'\0\0\0\0'
        buf += b'\0' * (-len(buf) % ELEM_PAD.get(elem[0], 1))
        start = len(buf)
        for v in value:
            encode(buf, e, elem, v)
        buf[lenpos:lenpos + 4] = struct.pack(e + 'I', len(buf) - start)
    elif t in '({':
        for ty, v in zip(split_types(typ[1:-1]), value):
            encode(buf, e, ty, v)
    else:
        raise ValueError(typ)


def body_bytes(sig, values, e='<'):
    buf = bytearray()
    for ty, v in zip(split_types(sig), values):
        encode(buf, e, ty, v)
    return bytes(buf)


def field(code, typ, value, e='<'):
    """One header field: code, 0x01, type, 0x00, the value, padded to 8."""
    buf = bytearray([code, 1, ord(typ), 0])
    encode(buf, e, typ, value)
    buf += b'\0' * (-len(buf) % 8)
    return bytes(buf)


def message(mtype, fields, sig=None, values=(), flags=0, serial=1, e='<', endian=None,
            body=None, version=1, hlen=None, blen=None):
    """An AllJoyn message. fields is a list of (code, type, value)."""
    flds = b''.join(f if isinstance(f, bytes) else field(*f, e) for f in fields)
    if sig is not None:
        flds += field(SIGNATURE, 'g', sig, e)
    if body is None:
        body = body_bytes(sig, values, e) if sig else b''
    hdr = struct.pack('B', ord(endian or ('l' if e == '<' else 'B'))) + \
        struct.pack('BBB', mtype, flags, version) + \
        struct.pack(e + 'III', len(body) if blen is None else blen, serial,
                    len(flds) if hlen is None else hlen)
    return hdr + flds + body


def call(member, sig=None, values=(), serial=1, iface='org.alljoyn.Bus', path='/org/alljoyn/Bus',
         dest='org.alljoyn.Bus', flags=0, e='<', extra=()):
    f = [(OBJ_PATH, 'o', path), (INTERFACE, 's', iface), (MEMBER, 's', member),
         (DESTINATION, 's', dest)] + list(extra)
    return message(CALL, f, sig, values, flags, serial, e)


def reply(serial_to, sig=None, values=(), serial=2, e='<', flags=0, extra=()):
    f = [(REPLY_SERIAL, 'u', serial_to), (SENDER, 's', ':abc.1'),
         (DESTINATION, 's', ':def.2')] + list(extra)
    return message(REPLY, f, sig, values, flags, serial, e)


def signal(member, sig=None, values=(), serial=3, e='<', flags=0, extra=()):
    f = [(OBJ_PATH, 'o', '/org/alljoyn/Bus'), (INTERFACE, 's', 'org.alljoyn.Bus'),
         (MEMBER, 's', member)] + list(extra)
    return message(SIGNAL, f, sig, values, flags, serial, e)


def error(serial_to, name, text, serial=4, e='<'):
    return message(ERROR, [(ERROR_NAME, 's', name), (REPLY_SERIAL, 'u', serial_to)],
                   's', [text], 0, serial, e)


# ---------------------------------------------------------------- ARDP

def ardp(flags, src, dst, seq, ack, data=b'', ttl=1000, lcs=0, nsa=0, fss=None, fcnt=1,
         bitmap=b'', hlen=None, dlen=None):
    """An ARDP packet. flags: SYN 1, ACK 2, EAK 4, RST 8, NUL 0x10; the
    version bits (0x40) are added."""
    fl = flags | 0x40
    if fl & 1:
        return struct.pack('>BBHHHII', fl, 14, src, dst, len(data) if dlen is None else dlen, seq, ack) + \
            struct.pack('>HHIH', 4, 1500, 100, 0) + b'\0\0' + data
    words = 17 + len(bitmap) // 2 if hlen is None else hlen
    return struct.pack('>BBHHHII', fl, words, src, dst, len(data) if dlen is None else dlen, seq, ack) + \
        struct.pack('>IIIIH', ttl, lcs, nsa, seq if fss is None else fss, fcnt) + bitmap + data


# ---------------------------------------------------------------- name service

def ns_header(version, questions, answers, timer=120, sender=1):
    return bytes([(sender << 4) | version, questions, answers, timer])


def whohas(flags, names):
    return bytes([flags, len(names)]) + b''.join(bytes([len(n)]) + n.encode() for n in names)


def isat_v0(flags, names, port=9955, ipv4_addr=None, ipv6_addr=None, guid=None):
    b = bytes([flags, len(names)]) + struct.pack('>H', port)
    if flags & 0x02:
        b += ipv6_addr
    if flags & 0x01:
        b += ipv4_addr
    if flags & 0x20:
        b += bytes([len(guid)]) + guid.encode()
    return b + b''.join(bytes([len(n)]) + n.encode() for n in names)


def isat_v1(flags, names, mask, r4=None, u4=None, r6=None, u6=None, guid=None):
    b = bytes([flags, len(names)]) + struct.pack('>H', mask)
    for flag, addr in ((0x08, r4), (0x04, u4)):
        if flags & flag:
            b += addr[0] + struct.pack('>H', addr[1])
    for flag, addr in ((0x02, r6), (0x01, u6)):
        if flags & flag:
            b += addr[0] + struct.pack('>H', addr[1])
    if flags & 0x20:
        b += bytes([len(guid)]) + guid.encode()
    return b + b''.join(bytes([len(n)]) + n.encode() for n in names)


IP6 = bytes.fromhex('20010db8000000000000000000000001')
IP6B = bytes.fromhex('20010db8000000000000000000000002')
GUID = '0123456789abcdef0123456789abcdef'


# ---------------------------------------------------------------- frames

class Cap:
    def __init__(self):
        self.frames = []
        self.ident = 1

    def add(self, frame):
        self.frames.append(frame)

    def udp(self, payload, sport, dport, src=CLIENT, dst=ROUTER):
        seg = udp(payload, sport, dport, src=src, dst=dst)
        self.ident += 1
        fa, fb = (b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02')
        smac, dmac = (fa, fb) if src == CLIENT else (fb, fa)
        self.add(eth(ipv4(seg, 17, src, dst, ident=self.ident), 0x0800, dst=dmac, src=smac))

    def handshake(self, flow):
        for d, flags in ((0, TCP_SYN), (1, TCP_SYN | TCP_ACK), (0, TCP_ACK)):
            sp, dp = (flow.sport, flow.dport) if d == 0 else (flow.dport, flow.sport)
            s, t = (flow.src, flow.dst) if d == 0 else (flow.dst, flow.src)
            sm, dm = (flow.smac, flow.dmac) if d == 0 else (flow.dmac, flow.smac)
            seg = tcp(b'', sp, dp, flow.seq[d], flow.seq[1 - d] if flags & TCP_ACK else 0, flags,
                      options=SYN_OPTIONS if flags & TCP_SYN else b'', src=s, dst=t)
            flow.seq[d] += 1 if flags & TCP_SYN else 0
            flow.ident += 1
            self.add(eth(ipv4(seg, 6, s, t, ident=flow.ident - 1), 0x0800, dst=dm, src=sm))


def flow(sport, dport=MSG_PORT, isn=1000):
    return TcpFlow(sport, dport, src=CLIENT, dst=ROUTER, isn_c=isn, isn_s=isn + 4000,
                   checksum=True, ip_ident=isn)


def build():
    ok, bad = Cap(), Cap()

    # ---- TCP: connect byte, SASL, messages
    f = flow(40010)
    ok.handshake(f)
    ok.add(f.send(b'\0AUTH EXTERNAL 31303030\r\n'))
    ok.add(f.recv(b'REJECTED EXTERNAL ANONYMOUS\r\n'))
    ok.add(f.send(b'AUTH ANONYMOUS 616c6c6a6f796e\r\n'))
    ok.add(f.recv(b'OK 0123456789abcdef0123456789abcdef\r\n'))
    ok.add(f.send(b'DATA 1234\r\n'))
    ok.add(f.recv(b'ERROR\r\n'))
    ok.add(f.send(b'CANCEL\r\n'))
    hello = call('Hello', serial=1)
    ok.add(f.send(b'BEGIN\r\n' + hello))            # SASL command and a message in one segment
    ok.add(f.recv(reply(1, 's', [':abc.1'], serial=1)))

    # every header field, flag and message type
    ok.add(f.send(call('Everything', 'u', [7], serial=2, flags=0xff, extra=[
        (HANDLES, 'u', 0), (TIMESTAMP, 'u', 123456), (TTL, 'q', 60), (COMPRESSION, 'u', 99),
        (SESSION, 'u', 4242), (SENDER, 's', ':abc.1')])))
    ok.add(f.recv(reply(2, 'u', [1], serial=3, flags=NO_REPLY | NO_AUTOSTART | ALLOW_REMOTE)))
    ok.add(f.recv(error(2, 'org.alljoyn.Bus.ErrorResponse', 'It failed', serial=4)))
    ok.add(f.send(signal('Ping', serial=5, flags=SESSIONLESS | GLOBAL)))
    ok.add(f.send(message(0, [(MEMBER, 's', 'Odd')], serial=6, flags=COMPRESSED | ENCRYPTED)))

    # arguments of every type, little and big endian
    all_sig = 'ybnqiuhxtdsog'
    all_val = [200, 1, -5, 65000, -100000, 4000000000, 3, -(2 ** 40), 2 ** 50, 3.25,
               'a string', '/obj/path', 'a{sv}']
    ok.add(f.send(call('AllTypes', all_sig, all_val, serial=7)))
    ok.add(f.send(call('AllTypesBE', all_sig, all_val, serial=8, e='>')))
    # padding between arguments
    ok.add(f.send(call('Padding', 'yyqyutyx', [1, 2, 3, 4, 5, 6, 7, 8], serial=9)))
    ok.add(f.send(signal('Arrays', 'asayaia(is)a{sv}aaiat', [
        ['one', 'two', 'three'], [1, 2, 3, 4, 5], [10, -20, 30],
        [(1, 'a'), (2, 'bb')],
        [('k1', ('s', ['v1'])), ('k2', ('u', [5])), ('k3', ('ai', [[1, 2, 3]]))],
        [[1, 2], [3]], [2 ** 33, 5]], serial=10)))
    ok.add(f.send(signal('Structs', '(ysu)(i(ii)s)', [
        (9, 'nine', 99), (1, (2, 3), 'three')], serial=11)))
    ok.add(f.send(signal('Variants', 'vvvv', [
        ('s', ['text']), ('u', [42]), ('ai', [[7, 8, 9]]), ('(is)', [(5, 'five')])], serial=12, e='>')))
    ok.add(f.send(signal('Dict', 'a{ss}a{yv}', [
        [('a', 'b'), ('c', 'd')], [(1, ('y', [2])), (3, ('s', ['x']))]], serial=13)))
    ok.add(f.send(signal('SigArg', 'ug', [5, 'a{sv}'], serial=14)))

    # reproducer J1: an empty array followed by a string; and more empty arrays
    ok.add(f.send(call('EmptyArray', 'ais', [[], 'hi'], serial=15)))
    ok.add(f.send(call('EmptyNested', 'aaiaa(is)a{sv}ayu', [[], [], [], [], 77], serial=16)))
    ok.add(f.send(call('EmptyStruct', 'a(ii)s', [[], 'after'], serial=17)))
    ok.add(f.send(call('EmptyDict', 'a{sa{su}}u', [[], 5], serial=18)))

    # arrays of every element type (an array of signatures stays empty: a
    # signature argument replaces the signature the rest of the body is read
    # with, see the README), header fields with unexpected bytes and
    # an invalid type
    ok.add(f.send(call('ArrayKinds', 'agahanavao', [[], [1, 2], [-1, -2, 3],
                                                   [('s', ['v1']), ('u', [2])], ['/a', '/b/c']],
                       serial=26)))
    ok.add(f.send(signal('ArrayKindsBE', 'agahanavao', [[], [7], [-9], [('y', [1])], ['/q']],
                         serial=27, e='>')))
    ok.add(f.send(message(SIGNAL, [bytes([MEMBER, 2, ord('s'), 1]) + struct.pack('<I', 3) + b'bad\0' + b'\0' * 4,
                                   bytes([OBJ_PATH, 1, 0, 0, 0, 0, 0, 0])], serial=28)))
    ok.add(f.send(call('EmptyUnknown', 'az', [[]], serial=29)))

    # TCP reassembly: a message in three segments, header cut short, two
    # messages in one segment
    big = call('Large', 'sas', ['x' * 200, ['y' * 100, 'z' * 100]], serial=19)
    ok.add(f.send(big[:10]))
    ok.add(f.send(big[10:100]))
    ok.add(f.send(big[100:]))
    m20 = signal('Two', 'u', [1], serial=20)
    m21 = signal('Two', 'u', [2], serial=21, e='>')
    ok.add(f.send(m20 + m21))
    ok.add(f.send(m20 + m21[:20]))
    ok.add(f.send(m21[20:]))

    # reproducer J5: absurd lengths are refused instead of waited for
    ok.add(f.send(message(CALL, [(MEMBER, 's', 'Huge')], blen=0xfffffff0, serial=22)[:40]))
    ok.add(f.send(message(CALL, [(MEMBER, 's', 'Huge')], hlen=0xfffffff0, serial=23)[:40]))
    ok.add(f.send(call('BadObj', 'o', ['/x'], serial=24)[:-7] + struct.pack('<I', 0xffffffff) +
                  b'\0\0\0\0'))
    ok.add(f.send(message(CALL, [(MEMBER, 's', 'ObjLen')], 'o', [], serial=25,
                          body=struct.pack('<I', 0xffffffff) + b'\0\0\0\0')))
    for fr in f.close():
        ok.add(fr)

    # a connection that is picked up without its handshake, the connect byte
    # alone in its segment
    g = flow(40011, isn=7000)
    ok.add(g.send(b'\0'))
    ok.add(g.send(signal('Late', 'y', [1], serial=30)))
    ok.add(g.recv(signal('Late', 'y', [2], serial=31)))

    # ---- UDP 9955: bare AllJoyn messages
    ok.udp(call('Bare', 's', ['udp'], serial=40), 40020, MSG_PORT)
    ok.udp(reply(40, 'u', [5], serial=41), 40020, MSG_PORT, src=ROUTER, dst=CLIENT)

    # ---- ARDP: connection, messages, EAK, NUL, RST, fragments
    c, r = 40021, MSG_PORT
    ok.udp(ardp(1, 1, 2, 10, 0), c, r)                                  # SYN
    ok.udp(ardp(3, 2, 1, 20, 10), r, c, src=ROUTER, dst=CLIENT)         # SYN ACK
    ok.udp(ardp(2, 1, 2, 11, 20, ttl=3000), c, r)                       # ACK
    ok.udp(ardp(2, 1, 2, 12, 20, data=call('ArdpHello', serial=50)), c, r)
    ok.udp(ardp(2, 2, 1, 21, 12, data=reply(50, 's', [':r.1'], serial=51)), r, c,
           src=ROUTER, dst=CLIENT)
    ok.udp(ardp(2, 1, 2, 13, 21, data=signal('Sig', 'ay', [[1, 2, 3]], serial=52, e='>')), c, r)
    ok.udp(ardp(2 | 4, 2, 1, 22, 13, bitmap=bytes.fromhex('a5a5a5a5a5a5')), r, c,
           src=ROUTER, dst=CLIENT)                                      # EAK (reproducer J2)
    ok.udp(ardp(2 | 4, 2, 1, 23, 13, bitmap=b'\x81\x42'), r, c, src=ROUTER, dst=CLIENT)
    ok.udp(ardp(0x10, 1, 2, 14, 23), c, r)                              # NUL
    ok.udp(ardp(2, 1, 2, 15, 23, ttl=0), c, r)
    ok.udp(ardp(2 | 4, 2, 1, 24, 15, bitmap=b'\xaa' * 244), r, c,
           src=ROUTER, dst=CLIENT)                                      # reproducer J4: 0x8f words
    ok.udp(ardp(1, 3, 4, 30, 0)[:6] + b'\0\0' + ardp(1, 3, 4, 30, 0)[8:], c, r)
    ok.udp(ardp(3, 4, 3, 31, 30), r, c, src=ROUTER, dst=CLIENT)

    # a message in three ARDP fragments: the first two bytes of the header
    # only, a part with all header fields, and the remainder
    frag = call('Fragmented', 'sas', ['q' * 300, ['w' * 100, 'e' * 100]], serial=60)
    ok.udp(ardp(2, 1, 2, 100, 31, data=frag[:20], fss=100, fcnt=3), c, r)
    ok.udp(ardp(2, 1, 2, 101, 31, data=frag[20:150], fss=100, fcnt=3), c, r)
    ok.udp(ardp(2, 1, 2, 102, 31, data=frag[150:], fss=100, fcnt=3), c, r)
    # a message cut after its header fields, in one packet
    frag2 = call('Fragmented2', 'sas', ['q' * 300], serial=61)
    hl = struct.unpack('<I', frag2[12:16])[0]
    ok.udp(ardp(2, 1, 2, 110, 31, data=frag2[:16 + hl + 8], fss=110, fcnt=2), c, r)
    ok.udp(ardp(2, 1, 2, 111, 31, data=frag2[16 + hl + 8:], fss=110, fcnt=2), c, r)
    # ARDP with a reset, and a packet with no data and a data length
    ok.udp(ardp(8, 1, 2, 120, 31), c, r)
    ok.udp(ardp(2, 1, 2, 121, 31, dlen=40), c, r)
    ok.udp(ardp(2, 1, 2, 122, 31, data=b'\x00' * 8), c, r)

    # ---- name service, UDP and TCP 9956
    ns = []
    # version 0 queries: every flag combination, several names
    ns.append(ns_header(0, 1, 0) + whohas(0x0f, ['org.example.one', 'org.example.two']))
    ns.append(ns_header(0, 2, 0) + whohas(0x01, ['a.b']) + whohas(0x0a, ['c.d', 'e.f', 'g.h']))
    ns.append(ns_header(0, 1, 0, timer=0, sender=0) + whohas(0x04, []))
    # version 0 advertisements: IPv4, IPv6, GUID, names
    ns.append(ns_header(0, 0, 1) + isat_v0(0x01 | 0x08 | 0x04 | 0x10, ['org.example.svc1'],
                                           ipv4_addr=bytes([192, 0, 2, 7])))
    ns.append(ns_header(0, 0, 2) +
              isat_v0(0x02 | 0x20 | 0x10, ['n1', 'n2'], port=9956, ipv6_addr=IP6, guid=GUID) +
              isat_v0(0x03 | 0x20, [], ipv4_addr=bytes([192, 0, 2, 8]), ipv6_addr=IP6B, guid=GUID))
    # version 1 queries and advertisements
    ns.append(ns_header(1, 1, 0) + whohas(0, ['org.example.v1']))
    ns.append(ns_header(1, 0, 1) + isat_v1(0x08 | 0x20, ['org.example.v1a'], 0x0004,
                                           r4=(bytes([192, 0, 2, 9]), 9955), guid=GUID))
    ns.append(ns_header(1, 1, 3, sender=2) + whohas(0, ['x.y']) +
              isat_v1(0x04 | 0x10, ['u4.name'], 0x0010 | 0x0080, u4=(bytes([192, 0, 2, 10]), 9956)) +
              isat_v1(0x02 | 0x01 | 0x20, ['r6.name', 'u6.name'], 0x0001 | 0x0002 | 0x0020,
                      r6=(IP6, 9955), u6=(IP6B, 9956), guid=GUID) +
              isat_v1(0x08 | 0x04 | 0x02 | 0x01 | 0x20 | 0x10, ['all.name'], 0x00ff | 0x0008,
                      r4=(bytes([192, 0, 2, 11]), 1), u4=(bytes([192, 0, 2, 12]), 2),
                      r6=(IP6, 3), u6=(IP6B, 4), guid=GUID))
    # an unsupported version
    ns.append(ns_header(2, 1, 1) + b'\0' * 12)
    for i, n in enumerate(ns):
        ok.udp(n, 40030 + i, NS_PORT, dst=ROUTER)
    g = flow(40040, NS_PORT, isn=9000)
    ok.handshake(g)
    ok.add(g.send(ns[3]))
    for fr in g.close():
        ok.add(fr)

    # a SASL command split over two segments, then a signal whose body
    # holds a signature argument followed by two int32
    h = flow(40060, isn=11000)
    ok.handshake(h)
    ok.add(h.send(b'AUTH ANONY'))
    ok.add(h.send(b'MOUS 616c\r\n'))
    ok.add(h.send(signal('SigFirst', 'gii', ['a{sv}', 1, 2], serial=60)))

    # ---- malformed capture
    b = flow(40050, isn=3000)
    bad.handshake(b)
    # a SASL command split over two segments: the first one is dissected as
    # far as it goes and the rest as an AllJoyn message (the Info column of
    # that frame differs from the one of a second pass)
    bad.add(b.send(b'AUTH ANONY'))
    bad.add(b.send(b'MOUS 616c\r\n'))
    bad.add(b.send(b'\0X' + b'\0' * 30))                        # bad endianness after the connect byte
    bad.add(b.send(signal('Short', 'u', [1])[:12]))             # shorter than a header
    bad.add(b.send(call('LongStr', 's', ['abc'], serial=70)[:-8] + struct.pack('<I', 5000) + b'abc\0'))
    bad.add(b.send(signal('SigLen', 'g', ['ab'], serial=71)[:-4] + b'\xf0abc'))
    # a signature argument replaces the signature the rest of the body is read with
    bad.add(b.send(signal('SigFirst', 'gii', ['a{sv}', 1, 2], serial=69)))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'ArrLen')], 'as', [], serial=72,
                           body=struct.pack('<I', 100000) + b'\0' * 4)))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'ArrBig')], 'ay', [], serial=73,
                           body=struct.pack('<I', 500000) + b'\0' * 4)))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'ArrNoSig')], 'a', [], serial=74,
                           body=struct.pack('<I', 0))))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'StructNoSig')], '(', [], serial=75,
                           body=struct.pack('<I', 0) * 4)))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'BadType')], 'z', [], serial=76,
                           body=struct.pack('<I', 0) * 4)))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'VarLen')], 'v', [], serial=77,
                           body=b'\xf0u\0' + b'\0' * 8)))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'Empty')], 'ii', [], serial=78, body=b'\0\0\0\0')))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'Inv')], '\0', [], serial=79, body=b'\0' * 8)))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'NestA')], 'a' * 40 + 'y', [], serial=80,
                           body=b'\0' * 64)))
    bad.add(b.send(signal('Cut', 'sas', ['x' * 50, ['y' * 40]], serial=81)[:70]))
    bad.add(b.send(call('X', serial=82)[:16] + b'\x01\x01\x00'))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'ZeroLen')], 'u', [], serial=83, body=b'')))
    # a message with a bad body length and header fields that stop short
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'HLen')], 'u', [1], serial=84, hlen=500)))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'BLen')], 'u', [1], serial=85, blen=50)))
    # a variant whose signature length byte is too small leaves no signature
    # for the element type of an array
    for t in 'a({':
        bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'VarNoSig')], 'v', [], serial=100,
                               body=b'\x01a' + t.encode() + b'\0' + struct.pack('<I', 8) +
                               b'\0' * 8)))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'ObjLen')], 'o', [], serial=101,
                           body=struct.pack('<I', 400) + b'/a\0\0')))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'ArrEnd')], 'at', [], serial=102,
                           body=struct.pack('<I', 0))))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'OpenStruct')], '(ii', [], serial=103,
                           body=struct.pack('<ii', 1, 2))))
    bad.add(b.send(message(SIGNAL, [(MEMBER, 's', 'ShortStr')], 's', [], serial=104,
                           body=struct.pack('<I', 3) + b'abc')))
    # ARDP over TCP that is too short for its header, and a connection that
    # starts with the ethertype-like bytes of an ARDP packet
    bad.add(b.send(b'\x42\x11\x00'))
    # ARDP
    c, r = 40051, MSG_PORT
    # a header whose last field lost its padding
    short = message(SIGNAL, [(MEMBER, 's', 'abc')], serial=105)
    bad.udp(ardp(2, 1, 2, 7, 1, data=short[:28]), c, r)
    # captured shorter than the packet: the ARDP header is all there is
    trunc = eth(ipv4(udp(ardp(2, 1, 2, 8, 1, data=b'l' * 40), c, r, src=CLIENT, dst=ROUTER), 17,
                     CLIENT, ROUTER, ident=900), 0x0800, dst='02:00:00:00:00:02',
                src='02:00:00:00:00:01')
    bad.add((trunc[:14 + 20 + 8 + 34], len(trunc)))
    bad.udp(ardp(2, 1, 2, 1, 1)[:5], c, r)                          # cut in the ARDP header
    bad.udp(ardp(2, 1, 2, 1, 1)[:12], c, r)
    bad.udp(ardp(2, 1, 2, 1, 1, data=b'abc', dlen=300), c, r)
    bad.udp(bytes([0x41, 20]) + b'\0' * 30, c, r)                   # SYN with a wrong header length
    bad.udp(bytes([0x42, 5]) + b'\0' * 30, c, r)                    # too short a header length
    bad.udp(b'l\x01\x00\x01' + b'\0' * 4, c, r)                     # cut message
    bad.udp(b'Z', c, r)
    bad.udp(ardp(2, 1, 2, 5, 1, data=b'X' * 16)[:36], c, r)
    bad.udp(ardp(2, 1, 2, 5, 1, data=call('C', serial=90)[:20]), c, r)
    bad.udp(ardp(2, 1, 2, 5, 1, data=message(SIGNAL, [(MEMBER, 's', 'a')], blen=0xfffffff0,
                                             serial=91)), c, r)
    # name service cut short
    bad.udp(ns_header(0, 1, 0) + b'\x0f\x03\x40abc', c, NS_PORT)
    bad.udp(ns_header(0, 0, 1) + b'\x31\x02\x26\xe3\xc0', c, NS_PORT)
    bad.udp(ns_header(1, 0, 1) + b'\x08\x01\x00\x04\xc0\x00', c, NS_PORT)
    bad.udp(ns_header(1, 3, 3), c, NS_PORT)
    bad.udp(b'\x00', c, NS_PORT)
    return ok.frames, bad.frames


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(outdir, exist_ok=True)
    ok, bad = build()
    ts = lambda i: (1700000000 + i // 10, (i % 10) * 100000)  # noqa: E731
    write_pcap(os.path.join(outdir, 'alljoyn-coverage.pcap'), ok, ts=ts)
    write_pcap(os.path.join(outdir, 'alljoyn-coverage-malformed.pcap'), bad, ts=ts)
    print(len(ok), len(bad))


if __name__ == '__main__':
    main()
