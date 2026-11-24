#!/usr/bin/env python3
# Generates test/captures/dbus_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the D-Bus dissector
(packet-dbus.c).

D-Bus messages are carried three ways: as link-layer type 231
(WTAP_ENCAP_DBUS, one message per frame), as Exported PDU with the
dissector name "dbus", and over TCP ("dbus.tcp", Decode As only; the
captures use port 55556). Every message is marshalled from scratch with
struct; no captured traffic is used.

Usage: mkdbus.py <output directory>

Writes:
  dbus-coverage.pcapng            calls, replies, errors and signals in
                                  both byte orders, every header field,
                                  every basic and container type, the
                                  name and call/reply tracking, TCP with
                                  several messages per segment and one
                                  message over several segments
  dbus-coverage-malformed.pcapng  the empty variant reproducer
                                  (dbus_empty_variant.py),
                                  and every error path: bad header values,
                                  invalid names, signatures, strings,
                                  booleans, padding, arrays, nesting
"""

import os
import struct
import sys

# ---------------------------------------------------------------------------
# D-Bus marshalling

BASIC = {
    'y': ('B', 1), 'b': ('I', 4), 'n': ('h', 2), 'q': ('H', 2), 'i': ('i', 4),
    'u': ('I', 4), 'x': ('q', 8), 't': ('Q', 8), 'd': ('d', 8), 'h': ('I', 4),
}
ALIGN = {'y': 1, 'g': 1, 'v': 1, 'n': 2, 'q': 2, 'i': 4, 'u': 4, 'b': 4, 'o': 4,
         'a': 4, 's': 4, 'h': 4, 'x': 8, 't': 8, 'd': 8, '(': 8, '{': 8}


def split_complete(sig):
    """Return (first complete type, rest)."""
    c = sig[0]
    if c == 'a':
        t, rest = split_complete(sig[1:])
        return 'a' + t, rest
    if c in '({':
        close = ')' if c == '(' else '}'
        depth = 0
        for i, ch in enumerate(sig):
            if ch == c:
                depth += 1
            elif ch == close:
                depth -= 1
                if depth == 0:
                    return sig[:i + 1], sig[i + 1:]
        raise ValueError(sig)
    return c, sig[1:]


def split_all(sig):
    out = []
    while sig:
        t, sig = split_complete(sig)
        out.append(t)
    return out


class Writer:
    def __init__(self, e, start=0):
        self.e = e          # '<' or '>'
        self.buf = bytearray()
        self.start = start  # offset of buf[0] in the message (for alignment)

    def pad(self, a):
        while (self.start + len(self.buf)) % a:
            self.buf.append(0)

    def raw(self, b):
        self.buf += b

    def put(self, t, v):
        c = t[0]
        self.pad(ALIGN[c])
        if c in BASIC:
            self.buf += struct.pack(self.e + BASIC[c][0], v)
        elif c in 'so':
            b = v.encode() if isinstance(v, str) else v
            self.buf += struct.pack(self.e + 'I', len(b)) + b + b'\0'
        elif c == 'g':
            b = v.encode() if isinstance(v, str) else v
            self.buf += bytes([len(b)]) + b + b'\0'
        elif c == 'v':
            vsig, vval = v
            self.put('g', vsig)
            self.put(vsig, vval)
        elif c == '(':
            for st, sv in zip(split_all(t[1:-1]), v):
                self.put(st, sv)
        elif c == '{':
            kt, vt = split_all(t[1:-1])
            self.put(kt, v[0])
            self.put(vt, v[1])
        elif c == 'a':
            et = t[1:]
            lenpos = len(self.buf)
            self.buf += b'\0\0\0\0'
            self.pad(ALIGN[et[0]])
            begin = len(self.buf)
            for item in v:
                self.put(et, item)
            n = len(self.buf) - begin
            self.buf[lenpos:lenpos + 4] = struct.pack(self.e + 'I', n)
        else:
            raise ValueError(t)


PATH, INTERFACE, MEMBER, ERROR_NAME, REPLY_SERIAL, DESTINATION, SENDER, \
    SIGNATURE, UNIX_FDS = range(1, 10)
FSIG = {PATH: 'o', INTERFACE: 's', MEMBER: 's', ERROR_NAME: 's', REPLY_SERIAL: 'u',
        DESTINATION: 's', SENDER: 's', SIGNATURE: 'g', UNIX_FDS: 'u'}

CALL, RETURN, ERROR, SIGNAL = 1, 2, 3, 4


def message(mtype, serial, fields, sig='', body=(), e='<', flags=0, raw_body=None,
            raw_fields=None, version=1, endian=None):
    """fields: list of (code, value) or (code, sig, value); body values
    follow the signature sig."""
    fl = []
    for f in fields:
        if len(f) == 2:
            fl.append((f[0], (FSIG[f[0]], f[1])))
        else:
            fl.append((f[0], (f[1], f[2])))
    if sig and not any(f[0] == SIGNATURE for f in fl):
        fl.append((SIGNATURE, ('g', sig)))
    if raw_fields is not None:
        hf = raw_fields
    else:
        w = Writer(e, 12)
        w.put('a{yv}', fl)
        hf = bytes(w.buf)
    hdr = bytearray(hf)
    while (12 + len(hdr)) % 8:
        hdr.append(0)
    if raw_body is not None:
        b = raw_body
    else:
        w = Writer(e, 0)
        for t, v in zip(split_all(sig), body):
            w.put(t, v)
        b = bytes(w.buf)
    fixed = (endian or (b'l' if e == '<' else b'B')) + bytes([mtype, flags, version]) + \
        struct.pack(e + 'II', len(b), serial)
    return fixed + bytes(hdr) + b


# ---------------------------------------------------------------------------
# Capture file writing

def pcapng_block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)


IF_DBUS, IF_EXP, IF_ETH = 0, 1, 2


def write_pcapng(path, frames):
    """frames: (interface, data); 0 D-Bus (231), 1 Exported PDU, 2 Ethernet."""
    with open(path, 'wb') as f:
        f.write(pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        for lt in (231, 252, 1):
            f.write(pcapng_block(1, struct.pack('<HHI', lt, 0, 262144)))
        for i, (ifc, p) in enumerate(frames):
            ts = (1700000000 + i) * 1000000 + 1000 * (i % 7)
            f.write(pcapng_block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                                len(p), len(p)) + p))


def exported_pdu(payload, name=b'dbus'):
    padded = name + b'\0' * (4 - len(name) % 4)
    return struct.pack('>HH', 12, len(padded)) + padded + struct.pack('>HH', 0, 0) + payload


MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 1])
IP_S = bytes([198, 51, 100, 2])
PORT = 55556


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def tcp_frame(sport, dport, payload, seq, ack, src, dst, flags=0x18, ident=1):
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), ident, 0,
                     64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + tcp + payload


class Conn:
    """A TCP connection from a client port to PORT with handshake."""

    def __init__(self, frames, cport):
        self.f = frames
        self.cport = cport
        self.cseq = 1000
        self.sseq = 5000
        self.add(True, b'', 0x02)
        self.add(False, b'', 0x12)
        self.add(True, b'', 0x10)

    def add(self, from_client, data, flags=0x18):
        ident = len(self.f) + 1
        if from_client:
            fr = tcp_frame(self.cport, PORT, data, self.cseq, self.sseq if flags != 0x02 else 0,
                           IP_C, IP_S, flags, ident)
            self.cseq += len(data) + (1 if flags & 0x03 else 0)
        else:
            fr = tcp_frame(PORT, self.cport, data, self.sseq, self.cseq, IP_S, IP_C, flags, ident)
            self.sseq += len(data) + (1 if flags & 0x03 else 0)
        self.f.append((IF_ETH, fr))

    def close(self):
        self.add(True, b'', 0x11)
        self.add(False, b'', 0x11)
        self.add(True, b'', 0x10)


# ---------------------------------------------------------------------------
# Main capture

BUS = 'org.freedesktop.DBus'
ME = ':1.42'
PLAYER = 'com.example.MusicPlayer1'
PLAYER_U = ':1.7'


def main_frames():
    F = []
    D = lambda m: F.append((IF_DBUS, m))
    X = lambda m: F.append((IF_EXP, exported_pdu(m)))

    # 1: Hello call to the bus (path, interface, member, destination; no body)
    D(message(CALL, 1, [(PATH, '/org/freedesktop/DBus'), (INTERFACE, BUS), (MEMBER, 'Hello'),
                        (DESTINATION, BUS)]))
    # 2: its reply from the bus with a string body (unique name)
    D(message(RETURN, 1, [(REPLY_SERIAL, 1), (DESTINATION, ME), (SENDER, BUS)], 's', [ME]))
    # 3: RequestName signal NameAcquired (signal with sender and destination)
    D(message(SIGNAL, 2, [(PATH, '/org/freedesktop/DBus'), (INTERFACE, BUS),
                          (MEMBER, 'NameAcquired'), (DESTINATION, ME), (SENDER, BUS)],
              's', [ME]))
    # 4: call to a well-known name, every basic type in the body
    basic_sig = 'ybnqiuxtdsogh'
    D(message(CALL, 2, [(PATH, '/com/example/MusicPlayer1'),
                        (INTERFACE, 'com.example.MusicPlayer1.Player'), (MEMBER, 'SetAll'),
                        (DESTINATION, PLAYER), (SENDER, ME), (UNIX_FDS, 1)],
              basic_sig, [0xA5, 1, -2, 65534, -100000, 4000000000, -(1 << 40), (1 << 63) + 5,
                          0.5, 'héllo', '/com/example/Track_1', 'a{sv}(ii)', 0],
              flags=0x04))
    # 5: the reply comes from the unique name of the player: the request is
    # matched by sender + serial, the unique name is mapped to the
    # well-known name; boolean false and an empty string
    D(message(RETURN, 77, [(REPLY_SERIAL, 2), (DESTINATION, ME), (SENDER, PLAYER_U)],
              'bs', [0, '']))
    # 6: a call from the player (now resolved to its well-known name) with
    # an a{sv} dictionary holding basic and container variants
    D(message(CALL, 78, [(PATH, '/'), (INTERFACE, 'org.freedesktop.DBus.Properties'),
                         (MEMBER, 'Set'), (DESTINATION, ME), (SENDER, PLAYER_U)],
              'sa{sv}', ['com.example.MusicPlayer1.Player', [
                  ('Volume', ('d', 0.75)),
                  ('Shuffle', ('b', 1)),
                  ('Title', ('s', 'Song')),
                  ('Track', ('o', '/com/example/Track_2')),
                  ('Ids', ('ai', [1, 2, 3])),
                  ('Pos', ('(xs)', (12345, 'ms'))),
                  ('Meta', ('a{ss}', [('artist', 'A'), ('album', 'B')])),
                  ('Nested', ('v', ('u', 9))),
                  ('Empty', ('as', [])),
              ]]))
    # 7: error reply to frame 6 (from the destination of the request: the
    # member comes from the tracked request)
    D(message(ERROR, 3, [(ERROR_NAME, 'org.freedesktop.DBus.Error.InvalidArgs'),
                         (REPLY_SERIAL, 78), (DESTINATION, PLAYER_U), (SENDER, ME)],
              's', ['No such property']))
    # 8: call with "no reply expected" and "no auto start" (not tracked)
    D(message(CALL, 4, [(PATH, '/com/example/MusicPlayer1'),
                        (INTERFACE, 'com.example.MusicPlayer1.Player'), (MEMBER, 'Stop'),
                        (DESTINATION, PLAYER), (SENDER, ME)], flags=0x03))
    # 9: call to the player, answered by the bus with an error (the error
    # comes from a sender other than the request destination)
    D(message(CALL, 5, [(PATH, '/com/example/MusicPlayer1'),
                        (INTERFACE, 'com.example.MusicPlayer1.Player'), (MEMBER, 'Eject'),
                        (DESTINATION, 'com.example.Absent'), (SENDER, ME)]))
    # 10: AccessDenied error from the bus
    D(message(ERROR, 9, [(ERROR_NAME, 'org.freedesktop.DBus.Error.ServiceUnknown'),
                         (REPLY_SERIAL, 5), (DESTINATION, ME), (SENDER, BUS)],
              's', ['The name com.example.Absent was not provided']))
    # 11: big-endian call with nested containers: aav, a(i(ss)), aa{ss},
    # an array of structs with variants, and an empty dict
    D(message(CALL, 6, [(PATH, '/a/b_2/C3'), (INTERFACE, 'a.b'), (MEMBER, 'Nested_1'),
                        (DESTINATION, ':1.7'), (SENDER, ME)],
              'aava(i(ss))aa{ss}a{ib}a(yv)',
              [[[('y', 1), ('s', 'x')], [], [('ay', [1, 2, 3])]],
               [(1, ('a', 'b')), (2, ('c', 'd'))],
               [[('k', 'v')], []],
               [],
               [(7, ('t', 1)), (8, ('a{sv}', [('k', ('i', 1))]))]], e='>'))
    # 12: big-endian reply with every basic type, matched to frame 11; the
    # reply has no body signature -> "OK"
    D(message(RETURN, 10, [(REPLY_SERIAL, 6), (DESTINATION, ME), (SENDER, ':1.7')], e='>'))
    # 13: big-endian reply to frame 4's serial again is not tracked: reply
    # without a matching request (reply serial 999) and with a signature
    D(message(RETURN, 11, [(REPLY_SERIAL, 999), (DESTINATION, ME), (SENDER, BUS)],
              'ybnqiuxtdsogh', [0, 0, 32767, 0, 2147483647, 0, (1 << 63) - 1, 0, -1.25,
                                'z', '/', '', 3], e='>'))
    # 14: peer-to-peer call (no sender/destination: not tracked)
    D(message(CALL, 1, [(PATH, '/'), (MEMBER, 'Ping')]))
    # 15: peer-to-peer reply with a body (no member known -> "-> 'sig'")
    D(message(RETURN, 2, [(REPLY_SERIAL, 1)], 'as', [['a', 'b']]))
    # 16: peer-to-peer error without a member
    D(message(ERROR, 3, [(ERROR_NAME, 'com.example.Error.Failed'), (REPLY_SERIAL, 1)]))
    # 17: peer-to-peer signal with an unknown header field (code 42, a
    # container variant that is skipped) and a dict entry with a struct
    # value
    D(message(SIGNAL, 4, [(PATH, '/com/example'), (INTERFACE, 'com.example.Signals'),
                          (MEMBER, 'Changed'),
                          (42, 'a{s(iv)}', [('k', (1, ('s', 'v')))]),
                          (43, 'u', 5)],
              'a{s(iv)}', [[('key', (5, ('ay', [9])))]]))
    # 18: names with hyphens, underscores, and an interface with three
    # elements; a well-known destination with digits after the first char
    D(message(CALL, 7, [(PATH, '/org/example_1'), (INTERFACE, 'org._a1.B_2'),
                        (MEMBER, '_m2'), (DESTINATION, 'org.ex-ample.Svc2'),
                        (SENDER, ':1.42')], 'y', [0]))
    # 19: Exported PDU: a method call whose reply follows in 20
    X(message(CALL, 8, [(PATH, '/exp'), (INTERFACE, 'com.example.Exp'), (MEMBER, 'Get'),
                        (DESTINATION, 'com.example.Exp'), (SENDER, ':1.99')], 'u', [7]))
    # 20: Exported PDU: the reply from the same name with a struct body
    X(message(RETURN, 12, [(REPLY_SERIAL, 8), (DESTINATION, ':1.99'),
                           (SENDER, 'com.example.Exp')], '(sv)', [('x', ('ay', []))]))
    # 21: Exported PDU: a signal with a basic dict
    X(message(SIGNAL, 13, [(PATH, '/exp'), (INTERFACE, 'com.example.Exp'),
                           (MEMBER, 'Changed')], 'a{yy}', [[(1, 2), (3, 4)]]))
    # 22: the reproducer's shape, valid: an "av" body whose variants have a
    # one-type signature (the reproducer's empty signature is in the
    # malformed capture)
    D(message(CALL, 2, [(PATH, '/'), (MEMBER, 'M')], 'av', [[('y', 0), ('ai', [])]]))
    # 23-24: a call to a unique name answered by a well-known name: the
    # unique name of the request is mapped to the well-known name (shown
    # in frame 23 only in the second pass)
    D(message(CALL, 20, [(PATH, '/svc3'), (MEMBER, 'Q'), (DESTINATION, ':1.30'),
                         (SENDER, ME)]))
    D(message(RETURN, 21, [(REPLY_SERIAL, 20), (DESTINATION, ME),
                           (SENDER, 'com.example.Svc3')], 'u', [1]))
    # 25-26: a call to a unique name answered by another unique name (not
    # mapped)
    D(message(CALL, 21, [(PATH, '/svc4'), (MEMBER, 'R'), (DESTINATION, ':1.31'),
                         (SENDER, ME)]))
    D(message(RETURN, 22, [(REPLY_SERIAL, 21), (DESTINATION, ME), (SENDER, ':1.32')]))
    # 27: peer-to-peer signal whose variant signature and dict entry value
    # hold nested structs (the closing brackets are matched over nesting)
    D(message(SIGNAL, 23, [(PATH, '/n'), (INTERFACE, 'com.example.N'), (MEMBER, 'Deep')],
              'va{s(i(y))}', [('((iy)u)', ((-1, 2), 3)), [('k', (4, (5,)))]]))

    # TCP connection (Decode As tcp.port == 55556 -> dbus.tcp)
    c = Conn(F, 40001)
    hello = message(CALL, 1, [(PATH, '/org/freedesktop/DBus'), (INTERFACE, BUS),
                              (MEMBER, 'Hello'), (DESTINATION, BUS)])
    # one message per segment
    c.add(True, hello)
    reply = message(RETURN, 1, [(REPLY_SERIAL, 1), (DESTINATION, ':1.5'), (SENDER, BUS)],
                    's', [':1.5'])
    c.add(False, reply)
    # two messages in one segment (the second big-endian)
    m1 = message(CALL, 2, [(PATH, '/t'), (INTERFACE, 'com.example.T'), (MEMBER, 'A'),
                           (DESTINATION, 'com.example.T'), (SENDER, ':1.5')], 'i', [1])
    m2 = message(CALL, 3, [(PATH, '/t'), (INTERFACE, 'com.example.T'), (MEMBER, 'B'),
                           (DESTINATION, 'com.example.T'), (SENDER, ':1.5')], 'i', [2], e='>')
    c.add(True, m1 + m2)
    # a large message over three segments, the first cut inside the fixed
    # header, the last also holds the start of the next message
    big = message(CALL, 4, [(PATH, '/t'), (INTERFACE, 'com.example.T'), (MEMBER, 'Put'),
                            (DESTINATION, 'com.example.T'), (SENDER, ':1.5')], 'ay',
                  [[i & 0xff for i in range(2500)]])
    nxt = message(CALL, 5, [(PATH, '/t'), (INTERFACE, 'com.example.T'), (MEMBER, 'C'),
                            (DESTINATION, 'com.example.T'), (SENDER, ':1.5')], 's', ['end'])
    c.add(True, big[:10])
    c.add(True, big[10:1400])
    c.add(True, big[1400:] + nxt[:20])
    c.add(True, nxt[20:])
    # replies from the unique name of the destination
    c.add(False, message(RETURN, 2, [(REPLY_SERIAL, 2), (DESTINATION, ':1.5'),
                                     (SENDER, ':1.6')], 'i', [10]) +
          message(RETURN, 3, [(REPLY_SERIAL, 3), (DESTINATION, ':1.5'),
                              (SENDER, ':1.6')], 'i', [20], e='>'))
    c.close()
    return F


# ---------------------------------------------------------------------------
# Malformed capture

def malformed_frames():
    F = []
    D = lambda m: F.append((IF_DBUS, m))
    X = lambda m: F.append((IF_EXP, exported_pdu(m)))
    C = [(PATH, '/'), (MEMBER, 'M')]

    def body(sig, raw, **kw):
        return message(CALL, 1, C + [(SIGNATURE, sig)], raw_body=raw, **kw)

    def le(fmt, *a):
        return struct.pack('<' + fmt, *a)

    # 1: the reproducer dbus_empty_variant.py: an "av" whose
    # variant has an empty signature (asserted before the fix)
    with_body = bytes.fromhex('6c01000106000000010000002800000001016f00010000002f00000000000000'
                              '03017300010000004d000000000000000801670002617600020000000000')
    D(with_body)
    # 2: the same via Exported PDU
    X(with_body)
    # 3: a variant signature with two complete types ("ii")
    D(body('v', b'\x02ii\0' + le('ii', 1, 2)))
    # 4: an invalid variant signature
    D(body('v', b'\x01z\0'))
    # 5: a variant signature that is not NUL terminated
    D(body('v', b'\x01iX' + le('i', 1)))
    # 6: invalid endianness
    D(b'x' + message(CALL, 1, C)[1:])
    # 7: message type 0 (invalid) and 8: unknown type 9
    D(message(0, 1, C))
    D(message(9, 1, C))
    # 9: version 2
    D(message(CALL, 1, C, version=2))
    # 10: serial 0
    D(message(CALL, 0, C))
    # 11: field code 0
    D(message(CALL, 1, C + [(0, 'u', 1)]))
    # 12: wrong header field signature (path as a string)
    D(message(CALL, 1, [(PATH, 's', '/'), (MEMBER, 'M')]))
    # 13-14: invalid interface names (one element; digit start); 15: an
    # interface name longer than 255
    D(message(CALL, 1, C + [(INTERFACE, 'single')]))
    D(message(CALL, 1, C + [(INTERFACE, 'a.1b')]))
    D(message(CALL, 1, C + [(INTERFACE, 'a.' + 'b' * 300)]))
    D(message(CALL, 1, C + [(INTERFACE, 'a.b-c')]))
    # 16-18: invalid member names (digit start, a period, too long)
    D(message(CALL, 1, [(PATH, '/'), (MEMBER, '1m')]))
    D(message(CALL, 1, [(PATH, '/'), (MEMBER, 'a.b')]))
    D(message(CALL, 1, [(PATH, '/'), (MEMBER, 'm' * 300)]))
    # 19: invalid error name
    D(message(ERROR, 1, [(ERROR_NAME, 'Bad'), (REPLY_SERIAL, 1)]))
    # 20-23: invalid bus names (destination one element, sender bad char,
    # well-known with digit start, too long)
    D(message(CALL, 1, C + [(DESTINATION, 'single')]))
    D(message(CALL, 1, C + [(SENDER, ':1.$')]))
    D(message(CALL, 1, C + [(DESTINATION, 'a.1b')]))
    D(message(CALL, 1, C + [(SENDER, 'a.' + 'b' * 300)]))
    D(message(CALL, 1, C + [(DESTINATION, 'a.b$c')]))
    # 24: reply serial 0
    D(message(RETURN, 1, [(REPLY_SERIAL, 0)]))
    # 25-28: required fields missing (call, reply, error, signal)
    D(message(CALL, 1, [(PATH, '/')]))
    D(message(RETURN, 1, []))
    D(message(ERROR, 1, [(REPLY_SERIAL, 1)]))
    D(message(SIGNAL, 1, [(PATH, '/'), (MEMBER, 'M')]))
    # 29: nonzero padding in the body (before an int32)
    D(body('yi', b'\x01\x01\0\0' + le('i', 1)))
    # 30: nonzero header padding at the end of the header fields
    m = bytearray(message(CALL, 1, [(PATH, '/'), (MEMBER, 'Mx')]))
    m[-1] = 1
    D(bytes(m))
    # 31: boolean 2
    D(body('b', le('I', 2)))
    # 32-34: invalid strings (invalid UTF-8, embedded NUL, no NUL)
    D(body('s', le('I', 2) + b'\xff\xfe\0'))
    D(body('s', le('I', 3) + b'a\0b\0'))
    D(body('s', le('I', 1) + b'aX'))
    # 35-38: invalid object paths ("", "a", "//", "/a/")
    D(body('o', le('I', 0) + b'\0'))
    D(body('o', le('I', 1) + b'a\0'))
    D(body('o', le('I', 2) + b'//\0'))
    D(body('o', le('I', 3) + b'/a/\0'))
    D(body('o', le('I', 3) + b'/a-\0'))
    # 40-: invalid signatures in a "g" value
    for s in [b'a', b'a)', b'a}', b'()', b'(i}', b')', b'{ss}', b'a{vs}', b'a{sss}',
              b'a{s}', b'(i', b'z', b'i' * 255, b'a{s(i}']:
        D(body('g', bytes([len(s)]) + s + b'\0'))
    # an invalid header signature (the body signature field)
    D(message(CALL, 1, C + [(SIGNATURE, 'a{')]))
    # array too long (64 MiB + 1)
    D(body('ay', le('I', 64 * 1024 * 1024 + 1)))
    # array content out of bounds (an int32 array with 6 octets)
    D(body('ai', le('I', 6) + le('ii', 1, 2)))
    # nested too deeply: 33 arrays, 33 structs, 33 dict entries, variants
    D(body('a' * 33 + 'y', le('I', 4) * 33 + b'\0'))
    D(body('(' * 33 + 'y' + ')' * 33, b'\0' * 8 * 33))
    v = b''
    for _ in range(70):
        v += b'\x01v\0'
    D(body('v', v + b'\x01y\0\0'))
    dict_sig = 'a{y' * 33 + 'y' + '}' * 33
    val = 0
    for _ in range(33):
        val = [(1, val)]
    D(message(CALL, 1, C, dict_sig, [val]))
    # truncated messages: body cut short, header field cut short
    m = message(CALL, 1, C, 's', ['hello world'])
    D(m[:-6])
    D(message(CALL, 1, C)[:20])
    # body length larger than the frame via Exported PDU
    X(message(CALL, 1, C, 'u', [1])[:-2])

    # TCP: a message with an invalid endianness octet (get_dbus_message_len
    # falls back to big-endian) and a message whose header length wraps
    def tcp(port, data, seq=1000):
        F.append((IF_ETH, tcp_frame(port, PORT, data, seq, 1, IP_C, IP_S, ident=len(F) + 1)))
    tcp(41001, b'Q' + message(CALL, 1, C)[1:])
    tcp(41002, b'B\x01\x00\x01' + struct.pack('>III', 0, 1, 0xfffffff0) + b'\0' * 16)
    # a TCP segment with only 10 octets (shorter than the fixed header)
    tcp(41003, message(CALL, 1, C)[:10])
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'dbus-coverage.pcapng'), main_frames())
    write_pcapng(os.path.join(out, 'dbus-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
