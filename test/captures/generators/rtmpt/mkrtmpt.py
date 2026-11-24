#!/usr/bin/env python3
# Generates test/captures/rtmpt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RTMPT coverage captures (RTMP over TCP 1935, RTMP tunnelled
in HTTP "application/x-fcs", AMF in HTTP "application/x-amf").
Usage: mkrtmpt.py <outdir> [-v]. Everything is synthetic (192.0.2.0/24,
198.51.100.0/24). No encryption: RTMPE is not generated."""
import os
import struct
import sys

# ---------------------------------------------------------------- packets
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Cap:
    def __init__(self):
        self.frames = []; self.marks = []; self.t = 1700000000.0
    def mark(self, text):
        self.marks.append((len(self.frames) + 1, text))
    def add(self, fr):
        self.frames.append((self.t, fr)); self.t += 0.001
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', int(t), int((t % 1) * 1e6), len(fr), len(fr)))
                f.write(fr)

class Conv:
    """One TCP connection. Sequence numbers are relative: the first data
    byte is 1 in each direction."""
    def __init__(self, cap, cip, sip, cport, sport, ipid=1, syn=True, isn_c=1000, isn_s=5000):
        self.cap = cap; self.cip = cip; self.sip = sip; self.cp = cport; self.sp = sport
        self.cseq = isn_c; self.sseq = isn_s; self.ipid = ipid; self.last = None
        if syn:
            self.fr(True, 0x02, b'')
            self.fr(False, 0x12, b'', syn=True)
            self.fr(True, 0x10, b'')
    def fr(self, from_client, flags, payload, syn=False, resend=None):
        if from_client:
            sip, dip, sp, dp, seq, ack = self.cip, self.sip, self.cp, self.sp, self.cseq, self.sseq
            eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
        else:
            sip, dip, sp, dp, seq, ack = self.sip, self.cip, self.sp, self.cp, self.sseq, self.cseq
            eth = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + b'\x08\x00'
        if flags == 0x02 and from_client: ack = 0
        if resend is not None: seq = resend
        seq &= 0xffffffff; ack &= 0xffffffff
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0)
        tot = 20 + len(tcp) + len(payload)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, self.ipid & 0xffff, 0, 64, 6, 0, bytes(sip), bytes(dip))
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.cap.add(eth + ip + tcp + payload)
        if payload: self.last = (from_client, seq, payload)
        if resend is not None: return
        # advance the sequence number (SYN and FIN use one)
        n = len(payload) + (1 if flags & 0x03 else 0)
        if from_client: self.cseq += n
        else: self.sseq += n
    def send(self, from_client, data, cuts=()):
        """Send data as TCP segments; cuts is a list of segment sizes, the
        rest goes into one last segment."""
        pos = 0
        for c in cuts:
            if pos >= len(data): break
            self.fr(from_client, 0x18, data[pos:pos + c]); pos += c
        if pos < len(data): self.fr(from_client, 0x18, data[pos:])
    def resend(self):
        fc, seq, payload = self.last
        self.fr(fc, 0x18, payload, resend=seq)
    def ack(self, from_client):
        self.fr(from_client, 0x10, b'')
    def close(self):
        self.fr(True, 0x11, b''); self.fr(False, 0x11, b''); self.fr(True, 0x10, b'')

def rnd(n):
    # a repeating pattern: the handshake data is opaque and this keeps the capture small
    return bytes((i * 37 + 11) & 0xff for i in range(n))

def handshake(c):
    c.send(True, b'\x03' + struct.pack('!II', 0, 0) + rnd(1528))                  # C0+C1
    c.send(False, b'\x03' + struct.pack('!II', 0, 0) + rnd(1528) + rnd(1536))     # S0+S1+S2
    c.send(True, rnd(1536))                                                       # C2

# ---------------------------------------------------------------- chunks
def basic(fmt, csid):
    if csid < 64: return bytes([(fmt << 6) | csid])
    if csid < 320: return bytes([fmt << 6, csid - 64])
    return bytes([(fmt << 6) | 1]) + struct.pack('<H', csid - 64)

CH = [128]
def msg(csid, mtype, body, ts=0, sid=0, fmt=0, chunk=None, ets=None):
    if chunk is None: chunk = CH[0]
    """One RTMP message cut into chunks of `chunk` octets. ts >= 0xffffff
    (fmt 0) or a delta >= 0xffffff (fmt 1, 2) is sent as an extended
    timestamp, repeated in every type 3 chunk of the message."""
    ext = ts >= 0xffffff
    t3 = struct.pack('!I', ts) if ext else b''
    f = ts if not ext else 0xffffff
    if fmt == 0:
        mh = f.to_bytes(3, 'big') + len(body).to_bytes(3, 'big') + bytes([mtype]) + struct.pack('<I', sid)
    elif fmt == 1:
        mh = f.to_bytes(3, 'big') + len(body).to_bytes(3, 'big') + bytes([mtype])
    elif fmt == 2:
        mh = f.to_bytes(3, 'big')
    else:
        mh = b''; t3 = b''; ext = False
    out = basic(fmt, csid) + mh + (t3 if ext else b'')
    out += body[:chunk]
    pos = chunk
    while pos < len(body):
        out += basic(3, csid) + t3 + body[pos:pos + chunk]
        pos += chunk
    return out

# ---------------------------------------------------------------- AMF0
def n0(x): return b'\x00' + struct.pack('!d', x)
def b0(x): return b'\x01' + bytes([1 if x else 0])
def s0(s): s = s.encode() if isinstance(s, str) else s; return b'\x02' + struct.pack('!H', len(s)) + s
def name0(s): s = s.encode(); return struct.pack('!H', len(s)) + s
END0 = b'\x00\x00\x09'
def props0(items): return b''.join(name0(k) + v for k, v in items) + END0
def o0(items): return b'\x03' + props0(items)
NULL0 = b'\x05'; UNDEF0 = b'\x06'
def ref0(n): return b'\x07' + struct.pack('!H', n)
def ecma0(items, count=None): return b'\x08' + struct.pack('!I', len(items) if count is None else count) + props0(items)
def strict0(vals): return b'\x0a' + struct.pack('!I', len(vals)) + b''.join(vals)
def date0(ms, tz=0): return b'\x0b' + struct.pack('!d', ms) + struct.pack('!H', tz)
def long0(s): s = s.encode() if isinstance(s, str) else s; return b'\x0c' + struct.pack('!I', len(s)) + s
UNSUP0 = b'\x0d'
def xml0(s): s = s.encode() if isinstance(s, str) else s; return b'\x0f' + struct.pack('!I', len(s)) + s
def typed0(cls, items): return b'\x10' + name0(cls) + props0(items)
AMF3_MARK = b'\x11'
def i64_0(x): return b'\x22' + struct.pack('!q', x)
EOO0 = b'\x09'

# ---------------------------------------------------------------- AMF3
def u29(n):
    if n < 0x80: return bytes([n])
    if n < 0x4000: return bytes([0x80 | (n >> 7), n & 0x7f])
    if n < 0x200000: return bytes([0x80 | (n >> 14), 0x80 | ((n >> 7) & 0x7f), n & 0x7f])
    return bytes([0x80 | (n >> 22), 0x80 | ((n >> 15) & 0x7f), 0x80 | ((n >> 8) & 0x7f), n & 0xff])
def utf3(s): s = s.encode() if isinstance(s, str) else s; return u29((len(s) << 1) | 1) + s
UNDEF3 = b'\x00'; NULL3 = b'\x01'; FALSE3 = b'\x02'; TRUE3 = b'\x03'
def i3(n): return b'\x04' + u29(n)
def d3(x): return b'\x05' + struct.pack('!d', x)
def s3(s): return b'\x06' + utf3(s)
def sref3(i): return b'\x06' + u29(i << 1)
def xmldoc3(s): return b'\x07' + utf3(s)
def date3(ms): return b'\x08' + u29(1) + struct.pack('!d', ms)
def dateref3(i): return b'\x08' + u29(i << 1)
def arr3(assoc, dense):
    out = b'\x09' + u29((len(dense) << 1) | 1)
    for name, val in assoc:
        out += (utf3(name) if isinstance(name, (str, bytes)) else u29(name << 1)) + val
    return out + b'\x01' + b''.join(dense)
def arrref3(i): return b'\x09' + u29(i << 1)
def obj3(cls, members, values, dynamic=None, clsref=None, memref=()):
    """traits object; members are names (or ('ref', n) for a string reference)."""
    flags = 0b0011 | (8 if dynamic is not None else 0) | (len(members) << 4)
    out = b'\x0a' + u29(flags) + (u29(clsref << 1) if clsref is not None else utf3(cls))
    for m in members:
        out += u29(m[1] << 1) if isinstance(m, tuple) else utf3(m)
    out += b''.join(values)
    if dynamic is not None:
        for name, val in dynamic:
            out += (u29(name[1] << 1) if isinstance(name, tuple) else utf3(name)) + val
        out += b'\x01'
    return out
OBJEXT3 = b'\x0a' + u29(0b0111)
def objtref3(i): return b'\x0a' + u29((i << 2) | 1)
def objref3(i): return b'\x0a' + u29(i << 1)
def xml3(s): return b'\x0b' + utf3(s)
def xmlref3(i): return b'\x0b' + u29(i << 1)
def ba3(b): return b'\x0c' + u29((len(b) << 1) | 1) + b
def baref3(i): return b'\x0c' + u29(i << 1)

# ---------------------------------------------------------------- commands
def cmd(name, txid, *args): return s0(name) + n0(txid) + b''.join(args)
def info(code, level='status', desc=''):
    return o0([('level', s0(level)), ('code', s0(code)), ('description', s0(desc))])

# ---------------------------------------------------------------- A/V
def audio_legacy(codec, rate, size, typ, data):
    return bytes([(codec << 4) | (rate << 2) | (size << 1) | typ]) + data
def audio_ex(ptype, fourcc, data, hi=0x90):
    return bytes([hi | ptype]) + fourcc + data
def audio_mt(mttype, ptype, fourcc, tracks, hi=0x90):
    """tracks: list of (id, fourcc or None, data)"""
    out = bytes([hi | 5, (ptype << 4) | mttype])
    if mttype != 2: out += fourcc
    for i, (tid, cc, data) in enumerate(tracks):
        out += bytes([tid])
        if mttype == 2: out += cc
        if mttype != 0: out += len(data).to_bytes(3, 'big')
        out += data
    return out
def video_legacy(ftype, codec, data):
    return bytes([(ftype << 4) | codec]) + data
def video_ex(ftype, ptype, fourcc, data):
    return bytes([0x80 | (ftype << 4) | ptype]) + fourcc + data
def video_mt(ftype, mttype, ptype, fourcc, tracks):
    out = bytes([0x80 | (ftype << 4) | 6, (mttype << 4) | ptype])
    if mttype != 2: out += fourcc
    for tid, cc, data in tracks:
        out += bytes([tid])
        if mttype == 2: out += cc
        if mttype != 0: out += len(data).to_bytes(3, 'big')
        out += data
    return out
def tag(ttype, data, ts=0, ets=0, sid=0, prev=None):
    return bytes([ttype]) + len(data).to_bytes(3, 'big') + ts.to_bytes(3, 'big') + bytes([ets]) + sid.to_bytes(3, 'big') + data + struct.pack('!I', 11 + len(data) if prev is None else prev)

CIP = [192, 0, 2, 10]; SIP = [198, 51, 100, 10]

# ================================================================ main
def build():
    cap = Cap(); mal = Cap()

    # ---------------------------------------------- 1. session, control, commands
    cap.mark('Session on TCP 1935: handshake C0+C1, S0+S1+S2, C2; window acknowledgement size, set peer bandwidth (hard, soft, dynamic, unknown limit type), set chunk size, user control messages (stream begin, EOF, dry, set buffer length, is recorded, ping request and response, unknown event), abort, acknowledgement')
    c = Conv(cap, CIP, SIP, 49152, 1935)
    handshake(c)
    c.send(True, msg(2, 5, struct.pack('!I', 2500000)))                                  # window ack size
    c.send(False, msg(2, 5, struct.pack('!I', 2500000)))
    for lim in (0, 1, 2, 7):
        c.send(False, msg(2, 6, struct.pack('!IB', 5000000 + lim, lim)))                 # peer bandwidth
    c.send(False, msg(2, 1, struct.pack('!I', 4096)))                                    # server chunk size
    c.send(True, msg(2, 1, struct.pack('!I', 256)))                                      # client chunk size
    CH[0] = 256
    ucm = lambda ev, *a: msg(2, 4, struct.pack('!H', ev) + b''.join(struct.pack('!I', x) for x in a))
    c.send(False, ucm(0, 1) + ucm(1, 1) + ucm(2, 1))                                     # begin, EOF, dry in one segment
    c.send(True, ucm(3, 1, 3000))                                                        # set buffer length
    c.send(False, ucm(4, 1) + ucm(6, 0x12345678))                                        # is recorded, ping request
    c.send(True, ucm(7, 0x12345678))                                                     # ping response
    c.send(False, ucm(0x1f, 7))                                                          # unknown event
    c.send(False, msg(2, 4, struct.pack('!H', 0)))                                       # stream begin without stream id
    c.send(True, msg(2, 4, struct.pack('!HI', 3, 1)))                                    # set buffer length without length
    c.send(True, msg(2, 2, struct.pack('!I', 5)))                                        # abort message
    c.send(True, msg(2, 3, struct.pack('!I', 123456)))                                   # acknowledgement
    c.send(True, msg(2, 1, struct.pack('!I', 0)))                                        # chunk size 0 is ignored
    c.send(True, msg(2, 1, struct.pack('!I', 256)))

    cap.mark('AMF0 commands: connect (long tcUrl, two chunks), _result matched by transaction ID, createStream, releaseStream, FCPublish, publish, play, play2, onStatus, onBWDone, _error, a call without a name, a command that the server answers with a matching _result')
    tcurl = 'rtmp://198.51.100.10/live' + '/x' * 90
    c.send(True, msg(3, 0x14, cmd('connect', 1, o0([('app', s0('live')), ('flashVer', s0('FMLE/3.0')), ('tcUrl', s0(tcurl)), ('type', s0('nonprivate'))])), sid=0))
    c.send(False, msg(3, 0x14, cmd('_result', 1, o0([('fmsVer', s0('FMS/3,0,1,123')), ('capabilities', n0(31))]),
                                    info('NetConnection.Connect.Success', desc='Connection succeeded.')), sid=0))
    c.send(True, msg(3, 0x14, cmd('releaseStream', 2, NULL0, s0('mystream'))))
    c.send(True, msg(3, 0x14, cmd('FCPublish', 3, NULL0, s0('mystream'))))
    c.send(True, msg(3, 0x14, cmd('createStream', 4, NULL0)))
    c.send(False, msg(3, 0x14, cmd('_result', 4, NULL0, n0(1))))
    c.send(True, msg(8, 0x14, cmd('publish', 5, NULL0, s0('mystream'), s0('live')), sid=1))
    c.send(False, msg(5, 0x14, cmd('onStatus', 0, NULL0, info('NetStream.Publish.Start', desc='mystream is now published.')), sid=1))
    c.send(True, msg(8, 0x14, cmd('play', 6, NULL0, s0('vod/file'), n0(0))))
    c.send(True, msg(8, 0x14, cmd('play2', 7, NULL0, o0([('streamName', s0('vod/file2')), ('start', n0(-2))]))))
    c.send(False, msg(5, 0x14, cmd('onStatus', 0, NULL0, info('NetStream.Play.Start', desc='Started playing.')), sid=1))
    c.send(False, msg(5, 0x14, cmd('onBWDone', 0, NULL0, n0(12345))))
    c.send(True, msg(3, 0x14, cmd('customCall', 8, NULL0, s0('arg'))))
    c.send(False, msg(3, 0x14, cmd('_error', 8, NULL0, info('NetConnection.Call.Failed', 'error', 'no such method'))))
    c.send(False, msg(3, 0x14, cmd('serverCall', 9, NULL0, s0('x'))))                    # server initiated call
    c.send(True, msg(3, 0x14, cmd('_result', 9, NULL0, n0(1))))                          # client answers (matched)
    c.send(True, msg(3, 0x14, s0('') + n0(10)))                                          # empty name
    c.send(True, msg(3, 0x14, cmd('connect', 11, NULL0)))                                # no command object: no app
    c.send(True, msg(3, 0x14, cmd('connect', 12, o0([('app', n0(1))]))))                 # app is not a string
    c.send(True, msg(3, 0x14, cmd('connect', 13, o0([('x', s0('1'))]))))                 # no app property
    c.send(True, msg(3, 0x14, cmd('connect', 14, UNDEF0)))                               # not an object
    c.send(True, msg(3, 0x14, cmd('play', 15, NULL0, n0(1))))                            # play without a string
    c.send(True, msg(3, 0x14, cmd('play2', 16, NULL0, o0([('streamName', n0(1))]))))
    c.send(True, msg(3, 0x14, cmd('play2', 17, NULL0, o0([('a', s0('b')), ('streamName', s0('s'))]))))
    c.send(True, msg(3, 0x14, cmd('onStatus', 18, NULL0, o0([('code', s0('NetStream.Test'))]))))
    c.send(False, msg(5, 0x12, s0('onStatus') + o0([('code', s0('NetStream.Data.Start'))])))   # data message variant
    c.send(False, msg(5, 0x12, s0('onPlayStatus') + o0([('code', s0('NetStream.Play.Complete')), ('duration', n0(1.5)), ('bytes', n0(1000))])))
    c.send(False, msg(5, 0x12, s0('onMetaData') + ecma0([('duration', n0(60.5)), ('width', n0(640)), ('height', n0(360)),
                                                          ('stereo', b0(True)), ('encoder', s0('Lavf'))])))
    c.send(True, msg(3, 0x14, cmd('connect', 19, o0([('a', n0(1)), ('b', b0(False)), ('c', NULL0), ('d', UNDEF0),
                                                      ('e', s0('str')), ('f', date0(1700000000000.0)), ('g', long0('long')),
                                                      ('h', i64_0(-5)), ('i', UNSUP0), ('j', o0([('k', n0(0))])),
                                                      ('l', ecma0([('m', xml0('<a/>'))])), ('app', s0('last'))]))))
    c.send(True, msg(3, 0x14, cmd('connect', 20, o0([('a', strict0([n0(1)])), ('app', s0('x'))]))))   # strict array stops the length scan
    c.send(True, msg(3, 0x14, cmd('connect', 21, o0([('a', o0([('b', UNSUP0)])), ('app', s0('y'))]))))

    cap.mark('AMF0 value types in a data message: number, boolean, string, object, null, undefined, reference, ECMA array, strict array, date, long string, unsupported, XML, typed object, int64, end of object marker, empty strings, nested objects')
    vals = [n0(3.25), b0(True), b0(False), s0('text'), s0(''), o0([('p', n0(1)), ('q', o0([('r', s0('deep'))]))]), NULL0, UNDEF0, ref0(2),
            ecma0([('a', n0(1)), ('b', s0('c'))]), ecma0([], count=7), strict0([n0(1), s0('x'), b0(True)]), strict0([]),
            date0(1700000000123.0, 60), long0('a long string'), long0(''), UNSUP0, xml0('<root><a/></root>'), xml0(''),
            typed0('com.example.Class', [('v', n0(9))]), i64_0(0x123456789abc), i64_0(-1), o0([]), EOO0 + b'\x00\x00\x00']
    c.send(True, msg(4, 0x12, s0('@setDataFrame') + b''.join(vals)))
    cap.mark('AMF0 values that stop the parse: movie clip, record set, unknown type (the dissector skips to the end of the message)')
    c.send(True, msg(4, 0x12, s0('x') + b'\x04abc'))
    c.send(True, msg(4, 0x12, s0('x') + b'\x0e' + b'abc'))
    c.send(True, msg(4, 0x12, s0('x') + b'\x30' + b'abc'))

    cap.mark('AMF3 command and data messages (marker 0 then AMF0) and a switch to AMF3 values: integers of 1-4 octets, double, strings (inline, empty, reference), date, arrays (associative with a name and a string reference, dense, reference), objects (traits with class name, members, dynamic members, traits reference, class name reference, member references, traits-ext, object reference), XML, byte array, undefined, null, booleans')
    c.send(True, msg(3, 0x11, b'\x00' + cmd('play', 30, NULL0, s0('amf3stream'))))
    c.send(True, msg(3, 0x11, b'\x00' + cmd('connect', 31, o0([('app', s0('amf3'))]))))
    c.send(False, msg(5, 0x0f, b'\x00' + s0('onStatus') + o0([('code', s0('NetStream.Amf3.Data'))])))
    c.send(False, msg(5, 0x0f, b'\x00' + s0('onPlayStatus') + o0([('code', s0('NetStream.Amf3.Complete'))])))
    c.send(True, msg(3, 0x11, b'\x00' + s0('x') + n0(0) + AMF3_MARK + i3(0) + i3(127) + i3(128) + i3(16383) + i3(16384) + i3(2097151) + i3(2097152) +
                     i3(0x1fffffff) + d3(2.5) + s3('inline') + s3('') + UNDEF3 + NULL3 + FALSE3 + TRUE3 + date3(1700000000000.0) + dateref3(1)))
    c.send(True, msg(3, 0x11, b'\x00' + s0('x') + n0(0) + AMF3_MARK +
                     arr3([('ab', i3(5)), (3, s3('refname'))], [i3(1), s3('dense')]) + arr3([], []) + arrref3(1) +
                     xml3('<x/>') + xml3('') + xmlref3(1) + ba3(b'\x01\x02\x03') + ba3(b'') + baref3(0)))
    c.send(True, msg(3, 0x11, b'\x00' + s0('x') + n0(0) + AMF3_MARK +
                     obj3('Cls', ['a', 'b'], [i3(1), s3('x')]) +
                     obj3('Dyn', [], [], dynamic=[('k', i3(2)), (('ref', 0), i3(3))]) +
                     obj3('Both', ['m'], [i3(4)], dynamic=[('z', i3(5))]) +
                     obj3(None, [('ref', 1), 'n'], [i3(6), i3(7)], clsref=2) +
                     objtref3(0) + objref3(0) + objext_pad()))
    c.send(True, msg(3, 0x11, b'\x00' + s0('x') + n0(0) + AMF3_MARK + arr3([('d', d3(1.5)), ('dt', date3(1700000000000.0)), ('dr', dateref3(1)), ('ar', arrref3(1)),
                     ('or', objref3(1)), ('xr', xmlref3(1)), ('br', baref3(1)), ('i', i3(5)), ('s', s3('v')), ('ba', ba3(b'\x01\x02'))], [])))   # values with a parent item; the inline byte array last (its data is not skipped)
    c.send(True, msg(3, 0x11, b'\x00' + s0('x') + n0(0) + AMF3_MARK + s3('tail') + sref3(0)))   # string reference last
    c.send(True, msg(3, 0x11, b'\x00' + s0('x') + n0(0) + AMF3_MARK + i3(1) + b'\x20xyz'))      # unknown AMF3 type
    c.send(True, msg(3, 0x11, b'\x00' + s0('x') + n0(0) + AMF3_MARK + i3(1) + xmldoc3('<d/>')))   # XML document (not decoded)
    c.send(True, msg(3, 0x14, s0('x') + n0(0) + AMF3_MARK + i3(9)))                                # switch inside an AMF0 command
    c.send(True, msg(3, 0x14, s0('x') + n0(0) + o0([('m', AMF3_MARK)]) + i3(4) + s3('z')))         # marker inside an object
    c.send(True, msg(3, 0x11, b'\x00' + s0('x') + n0(0) + AMF3_MARK + arr3([('only', s3('v'))], [])))
    c.send(True, msg(3, 0x11, b'\x00'))                                                           # AMF3 command with nothing after the marker byte
    c.send(True, msg(3, 0x0f, b'\x00' + s0('cmd') + n0(0)))
    # reproducer of "AMF3 offsets" (csid 70 = 2 octet basic header, associative array name, object reference, video multitrack many codecs)
    cap.mark('Reproducer of the fixed AMF3/csid bugs: AMF0 data message on csid 70 (two octet basic header, Chunk Stream ID shown as 70) with an AMF3 array whose associative element is named "ab" and an object reference; enhanced video multitrack message with many tracks and many codecs (FourCC after the track ID)')
    amf = s0('test') + AMF3_MARK + b'\x09\x01' + b'\x05' + b'ab' + b'\x04\x05' + b'\x01' + b'\x0a\x02' + b'\x04\x07'
    c.send(True, msg(70, 0x12, amf, sid=1))
    c.send(True, msg(4, 0x09, video_mt(1, 2, 0, None, [(0, b'avc1', b'\xaa\xbb'), (1, b'hvc1', b'\xcc')]), sid=1))

    CH[0] = 128
    # ---------------------------------------------- 2. audio and video
    cap.mark('Audio and video messages: every legacy audio codec/rate/size/type, sequence start and coded frames of enhanced audio, multichannel config, reserved packet type, audio multitrack (one track, many tracks, many tracks many codecs); video frame types, codecs, command frames, enhanced packet types, metadata, multitrack (one track, many tracks, many codecs), reserved values')
    a = Conv(cap, CIP, SIP, 49153, 1935, ipid=100)
    handshake(a)
    a.send(True, msg(2, 1, struct.pack('!I', 1024)))
    for codec, rate, size, typ in [(0, 0, 0, 0), (1, 1, 1, 1), (2, 2, 0, 1), (3, 3, 1, 0), (4, 0, 1, 1), (5, 1, 0, 0), (6, 2, 1, 0), (7, 3, 0, 1),
                                   (8, 0, 0, 0), (10, 2, 0, 0), (12, 3, 1, 1), (14, 0, 0, 0)]:
        a.send(True, msg(4, 8, audio_legacy(codec, rate, size, typ, b'\x01\x02\x03'), sid=1))
    for pt in (0, 1, 4, 2, 3, 15):
        a.send(True, msg(4, 8, audio_ex(pt, b'mp4a', b'\xaa\xbb\xcc'), sid=1))
    a.send(True, msg(4, 8, audio_ex(1, b'Opus', b'\x01', hi=0xf0)))
    a.send(True, msg(4, 8, audio_mt(0, 1, b'mp4a', [(0, None, b'\xaa\xbb')])))
    a.send(True, msg(4, 8, audio_mt(1, 0, b'Opus', [(0, None, b'\x01\x02'), (1, None, b'\x03'), (2, None, b'')])))
    a.send(True, msg(4, 8, audio_mt(2, 1, None, [(0, b'mp4a', b'\x01\x02'), (1, b'Opus', b'\x03')])))
    a.send(True, msg(4, 8, audio_mt(9, 0, b'mp4a', [(0, None, b'\x01')])))                       # reserved multitrack type 9
    for ft, codec in [(1, 7), (2, 2), (3, 3), (4, 4), (1, 5), (2, 6), (1, 12), (1, 1), (7, 9)]:
        a.send(True, msg(4, 9, video_legacy(ft, codec, b'\x00\x00\x00\x01\x65\x88'), sid=1))
    a.send(True, msg(4, 9, video_legacy(5, 7, b'\x00')))                                           # command frame StartSeek
    a.send(True, msg(4, 9, video_legacy(5, 7, b'\x01')))
    for ft, pt in [(1, 0), (2, 1), (1, 2), (2, 3), (1, 5), (3, 7), (1, 4), (6, 8)]:
        a.send(True, msg(4, 9, video_ex(ft, pt, b'hvc1', b'\x00\x00\x00\x01'), sid=1))
    a.send(True, msg(4, 9, video_ex(5, 0, b'', b'\x00')[:2] + b'\x01'))                           # command frame in the enhanced header (4 octet fourcc not present)
    a.send(True, msg(4, 9, video_ex(5, 4, b'av01', b'\x07\x07')))                                  # metadata packet with frame type command
    a.send(True, msg(4, 9, video_mt(1, 0, 1, b'av01', [(0, None, b'\x01\x02\x03')])))
    a.send(True, msg(4, 9, video_mt(2, 1, 3, b'vp09', [(0, None, b'\x01\x02'), (1, None, b'\x03'), (2, None, b'')])))
    a.send(True, msg(4, 9, video_mt(1, 2, 1, None, [(0, b'avc1', b'\x01'), (1, b'hvc1', b'\x02\x03')])))
    a.send(True, msg(4, 9, video_mt(5, 1, 0, b'av01', [(0, None, b'\x01')])))                     # command frame with multitrack packet type

    cap.mark('Aggregate messages: audio, video and script tags, an unknown tag type, a tag of size 0, and a script tag whose AMF string stays within its tag (several tags, as in the fixed reproducer)')
    ag = b''
    ag = tag(8, audio_legacy(10, 3, 1, 1, b'\x01\x02\x03'), ts=10, sid=1) + tag(9, video_legacy(1, 7, b'\x00\x01\x02'), ts=10, sid=1) + \
         tag(18, s0('onMetaData') + ecma0([('x', n0(1))]), ts=11) + tag(0x30, b'abcdef') + tag(0x30, b'')
    a.send(True, msg(5, 0x16, ag, sid=1))
    ag2 = b''.join(tag(18, b'\x0c' + struct.pack('!I', 4) + b'abcd', ts=i) for i in range(12))
    a.send(True, msg(5, 0x16, ag2, sid=1, chunk=1024))
    a.send(True, msg(5, 0x16, tag(8, audio_mt(1, 1, b'Opus', [(0, None, b'\x01\x02'), (1, None, b'\x03')])) +
                              tag(9, video_mt(1, 2, 1, None, [(0, b'avc1', b'\x01'), (1, b'hvc1', b'\x02')]))))

    # ---------------------------------------------- 3. headers, chunking, segmentation
    cap.mark('Header formats and chunking: type 0, 1, 2 and 3 headers, new messages with type 3 (previous length and type reused), basic headers of 1, 2 and 3 octets (Chunk Stream ID 2, 63, 64, 319, 320, 65599), extended timestamps in type 0, 1 and 2 headers and repeated in the type 3 chunks of a message, messages of length 0, a message split over many chunks of 128, 60 and 4096')
    h = Conv(cap, CIP, SIP, 49154, 1935, ipid=200)
    handshake(h)
    body = bytes(range(256)) * 2
    h.send(True, msg(4, 9, video_legacy(1, 7, body), ts=100, sid=1))                                     # type 0 over 5 chunks
    h.send(True, msg(4, 9, video_legacy(2, 7, body), ts=20, fmt=1, sid=1)[:0] + msg(4, 9, video_legacy(2, 7, body), ts=20, fmt=1))   # type 1, same length
    h.send(True, msg(4, 9, video_legacy(2, 7, body), ts=20, fmt=2))                                      # type 2
    h.send(True, msg(4, 9, video_legacy(2, 7, body), fmt=3))                                             # type 3 starts a message
    h.send(True, msg(4, 9, video_legacy(2, 7, body), fmt=3))
    for csid in (2, 63, 64, 319, 320, 65599, 1000):
        h.send(True, msg(csid, 0x14, cmd('ping', csid, NULL0)))
    h.send(True, msg(6, 8, audio_legacy(10, 3, 1, 1, b'\x01'), ts=0x01000000, sid=1))                    # ETS in type 0
    h.send(True, msg(6, 8, audio_legacy(10, 3, 1, 1, b'\x02'), ts=0x01000100, fmt=1))                    # ETS in type 1
    h.send(True, msg(6, 8, audio_legacy(10, 3, 1, 1, b'\x03'), ts=0x01000200, fmt=2))                    # ETS in type 2
    h.send(True, msg(7, 9, video_legacy(1, 7, body), ts=0x02000000, sid=1))                              # ETS repeated in type 3 chunks
    h.send(True, msg(7, 9, video_legacy(1, 7, body), ts=0x02000000, fmt=1))
    h.send(True, msg(7, 9, video_legacy(1, 7, body), ts=0x02000000, fmt=2))
    h.send(True, msg(8, 9, video_legacy(1, 7, body), ts=0xffffff, sid=1))                                # exactly 0xffffff
    h.send(True, msg(9, 0x14, b'', sid=1))                                                              # message of length 0
    h.send(True, msg(9, 0x14, cmd('after', 1, NULL0), sid=1))
    h.send(True, msg(2, 1, struct.pack('!I', 60)))
    h.send(True, msg(10, 9, video_legacy(1, 7, body), ts=1, sid=1, chunk=60))
    h.send(True, msg(2, 1, struct.pack('!I', 4096)))
    h.send(True, msg(10, 9, video_legacy(1, 7, body * 10), ts=2, sid=1, chunk=4096))
    h.send(True, msg(11, 9, video_legacy(1, 7, body * 3), ts=3, sid=1, chunk=4096))
    h.send(False, msg(2, 1, struct.pack('!I', 100)))
    h.send(False, msg(4, 9, video_legacy(1, 7, body), ts=5, sid=1, chunk=100))
    # fresh csid that starts with type 3 (no previous message: default chunk size and length)
    h.send(True, msg(40, 9, b'x' * 20, fmt=3))
    h.send(True, msg(41, 9, b'y' * 200, fmt=3)[:100] + b'')                                              # starts a message of the chunk size (4096), cut
    h.send(True, b'z' * 4000)                                                                           # ... and finishes it
    # fmt 1 and 2 on an unseen csid (no ti)
    h.send(True, msg(42, 8, audio_legacy(10, 3, 1, 1, b'\x01\x02'), ts=7, fmt=1))
    h.send(True, msg(43, 8, audio_legacy(10, 3, 1, 1, b'\x01\x02'), ts=7, fmt=2))
    # a message that is abandoned: new type 0 header on the same chunk stream
    h.send(True, msg(2, 1, struct.pack('!I', 128)))
    big = msg(12, 9, video_legacy(1, 7, body), ts=1, sid=1)
    h.send(True, big[:269])
    h.send(True, msg(12, 9, video_legacy(1, 7, b'short'), ts=2, sid=1))

    cap.mark('TCP segmentation: several messages in one segment, a message split at every position of the headers (one octet per segment), headers split before and after the extended timestamp, chunks split across segments, messages of many chunks across segments, a type 3 header with a repeated extended timestamp split after the basic header')
    s = Conv(cap, CIP, SIP, 49155, 1935, ipid=300)
    handshake(s)
    m1 = msg(4, 0x14, cmd('one', 1, NULL0, s0('a')), ts=5, sid=1) + msg(5, 0x14, cmd('two', 2, NULL0, s0('b')), ts=5, sid=1) + msg(2, 5, struct.pack('!I', 1))
    s.send(True, m1)
    s.send(True, m1, cuts=[1] * 40)                                                                      # one octet per segment
    s.send(True, msg(13, 9, video_legacy(1, 7, b'q' * 300), ts=0x03000000, sid=1), cuts=[3, 1, 1, 1, 1, 1, 1, 1, 1, 5, 130, 140, 7])
    s.send(True, msg(13, 9, video_legacy(1, 7, b'q' * 300), ts=0x03000000, fmt=1), cuts=[1, 3, 4, 2, 100, 40])
    s.send(True, msg(13, 9, video_legacy(1, 7, b'q' * 300), ts=0x03000000, fmt=2), cuts=[2, 3, 1, 2, 128, 1, 1, 3, 1, 1, 160])
    s.send(True, msg(14, 9, video_legacy(1, 7, b'w' * 600), ts=0x03000001, sid=1), cuts=[8, 120, 4, 125, 1, 4, 100, 250])   # split inside the type 3 headers
    s.send(True, msg(14, 9, video_legacy(1, 7, b'w' * 600), ts=0x03000001, fmt=1), cuts=[7, 127, 5, 100, 1])
    s.send(True, msg(15, 9, video_legacy(1, 7, b'e' * 900), ts=9, sid=1), cuts=[1, 127, 129, 5, 123, 128, 128, 128, 1])
    s.send(True, msg(16, 9, video_legacy(1, 7, b'e' * 900), ts=9, sid=1), cuts=[100] * 12)
    s.send(True, msg(65, 8, audio_legacy(10, 3, 1, 1, b'\x01' * 300), ts=9, sid=1), cuts=[1, 1, 130, 2, 1, 200])  # 2 octet basic header split
    s.send(True, msg(330, 8, audio_legacy(10, 3, 1, 1, b'\x01' * 300), ts=9, sid=1), cuts=[1, 1, 1, 3, 130, 2, 200])  # 3 octet basic header split
    s.send(True, msg(330, 8, audio_legacy(10, 3, 1, 1, b'\x01' * 300), ts=9, fmt=3), cuts=[1, 1, 1, 129, 200])
    s.send(True, msg(17, 0x14, cmd('tail', 3, NULL0, s0('z')), ts=1, sid=1) + msg(17, 0x14, cmd('tail', 3, NULL0, s0('z')), fmt=3))   # a type 3 message after a complete one
    # server direction with retransmitted data: the dissector sees the same sequence numbers again
    s.send(False, msg(4, 9, video_legacy(1, 7, b'r' * 300), ts=5, sid=1), cuts=[50, 100, 200])
    s.resend()                                                                                          # retransmission of the last segment (tcp.analyze_sequence_numbers off: RTMP sees it again)
    s.send(True, msg(18, 9, video_legacy(1, 7, b't' * 300), ts=5, sid=1), cuts=[50, 100, 100])
    s.resend()

    cap.mark('Session already in progress (no handshake in the capture): default chunk size 128, a type 3 header that starts a message, a continuation of a message whose first chunk is missing')
    m = Conv(cap, CIP, SIP, 49156, 1935, ipid=400, syn=False)
    m.cseq += 4000; m.sseq += 4000
    m.send(True, msg(5, 0x14, cmd('play', 1, NULL0, s0('mid')), ts=5, sid=1))
    m.send(True, msg(4, 9, video_legacy(1, 7, b'k' * 300), ts=5, sid=1))
    m.send(False, msg(3, 0x14, cmd('_result', 1, NULL0, n0(1))))
    m.send(False, msg(6, 9, video_legacy(1, 7, b'k' * 300), fmt=3))
    m.send(True, b'\xc4' + b'a' * 100)                                                                    # type 3 on csid 4 after a complete message, cut mid-message

    cap.mark('Connection whose sequence numbers wrap around (client ISN 0xffffffff, server ISN 0xffffffe0): the handshake and messages cross the wrap')
    w = Conv(cap, CIP, SIP, 49162, 1935, ipid=450, isn_c=0xffffffff, isn_s=0xffffffe0)
    handshake(w)
    w.send(True, msg(3, 0x14, cmd('connect', 1, o0([('app', s0('wrap'))]))))
    w.send(False, msg(9, 9, video_legacy(1, 7, b'v' * 300), ts=1, sid=1), cuts=[10, 20, 100])
    w.send(False, msg(9, 9, video_legacy(1, 7, b'v' * 300), ts=2, fmt=1), cuts=[3, 130])

    w2 = Conv(cap, CIP, SIP, 49163, 1935, ipid=470, syn=False, isn_c=0xffffff80)
    w2.send(True, msg(5, 9, video_legacy(1, 7, b'u' * 300), ts=1, sid=1), cuts=[100, 100, 100])
    w2.send(True, msg(5, 9, video_legacy(1, 7, b'u' * 300), ts=2, fmt=1), cuts=[150])

    cap.mark('Heuristic (disabled by default; enabled with --enable-heuristic rtmpt_tcp): server handshake on TCP 31935 at the sequence number the heuristic expects, then RTMP messages. Without the heuristic these frames are TCP payload')
    g = Conv(cap, CIP, SIP, 49157, 31935, ipid=500)
    g.send(True, b'\x03' + struct.pack('!II', 0, 0) + rnd(1528))
    g.send(False, b'\x03' + struct.pack('!II', 0, 0) + rnd(1528) + rnd(1536))
    g.send(True, rnd(1536))
    g.send(True, msg(2, 5, struct.pack('!I', 5000000)))
    g.send(False, msg(3, 0x14, cmd('_result', 1, NULL0, info('NetConnection.Connect.Success'))))
    # a second non-1935 connection that the heuristic rejects: not 0x03, or too short
    g2 = Conv(cap, CIP, SIP, 49158, 31936, ipid=550)
    g2.send(True, b'\x03' + rnd(1536))
    g2.send(False, b'\x06' + rnd(1536) + rnd(1536))                                                     # not 0x03 (RTMPE would use 0x06; no RTMPE data is generated)
    g3 = Conv(cap, CIP, SIP, 49159, 31937, ipid=560)
    g3.send(True, b'\x03' + rnd(1536))
    g3.send(False, b'\x03' + rnd(5))

    # ---------------------------------------------- HTTP tunnel
    cap.mark('RTMPT: RTMP tunnelled in HTTP (Content-Type application/x-fcs) on TCP 80: /open (one octet request, 17 octet response), /send with handshake C0+C1, response with S0+S1+S2, C2, a client command and a server response, /idle (one octet), /close')
    hc = Conv(cap, CIP, SIP, 49160, 80, ipid=600)
    def post(path, body):
        hd = ('POST %s HTTP/1.1\r\nHost: media.example\r\nContent-Type: application/x-fcs\r\nContent-Length: %d\r\n\r\n' % (path, len(body))).encode()
        hc.send(True, hd + body)
    def resp(body):
        hd = ('HTTP/1.1 200 OK\r\nContent-Type: application/x-fcs\r\nContent-Length: %d\r\n\r\n' % len(body)).encode()
        hc.send(False, hd + body)
    post('/open/1', b'\x00')
    resp(b'0123456789abcdef\n')
    post('/send/0123456789abcdef/0', b'\x03' + struct.pack('!II', 0, 0) + rnd(1528))
    resp(b'\x01' + b'\x03' + struct.pack('!II', 0, 0) + rnd(1528) + rnd(1536))
    post('/send/0123456789abcdef/1', rnd(1536))
    resp(b'\x01' + msg(2, 5, struct.pack('!I', 2500000)))
    post('/send/0123456789abcdef/2', msg(3, 0x14, cmd('connect', 1, o0([('app', s0('http'))]))))
    resp(b'\x01' + msg(3, 0x14, cmd('_result', 1, NULL0, info('NetConnection.Connect.Success'))) + msg(2, 4, struct.pack('!HI', 0, 0)))
    post('/idle/0123456789abcdef/3', b'\x01')
    resp(b'\x01')
    post('/send/0123456789abcdef/4', msg(3, 0x14, cmd('createStream', 2, NULL0)))
    resp(b'\x01' + msg(3, 0x14, cmd('_result', 2, NULL0, n0(1)))[:20])                                 # response cut inside a chunk header... continues next
    resp(b'\x01' + msg(3, 0x14, cmd('_result', 2, NULL0, n0(1)))[20:])
    post('/close/0123456789abcdef/5', b'\x01')
    resp(b'\x01')

    cap.mark('RTMPT conversation that starts with a server response (no request seen)')
    hr = Conv(cap, CIP, SIP, 49170, 80, ipid=650, syn=False)
    hd = lambda b: ('HTTP/1.1 200 OK\r\nContent-Type: application/x-fcs\r\nContent-Length: %d\r\n\r\n' % len(b)).encode() + b
    hr.send(False, hd(b'\x01' + msg(5, 0x14, cmd('onStatus', 0, NULL0, info('NetStream.Play.Start')))))
    hr.send(False, hd(b'\x01'))

    cap.mark('AMF over HTTP (Content-Type application/x-amf): AMF0 headers and messages with known and unknown length, AMF3 switch in a header, a response')
    ac = Conv(cap, CIP, SIP, 49161, 80, ipid=700)
    def amf_req(body, ctype='application/x-amf', server=False):
        if server:
            hd = ('HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n' % (ctype, len(body))).encode()
        else:
            hd = ('POST /gateway HTTP/1.1\r\nHost: media.example\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n' % (ctype, len(body))).encode()
        ac.send(not server, hd + body)
    def amf_msg(target, resp_uri, length, body):
        return name0(target) + name0(resp_uri) + struct.pack('!I', length) + body
    def amf_hdr(name, mu, length, val):
        return name0(name) + bytes([1 if mu else 0]) + struct.pack('!I', length) + val
    hb = amf_hdr('Credentials', True, 0xffffffff, o0([('userid', s0('u'))])) + amf_hdr('Other', False, 8, n0(1))
    mb = amf_msg('svc.method', '/1', 0xffffffff, strict0([s0('a'), n0(2)]))
    amf_req(struct.pack('!HH', 0, 2) + hb + struct.pack('!H', 1) + mb)
    amf_req(struct.pack('!HH', 0, 0) + struct.pack('!H', 1) + amf_msg('svc.other', '/2', 12, n0(5)))
    amf_req(struct.pack('!HH', 3, 1) + amf_hdr('H3', False, 3, AMF3_MARK) + struct.pack('!H', 0))      # header value is the AMF3 marker
    amf_req(struct.pack('!HH', 0, 3) + amf_hdr('A', False, 9, n0(1)) + amf_hdr('B', False, 9, AMF3_MARK) + amf_hdr('C', False, 2, i3(1)) + struct.pack('!H', 1) + amf_msg('t', 'r', 9, n0(1)))
    amf_req(struct.pack('!HH', 0, 0) + struct.pack('!H', 1) + amf_msg('/1/onResult', 'null', 5, o0([('ok', b0(True))])), server=True)

    # ---------------------------------------------- malformed
    mal.mark('start')
    # reproducer of the aggregate bug: every script tag holds a long string that runs to the end of the message
    N, T = 6, 200
    TAG = 11 + 5 + 4
    msglen = N * TAG + T
    body = bytearray()
    for i in range(N):
        data_start = i * TAG + 11
        body += bytes([18]) + (5).to_bytes(3, 'big') + b'\0\0\0\0' + b'\0\0\0' + b'\x0c' + struct.pack('!I', msglen - (data_start + 5)) + struct.pack('!I', TAG - 4)
    body += b'\x80' * T
    mc = Conv(mal, CIP, SIP, 50000, 1935, ipid=800)
    handshake(mc)
    mc.send(True, msg(2, 1, struct.pack('!I', 1000000)))
    CH[0] = 1000000
    mc.send(True, msg(3, 0x16, bytes(body), sid=1))
    # truncated AMF in the commands whose description is built from the AMF (every cut of a long command)
    full = cmd('connect', 1, o0([('a', n0(1)), ('b', b0(True)), ('c', NULL0), ('e', s0('str')), ('f', date0(1.0)), ('g', long0('long')), ('h', i64_0(5)),
                                  ('j', o0([('k', n0(0))])), ('l', ecma0([('m', xml0('<a/>'))])), ('app', s0('last'))]))
    for n in range(8, len(full), 2):
        mc.send(True, msg(3, 0x14, full[:n]))
    for n in range(12, 60, 3):
        mc.send(True, msg(3, 0x14, cmd('play', 2, o0([('a', s0('xyz')), ('b', ecma0([('c', n0(1))]))]), s0('name'))[:n]))
    for n in range(10, 50, 4):
        mc.send(True, msg(3, 0x14, cmd('onStatus', 0, NULL0, o0([('code', s0('abcdef'))]))[:n]))
    mc.send(True, msg(3, 0x14, cmd('_result', 1, NULL0, o0([('code', s0('abcdef'))])).replace(b'\x00\x06abcdef', b'\x00\xff' + b'abcdef')))
    big = o0([('a%d' % i, n0(1)) for i in range(1100)])
    mc.send(True, msg(3, 0x14, cmd('connect', 5, o0([('x', big), ('app', s0('z'))]))))                  # property value that trips the loop guard
    mc.send(True, msg(3, 0x14, big + s0('rest')))                                                        # first item that trips the loop guard (transaction ID)
    mc.send(True, msg(3, 0x14, cmd('connect', 6, o0([('app', s0('abcdef'))]))[:-9] ))                   # string longer than the rest
    # an object with more than 1000 properties in a skipped parameter: loop guard of the length scan
    mc.send(True, msg(3, 0x14, cmd('play', 3, o0([('a%d' % i, n0(1)) for i in range(1100)]), s0('x'))))
    mc.send(True, msg(3, 0x14, cmd('connect', 4, o0([('a%d' % i, n0(1)) for i in range(1100)]))))
    # control messages that are too short for their fields
    mc.send(True, msg(2, 1, b'\x00\x00'))
    mc.send(True, msg(2, 6, struct.pack('!I', 5)))
    mc.send(True, msg(2, 3, b'\x01'))
    mc.send(True, msg(2, 4, b'\x00'))
    mc.send(True, msg(2, 4, struct.pack('!H', 3) + b'\x00'))
    mc.send(True, msg(2, 4, struct.pack('!HI', 0, 1)[:4]))
    mc.send(True, msg(4, 0x12, b''.join(vals[:8])))                                                     # data message that starts with a number: the name length comes from the number
    mc.send(True, msg(4, 8, audio_legacy(10, 3, 1, 1, b'')))                                            # control octet only
    mc.send(True, msg(4, 9, video_legacy(1, 7, b'')))
    mc.send(True, msg(4, 8, audio_legacy(9, 1, 1, 1, b'\x01\x02\x03')))                                # codec 9, 11, 13, 15 have bit 4 and 7 set: taken for an enhanced header
    mc.send(True, msg(4, 8, audio_legacy(11, 3, 1, 1, b'\x01\x02\x03')))
    # AMF0 truncated values
    for b in (n0(1)[:5], s0('abcdef')[:4], o0([('a', n0(1))])[:6], date0(1.0)[:6], long0('abcdef')[:5], i64_0(1)[:4], ref0(1)[:2], ecma0([('a', s0('b'))])[:9],
              strict0([n0(1)])[:7], typed0('c', [('a', n0(1))])[:6], o0([('a', s0('x'))]).replace(END0, b'')):
        mc.send(True, msg(3, 0x14, s0('x') + n0(0) + b))
    mc.send(True, msg(3, 0x14, s0('x') + n0(0) + strict0([NULL0]) [:5] + struct.pack('!I', 0x7fffffff)[:0]))
    mc.send(True, msg(3, 0x14, s0('x') + n0(0) + b'\x0a' + struct.pack('!I', 5000)))                    # strict array count far past the data
    # deep recursion of nested objects: more levels than the dissection depth limit
    deep = b''
    for _ in range(300): deep += b'\x03\x00\x01a'
    mc.send(True, msg(3, 0x14, s0('x') + n0(0) + deep))
    deep = b'\x0a' * 0
    inner = b''
    for _ in range(300): inner += b'\x0a\x0b\x01\x01'
    mc.send(True, msg(3, 0x14, s0('x') + n0(0) + AMF3_MARK + inner))
    deep3 = b''.join(b'\x09\x03\x01' for _ in range(300))
    mc.send(True, msg(3, 0x14, s0('x') + n0(0) + AMF3_MARK + deep3))
    mc.send(True, msg(3, 0x11, b'\x00' + s0('x') + n0(0) + AMF3_MARK + arr3([('sr', sref3(0))], [])))   # string reference as an array value: the extra skip eats the end marker
    # AMF3 truncations
    for b in (i3(0x1fffffff)[:3], d3(1.0)[:4], s3('abcdef')[:4], date3(1.0)[:4], arr3([('ab', i3(5))], [i3(1)])[:6], arr3([], [i3(1), i3(2)])[:4],
              obj3('C', ['a'], [i3(1)])[:5], obj3('C', ['a'], [i3(1)], dynamic=[('k', i3(2))])[:12], xml3('abcdef')[:4], ba3(b'abcdef')[:4],
              b'\x0a' + u29((2 << 4) | 3) + utf3('C') + utf3('a')):
        mc.send(True, msg(3, 0x14, s0('x') + n0(0) + AMF3_MARK + b))
    # audio / video truncations
    mc.send(True, msg(4, 8, bytes([0x95, 0x00]) + b'mp'))
    mc.send(True, msg(4, 8, bytes([0x95, 0x01]) + b'mp4a' + b'\x00\x00'))
    mc.send(True, msg(4, 8, audio_mt(1, 1, b'mp4a', [(0, None, b'\x01\x02')])[:10] + b'\x00\x00\x20\x01'))
    mc.send(True, msg(4, 8, audio_mt(2, 1, None, [(0, b'mp4a', b'\x01\x02')])[:5]))
    mc.send(True, msg(4, 9, bytes([0x86, 0x20]) + b'av'))
    mc.send(True, msg(4, 9, video_mt(1, 1, 1, b'av01', [(0, None, b'\x01\x02')])[:9] + b'\x00\x00\x20\x01'))
    mc.send(True, msg(4, 9, bytes([0x87])))                                                             # enhanced, no fourcc
    mc.send(True, msg(4, 9, bytes([0x17])[:0] + b'\x57'))                                               # command frame without command
    mc.send(True, msg(4, 8, b'\x00'[:0] + b'\x01'))
    # aggregate truncated tags
    mc.send(True, msg(5, 0x16, tag(8, b'\x00\x00', ts=1)[:14]))
    mc.send(True, msg(5, 0x16, bytes([8]) + (500).to_bytes(3, 'big') + b'\0' * 7 + b'\x20\x01'))
    mc.send(True, msg(5, 0x16, tag(9, b'\x17\x01\x02') + b'\x08\x00'))
    # a message that declares more than what arrives: header cut
    mc.send(True, b'\x03\x00\x00\x00\x00\x00\x10\x14\x00\x00\x00', cuts=[5])
    # AMF over HTTP: two messages (the first consumes the whole body) and truncated pieces
    ma = Conv(mal, CIP, SIP, 50001, 80, ipid=900)
    def mamf(body, server=False):
        if server:
            hd = ('HTTP/1.1 200 OK\r\nContent-Type: application/x-amf\r\nContent-Length: %d\r\n\r\n' % len(body)).encode()
        else:
            hd = ('POST /gateway HTTP/1.1\r\nHost: media.example\r\nContent-Type: application/x-amf\r\nContent-Length: %d\r\n\r\n' % len(body)).encode()
        ma.send(not server, hd + body)
    mamf(struct.pack('!HH', 0, 0) + struct.pack('!H', 2) + amf_msg('a', 'b', 0, n0(1)) + amf_msg('c', 'd', 0, n0(2)))
    mamf(struct.pack('!HH', 0, 1) + name0('H')[:3])
    mamf(struct.pack('!H', 0))
    mamf(struct.pack('!HHH', 0, 0, 1) + name0('t'))
    mamf(struct.pack('!HHH', 0, 0, 1) + name0('t') + name0('r') + struct.pack('!I', 0) + b'\x03')
    # Tunnel with data that does not parse
    mh = Conv(mal, CIP, SIP, 50002, 80, ipid=950)
    def mpost(body):
        hd = ('POST /send/ab/0 HTTP/1.1\r\nHost: m\r\nContent-Type: application/x-fcs\r\nContent-Length: %d\r\n\r\n' % len(body)).encode()
        mh.send(True, hd + body)
    def mresp(body):
        hd = ('HTTP/1.1 200 OK\r\nContent-Type: application/x-fcs\r\nContent-Length: %d\r\n\r\n' % len(body)).encode()
        mh.send(False, hd + body)
    mpost(b'\x00'); mresp(b'0123456789abcdef\n'); mpost(msg(3, 0x14, cmd('x', 1, NULL0))[:5]); mresp(b'\x01'); mresp(b'\x01' + msg(3, 0x14, b'\x02\x00\x10ab'))
    return cap, mal

def objext_pad():
    # U29O-traits-ext is the last element: the dissector reads nothing after the flags
    return OBJEXT3

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    cap, mal = build()
    cap.write(os.path.join(out, 'rtmpt-coverage.pcap'))
    mal.write(os.path.join(out, 'rtmpt-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, t in cap.marks: print(n, t)
        print(len(cap.frames), 'frames', len(mal.frames), 'malformed')
