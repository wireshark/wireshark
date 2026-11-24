#!/usr/bin/env python3
# Generates test/captures/protobuf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Protobuf dissector
(packet-protobuf.c).

The Protobuf dissector is reached (a) over HTTP by the media type
"application/x-protobuf" (default preferences: no message type, so every
field is "undefined"), (b) from the gRPC dissector with
"application/grpc,/<service>/<method>,request|response" over HTTP/2, (c)
over UDP ports listed in the "Protobuf UDP message types" UAT, (d) over
HTTP for the request URIs of the "Protobuf URI message types" UAT.
Message types come from .proto files (protos/ here; the test class holds
copies): cov2.proto (proto2: every scalar type, group, Timestamp,
packed/unpacked repeated, defaults, oneof, maps, nesting), cov3.proto
(proto3 with a gRPC service) and broken.proto (a field whose type does
not resolve).

Everything is built with struct; nothing is captured traffic.

Usage: mkprotobuf.py <output directory>

Writes:
  protobuf-coverage.pcap            UDP messages for UDP ports 30001-30007,
                                    HTTP x-protobuf requests/responses
                                    (untyped, and typed through URIs),
                                    gRPC over HTTP/2, MySQL X and Sparkplug B
                                    (types from the installed .proto files),
                                    port 30008 with broken.proto (the
                                    reproducers of the fixed bugs)
  protobuf-coverage-malformed.pcap  packet and field level errors
"""
import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 10])
IP_S = bytes([192, 0, 2, 1])

UDP_TYPES = {30009: 'adc.sip.RequestPDU', 30010: 'adc.sip.ResponsePDU', 30001: 'cov.Scalars', 30002: 'cov.Repeated', 30003: 'cov.Defaults',
             30004: 'cov.Oneofs', 30005: 'cov.Nested', 30006: 'cov3.Msg3',
             30007: 'cov.NoSuchMessage', 30008: 'brk.Broken'}

# ------------------------------------------------------------- protobuf wire


def varint(n):
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(fn, wt):
    return varint((fn << 3) | wt)


def f_var(fn, v):
    return tag(fn, 0) + varint(v)


def f_len(fn, data):
    if isinstance(data, str):
        data = data.encode()
    return tag(fn, 2) + varint(len(data)) + data


def f_64(fn, data8):
    return tag(fn, 1) + data8


def f_32(fn, data4):
    return tag(fn, 5) + data4


def zz32(n):
    return ((n << 1) ^ (n >> 31)) & 0xffffffff


def zz64(n):
    return ((n << 1) ^ (n >> 63)) & 0xffffffffffffffff


def ts(secs, nanos=None):
    b = f_var(1, secs)
    if nanos is not None:
        b += f_var(2, nanos)
    return b


def inner(name=None, id_=None):
    b = b''
    if name is not None:
        b += f_len(1, name)
    if id_ is not None:
        b += f_var(2, id_)
    return b


# ------------------------------------------------------------------ packets

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip_frame(proto, payload, c2s=True):
    src, dst = (IP_C, IP_S) if c2s else (IP_S, IP_C)
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0) + src + dst
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    mac = (MAC_S + MAC_C) if c2s else (MAC_C + MAC_S)
    return mac + b'\x08\x00' + ip + payload


def udp(frames, port, payload, c2s=True):
    sp, dp = (40000, port) if c2s else (port, 40000)
    u = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    frames.append(ip_frame(17, u, c2s))


class Tcp:
    def __init__(self, frames, cport, sport):
        self.frames, self.cport, self.sport = frames, cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.seg(True, 0x02, b'')
        self.cseq += 1
        self.seg(False, 0x12, b'')
        self.sseq += 1
        self.seg(True, 0x10, b'')

    def seg(self, c2s, flags, data):
        sp, dp = (self.cport, self.sport) if c2s else (self.sport, self.cport)
        seq, ack = (self.cseq, self.sseq) if c2s else (self.sseq, self.cseq)
        if flags == 0x02:
            ack = 0
        if flags & 0x02:
            hdr = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x70, flags, 65535, 0, 0) \
                + struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1)
        else:
            hdr = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
        self.frames.append(ip_frame(6, hdr + data, c2s))

    def send(self, c2s, data):
        self.seg(c2s, 0x18, data)
        if c2s:
            self.cseq += len(data)
        else:
            self.sseq += len(data)
        self.seg(not c2s, 0x10, b'')


def http_req(t, uri, body, ctype=b'application/x-protobuf'):
    t.send(True, b'POST ' + uri.encode() + b' HTTP/1.1\r\nHost: example.com\r\nContent-Type: '
           + ctype + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


def http_resp(t, body, ctype=b'application/x-protobuf'):
    t.send(False, b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype + b'\r\nContent-Length: '
           + str(len(body)).encode() + b'\r\n\r\n' + body)


# --------------------------------------------------------------- HTTP/2 / gRPC

def h2(ftype, flags, stream, payload):
    return struct.pack('>I', len(payload))[1:] + bytes([ftype, flags]) + struct.pack('>I', stream) + payload


def hp_lit(name_idx, value):
    """HPACK literal header without indexing, indexed name."""
    v = value if isinstance(value, bytes) else value.encode()
    if name_idx < 15:
        first = bytes([name_idx])
    else:
        first = bytes([0x0f, name_idx - 15])
    return first + bytes([len(v)]) + v


def grpc_msg(data, compressed=0):
    return bytes([compressed]) + struct.pack('>I', len(data)) + data


# ------------------------------------------------------------- the messages

def scalars_full():
    return (f_64(1, struct.pack('<d', 1.5)) + f_32(2, struct.pack('<f', 2.5))
            + f_var(3, 150) + f_var(4, -2) + f_var(5, 4000000000) + f_var(6, (1 << 63) + 5)
            + f_var(7, zz32(-3)) + f_var(8, zz64(-5)) + f_32(9, struct.pack('<I', 0xdeadbeef))
            + f_64(10, struct.pack('<Q', 0x1122334455667788)) + f_32(11, struct.pack('<i', -5))
            + f_64(12, struct.pack('<q', -6)) + f_var(13, 1) + f_len(14, 'héllo')
            + f_len(15, b'\x00\x01\xfe') + f_var(16, 2) + f_len(17, inner('in', 5))
            + f_len(18, ts(1700000000)) + f_len(19, f_var(1, 5) + f_len(2, 'x')))


def repeated_full():
    def pk(fn, vals):
        return f_len(fn, b''.join(vals))
    return (pk(1, [varint(1), varint(300), varint(-1)])
            + pk(2, [varint(-2), varint(5)])
            + pk(3, [varint(7), varint(4000000000)])
            + pk(4, [varint(1 << 40)])
            + pk(5, [varint(zz32(-1)), varint(zz32(2))])
            + pk(6, [varint(zz64(-9)), varint(zz64(10))])
            + pk(7, [varint(1), varint(0)])
            + pk(8, [varint(0), varint(1), varint(2), varint(7)])
            + pk(9, [struct.pack('<I', 1), struct.pack('<I', 2)])
            + pk(10, [struct.pack('<i', -1), struct.pack('<i', 2)])
            + pk(11, [struct.pack('<f', 1.0), struct.pack('<f', -2.0)])
            + pk(12, [struct.pack('<Q', 1), struct.pack('<Q', 2)])
            + pk(13, [struct.pack('<q', -1), struct.pack('<q', 2)])
            + pk(14, [struct.pack('<d', 1.0), struct.pack('<d', -2.0)])
            + f_var(15, 1) + f_var(15, 2) + f_var(15, 3)
            + f_len(16, 'a') + f_len(16, 'bb')
            + f_len(17, inner('x', 1)) + f_len(17, inner('y', 2))
            + f_var(18, 1) + f_var(18, 5)
            + f_len(19, b'\x01') + f_len(19, b'\x02\x03')
            + f_var(20, 99))


def mapentry(k, v):
    return k + v


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    F = []   # main capture

    # ---------------- UDP, cov.Scalars (30001)
    P = 30001
    udp(F, P, scalars_full())                                            # 1 every type
    udp(F, P, f_var(13, 0) + f_var(16, 9) + f_len(18, ts(1700000000, 500000000)) + f_var(3, 1))   # false, unknown enum, .500
    udp(F, P, f_len(18, ts(1700000000, 123456789)) + f_var(3, 2))   # nanos width 9
    udp(F, P, f_len(18, ts(1, 120000)) + f_var(3, 2))                    # nanos width 6
    udp(F, P, f_len(18, ts(1700000000, 1)) + f_var(3, 3))                # nanos 1
    udp(F, P, f_len(18, b'') + f_var(3, 3))                              # empty Timestamp
    udp(F, P, f_var(3, -1) + f_var(4, -1) + f_var(13, 1) + f_var(7, 0) + f_var(8, 1))  # negative int32
    udp(F, P, f_var(13, 0x8000) + f_var(3, 7))                           # BOOL in two bytes, F1
    udp(F, P, f_var(99, 7) + f_32(98, b'abcd') + f_64(97, b'12345678') + f_len(96, 'unknown') + f_var(3, 1))
    udp(F, P, f_var(3, 1) + f_var(13, 1), c2s=False)                     # reverse direction
    udp(F, P, f_len(17, inner('only name')) + f_len(17, inner(None, 3)) + f_len(14, ''))
    udp(F, P, f_var(1 << 20, 5) + f_len(15, b''))                        # large field number
    udp(F, 30001, f_len(18, ts(1 << 62)) + f_var(3, 4))                  # seconds that gmtime() cannot represent
    udp(F, 30001, f_len(18, f_64(3, b'12345678') + f_var(1, 5)) + f_var(3, 5))   # Timestamp with a fixed64 field
    # ---------------- cov.Repeated (30002)
    P = 30002
    udp(F, P, repeated_full())
    udp(F, P, f_len(1, b'') + f_len(11, b'') + f_var(15, 1) + f_var(20, 2) + f_var(15, 3))
    udp(F, P, f_var(1, 5) + f_32(11, struct.pack('<f', 3.0)) + f_64(14, struct.pack('<d', 3.0)))  # packed fields not packed
    udp(F, P, f_len(16, 'one') + f_var(20, 1) + f_len(16, 'two') + f_len(16, 'three'))
    udp(F, P, f_len(17, inner('a', 1)) + f_len(17, inner('b', 2)) + f_var(18, 2))
    udp(F, P, f_var(15, 1) + f_var(15, 2) + f_var(99, 5) + f_var(20, 1))   # unknown field after a repeated one
    # ---------------- cov.Defaults (30003)
    P = 30003
    udp(F, P, f_var(1, 1))                                               # all defaults missing
    udp(F, P, f_var(1, 2) + f_var(2, 5) + f_len(15, 'x') + f_var(17, 1) + f_var(12, 0) + f_var(28, 1)
        + f_len(32, b'\xff') + f_len(31, 'abc') + f_var(33, 2))
    udp(F, P, f_var(1, 3) + f_var(35, 1) + f_var(35, 2) + f_len(34, inner('d', 1)))
    udp(F, P, f_var(2, 5) + f_var(12, 1))                                # missing the required field
    # ---------------- cov.Oneofs (30004)
    P = 30004
    udp(F, P, f_var(1, 5))
    udp(F, P, f_len(2, 'text'))
    udp(F, P, f_len(3, inner('sub', 9)))
    udp(F, P, f_len(4, f_len(1, 'k1') + f_var(2, 1)) + f_len(4, f_len(1, 'k2') + f_var(2, 2))
        + f_len(5, f_var(1, 7) + f_len(2, inner('v', 7))) + f_len(6, f_var(1, 1) + f_len(2, b'\x01\x02')))
    # ---------------- cov.Nested (30005)
    P = 30005
    udp(F, P, f_var(1, 1) + f_len(2, f_var(1, 2) + f_len(2, f_var(1, 3))))

    def chain(n):
        m = f_var(1, n)
        for i in range(n - 1, 0, -1):
            m = f_var(1, i) + f_len(2, m)
        return m
    udp(F, P, chain(40))
    # ---------------- cov3.Msg3 (30006, proto3)
    P = 30006
    udp(F, P, f_var(1, 1) + f_len(2, 'b') + f_len(3, b'\x00\x01') + f_var(4, 1) + f_var(5, 1)
        + f_len(6, varint(1) + varint(2)) + f_len(7, 'x') + f_len(7, 'y')
        + f_len(8, struct.pack('<dd', 1.0, 2.0))
        + f_len(9, f_len(1, 'key') + f_len(2, 'val')))
    udp(F, P, f_var(1, 0) + f_var(4, 0) + f_var(5, 3))                  # zero values, unknown enum value
    # ---------------- untyped (30007: message type that does not exist)
    P = 30007
    untyped = (f_var(1, 1) + f_var(2, 300) + f_var(3, 1 << 40) + f_64(4, struct.pack('<Q', 5))
               + f_32(5, struct.pack('<I', 6)) + f_len(6, 'plain text')
               + f_len(7, b'\x00\xff\x01\x02') + f_len(8, f_var(1, 1) + f_len(2, 'nest')) + f_len(9, b''))
    udp(F, P, untyped)
    udp(F, P, f_var(1, 0xffffffff) + f_var(2, 0x100000000) + f_len(3, 'ünï'))
    # ---------------- HTTP (TCP 8080), default preferences: untyped
    t = Tcp(F, 41001, 8080)
    http_req(t, '/upload', untyped)
    http_resp(t, f_var(1, 1) + f_len(2, 'ok'))
    http_req(t, '/other', f_len(1, 'abc'))
    http_resp(t, b'')
    # typed through the URI UAT: /api/cov -> cov.Scalars, /api/*/items -> cov.Repeated
    t = Tcp(F, 41002, 8080)
    http_req(t, '/api/cov', scalars_full())
    http_resp(t, f_var(3, 1) + f_len(14, 'resp'))
    http_req(t, '/api/x/items', repeated_full())
    http_resp(t, f_var(20, 1))
    http_req(t, '/api/x/y/z', f_var(1, 1))          # does not match, default_type
    http_resp(t, f_var(1, 2))
    http_req(t, '/api/', f_var(1, 1))               # pattern /api/*/items is longer than the URI
    http_resp(t, f_var(1, 2))
    http_req(t, '/exact', f_len(2, 'text'))
    http_resp(t, f_var(1, 4))
    t = Tcp(F, 41004, 8080)
    http_req(t, '/star/anything/at/all', f_var(3, 5) + f_len(14, 'star'))
    http_resp(t, f_var(3, 6))
    http_req(t, '/' + 'a' * 40 + '!', f_var(1, 5))     # a pattern with 16 wildcards that does not match
    http_resp(t, f_var(1, 6))
    # ---------------- MySQL X protocol (TCP 33060): message types from the global .proto files
    def mx(typ, body):
        return struct.pack('<IB', len(body) + 1, typ) + body
    t = Tcp(F, 41005, 33060)
    t.send(True, mx(1, b''))                                                    # CapabilitiesGet
    t.send(False, mx(0, f_len(1, 'ok')))                  # Ok
    t.send(True, mx(4, f_len(1, 'MYSQL41') + f_len(2, b'\x01\x02') + f_len(3, b'resp')))   # AuthenticateStart
    t.send(False, mx(1, f_var(1, 1) + f_var(2, 1045) + f_len(3, 'Access denied') + f_len(4, 'HY000')))   # Error
    t.send(True, mx(12, f_len(1, 'SELECT 1') + f_len(3, 'sql') + f_var(4, 1)))  # StmtExecute
    t.send(False, mx(17, b''))                                                  # StmtExecuteOk
    # ---------------- Sparkplug B over MQTT (TCP 1883)
    def publish(topic, payload):
        body = struct.pack('>H', len(topic)) + topic.encode() + payload
        rl = varint(len(body))
        return bytes([0x30]) + rl + body
    metric = lambda name, extra: f_len(2, f_len(1, name) + f_var(3, 1700000000000) + extra)
    spb = (f_var(1, 1700000000000)
           + metric('temperature', f_var(4, 10) + f_64(13, struct.pack('<d', 21.5)))
           + metric('count', f_var(4, 7) + f_var(10, 42))
           + metric('label', f_var(4, 12) + f_len(15, 'tank 1'))
           + metric('on', f_var(4, 11) + f_var(14, 1))
           + f_var(3, 9))
    t = Tcp(F, 41006, 1883)
    cb = struct.pack('>H', 4) + b'MQTT' + bytes([4, 2]) + struct.pack('>H', 60) + struct.pack('>H', 2) + b'c1'
    t.send(True, bytes([0x10]) + varint(len(cb)) + cb)
    t.send(False, bytes([0x20, 2, 0, 0]))
    t.send(True, publish('spBv1.0/Group1/NDATA/Edge1', spb))
    t.send(True, publish('spBv1.0/Group1/DDATA/Edge1/Dev1', spb))
    # ---------------- gRPC over HTTP/2 (TCP 50051)
    t = Tcp(F, 41003, 50051)
    t.send(True, b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2(4, 0, 0, b''))
    t.send(False, h2(4, 0, 0, b'') + h2(4, 1, 0, b''))
    t.send(True, h2(4, 1, 0, b''))
    req = f_var(1, 7) + f_len(2, 'grpc request') + f_len(6, varint(3) + varint(4))
    hdr = (b'\x83\x86' + hp_lit(4, '/cov3.Svc/Call') + hp_lit(1, 'example.com')
           + hp_lit(31, 'application/grpc'))
    t.send(True, h2(1, 4, 1, hdr) + h2(0, 1, 1, grpc_msg(req)))
    resp = f_var(1, 8) + f_len(2, 'grpc response')
    t.send(False, h2(1, 4, 1, b'\x88' + hp_lit(31, 'application/grpc')) + h2(0, 0, 1, grpc_msg(resp)))
    # a gRPC method that the proto files do not know
    hdr = b'\x83\x86' + hp_lit(4, '/cov3.Svc/Unknown') + hp_lit(1, 'example.com') + hp_lit(31, 'application/grpc')
    t.send(True, h2(1, 4, 3, hdr) + h2(0, 1, 3, grpc_msg(f_var(1, 1) + f_len(2, 'unknown method'))))
    # ---------------- brk.Broken (30008, needs broken.proto): reproducers of the fixed bugs
    P = 30008
    udp(F, P, f_var(1, 1) + f_var(2, 5))                                 # valid
    udp(F, P, f_var(1, 0x8000) + f_var(2, 5))                            # flag in two bytes (JSON assert)
    udp(F, P, f_var(1, 1) + f_len(3, b'abc') + f_var(4, 1))              # field of unresolved type (hf assert)
    udp(F, P, f_var(1, 1) + f_var(3, 5) + f_var(4, 2))
    # ---------------- adc.sip (30009, 30010): the SIP subdissector of the bytes fields
    sip_req = (b'OPTIONS sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060\r\n'
               b'From: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>\r\nCall-ID: 1@x\r\n'
               b'CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n')
    sip_rsp = (b'SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.0.2.10:5060\r\nFrom: <sip:a@example.com>;tag=1\r\n'
               b'To: <sip:b@example.com>;tag=2\r\nCall-ID: 1@x\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n')
    udp(F, 30009, f_len(1, 'req-1') + f_len(2, sip_req))
    udp(F, 30010, f_len(1, sip_rsp), c2s=False)
    pcap(os.path.join(outdir, 'protobuf-coverage.pcap'), F)

    # =================== malformed
    M = []
    P = 30001
    udp(M, P, f_var(3, 1) + f_var(3, 2))                                 # a field that is not repeated, twice (JSON mapping: bad state)
    udp(M, P, f_len(18, ts(1, 5)) + f_len(18, ts(2, 6)))                 # the same with Timestamp
    udp(M, P, b'\x80')                                                   # tag varint cut off
    udp(M, P, b'\x08')                                                   # varint field without value
    udp(M, P, tag(3, 0) + b'\x80\x80')                                   # unterminated value varint
    udp(M, P, tag(14, 2) + b'\x80')                                      # length varint cut off
    udp(M, P, tag(14, 2) + varint(100) + b'abc')                        # length past the end
    udp(M, P, tag(10, 1) + b'\x01\x02')                                  # fixed64 cut short
    udp(M, P, tag(9, 5) + b'\x01')                                       # fixed32 cut short
    udp(M, P, tag(3, 3) + f_var(1, 1) + tag(3, 4))                      # start/end group wire types
    udp(M, P, tag(3, 6) + b'\x00')                                       # reserved wire type 6
    udp(M, P, f_len(18, ts(1700000000, 500000000)))                      # Timestamp as the last field
    udp(M, P, f_len(18, f_var(2, 1000000000)))                          # Timestamp nanos out of range
    udp(M, P, f_len(18, f_var(1, 1) + b'\x80'))                         # Timestamp with a broken varint
    udp(M, P, f_len(17, f_len(1, 'x') + b'\x80'))                       # error inside a nested message
    udp(M, P, f_len(17, tag(2, 2) + varint(50) + b'ab') + f_var(3, 1))  # nested length past the nested message
    P = 30002
    udp(M, P, f_len(11, b'\x00\x00\x80'))                               # packed float, length not a multiple of 4
    udp(M, P, f_len(14, b'\x00' * 12))                                  # packed double, not a multiple of 8
    udp(M, P, f_len(1, b'\x80'))                                         # packed varint cut off
    udp(M, P, f_len(7, b'\x01\x80'))
    P = 30003
    udp(M, P, b'')                                                       # missing required, default values
    P = 30007
    udp(M, P, f_len(1, b'\x80\x80'))
    udp(M, P, b'\x07')                                                   # wire type 7
    udp(M, 30012, f_var(1, 1))                  # a port whose message type row is empty
    udp(M, 30008, f_64(2, b'\x01\x02'))        # cut-short fixed64: the JSON dumper's GString leaked
    pcap(os.path.join(outdir, 'protobuf-coverage-malformed.pcap'), M)



def pcap(path, frs):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frs):
            f.write(struct.pack('<IIII', 1700000000 + i // 100, 10000 * (i % 100), len(fr), len(fr)))
            f.write(fr)


if __name__ == '__main__':
    main(sys.argv[1])
