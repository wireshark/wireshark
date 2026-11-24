#!/usr/bin/env python3
# Generates test/captures/roughtime_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the Roughtime coverage captures: mkroughtime.py <outdir>
# Every packet is built with struct; nothing comes from a real network.
# Signatures, public keys and Merkle roots are placeholder bytes: there is
# no signing code. Roughtime: IETF format (ROUGHTIM header, UDP/TCP 5319)
# and the Google format (UDP 2002, 2003).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pk import Cap, Tcp, udp_frame

SIG = b'SIG\0'; VER = b'VER\0'; SRV = b'SRV\0'; NONC = b'NONC'; DELE = b'DELE'
TYPE = b'TYPE'; PATH = b'PATH'; RADI = b'RADI'; PUBK = b'PUBK'; MIDP = b'MIDP'
SREP = b'SREP'; VERS = b'VERS'; MINT = b'MINT'; ROOT = b'ROOT'; CERT = b'CERT'
MAXT = b'MAXT'; INDX = b'INDX'; ZZZZ = b'ZZZZ'; PAD = b'PAD\xff'

def msg(tags):
    '''A Roughtime message: num_tags, offsets (all but the first), tags,
    values. tags is a list of (tag, value); values are padded to 4.'''
    vals = [v + b'\0' * (-len(v) % 4) for _, v in tags]
    offs = []
    o = 0
    for v in vals[:-1]:
        o += len(v)
        offs.append(o)
    return (struct.pack('<I', len(tags)) + b''.join(struct.pack('<I', x) for x in offs)
            + b''.join(t for t, _ in tags) + b''.join(vals))

def ietf(m):
    return b'ROUGHTIM' + struct.pack('<I', len(m)) + m

def ph(n, seed=0):
    '''n placeholder bytes (not a real signature, key or hash)'''
    return bytes((seed + i) & 0xff for i in range(n))

def u32(*v): return b''.join(struct.pack('<I', x) for x in v)
def u64(v): return struct.pack('<Q', v)

NOW = 1700000000        # seconds
VERS_IETF = (0x8000000c,)   # draft version number placeholder

def ietf_request(nonce_seed=1, ver=(0x8000000c, 0x8000000b), total=1024, srv=True):
    tags = [(VER, u32(*ver)), (NONC, ph(32, nonce_seed))]
    tags.append((TYPE, u32(0)))
    if srv:
        tags.append((SRV, ph(32, 100)))
    m = msg(tags + [(ZZZZ, b'')])
    pad = total - 12 - len(m) - 8     # a ZZZZ value that fills up to total
    tags.append((ZZZZ, bytes(max(pad, 0))))
    return ietf(msg(tags))

def ietf_cert(seed=3):
    dele = msg([(MINT, u64(NOW - 86400)), (MAXT, u64(NOW + 86400)), (PUBK, ph(32, seed))])
    return msg([(SIG, ph(64, seed)), (DELE, dele)])

def ietf_response(nonce_seed=1, path=0, radius=3, extra=None):
    srep = msg([(RADI, u32(radius)), (MIDP, u64(NOW)), (VERS, u32(0x8000000c)), (ROOT, ph(32, 7))])
    tags = [(SIG, ph(64, 9)), (NONC, ph(32, nonce_seed)), (TYPE, u32(1)),
            (PATH, ph(32 * path, 11)), (SREP, srep), (CERT, ietf_cert()), (INDX, u32(0))]
    return ietf(msg(tags + (extra or [])))

def g_request(total=1024):
    m = msg([(NONC, ph(64, 1)), (PAD, b'')])
    pad = total - len(m)
    return msg([(NONC, ph(64, 1)), (PAD, bytes(pad))])

def g_cert(seed=3):
    dele = msg([(PUBK, ph(32, seed)), (MAXT, u64(NOW * 1000000 + 10**9)), (MINT, u64(NOW * 1000000 - 10**9))])
    return msg([(SIG, ph(64, seed)), (DELE, dele)])

def g_response(path=0, radius=1000000):
    srep = msg([(RADI, u32(radius)), (MIDP, u64(NOW * 1000000)), (ROOT, ph(64, 7))])
    return msg([(SIG, ph(64, 9)), (PATH, ph(64 * path, 11)), (SREP, srep), (CERT, g_cert()), (INDX, u32(0))])

def main(out):
    cap = Cap()
    n = [0]
    def c2s(payload, sport, dport=5319):
        n[0] += 1
        return cap.add(udp_frame(sport, dport, payload, ident=n[0]))
    def s2c(payload, sport, dport):
        n[0] += 1
        return cap.add(udp_frame(sport, dport, payload, '192.0.2.2', '192.0.2.1', ident=n[0]))

    # IETF over UDP 5319: request, response (Merkle path of 1 and of 32 hashes,
    # the longest allowed)
    c2s(ietf_request(1), 40001); s2c(ietf_response(1, path=0), 5319, 40001)
    c2s(ietf_request(2, srv=False), 40002); s2c(ietf_response(2, path=1, radius=0), 5319, 40002)
    c2s(ietf_request(3, ver=(1,), total=1600), 40003); s2c(ietf_response(3, path=32), 5319, 40003)
    # A response arriving before its request and a request without response
    # (a response without request is in the malformed capture: with -2 it
    # is shown as its own request)
    s2c(ietf_response(4), 5319, 40004); c2s(ietf_request(4), 40004)
    c2s(ietf_request(5), 40005)
    # Tags: empty version list, unknown tag, PATH of zero length, SRV, SIG
    c2s(ietf(msg([(VER, b''), (NONC, ph(32)), (b'ABCD', b'unknown tag value'), (PATH, b''), (SRV, ph(32, 5))])), 40007)
    # Google format over UDP 2002 and 2003
    c2s(g_request(), 40010, 2002); s2c(g_response(0), 2002, 40010)
    c2s(g_request(), 40011, 2003); s2c(g_response(2, radius=5), 2003, 40011)
    c2s(g_request(900), 40012, 2002); s2c(g_response(3, radius=0), 2002, 40012)
    # Google messages with a VER/VERS list, a pad tag, ZZZZ and an empty PATH
    c2s(msg([(NONC, ph(64)), (VER, u32(0, 1)), (ZZZZ, bytes(8)), (PAD, bytes(100))]), 40013, 2002)
    # Not Roughtime: first word >= 16 on port 2002, and a payload under 8 octets
    c2s(struct.pack('<I', 99) + bytes(40), 40014, 2002)
    c2s(b'abc', 40015, 5319)
    # A Google message with no tags that is shorter than the IETF header
    c2s(struct.pack('<I', 0) + b'\1\2\3\4\5\6', 40017, 2002)
    # IETF message with the short tag count 1 and a SREP nested up to the
    # limit (depth 8)
    m = msg([(MIDP, u64(NOW)), (RADI, u32(1))])
    for _ in range(8):
        m = msg([(SREP, m)])
    c2s(ietf(m), 40016)
    # TCP 5319: request/response, two PDUs in a segment, a split PDU
    t = Tcp(cap, 40020, 5319)
    t.handshake()
    t.c(ietf_request(20))
    t.s(ietf_response(20))
    r = ietf_request(21); s = ietf_response(21)
    t.c(r + ietf_request(22))
    p = s + ietf_response(22, path=2)
    t.s(p[:20]); t.s(p[20:300]); t.s(p[300:])
    # Not IETF on the TCP port: ignored
    t.c(b'NOT ROUGHTIME, JUST SOME BYTES')
    t.fin()

    # --- Frames from here on show errors ---
    first_err = len(cap.frames) + 1
    # Response larger than its request (amplification)
    c2s(ietf(msg([(NONC, ph(32)), (TYPE, u32(0))])), 40030)
    s2c(ietf_response(30, path=4), 5319, 40030)
    # Reproducer of "Roughtime: Validate the tag offsets and bound the
    # nesting": two SREP tags, the second tag's offset 0xfffffff0 moved the
    # offset of the first value back to 0, the message recursed into itself
    c2s(struct.pack('<II', 2, 0xfffffff0) + b'SREPSREP' + struct.pack('<I', 0), 40031, 2002)
    # SREP nested 12 deep (the limit is 8)
    m = msg([(MIDP, u64(NOW)), (RADI, u32(1))])
    for _ in range(12):
        m = msg([(SREP, m)])
    c2s(ietf(m), 40032)
    # Same in the Google format
    m = msg([(MIDP, u64(NOW)), (RADI, u32(1))])
    for _ in range(12):
        m = msg([(DELE, m)])
    c2s(m, 40033, 2002)
    # Reproducer of the depth leak: 600 PDUs with message length 0 in one
    # TCP segment, every PDU throws; the dissection depth must not leak
    t = Tcp(cap, 40034, 5319)
    t.handshake()
    t.c((b'ROUGHTIM' + struct.pack('<I', 0)) * 600)
    t.fin()
    # IETF Merkle path of 33 hashes (longest is 32)
    c2s(ietf_request(40), 40035); s2c(ietf_response(40, path=33), 5319, 40035)
    cap.write(os.path.join(out, 'roughtime-coverage.pcap'))
    print('first error frame', first_err)

    # Malformed
    cap = Cap()
    n[0] = 0
    def x(payload, sport=41000, dport=5319, trunc=None):
        n[0] += 1
        f = udp_frame(sport + n[0], dport, payload, ident=n[0])
        cap.add(f[:len(f) - trunc] if trunc else f, len(f))
    def gx(tags): x(msg(tags), dport=2002)
    # Wrong value lengths
    # VER as the last tag with a length that is not a multiple of 4 (the
    # last value runs to the end of the message)
    x(msg([(NONC, ph(64)), (VER, b'\1\2\3\4\5\6\7\0')])[:-2], dport=2002)
    gx([(SIG, ph(8)), (NONC, ph(64))])
    gx([(NONC, ph(64)), (INDX, ph(8))])
    gx([(RADI, ph(8)), (NONC, ph(64))])
    gx([(MIDP, ph(4)), (NONC, ph(64))])
    gx([(MINT, ph(4)), (NONC, ph(64))])
    gx([(MAXT, ph(12)), (NONC, ph(64))])
    gx([(PATH, ph(40)), (NONC, ph(64))])
    x(ietf(msg([(RADI, ph(8)), (NONC, ph(32))])))
    x(ietf(msg([(MIDP, ph(4)), (MINT, ph(4)), (MAXT, ph(12)), (NONC, ph(32))])))
    x(ietf(msg([(PATH, ph(40)), (NONC, ph(32))])))
    x(ietf(msg([(PATH, ph(32 * 40)), (NONC, ph(32))])))
    # Offsets: not increasing, not aligned, past the value block
    m = struct.pack('<III', 3, 16, 8) + b'AAAA' + b'BBBB' + b'CCCC' + bytes(20)
    x(m, dport=2002)
    m = struct.pack('<II', 2, 6) + b'AAAA' + b'BBBB' + bytes(12)
    x(m, dport=2002)
    m = struct.pack('<II', 2, 1000) + b'AAAA' + b'BBBB' + bytes(12)
    x(m, dport=2002)
    # Tag count larger than the message
    x(struct.pack('<I', 15) + bytes(40), dport=2002)
    x(ietf(struct.pack('<I', 0xffffffff) + bytes(40)))
    # IETF message length larger than the data, and zero
    x(b'ROUGHTIM' + struct.pack('<I', 5000) + msg([(NONC, ph(32))]))
    x(b'ROUGHTIM' + struct.pack('<I', 0))
    x(b'ROUGHTIM' + struct.pack('<I', 2))
    # Empty last value: the value block check is four octets too strict
    x(ietf(msg([(NONC, ph(32)), (PATH, b'')])))
    # A response without a request (second pass: shown as request and response)
    n[0] += 1
    cap.add(udp_frame(5319, 41500, ietf_response(6), '192.0.2.2', '192.0.2.1', ident=n[0]))
    # Truncated frames
    x(ietf_response(50), trunc=100)
    x(g_response(1), dport=2002, trunc=30)
    # TCP: PDU whose length field is smaller than the header, split header
    t = Tcp(cap, 41100, 5319)
    t.handshake()
    t.c(b'ROUGHTIM' + struct.pack('<I', 3) + b'abc')
    t.c(b'ROUGHTIM' + struct.pack('<I', 0xfffffff0) + b'abc')
    t.c(ietf_response(51)[:20])
    cap.write(os.path.join(out, 'roughtime-coverage-malformed.pcap'))

main(sys.argv[1])
