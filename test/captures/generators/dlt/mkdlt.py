#!/usr/bin/env python3
# Generates test/captures/dlt_coverage.dlt.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic AUTOSAR DLT coverage captures.

dlt-coverage.dlt          native DLT file (storage header per message), main
dlt-coverage-malformed.dlt  malformed messages (coverage only)
dlt-coverage-net.pcap     DLT over UDP and TCP port 3490 (needs Decode As,
                          the dissector has no default port)
Usage: mkdlt.py <outdir>"""
import os
import struct
import sys

EXT, MSB, WEID, WSID, WTMS = 0x01, 0x02, 0x04, 0x08, 0x10
VER1 = 0x20

BOOL, SINT, UINT, FLOA, STRG, RAWD, VARI, UTF8 = 0x10, 0x20, 0x40, 0x80, 0x200, 0x400, 0x800, 0x8000
LEN = {1: 1, 2: 2, 4: 3, 8: 4, 16: 5}

class Msg:
    """One DLT message; e is '!' (MSB first) or '<'."""
    def __init__(self, be=True):
        self.e = '!' if be else '<'

def storage(ts, ecu=b'ECU1'):
    return b'DLT\x01' + struct.pack('<II', 1700000000 + ts, ts * 1000) + ecu

def dlt(payload, be=True, ecu=b'ECU1', session=None, tmsp=None, ext=None, mcnt=0, version=VER1):
    """ext = (msg_info, nargs, app, ctx) or None."""
    htype = version | (MSB if be else 0)
    body = b''
    if ecu is not None:
        htype |= WEID
        body += ecu
    if session is not None:
        htype |= WSID
        body += struct.pack('!I', session)
    if tmsp is not None:
        htype |= WTMS
        body += struct.pack('!I', tmsp)
    if ext is not None:
        htype |= EXT
        body += struct.pack('!BB4s4s', *ext)
    body += payload
    return struct.pack('!BBH', htype, mcnt & 0xff, 4 + len(body)) + body

# --- verbose arguments ---
def ti(e, t):
    return struct.pack(e + 'I', t)

def vari(e, name, unit):
    n, u = name + b'\0', unit + b'\0'
    return struct.pack(e + 'HH', len(n), len(u)) + n + u

def a_bool(e, v, var=None):
    t = BOOL | LEN[1] | (VARI if var else 0)
    return ti(e, t) + (vari(e, *var) if var else b'') + bytes([v])

def a_int(e, signed, size, v, var=None):
    t = (SINT if signed else UINT) | LEN[size] | (VARI if var else 0)
    fmt = {1: 'b', 2: 'h', 4: 'i', 8: 'q'}[size]
    if not signed:
        fmt = fmt.upper()
    return ti(e, t) + (vari(e, *var) if var else b'') + struct.pack(e + fmt, v)

def a_float(e, size, v, var=None):
    t = FLOA | LEN[size] | (VARI if var else 0)
    return ti(e, t) + (vari(e, *var) if var else b'') + struct.pack(e + ('f' if size == 4 else 'd'), v)

def a_str(e, s, utf8=False, var=None, nul=True):
    t = STRG | (UTF8 if utf8 else 0) | (VARI if var else 0)
    s = s + (b'\0' if nul else b'')
    return ti(e, t) + (vari(e, *var) if var else b'') + struct.pack(e + 'H', len(s)) + s

def a_raw(e, data, var=None):
    t = RAWD | (VARI if var else 0)
    return ti(e, t) + (vari(e, *var) if var else b'') + struct.pack(e + 'H', len(data)) + data

def verbose(args, be=True, mi=0x41, app=b'APP1', ctx=b'CTX1', **kw):
    e = '!' if be else '<'
    payload = b''.join(a(e) for a in args)
    return dlt(payload, be=be, ext=(mi, len(args), app, ctx), **kw)

# --- non-verbose / control ---
REQ, RES = 0x16, 0x26

def ctrl(mi, service, data=b'', be=True, **kw):
    e = '!' if be else '<'
    return dlt(struct.pack(e + 'I', service) + data, be=be, ext=(mi, 0, b'DA1\0', b'DC1\0'), **kw)

def log_info_response(e, status, apps):
    """apps = [(appid, [(ctxid, ll, ts, desc)], appdesc)]"""
    b = struct.pack(e + 'H', len(apps))
    for appid, ctxs, adesc in apps:
        b += appid + struct.pack(e + 'H', len(ctxs))
        for ctxid, ll, ts, cdesc in ctxs:
            b += ctxid + struct.pack('bb', ll, ts)
            if status == 7:
                b += struct.pack(e + 'H', len(cdesc)) + cdesc
        if status == 7:
            b += struct.pack(e + 'H', len(adesc)) + adesc
    return bytes([status]) + b + b'remo'

def main_messages():
    m = []
    A = lambda f, *x, **k: (lambda e: f(e, *x, **k))
    # 1-3: the reproducer of the payload length fix (dlt_storage_payload_len.py)
    m.append(verbose([A(a_str, b'hi')], mcnt=0))
    m.append(verbose([A(a_int, False, 4, 7)], mcnt=1))
    m.append(verbose([A(a_str, b'A' * 40)], mcnt=2))
    # 4: booleans, big endian, with variable info on one
    m.append(verbose([A(a_bool, 1), A(a_bool, 0), A(a_bool, 2), A(a_bool, 1, var=(b'flag', b'on'))], mcnt=3))
    # 5: signed integers of every size, big endian
    m.append(verbose([A(a_int, True, 1, -1), A(a_int, True, 2, -300), A(a_int, True, 4, -70000),
                      A(a_int, True, 8, -5000000000), A(a_int, True, 4, 42, var=(b'speed', b'km/h'))],
                     mi=0x31, mcnt=4))
    # 6: unsigned integers of every size, little endian
    m.append(verbose([A(a_int, False, 1, 255), A(a_int, False, 2, 65535), A(a_int, False, 4, 4000000000),
                      A(a_int, False, 8, 10000000000), A(a_int, False, 2, 12, var=(b'count', b''))],
                     be=False, mi=0x51, mcnt=5))
    # 7: floats, with and without variable info
    m.append(verbose([A(a_float, 4, 1.5), A(a_float, 8, -2.25), A(a_float, 4, 0.5, var=(b'temp', b'C'))],
                     mi=0x61, mcnt=6))
    # 8: strings: ASCII with control characters, UTF-8, with variable info
    m.append(verbose([A(a_str, b'line1\tline2\x01end'), A(a_str, 'grüße'.encode(), utf8=True),
                      A(a_str, b'named', var=(b'label', b''))],
                     be=False, mi=0x21, mcnt=7))
    # 9: raw data with and without variable info
    m.append(verbose([A(a_raw, b'\x01\x02\x03\xff'), A(a_raw, b'\xaa\xbb', var=(b'blob', b'B'))],
                     mi=0x11, mcnt=8))
    # 10: verbose trace message with session ID and timestamp
    m.append(verbose([A(a_int, False, 4, 0xdeadbeef)], mi=0x13, session=1234, tmsp=123456, mcnt=9))
    # 11: verbose network message without ECU ID
    m.append(verbose([A(a_raw, b'\x7f' * 8)], mi=0x25, ecu=None, mcnt=10))
    # 12: verbose with zero arguments
    m.append(verbose([], mcnt=11))
    # 13: fewer arguments than announced: the loop stops at the end
    m.append(dlt(a_int('!', False, 1, 1), ext=(0x41, 1, b'APP1', b'CTX1'), mcnt=12))
    # control requests (big endian)
    m.append(ctrl(REQ, 0x01, b'APP1CTX1' + b'\x04' + b'\0' * 4, mcnt=13))       # 14 set log level
    m.append(ctrl(REQ, 0x02, b'APP1CTX1' + b'\x01' + b'\0' * 4, mcnt=14))       # 15 set trace status
    m.append(ctrl(REQ, 0x03, b'\x07' + b'APP1CTX1' + b'\0' * 4, mcnt=15))       # 16 get log info
    m.append(ctrl(REQ, 0x0a, b'\x01', mcnt=16))                                 # 17 set message filtering
    m.append(ctrl(REQ, 0x11, b'\x05' + b'\0' * 4, mcnt=17))                     # 18 set default log level
    m.append(ctrl(REQ, 0x12, b'\x00' + b'\0' * 4, mcnt=18))                     # 19 set default trace status
    m.append(ctrl(REQ, 0x13, b'\0' * 4, mcnt=19))                               # 20 get sw version (no body decoder)
    m.append(ctrl(REQ, 0x04, mcnt=20))                                          # 21 no payload after the ID
    # control responses (little endian)
    for i, sid in enumerate((0x01, 0x02, 0x05, 0x06, 0x09, 0x0a, 0x0b, 0x11, 0x12, 0x20)):
        m.append(ctrl(RES, sid, bytes([i % 3]), be=False, mcnt=21 + i))         # 22-31 status
    e = '<'
    m.append(ctrl(RES, 0x03, log_info_response(e, 6, [
        (b'APP1', [(b'CTX1', 4, 1, b''), (b'CTX2', -1, -1, b'')], b''),
        (b'APP2', [], b'')]), be=False, mcnt=31))                             # 32 log info
    m.append(ctrl(RES, 0x03, log_info_response('!', 7, [
        (b'APP1', [(b'CTX1', 6, 0, b'first context')], b'application one')]), mcnt=32))  # 33 log info + text
    m.append(ctrl(RES, 0x04, b'\x00\x05', mcnt=33))                             # 34 default log level
    m.append(ctrl(RES, 0x13, b'\x00' + struct.pack('!I', 9) + b'DLT 2.18\0', mcnt=34))  # 35 sw version
    m.append(ctrl(RES, 0xf04, b'\x00', mcnt=35))                                # 36 marker (no decoder)
    m.append(ctrl(RES, 0x99, b'\x00\x01', mcnt=36))                             # 37 unknown service
    # non-verbose log messages: handed to the heuristic list, then data
    m.append(dlt(struct.pack('!I', 0x1001) + b'\x10\x20\x30', ext=(0x40, 0, b'NV1\0', b'NV2\0'), mcnt=37))  # 38
    m.append(dlt(struct.pack('<I', 0x1002) + b'\x01\x02', be=False, ecu=None, mcnt=38))  # 39 no ext header
    m.append(dlt(struct.pack('!I', 0x1003), version=0x40, tmsp=1, session=2, mcnt=39))   # 40 version 2, no data
    return m

def malformed_messages():
    m = []
    A = lambda f, *x, **k: (lambda e: f(e, *x, **k))
    e = '!'
    # 1-4: the reproducer dlt_misc.py (truncated second argument, sw
    # version length 0xfffffffc, short log info, 60000 octets raw data)
    m.append(dlt(struct.pack('!IB', 0x41, 5) + b'\0\0\0', ext=(0x41, 20, b'APP1', b'CTX1'), mcnt=0))
    m.append(dlt(struct.pack('!I', 0x13) + b'\0' + struct.pack('!I', 0xfffffffc) + b'v1.0', ext=(0x26, 0, b'APP1', b'CTX1'), mcnt=1))
    m.append(dlt(struct.pack('!I', 0x03) + b'\x07\0\0', ext=(0x26, 0, b'APP1', b'CTX1'), mcnt=2))
    raw = bytes(range(256)) * 234 + bytes(96)
    m.append(dlt(struct.pack('!IH', 0x400, len(raw)) + raw, ext=(0x41, 1, b'APP1', b'CTX1'), mcnt=3))
    # 5: unsupported argument types (array, fixed point, struct, trace info)
    m.append(dlt(ti(e, 0x100) + ti(e, 0x1043) + ti(e, 0x4000) + ti(e, 0x2000), ext=(0x41, 4, b'APP1', b'CTX1')))
    # 6: 128 bit integers and a 16 bit float, unsupported lengths
    m.append(verbose([lambda e: ti(e, SINT | 5) + bytes(16)]))
    m.append(verbose([lambda e: ti(e, UINT | 5) + bytes(16)]))
    m.append(verbose([lambda e: ti(e, FLOA | 2) + bytes(2)]))
    # 9: bool with length 2
    m.append(verbose([lambda e: ti(e, BOOL | 2) + b'\0\1']))
    # 10: string with an unsupported coding, then a normal one
    m.append(verbose([lambda e: ti(e, STRG | 0x10000) + struct.pack('!H', 3) + b'ab\0', A(a_str, b'after')]))
    # 11: empty string
    m.append(verbose([lambda e: ti(e, STRG) + struct.pack('!H', 0)]))
    # 12-15: arguments cut short: value, variable info, string length, raw length
    m.append(verbose([lambda e: ti(e, UINT | 3) + b'\0\0']))
    m.append(verbose([lambda e: ti(e, UINT | VARI | 1) + struct.pack('!HH', 1, 1) + b'ab']))
    m.append(verbose([lambda e: ti(e, SINT | VARI | 1) + struct.pack('!HH', 1, 1) + b'ab']))
    m.append(verbose([lambda e: ti(e, FLOA | VARI | 3) + struct.pack('!HH', 1, 1) + b'ab']))
    m.append(verbose([lambda e: ti(e, BOOL | VARI | 1) + struct.pack('!HH', 1, 1) + b'ab']))
    m.append(verbose([lambda e: ti(e, STRG) + b'\0']))
    m.append(verbose([lambda e: ti(e, STRG) + struct.pack('!H', 9) + b'ab']))
    m.append(verbose([lambda e: ti(e, RAWD) + b'\0']))
    m.append(verbose([lambda e: ti(e, RAWD) + struct.pack('!H', 9) + b'ab']))
    # 22: non-verbose trace and network messages: unsupported
    m.append(dlt(struct.pack('!I', 1) + b'x', ext=(0x12, 0, b'APP1', b'CTX1')))
    m.append(dlt(struct.pack('!I', 1) + b'x', ext=(0x36, 0, b'APP1', b'CTX1')))
    # 24: header only, length 4, and a message shorter than its header
    m.append(struct.pack('!BBH', VER1, 0, 4))
    m.append(struct.pack('!BBH', VER1 | WEID | EXT, 0, 8) + b'ECU1')
    # 26: control request cut short
    m.append(ctrl(REQ, 0x01, b'APP1'))
    # 27: string without a terminating NUL
    m.append(verbose([A(a_str, b'nonul', nul=False)]))
    # 28: software version longer than the message
    m.append(ctrl(RES, 0x13, b'\x00' + struct.pack('!I', 50) + b'v1.0'))
    # 29 (last): a message length of 2, shorter than the DLT header; the
    # two octets after it end the file with a bad storage header
    m.append(struct.pack('!BBH', VER1, 0, 2))
    return m

def net_frames():
    pass
    from pcaplib import udp, Tcp
    f = []
    A = lambda fn, *x, **k: (lambda e: fn(e, *x, **k))
    one = verbose([A(a_str, b'over udp')])
    two = verbose([A(a_int, False, 2, 513)], be=False)
    f.append(udp(40000, 3490, one))
    f.append(udp(40000, 3490, one + two))                 # two messages in one datagram
    t = Tcp(40001, 3490)
    f.append(t.c2s(one + two))
    big = verbose([A(a_raw, bytes(range(200)))])
    f.append(t.c2s(big[:30]))
    f.append(t.c2s(big[30:]))
    f.append(udp(40000, 3490, b'\x35\x00'))               # shorter than a header
    return f

def write_dlt(path, msgs, ecu=b'ECU1'):
    with open(path, 'wb') as fp:
        for i, msg in enumerate(msgs):
            fp.write(storage(i, ecu) + msg)

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_dlt(os.path.join(out, 'dlt-coverage.dlt'), main_messages())
    write_dlt(os.path.join(out, 'dlt-coverage-malformed.dlt'), malformed_messages())
    from pcaplib import write_pcap
    write_pcap(os.path.join(out, 'dlt-coverage-net.pcap'), net_frames())
