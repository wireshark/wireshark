#!/usr/bin/env python3
# Generates test/captures/osc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OSC (Open Sound Control) coverage captures.

Usage: mkosc.py <outdir>

Writes osc-coverage.pcapng (clean, Exported PDU frames for osc.tcp and
osc.udp), osc-coverage-malformed.pcapng (malformed OSC), and
osc-coverage-wire.pcapng (Ethernet frames, reached only with Decode As or
the disabled UDP heuristic; used by runcov.sh only).
Synthetic: nothing comes from a real network.
"""
import struct
import sys
import os

# ---------------------------------------------------------------- pcapng
def _blk(btype, body):
    pad = (-len(body)) % 4
    tl = 12 + len(body) + pad
    return struct.pack('<II', btype, tl) + body + b'\0' * pad + struct.pack('<I', tl)

def pcapng(path, frames):
    """frames: list of (linktype, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    lts = []
    for lt, _ in frames:
        if lt not in lts:
            lts.append(lt)
            out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, p) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32,
                                   ts & 0xffffffff, len(p), len(p)) + p)
    with open(path, 'wb') as f:
        f.write(out)

def exppdu(proto, payload):
    return (struct.pack('>HH', 12, (len(proto) + 3) & ~3) +
            proto.encode().ljust((len(proto) + 3) & ~3, b'\0') +
            struct.pack('>HH', 0, 0) + payload)

def eth_ip(proto, l4, src='10.0.0.1', dst='10.0.0.2'):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    s = 0
    for i in range(0, 20, 2):
        s += (ip[i] << 8) | ip[i + 1]
    s = (s & 0xffff) + (s >> 16)
    s = (~s) & 0xffff
    ip = ip[:10] + struct.pack('>H', s) + ip[12:]
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + l4

def udp(sp, dp, data, **kw):
    return eth_ip(17, struct.pack('>HHHH', sp, dp, 8 + len(data), 0) + data, **kw)

def tcp(sp, dp, seq, data, flags=0x18, **kw):
    return eth_ip(6, struct.pack('>HHIIBBHHH', sp, dp, seq, 1, 5 << 4, flags, 65535, 0, 0) + data, **kw)

# ------------------------------------------------------------------- OSC
def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)

def ostr(s):
    return pad4(s.encode() + b'\0')

def i32(v): return struct.pack('>i', v)
def f32(v): return struct.pack('>f', v)
def i64(v): return struct.pack('>q', v)
def f64(v): return struct.pack('>d', v)
def ttag(sec, frac): return struct.pack('>II', sec, frac)
def blob(b): return i32(len(b)) + pad4(b)

def msg(path, fmt, *args):
    return ostr(path) + ostr(',' + fmt) + b''.join(args)

def bundle(tag, *elems):
    return b'#bundle\0' + tag + b''.join(i32(len(e)) + e for e in elems)

def midi(port, cmd, d1, d2): return bytes((port, cmd, d1, d2))

def frame10(*pdus):
    return b''.join(struct.pack('>I', len(p)) + p for p in pdus)

END, ESC, ESCEND, ESCESC = 0xC0, 0xDB, 0xDC, 0xDD
def slip(p):
    o = bytearray()
    for b in p:
        if b == END: o += bytes((ESC, ESCEND))
        elif b == ESC: o += bytes((ESC, ESCESC))
        else: o.append(b)
    return bytes(o) + bytes((END,))

NOW = ttag(0, 1)
T0 = ttag(0xE0000000, 0x80000000)

# --------------------------------------------------------------- clean
def clean():
    fr = []
    def udpf(p): fr.append((252, exppdu('osc.udp', p)))
    def tcpf(p): fr.append((252, exppdu('osc.tcp', p)))

    # every argument type in one message, over UDP
    udpf(msg('/all', 'ifsbTFNIhdtScrm', i32(-5), f32(1.5), ostr('hello'),
             blob(b'abcde'), i64(-1234567890123), f64(2.25), ttag(0xE0000000, 0),
             ostr('sym'), b'\0\0\0A', bytes((1, 2, 3, 4)), midi(1, 0x90, 60, 100)))
    udpf(msg('/none', ''))
    udpf(msg('/blob0', 'bi', blob(b''), i32(7)))
    udpf(msg('/timetag/now', 't', NOW))
    udpf(msg('/timetag/norm', 't', T0))
    udpf(msg('/str4', 's', ostr('abc')))    # 'abc\0' exactly 4 bytes
    udpf(msg('/str', 'ss', ostr('abcd'), ostr('')))
    # every MIDI status
    for cmd, d1, d2 in ((0x80, 60, 0), (0x91, 61, 127), (0xA2, 62, 30), (0xB3, 7, 99),
                        (0xB3, 200, 99), (0xC4, 5, 0), (0xD5, 40, 0), (0xE6, 0x10, 0x40),
                        (0x05, 1, 2), (0xF0, 1, 2), (0xF2, 3, 4), (0xF8, 0, 0), (0xFF, 0, 0)):
        udpf(msg('/midi', 'm', midi(2, cmd, d1, d2)))
    # note names: a few notes incl. an unnamed data1 value
    udpf(msg('/midi/note', 'mmm', midi(0, 0x90, 0, 1), midi(0, 0x90, 127, 1), midi(0, 0x90, 128 - 1, 1)))
    # control names
    udpf(msg('/midi/cc', 'm' * 24, *[midi(0, 0xB0, c, 1) for c in range(0, 120, 5)]))
    # bundles
    udpf(bundle(NOW, msg('/a', 'i', i32(1))))
    udpf(bundle(T0, msg('/a', 'i', i32(1)), msg('/b', 'f', f32(0.5))))
    udpf(bundle(T0))                                   # empty bundle
    udpf(bundle(NOW, b''))                              # zero size element: size 0
    udpf(bundle(T0, bundle(NOW, msg('/n', 'T')), bundle(T0, bundle(T0, msg('/m', 'N')))))
    # OSC 1.0 framing, over TCP; several PDUs per frame
    tcpf(frame10(msg('/t', 'i', i32(1))))
    tcpf(frame10(msg('/t', 'i', i32(2)), bundle(NOW, msg('/t', 'F')), msg('/t', 'I')))
    # SLIP framing (OSC 1.1)
    tcpf(slip(msg('/slip', 'i', i32(0xC0))))             # data 0xC0 -> ESC ESC_END
    tcpf(slip(msg('/slip', 'i', i32(0xDB))))             # data 0xDB -> ESC ESC_ESC
    tcpf(slip(bundle(NOW, msg('/s', 'N'))))
    tcpf(bytes((END,)))                                  # empty SLIP frame
    tcpf(bytes((END,)) + slip(msg('/a', 'T')) + slip(msg('/b', 'F')))
    # fixed bugs
    # Immediate timetag (uninitialised nstime_t): bundle and message
    m = msg('/a', 't', NOW)
    udpf(bundle(NOW, m))
    udpf(m)
    # depth leak: 6 failing 100-deep nests, then a valid PDU (OSC 1.0 framing)
    e = b'XXXX'
    for _ in range(100):
        e = bundle(ttag(1, 2), e)
    good = bundle(ttag(1, 2), msg('/a', '', ))
    tcpf(frame10(e, e, e, e, e, e, good))
    return fr

# ------------------------------------------------------------ malformed
def malformed():
    fr = []
    def udpf(p): fr.append((252, exppdu('osc.udp', p)))
    def tcpf(p): fr.append((252, exppdu('osc.tcp', p)))
    udpf(b'\x00\x01\x02\x03')                       # neither '#' nor '/'
    udpf(msg('/a b', 'i', i32(1)))                  # space in path
    udpf(msg('/a#', 'i', i32(1)))                   # '#' in path
    udpf(b'/ok\0,z\0\0')                            # bad format char
    udpf(b'x/ok\0,i\0\0' + i32(1))                  # path not starting with '/'
    udpf(msg('/a', 'ii', i32(1)))                   # truncated args
    udpf(msg('/a', 'i', i32(1)) + b'\0\0\0\0')       # trailing bytes (offset != end)
    udpf(msg('/b', 'b', i32(1000) + b'abc'))        # blob longer than packet
    udpf(msg('/b', 'b', i32(-4)))                   # negative blob length
    udpf(msg('/s', 's') + b'abc')                   # unterminated string
    udpf(b'#bundle\0' + ttag(1, 2) + i32(4) + b'XXXX')       # element neither bundle nor msg
    udpf(b'#bundle\0' + ttag(1, 2) + i32(100) + b'/a\0\0,\0\0\0')  # element size too big
    udpf(b'#bundle\0' + ttag(1, 2) + i32(4) + b'/a\0\0' + b'\0\0')   # bad message in bundle
    udpf(b'#bundle\0' + ttag(1, 2) + i32(0x7fffffff) + b'/a\0\0')    # huge size
    udpf(b'#bundle\0' + ttag(1, 2) + i32(12) + b'#bundlX\0' + b'\0\0\0\0')   # nested bad bundle
    udpf(b'#bundle\0' + ttag(1, 2) + b'\0\0')       # short element size
    udpf(b'#bundle\0\0\0')                           # short timetag
    # nested bundle longer than the bundle it is in (offset != end after the loop)
    inner = bundle(ttag(1, 2), msg('/x', ''))
    b1 = b'#bundle\0' + ttag(1, 2) + i32(len(inner)) + inner[:4]
    udpf(i32(0)[:0] + b'#bundle\0' + ttag(1, 2) + i32(len(b1)) + b1 + inner[4:])
    udpf(bundle(ttag(1, 2), bundle(ttag(1, 2), b'XXXX')))  # nested failure
    udpf(bundle(ttag(1, 2), msg('/ok', 'i', i32(1)), b'XXXX'))
    tcpf(struct.pack('>I', 100) + msg('/a', ''))     # PDU longer than data
    tcpf(struct.pack('>I', 0xffffffff) + b'abcd')    # huge PDU length
    tcpf(b'\x00\x00')                                # short length header
    tcpf(bytes((ESC, 0x41, END)))                    # first byte ESC: 1.0 framing
    tcpf(b'/a\0\0,\0\0\0')                           # SLIP, no END: no desegment
    tcpf(b'/a\0\0\xdb\x41\xc0')                      # SLIP, bad escape
    tcpf(b'#bundle\0' + ttag(1, 2) + bytes((END,)))  # SLIP bundle, empty
    tcpf(slip(msg('/a', 'i')))                       # SLIP truncated message
    tcpf(b'/\xdb\xdc\xc0/a\0\0,\0\0\0\xc0')          # SLIP followed by SLIP
    return fr

# ---------------------------------------------------------------- wire
def wire():
    fr = []
    # OSC over TCP (Decode As tcp.port 9000): 1.0 framing split in two segments, and SLIP
    p = frame10(msg('/w', 'is', i32(1), ostr('tcp')), bundle(NOW, msg('/w', 'F')))
    seq = 1000
    fr.append((1, tcp(40000, 9000, seq, p[:10]))); seq += 10
    fr.append((1, tcp(40000, 9000, seq, p[10:]))); seq += len(p) - 10
    q = slip(msg('/slip', 'i', i32(0xC0))) + slip(msg('/slip2', 'N'))
    fr.append((1, tcp(40000, 9000, seq, q[:7]))); seq += 7        # SLIP split: desegment
    fr.append((1, tcp(40000, 9000, seq, q[7:]))); seq += len(q) - 7
    # UDP heuristic (osc_udp enabled): messages and bundles, then follow-up via conversation
    fr.append((1, udp(50000, 7000, msg('/h', 'if', i32(1), f32(2)))))
    fr.append((1, udp(50000, 7000, bundle(T0, msg('/h', 'T')))))
    fr.append((1, udp(50000, 7000, bundle(NOW, msg('/h', 'T')))))
    fr.append((1, udp(50001, 7001, b'\x01\x02\x03')))       # short: heuristic rejects
    fr.append((1, udp(50002, 7002, b'/nofmt\0\0xxxxxxxx')))  # bad format: rejected
    fr.append((1, udp(50003, 7003, b'/pa th\0\0,i\0\0\0\0\0\0')))  # bad path: rejected
    fr.append((1, udp(50005, 7005, b'abcdefgh\0\0\0\0')))        # path without '/'
    fr.append((1, udp(50004, 7004, b'/abcd')))                # exception in heuristic
    return fr

if __name__ == '__main__':
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(d, 'osc-coverage.pcapng'), clean())
    pcapng(os.path.join(d, 'osc-coverage-malformed.pcapng'), malformed())
    pcapng(os.path.join(d, 'osc-coverage-wire.pcapng'), wire())
