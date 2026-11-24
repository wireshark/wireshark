#!/usr/bin/env python3
# Generates test/captures/otp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OTP (ANSI E1.59 Object Transform Protocol) coverage captures.

Usage: mkotp.py <outdir>

Writes otp-coverage.pcapng (clean: UDP frames recognised by the OTP
heuristic, which is enabled by default), otp-coverage-malformed.pcapng
(unknown vectors, length mismatches, truncation and the like) and
otp-coverage-wire.pcapng (not OTP on a Decode As port; runcov.sh only).
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
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += _blk(1, struct.pack('<HHI', 1, 0, 262144))
    for i, p in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff,
                                   len(p), len(p)) + p)
    with open(path, 'wb') as f:
        f.write(out)

def udp_frame(data, sport=5568, dport=5568, src=(10, 0, 0, 1), dst=(239, 0, 0, 1)):
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    s = sum((ip[i] << 8) | ip[i + 1] for i in range(0, 20, 2))
    s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', (~s) & 0xffff) + ip[12:]
    return b'\x01\x00\x5e\x00\x00\x01\x02\0\0\0\0\x01\x08\x00' + ip + u

# ------------------------------------------------------------------- OTP
IDENT = b'OTP-E1.59\0\0\0'
CID = bytes(range(0x10, 0x20))

def pdu(vector, body, delta=0):
    return struct.pack('>HH', vector, len(body) + delta) + body

def name32(s):
    return s.encode().ljust(32, b'\0')

def message(vector, layer, folio=1, name='Console', page=0, last=0, opts=0, flen=0):
    body = (struct.pack('>BB', opts, flen) + CID + struct.pack('>IHH', folio, page, last) +
            struct.pack('>BI', 0, 0) + name32(name) + layer)
    return IDENT + pdu(vector, body)

def module(manf, number, data, delta=0):
    return pdu(manf, struct.pack('>H', number) + data, delta)

def i32(*v): return b''.join(struct.pack('>i', x) for x in v)

def pos_mod(mm, manf=0):
    return module(manf, 1, bytes((0x80 if mm else 0,)) + i32(1000, -2000, 3000))
def pva_mod(manf=0): return module(manf, 2, i32(1, 2, 3, -4, -5, -6))
def rot_mod(manf=0): return module(manf, 3, i32(90000000, 180000000, 270000000))
def rva_mod(manf=0): return module(manf, 4, i32(10, 20, 30, 40, 50, 60))
def scale_mod(manf=0): return module(manf, 5, i32(1000000, 2000000, 500000))
def ref_mod(manf=0): return module(manf, 6, struct.pack('>BHI', 3, 7, 99))

def point(group, number, modules, priority=100, vector=1, ts=1700000000123456, opts=0, delta=0):
    return pdu(vector, struct.pack('>BHIQBI', priority, group, number, ts, opts, 0) + b''.join(modules), delta)

def transform(system, points, vector=1, ts=1700000000654321, opts=0x80):
    return pdu(vector, struct.pack('>BQBI', system, ts, opts, 0) + b''.join(points))

def advert(vector, sub):
    return pdu(vector, struct.pack('>I', 0) + sub)

def adv_modules(ids, vector=1, extra=b''):
    return pdu(vector, struct.pack('>I', 0) + b''.join(struct.pack('>HH', m, n) for m, n in ids) + extra)

def adv_names(entries, response=True, vector=1, extra=b''):
    body = struct.pack('>BI', 0x80 if response else 0, 0)
    for s, g, n, name in entries:
        body += struct.pack('>BHI', s, g, n) + name32(name)
    return pdu(vector, body + extra)

def adv_systems(systems, response=True, vector=1):
    return pdu(vector, struct.pack('>BI', 0x80 if response else 0, 0) + bytes(systems))

ALL = lambda manf=0: [pos_mod(False, manf), pos_mod(True, manf), pva_mod(manf), rot_mod(manf),
                      rva_mod(manf), scale_mod(manf), ref_mod(manf)]

def clean():
    f = []
    def add(m, **kw): f.append(udp_frame(m, **kw))
    # transform: every ESTA module, several points in one system
    add(message(1, transform(1, [point(1, 1, ALL()), point(1, 2, [pos_mod(True)], priority=0),
                                 point(2, 70000, [rot_mod(), scale_mod()], priority=200)]),
                folio=1))
    add(message(1, transform(255, [point(65535, 0xffffffff, [pva_mod(), rva_mod()])]), folio=2,
                name='Tracker', page=1, last=3, opts=0x80, flen=0))
    add(message(1, transform(2, []), folio=3))                  # no points
    add(message(1, transform(3, [point(1, 5, [])]), folio=4))    # a point without modules
    # Chamsys manufacturer code with ESTA module numbers (note only)
    add(message(1, transform(1, [point(1, 9, ALL(0x050A))]), folio=5, name='ChamSys MagicQ'))
    # unknown manufacturer: skipped with a note
    add(message(1, transform(1, [point(1, 10, [module(0x1234, 1, b'abcdef'), pos_mod(False)])]),
                folio=6))
    # advertisements
    add(message(2, advert(1, adv_modules([(0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6)])), folio=7))
    add(message(2, advert(1, adv_modules([(0x050A, 1), (0x1234, 55), (0, 153), (0x050A, 9)])), folio=8))
    add(message(2, advert(1, adv_modules([])), folio=9))
    add(message(2, advert(2, adv_names([], response=False)), folio=10))
    add(message(2, advert(2, adv_names([(1, 1, 1, 'Camera 1'), (1, 1, 2, 'Camera 2'),
                                        (2, 3, 4, 'Light éè')])), folio=11))
    add(message(2, advert(3, adv_systems([], response=False)), folio=12))
    add(message(2, advert(3, adv_systems([1, 2, 3, 250])), folio=13))
    # other source and destination ports (the heuristic finds them)
    add(message(1, transform(1, [point(1, 1, [pos_mod(False)])]), folio=14), sport=40000, dport=40001,
        dst=(10, 0, 0, 2))
    add(message(1, transform(1, [point(1, 1, [pos_mod(False)])]), folio=15), sport=40000, dport=40001,
        dst=(10, 0, 0, 2))
    return f

def malformed():
    f = []
    def add(m, **kw): f.append(udp_frame(m, **kw))
    t = transform(1, [point(1, 1, [pos_mod(False)])])
    # unknown message vector
    add(message(0x77, t))
    # unknown transform / point / module vectors
    add(message(1, transform(1, [point(1, 1, [pos_mod(False)])], vector=9)))
    add(message(1, transform(1, [point(1, 1, [pos_mod(False)], vector=9)])))
    # unknown ESTA module: body skipped (the fix); module followed by a good one
    add(message(1, transform(1, [point(1, 1, [module(0, 153, b'\1\2\3\4'), pos_mod(True)])])))
    add(message(1, transform(1, [point(1, 1, [module(0, 7, b''), module(0, 0x8001, b'xx')])])))
    # module body longer / shorter than its type needs
    add(message(1, transform(1, [point(1, 1, [module(0, 3, i32(1, 2, 3) + b'\0\0\0\0'), pos_mod(False)])])))
    add(message(1, transform(1, [point(1, 1, [module(0, 5, i32(1, 2, 3)[:8] + b'\0\0\0\0')])])))
    add(message(1, transform(1, [point(1, 1, [module(0x050A, 7, b'zz')])])))   # Chamsys, unknown number
    # advertisements with unknown vectors
    add(message(0x2, advert(9, b'\0\0')))
    add(message(2, advert(1, adv_modules([(0, 1)], vector=9))))
    add(message(2, advert(2, adv_names([(1, 1, 1, 'x')], vector=9))))
    add(message(2, advert(3, adv_systems([1], vector=9))))
    # length mismatches
    m = bytearray(message(1, transform(1, [point(1, 1, [pos_mod(False)])])))
    m[14:16] = struct.pack('>H', len(m) - 16 + 10)          # message longer than data
    add(bytes(m))
    m = bytearray(message(1, transform(1, [point(1, 1, [pos_mod(False)])])))
    m[14:16] = struct.pack('>H', len(m) - 16 - 4)           # message shorter than layers
    add(bytes(m))
    add(message(1, transform(1, [point(1, 1, [pos_mod(False)]) + b'\0\0'])))      # trailing bytes
    add(message(1, transform(1, [point(1, 1, [pos_mod(False)])]) + b'\0\0\0'))
    add(message(2, advert(1, adv_modules([(0, 1)]) + b'\0\0')))
    add(message(2, advert(1, adv_modules([(0, 1)]) [:-1])))
    add(message(2, advert(2, adv_names([(1, 1, 1, 'x')])[:-3])))
    add(message(2, advert(3, adv_systems([1, 2]) + b'\1')))
    # truncated
    full = message(1, transform(1, [point(1, 1, ALL())]))
    for cut in (13, 15, 20, 50, 80, 100, 120, 150, 200):
        add(full[:cut])
    # inner layers that end beyond the layer they are in (more data follows the
    # message, so reading on works): the length-mismatch warning at every level
    tail = b'\0' * 64
    add(message(1, transform(1, [point(1, 1, [module(0, 1, b'\0' + i32(1, 2, 3), delta=4)])])) + tail)
    add(message(1, transform(1, [point(1, 1, [pos_mod(False)], delta=4)])) + tail)
    add(message(2, advert(1, adv_modules([(0, 1)], extra=b'\0\0'))) + tail)             # 2 spare bytes
    add(message(2, advert(2, adv_names([(1, 1, 1, 'x')], extra=b'\0' * 10))) + tail)
    add(message(2, advert(1, adv_modules([(0, 1), (0, 2)]), )[:-4] + b'') + tail)
    m = bytearray(message(2, advert(1, adv_modules([(0, 1), (0, 2)]))))
    m[16 + 63 + 2:16 + 63 + 4] = struct.pack('>H', 4 + 4)    # advertisement shorter than its sub-layer
    add(bytes(m) + tail)
    # heuristic: too short / bad identifier / right size
    add(IDENT[:11])
    add(b'OTP-E1.59\0\0\1' + b'\0' * 80)
    add(b'')
    return f

def wire():
    f = []
    # not OTP on a port where OTP is Decode As: bad identifier, too short
    f.append(udp_frame(b'OTP-E1.58\0\0\0' + b'\0' * 70, sport=9999, dport=9999))
    f.append(udp_frame(b'OTP-E1', sport=9999, dport=9999))
    f.append(udp_frame(message(1, transform(1, [point(1, 1, [pos_mod(False)])])), sport=9999, dport=9999))
    f.append(udp_frame(message(1, transform(1, [point(1, 1, [pos_mod(False)])])), sport=9999, dport=9999))
    return f

if __name__ == '__main__':
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(d, 'otp-coverage.pcapng'), clean())
    pcapng(os.path.join(d, 'otp-coverage-malformed.pcapng'), malformed())
    pcapng(os.path.join(d, 'otp-coverage-wire.pcapng'), wire())
