#!/usr/bin/env python3
# Generates test/captures/rtps_virtual_transport_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the synthetic RTPS virtual transport (RTPS-VT) coverage capture:
# RTI Network Capture Utility style records as Exported PDUs naming "rtpsvt"
# (nothing from a real network; addresses 192.0.2.0/24, 2001:db8::/32).
# Usage: mkrtps-virtual-transport.py <outdir>
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
PREFIX = bytes.fromhex('0a0b0c0d0e0f101112131415')


def pcap_ex(path, frames):
    """Classic pcap, link type 252 (Exported PDU)."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def exp(payload, name=b'rtpsvt'):
    pad = (-len(name)) % 4
    return struct.pack('>HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


def sm(sid, flags, body, le=True):
    flags = (flags | 1) if le else (flags & ~1)
    return struct.pack('<BBH' if le else '>BBH', sid, flags, len(body)) + body


def rtps(*sms, ver=(2, 3), vendor=0x0101):
    return b'RTPS' + bytes(ver) + struct.pack('>H', vendor) + PREFIX + b''.join(sms)


def info_ts():
    return sm(0x09, 0, struct.pack('<iI', 1700000000, 0))


def heartbeat(w=0x00000103, count=1):
    return sm(0x07, 0, struct.pack('>II', 0x00000104, w) + struct.pack('<iIiII', 0, 1, 0, 5, count))


def data(w, seq, payload=b'', flags=0x04):
    body = struct.pack('<HH', 0, 16) + struct.pack('>II', 0x00000107, w) + struct.pack('<iI', 0, seq) + payload
    return sm(0x15, flags, body)


def p(pid, val=b''):
    return struct.pack('>HH', pid, len(val)) + val


def v4(a):
    return b'\0' * 12 + bytes(int(x) for x in a.split('.'))


NOFRAMES = b'\0' * 8        # frame0 and frame1 placeholders of the RTPS-PROC layer


def vt(params, main, frame_tail=NOFRAMES, kind=1, version=(1, 0)):
    """params: the 9 transport parameters (already encoded) in the order the dissector reads them."""
    out = bytes(version) + bytes([kind]) + b''.join(params)
    out += p(0x00c0, main) + frame_tail
    return exp(out)


EMPTY = lambda n=0x00ff: struct.pack('>HH', n, 0)


def transport(cls=1, guid=PREFIX, sn=5, src=None, sport=7410, dst=None, rport=7411, dport=7411, direction=0):
    src = src if src is not None else v4('192.0.2.1')
    dst = dst if dst is not None else v4('192.0.2.2')
    return [p(1, struct.pack('>i', cls)), p(2, guid), p(3, struct.pack('>Q', sn)), p(4, src), p(5, struct.pack('>I', sport)),
            p(6, dst), p(7, struct.pack('>I', rport)), p(8, struct.pack('>I', dport)), p(9, bytes([direction]))]


frames = []
marks = []


def add(fr):
    frames.append(fr)


def mark(name, s):
    marks.append((name, s + 1, len(frames)))


s = len(frames)
m = rtps(info_ts(), heartbeat())
# every transport class
for cls in (0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 0x01000000, 0x01000001, 77):
    add(vt(transport(cls=cls, sn=cls & 0xffff), m))
mark('Transport classes (known and unknown)', s)
s = len(frames)
v6 = bytes.fromhex('20010db8000000000000000000000001')
shm = b'shmem_prefix' + struct.pack('>I', 4242)
add(vt(transport(src=v6, dst=v6), m))
add(vt(transport(src=shm, dst=shm, cls=0x01000000), m))
add(vt(transport(src=shm, dst=v4('192.0.2.9')), m))
add(vt(transport(src=v4('192.0.2.9'), dst=v6), m))
add(vt(transport(direction=1), m))
add(vt(transport(direction=0), m))
mark('Source and destination: IPv4, IPv6, shared memory process IDs; direction', s)
s = len(frames)
# missing parameters (length 0), unknown parameter ids, long guid, different parameter order
t = transport()
for i in range(9):
    tt = list(t)
    tt[i] = EMPTY(i + 1)
    add(vt(tt, m))
tt = list(t)
tt[0] = p(0x0123, b'unknown parameter')
tt[4] = p(0x00fe, b'abcd')
add(vt(tt, m))
tt = list(t)
tt[1] = p(2, bytes(range(16)))
add(vt(tt, m))
tt[1] = p(2, bytes(range(5)))
add(vt(tt, m))
mark('Missing and unknown transport parameters, GUID lengths', s)
s = len(frames)
# parameters between the transport block and the main frame; a loss record; other content kinds
extra = p(0x0123, b'x' * 8) + p(0x0124, b'')
add(exp(bytes((1, 0, 1)) + b''.join(transport()) + extra + p(0x00c0, m) + NOFRAMES))
add(exp(bytes((1, 0, 2)) + p(1, struct.pack('>QQ', 7, 12))))
add(exp(bytes((1, 0, 2)) + p(5, struct.pack('>QQ', 7, 12))))
add(exp(bytes((1, 0, 3)) + b'\0' * 16))
add(exp(bytes((2, 1, 1)) + b''.join(transport()) + p(0x00c0, m) + NOFRAMES))
add(vt(transport(), b''))          # a main frame of length 0
mark('Extra parameters, loss info, other content kinds, other version, empty main frame', s)
s = len(frames)
# the main frame as the RTPS dissector sees it: small messages of every kind
for sub in (info_ts(), heartbeat(), data(0x00000102, 7, struct.pack('>HH', 1, 0) + b'abcd'),
            sm(0x06, 0, struct.pack('>II', 0x00000104, 0x00000103) + struct.pack('<iII', 0, 3, 0) + struct.pack('<I', 2)),
            sm(0x08, 0, struct.pack('>II', 0x00000104, 0x00000103) + struct.pack('<iI', 0, 3) + struct.pack('<iII', 0, 5, 0))):
    add(vt(transport(sn=len(frames)), rtps(sub)))
mark('RTPS messages in the main frame', s)

s = len(frames)
# fix: reproducers of the fixes of RTPS-VT: an unknown parameter id with a non-zero length
# (mis-parsed the rest of the parameters)
unk = list(transport())
unk[4] = p(0x00aa, b'\x01\x02\x03\x04')
add(vt(unk, m))
mark('Unknown parameter with a length (RTPS-VT fix)', s)

os.makedirs(OUT, exist_ok=True)
pcap_ex(os.path.join(OUT, 'rtps-virtual-transport-coverage.pcap'), frames)
if '-v' in sys.argv:
    for n, a, b in marks:
        print('%4d-%4d %s' % (a, b, n))
print(len(frames), 'frames')
