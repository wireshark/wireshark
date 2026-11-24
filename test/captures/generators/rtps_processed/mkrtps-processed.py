#!/usr/bin/env python3
# Generates test/captures/rtps_processed_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the synthetic RTPS processed (RTPS-PROC) coverage capture: Exported
# PDUs naming "rtpsvt" whose main frame is followed by the optional frame0 and
# frame1 (RTI Network Capture Utility layout). The protected submessages carry
# made-up bytes: nothing is encrypted and no key is involved; only the framing
# (SEC_PREFIX, SEC_BODY, SEC_POSTFIX) and the decoded submessages are used.
# Nothing comes from a real network (addresses 192.0.2.0/24).
# Usage: mkrtps-processed.py <outdir> [-v]
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
PREFIX = bytes.fromhex('0a0b0c0d0e0f101112131415')


def pcap_ex(path, frames):
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


def gap(w=0x00000103):
    return sm(0x08, 0, struct.pack('>II', 0x00000104, w) + struct.pack('<iI', 0, 3) + struct.pack('<iII', 0, 5, 0))


def sec_prefix():
    return sm(0x31, 0, b'\x00\x00\x01\x01\x00\x00\x00\x02' + b'\x00\x00\x00\x07' + b'\xaa' * 8)


def sec_body(n=16):
    return sm(0x30, 0, struct.pack('>I', n) + b'\x5a' * n)


def sec_postfix():
    return sm(0x32, 0, b'\x22' * 16)


def protected():
    """What the main frame carries for one protected submessage."""
    return sec_prefix() + sec_body() + sec_postfix()


def p(pid, val=b''):
    return struct.pack('>HH', pid, len(val)) + val


def v4(a):
    return b'\0' * 12 + bytes(int(x) for x in a.split('.'))


def vt(main, frame0=None, frame1=None, direction=1, sn=1):
    t = [p(1, struct.pack('>i', 1)), p(2, PREFIX), p(3, struct.pack('>Q', sn)), p(4, v4('192.0.2.1')),
         p(5, struct.pack('>I', 7410)), p(6, v4('192.0.2.2')), p(7, struct.pack('>I', 7411)),
         p(8, struct.pack('>I', 7411)), p(9, bytes([direction]))]
    out = bytes((1, 0, 1)) + b''.join(t) + p(0x00c0, main)
    out += p(0x00c1, frame0) if frame0 is not None else struct.pack('>HH', 0, 0)
    out += p(0x00c2, frame1) if frame1 is not None else struct.pack('>HH', 0, 0)
    return exp(out)


frames = []
marks = []


def add(fr):
    frames.append(fr)


def mark(name, s):
    marks.append((name, s + 1, len(frames)))


s = len(frames)
# plain frames: only the main frame, with and without placeholders
add(vt(rtps(info_ts(), heartbeat()), direction=1))
add(vt(rtps(info_ts(), heartbeat()), direction=0))
mark('Main frame only (inbound, outbound)', s)
s = len(frames)
# inbound: protected submessages in the main frame, decoded submessages in frame1
add(vt(rtps(info_ts(), protected()), frame0=rtps(info_ts(), data(0x00000102, 1)), frame1=data(0x00000102, 1) + heartbeat(), sn=3))
add(vt(rtps(protected(), protected(), info_ts(), protected()), frame0=rtps(data(0x00000102, 2), heartbeat(), gap()),
       frame1=data(0x00000102, 2) + heartbeat() + gap(), sn=4))
add(vt(rtps(protected(), protected()), frame1=data(0x00000102, 5), sn=5))                        # fewer decoded than protected
add(vt(rtps(info_ts()), frame1=data(0x00000102, 6) + heartbeat() + gap(), sn=6))                # no protected submessage
add(vt(rtps(protected(), info_ts()), frame0=rtps(data(0x00000102, 7)), sn=7))                   # frame0 only
add(vt(rtps(protected()), frame1=data(0x00000102, 8, struct.pack('>HH', 1, 0) + b'abcd'), sn=8))
mark('Inbound: protected submessages replaced by the decoded ones (frame0, frame1)', s)
s = len(frames)
# outbound: frame1 is an RTPS message before protection
add(vt(rtps(protected()), frame1=rtps(data(0x00000102, 9), heartbeat()), direction=0, sn=9))
add(vt(rtps(protected()), frame0=rtps(data(0x00000102, 10)), frame1=rtps(data(0x00000102, 10), heartbeat()), direction=0, sn=10))
add(vt(rtps(info_ts(), heartbeat()), frame0=rtps(info_ts(), heartbeat()), direction=0, sn=11))
mark('Outbound: the message before protection (frame0, frame1)', s)
s = len(frames)
# other RTPS versions and vendors in the main frame
add(vt(rtps(protected(), ver=(2, 1), vendor=0x0102), frame1=data(0x00000102, 12), sn=12))
add(vt(rtps(protected(), ver=(2, 5), vendor=0x010f), frame1=heartbeat(), sn=13))
mark('Other protocol versions and vendors', s)

os.makedirs(OUT, exist_ok=True)
pcap_ex(os.path.join(OUT, 'rtps-processed-coverage.pcap'), frames)
if '-v' in sys.argv:
    for n, a, b in marks:
        print('%4d-%4d %s' % (a, b, n))
print(len(frames), 'frames')
