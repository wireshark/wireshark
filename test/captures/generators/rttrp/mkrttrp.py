#!/usr/bin/env python3
# Generates test/captures/rttrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RTTrP coverage captures. Usage: mkrttrp.py <outdir>"""
import sys
import os
import struct
from pcaplib import Pcap, udp_frame

PORT = 24002
MOTION_BE, MOTION_LE, LIGHT_BE, LIGHT_LE = b'C4', b'4C', b'D4', b'4D'

class Fmt:
    """Integer byte order from the integer signature, float byte order from the float signature."""
    def __init__(self, int_le, float_sig):
        self.il = int_le
        self.fs = float_sig
        self.fl = float_sig in (MOTION_LE, LIGHT_LE)
        self.e = '<' if int_le else '>'
        self.fe = '<' if self.fl else '>'
    def sig(self):
        return (b'TA' if self.il else b'AT') + self.fs
    def i(self, fmt, *v):
        return struct.pack(self.e + fmt, *v)
    def d(self, *v):
        return b''.join(struct.pack(self.fe + 'd', x) for x in v)
    def f(self, *v):
        return b''.join(struct.pack(self.fe + 'f', x) for x in v)

def module(F, typ, body, size=None):
    """type, size (includes the 3 octets of type and size), body"""
    return struct.pack('B', typ) + F.i('H', len(body) + 3 if size is None else size) + body

def packet(F, modules, pid=1, fmt=0, ctx=0x01020304, count=None, version=0x0003, size=None):
    n = len(modules) if count is None else count
    rest = b''.join(modules)
    total = 18 + len(rest)
    return (F.sig() + struct.pack('>H', version) + F.i('I', pid) + bytes([fmt]) +
            F.i('H', total if size is None else size) + F.i('I', ctx) + bytes([n]) + rest)

# ---- motion modules
def centroid(F, lat=5, x=1.5, y=-2.25, z=3.0, typ=0x02):
    return module(F, typ, F.i('H', lat) + F.d(x, y, z))
def point(F, idx=3, lat=7):
    return module(F, 0x06, F.i('H', lat) + F.d(10.0, 20.0, 30.0) + bytes([idx]))
def quat(F, lat=9):
    return module(F, 0x03, F.i('H', lat) + F.d(0.0, 0.5, 0.25, 1.0))
def euler(F, order=0x0123, lat=11):
    return module(F, 0x04, F.i('H', lat) + F.i('H', order) + F.d(10.0, 20.0, 30.0))
def accvel(F, point_idx=None):
    body = F.d(1.0, 2.0, 3.0) + F.f(0.5, 0.25, 0.125, 4.0, 5.0, 6.0)
    if point_idx is None:
        return module(F, 0x20, body)
    return module(F, 0x21, body + bytes([point_idx]))
def zones_old(F, names):
    s = names.encode()
    return module(F, 0x22, F.i('H', len(s)) + s)
def zones_new(F, names):
    body = bytes([len(names)]) + b''.join(bytes([len(n) + 2, len(n)]) + n.encode() for n in names)
    return module(F, 0x22, body)

def trackable(F, name, subs, ts=None, count=None):
    n = name.encode()
    body = bytes([len(n)]) + n
    if ts is not None:
        body += F.i('I', ts)
    body += bytes([len(subs) if count is None else count]) + b''.join(subs)
    return module(F, 0x51 if ts is not None else 0x01, body)

# ---- lighting modules
def channel(F, off, xfade, val):
    return F.i('HH', off, xfade) + bytes([val])
def spot(F, sid, off, chans):
    return module(F, 0x0a, F.i('HHH', sid, off, len(chans)) + b''.join(chans))
def universe(F, uid, spots):
    return module(F, 0x09, F.i('HH', uid, len(spots)) + b''.join(spots))
def lighting(F, seq, action, hold, universes):
    return module(F, 0x07, F.i('I', seq) + bytes([action]) + F.i('I', hold) + F.i('H', len(universes)) + b''.join(universes))
def sync(F, dev, s0, s1, seq):
    return module(F, 0x08, F.i('IIII', dev, s0, s1, seq))


def main(out):
    p = Pcap()
    def f(payload, port=PORT, sport=PORT):
        p.add(udp_frame(payload, sport, port))

    for il, fs in ((True, MOTION_LE), (False, MOTION_BE), (True, MOTION_BE), (False, MOTION_LE)):
        F = Fmt(il, fs)
        # a tracker without sub-modules, one with a timestamp and every position module
        f(packet(F, [trackable(F, 'Tracker1', [])], pid=1))
        f(packet(F, [trackable(F, 'Obj', [centroid(F), quat(F), euler(F), point(F), accvel(F), accvel(F, 2)], ts=123456)], pid=2, fmt=0))
        if il and fs == MOTION_LE:
            # several trackers, other formats, a name of length 0
            f(packet(F, [trackable(F, 'A', [centroid(F)]), trackable(F, 'B', [euler(F, 0x0111), euler(F, 0x0333)], ts=1), trackable(F, '', [])], pid=3, fmt=1))
            f(packet(F, [trackable(F, 'T', [centroid(F, lat=0)])], pid=4, fmt=2, ctx=0xffffffff))
            f(packet(F, [], pid=5))
            # zones, old and new style
            f(packet(F, [trackable(F, 'Z', [zones_old(F, 'alpha$beta$gamma')])], pid=6))
            f(packet(F, [trackable(F, 'Z', [zones_old(F, 'alpha$beta$')])], pid=7))
            f(packet(F, [trackable(F, 'Z', [zones_old(F, '')])], pid=8))
            f(packet(F, [trackable(F, 'Z', [zones_old(F, 'solo')])], pid=9))
            f(packet(F, [trackable(F, 'Z', [zones_new(F, ['north', 'south'])])], pid=10))
            f(packet(F, [trackable(F, 'Z', [zones_new(F, [])]), trackable(F, 'Y', [])], pid=11))
    # ---- lighting, both byte orders
    for il, fs in ((True, LIGHT_LE), (False, LIGHT_BE), (True, LIGHT_BE), (False, LIGHT_LE)):
        F = Fmt(il, fs)
        u1 = universe(F, 1, [spot(F, 1, 0, [channel(F, 0, 0, 255), channel(F, 1, 10, 128)]), spot(F, 2, 16, [channel(F, 0, 0, 1)]), spot(F, 3, 32, [])])
        u2 = universe(F, 2, [])
        f(packet(F, [lighting(F, 100, 0, 0, [u1, u2])], pid=20))
        f(packet(F, [lighting(F, 101, 1, 5000, [u2])], pid=21))
        f(packet(F, [lighting(F, 102, 1, 0, [])], pid=22))
        f(packet(F, [sync(F, 0x01020304, 5, 6, 77)], pid=23))
        f(packet(F, [lighting(F, 103, 0, 1, [u1]), sync(F, 9, 8, 7, 78)], pid=24))
    # ---- reproducer of "RTTrp: Fix quadratic work on overlapping modules": a lighting packet whose universes each claim many
    # spots but have a module size of 7; every spot used to be parsed across the following universes
    F = Fmt(True, LIGHT_LE)
    N, S = 1200, 600
    uni = struct.pack('<BHHH', 0x09, 7, 1, S)
    light = struct.pack('<BHIBIH', 0x07, 14 + 7 * N, 1, 0, 0, N)
    pk = b'TA' + b'4D' + b'\x00\x02' + struct.pack('<IBHIB', 1, 0, 0, 0, 1) + light + uni * N
    f(pk)
    p.write(os.path.join(out, 'rttrp-coverage.pcap'))

    # ===== malformed and error expert infos
    m = Pcap()
    def mf(payload, port=PORT):
        m.add(udp_frame(payload, PORT, port))
    F = Fmt(True, MOTION_LE)
    # invalid module types in each position, and size mismatches
    mf(packet(F, [module(F, 0x02, F.i('H', 1) + F.d(1, 2, 3))]))                                   # position module where a trackable belongs
    mf(packet(F, [trackable(F, 'T', [module(F, 0x55, b'\0' * 8)])]))                               # invalid sub-module
    mf(packet(F, [trackable(F, 'T', [centroid(F)], count=3)]))                                     # fewer sub-modules than counted
    mf(packet(F, [module(F, 0x01, b'\x01T\x00' + b'\x00')[:3] + b'\x05\x00' + b'\x01T\x00']))      # odd size
    t = trackable(F, 'T', [centroid(F)])
    mf(packet(F, [t[:3] + b'\x04' + t[4:]], size=None))
    mf(packet(F, [trackable(F, 'T', [module(F, 0x02, F.i('H', 1) + F.d(1, 2, 3) + b'\0\0\0\0')])]))  # module longer than its fields
    mf(packet(F, [trackable(F, 'T', [module(F, 0x02, F.i('H', 1) + F.d(1, 2, 3), size=40)])]))
    mf(packet(F, [trackable(F, 'T', [centroid(F)])], count=4))                                      # more modules than data
    mf(packet(F, [trackable(F, 'T', [module(F, 0x22, b'\x03\x07\x05abcde' + b'\0' * 5)])]))        # zones: new style, sizes beyond the module
    mf(packet(F, [trackable(F, 'T', [module(F, 0x22, F.i('H', 4000) + b'abc$d')])]))                # old style, length beyond the data
    mf(packet(F, [trackable(F, 'T', [module(F, 0x22, b'')])]))                                      # zone body missing
    mf(packet(F, [trackable(F, 'T', [module(F, 0x22, b'\x02\xff\xff')])]))
    G = Fmt(True, LIGHT_LE)
    mf(packet(G, [module(G, 0x55, b'\0' * 8)]))                                                    # invalid lighting module
    mf(packet(G, [lighting(G, 1, 0, 0, [module(G, 0x55, b'\0' * 8)])]))                            # universe expected
    mf(packet(G, [lighting(G, 1, 0, 0, [universe(G, 1, [module(G, 0x55, b'\0' * 8)])])]))          # spot expected
    mf(packet(G, [lighting(G, 1, 0, 0, [universe(G, 1, [spot(G, 1, 0, [channel(G, 0, 0, 1)] * 3)])])], count=2))
    mf(packet(G, [sync(G, 1, 2, 3, 4)[:3] + b'\0' * 20]))                                          # sync longer than its fields
    mf(packet(G, [module(G, 0x08, b'\0' * 8)]))                                                    # sync shorter
    mf(packet(G, [module(G, 0x07, G.i('I', 1) + b'\0')]))                                          # lighting output cut
    mf(packet(G, [module(G, 0x07, G.i('I', 1) + bytes([0]) + G.i('I', 0) + G.i('H', 5))]))         # universes counted, none present
    mf(packet(G, [lighting(G, 1, 0, 0, [universe(G, 1, [spot(G, 1, 0, [channel(G, 0, 0, 1)])])])])[:-3])   # truncated in a channel
    # spot with a channel count beyond its module, universe with spot count beyond its module
    mf(packet(G, [lighting(G, 1, 0, 0, [module(G, 0x09, G.i('HH', 1, 2) + spot(G, 1, 0, [])[:3])])]))
    mf(packet(G, [module(G, 0x09, G.i('HH', 1, 5), size=2)]))
    # a spot module and a lighting sync module larger than their fields (module size mismatch warnings)
    mf(packet(G, [lighting(G, 1, 0, 0, [universe(G, 1, [module(G, 0x0a, G.i('HHH', 1, 0, 0) + b'\0' * 5)])])]))
    mf(packet(G, [module(G, 0x08, G.i('IIII', 1, 2, 3, 4) + b'\0' * 6)]))
    # header only / truncated headers
    mf(F.sig() + b'\x00\x03\x00\x00')
    mf(packet(F, [])[:10])
    mf(packet(F, [trackable(F, 'T', [])])[:20])
    # universe module size smaller than 7 (cosmetic length): universe with spots listed
    mf(packet(G, [lighting(G, 1, 0, 0, [module(G, 0x09, G.i('HH', 1, 1) + spot(G, 1, 0, []), size=5)])]))
    # not RTTrP at all (only reachable with Decode As): wrong int signature, wrong float signature, too short
    mf(b'XXXX' + b'\0' * 20, 30001)
    mf(b'TA' + b'ZZ' + b'\0' * 20, 30001)
    mf(b'TA4', 30001)
    m.write(os.path.join(out, 'rttrp-coverage-malformed.pcap'))

main(sys.argv[1])
